import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { access, realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { promisify } from 'node:util';
import { codexOverrides } from '../../apps/cli/profile.js';
import { ShareError } from '../protocol/index.js';
import { restoreClientError } from '../protocol/client-errors.js';

const execFileAsync = promisify(execFile);
export interface CodexInstallation {
  path: string; version: string; client: 'cli';
  status: 'mock-text-verified' | 'unverified';
  note: string;
}
export interface TerminalHandle {
  pid: number;
  write(data: string): void;
  resize(cols: number, rows: number): void;
  stop(): Promise<void>;
}
export interface LauncherInput {
  codexPath: string; cwd: string; model: string; baseUrl: string; localKey: string;
  cols?: number; rows?: number;
  onData(data: string): void;
  onExit(event: { exitCode: number; signal?: number }): void;
}
export interface CodexLauncher { start(input: LauncherInput): Promise<TerminalHandle> }

function cleanEnvironment(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !/^(?:NODE_OPTIONS|NODE_PATH|ELECTRON_RUN_AS_NODE|SHARE_TOKEN_|ST_(?:ACCESS|REFRESH|RELAY|CONTROL|DEVICE)_)/.test(key)) env[key] = value;
  }
  // A shebang-based installation can use the signed Node sidecar without a separate user Node.
  env.PATH = `${dirname(process.execPath)}:${env.PATH ?? '/usr/bin:/bin:/usr/sbin:/sbin'}`;
  env.TERM = 'xterm-256color';
  return env;
}

export async function inspectCodexPath(path: string): Promise<CodexInstallation> {
  if (!isAbsolute(path)) throw new ShareError('SHARE_CODEX_PATH_INVALID', 'Codex 路径必须是用户选择的绝对路径。');
  const resolved = await realpath(path).catch(() => { throw new ShareError('SHARE_CODEX_NOT_FOUND', '没有找到该 Codex 程序。', 404); });
  const info = await stat(resolved);
  if (!info.isFile()) throw new ShareError('SHARE_CODEX_PATH_INVALID', 'Codex 路径不是可执行文件。');
  await access(resolved, constants.X_OK).catch(() => { throw new ShareError('SHARE_CODEX_NOT_EXECUTABLE', '所选 Codex 程序不可执行。'); });
  let output: string;
  try { const result = await execFileAsync(resolved, ['--version'], { timeout: 5000, maxBuffer: 64 * 1024, env: cleanEnvironment(), cwd: homedir() }); output = result.stdout; }
  catch { throw new ShareError('SHARE_CODEX_DETECTION_FAILED', '无法读取 Codex 版本，请检查安装。'); }
  const version = /^codex-cli\s+(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)/m.exec(output)?.[1];
  if (!version) throw new ShareError('SHARE_CODEX_DETECTION_FAILED', '所选程序未返回可辨认的 Codex CLI 版本。');
  return { path: resolved, version, client: 'cli', status: version === '0.153.4' ? 'mock-text-verified' : 'unverified', note: version === '0.153.4' ? '仅验证过本地模拟文本链路，完整原生工具循环与官方桌面 App 不在此证明范围。' : '此版本尚未完成兼容验收；只能用于显式模拟验证。' };
}

/** Fixed installation locations only. A renderer cannot turn PATH/cwd into an executable choice. */
export async function detectCodex(): Promise<CodexInstallation[]> {
  const candidates = [join(homedir(), '.local/bin/codex'), '/opt/homebrew/bin/codex', '/usr/local/bin/codex', '/usr/bin/codex', join(homedir(), '.npm-global/bin/codex')];
  const found = await Promise.all(candidates.map(path => inspectCodexPath(path).catch(() => null)));
  const unique = new Map<string, CodexInstallation>();
  for (const item of found) if (item) unique.set(item.path, item);
  return [...unique.values()];
}

export class NativeCodexLauncher implements CodexLauncher {
  async start(input: LauncherInput): Promise<TerminalHandle> {
    const installation = await inspectCodexPath(input.codexPath);
    if (!isAbsolute(input.cwd) || !(await stat(input.cwd).catch(() => null))?.isDirectory()) throw new ShareError('SHARE_PROJECT_INVALID', '请选择一个存在的本机项目目录。');
    const pty = await import('node-pty').catch(() => { throw restoreClientError({ code: 'SHARE_TERMINAL_RUNTIME_UNAVAILABLE' }); });
    const args = codexOverrides(input.baseUrl, input.model).flatMap(value => ['-c', value]);
    let processHandle: import('node-pty').IPty;
    try {
      processHandle = pty.spawn(installation.path, args, { name: 'xterm-256color', cwd: input.cwd, cols: input.cols ?? 100, rows: input.rows ?? 30,
        env: { ...cleanEnvironment(), SHARE_TOKEN_ACCESS_KEY: input.localKey }, });
    } catch (error) {
      // Native spawn errors can include paths or environment values. Only a fixed,
      // actionable category crosses into the worker reply or session snapshot.
      const code = (error as NodeJS.ErrnoException | null)?.code;
      throw restoreClientError({ code: code === 'EACCES' || code === 'EPERM' ? 'SHARE_CODEX_START_DENIED' : 'SHARE_TERMINAL_START_FAILED' });
    }
    let exited = false;
    let resolveExit!: () => void;
    const exit = new Promise<void>(resolve => { resolveExit = resolve; });
    const dataSubscription = processHandle.onData(input.onData);
    const exitSubscription = processHandle.onExit(event => {
      exited = true; resolveExit(); input.onExit(event);
      dataSubscription.dispose(); exitSubscription.dispose();
    });
    let stopping: Promise<void> | null = null;
    return {
      pid: processHandle.pid,
      write(data) { if (!exited) processHandle.write(data); },
      resize(cols, rows) { if (!exited) processHandle.resize(cols, rows); },
      stop() {
        if (stopping) return stopping;
        stopping = (async () => {
          if (exited) return;
          // Only this owned PTY process group is addressed, never a global process-name match.
          const signalGroup = (signal: NodeJS.Signals) => {
            if (exited) return;
            try { if (process.platform !== 'win32') process.kill(-processHandle.pid, signal); else processHandle.kill(signal); }
            catch { try { processHandle.kill(signal); } catch { /* It may already have exited. */ } }
          };
          signalGroup('SIGTERM');
          let timer: NodeJS.Timeout | undefined;
          await Promise.race([exit, new Promise<void>(resolve => { timer = setTimeout(resolve, 1500); })]);
          if (timer) clearTimeout(timer);
          if (!exited) signalGroup('SIGKILL');
          let killTimer: NodeJS.Timeout | undefined;
          await Promise.race([exit, new Promise<void>(resolve => { killTimer = setTimeout(resolve, 1500); })]);
          if (killTimer) clearTimeout(killTimer);
          if (!exited) throw new ShareError('SHARE_TERMINAL_STOP_UNCONFIRMED', '本机 Codex 退出尚未确认，请检查该会话。', 409);
        })();
        return stopping;
      },
    };
  }
}
