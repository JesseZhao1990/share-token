import type { LocalSession } from './api.js';

const labels: Record<string, string> = {
  starting: '正在启动', running: '运行中', requesting: '正在请求', attention: '需要处理',
  needs_attention: '需要处理', stopping: '正在停止', stopped: '已结束', closed: '已结束', completed: '已完成',
};
const activeStates = new Set(['starting', 'running', 'requesting', 'attention', 'needs_attention']);
const endedStates = new Set(['stopped', 'closed', 'completed', 'failed']);

export function sessionPresentation(session: LocalSession) {
  const state = session.state.toLowerCase();
  const hasPid = typeof session.pid === 'number' && session.pid > 0;
  const hasExit = typeof session.exitCode === 'number' || typeof session.exitSignal === 'number' && session.exitSignal > 0;
  // pid is cleared on exit, while the terminal buffer remains available. Prefer the explicit
  // controller field; older snapshots can still establish a terminal from their lifecycle.
  const canOpenTerminal = session.terminalStarted ?? (hasPid || hasExit || ['running', 'requesting', 'attention', 'needs_attention', 'stopping', 'stopped', 'closed', 'completed'].includes(state));
  // The controller knows whether exit followed an explicit stop. A SIGTERM/SIGKILL from that
  // action must not turn its final stopped state back into a failure in the renderer.
  const failed = state === 'failed';
  const label = failed ? canOpenTerminal ? '异常退出' : '启动失败' : labels[state] ?? '状态待确认';
  const diagnostic = session.message?.trim() || session.error?.trim();
  const exitDescription = typeof session.exitSignal === 'number' && session.exitSignal > 0
    ? `Codex 被信号 ${session.exitSignal} 终止。`
    : typeof session.exitCode === 'number' && session.exitCode !== 0 ? `Codex 已退出，退出码为 ${session.exitCode}。` : '';
  let message = diagnostic || (failed ? exitDescription || (canOpenTerminal ? 'Codex 已异常退出，可查看终端输出了解原因。' : 'Codex 未能启动。请检查程序和项目目录后重试。') : '');
  if (failed && canOpenTerminal && exitDescription && !message.includes(exitDescription)) message += ` ${exitDescription}`;
  return {
    label, message, canOpenTerminal,
    terminalActionLabel: endedStates.has(state) ? '查看终端输出' : '打开终端',
    canStop: activeStates.has(state) || state === 'failed' && hasPid,
    canCheckSetup: failed,
    problem: failed || state === 'attention' || state === 'needs_attention',
  };
}

export function terminalSessionStatus(session?: LocalSession): string {
  if (!session) return '正在读取会话状态…';
  const view = sessionPresentation(session);
  return view.message ? `${view.label} · ${view.message}` : view.label;
}
