import { experimentalSubscriptionEnabled, EXPERIMENTAL_SUBSCRIPTION_ENV } from '../../../packages/upstream/experimental.js';
import { fork, type ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { restoreClientError, serializeClientError } from '../../../packages/protocol/client-errors.js';

export class WorkerProcess extends EventEmitter {
  private child: ChildProcess;
  private pending = new Map<string, { resolve(value: unknown): void; reject(error: Error): void; timer: NodeJS.Timeout }>();
  private closed = false;
  constructor(runtime: string, entry: string, role: 'consumer' | 'donor', private hubProxy?: (method: string, path: string, body?: unknown) => Promise<unknown>, private saveCredentials?: (value: unknown) => Promise<void>) {
    super();
    const env = { ...process.env };
    for (const key of Object.keys(env)) if (/^(NODE_OPTIONS|NODE_PATH|ELECTRON_|SHARE_TOKEN_|DYLD_|LD_PRELOAD)/.test(key)) delete env[key];
    if (experimentalSubscriptionEnabled()) env[EXPERIMENTAL_SUBSCRIPTION_ENV] = '1';
    this.child = fork(entry, [role], { execPath: runtime, execArgv: [], env, stdio: ['ignore', 'ignore', 'ignore', 'ipc'], serialization: 'json' });
    this.child.on('message', message => { void this.receive(message); });
    this.child.on('error', () => this.exited('工作进程无法启动，请检查安装包运行时。'));
    this.child.on('exit', () => this.exited('本地工作进程已退出，请重新启动应用。'));
  }
  private async receive(message: unknown) {
    if (!message || typeof message !== 'object') return;
    const msg = message as { type?: string; id?: string; ok?: boolean; value?: unknown; error?: unknown; method?: string; path?: string; body?: unknown; hubUrl?: string; credentials?: unknown };
    if (msg.type === 'reply' && msg.id) {
      const pending = this.pending.get(msg.id); if (!pending) return;
      clearTimeout(pending.timer); this.pending.delete(msg.id);
      if (msg.ok) pending.resolve(msg.value); else pending.reject(restoreClientError(msg.error));
    } else if (msg.type === 'hub.request' && msg.id && this.hubProxy) {
      try { const value = await this.hubProxy(msg.method!, msg.path!, msg.body); this.reply({ type: 'hub.reply', id: msg.id, ok: true, value }); }
      catch (error) { this.reply({ type: 'hub.reply', id: msg.id, ok: false, error: serializeClientError(error) }); }
    } else if (msg.type === 'credentials.save' && msg.id && this.saveCredentials) {
      try { await this.saveCredentials({ hubUrl: msg.hubUrl, credentials: msg.credentials }); this.reply({ type: 'credentials.reply', id: msg.id, ok: true }); }
      catch { this.reply({ type: 'credentials.reply', id: msg.id, ok: false, error: serializeClientError({ code: 'SHARE_CREDENTIAL_STORE_FAILED' }) }); }
    } else if (msg.type === 'event') this.emit('event', msg.value);
  }
  private reply(message: object) { if (this.child.connected) this.child.send(message, () => {}); }
  request<T = unknown>(method: string, args?: unknown): Promise<T> {
    if (this.closed || !this.child.connected) return Promise.reject(restoreClientError({ code: 'SHARE_WORKER_UNAVAILABLE' }));
    const id = randomUUID();
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(restoreClientError({ code: 'SHARE_WORKER_TIMEOUT' })); }, 25_000);
      this.pending.set(id, { resolve: value => resolve(value as T), reject, timer });
      this.child.send({ type: 'request', id, method, args }, error => { if (error) { clearTimeout(timer); this.pending.delete(id); reject(restoreClientError({ code: 'SHARE_WORKER_UNAVAILABLE' })); } });
    });
  }
  private exited(message: string) {
    if (this.closed) return; this.closed = true;
    for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(restoreClientError({ code: 'SHARE_WORKER_UNAVAILABLE' })); }
    this.pending.clear(); this.emit('stopped', message);
  }
  async close() {
    if (this.closed) return;
    await this.request('close').catch(() => {});
    if (this.child.connected) this.child.disconnect();
    const process = this.child;
    if (process.exitCode === null) await new Promise<void>(resolve => {
      const timer = setTimeout(() => { process.kill('SIGTERM'); resolve(); }, 3000);
      process.once('exit', () => { clearTimeout(timer); resolve(); });
    });
    this.exited('工作进程已关闭。');
  }
}
