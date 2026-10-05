import { createHash } from 'node:crypto';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { MAX_BODY_BYTES, ShareError, type Capabilities, type QuotaSnapshot } from '../protocol/index.js';
import { normalizeCodexQuota, unknownQuota } from './quota.js';
import { assertExperimentalSubscriptionEnabled } from './experimental.js';
import type { UpstreamAdapter, UpstreamRequest, UpstreamResponse } from './index.js';

// These endpoints are the ChatGPT provider endpoints in openai/codex. They are
// deliberately not configurable by the Hub, a request, or a renderer.
const CODEX_BASE_URL = 'https://chatgpt.com/backend-api/codex';
const RPC_METHODS = new Set(['initialize', 'account/read', 'account/login/start', 'account/login/cancel', 'account/logout', 'account/rateLimits/read', 'model/list']);
const OWNER_MARKER = '.share-token-account';
const OWNER_CONTENT = 'share-token:isolated-codex-account:v1\n';
const credentialReaders = new WeakMap<CodexSubscriptionAccount, () => Promise<LocalCredentials>>();
const credentialRefreshers = new WeakMap<CodexSubscriptionAccount, () => Promise<void>>();
const privateStatus = () => ({ authenticated: false, accountBinding: null, planType: null, models: [], quota: unknownQuota('codex') });

export interface SubscriptionAccountStatus {
  authenticated: boolean;
  accountBinding: string | null;
  planType: string | null;
  models: string[];
  quota: QuotaSnapshot;
  lastError?: { code: string; message: string };
}
export interface CodexSubscriptionAccountOptions { codexHome: string; binary?: string; timeoutMs?: number }
interface LocalCredentials { accessToken: string; accountId: string; binding: string; expiresAt: number | null }
interface PendingRpc { resolve(value: unknown): void; reject(error: Error): void; timer: NodeJS.Timeout }

/**
 * Manages an app-owned Codex login through the official app-server. It never
 * starts a thread/turn or executes tools. The public interface contains no
 * tokens, email address, or raw ChatGPT account identifier.
 */
export class CodexSubscriptionAccount {
  private child: ChildProcessWithoutNullStreams | null = null;
  private starting: Promise<void> | null = null;
  private pending = new Map<number, PendingRpc>();
  private nextId = 1;
  private closed = false;
  private loginId: string | null = null;
  private lastError: SubscriptionAccountStatus['lastError'];
  private inspectInFlight: Promise<SubscriptionAccountStatus> | null = null;
  private refreshInFlight: Promise<void> | null = null;
  readonly codexHome: string;

  constructor(private readonly options: CodexSubscriptionAccountOptions) {
    if (!isAbsolute(options.codexHome)) throw problem('SHARE_CODEX_HOME_INVALID', 'Codex 登录目录必须是本应用专用的绝对路径。');
    this.codexHome = resolve(options.codexHome);
    if (this.codexHome === resolve(homedir(), '.codex') || (process.env.CODEX_HOME && this.codexHome === resolve(process.env.CODEX_HOME))) throw problem('SHARE_CODEX_HOME_INVALID', '不能使用现有 Codex 登录目录；请使用本应用独立的登录目录。');
    credentialReaders.set(this, () => this.credentials());
    credentialRefreshers.set(this, () => this.refresh());
  }

  inspect(): Promise<SubscriptionAccountStatus> {
    if (!this.inspectInFlight) this.inspectInFlight = this.inspectNow().finally(() => { this.inspectInFlight = null; });
    return this.inspectInFlight.then(value => structuredClone(value));
  }

  private async inspectNow(): Promise<SubscriptionAccountStatus> {
    try {
      await this.ensureStarted();
      const response = object(await this.rpc('account/read', { refreshToken: false }));
      const account = object(response.account);
      if (account.type !== 'chatgpt') return { ...privateStatus(), ...(this.lastError ? { lastError: this.lastError } : {}) };
      const before = await this.readCredentials();
      const models: string[] = [];
      let cursor: string | null = null;
      for (let page = 0; page < 8; page++) {
        const result = object(await this.rpc('model/list', { cursor, limit: 100, includeHidden: false }));
        if (!Array.isArray(result.data)) throw problem('SHARE_CODEX_PROTOCOL_INVALID', 'Codex 模型目录格式不可识别。');
        for (const raw of result.data) {
          const model = object(raw);
          if (model.hidden !== true && typeof model.model === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(model.model) && !models.includes(model.model)) models.push(model.model);
        }
        cursor = typeof result.nextCursor === 'string' && result.nextCursor.length <= 1024 ? result.nextCursor : null;
        if (!cursor) break;
        if (page === 7) throw problem('SHARE_CODEX_PROTOCOL_INVALID', 'Codex 模型目录分页超过限制。');
      }
      const rawQuota = object(await this.rpc('account/rateLimits/read'));
      const after = await this.readCredentials();
      if (before.binding !== after.binding || (rawQuota.accountId !== undefined && rawQuota.accountId !== null && rawQuota.accountId !== after.accountId)) throw problem('SHARE_ACCOUNT_CHANGED', 'Codex 账户在检查期间发生变化，请重新绑定来源。', 409);
      this.lastError = undefined;
      return { authenticated: true, accountBinding: after.binding, planType: typeof account.planType === 'string' ? account.planType.slice(0, 64) : null, models: models.slice(0, 32), quota: normalizeCodexQuota(rawQuota) };
    } catch (error) {
      const failure = sanitized(error);
      this.lastError = failure;
      return { ...privateStatus(), lastError: failure };
    }
  }

  async startLogin(): Promise<{ loginId: string; authUrl: string }> {
    assertExperimentalSubscriptionEnabled();
    await this.ensureStarted();
    if (this.loginId) await this.cancelLogin();
    const response = object(await this.rpc('account/login/start', { type: 'chatgpt' }));
    if (response.type !== 'chatgpt' || typeof response.loginId !== 'string' || response.loginId.length > 256 || typeof response.authUrl !== 'string') throw problem('SHARE_CODEX_PROTOCOL_INVALID', 'Codex 登录响应格式不可识别。');
    let url: URL;
    try { url = new URL(response.authUrl); } catch { throw problem('SHARE_CODEX_PROTOCOL_INVALID', 'Codex 返回了无效的登录地址。'); }
    if (url.protocol !== 'https:' || url.username || url.password || !['auth.openai.com', 'auth0.openai.com', 'chatgpt.com'].includes(url.hostname)) throw problem('SHARE_CODEX_LOGIN_URL_INVALID', 'Codex 返回的登录地址不属于受信任的登录站点。');
    this.loginId = response.loginId; this.lastError = undefined;
    return { loginId: response.loginId, authUrl: url.toString() };
  }

  async cancelLogin(): Promise<void> {
    assertExperimentalSubscriptionEnabled();
    if (!this.loginId) return;
    const loginId = this.loginId;
    await this.ensureStarted(); await this.rpc('account/login/cancel', { loginId });
    if (this.loginId === loginId) this.loginId = null;
  }

  async logout(): Promise<void> {
    assertExperimentalSubscriptionEnabled();
    await this.ensureStarted();
    await this.cancelLogin(); await this.rpc('account/logout');
    this.lastError = undefined;
  }

  async close(): Promise<void> {
    this.closed = true;
    const child = this.child;
    this.child = null; this.starting = null;
    this.failPending(problem('SHARE_CODEX_CLOSED', '本机 Codex 登录服务已关闭。', 503));
    if (child && child.exitCode === null) {
      child.stdin.end(); child.kill('SIGTERM');
      await new Promise<void>(resolveExit => {
        const timer = setTimeout(() => { child.kill('SIGKILL'); resolveExit(); }, 1000);
        child.once('close', () => { clearTimeout(timer); resolveExit(); });
      });
    }
  }

  private async refresh(): Promise<void> {
    if (!this.refreshInFlight) this.refreshInFlight = (async () => {
      await this.ensureStarted();
      const before = await this.readCredentials();
      const response = object(await this.rpc('account/read', { refreshToken: true }));
      if (object(response.account).type !== 'chatgpt') throw problem('SHARE_UPSTREAM_AUTH_REQUIRED', '请在共享端重新登录 Codex。', 401);
      const after = await this.readCredentials();
      if (after.binding !== before.binding) throw problem('SHARE_ACCOUNT_CHANGED', '刷新登录时账户发生变化，请重新绑定来源。', 409);
    })().finally(() => { this.refreshInFlight = null; });
    return this.refreshInFlight;
  }

  private async credentials(): Promise<LocalCredentials> {
    await this.ensureStarted();
    const response = object(await this.rpc('account/read', { refreshToken: false }));
    if (object(response.account).type !== 'chatgpt') throw problem('SHARE_UPSTREAM_AUTH_REQUIRED', '请在共享端登录 Codex 的 ChatGPT 账户。', 401);
    let credentials = await this.readCredentials();
    if (credentials.expiresAt !== null && credentials.expiresAt <= Date.now() + 60_000) {
      const binding = credentials.binding;
      await this.refresh(); credentials = await this.readCredentials();
      if (binding !== credentials.binding) throw problem('SHARE_ACCOUNT_CHANGED', '刷新登录时账户发生变化，请重新绑定来源。', 409);
      if (credentials.expiresAt !== null && credentials.expiresAt <= Date.now()) throw problem('SHARE_UPSTREAM_AUTH_REQUIRED', 'Codex 登录已过期，请在共享端重新登录。', 401);
    }
    return credentials;
  }

  private async ensureHome(): Promise<void> {
    assertExperimentalSubscriptionEnabled();
    await mkdir(this.codexHome, { recursive: true, mode: 0o700 });
    const stat = await lstat(this.codexHome);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (process.getuid && stat.uid !== process.getuid()) || (stat.mode & 0o077) !== 0) throw problem('SHARE_CODEX_HOME_UNSAFE', '本应用的 Codex 登录目录必须属于当前用户，且权限为 0700。');
    const canonical = await realpath(this.codexHome);
    for (const unsafe of [join(homedir(), '.codex'), ...(process.env.CODEX_HOME ? [process.env.CODEX_HOME] : [])]) {
      const target = await realpath(unsafe).catch(() => resolve(unsafe));
      if (canonical === target) throw problem('SHARE_CODEX_HOME_INVALID', '不能使用现有 Codex 登录目录。');
    }
    const entries = await readdir(this.codexHome);
    if (entries.length) {
      const marker = join(this.codexHome, OWNER_MARKER);
      const markerStat = await lstat(marker).catch(() => null);
      if (!markerStat?.isFile() || markerStat.isSymbolicLink() || (markerStat.mode & 0o077) !== 0 || (process.getuid && markerStat.uid !== process.getuid()) || await readFile(marker, 'utf8').catch(() => '') !== OWNER_CONTENT) throw problem('SHARE_CODEX_HOME_NOT_OWNED', '现有目录不属于本应用；请选择新的空目录完成独立登录。');
    } else await writeFile(join(this.codexHome, OWNER_MARKER), OWNER_CONTENT, { mode: 0o600, flag: 'wx' });
  }

  private async readCredentials(): Promise<LocalCredentials> {
    assertExperimentalSubscriptionEnabled();
    const file = join(this.codexHome, 'auth.json');
    let handle;
    try {
      const stat = await lstat(file);
      if (!stat.isFile() || stat.isSymbolicLink() || (process.getuid && stat.uid !== process.getuid()) || (stat.mode & 0o077) !== 0 || stat.size > 64 * 1024) throw problem('SHARE_CODEX_CREDENTIALS_UNSAFE', '本应用的 Codex 登录文件权限或格式不安全。');
      handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const actual = await handle.stat();
      if (stat.ino !== actual.ino || stat.dev !== actual.dev || (actual.mode & 0o077) !== 0 || actual.uid !== stat.uid || actual.size > 64 * 1024) throw problem('SHARE_CODEX_CREDENTIALS_UNSAFE', 'Codex 登录文件正在变化，请重试。');
      const auth = object(JSON.parse(await handle.readFile('utf8')));
      if ((auth.auth_mode !== undefined && auth.auth_mode !== null && auth.auth_mode !== 'chatgpt') || auth.OPENAI_API_KEY) throw problem('SHARE_UPSTREAM_AUTH_REQUIRED', '此来源仅接受 ChatGPT 登录，不接受 API 密钥。', 401);
      const tokens = object(auth.tokens);
      if (typeof tokens.access_token !== 'string' || tokens.access_token.length < 16 || tokens.access_token.length > 32 * 1024 || /\s/.test(tokens.access_token) || typeof tokens.account_id !== 'string' || !/^[A-Za-z0-9_.:@-]{1,256}$/.test(tokens.account_id)) throw problem('SHARE_UPSTREAM_AUTH_REQUIRED', 'Codex 登录材料不完整，请在共享端重新登录。', 401);
      const accessClaims = jwtClaims(tokens.access_token);
      const idClaims = typeof tokens.id_token === 'string' ? jwtClaims(tokens.id_token) : {};
      const authClaims = object(idClaims['https://api.openai.com/auth']);
      const userId = authClaims.chatgpt_user_id ?? authClaims.user_id ?? idClaims.sub;
      if (typeof userId !== 'string' || !userId || userId.length > 256) throw problem('SHARE_UPSTREAM_AUTH_REQUIRED', 'Codex 登录缺少稳定的用户身份，请在共享端重新登录。', 401);
      if (authClaims.chatgpt_account_is_fedramp === true) throw problem('SHARE_CODEX_ACCOUNT_UNSUPPORTED', '此账户需要专用服务区域，当前共享适配尚不支持。', 403);
      return { accessToken: tokens.access_token, accountId: tokens.account_id, binding: bindingOf(tokens.account_id, userId), expiresAt: typeof accessClaims.exp === 'number' && Number.isFinite(accessClaims.exp) ? accessClaims.exp * 1000 : null };
    } catch (error) {
      if (error instanceof ShareError) throw error;
      throw problem('SHARE_UPSTREAM_AUTH_REQUIRED', '无法读取本应用的 Codex 登录，请在共享端重新登录。', 401);
    } finally { await handle?.close(); }
  }

  private ensureStarted(): Promise<void> {
    try { assertExperimentalSubscriptionEnabled(); } catch (error) { return Promise.reject(error); }
    if (this.closed) return Promise.reject(problem('SHARE_CODEX_CLOSED', '本机 Codex 登录服务已关闭。', 503));
    if (!this.starting) this.starting = this.start().catch(error => { this.starting = null; throw error; });
    return this.starting;
  }

  private async start(): Promise<void> {
    assertExperimentalSubscriptionEnabled();
    await this.ensureHome();
    if (this.closed) throw problem('SHARE_CODEX_CLOSED', '本机 Codex 登录服务已关闭。', 503);
    // Do not inherit authentication, provider, proxy, instrumentation, or arbitrary
    // Node/Rust loader environment. In particular, no ambient API billing fallback.
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, HOME: homedir(), CODEX_HOME: this.codexHome, TMPDIR: tmpdir(), LANG: 'en_US.UTF-8' };
    if (process.platform === 'win32') { env.SystemRoot = process.env.SystemRoot; env.USERPROFILE = homedir(); }
    assertExperimentalSubscriptionEnabled();
    const child = spawn(this.options.binary ?? 'codex', ['-c', 'cli_auth_credentials_store="file"', '-c', 'forced_login_method="chatgpt"', '-c', 'model_provider="openai"', 'app-server', '--listen', 'stdio://'], { cwd: this.codexHome, env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    this.child = child;
    let buffer = '';
    const fail = () => {
      if (this.child !== child) return;
      this.child = null; this.starting = null;
      this.failPending(problem('SHARE_CODEX_UNAVAILABLE', '本机 Codex 登录服务不可用，请检查安装后重试。', 503));
    };
    child.once('error', fail); child.once('exit', fail); child.stdin.on('error', fail);
    // Never forward or persist stderr: upstream failures may include private auth details.
    child.stderr.resume(); child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      if (this.child !== child) return;
      buffer += chunk;
      if (Buffer.byteLength(buffer) > 2 * 1024 * 1024) { fail(); child.kill(); return; }
      let newline: number;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1);
        let frame: Record<string, unknown>;
        try { frame = object(JSON.parse(line)); if (!Object.keys(frame).length) throw new Error(); }
        catch { fail(); child.kill(); return; }
        if (typeof frame.id === 'number' && this.pending.has(frame.id)) {
          const pending = this.pending.get(frame.id)!; this.pending.delete(frame.id); clearTimeout(pending.timer);
          if (frame.error !== undefined) pending.reject(problem('SHARE_CODEX_RPC_FAILED', 'Codex 无法完成当前登录或额度操作，请在共享端检查账户状态。', 503));
          else pending.resolve(frame.result);
        } else if (typeof frame.method === 'string' && frame.id === undefined) {
          if (frame.method === 'account/login/completed') {
            const params = object(frame.params);
            if (params.loginId === this.loginId) {
              this.loginId = null;
              this.lastError = params.success === true ? undefined : { code: 'SHARE_CODEX_LOGIN_FAILED', message: 'Codex 登录未完成，请重试。' };
            }
          }
        } else if (frame.id !== undefined && typeof frame.method === 'string') {
          child.stdin.write(`${JSON.stringify({ id: frame.id, error: { code: -32601, message: 'Unsupported account client operation' } })}\n`);
        }
      }
    });
    try {
      await this.rpc('initialize', { clientInfo: { name: 'share_token_subscription', title: 'Share Token local subscription account', version: '0.3.0' }, capabilities: { experimentalApi: false, requestAttestation: false } });
      child.stdin.write(`${JSON.stringify({ method: 'initialized' })}\n`);
    } catch (error) { fail(); child.kill('SIGTERM'); throw error; }
  }

  private rpc(method: string, params?: unknown): Promise<unknown> {
    try { assertExperimentalSubscriptionEnabled(); } catch (error) { return Promise.reject(error); }
    if (!RPC_METHODS.has(method) || !this.child || this.closed) return Promise.reject(problem('SHARE_CODEX_UNAVAILABLE', '本机 Codex 登录服务不可用。', 503));
    const id = this.nextId++;
    return new Promise((resolveRpc, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(problem('SHARE_CODEX_TIMEOUT', 'Codex 登录或额度请求超时，请稍后重试。', 504)); }, this.options.timeoutMs ?? 15_000);
      this.pending.set(id, { resolve: resolveRpc, reject, timer });
      this.child!.stdin.write(`${JSON.stringify({ id, method, ...(params === undefined ? {} : { params }) })}\n`, error => {
        if (!error) return;
        const pending = this.pending.get(id); if (!pending) return;
        this.pending.delete(id); clearTimeout(pending.timer); pending.reject(problem('SHARE_CODEX_UNAVAILABLE', '本机 Codex 登录服务不可用。', 503));
      });
    });
  }

  private failPending(error: Error) { for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(error); } this.pending.clear(); }
}

export interface SubscriptionAdapterOptions {
  account: CodexSubscriptionAccount;
  models: string[];
  accountBinding: string;
  /** Trusted in-process test seam. Never accepted from a Hub/CLI/renderer config. */
  transport?: typeof fetch;
}

/** Raw inference transport. All tools continue to execute in the consumer's Codex. */
export class SubscriptionAdapter implements UpstreamAdapter {
  private rejectedCredentialHash: string | null = null;
  constructor(private readonly options?: SubscriptionAdapterOptions) {}

  async inspect(): Promise<Capabilities> {
    assertExperimentalSubscriptionEnabled();
    if (!this.options) return { kind: 'subscription', verified: false, accountBinding: 'subscription:unverified', models: ['unverified'], responses: false, compact: false };
    const status = await this.options.account.inspect();
    if (!status.authenticated || !status.accountBinding) throw problem(status.lastError?.code ?? 'SHARE_UPSTREAM_AUTH_REQUIRED', status.lastError?.message ?? '请在共享端登录 Codex 的 ChatGPT 账户。', 503);
    if (this.rejectedCredentialHash && status.authenticated) {
      try { const current = await credentialReaders.get(this.options.account)!(); if (tokenHash(current.accessToken) !== this.rejectedCredentialHash) this.rejectedCredentialHash = null; }
      catch { /* The source remains unavailable until authentication recovers. */ }
    }
    const models = this.options.models.filter(model => status.models.includes(model));
    if (status.accountBinding === this.options.accountBinding && this.rejectedCredentialHash) throw problem('SHARE_UPSTREAM_AUTH_REQUIRED', '共享端 Codex 登录需要恢复，请重新登录后继续。', 401);
    if (status.accountBinding === this.options.accountBinding && !models.length) throw problem('SHARE_CAPABILITY_UNAVAILABLE', '所选模型不在当前 Codex 账户的模型目录中。', 503);
    const verified = status.authenticated && status.accountBinding === this.options.accountBinding && models.length > 0 && !this.rejectedCredentialHash;
    return { kind: 'subscription', verified, accountBinding: status.accountBinding ?? 'subscription:unverified', models: models.length ? models : this.options.models, responses: verified, compact: verified };
  }

  async readQuota(): Promise<QuotaSnapshot> {
    assertExperimentalSubscriptionEnabled();
    if (!this.options || this.rejectedCredentialHash) return unknownQuota('codex');
    const status = await this.options.account.inspect();
    return status.accountBinding === this.options.accountBinding ? status.quota : unknownQuota('codex');
  }

  async open(request: UpstreamRequest, signal: AbortSignal): Promise<UpstreamResponse> {
    assertExperimentalSubscriptionEnabled();
    signal.throwIfAborted();
    if (!this.options) throw new ShareError('SHARE_SUBSCRIPTION_UNVERIFIED', 'Personal subscription inference sharing has no verified authorized adapter. No upstream request was made.', 501);
    if (!this.options.models.includes(request.model)) return rejection(403, 'SHARE_MODEL_NOT_ALLOWED', '模型未获本机共享规则允许。');
    let body: Record<string, unknown>;
    try { body = object(JSON.parse(Buffer.from(request.body).toString('utf8'))); }
    catch { return rejection(400, 'SHARE_REQUEST_INVALID', '推理请求不是有效 JSON。'); }
    if (body.model !== request.model || body.store === true || body.background === true || (request.operation === 'responses' && body.stream !== true)) return rejection(400, 'SHARE_REQUEST_UNSUPPORTED', '订阅通道仅支持不存储的流式 Responses 和显式压缩请求。');
    const credentials = await credentialReaders.get(this.options.account)!();
    if (credentials.binding !== this.options.accountBinding) throw problem('SHARE_ACCOUNT_CHANGED', '本机 Codex 账户已变化，旧来源不能继续使用。', 409);
    if (this.rejectedCredentialHash === tokenHash(credentials.accessToken)) return rejection(401, 'SHARE_UPSTREAM_AUTH_REQUIRED', '共享端 Codex 登录仍需恢复；未重复发送已拒绝的认证材料。');
    this.rejectedCredentialHash = null;
    signal.throwIfAborted();
    // No retry and no redirect: a transport failure after this call remains UNKNOWN.
    assertExperimentalSubscriptionEnabled();
    const response = await (this.options.transport ?? fetch)(`${CODEX_BASE_URL}/responses${request.operation === 'compact' ? '/compact' : ''}`, {
      method: 'POST', redirect: 'error', signal,
      headers: { authorization: `Bearer ${credentials.accessToken}`, 'chatgpt-account-id': credentials.accountId, 'content-type': 'application/json', accept: request.operation === 'compact' ? 'application/json' : 'text/event-stream', 'accept-encoding': 'identity', originator: 'share_token', 'user-agent': 'share-token/0.3.0' },
      body: Buffer.from(request.body),
    });
    if (response.status >= 400) {
      await response.body?.cancel().catch(() => {});
      if (response.status === 401) {
        this.rejectedCredentialHash = tokenHash(credentials.accessToken);
        // Refresh only prepares a later request. Never replay this inference POST.
        try {
          await credentialRefreshers.get(this.options.account)!();
          const refreshed = await credentialReaders.get(this.options.account)!();
          if (refreshed.binding === this.options.accountBinding && tokenHash(refreshed.accessToken) !== this.rejectedCredentialHash) this.rejectedCredentialHash = null;
        } catch { /* Explicit re-login remains required. */ }
      }
      const code = response.status === 401 ? 'SHARE_UPSTREAM_AUTH_REQUIRED' : response.status === 429 ? 'SHARE_UPSTREAM_RATE_LIMITED' : 'SHARE_UPSTREAM_REJECTED';
      const message = response.status === 401 ? '共享端 Codex 登录已失效；本次请求没有自动重试。' : response.status === 429 ? '共享端订阅达到限额，请等待额度恢复；本次请求没有换号或重试。' : 'Codex 上游拒绝了请求，私密错误详情未转发。';
      const rejected = rejection(response.status, code, message);
      const retryAfter = response.headers.get('retry-after');
      if (retryAfter && /^\d{1,6}$/.test(retryAfter)) rejected.headers['retry-after'] = retryAfter;
      return rejected;
    }
    const contentType = (response.headers.get('content-type') ?? '').trim();
    const headerless = contentType.length === 0;
    const sse = /^text\/event-stream(?:\s*;|$)/i.test(contentType);
    if (response.status < 200 || response.status >= 300 || (!headerless && ((request.operation === 'responses' && !sse) || (request.operation === 'compact' && !/^application\/json(?:\s*;|$)/i.test(contentType))))) {
      await response.body?.cancel().catch(() => {});
      // A successful upstream request may already have executed. A local parser error is not
      // an upstream rejection: throwing preserves Relay's UNKNOWN state and prevents replay.
      throw protocolFailure();
    }
    const headers: Record<string, string> = { 'content-type': request.operation === 'responses' ? 'text/event-stream' : 'application/json', 'cache-control': 'no-store', 'x-share-adapter': 'subscription' };
    const requestId = response.headers.get('x-request-id');
    if (requestId && /^[A-Za-z0-9_.:-]{1,200}$/.test(requestId) && !requestId.includes(credentials.accessToken) && !requestId.includes(credentials.accountId)) headers['x-request-id'] = requestId;
    if (request.operation === 'compact') {
      const reader = response.body?.getReader();
      const abort = () => { void reader?.cancel().catch(() => {}); };
      signal.addEventListener('abort', abort, { once: true });
      const pieces: Uint8Array[] = []; let size = 0;
      try {
        if (reader) for (;;) {
          signal.throwIfAborted(); const next = await reader.read(); signal.throwIfAborted(); if (next.done) break;
          size += next.value.byteLength;
          if (size > MAX_BODY_BYTES) throw protocolFailure();
          pieces.push(next.value);
        }
        const bytes = Buffer.concat(pieces); const text = new TextDecoder('utf8', { fatal: true }).decode(bytes);
        const compact = object(JSON.parse(text));
        if (text.includes(credentials.accessToken) || compact.error !== undefined || compact.object !== 'response.compaction' || typeof compact.id !== 'string' || !/^resp_[A-Za-z0-9_-]{1,120}$/.test(compact.id) || !Array.isArray(compact.output) || !compact.output.length) throw protocolFailure();
        return { status: response.status, headers, body: (async function* () { signal.throwIfAborted(); yield bytes; })() };
      } catch (error) {
        if (signal.aborted) throw error;
        throw protocolFailure();
      } finally { signal.removeEventListener('abort', abort); await reader?.cancel().catch(() => {}); reader?.releaseLock(); }
    }
    const stream = subscriptionEvents(response, signal, credentials.accessToken, headerless);
    if (!headerless) return { status: response.status, headers, body: stream };
    // Some Codex responses omit Content-Type. Do not announce SSE until one complete JSON
    // event has been validated; only this bounded prefix is read before returning the stream.
    const first = await stream.next();
    if (first.done) throw protocolFailure();
    return { status: response.status, headers, body: prefixedEvents(first.value, stream, signal) };
  }
}

function protocolFailure(): ShareError { return problem('SHARE_UPSTREAM_PROTOCOL_INVALID', 'Codex 的响应格式无法确认，请先核实执行结果；本次请求不会自动重试。', 502); }

/** The inner stream already owns a reader, so even an unstarted consumer must release it. */
function prefixedEvents(first: Uint8Array, stream: AsyncGenerator<Uint8Array, void, unknown>, signal: AbortSignal): AsyncIterableIterator<Uint8Array> {
  let prefix: Uint8Array | undefined = first, closing: Promise<IteratorResult<Uint8Array, void>> | undefined;
  const close = () => {
    if (!closing) {
      prefix = undefined; signal.removeEventListener('abort', abort);
      closing = stream.return();
    }
    return closing;
  };
  // subscriptionEvents installs its own cancellation listener first. That cancels any
  // pending read before return is queued, then this listener runs the generator's finally.
  const abort = () => { void close().catch(() => {}); };
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  return {
    [Symbol.asyncIterator]() { return this; },
    async next() {
      try {
        signal.throwIfAborted();
        if (closing) return closing;
        if (prefix) { const value = prefix; prefix = undefined; return { value, done: false }; }
        const next = await stream.next();
        if (next.done) await close();
        return next;
      } catch (error) { await close(); throw error; }
    },
    async return() { return close(); },
    async throw(error: unknown) {
      try { return await stream.throw(error); }
      finally { await close(); }
    },
  };
}

/** Headerless detection accepts Responses JSON events, never a page or an unframed JSON error. */
function verifiedHeaderlessEvent(event: string, accessToken: string, identified: boolean): { bytes: Buffer | null; terminal: boolean; json: boolean } {
  const data: string[] = []; let eventName: string | undefined;
  for (const line of event.split(/\r?\n/)) {
    if (!line || line.startsWith(':')) continue;
    const separator = line.indexOf(':');
    if (separator < 0) throw protocolFailure();
    const field = line.slice(0, separator), value = line.slice(separator + 1).replace(/^ /, '');
    if (field === 'data') data.push(value);
    else if (field === 'event' && !eventName) eventName = value;
    else if (field !== 'id' && field !== 'retry') throw protocolFailure();
  }
  if (!data.length) { if (eventName) throw protocolFailure(); return { bytes: null, terminal: false, json: false }; }
  const payload = data.join('\n');
  if (payload === '[DONE]') return { bytes: null, terminal: false, json: false };
  let value: Record<string, unknown>;
  try { value = object(JSON.parse(payload)); } catch { throw protocolFailure(); }
  const type = value.type;
  if (typeof type !== 'string' || type.length > 160 || eventName && eventName !== type || type !== 'error' && !/^response\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,5}$/.test(type)) throw protocolFailure();
  const lifecycle = ['response.created', 'response.queued', 'response.in_progress', 'response.completed', 'response.failed', 'response.incomplete'];
  // A lifecycle/error event identifies the protocol. Once identified, preserve valid future
  // response.* event types and fields rather than pinning this relay to a Codex event catalog.
  if (!identified && type !== 'error' && !lifecycle.includes(type)) throw protocolFailure();
  const response = object(value.response);
  if (lifecycle.includes(type) && (typeof response.id !== 'string' || !/^resp_[A-Za-z0-9_-]{1,120}$/.test(response.id))) throw protocolFailure();
  if (!identified && type === 'error' && typeof value.message !== 'string' && typeof object(value.error).message !== 'string') throw protocolFailure();
  // Re-encode only parsed protocol data. Untrusted SSE comments/id fields cannot leak through
  // format detection. Failure event payloads receive the same redaction as declared SSE.
  const normalized = `event: ${type}\ndata: ${JSON.stringify(value)}\n\n`;
  const safe = sanitizeFailureEvent(normalized, accessToken);
  return { bytes: Buffer.from(safe), terminal: ['error', 'response.completed', 'response.failed', 'response.incomplete'].includes(type), json: true };
}

async function* subscriptionEvents(response: Response, signal: AbortSignal, accessToken: string, strict: boolean): AsyncGenerator<Uint8Array, void, unknown> {
  if (!response.body) { if (strict) throw protocolFailure(); return; }
  const reader = response.body.getReader(), decoder = new TextDecoder('utf8', { fatal: true });
  const abort = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', abort, { once: true });
  let pending = '', probeBytes = 0, seenJson = false, terminal = false;
  try {
    for (;;) {
      signal.throwIfAborted(); const next = await reader.read(); signal.throwIfAborted(); if (next.done) break;
      if (strict && !seenJson && (probeBytes += next.value.byteLength) > MAX_BODY_BYTES) throw protocolFailure();
      pending += decoder.decode(next.value, { stream: true });
      if (Buffer.byteLength(pending) > MAX_BODY_BYTES) throw protocolFailure();
      let boundary: RegExpExecArray | null;
      while ((boundary = /\r?\n\r?\n/.exec(pending))) {
        const end = boundary.index + boundary[0].length, event = pending.slice(0, end); pending = pending.slice(end);
        if (strict) {
          const verified = verifiedHeaderlessEvent(event, accessToken, seenJson);
          seenJson ||= verified.json; terminal ||= verified.terminal;
          if (verified.bytes) yield verified.bytes;
        } else yield Buffer.from(sanitizeFailureEvent(event, accessToken));
      }
    }
    pending += decoder.decode();
    if (strict) {
      if (pending.trim() || !seenJson || !terminal) throw protocolFailure();
    } else if (pending && !/(?:event:\s*(?:error|response\.(?:failed|incomplete))|"type"\s*:\s*"(?:error|response\.(?:failed|incomplete))")/.test(pending) && !pending.includes(accessToken)) yield Buffer.from(pending);
  } catch (error) {
    if (signal.aborted) throw error;
    throw protocolFailure();
  } finally { signal.removeEventListener('abort', abort); await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

function object(value: unknown): Record<string, unknown> { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function jwtClaims(token: string): Record<string, unknown> { try { return object(JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8'))); } catch { return {}; } }
function bindingOf(accountId: string, userId: string): string { return `codex:${createHash('sha256').update(JSON.stringify([accountId, userId])).digest('hex')}`; }
function tokenHash(token: string): string { return createHash('sha256').update(token).digest('hex'); }
function problem(code: string, message: string, status = 400): ShareError { return new ShareError(code, message, status); }
function sanitized(error: unknown): { code: string; message: string } { return error instanceof ShareError ? { code: error.code, message: error.message } : { code: 'SHARE_CODEX_UNAVAILABLE', message: '本机 Codex 账户检查失败，请在共享端重新检查登录。' }; }
function rejection(status: number, code: string, message: string): UpstreamResponse {
  return { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-share-adapter': 'subscription' }, body: (async function* () { yield Buffer.from(JSON.stringify({ error: { code, message } })); })() };
}

function sanitizeFailureEvent(event: string, accessToken: string): string {
  const data = event.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => line.slice(5).replace(/^ /, '')).join('\n');
  if (!data || data === '[DONE]') {
    if (event.includes(accessToken)) throw problem('SHARE_UPSTREAM_PROTOCOL_INVALID', 'Codex 返回了不应公开的认证材料。', 502);
    return event;
  }
  let value: Record<string, unknown>;
  try { value = object(JSON.parse(data)); } catch {
    if (event.includes(accessToken) || /event:\s*(?:error|response\.(?:failed|incomplete))/.test(event)) throw problem('SHARE_UPSTREAM_PROTOCOL_INVALID', 'Codex 返回了无法识别的错误事件。', 502);
    return event;
  }
  if (['error', 'response.failed', 'response.incomplete'].includes(String(value.type))) {
    const error = { code: 'SHARE_UPSTREAM_REJECTED', message: 'Codex 上游未完成请求，私密错误详情未转发。' };
    const original = object(value.response);
    const response = value.type === 'error' ? {} : { response: { ...(typeof original.id === 'string' && /^resp_[A-Za-z0-9_-]{1,120}$/.test(original.id) ? { id: original.id } : {}), status: value.type === 'response.failed' ? 'failed' : 'incomplete', output: [], error } };
    return `event: ${value.type}\ndata: ${JSON.stringify({ type: value.type, ...(Number.isSafeInteger(value.sequence_number) ? { sequence_number: value.sequence_number } : {}), ...response, ...(value.type === 'error' ? error : {}) })}\n\n`;
  }
  if (event.includes(accessToken)) throw problem('SHARE_UPSTREAM_PROTOCOL_INVALID', 'Codex 返回了不应公开的认证材料。', 502);
  return event;
}
