import { assertExperimentalSubscriptionEnabled } from '../upstream/experimental.js';
import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { HubClient } from '../hub-client/index.js';
import { MAX_BODY_BYTES, ShareError, type Grant } from '../protocol/index.js';
import type { ClientRequest, ClientSession, ClientSource, RunLeaseResponse } from '../protocol/client.js';
import { equalToken, randomToken, safeError } from '../protocol/security.js';
import { serializeClientError } from '../protocol/client-errors.js';
import { ResponseObserver } from '../upstream/observer.js';
import { NativeCodexLauncher, type CodexLauncher, type TerminalHandle } from './launcher.js';

export { detectCodex, inspectCodexPath, NativeCodexLauncher } from './launcher.js';
export type { CodexInstallation, CodexLauncher, LauncherInput, TerminalHandle } from './launcher.js';

export interface BridgeEvent { type: 'request.started' | 'request.finished' | 'request.attention'; operationId: string; requestId?: string; code?: string; message?: string }
export interface ConsumerBridgeOptions {
  hub: HubClient; sessionId: string; leaseId: string; model: string;
  getLeaseToken(): Promise<string>;
  onEvent?: (event: BridgeEvent) => void;
  maxBodyBytes?: number;
}
export interface ConsumerBridge {
  /** Only pass to the owned launcher. Neither localKey nor the endpoint is a Hub credential. */
  readonly url: string;
  readonly localKey: string;
  snapshot(): { active: boolean; blocked: boolean; pendingDeliveryAcks: number; closed: boolean };
  reconcile(): Promise<void>;
  close(): Promise<void>;
}
interface Delivery { requestId: string; operationId: string; outcome: 'transport_finished' | 'lost' }
interface ActiveRequest { controller: AbortController; phase: 'request' | 'ack'; done: Promise<void>; resolve(): void }

/** One fixed session/run lease per listener. No browser, arbitrary URL, or account routing surface. */
export async function createConsumerBridge(options: ConsumerBridgeOptions): Promise<ConsumerBridge> {
  const localKey = randomToken('local');
  const acknowledgements = new Map<string, Delivery>();
  let active: ActiveRequest | null = null;
  let closed = false;
  let blocked = false;
  let port = 0;
  let closePromise: Promise<void> | null = null;
  let ackTimer: NodeJS.Timeout | null = null;
  let ackRetries = 0;
  const emit = (event: BridgeEvent) => { try { options.onEvent?.(event); } catch { /* UI callbacks cannot interrupt transfer state. */ } };
  const server = createServer((req, res) => {
    void handle(req, res).catch(error => {
      const result = safeError(error);
      if (!res.headersSent && !res.destroyed) { res.writeHead(result.status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify({ error: { code: result.code, message: result.message } })); }
      else if (!res.destroyed) res.destroy();
    });
  });
  server.headersTimeout = 10000;
  server.requestTimeout = 30000;
  server.maxHeadersCount = 32;
  server.on('clientError', (_error, socket) => { if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); port = (server.address() as AddressInfo).port; resolve(); }); });

  async function acknowledge(delivery: Delivery): Promise<void> {
    await options.hub.request('POST', `/client/v2/requests/${encodeURIComponent(delivery.requestId)}/delivery-ack`, { operationId: delivery.operationId, outcome: delivery.outcome });
    acknowledgements.delete(delivery.operationId);
  }
  async function reconcile(): Promise<void> {
    for (const delivery of [...acknowledgements.values()]) {
      await acknowledge(delivery);
      if (delivery.outcome === 'transport_finished' && !blocked) emit({ type: 'request.finished', operationId: delivery.operationId, requestId: delivery.requestId });
    }
    ackRetries = 0;
    // An unresolved execution or a lost delivery is never cleared just by replaying an ACK.
  }
  function scheduleAcknowledgements(): void {
    if (closed || ackTimer || !acknowledgements.size || ackRetries >= 3) return;
    ackTimer = setTimeout(() => { ackTimer = null; ackRetries++; void reconcile().catch(() => scheduleAcknowledgements()); }, ackRetries ? 5000 : 1000);
    ackTimer.unref();
  }
  async function lookupRequest(operationId: string): Promise<string | undefined> {
    try { const result = await options.hub.request<{ request: ClientRequest }>('GET', `/client/v2/sessions/${encodeURIComponent(options.sessionId)}/operations/${encodeURIComponent(operationId)}`); return result.request?.id; }
    catch { return undefined; }
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (closed) throw new ShareError('SHARE_BRIDGE_CLOSED', '本机会话入口已关闭。', 503);
    if (req.headers.host !== `127.0.0.1:${port}` || req.headers.origin !== undefined || req.method === 'OPTIONS') throw new ShareError('SHARE_LOCAL_ORIGIN_REJECTED', '本机会话入口不接受浏览器或其他主机访问。', 403);
    const authorization = req.headers.authorization;
    if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ') || !equalToken(authorization.slice(7), localKey)) throw new ShareError('SHARE_LOCAL_AUTH_INVALID', '本机会话凭据无效。', 401);
    const path = req.url ?? '';
    const isModel = path === '/v1/models' && req.method === 'GET';
    const isInference = ['/v1/responses', '/v1/responses/compact'].includes(path) && req.method === 'POST';
    if (!isModel && !isInference) throw new ShareError('SHARE_PATH_UNSUPPORTED', '本机入口只支持已验证的模型路径。', 404);
    if (isModel) {
      // The fixed launch model is the only model this local credential is allowed to select.
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ object: 'list', data: [{ id: options.model, object: 'model', owned_by: 'share-token' }] })); return;
    }
    if (blocked) throw new ShareError('SHARE_DELIVERY_PENDING', '此会话有待核实的执行或交付结果，不能自动重试模型请求。', 409);
    if (active?.phase === 'ack') {
      // A normal next tool turn may arrive immediately after local HTTP.finish.
      await Promise.race([active.done, new Promise<void>(resolve => { const timer = setTimeout(resolve, 5000); timer.unref(); })]);
    }
    if (active) throw new ShareError('SHARE_BUSY', '本机会话已有一个模型请求在处理。', 429);
    if (blocked || acknowledgements.size) throw new ShareError('SHARE_DELIVERY_PENDING', '上一请求的交付回执待确认。', 409);
    if (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity') throw new ShareError('SHARE_ENCODING_UNSUPPORTED', '本机入口不接受压缩请求正文。', 415);
    if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] ?? '')) throw new ShareError('SHARE_CONTENT_TYPE_INVALID', '模型请求需要 application/json。', 415);
    const controller = new AbortController();
    let resolveActive!: () => void;
    const current: ActiveRequest = { controller, phase: 'request', done: new Promise<void>(resolve => { resolveActive = resolve; }), resolve: () => resolveActive() };
    active = current;
    const operationId = randomUUID();
    let requestId: string | undefined;
    let attempted = false;
    let completeTransport = false;
    let terminalKnown = false;
    let responseStatus: number | undefined;
    const abort = () => { if (!res.writableFinished) controller.abort(new Error('consumer disconnected')); };
    const timeout = setTimeout(() => controller.abort(new Error('request deadline')), 15 * 60_000); timeout.unref();
    req.once('aborted', abort); res.once('close', abort);
    try {
      const body = await readBody(req, options.maxBodyBytes ?? MAX_BODY_BYTES);
      let value: unknown;
      try { value = JSON.parse(body.toString('utf8')); } catch { throw new ShareError('SHARE_INPUT_INVALID', '模型请求正文不是有效 JSON。'); }
      if (!value || typeof value !== 'object' || Array.isArray(value) || (value as Record<string, unknown>).model !== options.model) throw new ShareError('SHARE_MODEL_FORBIDDEN', '本次会话固定使用启动时选择的模型。', 403);
      const token = await options.getLeaseToken();
      if (closed || controller.signal.aborted) throw new ShareError('SHARE_CANCELLED_NOT_SENT', '请求在发送前已停止。', 409);
      attempted = true;
      emit({ type: 'request.started', operationId });
      const upstream = await options.hub.dataRequest(path, { method: 'POST', token, body, operationId, signal: controller.signal });
      responseStatus = upstream.status;
      requestId = validRequestId(upstream.headers.get('x-share-request-id'));
      const streaming = (upstream.headers.get('content-type') ?? '').includes('text/event-stream');
      const observer = new ResponseObserver(streaming, path.endsWith('/compact') ? 'compact' : 'responses');
      res.statusCode = upstream.status;
      for (const key of ['content-type', 'retry-after', 'x-request-id', 'x-share-request-id']) { const value = upstream.headers.get(key); if (value) res.setHeader(key, value); }
      // fetch may decode upstream Content-Encoding. Never retain the old encoding/length headers.
      res.setHeader('cache-control', 'no-store');
      if (streaming) {
        res.setHeader('x-accel-buffering', 'no');
        // Keep streaming HTTP framing even when a short response consists only of the tail.
        res.flushHeaders();
      }
      const reader = upstream.body?.getReader();
      const terminalTail: Uint8Array[] = []; let terminalTailBytes = 0, holdingTerminal = false;
      try {
        if (reader) while (true) {
          const chunk = await reader.read(); if (chunk.done) break;
          observer.feed(chunk.value);
          // Codex stops reading as soon as a complete Responses terminal event arrives.
          // Keep its final framing bytes until Hub EOF, then send them with HTTP.end so
          // normal protocol completion cannot race an unfinished local HTTP response.
          if (streaming && (holdingTerminal || observer.terminal !== null && !observer.malformed)) {
            holdingTerminal = true; terminalTailBytes += chunk.value.byteLength;
            if (terminalTailBytes > MAX_BODY_BYTES) throw new ShareError('SHARE_UPSTREAM_PROTOCOL_INVALID', '响应终结后的数据超过本机处理上限，请核实本次执行结果。', 502);
            terminalTail.push(chunk.value);
            continue;
          }
          for (let offset = 0; offset < chunk.value.byteLength; offset += 32 * 1024) {
            if (controller.signal.aborted) throw new ShareError('SHARE_CONSUMER_DISCONNECTED', '消费端连接已中断。', 409);
            if (!res.write(chunk.value.subarray(offset, offset + 32 * 1024))) await waitForDrain(res, controller.signal);
          }
        }
      } catch (error) { await reader?.cancel().catch(() => undefined); throw error; }
      finally { reader?.releaseLock(); }
      terminalKnown = observer.finish(upstream.status) !== 'UNKNOWN';
      if (!terminalKnown) blocked = true;
      await finishResponse(res, terminalTailBytes ? Buffer.concat(terminalTail, terminalTailBytes) : undefined);
      completeTransport = true;
      current.phase = 'ack';
      if (!requestId && responseStatus < 400) requestId = await lookupRequest(operationId);
      if (requestId) {
        const delivery: Delivery = { requestId, operationId, outcome: 'transport_finished' };
        acknowledgements.set(operationId, delivery);
        await acknowledge(delivery);
      } else if (responseStatus < 400) {
        blocked = true;
        throw new ShareError('SHARE_DELIVERY_PENDING', '模型响应缺少可核实的请求归属，当前会话已阻挡后续请求。', 409);
      }
      if (responseStatus === 401) {
        blocked = true;
        emit({ type: 'request.attention', operationId, requestId, code: 'SHARE_LEASE_AUTH_INVALID', message: '此运行授权已失效，本机会话正在停止。' });
      } else emit(terminalKnown ? { type: 'request.finished', operationId, requestId } : { type: 'request.attention', operationId, requestId, code: 'SHARE_RESULT_UNKNOWN', message: '响应没有可验证的终态，请核实后再继续。' });
    } catch (error) {
      if (attempted) {
        current.phase = 'ack';
        if (!completeTransport) {
          blocked = true;
          requestId ??= await lookupRequest(operationId);
          if (requestId) {
            const delivery: Delivery = { requestId, operationId, outcome: 'lost' };
            acknowledgements.set(operationId, delivery);
            await acknowledge(delivery).catch(() => undefined);
          }
        }
        const safe = safeError(error);
        emit({ type: 'request.attention', operationId, requestId, code: completeTransport ? 'SHARE_DELIVERY_PENDING' : 'SHARE_RESULT_UNKNOWN', message: completeTransport ? '本地响应已写完，但交付回执尚未确认。' : safe.message });
        scheduleAcknowledgements();
      }
      throw error;
    } finally {
      clearTimeout(timeout); req.removeListener('aborted', abort); res.removeListener('close', abort);
      if (active === current) active = null;
      current.resolve();
    }
  }

  return {
    url: `http://127.0.0.1:${port}/v1`, localKey,
    snapshot: () => ({ active: active !== null, blocked, pendingDeliveryAcks: acknowledgements.size, closed }),
    reconcile,
    close() {
      if (closePromise) return closePromise;
      closed = true; active?.controller.abort(new Error('bridge closed'));
      if (ackTimer) clearTimeout(ackTimer);
      closePromise = new Promise<void>(resolve => { server.close(() => resolve()); server.closeAllConnections(); });
      return closePromise;
    },
  };
}

async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const announced = Number(req.headers['content-length']);
  if (Number.isFinite(announced) && announced > limit) throw new ShareError('SHARE_BODY_TOO_LARGE', '模型请求超过本机大小限制。', 413);
  const chunks: Buffer[] = []; let size = 0;
  for await (const raw of req) { const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw); size += chunk.length; if (size > limit) throw new ShareError('SHARE_BODY_TOO_LARGE', '模型请求超过本机大小限制。', 413); chunks.push(chunk); }
  return Buffer.concat(chunks);
}
function waitForDrain(res: ServerResponse, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const done = () => { cleanup(); resolve(); };
    const fail = () => { cleanup(); reject(new ShareError('SHARE_CONSUMER_DISCONNECTED', '消费端连接已中断。', 409)); };
    const cleanup = () => { res.removeListener('drain', done); res.removeListener('close', fail); res.removeListener('error', fail); signal.removeEventListener('abort', fail); };
    res.once('drain', done); res.once('close', fail); res.once('error', fail); signal.addEventListener('abort', fail, { once: true });
    if (signal.aborted || res.destroyed) fail();
  });
}
function finishResponse(res: ServerResponse, tail?: Uint8Array): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = () => { res.removeListener('finish', done); res.removeListener('close', fail); res.removeListener('error', fail); };
    const done = () => { cleanup(); resolve(); };
    const fail = () => { cleanup(); reject(new ShareError('SHARE_CONSUMER_DISCONNECTED', '消费端未完成响应接收。', 409)); };
    res.once('finish', done); res.once('close', fail); res.once('error', fail);
    if (res.destroyed) fail(); else res.end(tail);
  });
}
function validRequestId(value: string | null): string | undefined { return value && /^[a-zA-Z0-9_.:-]{1,128}$/.test(value) ? value : undefined; }

export interface ConsumerCreateInput { grantId: string; model: string; cwd: string; codexPath: string; cols?: number; rows?: number }
export interface ConsumerSessionSnapshot {
  sessionId: string; leaseId: string; grantId: string; sourceId: string; model: string; cwd: string; codexPath: string;
  state: 'starting' | 'running' | 'requesting' | 'attention' | 'stopping' | 'stopped' | 'failed';
  createdAt: number; expiresAt: number; pid: number | null; lastRequestId: string | null; message: string | null;
  errorCode?: string | null; exitCode?: number | null; exitSignal?: number | null; terminalStarted?: boolean;
}
export type ConsumerEvent = { type: 'session.updated'; session: ConsumerSessionSnapshot } | { type: 'terminal.data'; sessionId: string; data: string } | { type: 'terminal.exit'; sessionId: string; exitCode: number; signal?: number } | { type: 'error'; sessionId?: string; code: string; message: string };
export interface ConsumerControllerOptions { hub: HubClient; launcher?: CodexLauncher; onEvent?: (event: ConsumerEvent) => void }
interface RunningSession { session: ClientSession; auth: RunLeaseResponse; view: ConsumerSessionSnapshot; bridge: ConsumerBridge | null; terminal: TerminalHandle | null; renewal: NodeJS.Timeout | null; renewing: Promise<string> | null; closing: Promise<void> | null; stopRequested: boolean; exited: boolean; failure: { code: string; message: string } | null }

export class ConsumerController {
  private readonly sessions = new Map<string, RunningSession>();
  private readonly creating = new Set<Promise<ConsumerSessionSnapshot>>();
  private readonly launcher: CodexLauncher;
  private readonly unsubscribeInvalidation: () => void;
  private closed = false;
  constructor(private readonly options: ConsumerControllerOptions) {
    this.launcher = options.launcher ?? new NativeCodexLauncher();
    this.unsubscribeInvalidation = options.hub.onCredentialsInvalidated(() => {
      for (const id of this.sessions.keys()) void this.stop(id).catch(error => this.emitError(error, id));
    });
  }

  snapshot(): ConsumerSessionSnapshot[] { return [...this.sessions.values()].map(run => ({ ...run.view })); }
  create(input: ConsumerCreateInput): Promise<ConsumerSessionSnapshot> {
    const result = this.createSession(input);
    this.creating.add(result);
    void result.finally(() => this.creating.delete(result)).catch(() => undefined);
    return result;
  }
  private async createSession(input: ConsumerCreateInput): Promise<ConsumerSessionSnapshot> {
    if (this.closed) throw new ShareError('SHARE_CONSUMER_CLOSED', '消费工作进程正在退出。', 503);
    if (!input.grantId || !/^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$/.test(input.model)) throw new ShareError('SHARE_INPUT_INVALID', '请选择有效的接入授权和模型。');
    const [grantResult, sourceResult] = await Promise.all([
      this.options.hub.request<{ grants: Grant[] }>('GET', '/client/v2/grants'),
      this.options.hub.request<{ sources: ClientSource[] }>('GET', '/client/v2/sources'),
    ]);
    if (this.closed) throw new ShareError('SHARE_CONSUMER_CLOSED', '消费工作进程正在退出。', 503);
    const grant = grantResult.grants.find(grant => grant.id === input.grantId);
    const source = sourceResult.sources.find(source => source.id === grant?.sourceId);
    if (!grant || grant.revoked || (grant.expiresAt !== null && grant.expiresAt <= Date.now()) || !grant.models.includes(input.model)) throw new ShareError('SHARE_GRANT_INVALID', '授权无效、已到期或不允许该模型。', 403);
    if (!source || !((source.kind === 'mock' && source.clientMode === 'mock-v1-compatibility') || (source.kind === 'subscription' && source.clientMode === 'subscription-v1-compatibility'))) throw new ShareError('SHARE_DESKTOP_CHANNEL_UNAVAILABLE', '此来源未声明兼容的模拟或订阅通道，请刷新来源或升级 Hub。', 501);
    if (source.kind === 'subscription') assertExperimentalSubscriptionEnabled();
    const { session } = await this.options.hub.request<{ session: ClientSession }>('POST', '/client/v2/sessions', { grantId: grant.id, modelScope: [input.model], requestNonce: randomUUID() });
    if (session.grantId !== grant.id || session.sourceId !== source.id || !session.modelScope.includes(input.model)) throw new ShareError('SHARE_SESSION_BINDING_INVALID', 'Hub 会话来源与所选授权不一致。', 502);
    if (this.closed) { await this.options.hub.request('POST', `/client/v2/sessions/${encodeURIComponent(session.id)}/close`, {}).catch(() => undefined); throw new ShareError('SHARE_CONSUMER_CLOSED', '消费工作进程正在退出。', 503); }
    let auth: RunLeaseResponse;
    try { auth = await this.options.hub.request<RunLeaseResponse>('POST', `/client/v2/sessions/${encodeURIComponent(session.id)}/leases`, {}); }
    catch (error) { await this.options.hub.request('POST', `/client/v2/sessions/${encodeURIComponent(session.id)}/close`, {}).catch(() => undefined); throw error; }
    if (auth.lease.sessionId !== session.id || auth.lease.deviceId !== this.options.hub.getCredentials()?.deviceId || auth.lease.state !== 'active' || !auth.token || auth.lease.expiresAt <= Date.now()) {
      await Promise.allSettled([
        this.options.hub.request('POST', `/client/v2/run-leases/${encodeURIComponent(auth.lease.id)}/close`, {}),
        this.options.hub.request('POST', `/client/v2/sessions/${encodeURIComponent(session.id)}/close`, {}),
      ]);
      throw new ShareError('SHARE_LEASE_BINDING_INVALID', '运行授权与当前会话不一致。', 502);
    }
    const run: RunningSession = { session, auth, view: { sessionId: session.id, leaseId: auth.lease.id, grantId: grant.id, sourceId: source.id, model: input.model, cwd: input.cwd, codexPath: input.codexPath, state: 'starting', createdAt: Date.now(), expiresAt: auth.lease.expiresAt, pid: null, lastRequestId: null, message: null, errorCode: null, exitCode: null, exitSignal: null, terminalStarted: false }, bridge: null, terminal: null, renewal: null, renewing: null, closing: null, stopRequested: false, exited: false, failure: null };
    this.sessions.set(session.id, run); this.update(run);
    try {
      if (this.closed) throw new ShareError('SHARE_CONSUMER_CLOSED', '消费工作进程正在退出。', 503);
      run.bridge = await createConsumerBridge({ hub: this.options.hub, sessionId: session.id, leaseId: auth.lease.id, model: input.model, getLeaseToken: () => this.leaseToken(run), onEvent: event => {
        if (run.closing || run.failure || run.view.state === 'stopping' || run.view.state === 'stopped') return;
        run.view.state = event.type === 'request.started' ? 'requesting' : event.type === 'request.attention' ? 'attention' : 'running';
        if (event.requestId) run.view.lastRequestId = event.requestId;
        run.view.message = event.message ?? null; this.update(run);
        if (event.code === 'SHARE_LEASE_AUTH_INVALID') {
          void this.stop(session.id).catch(error => this.emitError(error, session.id));
          // A lease failure may be local to this lease. Only device-level 401 clears login.
          void this.options.hub.request('GET', '/client/v2/me').catch(() => undefined);
        }
      } });
      run.terminal = await this.launcher.start({ codexPath: input.codexPath, cwd: input.cwd, model: input.model, baseUrl: run.bridge.url, localKey: run.bridge.localKey, cols: input.cols, rows: input.rows,
        onData: data => this.emit({ type: 'terminal.data', sessionId: session.id, data }),
        onExit: event => {
          if (run.exited) return;
          run.exited = true; run.view.terminalStarted = true;
          run.view.exitCode = event.exitCode; run.view.exitSignal = event.signal || null;
          if (!run.stopRequested && (event.exitCode !== 0 || !!event.signal)) this.recordFailure(run, { code: 'SHARE_CODEX_EXITED' });
          this.emit({ type: 'terminal.exit', sessionId: session.id, ...event });
          void this.stop(session.id).catch(error => this.emitError(error, session.id));
        },
      });
      run.view.terminalStarted = true;
      if (run.closing) { await run.terminal.stop(); await run.closing; this.update(run); return { ...run.view }; }
      run.view.pid = run.terminal.pid; run.view.state = 'running'; this.update(run); this.scheduleRenewal(run);
      if (this.closed) await this.stop(session.id);
      return { ...run.view };
    } catch (error) {
      const failure = this.recordFailure(run, error, 'SHARE_TERMINAL_START_FAILED');
      await this.stop(session.id);
      throw new ShareError(failure.code, failure.message, failure.status);
    }
  }

  write(sessionId: string, data: string): void {
    const run = this.owned(sessionId);
    if (typeof data !== 'string' || Buffer.byteLength(data) > 64 * 1024) throw new ShareError('SHARE_TERMINAL_INPUT_INVALID', '终端输入超出限制。');
    if (!run.terminal || ['stopped', 'stopping', 'failed'].includes(run.view.state)) throw new ShareError('SHARE_TERMINAL_CLOSED', '终端已经停止。', 409);
    run.terminal.write(data);
  }
  resize(sessionId: string, cols: number, rows: number): void {
    const run = this.owned(sessionId);
    if (!Number.isInteger(cols) || !Number.isInteger(rows) || cols < 20 || cols > 500 || rows < 5 || rows > 300) throw new ShareError('SHARE_TERMINAL_SIZE_INVALID', '终端尺寸超出支持范围。');
    run.terminal?.resize(cols, rows);
  }
  async reconcile(sessionId: string): Promise<void> { await this.owned(sessionId).bridge?.reconcile(); }
  async stop(sessionId: string): Promise<void> {
    const run = this.owned(sessionId);
    run.stopRequested = true;
    if (run.closing) return run.closing;
    run.view.state = 'stopping'; this.update(run);
    if (run.renewal) clearTimeout(run.renewal);
    run.closing = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([
        run.bridge?.close(), run.terminal?.stop(),
        this.options.hub.request('POST', `/client/v2/run-leases/${encodeURIComponent(run.auth.lease.id)}/close`, {}),
        this.options.hub.request('POST', `/client/v2/sessions/${encodeURIComponent(run.session.id)}/close`, {}),
      ]);
      const terminalError = results[1]?.status === 'rejected';
      const closeError = results[2]?.status === 'rejected' || results[3]?.status === 'rejected';
      run.view.state = terminalError ? 'attention' : run.failure ? 'failed' : 'stopped';
      const cleanupNotes = [terminalError ? '本机 Codex 退出尚未确认。' : null, closeError ? 'Hub 的会话或运行授权关闭尚未确认；不会自动重放请求。' : null].filter(Boolean);
      run.view.message = [run.failure?.message, ...cleanupNotes].filter(Boolean).join(' ') || null;
      if (!terminalError) run.view.pid = null;
      this.update(run);
    });
    return run.closing;
  }
  async close(): Promise<void> {
    this.closed = true; this.unsubscribeInvalidation();
    await Promise.allSettled([...this.creating, ...[...this.sessions.keys()].map(id => this.stop(id))]);
    await Promise.all([...this.sessions.keys()].map(id => this.stop(id)));
  }

  private async leaseToken(run: RunningSession): Promise<string> {
    if (run.closing || this.closed) throw new ShareError('SHARE_LEASE_CLOSED', '运行授权已关闭。', 403);
    if (run.auth.lease.expiresAt > Date.now() + 30_000) return run.auth.token;
    try { return await this.renew(run); }
    catch (error) { this.emitError(error, run.session.id); void this.stop(run.session.id).catch(() => undefined); throw error; }
  }
  private async renew(run: RunningSession): Promise<string> {
    if (run.renewing) return run.renewing;
    run.renewing = (async () => {
      const result = await this.options.hub.request<RunLeaseResponse>('POST', `/client/v2/run-leases/${encodeURIComponent(run.auth.lease.id)}/renew`, {});
      const previous = run.auth.lease;
      if (result.lease.id !== previous.id || result.lease.sessionId !== previous.sessionId || result.lease.deviceId !== previous.deviceId || result.lease.epoch !== previous.epoch || result.lease.state !== 'active' || result.lease.expiresAt <= Date.now() || !result.token) throw new ShareError('SHARE_LEASE_BINDING_INVALID', '运行授权更新改变了会话归属，已拒绝。', 502);
      if (run.closing || this.closed) throw new ShareError('SHARE_LEASE_CLOSED', '会话正在停止。', 403);
      run.auth = result; run.view.expiresAt = result.lease.expiresAt; this.scheduleRenewal(run); this.update(run); return result.token;
    })().finally(() => { run.renewing = null; });
    return run.renewing;
  }
  private scheduleRenewal(run: RunningSession): void {
    if (run.renewal) clearTimeout(run.renewal);
    if (run.closing || this.closed) return;
    run.renewal = setTimeout(() => { void this.renew(run).catch(async error => { this.emitError(error, run.session.id); await this.stop(run.session.id); run.view.message = '运行授权更新失败，本机会话已停止；请核实设备和来源状态。'; this.update(run); }); }, Math.max(1000, run.auth.lease.expiresAt - Date.now() - 60_000));
    run.renewal.unref();
  }
  private owned(id: string): RunningSession { const run = this.sessions.get(id); if (!run) throw new ShareError('SHARE_SESSION_NOT_FOUND', '当前工作进程没有这个会话。', 404); return run; }
  private recordFailure(run: RunningSession, error: unknown, fallback?: string) {
    let failure = serializeClientError(error);
    if (fallback && failure.code === 'SHARE_CLIENT_ERROR') failure = serializeClientError({ code: fallback });
    run.failure = { code: failure.code, message: failure.message };
    run.view.errorCode = failure.code; run.view.message = failure.message; run.view.state = 'failed'; this.update(run);
    return failure;
  }
  private update(run: RunningSession): void { this.emit({ type: 'session.updated', session: { ...run.view } }); }
  private emit(event: ConsumerEvent): void { try { this.options.onEvent?.(event); } catch { /* Event observers cannot widen permissions or block cleanup. */ } }
  private emitError(error: unknown, sessionId?: string): void { const value = serializeClientError(error); this.emit({ type: 'error', sessionId, code: value.code, message: value.message }); }
}
