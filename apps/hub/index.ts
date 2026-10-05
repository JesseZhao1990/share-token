import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { WebSocket, WebSocketServer } from 'ws';
import { z } from 'zod';
import { ClientStore, type InferenceAuth, type RelayAuth } from '../../packages/storage/client.js';
import { createClientRouter } from './client-v2.js';
import { Store, type Credential } from '../../packages/storage/index.js';
import { loadSharedCodeVerifier } from '../../packages/storage/shared-code.js';
import { checkAdmission } from '../../packages/policy/index.js';
import { equalToken, safeError } from '../../packages/protocol/security.js';
import { MAX_BODY_BYTES, MAX_BUFFER_BYTES, CHUNK_BYTES, EMPTY_USAGE, ShareError, adapterKindSchema, policySchema, relayFrameSchema, isTerminal, type HubFrame, type RelayFrame, type Source, type Grant, type Member, type RequestRecord, type Dashboard, type Operation } from '../../packages/protocol/index.js';

interface NodeConnection { ws: WebSocket; sourceId: string; fence: number; ready: boolean; paused: boolean; lastSeen: number; credential: Credential | null; deviceId?: string; relayLeaseId?: string }
interface Pending { record: RequestRecord; body: Buffer; res: ServerResponse; timer: NodeJS.Timeout; credit: number; sequence: number; head: boolean; queuedCredit: number; drainListener: boolean; deliveryWaitDeadline?: number }
export interface HubOptions { dbPath: string; adminToken: string; host?: string; port?: number; staticDir?: string; queueTimeoutMs?: number; sharedCodePath?: string }
const nameSchema = z.string().trim().min(1).max(80);
const credentialsError = () => new ShareError('SHARE_AUTH_INVALID', '登录或接入凭据无效。', 401);
const notFound = () => new ShareError('SHARE_NOT_FOUND', '资源不存在或无权访问。', 404);
const COOKIE = 'share_session';
const terminalStates = new Set(['COMPLETED', 'FAILED_KNOWN', 'CANCELLED_NOT_SENT', 'UNKNOWN']);

export async function createHub(options: HubOptions): Promise<{ url: string; close(): Promise<void>; store: Store }> {
  if (options.adminToken.length < 24) throw new ShareError('SHARE_CONFIG_INVALID', '管理员凭据至少需要 24 个字符。');
  await loadSharedCodeVerifier(options.sharedCodePath);
  const store = new Store(options.dbPath);
  let clients: ClientStore;
  try { store.acquireHubLease(); clients = new ClientStore(store); store.ensureAdmin(options.adminToken); store.recoverInterrupted(); clients.recoverInterrupted(); }
  catch (error) { store.close(); throw error; }
  const nodes = new Map<string, NodeConnection>();
  const pending = new Map<string, Pending>();
  const modelReaders = new Set<string>();
  let closing = false;
  let closed = false;
  const queueTimeoutMs = options.queueTimeoutMs ?? 30_000;
  function assertSiblingRelayIdle(sourceId: string) {
    if (store.accountSiblingSources(sourceId).some(sibling => nodes.has(sibling.id))) throw new ShareError('SHARE_RELAY_BUSY', '该订阅已有共享连接。', 409);
  }

  const bearer = (req: IncomingMessage) => /^Bearer ([^\s]+)$/i.exec(req.headers.authorization ?? '')?.[1] ?? '';
  const cookieToken = (req: IncomingMessage) => req.headers.cookie?.split(';').map(item => item.trim()).find(item => item.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1) ?? '';
  function originCheck(req: IncomingMessage) {
    const origin = req.headers.origin;
    if (req.headers['sec-fetch-site'] === 'cross-site') throw new ShareError('SHARE_CSRF_INVALID', '请求来源不被允许。', 403);
    if (origin) {
      let url: URL; try { url = new URL(origin); } catch { throw new ShareError('SHARE_CSRF_INVALID', '请求来源无效。', 403); }
      if (url.host !== req.headers.host || !['http:', 'https:'].includes(url.protocol)) throw new ShareError('SHARE_CSRF_INVALID', '请求来源不被允许。', 403);
    }
  }
  function controlAuth(req: IncomingMessage, mutate = false): { member: Member; credential: Credential } {
    const token = bearer(req);
    const credential = token ? store.authenticate(token, 'control') : store.authenticate(cookieToken(req), 'session');
    if (!credential) throw credentialsError();
    if (mutate && !token) {
      originCheck(req);
      if (!credential.csrfToken || typeof req.headers['x-csrf-token'] !== 'string' || !equalToken(credential.csrfToken, req.headers['x-csrf-token'])) throw new ShareError('SHARE_CSRF_INVALID', '页面会话校验失败，请刷新页面。', 403);
    }
    return { member: store.getMember(credential.memberId)!, credential };
  }
  function requireAdmin(member: Member) { if (member.role !== 'admin') throw new ShareError('SHARE_FORBIDDEN', '此操作需要管理员权限。', 403); }
  function ownedSource(member: Member, id: string) { const source = store.getSource(id); if (!source || !clients.sameRoom(member.id, source.ownerId) || (source.ownerId !== member.id && member.role !== 'admin')) throw notFound(); return source; }
  function ownedGrant(member: Member, id: string) { const grant = store.getGrant(id); const source = grant && store.getSource(grant.sourceId); if (!grant || !clients.grantInRoom(member.id, grant) || (grant.memberId !== member.id && source?.ownerId !== member.id && member.role !== 'admin')) throw notFound(); return grant; }
  function requestInRoom(memberId: string, request: RequestRecord) { return clients.sourceInRoom(memberId, request.sourceId) && clients.sameRoom(memberId, request.memberId); }
  function ownedRequest(member: Member, id: string) { const request = store.getRequest(id); const source = request && store.getSource(request.sourceId); if (!request || !requestInRoom(member.id, request) || (request.memberId !== member.id && source?.ownerId !== member.id && member.role !== 'admin')) throw notFound(); return request; }
  const json = (res: ServerResponse, status: number, value: unknown) => { if (res.destroyed || res.writableEnded) return; res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(value)); };
  function fail(res: ServerResponse, error: unknown) { const safe = safeError(error); if (res.headersSent) { res.destroy(); return; } json(res, safe.status, { error: { code: safe.code, message: safe.message } }); }
  async function body(req: IncomingMessage, limit = MAX_BODY_BYTES): Promise<Buffer> {
    if (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity') throw new ShareError('SHARE_ENCODING_UNSUPPORTED', '当前版本只接受未压缩的 JSON 请求。', 415);
    if (!req.headers['content-type']?.toLowerCase().startsWith('application/json')) throw new ShareError('SHARE_CONTENT_TYPE_INVALID', '请使用 application/json。', 415);
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > limit) throw new ShareError('SHARE_BODY_TOO_LARGE', '请求正文过大。', 413);
    const chunks: Buffer[] = []; let size = 0;
    for await (const chunk of req) { const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); size += bytes.length; if (size > limit) throw new ShareError('SHARE_BODY_TOO_LARGE', '请求正文过大。', 413); chunks.push(bytes); }
    return Buffer.concat(chunks, size);
  }
  function parseJson(buffer: Buffer): unknown { try { return JSON.parse(buffer.toString('utf8')); } catch { throw new ShareError('SHARE_JSON_INVALID', '请求正文不是有效 JSON。'); } }
  async function input<T>(req: IncomingMessage, schema: z.ZodType<T>): Promise<T> { const parsed = schema.safeParse(parseJson(await body(req, 128 * 1024))); if (!parsed.success) throw new ShareError('SHARE_INPUT_INVALID', '请求字段无效，请检查输入。'); return parsed.data; }
  function session(res: ServerResponse, req: IncomingMessage, member: Member) {
    const { token, credential } = store.issueCredential('session', member.id, { expiresAt: Date.now() + 7 * 24 * 3600_000 });
    const secure = ('encrypted' in req.socket && req.socket.encrypted) || (['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress ?? '') && req.headers['x-forwarded-proto'] === 'https');
    res.setHeader('set-cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${secure ? '; Secure' : ''}`);
    return { member, csrfToken: credential.csrfToken };
  }
  function dashboard(member: Member): Dashboard {
    const allSources = store.listSources().filter(source => clients.sameRoom(member.id, source.ownerId));
    const allGrants = store.listGrants().filter(grant => clients.grantInRoom(member.id, grant));
    const sources = allSources.filter(source => member.role === 'admin' || source.ownerId === member.id || source.policy.allowedMemberIds.includes(member.id) || allGrants.some(grant => grant.memberId === member.id && grant.sourceId === source.id && !grant.revoked));
    const owned = new Set(allSources.filter(source => source.ownerId === member.id).map(source => source.id));
    const grants = allGrants.filter(grant => member.role === 'admin' || grant.memberId === member.id || owned.has(grant.sourceId));
    // Filter before limiting so another room cannot hide this room's recent
    // requests. Statistics retain the full visible history, not just 200 rows.
    const visibleRequests = store.listVisibleRequests(member, -1).filter(request => requestInRoom(member.id, request));
    const stats = visibleRequests.reduce((result, request) => ({
      completed: result.completed + Number(request.state === 'COMPLETED'),
      unknown: result.unknown + Number(request.state === 'UNKNOWN'),
      inputTokens: result.inputTokens + (request.usage.inputTokens ?? 0),
      outputTokens: result.outputTokens + (request.usage.outputTokens ?? 0),
    }), { completed: 0, unknown: 0, inputTokens: 0, outputTokens: 0 });
    return { member, sources, grants, requests: visibleRequests.slice(0, 200), members: store.listMembers().filter(candidate => clients.sameRoom(member.id, candidate.id)), stats };
  }
  function send(node: NodeConnection, frame: HubFrame): boolean { if (node.ws.readyState !== WebSocket.OPEN) return false; try { node.ws.send(JSON.stringify(frame)); return true; } catch { return false; } }
  function admission(grant: Grant, model: string, bytes: number, operation: Operation): Source {
    if (grant.revoked || (grant.expiresAt !== null && grant.expiresAt <= Date.now())) throw new ShareError('SHARE_GRANT_REVOKED', '接入授权已撤销或到期。', 403);
    if (grant.frozen) throw new ShareError('SHARE_DELIVERY_LOST', '该接入有未确认交付，请先核实并解除冻结。', 409);
    if (!store.getMember(grant.memberId)?.active) throw credentialsError();
    if (!grant.models.includes(model)) throw new ShareError('SHARE_MODEL_NOT_ALLOWED', '此接入未授权使用该模型。', 403);
    const source = store.getSource(grant.sourceId); if (!source || !clients.sameRoom(grant.memberId, source.ownerId)) throw notFound();
    if (source.frozen) throw new ShareError('SHARE_RESULT_UNKNOWN', '来源存在结果未知的请求，需要贡献者核实。', 409);
    if (source.paused || nodes.get(source.id)?.paused) throw new ShareError('SHARE_SOURCE_PAUSED', '贡献者已暂停共享。', 503);
    const node = nodes.get(source.id);
    if (node?.relayLeaseId && !clients.relayConnectionValid(node.relayLeaseId, node.deviceId!)) { node.ws.terminate(); throw new ShareError('SHARE_RELAY_LEASE_EXPIRED', '贡献设备的授权已撤销或到期，请求未发送。', 503); }
    if (!node?.ready || !source.online || node.ws.readyState !== WebSocket.OPEN) throw new ShareError('SHARE_SOURCE_OFFLINE', '贡献者节点当前离线。', 503);
    const caps = source.capabilities;
    if (!caps?.verified || caps.kind !== source.kind || caps.accountBinding !== source.accountBinding || !caps.models.includes(model) || (operation === 'responses' ? !caps.responses : !caps.compact)) throw new ShareError('SHARE_CAPABILITY_UNAVAILABLE', '此来源尚未确认当前账号、模型或请求能力，请检查共享端状态。', 501);
    const quotaOrigin = { mock: 'mock', api_fixture: 'fixture', subscription: 'codex' }[source.kind];
    if (source.quota?.origin !== quotaOrigin) throw new ShareError('SHARE_QUOTA_STALE', '额度来源与模型供给类型不匹配。', 503);
    checkAdmission({ policy: source.policy, quota: source.quota, memberId: grant.memberId, model, bodyBytes: bytes });
    return source;
  }
  function freezeDelivery(request: RequestRecord, outcome: 'unknown' | 'lost') { if (!clients.freezeRequest(request.id, outcome)) store.updateGrant(request.grantId, { frozen: true }); }
  function release(requestId: string) { const work = pending.get(requestId); if (work) { clearTimeout(work.timer); work.body = Buffer.alloc(0); pending.delete(requestId); } }
  function unknown(requestId: string, code = 'SHARE_RESULT_UNKNOWN') {
    const request = store.getRequest(requestId); if (!request || isTerminal(request.state)) return;
    store.updateRequest(requestId, { state: 'UNKNOWN', errorCode: code, finishedAt: Date.now(), delivery: 'unknown' });
    store.updateSource(request.sourceId, { frozen: true }); freezeDelivery(request, 'unknown');
    const work = pending.get(requestId); if (work) fail(work.res, new ShareError('SHARE_RESULT_UNKNOWN', '上游可能已执行，结果待核实；不会自动重放。', 409));
    release(requestId); flushQueue(request.sourceId);
  }
  function unsent(requestId: string, error: ShareError) {
    const request = store.getRequest(requestId); if (!request || isTerminal(request.state)) return;
    store.updateRequest(requestId, { state: 'CANCELLED_NOT_SENT', errorCode: error.code, finishedAt: Date.now() }); clients.resolveUnsent(requestId);
    const work = pending.get(requestId); if (work) fail(work.res, error); release(requestId);
  }
  function cancel(requestId: string, reason: string) {
    const request = store.getRequest(requestId); if (!request || isTerminal(request.state)) return;
    store.updateRequest(requestId, { cancelRequested: true });
    if (request.state === 'QUEUED' || request.state === 'RESERVED') { unsent(requestId, new ShareError('SHARE_CANCELLED', '请求在发送前已取消。', 409)); flushQueue(request.sourceId); return; }
    const node = nodes.get(request.sourceId);
    if (!node || !send(node, { v: 1, type: 'cancel.request', requestId, fence: request.fence, reason })) { unknown(requestId); return; }
    const work = pending.get(requestId); if (work) { clearTimeout(work.timer); work.timer = setTimeout(() => unknown(requestId, 'SHARE_CANCEL_UNCONFIRMED'), 3000); }
  }
  function dispatch(requestId: string) {
    const work = pending.get(requestId), request = store.getRequest(requestId); if (!work || !request || request.state !== 'RESERVED') return;
    const deliveryBlockers = clients.dispatchDeliveryBlockers(requestId);
    if (deliveryBlockers.length) {
      work.deliveryWaitDeadline ??= Date.now() + 5000;
      if (deliveryBlockers.every(candidate => candidate.consumerDelivery === 'pending') && Date.now() < work.deliveryWaitDeadline) {
        clearTimeout(work.timer); work.timer = setTimeout(() => { if (!closed) dispatch(requestId); }, 25); return;
      }
      for (const candidate of deliveryBlockers) if (candidate.consumerDelivery === 'pending') clients.freezeRequest(candidate.id, 'unknown');
      unsent(requestId, new ShareError('SHARE_DELIVERY_PENDING', '前一条请求的交付尚未确认，当前请求未发送。', 409)); flushQueue(request.sourceId); return;
    }
    let source: Source;
    try { clients.assertDispatch(requestId); const grant = store.getGrant(request.grantId); if (!grant) throw notFound(); source = admission(grant, request.model, work.body.length, request.operation); } catch (error) { unsent(requestId, error instanceof ShareError ? error : new ShareError('SHARE_INTERNAL_ERROR', '准入失败。', 500)); flushQueue(request.sourceId); return; }
    const node = nodes.get(source.id)!;
    clearTimeout(work.timer); work.timer = setTimeout(() => cancel(requestId, 'deadline'), source.policy.maxRequestMs);
    store.updateRequest(requestId, { state: 'DISPATCHED', fence: node.fence });
    const sent = send(node, { v: 1, type: 'request.open', requestId, fence: node.fence, sourceId: source.id, grantId: request.grantId, memberId: request.memberId, operation: request.operation, model: request.model, body: work.body.toString('base64'), deadline: Date.now() + source.policy.maxRequestMs });
    work.body = Buffer.alloc(0);
    if (!sent) { unknown(requestId); return; }
    work.credit = MAX_BUFFER_BYTES;
    send(node, { v: 1, type: 'window.update', requestId, fence: node.fence, bytes: MAX_BUFFER_BYTES });
  }
  function flushQueue(sourceId: string) {
    if (store.activeForSource(sourceId)) return;
    for (const request of store.queuedForSource(sourceId)) {
      if (closing) { unsent(request.id, new ShareError('SHARE_SHUTTING_DOWN', '服务正在关闭。', 503)); continue; }
      const work = pending.get(request.id);
      if (!work) { unknown(request.id, 'SHARE_REQUEST_STATE_LOST'); continue; }
      try { const grant = store.getGrant(request.grantId); if (!grant) throw notFound(); admission(grant, request.model, work.body.length, request.operation); }
      catch (error) { unsent(request.id, error instanceof ShareError ? error : new ShareError('SHARE_INTERNAL_ERROR', '准入失败。', 500)); continue; }
      store.updateRequest(request.id, { state: 'RESERVED' }); dispatch(request.id); break;
    }
  }
  function returnCredit(work: Pending, node: NodeConnection, bytes: number) {
    work.queuedCredit += bytes;
    if (work.res.writableNeedDrain) {
      if (!work.drainListener) { work.drainListener = true; work.res.once('drain', () => { work.drainListener = false; returnCredit(work, node, 0); }); }
      return;
    }
    if (pending.get(work.record.id) !== work || node.fence !== store.getRequest(work.record.id)?.fence) return;
    const credit = Math.min(work.queuedCredit, MAX_BUFFER_BYTES - work.credit);
    if (credit > 0) { work.queuedCredit -= credit; work.credit += credit; send(node, { v: 1, type: 'window.update', requestId: work.record.id, fence: node.fence, bytes: credit }); }
  }
  function safeHeaders(headers: Record<string, string>) {
    const safe: Record<string, string> = {};
    // Allowlist prevents Set-Cookie, authentication, content-length and hop-by-hop propagation.
    for (const key of ['content-type', 'retry-after', 'x-request-id']) { const value = Object.entries(headers).find(([name]) => name.toLowerCase() === key)?.[1]; if (value && !/[\r\n\0]/.test(value)) safe[key] = value; }
    return { ...safe, 'cache-control': 'no-store', 'x-accel-buffering': 'no' };
  }
  function endResponse(node: NodeConnection, frame: Extract<RelayFrame, { type: 'response.end' }>) {
    const request = store.getRequest(frame.requestId), work = pending.get(frame.requestId); if (!request || isTerminal(request.state)) return;
    try { clients.bindResources(request.id, frame.responseIds); store.bindResources(request.sourceId, request.grantId, frame.responseIds); } catch { unknown(request.id, 'SHARE_RESOURCE_CONFLICT'); node.ws.close(1008, 'resource conflict'); return; }
    const state = frame.state;
    if (state === 'CANCELLED_NOT_SENT' && ['UPSTREAM_STARTED', 'STREAMING'].includes(request.state)) { unknown(request.id, 'SHARE_INVALID_TERMINAL'); return; }
    if (state === 'UNKNOWN') { store.updateRequest(request.id, { usage: frame.usage }); unknown(request.id); return; }
    if (state === 'COMPLETED' && !work?.head) { unknown(request.id, 'SHARE_MISSING_RESPONSE'); return; }
    store.updateRequest(request.id, { state, usage: frame.usage, finishedAt: Date.now(), errorCode: frame.errorCode && /^[A-Z0-9_]{1,100}$/.test(frame.errorCode) ? frame.errorCode : null });
    if (state === 'CANCELLED_NOT_SENT') clients.resolveUnsent(request.id);
    if (work) {
      if (work.res.destroyed) { store.updateRequest(request.id, { delivery: 'lost' }); freezeDelivery(request, 'unknown'); }
      else if (!work.head) fail(work.res, new ShareError(state === 'CANCELLED_NOT_SENT' ? 'SHARE_CANCELLED' : 'SHARE_UPSTREAM_FAILED', state === 'CANCELLED_NOT_SENT' ? '请求在发送前取消。' : '上游明确拒绝或执行失败。', 502));
      else work.res.end();
    }
    release(request.id); flushQueue(request.sourceId);
  }
  function reconcile(node: NodeConnection, frame: Extract<RelayFrame, { type: 'status.result' }>, request: RequestRecord) {
    if (request.state !== 'UNKNOWN' || !['COMPLETED', 'FAILED_KNOWN', 'CANCELLED_NOT_SENT'].includes(frame.state)) return;
    // Recovery evidence belongs to the authenticated source and its new connection epoch.
    // No response body is available: retain failed delivery separately from execution success.
    if (frame.state === 'CANCELLED_NOT_SENT' && request.startedAt !== null) return;
    try { clients.bindResources(request.id, frame.responseIds); store.bindResources(request.sourceId, request.grantId, frame.responseIds); }
    catch { node.ws.close(1008, 'resource conflict'); return; }
    store.updateRequest(request.id, { state: frame.state as 'COMPLETED' | 'FAILED_KNOWN' | 'CANCELLED_NOT_SENT', usage: frame.usage, delivery: 'lost', errorCode: 'SHARE_DELIVERY_LOST', finishedAt: Date.now() });
    freezeDelivery(request, 'unknown');
    if (!store.listSourceRequests(request.sourceId).some(candidate => candidate.state === 'UNKNOWN')) store.updateSource(request.sourceId, { frozen: false });
    store.audit(store.getSource(request.sourceId)!.ownerId, 'request.reconcile', request.id);
  }
  function handleFrame(node: NodeConnection, frame: RelayFrame) {
    if (nodes.get(node.sourceId) !== node) return;
    if (frame.type === 'hello') {
      if (node.ready || frame.sourceId !== node.sourceId) throw new ShareError('SHARE_RELAY_INVALID', '节点身份不匹配。');
      const source = store.getSource(node.sourceId)!;
      if (frame.capabilities.kind !== source.kind || frame.capabilities.accountBinding !== source.accountBinding) throw new ShareError('SHARE_RELAY_INVALID', '节点账户绑定不匹配。');
      node.fence = source.fence + 1; node.ready = true; node.lastSeen = Date.now();
      store.updateSource(source.id, { fence: node.fence, online: true, lastSeen: node.lastSeen, quota: frame.quota, capabilities: frame.capabilities });
      send(node, { v: 1, type: 'welcome', sourceId: source.id, fence: node.fence });
      for (const request of store.listSourceRequests(source.id)) if (request.state === 'UNKNOWN') send(node, { v: 1, type: 'status.query', requestId: request.id, fence: node.fence });
      return;
    }
    if (!node.ready || frame.fence !== node.fence) throw new ShareError('SHARE_FENCE_INVALID', '节点连接已过期。');
    node.lastSeen = Date.now();
    if (frame.type === 'heartbeat') { node.paused = frame.paused; store.updateSource(node.sourceId, { quota: frame.quota, lastSeen: node.lastSeen }); return; }
    const request = store.getRequest(frame.requestId);
    if (!request || request.sourceId !== node.sourceId) throw new ShareError('SHARE_REQUEST_INVALID', '请求归属不匹配。');
    if (frame.type === 'status.result' && request.state === 'UNKNOWN') { reconcile(node, frame, request); return; }
    if (request.fence !== node.fence) throw new ShareError('SHARE_REQUEST_INVALID', '请求所属连接不匹配。');
    if (isTerminal(request.state)) return;
    const work = pending.get(request.id);
    if (!work) { unknown(request.id); return; }
    if (frame.type === 'request.accepted') { if (request.state !== 'DISPATCHED') throw new ShareError('SHARE_SEQUENCE_INVALID', '请求状态顺序无效。'); store.updateRequest(request.id, { state: 'ACCEPTED' }); }
    else if (frame.type === 'attempt.started') { if (request.state !== 'ACCEPTED') throw new ShareError('SHARE_SEQUENCE_INVALID', '发送状态顺序无效。'); store.updateRequest(request.id, { state: 'UPSTREAM_STARTED', startedAt: Date.now() }); }
    else if (frame.type === 'response.head') {
      if (request.state !== 'UPSTREAM_STARTED' || work.head) throw new ShareError('SHARE_SEQUENCE_INVALID', '响应状态顺序无效。');
      if (frame.status < 200 || frame.status > 599) throw new ShareError('SHARE_RESPONSE_INVALID', '上游 HTTP 状态无效。');
      work.head = true; store.updateRequest(request.id, { state: 'STREAMING', delivery: work.res.destroyed ? 'lost' : 'streaming' });
      if (!work.res.destroyed) { work.res.writeHead(frame.status, safeHeaders(frame.headers)); work.res.flushHeaders(); }
    }
    else if (frame.type === 'response.chunk') {
      if (!work.head || request.state !== 'STREAMING' || frame.seq !== work.sequence) throw new ShareError('SHARE_SEQUENCE_INVALID', '响应分片顺序无效。');
      const bytes = Buffer.from(frame.data, 'base64');
      if (bytes.toString('base64') !== frame.data || bytes.length < 1 || bytes.length > CHUNK_BYTES || bytes.length > work.credit) throw new ShareError('SHARE_FLOW_INVALID', '响应流超过窗口限制。');
      work.sequence++; work.credit -= bytes.length;
      if (!work.res.destroyed) { work.res.write(bytes); returnCredit(work, node, bytes.length); }
      else { work.queuedCredit += bytes.length; }
    }
    else if (frame.type === 'response.end') endResponse(node, frame);
    else if (frame.type === 'status.result') {
      if (terminalStates.has(frame.state)) endResponse(node, { v: 1, type: 'response.end', requestId: frame.requestId, fence: frame.fence, state: frame.state as 'COMPLETED' | 'FAILED_KNOWN' | 'CANCELLED_NOT_SENT' | 'UNKNOWN', usage: frame.usage, responseIds: frame.responseIds, errorCode: null });
      else if (frame.state === 'NOT_FOUND') unknown(request.id);
    }
  }

  async function handleControl(req: IncomingMessage, res: ServerResponse, path: string) {
    const method = req.method ?? 'GET'; originCheck(req);
    if (path === '/control/login' && method === 'POST') { const data = await input(req, z.object({ token: z.string().max(512) }).strict()); const credential = store.authenticate(data.token, 'control'); if (!credential) throw credentialsError(); const prior = store.authenticate(cookieToken(req), 'session'); if (prior) store.revokeCredential(prior.hash); json(res, 200, session(res, req, store.getMember(credential.memberId)!)); return; }
    if (path === '/control/invitations/redeem' && method === 'POST') { const data = await input(req, z.object({ token: z.string().max(512), name: nameSchema }).strict()); const { member, token } = store.redeemInvitation(data.token, data.name); store.audit(member.id, 'invitation.redeem', member.id); json(res, 201, { ...session(res, req, member), token }); return; }
    const { member, credential } = controlAuth(req, !['GET', 'HEAD'].includes(method));
    if (path === '/control/session' && method === 'GET') { json(res, 200, { member, csrfToken: credential.csrfToken }); return; }
    if (path === '/control/logout' && method === 'POST') { if (credential.kind === 'session') store.revokeCredential(credential.hash); res.setHeader('set-cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`); json(res, 200, { ok: true }); return; }
    if (path === '/control/dashboard' && method === 'GET') { json(res, 200, dashboard(member)); return; }
    if (path === '/control/invitations' && method === 'POST') { requireAdmin(member); await input(req, z.object({ name: nameSchema.optional() }).strict()); const expiresAt = Date.now() + 24 * 3600_000; const { token } = store.issueCredential('invitation', member.id, { expiresAt }); store.audit(member.id, 'invitation.create', 'invitation'); json(res, 201, { token, expiresAt }); return; }
    if (path === '/control/sources' && method === 'POST') {
      const data = await input(req, z.object({ name: nameSchema, kind: adapterKindSchema, accountBinding: z.string().min(1).max(256), policy: policySchema }).strict());
      clients.validateRoomPolicy(member.id, data.policy);
      const source = store.createSource({ ...data, ownerId: member.id }); const { token: relayToken } = store.issueCredential('relay', member.id, { sourceId: source.id }); store.audit(member.id, 'source.create', source.id); json(res, 201, { source, relayToken }); return;
    }
    if (path === '/control/grants' && method === 'POST') {
      const data = await input(req, z.object({ sourceId: z.string().max(128), memberId: z.string().max(128).optional(), label: nameSchema, models: z.array(z.string().min(1).max(128)).min(1).max(32), expiresAt: z.number().int().positive().nullable().optional() }).strict());
      const source = store.getSource(data.sourceId); const targetId = data.memberId ?? member.id;
      if (!source || !store.getMember(targetId)?.active || !clients.sameRoom(member.id, source.ownerId) || !clients.sameRoom(source.ownerId, targetId)) throw notFound();
      if (clients.isManagedSource(source.id)) throw new ShareError('SHARE_UPGRADE_REQUIRED', '桌面来源不能签发旧版模型凭据。', 409);
      if (targetId !== member.id && member.role !== 'admin' && source.ownerId !== member.id) throw notFound();
      if (!source.policy.allowedMemberIds.includes(targetId) || data.models.some(model => !source.policy.models.includes(model))) throw new ShareError('SHARE_GRANT_FORBIDDEN', '成员或模型未获贡献者允许。', 403);
      const grant = store.createGrant({ ...data, memberId: targetId }); const { token } = store.issueCredential('grant', targetId, { grantId: grant.id }); store.audit(member.id, 'grant.create', grant.id); json(res, 201, { grant, token }); return;
    }
    const sourceAction = /^\/control\/sources\/([^/]+)\/(pause|resolve-unknown|policy)$/.exec(path);
    if (sourceAction) {
      const source = ownedSource(member, sourceAction[1]!); if (clients.isManagedSource(source.id)) throw new ShareError('SHARE_UPGRADE_REQUIRED', '桌面来源请使用设备控制接口修改。', 409); const action = sourceAction[2];
      if (action === 'pause' && method === 'POST') { const data = await input(req, z.object({ paused: z.boolean() }).strict()); store.updateSource(source.id, data); if (data.paused) for (const request of store.queuedForSource(source.id)) unsent(request.id, new ShareError('SHARE_SOURCE_PAUSED', '贡献者已暂停。', 503)); }
      else if (action === 'resolve-unknown' && method === 'POST') { await input(req, z.object({ acknowledge: z.literal(true) }).strict()); if (store.activeForSource(source.id)) throw new ShareError('SHARE_BUSY', '来源仍有执行中的请求。', 409); store.updateSource(source.id, { frozen: false }); }
      else if (action === 'policy' && method === 'PATCH') { const data = await input(req, z.object({ policy: policySchema }).strict()); clients.validateRoomPolicy(source.ownerId, data.policy); store.updateSource(source.id, { policy: data.policy }); for (const request of store.listSourceRequests(source.id)) if (!isTerminal(request.state) && (!data.policy.allowedMemberIds.includes(request.memberId) || !data.policy.models.includes(request.model) || !data.policy.enabled)) cancel(request.id, 'policy_revoked'); }
      else throw notFound();
      store.audit(member.id, `source.${action}`, source.id); json(res, 200, { source: store.getSource(source.id) }); return;
    }
    const grantAction = /^\/control\/grants\/([^/]+)(?:\/(resolve-unknown))?$/.exec(path);
    if (grantAction) {
      const grant = ownedGrant(member, grantAction[1]!);
      if (method === 'DELETE' && !grantAction[2]) { store.updateGrant(grant.id, { revoked: true }); for (const request of store.listSourceRequests(grant.sourceId)) if (request.grantId === grant.id && !isTerminal(request.state)) cancel(request.id, 'grant_revoked'); store.audit(member.id, 'grant.revoke', grant.id); }
      else if (method === 'POST' && grantAction[2]) { await input(req, z.object({ acknowledge: z.literal(true) }).strict()); if (store.listSourceRequests(grant.sourceId).some(request => request.grantId === grant.id && !isTerminal(request.state))) throw new ShareError('SHARE_BUSY', '仍有执行中的请求。', 409); store.updateGrant(grant.id, { frozen: false }); store.audit(member.id, 'grant.resolve', grant.id); }
      else throw notFound(); json(res, 200, { grant: store.getGrant(grant.id) }); return;
    }
    const requestAction = /^\/control\/requests\/([^/]+)(?:\/(cancel))?$/.exec(path);
    if (requestAction) { const request = ownedRequest(member, requestAction[1]!); if (method === 'POST' && requestAction[2]) { await input(req, z.object({}).strict()); cancel(request.id, 'user_cancelled'); store.audit(member.id, 'request.cancel', request.id); } else if (method !== 'GET' || requestAction[2]) throw notFound(); json(res, 200, { request: store.getRequest(request.id) }); return; }
    const memberAction = /^\/control\/members\/([^/]+)$/.exec(path);
    if (memberAction && method === 'DELETE') { requireAdmin(member); const target = store.getMember(memberAction[1]!); if (!target || !clients.sameRoom(member.id, target.id)) throw notFound(); if (target.role === 'admin') throw new ShareError('SHARE_FORBIDDEN', '不能移除管理员。', 403); store.deactivateMember(target.id); for (const grant of store.listGrants()) if (grant.memberId === target.id) store.updateGrant(grant.id, { revoked: true }); for (const source of store.listSources()) { if (source.ownerId === target.id) { store.updateSource(source.id, { paused: true }); nodes.get(source.id)?.ws.close(1008, 'member revoked'); } for (const request of store.listSourceRequests(source.id)) if (request.memberId === target.id && !isTerminal(request.state)) cancel(request.id, 'member_revoked'); } store.audit(member.id, 'member.revoke', target.id); json(res, 200, { ok: true }); return; }
    throw notFound();
  }

  async function handleData(req: IncomingMessage, res: ServerResponse, path: string) {
    const credential = store.authenticate(bearer(req), 'grant');
    const desktop: InferenceAuth | null = credential?.grantId ? null : clients.inference(bearer(req));
    const grant = desktop?.grant ?? store.getGrant(credential!.grantId!);
    if (grant && (!clients.sourceInRoom(grant.memberId, grant.sourceId) || credential && credential.memberId !== grant.memberId)) throw notFound();
    if (!desktop && grant && clients.isManagedSource(grant.sourceId)) throw new ShareError('SHARE_UPGRADE_REQUIRED', '桌面来源必须使用会话运行授权。', 409); if (!grant || grant.revoked || (grant.expiresAt !== null && grant.expiresAt <= Date.now())) throw new ShareError('SHARE_GRANT_REVOKED', '接入授权已撤销或到期。', 403);
    if (path === '/v1/models' && req.method === 'GET') { const source = store.getSource(grant.sourceId)!; const models = grant.models.filter(model => (!desktop || desktop.session.modelScope.includes(model)) && source.policy.models.includes(model) && (!source.capabilities || source.capabilities.models.includes(model))); json(res, 200, { object: 'list', data: models.map(id => ({ id, object: 'model', owned_by: `share-token:${source.kind}` })) }); return; }
    const operation: Operation = path === '/v1/responses/compact' ? 'compact' : 'responses';
    if (req.method !== 'POST' || !['/v1/responses', '/v1/responses/compact'].includes(path)) throw notFound();
    if (closing) throw new ShareError('SHARE_SHUTTING_DOWN', '服务正在关闭。', 503);
    const readerKey = desktop ? `session:${desktop.session.id}` : `grant:${grant.id}`;
    if (modelReaders.has(readerKey) || modelReaders.size >= 16) throw new ShareError('SHARE_BUSY', '已有请求正在接收，请稍后再试。', 429);
    modelReaders.add(readerKey);
    try {
      const bytes = await body(req); const payload = parseJson(bytes);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload) || typeof (payload as Record<string, unknown>).model !== 'string') throw new ShareError('SHARE_INPUT_INVALID', '模型请求需要 model 字段。');
      const data = payload as Record<string, unknown>; const model = data.model as string;
      let operationId: string | null = null;
      if (desktop) {
        const header = req.headers['x-share-operation-id']; if (typeof header !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(header)) throw new ShareError('SHARE_OPERATION_REQUIRED', '桌面模型请求必须携带稳定的操作编号。'); operationId = header;
        const old = clients.operation(desktop.device.id, desktop.session.id, operationId); if (old) { res.setHeader('x-share-request-id', old.id); clients.assertOperationBody(old.id, bytes, operation); throw new ShareError('SHARE_OPERATION_EXISTS', '操作已登记，请查询请求状态；不会再次调用上游。', 409); }
        clients.assertInferenceReady(desktop, model);
      }
      admission(grant, model, bytes.length, operation);
      if (data.background === true) throw new ShareError('SHARE_BACKGROUND_UNSUPPORTED', '当前版本不支持后台模型任务。', 400);
      const toolStack: unknown[] = Array.isArray(data.tools) ? [...data.tools] : [];
      if (data.tools !== undefined && !Array.isArray(data.tools)) throw new ShareError('SHARE_INPUT_INVALID', 'tools 必须是数组。');
      if (data.tool_choice && typeof data.tool_choice === 'object') toolStack.push(data.tool_choice);
      while (toolStack.length) {
        const tool = toolStack.pop(); if (!tool || typeof tool !== 'object' || Array.isArray(tool)) throw new ShareError('SHARE_INPUT_INVALID', '工具定义无效。');
        const object = tool as Record<string, unknown>;
        if (!['function', 'custom', 'namespace', 'allowed_tools'].includes(String(object.type))) throw new ShareError('SHARE_TOOL_UNSUPPORTED', '当前版本仅支持使用者本机执行的 function/custom 工具，不支持上游原生工具或资源。', 400);
        if (object.type === 'namespace' || object.type === 'allowed_tools') {
          if (!Array.isArray(object.tools)) throw new ShareError('SHARE_INPUT_INVALID', '工具分组定义无效。');
          for (const child of object.tools) toolStack.push(child);
        }
      }
      if (data.previous_response_id !== undefined && data.previous_response_id !== null) { if (typeof data.previous_response_id !== 'string' || data.previous_response_id.length > 128) throw new ShareError('SHARE_INPUT_INVALID', '历史响应标识无效。'); if (desktop) clients.assertResource(grant.sourceId, desktop.session.id, data.previous_response_id); store.assertResourceOwnership(grant.sourceId, grant.id, data.previous_response_id); }
      if (data.conversation !== undefined && data.conversation !== null || (data.prompt && typeof data.prompt === 'object' && 'id' in data.prompt)) throw new ShareError('SHARE_RESOURCE_UNSUPPORTED', '当前版本不支持引用上游会话或已保存的提示模板。', 400);
      const inspect: unknown[] = [data.input]; let inspected = 0;
      while (inspect.length) {
        const item = inspect.pop(); if (++inspected > 100_000) throw new ShareError('SHARE_INPUT_INVALID', '输入结构过于复杂。');
        if (!item || typeof item !== 'object') continue;
        if (Array.isArray(item)) { for (const child of item) inspect.push(child); continue; }
        const object = item as Record<string, unknown>;
        if (object.type === 'item_reference') { if (typeof object.id !== 'string' || object.id.length > 128) throw new ShareError('SHARE_INPUT_INVALID', '输入项引用无效。'); if (desktop) clients.assertResource(grant.sourceId, desktop.session.id, object.id); store.assertResourceOwnership(grant.sourceId, grant.id, object.id); }
        if ('file_id' in object && object.file_id !== null) throw new ShareError('SHARE_RESOURCE_UNSUPPORTED', '当前版本不支持引用上游文件 ID，请使用内联内容。', 400);
        for (const child of Object.values(object)) if (child && typeof child === 'object') inspect.push(child);
      }
      const request = desktop ? clients.createRequest(desktop, operationId!, bytes, model, operation) : store.createRequest({ grantId: grant.id, memberId: grant.memberId, sourceId: grant.sourceId, model, operation });
      res.setHeader('x-share-request-id', request.id);
      const work: Pending = { record: request, body: bytes, res, timer: setTimeout(() => { unsent(request.id, new ShareError('SHARE_QUEUE_TIMEOUT', '等待超时，尚未调用上游。', 429)); flushQueue(grant.sourceId); }, queueTimeoutMs), credit: 0, sequence: 0, head: false, queuedCredit: 0, drainListener: false };
      pending.set(request.id, work);
      res.on('finish', () => { if (closed) return; const current = store.getRequest(request.id); if (current && current.delivery !== 'lost' && current.delivery !== 'unknown') store.updateRequest(request.id, { delivery: 'transport_finished' }); });
      res.on('close', () => { if (closed) return; const current = store.getRequest(request.id); if (!current || res.writableFinished) return; store.updateRequest(request.id, { delivery: 'lost' }); freezeDelivery(request, 'unknown'); if (!isTerminal(current.state)) cancel(request.id, 'consumer_disconnected'); });
      if (request.state === 'RESERVED') dispatch(request.id);
    } finally { modelReaders.delete(readerKey); }
  }

  const handleClient = createClientRouter({ store, clients, sharedCodePath: options.sharedCodePath, originCheck, controlAuth, input, json, cancel, assertSiblingRelayIdle, revokeDevice(deviceId) {
    for (const request of clients.deviceRequests(deviceId)) if (!isTerminal(request.state)) cancel(request.id, 'device_revoked');
    for (const node of nodes.values()) if (node.deviceId === deviceId) node.ws.terminate();
  }, closeRelay(leaseId) { for (const node of nodes.values()) if (node.relayLeaseId === leaseId) node.ws.terminate(); } });

  const server = createServer((req, res) => {
    res.setHeader('x-content-type-options', 'nosniff'); res.setHeader('referrer-policy', 'no-referrer'); res.setHeader('x-frame-options', 'DENY');
    res.setHeader('content-security-policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://hub.local');
      if (url.search && (url.pathname.startsWith('/v1/') || url.pathname.startsWith('/control/') || url.pathname.startsWith('/client/'))) {
        const parameters = [...url.searchParams.entries()];
        const modelVersionQuery = req.method === 'GET' && url.pathname === '/v1/models' && parameters.length === 1 && parameters[0]![0] === 'client_version' && /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/.test(parameters[0]![1]);
        if (!modelVersionQuery) throw new ShareError('SHARE_URL_INVALID', '接口仅允许模型列表的 client_version 查询参数，不接受 URL 凭据。');
      }
      if (url.pathname === '/healthz' && req.method === 'GET') { json(res, 200, { ok: !closing, subscriptionAvailable: true }); return; }
      if (await handleClient(req, res, url.pathname)) return;
      if (url.pathname.startsWith('/control/')) { await handleControl(req, res, url.pathname); return; }
      if (url.pathname.startsWith('/v1/')) { await handleData(req, res, url.pathname); return; }
      if (options.staticDir && req.method === 'GET') {
        let pathname: string; try { pathname = decodeURIComponent(url.pathname); } catch { throw notFound(); }
        const root = resolve(options.staticDir); const target = resolve(root, '.' + pathname);
        if (target !== root && !target.startsWith(root + sep)) throw notFound();
        const file = extname(target) ? target : resolve(root, 'index.html');
        let content: Buffer; try { content = await readFile(file); } catch { throw notFound(); }
        const mime: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
        res.writeHead(200, { 'content-type': mime[extname(file)] ?? 'application/octet-stream', 'cache-control': 'no-cache' }); res.end(content); return;
      }
      throw notFound();
    })().catch(error => { req.resume(); fail(res, error); });
  });
  server.requestTimeout = 30_000; server.headersTimeout = 15_000; server.maxHeadersCount = 100;
  const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024, perMessageDeflate: false });
  server.on('upgrade', (req, socket, head) => {
    if (closing || req.url !== '/relay/v1' || req.headers.origin) { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return; }
    const credential = store.authenticate(bearer(req), 'relay'); let desktop: RelayAuth | null = null;
    if (!credential) { try { desktop = clients.relayAuth(bearer(req)); } catch { /* Reject below without revealing credentials. */ } }
    const source = store.getSource(desktop?.lease.sourceId ?? credential?.sourceId ?? '');
    if ((!credential && !desktop) || !source || source.ownerId !== (desktop?.member.id ?? credential?.memberId) || (!desktop && clients.isManagedSource(source.id))) { socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); return; }
    if (nodes.has(source.id)) { socket.end('HTTP/1.1 409 Conflict\r\nConnection: close\r\n\r\n'); return; }
    // Both legacy and desktop relays share the same account-wide single-node
    // boundary. A new member's source must not overlap or inherit unfinished
    // work from an older source backed by the same upstream account.
    try {
      store.assertAccountIdle(source.id);
      clients.assertAccountRelayAvailable(source.id, desktop?.lease.id);
      assertSiblingRelayIdle(source.id);
    } catch { socket.end('HTTP/1.1 409 Conflict\r\nConnection: close\r\n\r\n'); return; }
    wss.handleUpgrade(req, socket, head, ws => {
      const node: NodeConnection = { ws, sourceId: source.id, fence: 0, ready: false, paused: false, lastSeen: Date.now(), credential, deviceId: desktop?.device.id, relayLeaseId: desktop?.lease.id }; nodes.set(source.id, node);
      const helloTimer = setTimeout(() => { if (!node.ready) ws.close(1008, 'hello required'); }, 5000);
      ws.on('message', (raw, binary) => { if (closed) return; try { if (node.relayLeaseId && !clients.relayConnectionValid(node.relayLeaseId, node.deviceId!)) throw new Error('revoked relay'); if (binary) throw new Error('binary unsupported'); const parsed = relayFrameSchema.safeParse(JSON.parse(raw.toString())); if (!parsed.success) throw new Error('invalid frame'); handleFrame(node, parsed.data); } catch { for (const request of store.listSourceRequests(source.id)) if (!isTerminal(request.state) && request.state !== 'QUEUED' && request.state !== 'RESERVED') unknown(request.id, 'SHARE_RELAY_PROTOCOL_ERROR'); ws.close(1008, 'invalid relay frame'); } });
      ws.on('error', () => {});
      ws.on('close', () => {
        clearTimeout(helloTimer); if (closed || nodes.get(source.id) !== node) return; nodes.delete(source.id); store.updateSource(source.id, { online: false });
        for (const request of store.listSourceRequests(source.id)) if (!isTerminal(request.state)) { if (request.state === 'QUEUED' || request.state === 'RESERVED') unsent(request.id, new ShareError('SHARE_SOURCE_OFFLINE', '贡献者离线，请求尚未发送。', 503)); else unknown(request.id); }
      });
    });
  });
  const heartbeatTimer = setInterval(() => { for (const node of nodes.values()) if (Date.now() - node.lastSeen > 45_000 || (node.relayLeaseId ? !clients.relayConnectionValid(node.relayLeaseId, node.deviceId!) : !store.getMember(node.credential!.memberId)?.active)) node.ws.terminate(); }, 15_000); heartbeatTimer.unref();
  try { await new Promise<void>((resolveListen, reject) => { server.once('error', reject); server.listen(options.port ?? 8787, options.host ?? '127.0.0.1', () => { server.off('error', reject); resolveListen(); }); }); }
  catch (error) { clearInterval(heartbeatTimer); closed = true; wss.close(); store.close(); throw error; }
  const address = server.address() as AddressInfo; const displayHost = address.address.includes(':') ? `[${address.address}]` : address.address;
  return { url: `http://${displayHost}:${address.port}`, store, async close() {
    if (closing) return; closing = true; clearInterval(heartbeatTimer);
    for (const request of [...pending.values()].map(work => store.getRequest(work.record.id)!)) {
      if (request.state === 'QUEUED' || request.state === 'RESERVED') unsent(request.id, new ShareError('SHARE_SHUTTING_DOWN', '服务关闭前请求未发送。', 503));
      else { const node = nodes.get(request.sourceId); if (node) send(node, { v: 1, type: 'cancel.request', requestId: request.id, fence: request.fence, reason: 'hub_shutdown' }); unknown(request.id, 'SHARE_HUB_SHUTDOWN'); }
    }
    for (const node of nodes.values()) node.ws.terminate();
    await new Promise<void>(resolveClose => wss.close(() => resolveClose()));
    server.closeAllConnections(); await new Promise<void>(resolveClose => server.close(() => resolveClose())); closed = true; store.close();
  } };
}
