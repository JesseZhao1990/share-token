import type { IncomingMessage, ServerResponse } from 'node:http';
import { z } from 'zod';
import { ShareError, isTerminal, policySchema, type Member, type RequestRecord } from '../../packages/protocol/index.js';
import { ClientStore, type DeviceAuth } from '../../packages/storage/client.js';
import type { Store, Credential } from '../../packages/storage/index.js';
import { PAIR_CSS, PAIR_HTML, PAIR_JS } from './pair-page.js';
import { loadSharedCodeVerifier } from '../../packages/storage/shared-code.js';

const name = z.string().trim().min(1).max(80), id = z.string().min(1).max(128);
const scopes = z.array(z.enum(['consumer', 'donor'])).min(1).max(2);
const empty = z.object({}).strict();
const missing = () => new ShareError('SHARE_NOT_FOUND', '资源不存在或无权访问。', 404);
const bearer = (req: IncomingMessage) => /^Bearer ([^\s]+)$/i.exec(req.headers.authorization ?? '')?.[1] ?? '';
export function createClientRouter(options: {
  store: Store; clients: ClientStore;
  sharedCodePath?: string;
  originCheck(req: IncomingMessage): void;
  controlAuth(req: IncomingMessage, mutate?: boolean): { member: Member; credential: Credential };
  input<T>(req: IncomingMessage, schema: z.ZodType<T>): Promise<T>;
  json(res: ServerResponse, status: number, body: unknown): void;
  cancel(requestId: string, reason: string): void;
  revokeDevice(deviceId: string): void;
  closeRelay(leaseId: string): void;
  assertSiblingRelayIdle(sourceId: string): void;
}) {
  const { store, clients, input, json } = options;
  const rates = new Map<string, { start: number; count: number }>();
  function requestOrigin(req: IncomingMessage) {
    const secure = ('encrypted' in req.socket && req.socket.encrypted) || (['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress ?? '') && req.headers['x-forwarded-proto'] === 'https');
    return new URL(`${secure ? 'https' : 'http'}://${req.headers.host}`).origin;
  }
  function rate(req: IncomingMessage, group: string, limit: number) {
    const key = `${req.socket.remoteAddress}:${group}`, now = Date.now();
    let value = rates.get(key); if (!value || now - value.start > 60_000) { value = { start: now, count: 0 }; rates.set(key, value); }
    if (++value.count > limit) throw new ShareError('SHARE_RATE_LIMITED', '请求频率过高，请稍后再试。', 429);
    if (rates.size > 5000) for (const [entry, value] of rates) if (now - value.start > 60_000) rates.delete(entry);
  }
  function sourceOwner(auth: DeviceAuth, sourceId: string) { clients.requireScope(auth, 'donor'); const source = store.getSource(sourceId); if (!source || source.ownerId !== auth.member.id || !clients.isManagedSource(sourceId)) throw missing(); return source; }
  function validatePolicy(ownerId: string, policy: z.infer<typeof policySchema>) { clients.validateRoomPolicy(ownerId, policy); }
  function visibleRequest(auth: DeviceAuth, requestId: string) { const request = clients.request(requestId); if (!request || !clients.sourceInRoom(auth.member.id, request.sourceId) || !clients.sameRoom(auth.member.id, request.memberId) || (request.memberId !== auth.member.id && store.getSource(request.sourceId)?.ownerId !== auth.member.id && auth.member.role !== 'admin')) throw missing(); return request; }
  function cancelMatching(test: (request: RequestRecord) => boolean, reason: string) { for (const source of store.listSources()) for (const request of store.listSourceRequests(source.id)) if (!isTerminal(request.state) && test(request)) options.cancel(request.id, reason); }
  return async function handle(req: IncomingMessage, res: ServerResponse, path: string): Promise<boolean> {
    const method = req.method ?? 'GET';
    if (method === 'GET' && (path === '/pair' || path === '/pair.js' || path === '/pair.css')) {
      const type = path === '/pair' ? 'text/html' : path === '/pair.js' ? 'application/javascript' : 'text/css';
      res.writeHead(200, { 'content-type': type + '; charset=utf-8', 'cache-control': 'no-store' });
      res.end(path === '/pair' ? PAIR_HTML : path === '/pair.js' ? PAIR_JS : PAIR_CSS); return true;
    }
    const browserJoin = /^\/control\/v2\/device-pairings\/([A-Z0-9-]{8,16})\/join$/.exec(path);
    if (browserJoin && method === 'POST') {
      if (!req.headers.origin) throw new ShareError('SHARE_CSRF_INVALID', '请从本空间的设备连接页面提交配对码。', 403);
      options.originCheck(req);
      if (new URL(req.headers.origin).origin !== requestOrigin(req)) throw new ShareError('SHARE_CSRF_INVALID', '配对码只能提交给当前共享空间。', 403);
      rate(req, 'shared-code', 30);
      const data = await input(req, z.object({ sharedCode: z.string().min(1).max(128) }).strict());
      json(res, 200, { pairing: clients.joinPairingFromBrowser(browserJoin[1]!, data.sharedCode, await loadSharedCodeVerifier(options.sharedCodePath)) }); return true;
    }
    const approval = /^\/control\/v2\/device-pairings\/([A-Z0-9-]{8,16})(?:\/(approve|deny))?$/.exec(path);
    if (approval) {
      rate(req, 'approval', 30);
      const { member, credential } = options.controlAuth(req, method !== 'GET');
      if (credential.kind !== 'session') throw new ShareError('SHARE_BROWSER_REQUIRED', '请在已登录的浏览器页面批准设备。', 403);
      if (method === 'GET' && !approval[2]) json(res, 200, { pairing: clients.pairingView(approval[1]!) });
      else if (method === 'POST' && approval[2] === 'approve') { const data = await input(req, z.object({ approvedScopes: scopes.optional() }).strict()); json(res, 200, { pairing: clients.approvePairing(approval[1]!, member, data.approvedScopes) }); }
      else if (method === 'POST' && approval[2] === 'deny') { await input(req, empty); json(res, 200, clients.denyPairing(approval[1]!, member)); }
      else throw missing(); return true;
    }
    if (!path.startsWith('/client/v2/')) return false;
    if (path === '/client/v2/meta' && method === 'GET') { json(res, 200, { hubId: clients.hubId, spaceName: '朋友共享空间', apiVersion: 2, relayProtocolVersion: 1, desktopDataPlane: 'responses-v1', subscriptionAvailable: true, pairing: { method: 'S256', expiresIn: 300, interval: 3, matchingCodeAvailable: true, sharedCodeAvailable: !!await loadSharedCodeVerifier(options.sharedCodePath) }, features: ['owner-scoped-sources', 'friend-code-matching', 'device-pairing', 'rotating-refresh', 'stable-sessions', 'run-leases', 'delivery-ack', 'policy-ack', 'mock-v1-compatibility', 'subscription-v1-compatibility'] }); return true; }
    if (path === '/client/v2/device-pairings' && method === 'POST') {
      rate(req, 'pairing', 10); const data = await input(req, z.object({ deviceName: name, platform: name, clientVersion: name, requestedScopes: scopes, codeChallenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/), codeChallengeMethod: z.literal('S256') }).strict());
      json(res, 201, clients.createPairing(data, requestOrigin(req))); return true;
    }
    if (method === 'POST' && ['/client/v2/device-pairings/token', '/client/v2/device-pairings/cancel'].includes(path)) {
      rate(req, 'poll', 100); const data = await input(req, z.object({ deviceCode: z.string().min(16).max(512), codeVerifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/) }).strict());
      if (path.endsWith('/cancel')) { const result = clients.cancelPairing(data.deviceCode, data.codeVerifier); if (result.deviceId) options.revokeDevice(result.deviceId); json(res, 200, result); } else json(res, 200, clients.redeemPairing(data.deviceCode, data.codeVerifier)); return true;
    }
    if (path === '/client/v2/device-pairings/join' && method === 'POST') {
      if (req.headers.origin !== undefined || req.headers['sec-fetch-site'] === 'cross-site') throw new ShareError('SHARE_CSRF_INVALID', '请在桌面应用中输入配对码。', 403);
      rate(req, 'shared-code', 30);
      const data = await input(req, z.object({ deviceCode: z.string().min(16).max(512), codeVerifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/), sharedCode: z.string().min(1).max(128) }).strict());
      json(res, 200, { pairing: clients.joinPairing(data.deviceCode, data.codeVerifier, data.sharedCode, await loadSharedCodeVerifier(options.sharedCodePath)) }); return true;
    }
    if (path === '/client/v2/device-pairings/match' && method === 'POST') {
      if (req.headers.origin !== undefined || req.headers['sec-fetch-site'] === 'cross-site') throw new ShareError('SHARE_CSRF_INVALID', '请在桌面应用中输入配对码。', 403);
      rate(req, 'matching-code', 30);
      const data = await input(req, z.object({ deviceCode: z.string().min(16).max(512), codeVerifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/), sharedCode: z.string().min(1).max(128) }).strict());
      json(res, 200, { pairing: clients.matchPairing(data.deviceCode, data.codeVerifier, data.sharedCode) }); return true;
    }
    if (path === '/client/v2/auth/refresh' && method === 'POST') { rate(req, 'refresh', 60); const data = await input(req, z.object({ refreshToken: z.string().min(16).max(512) }).strict()); const result = clients.refresh(data.refreshToken); if (result.revokedDeviceId) { options.revokeDevice(result.revokedDeviceId); throw new ShareError('SHARE_REFRESH_REUSED', '刷新凭据重复使用，设备已撤销，请重新配对。', 401); } json(res, 200, result.auth); return true; }
    const auth = clients.access(bearer(req));
    if (path === '/client/v2/me' && method === 'GET') { json(res, 200, { member: auth.member, device: auth.device, matchingRoom: clients.memberRoom(auth.member.id) !== 'legacy' }); return true; }
    if (path === '/client/v2/members' && method === 'GET') { json(res, 200, { members: store.listMembers().filter(member => member.active && clients.sameRoom(auth.member.id, member.id)) }); return true; }
    if (path === '/client/v2/devices' && method === 'GET') { json(res, 200, { devices: clients.devices(auth.member) }); return true; }
    const devicePath = /^\/client\/v2\/devices\/([^/]+)$/.exec(path);
    if (devicePath && method === 'DELETE') { const device = clients.getDevice(devicePath[1]!); if (!device || device.memberId !== auth.member.id) throw missing(); clients.revokeDevice(device.id); options.revokeDevice(device.id); json(res, 200, { device: clients.getDevice(device.id) }); return true; }
    if (path === '/client/v2/sources' && method === 'GET') { const grants = store.listGrants(); json(res, 200, { sources: store.listSources().filter(source => clients.sameRoom(auth.member.id, source.ownerId) && (source.ownerId === auth.member.id || auth.member.role === 'admin' || source.policy.allowedMemberIds.includes(auth.member.id) || grants.some(grant => grant.sourceId === source.id && grant.memberId === auth.member.id && !grant.revoked))).map(source => clients.decorateSource(source)) }); return true; }
    if (path === '/client/v2/sources' && method === 'POST') {
      clients.requireScope(auth, 'donor');
      const data = await input(req, z.object({ name, kind: z.enum(['mock', 'subscription']), accountBinding: z.string().min(1).max(256), policy: policySchema }).strict());
      validatePolicy(auth.member.id, data.policy);
      const result = store.transaction(() => {
        // An account label never authorizes taking over another member's source.
        // Repeated saves recover only this member's managed source, including
        // older desktop clients whose successful create response was lost.
        const existing = store.listSources().find(source => source.ownerId === auth.member.id && source.kind === data.kind && source.accountBinding === data.accountBinding);
        if (existing) {
          if (!clients.isManagedSource(existing.id)) throw new ShareError('SHARE_UPGRADE_REQUIRED', '该来源仍使用旧协议，请在原设备完成升级后重试。', 409);
          return { created: false, response: clients.sourceResponse(existing.id) };
        }
        return { created: true, response: clients.registerSource(store.createSource({ ...data, ownerId: auth.member.id })) };
      });
      if (result.created) store.audit(auth.member.id, 'v2.source.create', result.response.source.id);
      json(res, result.created ? 201 : 200, result.response); return true;
    }
    const sourcePath = /^\/client\/v2\/sources\/([^/]+)(?:\/(policy|policy-acks|pause|desired-state|relay-leases|resolve-unknown))?$/.exec(path);
    if (sourcePath) {
      const source = sourceOwner(auth, sourcePath[1]!); const action = sourcePath[2];
      if (method === 'GET' && !action) json(res, 200, clients.sourceResponse(source.id));
      else if (method === 'PATCH' && action === 'policy') { const data = await input(req, z.object({ policy: policySchema, expectedRevision: z.number().int().positive().optional() }).strict()); validatePolicy(auth.member.id, data.policy); const response = store.transaction(() => clients.updatePolicy(source.id, data.policy, data.expectedRevision)); cancelMatching(request => request.sourceId === source.id && (!data.policy.enabled || !data.policy.allowedMemberIds.includes(request.memberId) || !data.policy.models.includes(request.model)), 'policy_revoked'); json(res, 200, response); }
      else if (method === 'POST' && action === 'policy-acks') { const data = await input(req, z.object({ revision: z.number().int().positive(), policyHash: z.string().regex(/^[0-9a-f]{64}$/).optional() }).strict()); json(res, 200, clients.ackPolicy(source.id, auth.device.id, data.revision, data.policyHash)); }
      else if (method === 'POST' && action === 'relay-leases') { await input(req, empty); options.assertSiblingRelayIdle(source.id); json(res, 201, clients.createRelay(auth, source.id)); }
      else if (method === 'POST' && (action === 'pause' || action === 'desired-state')) {
        const state = action === 'pause' ? ((await input(req, z.object({ paused: z.boolean() }).strict())).paused ? 'drain' : 'active') : (await input(req, z.object({ state: z.enum(['active', 'drain', 'stop']) }).strict())).state;
        store.updateSource(source.id, { paused: state !== 'active' }); cancelMatching(request => request.sourceId === source.id && (state === 'stop' || state === 'drain' && ['QUEUED', 'RESERVED'].includes(request.state)), `source_${state}`); json(res, 200, { source: clients.decorateSource(store.getSource(source.id)!) });
      } else if (method === 'POST' && action === 'resolve-unknown') { await input(req, z.object({ acknowledge: z.literal(true) }).strict()); if (store.activeForSource(source.id)) throw new ShareError('SHARE_BUSY', '来源仍有执行中的请求。', 409); store.updateSource(source.id, { frozen: false }); store.audit(auth.member.id, 'v2.source.resolve', source.id); json(res, 200, { source: clients.decorateSource(store.getSource(source.id)!) }); }
      else throw missing(); return true;
    }
    const relayPath = /^\/client\/v2\/relay-leases\/([^/]+)(?:\/(renew))?$/.exec(path);
    if (relayPath) { if (method === 'POST' && relayPath[2]) { await input(req, empty); json(res, 200, clients.renewRelay(auth, relayPath[1]!)); } else if (method === 'DELETE' && !relayPath[2]) { const lease = clients.closeRelay(auth, relayPath[1]!); options.closeRelay(lease.id); json(res, 200, { lease }); } else throw missing(); return true; }
    if (path === '/client/v2/grants' && method === 'GET') { const owned = new Set(store.listSources().filter(source => source.ownerId === auth.member.id).map(source => source.id)); json(res, 200, { grants: store.listGrants().filter(grant => clients.grantInRoom(auth.member.id, grant) && (grant.memberId === auth.member.id || owned.has(grant.sourceId) || auth.member.role === 'admin')) }); return true; }
    if (path === '/client/v2/grants' && method === 'POST') {
      const data = await input(req, z.object({ sourceId: id, memberId: id.optional(), label: name, models: z.array(id).min(1).max(32), expiresAt: z.number().int().positive().nullable().optional() }).strict()); const source = store.getSource(data.sourceId), memberId = data.memberId ?? auth.member.id;
      if (!source || !clients.isManagedSource(source.id) || !store.getMember(memberId)?.active || !clients.sameRoom(auth.member.id, source.ownerId) || !clients.sameRoom(source.ownerId, memberId)) throw missing();
      if (memberId !== auth.member.id) sourceOwner(auth, source.id); else clients.requireScope(auth, 'consumer');
      if (!source.policy.allowedMemberIds.includes(memberId) || data.models.some(model => !source.policy.models.includes(model))) throw new ShareError('SHARE_GRANT_FORBIDDEN', '成员或模型未获贡献者允许。', 403);
      const grant = store.createGrant({ ...data, memberId }); store.audit(auth.member.id, 'v2.grant.create', grant.id); json(res, 201, { grant }); return true;
    }
    const grantPath = /^\/client\/v2\/grants\/([^/]+)$/.exec(path);
    if (grantPath && method === 'DELETE') { const grant = store.getGrant(grantPath[1]!); if (!grant || !clients.grantInRoom(auth.member.id, grant) || (grant.memberId !== auth.member.id && store.getSource(grant.sourceId)?.ownerId !== auth.member.id)) throw missing(); clients.requireScope(auth, grant.memberId === auth.member.id ? 'consumer' : 'donor'); store.updateGrant(grant.id, { revoked: true }); cancelMatching(request => request.grantId === grant.id, 'grant_revoked'); json(res, 200, { grant: store.getGrant(grant.id) }); return true; }
    if (path === '/client/v2/sessions' && method === 'GET') { json(res, 200, { sessions: clients.sessions(auth.member.id) }); return true; }
    if (path === '/client/v2/sessions' && method === 'POST') { const data = await input(req, z.object({ grantId: id, modelScope: z.array(id).min(1).max(32), requestNonce: id.optional() }).strict()); json(res, 201, { session: clients.createSession(auth, data) }); return true; }
    const sessionPath = /^\/client\/v2\/sessions\/([^/]+)(?:\/(leases|close|resolve-unknown))?$/.exec(path);
    if (sessionPath) {
      const sessionId = sessionPath[1]!; clients.ownedSession(auth, sessionId); if (method !== 'GET') clients.requireScope(auth, 'consumer');
      if (method === 'GET' && !sessionPath[2]) json(res, 200, { session: clients.getSession(sessionId) });
      else if (method === 'POST' && sessionPath[2] === 'leases') { const data = await input(req, z.object({ expectedEpoch: z.number().int().nonnegative().optional() }).strict()); json(res, 201, clients.createRun(auth, sessionId, data.expectedEpoch)); }
      else if (method === 'POST' && sessionPath[2] === 'close') { await input(req, empty); const session = clients.closeSession(auth, sessionId); cancelMatching(request => clients.requestMeta(request.id)?.sessionId === sessionId, 'session_closed'); json(res, 200, { session }); }
      else if (method === 'POST' && sessionPath[2] === 'resolve-unknown') { await input(req, z.object({ acknowledge: z.literal(true) }).strict()); json(res, 200, { session: clients.resolveSession(auth, sessionId) }); }
      else throw missing(); return true;
    }
    const runPath = /^\/client\/v2\/run-leases\/([^/]+)\/(renew|close)$/.exec(path);
    if (runPath && method === 'POST') { clients.requireScope(auth, 'consumer'); await input(req, empty); if (runPath[2] === 'renew') json(res, 200, clients.renewRun(auth, runPath[1]!)); else { const lease = clients.closeRun(auth, runPath[1]!); cancelMatching(request => clients.requestMeta(request.id)?.leaseId === lease.id, 'run_closed'); json(res, 200, { lease }); } return true; }
    const opPath = /^\/client\/v2\/sessions\/([^/]+)\/operations\/([^/]+)$/.exec(path);
    if (opPath && method === 'GET') { clients.ownedSession(auth, opPath[1]!); const request = clients.operation(auth.device.id, opPath[1]!, opPath[2]!); if (!request) throw missing(); json(res, 200, { request }); return true; }
    if (path === '/client/v2/requests' && method === 'GET') { json(res, 200, { requests: store.listVisibleRequests(auth.member).filter(request => clients.sourceInRoom(auth.member.id, request.sourceId) && clients.sameRoom(auth.member.id, request.memberId)).map(request => clients.request(request.id)).filter(Boolean) }); return true; }
    const requestPath = /^\/client\/v2\/requests\/([^/]+)(?:\/(delivery-ack|cancel))?$/.exec(path);
    if (requestPath) { const requestId = requestPath[1]!;
      if (method === 'GET' && !requestPath[2]) json(res, 200, { request: visibleRequest(auth, requestId) });
      else if (method === 'POST' && requestPath[2] === 'delivery-ack') { const data = await input(req, z.object({ operationId: id, outcome: z.enum(['transport_finished', 'lost']) }).strict()); json(res, 200, { request: clients.deliveryAck(auth, requestId, data.operationId, data.outcome) }); }
      else if (method === 'POST' && requestPath[2] === 'cancel') { await input(req, empty); const request = visibleRequest(auth, requestId); if (request.memberId === auth.member.id) clients.requireScope(auth, 'consumer'); else sourceOwner(auth, request.sourceId); options.cancel(requestId, 'user_cancelled'); json(res, 200, { request: clients.request(requestId) }); }
      else throw missing(); return true;
    }
    throw missing();
  };
}
