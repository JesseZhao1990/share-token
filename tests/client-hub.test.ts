import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHub } from '../apps/hub/index.js';
import { createRelay } from '../apps/relay/index.js';
import { MockAdapter, type MockOptions } from '../packages/upstream/index.js';
import { policySchema, type Member, type Grant } from '../packages/protocol/index.js';
import type { ClientAuthResponse, DevicePairingResponse, ClientSourceResponse, ClientSession, RunLeaseResponse, RelayLeaseResponse, ClientRequest } from '../packages/protocol/client.js';

async function setup() {
  const dir = await mkdtemp(join(tmpdir(), 'share-client-hub-')), admin = 'test_admin_abcdefghijklmnopqrstuvwxyz';
  const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: admin, port: 0 });
  async function raw(path: string, body?: unknown, token?: string, method = body === undefined ? 'GET' : 'POST', headers: Record<string, string> = {}) { return fetch(hub.url + path, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }); }
  async function api<T>(path: string, body?: unknown, token?: string, method?: string, headers?: Record<string,string>): Promise<T> { const response = await raw(path, body, token, method, headers); assert.equal(response.ok, true, `${path}: ${response.status} ${response.ok ? '' : await response.text()}`); return response.json() as Promise<T>; }
  const login = await raw('/control/login', { token: admin }); const cookie = login.headers.get('set-cookie')!.split(';')[0]!; const logged = await login.json() as { member: Member; csrfToken: string };
  const browser = { cookie, 'x-csrf-token': logged.csrfToken };
  async function startPair() { const verifier = randomBytes(48).toString('base64url'); const pair = await api<DevicePairingResponse>('/client/v2/device-pairings', { deviceName: '桌面测试', platform: 'darwin', clientVersion: 'test-v2', requestedScopes: ['consumer', 'donor'], codeChallengeMethod: 'S256', codeChallenge: createHash('sha256').update(verifier).digest('base64url') }); return { pair, verifier }; }
  async function approve(pair: DevicePairingResponse) { return api(`/control/v2/device-pairings/${pair.userCode}/approve`, { approvedScopes: ['consumer','donor'] }, undefined, 'POST', browser); }
  async function pair() { const started = await startPair(); await approve(started.pair); return api<ClientAuthResponse>('/client/v2/device-pairings/token', { deviceCode: started.pair.deviceCode, codeVerifier: started.verifier }); }
  let relay: Awaited<ReturnType<typeof createRelay>> | undefined;
  async function modelFixture(options: MockOptions = {}, kind: 'mock' | 'subscription' = 'mock') {
    const auth = await pair(); const policy = policySchema.parse({ allowedMemberIds: [auth.member.id], models: ['mock-codex'] });
    const created = await api<ClientSourceResponse>('/client/v2/sources', { name: '桌面协议测试', kind, accountBinding: `${kind}:desktop-fixture`, policy }, auth.accessToken);
    const source = created.source;
    await api(`/client/v2/sources/${source.id}/policy-acks`, { revision: 1 }, auth.accessToken);
    const relayLease = await api<RelayLeaseResponse>(`/client/v2/sources/${source.id}/relay-leases`, {}, auth.accessToken);
    const adapter = new MockAdapter({ ...options, accountBinding: source.accountBinding, models: policy.models });
    if (kind === 'subscription') {
      // Synthetic transport tagged as subscription to exercise v2 kind gates;
      // real authentication/HTTP behavior has separate adapter contract tests.
      const inspect = adapter.inspect.bind(adapter), quota = adapter.readQuota.bind(adapter);
      adapter.inspect = async () => ({ ...await inspect(), kind });
      adapter.readQuota = async () => ({ ...await quota(), origin: 'codex' });
    }
    relay = await createRelay({ hubUrl: hub.url, token: relayLease.token, sourceId: source.id, nodeId: 'desktop-node', dbPath: join(dir, 'relay.sqlite'), policy, adapter }); await relay.waitUntilReady();
    const { grant } = await api<{ grant: Grant }>('/client/v2/grants', { sourceId: source.id, label: '桌面会话', models: policy.models }, auth.accessToken);
    async function session() { const { session } = await api<{ session: ClientSession }>('/client/v2/sessions', { grantId: grant.id, modelScope: policy.models }, auth.accessToken); const run = await api<RunLeaseResponse>(`/client/v2/sessions/${session.id}/leases`, {}, auth.accessToken); return { session, run }; }
    const first = await session();
    const infer = (run: RunLeaseResponse, operationId = randomUUID(), input: Record<string, unknown> = {}) => raw('/v1/responses', { model: 'mock-codex', input: 'private-desktop-prompt', ...input }, run.token, 'POST', { 'x-share-operation-id': operationId });
    const ack = (requestId: string, operationId: string, outcome = 'transport_finished') => api<{ request: ClientRequest }>(`/client/v2/requests/${requestId}/delivery-ack`, { operationId, outcome }, auth.accessToken);
    return { auth, source, policy, grant, relayLease, adapter, session, first, infer, ack };
  }
  return { hub, dir, admin, raw, api, browser, startPair, approve, pair, modelFixture, async close() { await relay?.close(); await hub.close(); await rm(dir, { force: true, recursive: true }); } };
}

test('S256 pairing requires browser CSRF, binds challenge, and cancellation wins before redemption', async () => {
  const f = await setup(); try {
    const { pair, verifier } = await f.startPair();
    assert.equal((await f.raw(`/control/v2/device-pairings/${pair.userCode}/approve`, {}, f.admin)).status, 403);
    assert.equal((await f.raw(`/control/v2/device-pairings/${pair.userCode}/approve`, {}, undefined, 'POST', { cookie: f.browser.cookie })).status, 403);
    assert.equal((await f.raw('/client/v2/device-pairings/token', { deviceCode: pair.deviceCode, codeVerifier: 'A'.repeat(64) })).status, 401);
    await f.approve(pair);
    await f.api('/client/v2/device-pairings/cancel', { deviceCode: pair.deviceCode, codeVerifier: verifier });
    assert.equal((await f.raw('/client/v2/device-pairings/token', { deviceCode: pair.deviceCode, codeVerifier: verifier })).status, 403);
    const auth = await f.pair();
    assert.equal((await f.raw('/control/dashboard', undefined, auth.accessToken)).status, 401);
    assert.equal((await f.raw('/v1/models', undefined, auth.accessToken)).status, 401);
    assert.equal((await f.raw('/client/v2/members', undefined, auth.accessToken)).status, 200);
  } finally { await f.close(); }
});

test('refresh rotates atomically and reuse revokes the entire device family', async () => {
  const f = await setup(); try {
    const auth = await f.pair(); const rotated = await f.api<ClientAuthResponse>('/client/v2/auth/refresh', { refreshToken: auth.refreshToken });
    assert.notEqual(rotated.refreshToken, auth.refreshToken);
    const reused = await f.raw('/client/v2/auth/refresh', { refreshToken: auth.refreshToken }); assert.equal(reused.status, 401); assert.equal((await reused.json()).error.code, 'SHARE_REFRESH_REUSED');
    assert.equal((await f.raw('/client/v2/me', undefined, rotated.accessToken)).status, 401);
    assert.equal((await f.raw('/client/v2/auth/refresh', { refreshToken: rotated.refreshToken })).status, 401);
  } finally { await f.close(); }
});

test('desktop operation dedup, two-hop delivery ACK and stable-session resource isolation', async () => {
  const f = await setup(); try {
    const v = await f.modelFixture(); const operationId = randomUUID(); const response = await v.infer(v.first.run, operationId); assert.equal(response.status, 200); const requestId = response.headers.get('x-share-request-id')!; const result = await response.json() as { id: string };
    const duplicate = await v.infer(v.first.run, operationId); assert.equal(duplicate.status, 409); assert.equal(duplicate.headers.get('x-share-request-id'), requestId); assert.equal((await duplicate.json()).error.code, 'SHARE_OPERATION_EXISTS'); assert.equal(v.adapter.calls, 1);
    const changed = await v.infer(v.first.run, operationId, { input: 'changed' }); assert.equal((await changed.json()).error.code, 'SHARE_OPERATION_CONFLICT');
    const nextOp = randomUUID(), next = v.infer(v.first.run, nextOp, { previous_response_id: result.id });
    await new Promise(resolve => setTimeout(resolve, 50)); assert.equal(v.adapter.calls, 1); await v.ack(requestId, operationId);
    const following = await next; assert.equal(following.status, 200); await following.text(); await v.ack(following.headers.get('x-share-request-id')!, nextOp);
    const second = await v.session(); const cross = await v.infer(second.run, randomUUID(), { previous_response_id: result.id }); assert.equal(cross.status, 403); assert.equal(v.adapter.calls, 2);
    const legacy = f.hub.store.issueCredential('grant', v.auth.member.id, { grantId: v.grant.id }); assert.equal((await f.raw('/v1/models', undefined, legacy.token)).status, 409);
    f.hub.store.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); const db = await readFile(join(f.dir, 'hub.sqlite')); for (const value of [v.auth.accessToken, v.auth.refreshToken, v.first.run.token, 'private-desktop-prompt']) assert.equal(db.includes(Buffer.from(value)), false);
  } finally { await f.close(); }
});

test('policy revision ACK gates inference, late delivery ACK survives lease close, and device revoke stops credentials', async () => {
  const f = await setup(); try {
    const v = await f.modelFixture(); const policy = { ...v.policy, reservePercent: 25 };
    await f.api(`/client/v2/sources/${v.source.id}/policy`, { policy, expectedRevision: 1 }, v.auth.accessToken, 'PATCH');
    assert.equal((await v.infer(v.first.run)).status, 409); assert.equal(v.adapter.calls, 0);
    await f.api(`/client/v2/sources/${v.source.id}/policy-acks`, { revision: 2 }, v.auth.accessToken);
    const operationId = randomUUID(); const response = await v.infer(v.first.run, operationId); assert.equal(response.status, 200); await response.text();
    await f.api(`/client/v2/run-leases/${v.first.run.lease.id}/close`, {}, v.auth.accessToken);
    const ack = await v.ack(response.headers.get('x-share-request-id')!, operationId); assert.equal(ack.request.consumerDelivery, 'transport_finished');
    const restored = await f.api<RunLeaseResponse>(`/client/v2/sessions/${v.first.session.id}/leases`, { expectedEpoch: 1 }, v.auth.accessToken); assert.equal(restored.lease.epoch, 2);
    await f.api(`/client/v2/devices/${v.auth.device.id}`, undefined, v.auth.accessToken, 'DELETE');
    assert.equal((await v.infer(restored)).status, 401); assert.equal(v.adapter.calls, 1);
  } finally { await f.close(); }
});

test('lost consumer delivery freezes only its stable session and requires explicit resolution', async () => {
  const f = await setup(); try {
    const v = await f.modelFixture(); const operationId = randomUUID(), response = await v.infer(v.first.run, operationId); await response.text();
    const ack = await v.ack(response.headers.get('x-share-request-id')!, operationId, 'lost'); assert.equal(ack.request.consumerDelivery, 'lost');
    assert.equal((await v.infer(v.first.run)).status, 409); assert.equal(f.hub.store.getGrant(v.grant.id)!.frozen, false);
    const sessions = await f.api<{ sessions: ClientSession[] }>('/client/v2/sessions', undefined, v.auth.accessToken); assert.equal(sessions.sessions[0]!.frozen, true);
    await f.api(`/client/v2/sessions/${v.first.session.id}/resolve-unknown`, { acknowledge: true }, v.auth.accessToken);
    const next = await v.infer(v.first.run); assert.equal(next.status, 200); await next.text();
  } finally { await f.close(); }
});

test('cancel after redemption revokes the newly issued identity and is idempotent', async () => {
  const f = await setup(); try {
    const { pair, verifier } = await f.startPair(); await f.approve(pair);
    const auth = await f.api<ClientAuthResponse>('/client/v2/device-pairings/token', { deviceCode: pair.deviceCode, codeVerifier: verifier });
    const cancelled = await f.api<{status:string;deviceId:string}>('/client/v2/device-pairings/cancel', { deviceCode: pair.deviceCode, codeVerifier: verifier }); assert.equal(cancelled.deviceId, auth.device.id); assert.equal(cancelled.status, 'cancelled');
    await f.api('/client/v2/device-pairings/cancel', { deviceCode: pair.deviceCode, codeVerifier: verifier });
    assert.equal((await f.raw('/client/v2/me', undefined, auth.accessToken)).status, 401);
    assert.equal((await f.raw('/client/v2/auth/refresh', { refreshToken: auth.refreshToken })).status, 401);
  } finally { await f.close(); }
});

test('queued second stable session cannot pass the first session delivery ACK gate', async () => {
  const f = await setup(); try {
    const v = await f.modelFixture({ delayMs: 10 }); const second = await v.session();
    const firstOp = randomUUID(), secondOp = randomUUID();
    const first = await v.infer(v.first.run, firstOp, { stream: true });
    const queued = v.infer(second.run, secondOp);
    await first.text(); await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(v.adapter.calls, 1); assert.equal(f.hub.store.listRequests().length, 2);
    await v.ack(first.headers.get('x-share-request-id')!, firstOp);
    const next = await queued; assert.equal(next.status, 200); await next.text(); await v.ack(next.headers.get('x-share-request-id')!, secondOp); assert.equal(v.adapter.calls, 2);
  } finally { await f.close(); }
});

test('expired relay lease is rejected before dispatch even before the heartbeat timer', async () => {
  const f = await setup(); try {
    const v = await f.modelFixture();
    f.hub.store.db.prepare("UPDATE client_objects SET data=json_set(data,'$.expiresAt',?) WHERE kind='relay' AND id=?").run(Date.now() - 1, v.relayLease.lease.id);
    const response = await v.infer(v.first.run); assert.equal(response.status, 503); assert.equal((await response.json()).error.code, 'SHARE_RELAY_LEASE_EXPIRED'); assert.equal(v.adapter.calls, 0); assert.equal(f.hub.store.listRequests().length, 0);
  } finally { await f.close(); }
});

test('UNKNOWN freezes execution independently of delivery ACK and preserves operation dedup', async () => {
  const f = await setup(); try {
    const v = await f.modelFixture({ mode: 'truncate' }); const operationId = randomUUID();
    const response = await v.infer(v.first.run, operationId, { stream: true }); await response.text().catch(() => undefined);
    const requestId = response.headers.get('x-share-request-id')!;
    assert.equal(f.hub.store.getRequest(requestId)?.state, 'UNKNOWN'); assert.equal(f.hub.store.getSource(v.source.id)?.frozen, true); assert.equal(f.hub.store.getGrant(v.grant.id)?.frozen, false);
    const again = await v.infer(v.first.run, operationId, { stream: true }); assert.equal((await again.json()).error.code, 'SHARE_OPERATION_EXISTS'); assert.equal(v.adapter.calls, 1);
    await v.ack(requestId, operationId);
    const current = await f.api<{session:ClientSession}>(`/client/v2/sessions/${v.first.session.id}`, undefined, v.auth.accessToken); assert.equal(current.session.frozen, true);
    await f.api(`/client/v2/sources/${v.source.id}/resolve-unknown`, { acknowledge: true }, v.auth.accessToken);
    assert.equal((await v.infer(v.first.run)).status, 409); assert.equal(f.hub.store.getRequest(requestId)?.state, 'UNKNOWN');
  } finally { await f.close(); }
});

test('same device recovers a relay lease after restart; another device cannot acknowledge its policy', async () => {
  const f = await setup(); try {
    const v = await f.modelFixture(); const recovered = await f.api<RelayLeaseResponse>(`/client/v2/sources/${v.source.id}/relay-leases`, {}, v.auth.accessToken); assert.equal(recovered.lease.id, v.relayLease.lease.id); assert.notEqual(recovered.token, v.relayLease.token);
    const other = await f.pair(); assert.equal((await f.raw(`/client/v2/sources/${v.source.id}/policy-acks`, { revision: 1 }, other.accessToken)).status, 409);
    assert.equal((await f.raw(`/client/v2/sources/${v.source.id}/relay-leases`, {}, other.accessToken)).status, 409);
  } finally { await f.close(); }
});

test('Hub restart preserves the operation ledger and stable-session UNKNOWN without replay', async () => {
  const f = await setup(); let restarted: Awaited<ReturnType<typeof createHub>> | undefined;
  try {
    const v = await f.modelFixture({ mode: 'hang' }), operationId = randomUUID();
    const response = await v.infer(v.first.run, operationId, { stream: true }); const reading = response.text().catch(() => undefined);
    await f.hub.close(); await reading;
    restarted = await createHub({ dbPath: join(f.dir, 'hub.sqlite'), adminToken: f.admin, port: 0 });
    const headers = { authorization: `Bearer ${v.auth.accessToken}` };
    const session = await (await fetch(`${restarted.url}/client/v2/sessions/${v.first.session.id}`, { headers })).json(); assert.equal(session.session.frozen, true);
    const operation = await (await fetch(`${restarted.url}/client/v2/sessions/${v.first.session.id}/operations/${operationId}`, { headers })).json(); assert.equal(operation.request.state, 'UNKNOWN'); assert.equal(operation.request.consumerDelivery, 'unknown');
    assert.equal(restarted.store.getGrant(v.grant.id)?.frozen, false); assert.equal(restarted.store.getSource(v.source.id)?.frozen, true); assert.equal(v.adapter.calls, 1);
    const resolved = await fetch(`${restarted.url}/client/v2/sessions/${v.first.session.id}/resolve-unknown`, { method: 'POST', headers: { ...headers, 'content-type':'application/json' }, body: JSON.stringify({ acknowledge: true }) }); assert.equal(resolved.status, 200);
    await restarted.close(); restarted = await createHub({ dbPath: join(f.dir, 'hub.sqlite'), adminToken: f.admin, port: 0 });
    const afterAcknowledgement = await (await fetch(`${restarted.url}/client/v2/sessions/${v.first.session.id}`, { headers })).json(); assert.equal(afterAcknowledgement.session.frozen, false, 'manual acknowledgement must survive another restart');
    assert.equal(restarted.store.getRequest(operation.request.id)?.state, 'UNKNOWN', 'acknowledgement cannot rewrite execution history');
  } finally { await restarted?.close(); await f.close(); }
});

test('subscription-tagged synthetic v2 chain retains pairing, policy ACK, session and delivery protections', async () => {
  const f = await setup(); try {
    const v = await f.modelFixture({}, 'subscription');
    assert.equal(v.source.clientMode, 'subscription-v1-compatibility');
    const meta = await f.api<{ desktopDataPlane: string; subscriptionAvailable: boolean }>('/client/v2/meta');
    assert.equal(meta.desktopDataPlane, 'responses-v1'); assert.equal(meta.subscriptionAvailable, true);
    const operationId = randomUUID();
    const response = await v.infer(v.first.run, operationId, { stream: true });
    assert.equal(response.status, 200); assert.match(await response.text(), /response.completed/);
    await v.ack(response.headers.get('x-share-request-id')!, operationId);
    assert.equal(v.adapter.calls, 1);
    assert.equal((await v.infer(v.first.run, operationId)).status, 409);
    assert.equal(v.adapter.calls, 1, 'Repeated operations must not replay subscription requests');
    await f.api(`/client/v2/sources/${v.source.id}/policy`, { policy: { ...v.policy, reservePercent: 35 }, expectedRevision: 1 }, v.auth.accessToken, 'PATCH');
    assert.equal((await v.infer(v.first.run)).status, 409);
    assert.equal(v.adapter.calls, 1);
    assert.equal((await f.raw('/client/v2/sources', { name: 'API must remain explicit', kind: 'api_fixture', accountBinding: 'test', policy: v.policy }, v.auth.accessToken)).status, 400);
  } finally { await f.close(); }
});
