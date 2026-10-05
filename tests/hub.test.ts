import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WebSocket } from 'ws';
import { createHub } from '../apps/hub/index.js';
import { Store } from '../packages/storage/index.js';
import { EMPTY_USAGE, policySchema, type HubFrame, type Source, type Grant, type Member, type AdapterKind, type QuotaSnapshot } from '../packages/protocol/index.js';

const ADMIN = 'test_admin_0123456789_abcdefghijklmnopqrstuvwxyz';
const MODEL = 'test-model';
const quota = () => ({ fetchedAt: Date.now(), status: 'available' as const, origin: 'mock' as const, windows: [{ limitId: 'test', usedPercent: 10, windowDurationMins: 300, resetsAt: null }] });
type Hub = Awaited<ReturnType<typeof createHub>>;
async function control(hub: Hub, path: string, body?: unknown, token = ADMIN, method = body === undefined ? 'GET' : 'POST') {
  return fetch(hub.url + path, { method, headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
}
async function bootstrap(hub: Hub, kind: AdapterKind = 'mock') {
  const session = await (await control(hub, '/control/session')).json() as { member: Member };
  const owner = session.member;
  const response = await control(hub, '/control/sources', { name: '测试贡献节点', kind, accountBinding: 'test-account-' + kind, policy: { models: [MODEL], allowedMemberIds: [owner.id] } });
  assert.equal(response.status, 201);
  const { source, relayToken } = await response.json() as { source: Source; relayToken: string };
  const createGrant = async (label = 'test') => {
    const result = await control(hub, '/control/grants', { sourceId: source.id, label, models: [MODEL] });
    assert.equal(result.status, 201); return result.json() as Promise<{ grant: Grant; token: string }>;
  };
  return { owner, source, relayToken, createGrant, ...(await createGrant()) };
}
async function connect(hub: Hub, source: Source, token: string, initialQuota: QuotaSnapshot = quota(), verified = true) {
  const ws = new WebSocket(hub.url.replace('http:', 'ws:') + '/relay/v1', { headers: { Authorization: `Bearer ${token}` } });
  const frames: HubFrame[] = [];
  const waits: Array<{ predicate: (frame: HubFrame) => boolean; resolve: (frame: HubFrame) => void; timer: NodeJS.Timeout }> = [];
  ws.on('message', raw => { const frame = JSON.parse(raw.toString()) as HubFrame; const index = waits.findIndex(wait => wait.predicate(frame)); if (index >= 0) { const waiter = waits.splice(index, 1)[0]!; clearTimeout(waiter.timer); waiter.resolve(frame); } else frames.push(frame); });
  ws.on('error', () => {});
  function next(type: HubFrame['type']): Promise<HubFrame> {
    const index = frames.findIndex(frame => frame.type === type); if (index >= 0) return Promise.resolve(frames.splice(index, 1)[0]!);
    return new Promise((resolveFrame, reject) => { const entry = { predicate: (frame: HubFrame) => frame.type === type, resolve: resolveFrame, timer: setTimeout(() => { const index = waits.indexOf(entry); if (index >= 0) waits.splice(index, 1); reject(new Error(`timeout waiting for ${type}`)); }, 3000) }; waits.push(entry); });
  }
  await new Promise<void>((resolveOpen, reject) => { ws.once('open', resolveOpen); ws.once('error', reject); });
  ws.send(JSON.stringify({ v: 1, type: 'hello', nodeId: 'test-node', sourceId: source.id, capabilities: { kind: source.kind, verified, accountBinding: source.accountBinding, models: [MODEL], responses: true, compact: true }, quota: initialQuota }));
  const welcome = await next('welcome'); assert.equal(welcome.type, 'welcome');
  const fence = welcome.fence;
  const send = (frame: Record<string, unknown>) => ws.send(JSON.stringify({ v: 1, fence, ...frame }));
  const start = (requestId: string) => { send({ type: 'request.accepted', requestId }); send({ type: 'attempt.started', requestId }); };
  const head = (requestId: string, headers: Record<string, string> = {}) => send({ type: 'response.head', requestId, status: 200, headers: { 'content-type': 'text/event-stream', ...headers } });
  const chunk = (requestId: string, data: string, seq = 0) => send({ type: 'response.chunk', requestId, seq, data: Buffer.from(data).toString('base64') });
  const end = (requestId: string, responseIds: string[] = []) => send({ type: 'response.end', requestId, state: 'COMPLETED', usage: { ...EMPTY_USAGE, inputTokens: 12, outputTokens: 7 }, responseIds, errorCode: null });
  return { ws, frames, next, fence, send, start, head, chunk, end, complete(requestId: string, text = 'data: {"type":"response.completed"}\n\n', responseIds: string[] = []) { start(requestId); head(requestId); chunk(requestId, text); end(requestId, responseIds); } };
}
async function model(hub: Hub, token: string, payload: Record<string, unknown> = {}, signal?: AbortSignal) {
  return fetch(hub.url + '/v1/responses', { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ model: MODEL, input: 'synthetic-secret-prompt', stream: true, ...payload }), signal });
}
async function eventually(predicate: () => boolean, message: string) { for (let i = 0; i < 100; i++) { if (predicate()) return; await new Promise(resolveWait => setTimeout(resolveWait, 10)); } assert.fail(message); }

test('control credentials, model grants and relay tokens are separate; cookie writes require CSRF', async t => {
  const hub = await createHub({ dbPath: ':memory:', adminToken: ADMIN, port: 0 }); t.after(() => hub.close());
  assert.equal((await fetch(hub.url + '/control/dashboard')).status, 401);
  const setup = await bootstrap(hub);
  const models = (query: string) => fetch(hub.url + '/v1/models' + query, { headers: { Authorization: `Bearer ${setup.token}` } });
  assert.equal((await models('?client_version=0.153.4')).status, 200);
  assert.equal((await models('?client_version=0.153.4&client_version=0.154.0')).status, 400);
  assert.equal((await models('?api_key=not-a-key')).status, 400);
  assert.equal((await control(hub, '/control/dashboard', undefined, setup.token)).status, 401);
  assert.equal((await model(hub, ADMIN)).status, 401);
  assert.equal((await model(hub, setup.relayToken)).status, 401);
  const login = await fetch(hub.url + '/control/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: ADMIN }) });
  const cookie = login.headers.get('set-cookie')!.split(';')[0]!; const data = await login.json() as { csrfToken: string };
  assert.equal((await fetch(hub.url + '/control/session', { headers: { cookie } })).status, 200);
  assert.equal((await fetch(hub.url + '/control/invitations', { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: '{}' })).status, 403);
  const inviteResponse = await fetch(hub.url + '/control/invitations', { method: 'POST', headers: { cookie, 'content-type': 'application/json', 'x-csrf-token': data.csrfToken }, body: '{}' });
  assert.equal(inviteResponse.status, 201); const invite = await inviteResponse.json() as { token: string };
  const redeem = () => fetch(hub.url + '/control/invitations/redeem', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: invite.token, name: '朋友' }) });
  assert.equal((await redeem()).status, 201); assert.equal((await redeem()).status, 401);
  assert.equal((await fetch(hub.url + '/control/logout', { method: 'POST', headers: { cookie, 'x-csrf-token': data.csrfToken } })).status, 200);
  assert.equal((await fetch(hub.url + '/control/session', { headers: { cookie } })).status, 401);
});

test('Responses bytes and unknown fields survive; headers and resource ownership are constrained', async t => {
  const hub = await createHub({ dbPath: ':memory:', adminToken: ADMIN, port: 0 }); t.after(() => hub.close());
  const setup = await bootstrap(hub); const relay = await connect(hub, setup.source, setup.relayToken);
  const promise = model(hub, setup.token, { unknown_future_field: { enabled: true } });
  const frame = await relay.next('request.open'); assert.equal(frame.type, 'request.open');
  assert.deepEqual(JSON.parse(Buffer.from(frame.body, 'base64').toString()).unknown_future_field, { enabled: true });
  relay.start(frame.requestId); relay.head(frame.requestId, { 'set-cookie': 'stolen=secret', authorization: 'Bearer upstream-secret' });
  const output = 'event: unknown.event\ndata: {"future":true}\n\ndata: {"type":"response.completed"}\n\n';
  relay.chunk(frame.requestId, output); relay.end(frame.requestId, ['response-test']);
  const response = await promise; assert.equal(response.status, 200); assert.equal(response.headers.get('set-cookie'), null); assert.equal(response.headers.get('authorization'), null); assert.equal(await response.text(), output);
  await eventually(() => hub.store.getRequest(frame.requestId)?.delivery === 'transport_finished', 'delivery should finish');
  assert.equal(hub.store.getRequest(frame.requestId)?.usage.inputTokens, 12);
  const other = await setup.createGrant('second-device'); assert.equal((await model(hub, other.token, { previous_response_id: 'response-test' })).status, 403);
  assert.equal((await model(hub, other.token, { input: [{ type: 'item_reference', id: 'response-test' }] })).status, 403);
  assert.equal((await model(hub, setup.token, { conversation: 'unowned-conversation' })).status, 400);
  assert.equal((await model(hub, setup.token, { input: [{ type: 'message', content: [{ type: 'input_file', file_id: 'unowned-file' }] }] })).status, 400);
  assert.equal((await model(hub, setup.token, { tools: [{ type: 'file_search', vector_store_ids: ['private-vector-store'] }] })).status, 400);
  assert.equal((await model(hub, setup.token, { tools: [{ type: 'code_interpreter', container: 'private-container' }] })).status, 400);
  assert.equal((await model(hub, setup.token, { background: true })).status, 400);
  const followup = model(hub, setup.token, { previous_response_id: 'response-test' }); const followupFrame = await relay.next('request.open'); assert.equal(followupFrame.type, 'request.open'); relay.complete(followupFrame.requestId); assert.equal((await followup).status, 200);
  const stored = hub.store.db.prepare('SELECT data FROM requests').all().map(row => row.data).join(''); assert.ok(!stored.includes('synthetic-secret-prompt')); assert.ok(!stored.includes('upstream-secret'));
});

test('one active or queued request per grant, source queue bounded to three distinct grants', async t => {
  const hub = await createHub({ dbPath: ':memory:', adminToken: ADMIN, port: 0, queueTimeoutMs: 10_000 }); t.after(() => hub.close());
  const setup = await bootstrap(hub); const relay = await connect(hub, setup.source, setup.relayToken);
  const first = model(hub, setup.token); const open = await relay.next('request.open'); assert.equal(open.type, 'request.open');
  assert.equal((await model(hub, setup.token)).status, 429);
  const grants = await Promise.all([setup.createGrant('q1'), setup.createGrant('q2'), setup.createGrant('q3'), setup.createGrant('overflow')]);
  const queued = grants.slice(0, 3).map(grant => model(hub, grant.token));
  await eventually(() => hub.store.queuedForSource(setup.source.id).length === 3, 'three should be queued');
  assert.equal((await model(hub, grants[3]!.token)).status, 429);
  for (const request of hub.store.queuedForSource(setup.source.id)) assert.equal((await control(hub, `/control/requests/${request.id}/cancel`, {})).status, 200);
  for (const promise of queued) assert.equal((await promise).status, 409);
  relay.complete(open.requestId); assert.equal((await first).status, 200);
  assert.equal(hub.store.listRequests().length, 4);
});

test('relay disconnect after dispatch freezes source and grant with UNKNOWN, never redispatches', async t => {
  const hub = await createHub({ dbPath: ':memory:', adminToken: ADMIN, port: 0 }); t.after(() => hub.close());
  const setup = await bootstrap(hub); const relay = await connect(hub, setup.source, setup.relayToken);
  const promise = model(hub, setup.token); const open = await relay.next('request.open'); assert.equal(open.type, 'request.open');
  relay.start(open.requestId); relay.ws.terminate();
  assert.equal((await promise).status, 409);
  await eventually(() => !hub.store.getSource(setup.source.id)!.online, 'source should go offline');
  assert.equal(hub.store.getRequest(open.requestId)?.state, 'UNKNOWN'); assert.equal(hub.store.getSource(setup.source.id)?.frozen, true); assert.equal(hub.store.getGrant(setup.grant.id)?.frozen, true);
  const replacement = await connect(hub, setup.source, setup.relayToken); assert.ok(replacement.fence > relay.fence);
  assert.equal((await model(hub, setup.token)).status, 409); assert.equal(replacement.frames.filter(frame => frame.type === 'request.open').length, 0);
  assert.equal((await control(hub, `/control/sources/${setup.source.id}/resolve-unknown`, { acknowledge: true })).status, 200);
  assert.equal(hub.store.getRequest(open.requestId)?.state, 'UNKNOWN');
});

test('consumer delivery loss freezes only grant when upstream later confirms completion', async t => {
  const hub = await createHub({ dbPath: ':memory:', adminToken: ADMIN, port: 0 }); t.after(() => hub.close());
  const setup = await bootstrap(hub); const relay = await connect(hub, setup.source, setup.relayToken); const abort = new AbortController();
  const promise = model(hub, setup.token, {}, abort.signal); const open = await relay.next('request.open'); assert.equal(open.type, 'request.open');
  relay.start(open.requestId); relay.head(open.requestId); relay.chunk(open.requestId, 'data: {"type":"delta","value":"x"}\n\n');
  const response = await promise; assert.equal(response.status, 200); abort.abort();
  const cancel = await relay.next('cancel.request'); assert.equal(cancel.type, 'cancel.request'); assert.equal(cancel.requestId, open.requestId);
  relay.end(open.requestId);
  await eventually(() => hub.store.getRequest(open.requestId)?.state === 'COMPLETED', 'completion after cancellation must be retained');
  assert.equal(hub.store.getRequest(open.requestId)?.delivery, 'lost'); assert.equal(hub.store.getGrant(setup.grant.id)?.frozen, true); assert.equal(hub.store.getSource(setup.source.id)?.frozen, false);
});

test('a reconnected source can reconcile a persisted terminal result without replaying the request', async t => {
  const hub = await createHub({ dbPath: ':memory:', adminToken: ADMIN, port: 0 }); t.after(() => hub.close());
  const setup = await bootstrap(hub); const relay = await connect(hub, setup.source, setup.relayToken);
  const promise = model(hub, setup.token); const open = await relay.next('request.open'); assert.equal(open.type, 'request.open'); relay.start(open.requestId); relay.ws.terminate();
  assert.equal((await promise).status, 409); await eventually(() => !hub.store.getSource(setup.source.id)!.online, 'old relay should disconnect');
  const recovery = await connect(hub, setup.source, setup.relayToken); const query = await recovery.next('status.query'); assert.equal(query.type, 'status.query'); assert.equal(query.requestId, open.requestId); assert.ok(query.fence > relay.fence);
  recovery.send({ type: 'status.result', requestId: query.requestId, state: 'COMPLETED', usage: { ...EMPTY_USAGE, inputTokens: 99 }, responseIds: ['recovered-response'] });
  await eventually(() => hub.store.getRequest(open.requestId)?.state === 'COMPLETED', 'metadata should reconcile');
  assert.equal(hub.store.getRequest(open.requestId)?.delivery, 'lost'); assert.equal(hub.store.getRequest(open.requestId)?.usage.inputTokens, 99); assert.equal(hub.store.getSource(setup.source.id)?.frozen, false); assert.equal(hub.store.getGrant(setup.grant.id)?.frozen, true);
  assert.equal(recovery.frames.filter(frame => frame.type === 'request.open').length, 0); hub.store.assertResourceOwnership(setup.source.id, setup.grant.id, 'recovered-response');
});

test('stale quota and unverified subscription never dispatch; duplicate relay is rejected', async t => {
  const hub = await createHub({ dbPath: ':memory:', adminToken: ADMIN, port: 0 }); t.after(() => hub.close());
  const setup = await bootstrap(hub); const relay = await connect(hub, setup.source, setup.relayToken, { ...quota(), fetchedAt: Date.now() - 600_000 });
  assert.equal((await model(hub, setup.token)).status, 503); assert.equal(relay.frames.filter(frame => frame.type === 'request.open').length, 0);
  const duplicate = new WebSocket(hub.url.replace('http:', 'ws:') + '/relay/v1', { headers: { Authorization: `Bearer ${setup.relayToken}` } });
  await new Promise<void>((resolveRejected, reject) => { duplicate.once('unexpected-response', (_req, response) => { assert.equal(response.statusCode, 409); duplicate.terminate(); resolveRejected(); }); duplicate.once('open', () => reject(new Error('duplicate accepted'))); duplicate.on('error', () => {}); });
  const subscription = await bootstrap(hub, 'subscription'); const subscriptionRelay = await connect(hub, subscription.source, subscription.relayToken, { ...quota(), origin: 'codex' }, false);
  assert.equal((await model(hub, subscription.token)).status, 501); assert.equal(subscriptionRelay.frames.filter(frame => frame.type === 'request.open').length, 0);
});

test('protocol sequence violation becomes UNKNOWN instead of a successful empty response', async t => {
  const hub = await createHub({ dbPath: ':memory:', adminToken: ADMIN, port: 0 }); t.after(() => hub.close());
  const setup = await bootstrap(hub); const relay = await connect(hub, setup.source, setup.relayToken);
  const promise = model(hub, setup.token); const open = await relay.next('request.open'); assert.equal(open.type, 'request.open');
  relay.head(open.requestId); assert.equal((await promise).status, 409);
  assert.equal(hub.store.getRequest(open.requestId)?.state, 'UNKNOWN');
});

test('restart marks dispatched requests UNKNOWN, cancels provably unsent requests, retains metadata', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'share-token-hub-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'); const store = new Store(path); const member = store.ensureAdmin(ADMIN);
  const source = store.createSource({ name: 'restart source', ownerId: member.id, kind: 'mock', accountBinding: 'restart', policy: policySchema.parse({ models: [MODEL], allowedMemberIds: [member.id] }) });
  const grant = store.createGrant({ memberId: member.id, sourceId: source.id, label: 'restart', models: [MODEL] });
  const request = store.createRequest({ grantId: grant.id, memberId: member.id, sourceId: source.id, model: MODEL, operation: 'responses' }); store.updateRequest(request.id, { state: 'DISPATCHED' });
  const otherGrant = store.createGrant({ memberId: member.id, sourceId: source.id, label: 'queued', models: [MODEL] });
  const queued = store.createRequest({ grantId: otherGrant.id, memberId: member.id, sourceId: source.id, model: MODEL, operation: 'responses' }); store.close();
  const hub = await createHub({ dbPath: path, adminToken: ADMIN, port: 0 }); t.after(() => hub.close());
  assert.equal(hub.store.getRequest(request.id)?.state, 'UNKNOWN'); assert.equal(hub.store.getRequest(request.id)?.delivery, 'unknown'); assert.equal(hub.store.getSource(source.id)?.frozen, true); assert.equal(hub.store.getGrant(grant.id)?.frozen, true);
  assert.equal(hub.store.getRequest(queued.id)?.state, 'CANCELLED_NOT_SENT'); assert.equal(hub.store.getGrant(otherGrant.id)?.frozen, false);
});

test('a second hub cannot recover or mutate a live hub database', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'share-token-single-hub-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'hub.sqlite'); const hub = await createHub({ dbPath: path, adminToken: ADMIN, port: 0 }); t.after(() => hub.close());
  const setup = await bootstrap(hub); const relay = await connect(hub, setup.source, setup.relayToken);
  const promise = model(hub, setup.token); const open = await relay.next('request.open'); assert.equal(open.type, 'request.open'); relay.start(open.requestId);
  await eventually(() => hub.store.getRequest(open.requestId)?.state === 'UPSTREAM_STARTED', 'first hub must remain active');
  await assert.rejects(createHub({ dbPath: path, adminToken: 'different-admin-secret-0123456789', port: 0 }), (error: unknown) => error instanceof Error && 'code' in error && error.code === 'SHARE_HUB_ALREADY_RUNNING');
  assert.equal(hub.store.getRequest(open.requestId)?.state, 'UPSTREAM_STARTED'); assert.equal(hub.store.getSource(setup.source.id)?.frozen, false); assert.equal((await control(hub, '/control/session')).status, 200);
  relay.head(open.requestId); relay.chunk(open.requestId, 'data: {"type":"response.completed"}\n\n'); relay.end(open.requestId); assert.equal((await promise).status, 200);
});

test('verified subscription dispatch requires Codex quota and keeps fixed-source admission', async t => {
  const hub = await createHub({ dbPath: ':memory:', adminToken: ADMIN, port: 0 }); t.after(() => hub.close());
  const setup = await bootstrap(hub, 'subscription');
  const relay = await connect(hub, setup.source, setup.relayToken);
  // A mock or fixture percentage cannot authorize real subscription inference.
  assert.equal((await model(hub, setup.token)).status, 503);
  assert.equal(relay.frames.filter(frame => frame.type === 'request.open').length, 0);
  hub.store.updateSource(setup.source.id, { quota: { ...quota(), origin: 'codex' } });
  const pending = model(hub, setup.token);
  const open = await relay.next('request.open'); assert.equal(open.type, 'request.open');
  assert.equal(open.sourceId, setup.source.id);
  relay.complete(open.requestId);
  const response = await pending; assert.equal(response.status, 200); await response.text();
  await eventually(() => hub.store.getRequest(open.requestId)?.state === 'COMPLETED', 'Subscription tagged fixture should complete');
});
