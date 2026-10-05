import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WebSocket } from 'ws';
import { createHub } from '../apps/hub/index.js';
import { createRelay } from '../apps/relay/index.js';
import { ClientStore } from '../packages/storage/client.js';
import { MockAdapter } from '../packages/upstream/index.js';
import { policySchema, type Dashboard, type Grant, type Member, type Source } from '../packages/protocol/index.js';

async function fixture(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), 'matching-legacy-isolation-'));
  const adminToken = 'test_legacy_room_admin_abcdefghijklmnopqrstuvwxyz';
  const hub = await createHub({ dbPath: join(directory, 'hub.sqlite'), adminToken, port: 0 });
  let relay: Awaited<ReturnType<typeof createRelay>> | undefined;
  t.after(async () => { await relay?.close(); await hub.close(); await rm(directory, { recursive: true, force: true }); });
  const clients = new ClientStore(hub.store);
  const admin = hub.store.listMembers().find(member => member.role === 'admin')!;
  const legacy = hub.store.createMember('Legacy friend');
  function matched(code: string, name: string) {
    const verifier = randomBytes(48).toString('base64url');
    const pair = clients.createPairing({ deviceName: name, platform: 'test', clientVersion: 'test', requestedScopes: ['consumer', 'donor'], codeChallenge: createHash('sha256').update(verifier).digest('base64url') }, hub.url);
    clients.matchPairing(pair.deviceCode, verifier, code);
    return clients.redeemPairing(pair.deviceCode, verifier).member;
  }
  const first = matched('62841973', 'Room A donor'), friend = matched('62841973', 'Room A friend'), outsider = matched('39178624', 'Room B');
  const tokens = new Map([admin, legacy, first, friend, outsider].map(member => [member.id, member.id === admin.id ? adminToken : hub.store.issueCredential('control', member.id).token]));
  const raw = (path: string, member: Member, body?: unknown, method = body === undefined ? 'GET' : 'POST') => fetch(hub.url + path, {
    method, headers: { authorization: `Bearer ${tokens.get(member.id)}`, 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  async function api<T>(path: string, member: Member, body?: unknown, method?: string): Promise<T> {
    const response = await raw(path, member, body, method);
    assert.equal(response.ok, true, `${path}: ${response.status} ${response.ok ? '' : await response.text()}`);
    return response.json() as Promise<T>;
  }
  function source(owner: Member, allowed: Member[], binding: string) {
    return hub.store.createSource({ name: binding, kind: 'mock', accountBinding: binding, ownerId: owner.id, policy: policySchema.parse({ allowedMemberIds: allowed.map(member => member.id), models: ['mock-codex'] }) });
  }
  function grant(source: Source, member: Member) { return hub.store.createGrant({ sourceId: source.id, memberId: member.id, models: source.policy.models, label: 'test' }); }
  function request(source: Source, grant: Grant, inputTokens = 1, outputTokens = 2) {
    const request = hub.store.createRequest({ sourceId: source.id, grantId: grant.id, memberId: grant.memberId, model: 'mock-codex', operation: 'responses' });
    return hub.store.updateRequest(request.id, { state: 'COMPLETED', finishedAt: Date.now(), delivery: 'transport_finished', usage: { ...request.usage, inputTokens, outputTokens } });
  }
  async function startRelay(source: Source) {
    const adapter = new MockAdapter({ accountBinding: source.accountBinding, models: source.policy.models });
    relay = await createRelay({ hubUrl: hub.url, token: hub.store.issueCredential('relay', source.ownerId, { sourceId: source.id }).token,
      sourceId: source.id, nodeId: 'legacy-isolation-test', dbPath: join(directory, 'relay.sqlite'), policy: source.policy, adapter });
    await relay.waitUntilReady(); return adapter;
  }
  return { hub, clients, admin, legacy, first, friend, outsider, raw, api, source, grant, request, startRelay };
}

test('legacy dashboard scopes members, sources, grants, full-history stats and recent requests to its room', async t => {
  const f = await fixture(t);
  const legacySource = f.source(f.admin, [f.admin, f.legacy], 'legacy-dashboard');
  const roomSource = f.source(f.first, [f.first, f.friend], 'room-a-dashboard');
  const otherSource = f.source(f.outsider, [f.outsider], 'room-b-dashboard');
  const legacyGrant = f.grant(legacySource, f.legacy), roomGrant = f.grant(roomSource, f.friend), otherGrant = f.grant(otherSource, f.outsider);
  for (let i = 0; i < 205; i++) f.request(legacySource, legacyGrant);
  for (let i = 0; i < 205; i++) f.request(roomSource, roomGrant, 3, 4);
  f.request(otherSource, otherGrant, 10000, 20000);
  const legacy = await f.api<Dashboard>('/control/dashboard', f.admin);
  assert.deepEqual(new Set(legacy.members.map(member => member.id)), new Set([f.admin.id, f.legacy.id]));
  assert.deepEqual(legacy.sources.map(source => source.id), [legacySource.id]);
  assert.deepEqual(legacy.grants.map(grant => grant.id), [legacyGrant.id]);
  assert.equal(legacy.requests.length, 200, 'Newer requests in another room must not push this room out of the limit.');
  assert.ok(legacy.requests.every(request => request.sourceId === legacySource.id));
  assert.deepEqual(legacy.stats, { completed: 205, unknown: 0, inputTokens: 205, outputTokens: 410 });
  const room = await f.api<Dashboard>('/control/dashboard', f.first);
  assert.deepEqual(new Set(room.members.map(member => member.id)), new Set([f.first.id, f.friend.id]));
  assert.deepEqual(room.sources.map(source => source.id), [roomSource.id]);
  assert.deepEqual(room.grants.map(grant => grant.id), [roomGrant.id]);
  assert.equal(room.requests.length, 200);
  assert.deepEqual(room.stats, { completed: 205, unknown: 0, inputTokens: 615, outputTokens: 820 });
  const invalidGrant = f.grant(roomSource, f.outsider); f.request(roomSource, invalidGrant, 999, 999);
  const after = await f.api<Dashboard>('/control/dashboard', f.first);
  assert.deepEqual(after.stats, room.stats, 'An anomalous cross-room consumer must not leak through source ownership.');
  assert.equal(after.grants.some(grant => grant.id === invalidGrant.id), false);
});

test('legacy control routes reject cross-room reads, administration, policies and grants without changing same-room behavior', async t => {
  const f = await fixture(t);
  const source = f.source(f.first, [f.first, f.friend], 'control-room-a');
  const grant = f.grant(source, f.friend), request = f.request(source, grant);
  for (const actor of [f.admin, f.outsider]) {
    for (const [path, body, method] of [
      [`/control/sources/${source.id}/pause`, { paused: true }, 'POST'],
      [`/control/sources/${source.id}/resolve-unknown`, { acknowledge: true }, 'POST'],
      [`/control/sources/${source.id}/policy`, { policy: source.policy }, 'PATCH'],
      [`/control/grants/${grant.id}`, undefined, 'DELETE'],
      [`/control/grants/${grant.id}/resolve-unknown`, { acknowledge: true }, 'POST'],
      [`/control/requests/${request.id}`, undefined, 'GET'],
      [`/control/requests/${request.id}/cancel`, {}, 'POST'],
      ['/control/grants', { sourceId: source.id, memberId: f.friend.id, label: 'cross-room', models: ['mock-codex'] }, 'POST'],
    ] as const) assert.equal((await f.raw(path, actor, body, method)).status, 404, `${actor.name} ${path}`);
  }
  assert.equal((await f.raw(`/control/members/${f.friend.id}`, f.admin, undefined, 'DELETE')).status, 404);
  assert.equal(f.hub.store.getMember(f.friend.id)!.active, true);
  assert.equal(f.hub.store.getGrant(grant.id)!.revoked, false);
  assert.equal(f.hub.store.getSource(source.id)!.paused, false);

  const invalidPolicy = { ...source.policy, allowedMemberIds: [f.first.id, f.outsider.id] };
  assert.equal((await f.raw('/control/sources', f.first, { name: 'invalid', kind: 'mock', accountBinding: 'invalid-policy', policy: invalidPolicy })).status, 400);
  assert.equal((await f.raw(`/control/sources/${source.id}/policy`, f.first, { policy: invalidPolicy }, 'PATCH')).status, 400);
  assert.deepEqual(f.hub.store.getSource(source.id)!.policy, source.policy);
  f.hub.store.updateSource(source.id, { policy: invalidPolicy });
  assert.equal((await f.raw('/control/grants', f.first, { sourceId: source.id, memberId: f.outsider.id, label: 'stale policy', models: ['mock-codex'] })).status, 404);
  f.hub.store.updateSource(source.id, { policy: source.policy });
  await f.api(`/control/sources/${source.id}/pause`, f.first, { paused: true });
  await f.api(`/control/sources/${source.id}/pause`, f.first, { paused: false });
  await f.api(`/control/requests/${request.id}`, f.friend);
  const own = await f.api<{ grant: Grant }>('/control/grants', f.friend, { sourceId: source.id, label: 'same-room', models: ['mock-codex'] });
  await f.api(`/control/grants/${own.grant.id}/resolve-unknown`, f.friend, { acknowledge: true });
  await f.api(`/control/grants/${own.grant.id}`, f.friend, undefined, 'DELETE');
  const created = await f.api<{ source: Source }>('/control/sources', f.admin, { name: 'legacy', kind: 'mock', accountBinding: 'legacy-created', policy: policySchema.parse({ allowedMemberIds: [f.admin.id, f.legacy.id], models: ['mock-codex'] }) });
  await f.api(`/control/sources/${created.source.id}/policy`, f.admin, { policy: created.source.policy }, 'PATCH');
  await f.api(`/control/members/${f.legacy.id}`, f.admin, undefined, 'DELETE');
  assert.equal(f.hub.store.getMember(f.legacy.id)!.active, false);
});

test('legacy model and inference paths reject stale cross-room grants before reaching the relay', async t => {
  const f = await fixture(t);
  // Seed an old/inconsistent allowlist deliberately: room admission must still
  // reject it even if an existing grant and relay policy would otherwise allow it.
  const source = f.source(f.admin, [f.admin, f.legacy, f.outsider], 'legacy-data');
  const adapter = await f.startRelay(source);
  const valid = f.grant(source, f.legacy), invalid = f.grant(source, f.outsider);
  const token = f.hub.store.issueCredential('grant', invalid.memberId, { grantId: invalid.id }).token;
  for (const path of ['/v1/models', '/v1/responses', '/v1/responses/compact']) {
    const response = await fetch(f.hub.url + path, { method: path.endsWith('models') ? 'GET' : 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      ...(path.endsWith('models') ? {} : { body: JSON.stringify({ model: 'mock-codex', input: 'synthetic' }) }) });
    assert.equal(response.status, 404); await response.arrayBuffer();
  }
  assert.equal(adapter.calls, 0); assert.equal(f.hub.store.listRequests().length, 0);
  const allowedToken = f.hub.store.issueCredential('grant', valid.memberId, { grantId: valid.id }).token;
  const models = await fetch(f.hub.url + '/v1/models', { headers: { authorization: `Bearer ${allowedToken}` } });
  assert.equal(models.status, 200); await models.arrayBuffer();
  const response = await fetch(f.hub.url + '/v1/responses', { method: 'POST', headers: { authorization: `Bearer ${allowedToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-codex', input: 'synthetic' }) });
  assert.equal(response.status, 200); await response.arrayBuffer(); assert.equal(adapter.calls, 1);
});

test('legacy relay credential must belong to the source owner, even inside one room', async t => {
  const f = await fixture(t);
  const source = f.source(f.admin, [f.admin, f.legacy], 'relay-owner');
  await f.startRelay(source);
  for (const member of [f.legacy, f.outsider]) {
    const token = f.hub.store.issueCredential('relay', member.id, { sourceId: source.id }).token;
    const status = await new Promise<number>((resolve, reject) => {
      const socket = new WebSocket(f.hub.url.replace(/^http/, 'ws') + '/relay/v1', { headers: { authorization: `Bearer ${token}` } });
      const timeout = setTimeout(() => { socket.terminate(); reject(new Error('WebSocket rejection timed out')); }, 5000);
      socket.on('error', () => {});
      socket.on('unexpected-response', (_request, response) => { clearTimeout(timeout); response.resume(); socket.terminate(); resolve(response.statusCode!); });
      socket.on('open', () => { clearTimeout(timeout); socket.close(); resolve(101); });
    });
    assert.equal(status, 401, 'Non-owner relay credentials must fail before source occupancy is checked.');
  }
});
