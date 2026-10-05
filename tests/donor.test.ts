import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { DonorController, type DonorHub, type DonorSnapshot } from '../packages/client-core/donor.js';
import { createHub } from '../apps/hub/index.js';
import { HubClient } from '../packages/hub-client/index.js';
import { ClientStore } from '../packages/storage/client.js';
import { MockAdapter, type MockOptions } from '../packages/upstream/index.js';
import { policySchema, ShareError, type Source, type Member, type SharePolicy, type Grant } from '../packages/protocol/index.js';
import type { ClientAuthResponse, DevicePairingResponse, ClientSession, ClientSource, RunLeaseResponse } from '../packages/protocol/client.js';

// Opt in only for synthetic regression fixtures; these tests never call a real upstream.
const previousExperimentalSubscription = process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION;
process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = '1';
after(() => { if (previousExperimentalSubscription === undefined) delete process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION; else process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = previousExperimentalSubscription; });

async function eventually(predicate: () => boolean, description: string) {
  for (let attempt = 0; attempt < 200; attempt++) { if (predicate()) return; await delay(10); }
  assert.fail(description);
}
async function fixture(mockOptions: MockOptions = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'share-donor-test-'));
  const adminToken = 'donor_test_admin_abcdefghijklmnopqrstuvwxyz';
  const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken, port: 0 });
  const control = async <T>(path: string, body?: unknown): Promise<T> => {
    const response = await fetch(hub.url + path, { method: body === undefined ? 'GET' : 'POST', headers: { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    assert.equal(response.ok, true, `${path} ${response.status}`); return response.json() as Promise<T>;
  };
  const { member } = await control<{ member: Member }>('/control/session');
  const policy = policySchema.parse({ allowedMemberIds: [member.id], models: ['mock-codex'] });
  const { source, relayToken } = await control<{ source: Source; relayToken: string }>('/control/sources', { name: 'Donor 合成来源', kind: 'mock', accountBinding: 'mock:donor-test', policy });
  const { token: modelToken } = await control<{ token: string }>('/control/grants', { sourceId: source.id, label: 'consumer-test', models: ['mock-codex'] });
  const adapter = new MockAdapter({ ...mockOptions, accountBinding: source.accountBinding, models: policy.models });
  const snapshots: DonorSnapshot[] = [];
  const stateDir = join(dir, 'donor');
  const donor = new DonorController({ stateDir, adapterFactory: () => adapter, onSnapshot: state => snapshots.push(state), heartbeatMs: 30 });
  await donor.configure({ name: source.name, hubUrl: hub.url, sourceId: source.id, kind: 'mock', accountBinding: source.accountBinding, policy });
  const request = () => fetch(`${hub.url}/v1/responses`, { method: 'POST', headers: { authorization: `Bearer ${modelToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-codex', input: 'donor synthetic fixture', stream: true }) });
  return { dir, stateDir, hub, source, relayToken, modelToken, donor, adapter, snapshots, policy, request,
    async close() { await donor.close(); await hub.close(); await rm(dir, { recursive: true, force: true }); } };
}

test('donor starts a real relay chain, drains without aborting, and stores no bearer credential', async t => {
  const f = await fixture({ delayMs: 12 }); t.after(() => f.close());
  assert.equal(f.donor.snapshot().status, 'paused');
  assert.equal((await f.donor.start({ relayToken: f.relayToken })).status, 'sharing');
  const response = await f.request(); assert.equal(response.status, 200);
  await eventually(() => !!f.donor.snapshot().relay?.activeRequestId, 'Relay should have an active request');
  const paused = await f.donor.drain(); assert.equal(paused.desiredSharing, false); assert.equal(paused.status, 'draining');
  assert.match(await response.text(), /response.completed/);
  await eventually(() => f.donor.snapshot().status === 'paused', 'Drain should settle to paused');
  assert.equal(f.hub.store.listRequests()[0]?.state, 'COMPLETED'); assert.equal(f.adapter.calls, 1);
  assert.equal((await f.donor.resume()).status, 'sharing');
  const again = await f.request(); assert.equal(again.status, 200); await again.text(); assert.equal(f.adapter.calls, 2);
  await f.donor.close();
  const serialized = JSON.stringify(f.snapshots);
  assert.equal(serialized.includes(f.relayToken), false); assert.equal(serialized.includes(f.modelToken), false);
  for (const name of await readdir(f.stateDir)) {
    const bytes = await readFile(join(f.stateDir, name));
    assert.equal(bytes.includes(Buffer.from(f.relayToken)), false, `${name} stored a relay credential`);
  }
  const reopened = new DonorController({ stateDir: f.stateDir });
  assert.equal(reopened.snapshot().desiredSharing, false); assert.equal(reopened.snapshot().status, 'paused'); await reopened.close();
});

test('immediate stop aborts, keeps the result unknown, and never replays on resume', async t => {
  const f = await fixture({ mode: 'hang' }); t.after(() => f.close());
  await f.donor.start({ relayToken: f.relayToken }); const response = await f.request();
  const body = response.text().catch(() => 'disconnected');
  await f.donor.stopNow(); await body;
  await eventually(() => f.hub.store.listRequests()[0]?.state === 'UNKNOWN', 'Stop should not claim upstream cancellation');
  assert.equal(f.adapter.calls, 1); assert.equal(f.donor.snapshot().desiredSharing, false);
  assert.equal(f.donor.snapshot().status, 'frozen');
  await assert.rejects(f.donor.start({ relayToken: f.relayToken }), /待核实/);
  assert.equal(f.adapter.calls, 1);
});

test('suspend stops idle sharing and wake never implicitly enables it', async t => {
  const f = await fixture(); t.after(() => f.close());
  await f.donor.start({ relayToken: f.relayToken }); assert.equal((await f.donor.suspend()).status, 'suspended');
  const awakened = await f.donor.wake(); assert.equal(awakened.status, 'paused'); assert.equal(awakened.desiredSharing, false);
  assert.equal(f.adapter.calls, 0); assert.equal((await f.donor.start({ relayToken: f.relayToken })).status, 'sharing');
});

test('suspend during adapter inspection cancels startup and cannot enable sharing later', async t => {
  const f = await fixture(); t.after(() => f.close());
  const inspect = f.adapter.inspect.bind(f.adapter);
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  f.adapter.inspect = async () => { await pending; return inspect(); };
  const starting = f.donor.start({ relayToken: f.relayToken });
  const rejected = assert.rejects(starting, /已被暂停或停止/);
  await f.donor.suspend(); release(); await rejected;
  assert.equal(f.donor.snapshot().status, 'suspended'); assert.equal(f.donor.snapshot().desiredSharing, false);
  assert.equal(f.donor.snapshot().relay, null); assert.equal(f.adapter.calls, 0);
});

for (const kind of ['mock', 'subscription'] as const) test(`v2 ${kind} device lease executes a synthetic request and policy preserves source identity`, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'share-donor-v2-'));
  const admin = 'donor_v2_admin_abcdefghijklmnopqrstuvwxyz';
  const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: admin, port: 0 });
  let donor: DonorController | undefined;
  t.after(async () => { await donor?.close(); await hub.close(); await rm(dir, { recursive: true, force: true }); });
  async function api<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    const response = await fetch(hub.url + path, { method, headers: { 'content-type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    assert.equal(response.ok, true, `${path}: ${response.status} ${response.ok ? '' : await response.text()}`); return response.json() as Promise<T>;
  }
  const login = await fetch(hub.url + '/control/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: admin }) });
  const browser = { cookie: login.headers.get('set-cookie')!.split(';')[0]!, 'x-csrf-token': (await login.json() as { csrfToken: string }).csrfToken };
  const verifier = randomBytes(48).toString('base64url');
  const pair = await api<DevicePairingResponse>('POST', '/client/v2/device-pairings', { deviceName: 'Donor fixture', platform: 'test', clientVersion: 'test', requestedScopes: ['consumer', 'donor'], codeChallengeMethod: 'S256', codeChallenge: createHash('sha256').update(verifier).digest('base64url') });
  await api('POST', `/control/v2/device-pairings/${pair.userCode}/approve`, { approvedScopes: ['consumer', 'donor'] }, browser);
  const auth = await api<ClientAuthResponse>('POST', '/client/v2/device-pairings/token', { deviceCode: pair.deviceCode, codeVerifier: verifier });
  const facade: DonorHub = { baseUrl: hub.url, request: <T>(method: string, path: string, body?: unknown) => api<T>(method, path, body, { authorization: `Bearer ${auth.accessToken}` }) };
  const stateDir = join(dir, 'donor'); donor = new DonorController({ stateDir, hub: facade, heartbeatMs: 30,
    subscriptionAccount: { inspect: async () => ({ authenticated: true, accountBinding: 'codex:synthetic', planType: 'test', models: ['mock-codex'], quota: await new MockAdapter().readQuota() }) },
    adapterFactory: config => { const adapter = new MockAdapter({ accountBinding: config.accountBinding, models: config.policy.models, delayMs: 12 }); if (kind === 'subscription') { const inspect = adapter.inspect.bind(adapter), readQuota = adapter.readQuota.bind(adapter); adapter.inspect = async () => ({ ...await inspect(), kind: 'subscription' }); adapter.readQuota = async () => ({ ...await readQuota(), origin: 'codex' }); } return adapter; } });
  const policy = policySchema.parse({ models: ['mock-codex'], allowedMemberIds: [auth.member.id] });
  const configured = await donor.configure({ name: 'Test synthetic source', kind, policy });
  assert.equal(configured.policySync, 'synced'); assert.equal(configured.source?.appliedPolicyRevision, 1);
  const sourceId = configured.config!.sourceId!; const binding = configured.config!.accountBinding;
  const tighter = { ...policy, reservePercent: 40 };
  const saved = await donor.configure({ name: 'Test synthetic source', kind, policy: tighter });
  assert.equal(saved.config?.sourceId, sourceId); assert.equal(saved.config?.accountBinding, binding);
  assert.equal(saved.source?.policy.reservePercent, 40); assert.equal(saved.hubPolicyRevision, 2); assert.equal(saved.source?.appliedPolicyRevision, 2);
  assert.equal((await donor.start()).status, 'sharing');
  const { grant } = await facade.request<{ grant: Grant }>('POST', '/client/v2/grants', { sourceId, label: 'test', models: ['mock-codex'] });
  const { session } = await facade.request<{ session: ClientSession }>('POST', '/client/v2/sessions', { grantId: grant.id, modelScope: ['mock-codex'] });
  const run = await facade.request<RunLeaseResponse>('POST', `/client/v2/sessions/${session.id}/leases`, {});
  const operationId = randomUUID();
  const response = await fetch(hub.url + '/v1/responses', { method: 'POST', headers: { authorization: `Bearer ${run.token}`, 'content-type': 'application/json', 'x-share-operation-id': operationId }, body: JSON.stringify({ model: 'mock-codex', input: 'synthetic fixture', stream: true }) });
  assert.equal(response.status, 200);
  assert.equal((await donor.drain()).status, 'draining');
  assert.match(await response.text(), /response.completed/);
  await facade.request('POST', `/client/v2/requests/${response.headers.get('x-share-request-id')}/delivery-ack`, { operationId, outcome: 'transport_finished' });
  assert.equal(hub.store.listRequests()[0]?.state, 'COMPLETED');
  await donor.stopNow(); assert.equal(donor.snapshot().desiredSharing, false);
  for (const file of await readdir(stateDir)) {
    const bytes = await readFile(join(stateDir, file));
    for (const secret of [auth.accessToken, auth.refreshToken, run.token]) assert.equal(bytes.includes(Buffer.from(secret)), false);
  }
});

async function subscriptionRecoveryFixture() {
  const dir = await mkdtemp(join(tmpdir(), 'share-donor-recovery-'));
  const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: 'donor_recovery_admin_abcdefghijklmnopqrstuvwxyz', port: 0 });
  const clients = new ClientStore(hub.store);
  const owner = hub.store.createMember('Original owner'), other = hub.store.createMember('Another member');
  const donors: DonorController[] = [];
  function pair(member = owner) {
    const verifier = randomBytes(48).toString('base64url');
    const pairing = clients.createPairing({ deviceName: 'Recovery fixture', platform: 'test', clientVersion: 'test', requestedScopes: ['consumer', 'donor'], codeChallenge: createHash('sha256').update(verifier).digest('base64url') }, hub.url);
    clients.approvePairing(pairing.userCode, member);
    const auth = clients.redeemPairing(pairing.deviceCode, verifier);
    return new HubClient({ baseUrl: hub.url, credentials: { accessToken: auth.accessToken, refreshToken: auth.refreshToken, expiresAt: Date.now() + auth.expiresIn * 1000, refreshExpiresAt: auth.refreshExpiresAt, deviceId: auth.device.id, memberId: auth.member.id } });
  }
  function donor(stateName: string, client: DonorHub) {
    const value = new DonorController({ stateDir: join(dir, stateName), hub: client,
      subscriptionAccount: { inspect: async () => ({ authenticated: true, accountBinding: 'codex:recovery-fixture', planType: 'test', models: ['gpt-synthetic'], quota: await new MockAdapter().readQuota() }) },
      adapterFactory: () => { throw new Error('Saving rules must not start a model adapter'); } });
    donors.push(value); return value;
  }
  const input = { name: 'Recovery subscription', kind: 'subscription' as const, policy: policySchema.parse({ models: ['gpt-synthetic'], allowedMemberIds: [owner.id] }) };
  return { dir, hub, clients, owner, other, pair, donor, input,
    async close() { for (const value of donors) await value.close(); await hub.close(); await rm(dir, { recursive: true, force: true }); } };
}

test('subscription source recovers for the same owner on a new device and still updates and acknowledges policy', async t => {
  const f = await subscriptionRecoveryFixture(); t.after(() => f.close());
  const original = await f.donor('original', f.pair()).configure(f.input);
  const client = f.pair(), requests: string[] = [];
  const proxy: DonorHub = { baseUrl: client.baseUrl, request<T>(method: string, path: string, body?: unknown) { requests.push(`${method} ${path}`); return client.request<T>(method, path, body); } };
  const replacement = f.donor('replacement', proxy);
  const recovered = await replacement.configure({ ...f.input, policy: { ...f.input.policy, reservePercent: 40 } });
  assert.equal(recovered.config?.sourceId, original.config?.sourceId);
  assert.equal(f.hub.store.listSources().length, 1);
  assert.equal(recovered.source?.ownerId, f.owner.id);
  assert.equal(recovered.source?.policy.reservePercent, 40);
  assert.equal(recovered.policySync, 'synced');
  assert.equal(recovered.hubPolicyRevision, 2); assert.equal(recovered.source?.appliedPolicyRevision, 2);
  assert.equal(f.clients.policyMeta(recovered.config!.sourceId!)?.acknowledgedBy, client.getCredentials()!.deviceId);
  assert.deepEqual(requests, ['POST /client/v2/sources', `PATCH /client/v2/sources/${original.config!.sourceId}/policy`, `POST /client/v2/sources/${original.config!.sourceId}/policy-acks`]);
  const saved = JSON.parse(await readFile(join(f.dir, 'replacement', 'donor-config.json'), 'utf8'));
  assert.equal(saved.config.sourceId, original.config?.sourceId);
  assert.equal(recovered.desiredSharing, false); assert.equal(recovered.relay, null);
});

test('a lost create response does not replay a write and a later explicit save recovers the committed source', async t => {
  const f = await subscriptionRecoveryFixture(); t.after(() => f.close());
  const client = f.pair(), requests: string[] = [];
  const lostResponse = new ShareError('SHARE_HUB_CONNECTION_FAILED', 'Synthetic committed response loss', 503);
  let loseResponse = true;
  const proxy: DonorHub = { baseUrl: client.baseUrl, async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    requests.push(`${method} ${path}`);
    const result = await client.request<T>(method, path, body);
    if (method === 'POST' && path === '/client/v2/sources' && loseResponse) { loseResponse = false; throw lostResponse; }
    return result;
  } };
  const donor = f.donor('lost-response', proxy);
  await assert.rejects(donor.configure(f.input), error => error === lostResponse);
  assert.deepEqual(requests, ['POST /client/v2/sources']);
  assert.equal(donor.snapshot().config?.sourceId, null);
  const committed = f.hub.store.listSources(); assert.equal(committed.length, 1);
  const recovered = await donor.configure(f.input);
  assert.equal(recovered.config?.sourceId, committed[0]!.id);
  assert.equal(f.hub.store.listSources().length, 1);
  assert.equal(recovered.policySync, 'synced'); assert.equal(recovered.source?.appliedPolicyRevision, 1);
  assert.equal(requests.filter(value => value === 'POST /client/v2/sources').length, 2);
});

for (const visible of [false, true]) test(`another member creates an independent subscription source without taking over the original when visibility is ${visible}`, async t => {
  const f = await subscriptionRecoveryFixture(); t.after(() => f.close());
  const original = await f.donor('original', f.pair()).configure({ ...f.input, policy: { ...f.input.policy, allowedMemberIds: visible ? [f.owner.id, f.other.id] : [f.owner.id] } });
  const sourceId = original.config!.sourceId!, before = f.hub.store.getSource(sourceId), priorAck = f.clients.policyMeta(sourceId);
  const client = f.pair(f.other), listed = await client.request<{ sources: ClientSource[] }>('GET', '/client/v2/sources');
  assert.equal(listed.sources.some(source => source.id === sourceId), visible);
  const replacement = f.donor('other-member', client);
  const configured = await replacement.configure({ ...f.input, policy: { ...f.input.policy, allowedMemberIds: [f.other.id], reservePercent: 80 } });
  assert.notEqual(configured.config?.sourceId, sourceId);
  assert.equal(configured.source?.ownerId, f.other.id);
  assert.equal(configured.policySync, 'synced');
  assert.deepEqual(f.hub.store.getSource(sourceId), before);
  assert.deepEqual(f.clients.policyMeta(sourceId), priorAck);
  assert.equal(f.hub.store.listSources().length, 2);
});

for (const failurePoint of ['list', 'owner-read'] as const) test(`legacy Hub recovery preserves ${failurePoint} connection failures without claiming another owner`, async t => {
  const f = await subscriptionRecoveryFixture(); t.after(() => f.close());
  const original = await f.donor('original', f.pair()).configure(f.input);
  const client = f.pair(), requests: string[] = [];
  const failure = new ShareError('SHARE_HUB_CONNECTION_FAILED', 'Synthetic recovery read failure', 503);
  const proxy: DonorHub = { baseUrl: client.baseUrl, request<T>(method: string, path: string, body?: unknown): Promise<T> {
    requests.push(`${method} ${path}`);
    if (method === 'POST' && path === '/client/v2/sources') return Promise.reject(new ShareError('SHARE_SOURCE_EXISTS', 'Legacy Hub duplicate response', 409));
    if (method === 'GET' && path === (failurePoint === 'list' ? '/client/v2/sources' : `/client/v2/sources/${original.config!.sourceId}`)) return Promise.reject(failure);
    return client.request<T>(method, path, body);
  } };
  const replacement = f.donor('replacement', proxy);
  await assert.rejects(replacement.configure(f.input), error => error === failure);
  assert.equal(replacement.snapshot().config?.sourceId, null);
  assert.equal(requests.filter(value => value === 'POST /client/v2/sources').length, 1);
  assert.equal(f.hub.store.listSources().length, 1);
});

test('legacy Hub recovery cannot bypass a forbidden owner-only source read', async t => {
  const f = await subscriptionRecoveryFixture(); t.after(() => f.close());
  const original = await f.donor('original', f.pair()).configure(f.input);
  const client = f.pair();
  const proxy: DonorHub = { baseUrl: client.baseUrl, request<T>(method: string, path: string, body?: unknown): Promise<T> {
    if (method === 'POST' && path === '/client/v2/sources') return Promise.reject(new ShareError('SHARE_SOURCE_EXISTS', 'Legacy Hub duplicate response', 409));
    if (method === 'GET' && path === `/client/v2/sources/${original.config!.sourceId}`) return Promise.reject(new ShareError('SHARE_FORBIDDEN', 'Synthetic owner read denial', 403));
    return client.request<T>(method, path, body);
  } };
  const replacement = f.donor('replacement', proxy);
  await assert.rejects(replacement.configure(f.input), error => error instanceof ShareError && error.code === 'SHARE_SOURCE_OWNED_ELSEWHERE');
  assert.equal(replacement.snapshot().config?.sourceId, null);
  assert.equal(f.hub.store.listSources().length, 1);
});

test('subscription configuration requires an authenticated local account and never trusts a supplied account label', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'share-donor-subscription-')); t.after(() => rm(dir, { recursive: true, force: true }));
  let factoryCalls = 0;
  const donor = new DonorController({ stateDir: dir, adapterFactory: () => { factoryCalls++; return new MockAdapter(); } }); t.after(() => donor.close());
  await assert.rejects(donor.configure({ kind: 'subscription', hubUrl: 'http://127.0.0.1:8787', accountBinding: 'renderer-invented', policy: { models: ['gpt-synthetic'], allowedMemberIds: ['friend'] } }), /登录/);
  assert.equal(donor.snapshot().configured, false); assert.equal(factoryCalls, 0);
});

test('subscription binding, model removal, reserve limits and unknown quota fail closed before relay startup', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'share-donor-subscription-')); t.after(() => rm(dir, { recursive: true, force: true }));
  let binding = 'codex:account-a', models = ['gpt-synthetic'];
  let quota: import('../packages/protocol/index.js').QuotaSnapshot = { ...await new MockAdapter().readQuota(), origin: 'codex' };
  let sourceCount = 0, factoryCalls = 0;
  const sources: Source[] = [];
  const hub: DonorHub = { baseUrl: 'http://127.0.0.1:8787', async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    if (method === 'POST' && path === '/client/v2/sources') { const input = body as Source; const source: Source = { ...input, id: `source_${++sourceCount}`, ownerId: 'owner', paused: true, frozen: false, fence: 0, quota: null, capabilities: null, online: false, lastSeen: null, createdAt: Date.now() }; sources.push(source); return { source, revision: 1 } as T; }
    if (method === 'GET' && path === '/client/v2/sources') return { sources } as T;
    if (path.endsWith('/policy-acks')) return { source: sources.at(-1), revision: 1 } as T;
    throw new Error('No relay lease or inference should be attempted in this failure fixture');
  } };
  const account = { inspect: async () => ({ authenticated: true, accountBinding: binding, planType: 'test', models, quota }) };
  const donor = new DonorController({ stateDir: dir, hub, subscriptionAccount: account, adapterFactory: config => { factoryCalls++; return { inspect: async () => ({ kind: 'subscription', verified: true, accountBinding: config.accountBinding, models: config.policy.models, responses: true, compact: true }), readQuota: async () => quota, open: async () => { throw new Error('Must never infer'); } }; } }); t.after(() => donor.close());
  const input = { kind: 'subscription' as const, accountBinding: 'renderer-invented', policy: { models: ['gpt-synthetic'], allowedMemberIds: ['friend'] } };
  const first = await donor.configure(input);
  assert.equal(first.config?.accountBinding, 'codex:account-a'); assert.equal(first.desiredSharing, false);
  models = []; await assert.rejects(donor.start(), /模型/); assert.equal(factoryCalls, 0);
  models = ['gpt-synthetic']; binding = 'codex:account-b'; await assert.rejects(donor.start(), /账号已变化/); assert.equal(factoryCalls, 0);
  await assert.rejects(donor.configure({ ...input, sourceId: first.config!.sourceId! }), /新来源/);
  const rebound = await donor.configure(input); assert.notEqual(rebound.config?.sourceId, first.config?.sourceId); assert.equal(sourceCount, 2);
  quota = { ...quota, status: 'unknown', windows: [] }; await assert.rejects(donor.start(), /额度数据未知/);
  quota = { ...await new MockAdapter({ usedPercent: 90 }).readQuota(), origin: 'codex' }; await assert.rejects(donor.start(), /保留线/);
  assert.equal(donor.snapshot().desiredSharing, false); assert.equal(donor.snapshot().relay, null);
  const resumed = new DonorController({ stateDir: dir, hub, subscriptionAccount: account });
  assert.equal(resumed.snapshot().status, 'paused'); assert.equal(resumed.snapshot().desiredSharing, false); await resumed.close();
});

test('local policy tightening persists before Hub ACK; expansion requires confirmation', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'share-donor-policy-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const policy = policySchema.parse({ models: ['mock-codex'], allowedMemberIds: ['friend_a', 'friend_b'] });
  let current = policy; let revision = 1; let rejectAck = false; const requests: string[] = [];
  const source = (): Source => ({ id: 'source_policy', name: 'Mock policy source', ownerId: 'owner', kind: 'mock', accountBinding: 'mock:policy', policy: current, paused: true, frozen: false, fence: 0, quota: null, capabilities: null, online: false, lastSeen: null, createdAt: Date.now() });
  const hub: DonorHub = { baseUrl: 'http://127.0.0.1:8787', async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    requests.push(`${method} ${path}`);
    if (path === '/client/v2/sources' && method === 'POST') return { source: source(), revision, appliedRevision: 0 } as T;
    if (path.endsWith('/policy')) { current = (body as { policy: SharePolicy }).policy; revision++; return { source: source(), revision, appliedRevision: 1 } as T; }
    if (path.endsWith('/policy-acks')) { if (rejectAck) throw new ShareError('SHARE_TEST_ACK_LOST', 'Synthetic ACK loss', 503); return { source: source(), revision, appliedRevision: revision } as T; }
    throw new Error('Unexpected fixture request');
  } };
  const donor = new DonorController({ stateDir: dir, hub }); t.after(() => donor.close());
  await donor.configure({ name: 'Mock policy source', kind: 'mock', accountBinding: 'mock:policy', policy });
  const tighter = { ...policy, allowedMemberIds: ['friend_a'] }; rejectAck = true;
  await assert.rejects(donor.updatePolicy(tighter), /Synthetic ACK loss/);
  assert.equal(donor.snapshot().policySync, 'error'); assert.deepEqual(donor.snapshot().config?.policy.allowedMemberIds, ['friend_a']);
  const persisted = JSON.parse(await readFile(join(dir, 'donor-config.json'), 'utf8')); assert.deepEqual(persisted.config.policy.allowedMemberIds, ['friend_a']);
  await assert.rejects(donor.updatePolicy(policy), /本机明确确认/);
  rejectAck = false; await donor.updatePolicy(policy, { confirmExpansion: true });
  assert.equal(donor.snapshot().policySync, 'synced');
  assert(requests.some(path => path.endsWith('/policy-acks')));
  await assert.rejects(donor.configure({ ...persisted.config, token: 'must-not-save' } as never), /Unrecognized key/);
});
