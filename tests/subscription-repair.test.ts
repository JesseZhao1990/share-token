import test, { after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { WebSocket } from 'ws';
import { createHub } from '../apps/hub/index.js';
import { DonorController, type DonorHub } from '../packages/client-core/donor.js';
import { HubClient } from '../packages/hub-client/index.js';
import { ClientStore } from '../packages/storage/client.js';
import { MockAdapter } from '../packages/upstream/index.js';
import { ShareError, policySchema, type Grant, type Member } from '../packages/protocol/index.js';
import type { ClientAuthResponse, ClientSession, ClientSource, ClientSourceResponse, RelayLeaseResponse } from '../packages/protocol/client.js';

// Opt in only for synthetic regression fixtures; these tests never call a real upstream.
const previousExperimentalSubscription = process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION;
process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = '1';
after(() => { if (previousExperimentalSubscription === undefined) delete process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION; else process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = previousExperimentalSubscription; });

const binding = 'codex:subscription-repair-synthetic-account';
const model = 'gpt-subscription-repair-fixture';
const policy = (members: Member[], reservePercent = 20) => policySchema.parse({ models: [model], allowedMemberIds: members.map(member => member.id), reservePercent });

async function eventually(predicate: () => boolean, message: string) {
  for (let attempt = 0; attempt < 200; attempt++) { if (predicate()) return; await delay(10); }
  assert.fail(message);
}

async function fixture(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), 'subscription-repair-'));
  const hub = await createHub({ dbPath: join(directory, 'hub.sqlite'), adminToken: 'subscription_repair_local_test_admin_abcdefghijklmnopqrstuvwxyz', port: 0 });
  const clients = new ClientStore(hub.store), donors: DonorController[] = [];
  let inferenceCalls = 0, adapterCreations = 0;
  t.after(async () => {
    try { for (const donor of donors) await donor.close(); }
    finally { await hub.close(); await rm(directory, { recursive: true, force: true }); }
    assert.equal(inferenceCalls, 0, 'Configuration and relay lifecycle must never execute an inference.');
  });
  function connect(auth: ClientAuthResponse) {
    const client = new HubClient({ baseUrl: hub.url, credentials: { accessToken: auth.accessToken, refreshToken: auth.refreshToken,
      expiresAt: Date.now() + auth.expiresIn * 1000, refreshExpiresAt: auth.refreshExpiresAt, deviceId: auth.device.id, memberId: auth.member.id } });
    return { client, member: auth.member, device: auth.device };
  }
  function pair(memberOrCode: Member | string) {
    const verifier = randomBytes(48).toString('base64url');
    const pairing = clients.createPairing({ deviceName: 'Synthetic subscription repair device', platform: 'test', clientVersion: 'test',
      requestedScopes: ['consumer', 'donor'], codeChallenge: createHash('sha256').update(verifier).digest('base64url') }, hub.url);
    if (typeof memberOrCode === 'string') clients.matchPairing(pairing.deviceCode, verifier, memberOrCode);
    else clients.approvePairing(pairing.userCode, memberOrCode);
    return connect(clients.redeemPairing(pairing.deviceCode, verifier));
  }
  const quota = async () => ({ ...await new MockAdapter().readQuota(), origin: 'codex' as const });
  function donor(stateName: string, client: DonorHub) {
    const value = new DonorController({ stateDir: join(directory, stateName), hub: client, heartbeatMs: 30,
      subscriptionAccount: { inspect: async () => ({ authenticated: true, accountBinding: binding, models: [model], planType: 'test', quota: await quota() }) },
      adapterFactory: config => {
        adapterCreations++;
        return { inspect: async () => ({ kind: 'subscription', verified: true, accountBinding: config.accountBinding, models: config.policy.models, responses: true, compact: true }),
          readQuota: quota, open: async () => { inferenceCalls++; throw new Error('This regression must not call any model.'); } };
      } });
    donors.push(value); return value;
  }
  return { directory, hub, clients, pair, donor, adapterCreations: () => adapterCreations };
}

test('a newly matched member saves and shares its own subscription source while legacy ownership, grants and history remain intact', async t => {
  const f = await fixture(t);
  const legacyOwner = f.hub.store.createMember('Legacy subscription owner');
  const legacySource = f.hub.store.createSource({ name: 'Original subscription', kind: 'subscription', ownerId: legacyOwner.id, accountBinding: binding, policy: policy([legacyOwner]) });
  const legacyGrant = f.hub.store.createGrant({ sourceId: legacySource.id, memberId: legacyOwner.id, label: 'Original private grant', models: [model] });
  const request = f.hub.store.createRequest({ sourceId: legacySource.id, grantId: legacyGrant.id, memberId: legacyOwner.id, model, operation: 'responses' });
  const legacyHistory = f.hub.store.updateRequest(request.id, { state: 'COMPLETED', finishedAt: Date.now(), delivery: 'transport_finished', usage: { ...request.usage, inputTokens: 12, outputTokens: 8 } });
  const responseId = 'resp_subscription_repair_legacy';
  f.hub.store.bindResources(legacySource.id, legacyGrant.id, [responseId]);
  const legacyCredential = f.hub.store.issueCredential('grant', legacyOwner.id, { sourceId: legacySource.id, grantId: legacyGrant.id });

  const current = f.pair('47192836'), donor = f.donor('new-member', current.client);
  const input = { name: 'My independently owned subscription', kind: 'subscription' as const, policy: policy([current.member]) };
  const configured = await donor.configure(input);
  assert.equal(configured.source?.ownerId, current.member.id);
  assert.equal(configured.config?.accountBinding, binding);
  assert.notEqual(configured.config?.sourceId, legacySource.id);
  assert.equal(configured.policySync, 'synced');
  assert.equal(configured.hubPolicyRevision, 1);
  assert.equal(configured.source?.appliedPolicyRevision, 1);
  assert.equal(f.adapterCreations(), 0, 'Saving rules must not initialize the upstream adapter.');

  const sourceId = configured.config!.sourceId!;
  const updated = await donor.configure({ ...input, policy: policy([current.member], 45) });
  assert.equal(updated.config?.sourceId, sourceId);
  assert.equal(updated.source?.policy.reservePercent, 45);
  assert.equal(updated.policySync, 'synced');
  assert.equal(updated.source?.appliedPolicyRevision, 2);
  assert.equal(f.clients.policyMeta(sourceId)?.acknowledgedBy, current.device.id);
  assert.equal((await donor.start()).status, 'sharing');
  assert.equal(f.hub.store.getSource(sourceId)?.online, true);
  assert.equal((await donor.stopNow()).desiredSharing, false);
  await eventually(() => f.hub.store.getSource(sourceId)?.online === false, 'Stopping must release the new source connection.');

  assert.deepEqual((await current.client.request<{ sources: ClientSource[] }>('GET', '/client/v2/sources')).sources.map(source => source.id), [sourceId]);
  assert.deepEqual((await current.client.request<{ grants: Grant[] }>('GET', '/client/v2/grants')).grants, []);
  assert.deepEqual((await current.client.request<{ sessions: ClientSession[] }>('GET', '/client/v2/sessions')).sessions, []);
  assert.deepEqual((await current.client.request<{ requests: unknown[] }>('GET', '/client/v2/requests')).requests, []);
  assert.deepEqual(f.hub.store.getSource(legacySource.id), legacySource);
  assert.deepEqual(f.hub.store.getGrant(legacyGrant.id), legacyGrant);
  assert.deepEqual(f.hub.store.getRequest(legacyHistory.id), legacyHistory);
  assert.deepEqual(f.hub.store.authenticate(legacyCredential.token, 'grant'), legacyCredential.credential);
  assert.doesNotThrow(() => f.hub.store.assertResourceOwnership(legacySource.id, legacyGrant.id, responseId));
  assert.throws(() => f.hub.store.assertResourceOwnership(sourceId, legacyGrant.id, responseId), { code: 'SHARE_RESOURCE_FORBIDDEN' });
  assert.equal(f.hub.store.listSources().length, 2);
});

test('subscription repair recovers only the current member source even when a visible foreign source with the same binding is listed first', async t => {
  const f = await fixture(t);
  const first = f.pair(f.hub.store.createMember('First visible owner'));
  const second = f.pair(f.hub.store.createMember('Owner restoring local configuration'));
  const firstDonor = f.donor('first-owner', first.client), secondDonor = f.donor('second-owner', second.client);
  const firstConfigured = await firstDonor.configure({ name: 'Visible but not owned', kind: 'subscription', policy: policy([first.member, second.member]) });
  const firstId = firstConfigured.config!.sourceId!;
  const firstGrant = (await first.client.request<{ grant: Grant }>('POST', '/client/v2/grants', { sourceId: firstId, label: 'Private old grant', models: [model] })).grant;
  const firstSession = (await first.client.request<{ session: ClientSession }>('POST', '/client/v2/sessions', { grantId: firstGrant.id, modelScope: [model] })).session;
  const firstBefore = f.hub.store.getSource(firstId), firstAckBefore = f.clients.policyMeta(firstId);
  const secondInput = { name: 'Own subscription source', kind: 'subscription' as const, policy: policy([second.member]) };
  const ownConfigured = await secondDonor.configure(secondInput), ownId = ownConfigured.config!.sourceId!;
  assert.notEqual(ownId, firstId);
  await secondDonor.close();

  const replacementDevice = f.pair(second.member), requests: string[] = [];
  const visible = await replacementDevice.client.request<{ sources: ClientSource[] }>('GET', '/client/v2/sources');
  assert.equal(visible.sources[0]?.id, firstId, 'The first visible account match is not the source owned by this member.');
  assert.equal(visible.sources.some(source => source.id === ownId), true);
  const priorOwnSource = f.hub.store.getSource(ownId), priorOwnAck = f.clients.policyMeta(ownId);
  const idempotent = await replacementDevice.client.request<ClientSourceResponse>('POST', '/client/v2/sources', {
    name: 'Must not overwrite the saved policy', kind: 'subscription', accountBinding: binding, policy: policy([second.member], 75),
  });
  assert.equal(idempotent.source.id, ownId);
  assert.equal(idempotent.source.policy.reservePercent, 20, 'An idempotent create returns existing policy; policy changes require PATCH and ACK.');
  assert.deepEqual(f.hub.store.getSource(ownId), priorOwnSource);
  assert.deepEqual(f.clients.policyMeta(ownId), priorOwnAck);
  const observed: DonorHub = { baseUrl: replacementDevice.client.baseUrl, async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    requests.push(`${method} ${path}`);
    return replacementDevice.client.request<T>(method, path, body);
  } };
  const restored = f.donor('restored-without-local-config', observed);
  const recovered = await restored.configure({ ...secondInput, policy: policy([second.member], 55) });
  assert.equal(recovered.config?.sourceId, ownId);
  assert.equal(recovered.source?.ownerId, second.member.id);
  assert.equal(recovered.source?.policy.reservePercent, 55);
  assert.equal(recovered.policySync, 'synced');
  assert.equal(recovered.source?.appliedPolicyRevision, 2);
  assert.equal(f.clients.policyMeta(ownId)?.acknowledgedBy, replacementDevice.device.id);
  assert.equal(requests[0], 'POST /client/v2/sources');
  assert.ok(requests.every(entry => !entry.includes(`/sources/${firstId}`)), 'Recovery must not read or mutate the foreign owner endpoint.');
  const saved = JSON.parse(await readFile(join(f.directory, 'restored-without-local-config', 'donor-config.json'), 'utf8'));
  assert.equal(saved.config.sourceId, ownId);
  assert.equal((await restored.start()).status, 'sharing');
  await restored.stopNow();

  for (const [method, path, body] of [
    ['GET', `/client/v2/sources/${firstId}`, undefined],
    ['PATCH', `/client/v2/sources/${firstId}/policy`, { policy: policy([second.member], 90) }],
    ['POST', `/client/v2/sources/${firstId}/relay-leases`, {}],
    ['DELETE', `/client/v2/grants/${firstGrant.id}`, undefined],
    ['GET', `/client/v2/sessions/${firstSession.id}`, undefined],
  ] as const) await assert.rejects(replacementDevice.client.request(method, path, body), { code: 'SHARE_NOT_FOUND', status: 404 });
  assert.deepEqual((await replacementDevice.client.request<{ grants: Grant[] }>('GET', '/client/v2/grants')).grants, []);
  assert.deepEqual((await replacementDevice.client.request<{ sessions: ClientSession[] }>('GET', '/client/v2/sessions')).sessions, []);
  assert.deepEqual(f.hub.store.getSource(firstId), firstBefore);
  assert.deepEqual(f.clients.policyMeta(firstId), firstAckBefore);
  assert.deepEqual(f.hub.store.getGrant(firstGrant.id), firstGrant);
  assert.deepEqual(f.clients.getSession(firstSession.id), firstSession);
  assert.equal(f.hub.store.listSources().length, 2, 'Recovery must not create another source for the same member.');
});

test('independent owners sharing one subscription retain a single active relay and can switch after the previous owner stops', async t => {
  const f = await fixture(t), first = f.pair('27384619'), second = f.pair('96413827');
  const firstDonor = f.donor('active-owner', first.client), secondDonor = f.donor('next-owner', second.client);
  const one = await firstDonor.configure({ name: 'First subscription owner', kind: 'subscription', policy: policy([first.member]) });
  const two = await secondDonor.configure({ name: 'Second subscription owner', kind: 'subscription', policy: policy([second.member]) });
  const oneId = one.config!.sourceId!, twoId = two.config!.sourceId!;
  assert.notEqual(oneId, twoId);
  assert.equal((await firstDonor.start()).status, 'sharing');
  await assert.rejects(secondDonor.start(), error => error instanceof ShareError && error.code === 'SHARE_RELAY_BUSY' && error.status === 409);
  assert.equal(firstDonor.snapshot().status, 'sharing');
  assert.equal(secondDonor.snapshot().desiredSharing, false);
  assert.equal(f.hub.store.getSource(oneId)?.online, true);
  assert.equal(f.hub.store.getSource(twoId)?.online, false);

  await firstDonor.stopNow();
  await eventually(() => f.hub.store.getSource(oneId)?.online === false, 'The previous owner must release its relay before handoff.');
  assert.equal((await secondDonor.start()).status, 'sharing');
  assert.equal(f.hub.store.getSource(oneId)?.online, false);
  assert.equal(f.hub.store.getSource(twoId)?.online, true);
  await secondDonor.stopNow();
  await eventually(() => f.hub.store.getSource(twoId)?.online === false, 'The second owner must release its relay before the original owner resumes.');
  assert.equal((await firstDonor.start()).status, 'sharing');
  await firstDonor.stopNow();
  assert.equal(f.hub.store.getSource(oneId)?.ownerId, first.member.id);
  assert.equal(f.hub.store.getSource(twoId)?.ownerId, second.member.id);
  assert.equal(f.hub.store.listRequests().length, 0);
});

test('a same-owner legacy source still requires an explicit protocol upgrade and is never silently converted during subscription repair', async t => {
  const f = await fixture(t), owner = f.pair(f.hub.store.createMember('Legacy owner on a new device'));
  const legacy = f.hub.store.createSource({ name: 'Unmanaged legacy source', ownerId: owner.member.id, kind: 'subscription', accountBinding: binding, policy: policy([owner.member]) });
  const legacyGrant = f.hub.store.createGrant({ memberId: owner.member.id, sourceId: legacy.id, label: 'Preserve legacy grant', models: [model] });
  const donor = f.donor('legacy-same-owner', owner.client);
  await assert.rejects(donor.configure({ name: 'Must not convert the old source', kind: 'subscription', policy: policy([owner.member], 60) }), { code: 'SHARE_UPGRADE_REQUIRED', status: 409 });
  assert.equal(donor.snapshot().desiredSharing, false);
  assert.equal(donor.snapshot().config?.sourceId, null);
  assert.equal(f.adapterCreations(), 0);
  assert.equal(f.clients.isManagedSource(legacy.id), false);
  assert.deepEqual(f.hub.store.getSource(legacy.id), legacy);
  assert.deepEqual(f.hub.store.getGrant(legacyGrant.id), legacyGrant);
  assert.equal(f.hub.store.listSources().length, 1);
});

test('subscription single-relay ownership includes an open legacy socket before hello and a managed lease before socket connection', async t => {
  const f = await fixture(t), legacyOwner = f.hub.store.createMember('Legacy relay owner'), current = f.pair('58193647');
  const legacySource = f.hub.store.createSource({ name: 'Legacy relay before hello', kind: 'subscription', ownerId: legacyOwner.id, accountBinding: binding, policy: policy([legacyOwner]) });
  const token = f.hub.store.issueCredential('relay', legacyOwner.id, { sourceId: legacySource.id }).token;
  const donor = f.donor('managed-relay-owner', current.client);
  const configured = await donor.configure({ name: 'Managed relay before connection', kind: 'subscription', policy: policy([current.member]) });
  const sourceId = configured.config!.sourceId!;
  const sockets: WebSocket[] = [];
  t.after(() => { for (const socket of sockets) if (socket.readyState !== WebSocket.CLOSED) socket.terminate(); });
  function socket() {
    const value = new WebSocket(`${f.hub.url.replace(/^http/, 'ws')}/relay/v1`, { headers: { authorization: `Bearer ${token}` }, handshakeTimeout: 1500 });
    value.on('error', () => {}); sockets.push(value); return value;
  }
  const legacy = socket();
  await new Promise<void>((resolve, reject) => { legacy.once('open', resolve); legacy.once('error', reject); });
  assert.equal(f.hub.store.getSource(legacySource.id)?.online, false, 'A socket without hello has not published source presence.');
  await assert.rejects(current.client.request('POST', `/client/v2/sources/${sourceId}/relay-leases`, {}), { code: 'SHARE_RELAY_BUSY', status: 409 });
  await new Promise<void>(resolve => { legacy.once('close', () => resolve()); legacy.close(); });
  const managedLease = await current.client.request<RelayLeaseResponse>('POST', `/client/v2/sources/${sourceId}/relay-leases`, {});
  assert.equal(managedLease.lease.state, 'active');
  assert.equal(f.hub.store.getSource(sourceId)?.online, false, 'The managed lease is reserved before opening its socket.');
  const rejectedStatus = await new Promise<number | undefined>((resolve, reject) => {
    const contender = socket();
    contender.once('open', () => { contender.close(); reject(new Error('Legacy socket must not connect while the sibling managed lease is reserved.')); });
    contender.once('unexpected-response', (_request, response) => { response.resume(); contender.terminate(); resolve(response.statusCode); });
    contender.once('error', reject);
  });
  assert.equal(rejectedStatus, 409);
  await current.client.request('DELETE', `/client/v2/relay-leases/${managedLease.lease.id}`);
  assert.equal(f.hub.store.listRequests().length, 0);
});
