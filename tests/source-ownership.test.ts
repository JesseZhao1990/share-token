import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../packages/storage/index.js';
import { ClientStore, type DeviceAuth } from '../packages/storage/client.js';
import { policySchema, type Member, type Source } from '../packages/protocol/index.js';

const binding = 'codex:synthetic-owner-scope';
function source(store: Store, owner: Member, accountBinding = binding, kind: 'subscription' | 'mock' = 'subscription') {
  return store.createSource({ name: owner.name, ownerId: owner.id, kind, accountBinding, policy: policySchema.parse({ allowedMemberIds: [owner.id], models: ['test-model'] }) });
}
function pair(clients: ClientStore, member: Member): DeviceAuth {
  const verifier = randomBytes(32).toString('base64url');
  const pairing = clients.createPairing({ deviceName: member.name, platform: 'test', clientVersion: 'test', requestedScopes: ['consumer', 'donor'], codeChallenge: createHash('sha256').update(verifier).digest('base64url') }, 'http://127.0.0.1');
  clients.approvePairing(pairing.userCode, member); return clients.access(clients.redeemPairing(pairing.deviceCode, verifier).accessToken);
}
function managed(clients: ClientStore, auth: DeviceAuth, value: Source) { clients.registerSource(value); clients.ackPolicy(value.id, auth.device.id, 1); return value; }

test('owner-scoped source migration preserves old owners, policies, grants, history and resource bindings across restart', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'source-ownership-')), path = join(dir, 'hub.sqlite'); let store = new Store(path);
  try {
    const first = store.createMember('旧成员'), second = store.createMember('新成员');
    const old = source(store, first); store.db.prepare('UPDATE sources SET binding=? WHERE id=?').run(`${old.kind}:${old.accountBinding}`, old.id);
    const grant = store.createGrant({ memberId: first.id, sourceId: old.id, label: '旧授权', models: ['test-model'] });
    const request = store.createRequest({ memberId: first.id, sourceId: old.id, grantId: grant.id, model: 'test-model', operation: 'responses' });
    store.bindResources(old.id, grant.id, ['response-old']);
    store.db.exec('CREATE TABLE client_migrations(version INTEGER PRIMARY KEY,applied_at INTEGER NOT NULL); INSERT INTO client_migrations VALUES(1,1),(2,2)');
    new ClientStore(store);
    assert.equal(Number(store.db.prepare('SELECT MAX(version) AS v FROM client_migrations').get()!.v), 3);
    assert.deepEqual(JSON.parse(String(store.db.prepare('SELECT binding FROM sources WHERE id=?').get(old.id)!.binding)), [first.id, old.kind, old.accountBinding]);
    const next = source(store, second); assert.notEqual(next.id, old.id);
    assert.throws(() => source(store, first), { code: 'SHARE_SOURCE_EXISTS' });
    assert.deepEqual(store.getSource(old.id), old); assert.deepEqual(store.getGrant(grant.id), grant); assert.deepEqual(store.getRequest(request.id), request);
    assert.doesNotThrow(() => store.assertResourceOwnership(old.id, grant.id, 'response-old'));
    assert.throws(() => store.assertResourceOwnership(next.id, grant.id, 'response-old'), { code: 'SHARE_RESOURCE_FORBIDDEN' });
    store.close(); store = new Store(path); new ClientStore(store);
    assert.deepEqual(store.getSource(old.id), old); assert.deepEqual(store.getSource(next.id), next); assert.equal(store.listGrants().length, 1);
    store.db.prepare('INSERT INTO client_migrations VALUES(4,?)').run(Date.now());
    assert.throws(() => new ClientStore(store), { code: 'SHARE_SCHEMA_NEWER' });
  } finally { store.close(); await rm(dir, { recursive: true, force: true }); }
});

test('standalone Store detects same-owner legacy keys and permits another owner without claiming the original', () => {
  const store = new Store(':memory:'); try {
    const one = store.createMember('one'), two = store.createMember('two'); const original = source(store, one, 'binding:["quoted"]:part');
    store.db.prepare('UPDATE sources SET binding=? WHERE id=?').run(`${original.kind}:${original.accountBinding}`, original.id);
    assert.throws(() => source(store, one, original.accountBinding), { code: 'SHARE_SOURCE_EXISTS' });
    const next = source(store, two, original.accountBinding), otherKind = source(store, one, original.accountBinding, 'mock');
    assert.deepEqual(store.accountSiblingSources(original.id).map(item => item.id), [next.id]);
    assert.deepEqual(store.accountSiblingSources(otherKind.id), []);
    assert.equal(store.getSource(original.id)?.ownerId, one.id); assert.equal(store.getSource(next.id)?.ownerId, two.id);
  } finally { store.close(); }
});

test('source binding migration is atomic if old rows contain a conflicting owner/account identity', () => {
  const store = new Store(':memory:'); try {
    const owner = store.createMember('owner'), a = source(store, owner, 'account-a'), b = source(store, owner, 'account-b');
    store.db.prepare('UPDATE sources SET data=? WHERE id=?').run(JSON.stringify({ ...b, accountBinding: a.accountBinding }), b.id);
    const before = store.db.prepare('SELECT id,binding FROM sources ORDER BY id').all();
    assert.throws(() => new ClientStore(store));
    assert.deepEqual(store.db.prepare('SELECT id,binding FROM sources ORDER BY id').all(), before);
    assert.equal(Number(store.db.prepare('SELECT MAX(version) AS v FROM client_migrations').get()!.v), 2);
  } finally { store.close(); }
});

test('account-wide idle checks block sibling online, frozen and nonterminal work while preserving same-source recovery', () => {
  const store = new Store(':memory:'); try {
    const owner = store.createMember('old'), replacement = store.createMember('new'), a = source(store, owner), b = source(store, replacement);
    const grant = store.createGrant({ memberId: owner.id, sourceId: a.id, label: 'grant', models: ['test-model'] });
    store.updateSource(a.id, { online: true, paused: true }); assert.throws(() => store.assertAccountIdle(b.id), { code: 'SHARE_RELAY_BUSY' });
    store.updateSource(a.id, { online: false, frozen: true }); assert.throws(() => store.assertAccountIdle(b.id), { code: 'SHARE_RESULT_UNKNOWN' });
    assert.doesNotThrow(() => store.assertAccountIdle(a.id));
    store.updateSource(a.id, { frozen: false }); const request = store.createRequest({ memberId: owner.id, sourceId: a.id, grantId: grant.id, model: 'test-model', operation: 'responses' });
    for (const state of ['RESERVED', 'QUEUED', 'UPSTREAM_STARTED', 'STREAMING'] as const) { store.updateRequest(request.id, { state }); assert.throws(() => store.assertAccountIdle(b.id), { code: 'SHARE_RELAY_BUSY' }); }
    store.updateRequest(request.id, { state: 'COMPLETED', delivery: 'transport_finished' }); assert.doesNotThrow(() => store.assertAccountIdle(b.id));
    store.updateRequest(request.id, { state: 'UNKNOWN' }); store.updateGrant(grant.id, { frozen: true }); assert.throws(() => store.assertAccountIdle(b.id), { code: 'SHARE_RESULT_UNKNOWN' });
    store.updateGrant(grant.id, { frozen: false }); assert.doesNotThrow(() => store.assertAccountIdle(b.id), 'acknowledged legacy UNKNOWN history is not a permanent lock');
  } finally { store.close(); }
});

test('account-wide unknown checks honor v2 resolution and block unacknowledged terminal delivery', () => {
  const store = new Store(':memory:'); try {
    new ClientStore(store); const oldOwner = store.createMember('old'), newOwner = store.createMember('new'), a = source(store, oldOwner), b = source(store, newOwner);
    const grant = store.createGrant({ memberId: oldOwner.id, sourceId: a.id, label: 'grant', models: ['test-model'] });
    const request = store.createRequest({ memberId: oldOwner.id, sourceId: a.id, grantId: grant.id, model: 'test-model', operation: 'responses' });
    store.updateRequest(request.id, { state: 'UNKNOWN' });
    const meta = { id: request.id, deviceId: 'fixture-device', sessionId: 'fixture-session', leaseId: 'fixture-lease', operationId: 'fixture-operation', bodyHash: 'fixture', consumerDelivery: 'transport_finished', resolvedAt: null as number | null };
    const save = () => store.db.prepare('INSERT OR REPLACE INTO client_requests VALUES(?,?,?,?,?,?)').run(request.id, meta.deviceId, meta.sessionId, meta.leaseId, meta.operationId, JSON.stringify(meta)); save();
    assert.throws(() => store.assertAccountIdle(b.id), { code: 'SHARE_RESULT_UNKNOWN' });
    meta.resolvedAt = Date.now(); save(); assert.doesNotThrow(() => store.assertAccountIdle(b.id));
    store.updateRequest(request.id, { state: 'COMPLETED' }); meta.resolvedAt = null; meta.consumerDelivery = 'lost'; save();
    assert.throws(() => store.assertAccountIdle(b.id), { code: 'SHARE_RESULT_UNKNOWN' });
    meta.consumerDelivery = 'transport_finished'; save(); assert.doesNotThrow(() => store.assertAccountIdle(b.id));
    store.updateSource(a.id, { frozen: true }); assert.throws(() => store.assertAccountIdle(b.id), { code: 'SHARE_RESULT_UNKNOWN' });
  } finally { store.close(); }
});

test('same-account managed relay leases are mutually exclusive across owners and release without moving grants', () => {
  const store = new Store(':memory:'); try {
    const clients = new ClientStore(store), ownerA = store.createMember('a'), ownerB = store.createMember('b');
    const authA = pair(clients, ownerA), authB = pair(clients, ownerB);
    const a = managed(clients, authA, source(store, ownerA)), b = managed(clients, authB, source(store, ownerB));
    const leaseA = clients.createRelay(authA, a.id);
    assert.throws(() => clients.createRelay(authB, b.id), { code: 'SHARE_RELAY_BUSY' });
    assert.throws(() => clients.assertAccountRelayAvailable(a.id), { code: 'SHARE_RELAY_BUSY' }, 'legacy websocket cannot bypass a reserved lease on its own source');
    assert.doesNotThrow(() => clients.assertAccountRelayAvailable(a.id, leaseA.lease.id));
    store.updateSource(a.id, { online: true, frozen: true });
    assert.equal(clients.createRelay(authA, a.id).lease.id, leaseA.lease.id); assert.equal(clients.renewRelay(authA, leaseA.lease.id).lease.id, leaseA.lease.id);
    clients.closeRelay(authA, leaseA.lease.id); store.updateSource(a.id, { online: false, frozen: false });
    const leaseB = clients.createRelay(authB, b.id); assert.equal(leaseB.lease.sourceId, b.id);
    assert.throws(() => clients.createRelay(authA, a.id), { code: 'SHARE_RELAY_BUSY' });
    store.db.prepare("UPDATE client_objects SET data=json_set(data,'$.expiresAt',?) WHERE kind='relay' AND id=?").run(Date.now() - 1, leaseB.lease.id);
    assert.equal(clients.createRelay(authA, a.id).lease.sourceId, a.id); assert.equal(store.listGrants().length, 0);
  } finally { store.close(); }
});
