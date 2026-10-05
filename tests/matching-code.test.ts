import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHub } from '../apps/hub/index.js';
import { policySchema, type Grant, type Member, type Source } from '../packages/protocol/index.js';
import type { ClientAuthResponse, ClientSession, DevicePairingResponse, DevicePairingView, RunLeaseResponse } from '../packages/protocol/client.js';
import { ClientStore } from '../packages/storage/client.js';

const codeA = '86420975', codeB = '57319042';
async function setup() {
  const dir = await mkdtemp(join(tmpdir(), 'matching-code-'));
  const options = { dbPath: join(dir, 'hub.sqlite'), adminToken: 'matching_code_test_admin_abcdefghijklmnopqrstuvwxyz', port: 0 };
  let hub = await createHub(options);
  async function raw(path: string, body?: unknown, token?: string, method = body === undefined ? 'GET' : 'POST', extra: Record<string, string> = {}) {
    return fetch(hub.url + path, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...extra }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  }
  async function api<T>(path: string, body?: unknown, token?: string, method?: string): Promise<T> {
    const response = await raw(path, body, token, method); assert.equal(response.ok, true, `${path}: ${response.status} ${response.ok ? '' : await response.text()}`); return response.json() as Promise<T>;
  }
  async function start(code = codeA, deviceName = '朋友的电脑') {
    const verifier = randomBytes(48).toString('base64url');
    const pair = await api<DevicePairingResponse>('/client/v2/device-pairings', { deviceName, platform: 'darwin', clientVersion: 'matching-test', requestedScopes: ['consumer', 'donor'], codeChallengeMethod: 'S256', codeChallenge: createHash('sha256').update(verifier).digest('base64url') });
    return { pair, body: { deviceCode: pair.deviceCode, codeVerifier: verifier, sharedCode: code } };
  }
  async function redeem(started: Awaited<ReturnType<typeof start>>) { return api<ClientAuthResponse>('/client/v2/device-pairings/token', { deviceCode: started.body.deviceCode, codeVerifier: started.body.codeVerifier }); }
  async function connect(code = codeA, deviceName = '朋友的电脑') { const started = await start(code, deviceName); await api('/client/v2/device-pairings/match', started.body); return redeem(started); }
  return { dir, raw, api, start, redeem, connect, get hub() { return hub; }, get clients() { return new ClientStore(hub.store); }, async restart() { await hub.close(); hub = await createHub(options); }, async close() { await hub.close(); await rm(dir, { recursive: true, force: true }); } };
}

test('arbitrary matching codes create durable isolated rooms without preset configuration or plaintext storage', async () => {
  const f = await setup(); try {
    const meta = await f.api<{ pairing: { matchingCodeAvailable: boolean; sharedCodeAvailable: boolean }; features: string[] }>('/client/v2/meta');
    assert.equal(meta.pairing.matchingCodeAvailable, true); assert.equal(meta.pairing.sharedCodeAvailable, false); assert.ok(meta.features.includes('friend-code-matching'));
    const first = await f.connect(); await f.restart(); const second = await f.connect('8642-0975'), outsider = await f.connect(codeB);
    const members = await f.api<{ members: Member[] }>('/client/v2/members', undefined, first.accessToken);
    assert.deepEqual(new Set(members.members.map(member => member.id)), new Set([first.member.id, second.member.id]));
    assert.equal(first.member.role, 'member'); assert.equal(second.member.role, 'member'); assert.notEqual(first.member.id, second.member.id);
    assert.deepEqual((await f.api<{ members: Member[] }>('/client/v2/members', undefined, outsider.accessToken)).members.map(member => member.id), [outsider.member.id]);
    assert.equal(f.hub.store.listGrants().length, 0); assert.equal(f.hub.store.listSources().length, 0);
    const objects = f.hub.store.db.prepare('SELECT kind,id,data FROM client_objects').all();
    assert.equal(objects.filter(row => row.kind === 'matching-key').length, 1); assert.equal(objects.filter(row => row.kind === 'matching-room').length, 2);
    assert.equal(Number(f.hub.store.db.prepare('SELECT MAX(version) AS v FROM client_migrations').get()!.v), 3);
    f.hub.store.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    const database = await readFile(join(f.dir, 'hub.sqlite')); for (const code of [codeA, codeB]) assert.equal(database.includes(Buffer.from(code)), false);
  } finally { await f.close(); }
});

test('matching approval is atomic and idempotent, binds its code, and honors PKCE and pairing lifecycle', async () => {
  const f = await setup(); try {
    const started = await f.start();
    const responses = await Promise.all([f.raw('/client/v2/device-pairings/match', started.body), f.raw('/client/v2/device-pairings/match', { ...started.body, sharedCode: '8642 0975' })]);
    assert.deepEqual(responses.map(response => response.status), [200, 200]);
    const first = await responses[0]!.json() as { pairing: DevicePairingView }; assert.deepEqual(await responses[1]!.json(), first);
    assert.equal(f.hub.store.listMembers().length, 1);
    const changed = await f.raw('/client/v2/device-pairings/match', { ...started.body, sharedCode: codeB }); assert.equal(changed.status, 409); assert.equal((await changed.json()).error.code, 'SHARE_MATCHING_CODE_CONFLICT');
    assert.equal(f.hub.store.db.prepare("SELECT id FROM client_objects WHERE kind='matching-room'").all().length, 1);
    const auth = await f.redeem(started); assert.equal(auth.member.role, 'member'); assert.equal((await f.raw('/client/v2/device-pairings/match', started.body)).status, 409);
    const pending = await f.start();
    for (const sharedCode of ['1234567', 'abcdefgh', '１２３４５６７８']) { const response = await f.raw('/client/v2/device-pairings/match', { ...pending.body, sharedCode }); assert.equal(response.status, 400); assert.equal((await response.json()).error.code, 'SHARE_CODE_INVALID'); }
    assert.equal((await f.raw('/client/v2/device-pairings/match', { ...pending.body, codeVerifier: 'X'.repeat(64) })).status, 401);
    assert.equal((await f.raw('/client/v2/device-pairings/match', pending.body, undefined, 'POST', { origin: f.hub.url })).status, 403);
    await f.api('/client/v2/device-pairings/cancel', { deviceCode: pending.body.deviceCode, codeVerifier: pending.body.codeVerifier });
    assert.equal((await f.raw('/client/v2/device-pairings/match', pending.body)).status, 409); assert.equal(f.hub.store.listMembers().length, 2);
  } finally { await f.close(); }
});

test('simultaneous first arrivals share one room and legacy native admin cannot enumerate matching members', async () => {
  const f = await setup(); try {
    const legacyAdmin = f.hub.store.listMembers()[0]!;
    const legacyPair = await f.start(); f.clients.approvePairing(legacyPair.pair.userCode, legacyAdmin);
    const adminDevice = await f.redeem(legacyPair);
    const [first, second] = await Promise.all([f.connect(codeA, '第一台'), f.connect(codeA, '第二台')]);
    assert.equal(f.clients.memberRoom(first.member.id), f.clients.memberRoom(second.member.id));
    assert.equal(f.hub.store.db.prepare("SELECT id FROM client_objects WHERE kind='matching-room'").all().length, 1);
    assert.equal(f.clients.memberRoom(legacyAdmin.id), 'legacy');
    assert.deepEqual((await f.api<{ members: Member[] }>('/client/v2/members', undefined, adminDevice.accessToken)).members.map(member => member.id), [legacyAdmin.id]);
    assert.equal((await f.api<{ matchingRoom: boolean }>('/client/v2/me', undefined, adminDevice.accessToken)).matchingRoom, false);
    assert.equal((await f.api<{ matchingRoom: boolean }>('/client/v2/me', undefined, first.accessToken)).matchingRoom, true);
    const source = (await f.api<{ source: Source }>('/client/v2/sources', { name: '匹配来源', kind: 'mock', accountBinding: 'mock:matching-admin-test', policy: policySchema.parse({ allowedMemberIds: [first.member.id], models: ['mock-codex'] }) }, first.accessToken)).source;
    assert.deepEqual((await f.api<{ sources: Source[] }>('/client/v2/sources', undefined, adminDevice.accessToken)).sources, []);
    assert.equal((await f.raw('/client/v2/grants', { sourceId: source.id, label: '跨组管理员', models: ['mock-codex'] }, adminDevice.accessToken)).status, 404);
  } finally { await f.close(); }
});

test('cancelled and expired matching approvals leave no visible members and cancelling a redeemed device deactivates its member', async () => {
  const f = await setup(); try {
    const friend = await f.connect();
    const cancelled = await f.start(); await f.api('/client/v2/device-pairings/match', cancelled.body);
    await f.api('/client/v2/device-pairings/cancel', { deviceCode: cancelled.body.deviceCode, codeVerifier: cancelled.body.codeVerifier });
    const expired = await f.start(); await f.api('/client/v2/device-pairings/match', expired.body);
    f.hub.store.db.prepare("UPDATE client_objects SET data=json_set(data,'$.expiresAt',?) WHERE kind='pairing' AND id=?").run(Date.now() - 1, expired.pair.pairingId);
    assert.equal((await f.raw('/client/v2/device-pairings/token', { deviceCode: expired.body.deviceCode, codeVerifier: expired.body.codeVerifier })).status, 400);
    assert.equal(f.hub.store.listMembers().length, 2, 'unredeemed approvals create no member records');
    assert.deepEqual((await f.api<{ members: Member[] }>('/client/v2/members', undefined, friend.accessToken)).members.map(member => member.id), [friend.member.id]);
    const redeemed = await f.start(); await f.api('/client/v2/device-pairings/match', redeemed.body); const identity = await f.redeem(redeemed);
    const anotherDevice = await f.start(); f.clients.approvePairing(anotherDevice.pair.userCode, identity.member); await f.redeem(anotherDevice);
    await f.api('/client/v2/device-pairings/cancel', { deviceCode: redeemed.body.deviceCode, codeVerifier: redeemed.body.codeVerifier });
    assert.equal(f.hub.store.getMember(identity.member.id)?.active, true, 'another live device keeps this matched member active');
    await f.api('/client/v2/device-pairings/cancel', { deviceCode: anotherDevice.body.deviceCode, codeVerifier: anotherDevice.body.codeVerifier });
    assert.equal(f.hub.store.getMember(identity.member.id)?.active, false);
    assert.deepEqual((await f.api<{ members: Member[] }>('/client/v2/members', undefined, friend.accessToken)).members.map(member => member.id), [friend.member.id]);
  } finally { await f.close(); }
});

test('room boundaries protect policies, grants, sessions, runs and inference even with a stale cross-room grant', async () => {
  const f = await setup(); try {
    const donor = await f.connect(), friend = await f.connect(), outsider = await f.connect(codeB);
    const policy = policySchema.parse({ allowedMemberIds: [donor.member.id, friend.member.id], models: ['mock-codex'] });
    const payload = { name: '房间来源', kind: 'mock', accountBinding: 'mock:matching-room-a', policy };
    assert.equal((await f.raw('/client/v2/sources', { ...payload, policy: { ...policy, allowedMemberIds: [outsider.member.id] } }, donor.accessToken)).status, 400);
    assert.equal(f.hub.store.listSources().length, 0);
    const created = await f.api<{ source: Source }>('/client/v2/sources', payload, donor.accessToken), source = created.source;
    assert.equal((await f.raw(`/client/v2/sources/${source.id}/policy`, { policy: { ...policy, allowedMemberIds: [outsider.member.id] } }, donor.accessToken, 'PATCH')).status, 400);
    assert.deepEqual((await f.api<{ sources: Source[] }>('/client/v2/sources', undefined, outsider.accessToken)).sources, []);
    assert.equal((await f.raw('/client/v2/grants', { sourceId: source.id, memberId: outsider.member.id, label: '跨空间', models: ['mock-codex'] }, donor.accessToken)).status, 404);
    assert.equal((await f.raw('/client/v2/grants', { sourceId: source.id, label: '猜来源', models: ['mock-codex'] }, outsider.accessToken)).status, 404);
    const grant = (await f.api<{ grant: Grant }>('/client/v2/grants', { sourceId: source.id, label: '朋友授权', models: ['mock-codex'] }, friend.accessToken)).grant;
    assert.deepEqual((await f.api<{ grants: Grant[] }>('/client/v2/grants', undefined, outsider.accessToken)).grants, []);
    assert.equal((await f.raw('/client/v2/sessions', { grantId: grant.id, modelScope: ['mock-codex'] }, outsider.accessToken)).status, 404);
    const stale = f.hub.store.createGrant({ sourceId: source.id, memberId: outsider.member.id, label: '模拟历史错误授权', models: ['mock-codex'] });
    assert.equal((await f.raw('/client/v2/sessions', { grantId: stale.id, modelScope: ['mock-codex'] }, outsider.accessToken)).status, 404);
    assert.deepEqual((await f.api<{ grants: Grant[] }>('/client/v2/grants', undefined, outsider.accessToken)).grants, []);
    const session = (await f.api<{ session: ClientSession }>('/client/v2/sessions', { grantId: grant.id, modelScope: ['mock-codex'] }, friend.accessToken)).session;
    const run = await f.api<RunLeaseResponse>(`/client/v2/sessions/${session.id}/leases`, {}, friend.accessToken);
    assert.equal((await f.raw(`/client/v2/sessions/${session.id}/leases`, {}, outsider.accessToken)).status, 404);
    assert.equal(f.clients.inference(run.token).member.id, friend.member.id);
    // Simulate an old/admin-written source ownership inconsistency: every data-plane gate rechecks the boundary.
    f.hub.store.db.prepare("UPDATE sources SET data=json_set(data,'$.ownerId',?) WHERE id=?").run(outsider.member.id, source.id);
    assert.equal((await f.raw(`/client/v2/run-leases/${run.lease.id}/renew`, {}, friend.accessToken)).status, 404);
    assert.throws(() => f.clients.inference(run.token), { code: 'SHARE_NOT_FOUND' });
    assert.equal((await f.raw('/client/v2/sessions', { grantId: grant.id, modelScope: ['mock-codex'] }, friend.accessToken)).status, 404);
  } finally { await f.close(); }
});
