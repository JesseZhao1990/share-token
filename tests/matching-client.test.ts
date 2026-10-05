import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHub } from '../apps/hub/index.js';
import { WorkerProcess } from '../apps/desktop/main/worker.js';
import { HubClient, type DeviceCredentials, type PairingInput } from '../packages/hub-client/index.js';
import type { Member } from '../packages/protocol/index.js';

const code = '41826375', otherCode = '92735184';
const input: PairingInput = { deviceName: '匹配客户端测试', platform: 'darwin', clientVersion: 'test', requestedScopes: ['consumer', 'donor'] };
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'matching-client-'));
  const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: 'matching_client_admin_abcdefghijklmnopqrstuvwxyz', port: 0 });
  return { dir, hub, async close() { await hub.close(); await rm(dir, { recursive: true, force: true }); } };
}

test('real matching clients connect without preset code, retain identities, and see only same-code friends', async () => {
  const f = await fixture(); try {
    const saved: (DeviceCredentials | null)[] = [], paths: string[] = [];
    const first = new HubClient({ baseUrl: f.hub.url, onCredentials: value => { saved.push(value); }, fetch: async (url, options) => { paths.push(new URL(String(url)).pathname); return fetch(url, options); } });
    const second = new HubClient({ baseUrl: f.hub.url }), outsider = new HubClient({ baseUrl: f.hub.url });
    assert.equal((await first.meta()).pairing.sharedCodeAvailable, false);
    const joined = await first.joinWithMatchingCode(input, '4182 6375'); assert.equal(joined.status, 'approved');
    assert.equal((await second.joinWithMatchingCode(input, code)).status, 'approved');
    assert.equal((await outsider.joinWithMatchingCode(input, otherCode)).status, 'approved');
    assert.ok(paths.includes('/client/v2/device-pairings/match')); assert.equal(paths.includes('/client/v2/device-pairings/join'), false);
    assert.equal(saved.length, 1); assert.ok(saved[0]); assert.equal(JSON.stringify(saved).includes(code), false);
    const members = await first.request<{ members: Member[] }>('GET', '/client/v2/members');
    assert.deepEqual(new Set(members.members.map(member => member.id)), new Set([first.getCredentials()!.memberId, second.getCredentials()!.memberId]));
    assert.deepEqual((await outsider.request<{ members: Member[] }>('GET', '/client/v2/members')).members.map(member => member.id), [outsider.getCredentials()!.memberId]);
    const restored = new HubClient({ baseUrl: f.hub.url, credentials: saved[0] });
    const me = await restored.request<{ member: Member; matchingRoom: boolean }>('GET', '/client/v2/me');
    assert.equal(me.member.id, first.getCredentials()!.memberId); assert.equal(me.member.role, 'member'); assert.equal(me.matchingRoom, true);
  } finally { await f.close(); }
});

test('lost matching approval retries its original PKCE request and never falls back to legacy join', async () => {
  const f = await fixture(); try {
    let drop = true; const paths: string[] = [];
    const client = new HubClient({ baseUrl: f.hub.url, fetch: async (url, options) => {
      const path = new URL(String(url)).pathname; paths.push(path); const response = await fetch(url, options);
      if (path.endsWith('/device-pairings/match') && drop) { drop = false; assert.equal(response.status, 200); await response.arrayBuffer(); throw new TypeError('simulated response loss'); }
      return response;
    } });
    await assert.rejects(client.joinWithMatchingCode(input, code), { code: 'SHARE_HUB_CONNECTION_FAILED' });
    assert.equal(client.getCredentials(), null); assert.equal(f.hub.store.listMembers().length, 1, 'approval alone must not create a visible friend');
    await assert.rejects(client.joinWithSharedCode(input, code), { code: 'SHARE_PAIRING_ACTIVE' });
    assert.equal((await client.joinWithMatchingCode(input, code)).status, 'approved');
    assert.equal(f.hub.store.listMembers().length, 2); assert.equal(paths.filter(path => path === '/client/v2/device-pairings').length, 1); assert.equal(paths.includes('/client/v2/device-pairings/join'), false);
  } finally { await f.close(); }
});

test('changing a code after lost approval cancels the old request and the next click joins the new room without ghost members', async () => {
  const f = await fixture(); try {
    let drop = true; const paths: string[] = [];
    const client = new HubClient({ baseUrl: f.hub.url, fetch: async (url, options) => {
      const path = new URL(String(url)).pathname; paths.push(path); const response = await fetch(url, options);
      if (path.endsWith('/device-pairings/match') && drop) { drop = false; assert.equal(response.status, 200); await response.arrayBuffer(); throw new TypeError('simulated response loss'); }
      return response;
    } });
    await assert.rejects(client.joinWithMatchingCode(input, code), { code: 'SHARE_HUB_CONNECTION_FAILED' });
    await assert.rejects(client.joinWithMatchingCode(input, otherCode), { code: 'SHARE_JOIN_RESTART' });
    const oldPairings = f.hub.store.db.prepare("SELECT data FROM client_objects WHERE kind='pairing'").all();
    assert.equal(oldPairings.length, 1); assert.equal(JSON.parse(String(oldPairings[0]!.data)).status, 'cancelled');
    assert.equal(paths.filter(path => path.endsWith('/device-pairings/cancel')).length, 1);
    assert.equal(client.getCredentials(), null); assert.equal(f.hub.store.listMembers().length, 1);
    assert.equal((await client.joinWithMatchingCode(input, otherCode)).status, 'approved');
    assert.equal(f.hub.store.listMembers().length, 2); assert.equal(paths.filter(path => path === '/client/v2/device-pairings').length, 2);
    const friend = new HubClient({ baseUrl: f.hub.url }); await friend.joinWithMatchingCode(input, otherCode);
    assert.deepEqual(new Set((await client.request<{ members: Member[] }>('GET', '/client/v2/members')).members.map(member => member.id)), new Set([client.getCredentials()!.memberId, friend.getCredentials()!.memberId]));
    assert.equal(f.hub.store.listMembers().length, 3, 'only the two redeemed devices and legacy admin exist');
    assert.equal(paths.includes('/client/v2/device-pairings/join'), false);
  } finally { await f.close(); }
});

test('cancelling an in-flight matching approval prevents credential persistence and permits a fresh code', async () => {
  const f = await fixture(); let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  try {
    let approved!: () => void; const approval = new Promise<void>(resolve => { approved = resolve; }); let hold = true;
    const saved: (DeviceCredentials | null)[] = [];
    const client = new HubClient({ baseUrl: f.hub.url, onCredentials: value => { saved.push(value); }, fetch: async (url, options) => {
      const response = await fetch(url, options);
      if (String(url).endsWith('/device-pairings/match') && hold) { hold = false; assert.equal(response.status, 200); approved(); await held; }
      return response;
    } });
    const joining = client.joinWithMatchingCode(input, code); const cancelled = assert.rejects(joining, { code: 'PAIRING_CANCELLED' });
    await approval;
    await assert.rejects(client.joinWithMatchingCode(input, code), { code: 'SHARE_JOIN_BUSY' });
    await client.cancelPairing(); release(); await cancelled;
    assert.equal(client.getCredentials(), null); assert.deepEqual(saved, []); assert.equal(f.hub.store.listMembers().length, 1);
    assert.equal((await client.joinWithMatchingCode(input, otherCode)).status, 'approved'); assert.ok(client.getCredentials());
    assert.equal(f.hub.store.listMembers().filter(member => member.active).length, 2);
  } finally { release(); await f.close(); }
});

test('production worker joins without preset code and refuses old services before any pairing write', async () => {
  const f = await fixture(); const workers: WorkerProcess[] = []; const oldPaths: string[] = [];
  const old = createServer((req, res) => { oldPaths.push(req.url ?? ''); res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ pairing: { method: 'S256', expiresIn: 300, interval: 3, sharedCodeAvailable: true } })); });
  try {
    await new Promise<void>(resolve => { old.listen(0, '127.0.0.1', resolve); });
    const entry = join(f.dir, 'worker.mjs');
    await writeFile(entry, `import { register } from ${JSON.stringify(import.meta.resolve('tsx/esm/api'))}; register(); await import(${JSON.stringify(pathToFileURL(resolve('apps/client-worker/host.ts')).href)});`);
    const saved: unknown[] = [];
    const consumer = new WorkerProcess(process.execPath, entry, 'consumer', undefined, async value => { saved.push(value); }); workers.push(consumer);
    assert.equal((await consumer.request<{ status: string }>('pair.join', { hubUrl: f.hub.url, deviceName: '生产worker', sharedCode: code })).status, 'approved');
    const snapshot = await consumer.request<{ connected: boolean; matchingRoom: boolean }>('snapshot'); assert.equal(snapshot.connected, true); assert.equal(snapshot.matchingRoom, true); assert.equal(saved.length, 1);
    const legacy = new WorkerProcess(process.execPath, entry, 'consumer', undefined, async () => { assert.fail('Unsupported server must not save credentials'); }); workers.push(legacy);
    const oldAddress = old.address(); assert.ok(oldAddress && typeof oldAddress === 'object');
    await assert.rejects(legacy.request('pair.join', { hubUrl: `http://127.0.0.1:${oldAddress.port}`, deviceName: '旧服务测试', sharedCode: code }), { code: 'SHARE_MATCHING_UNAVAILABLE', status: 409 });
    assert.ok(oldPaths.length > 0); assert.ok(oldPaths.every(path => path === '/client/v2/meta'));
  } finally { await Promise.all(workers.map(worker => worker.close())); await new Promise<void>(resolve => { old.close(() => resolve()); }); await f.close(); }
});
