import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { createHub } from '../apps/hub/index.js';
import { policySchema } from '../packages/protocol/index.js';
import type { ClientAuthResponse, DevicePairingResponse } from '../packages/protocol/client.js';
import { loadSharedCodeVerifier, saveSharedCodeVerifier } from '../packages/storage/shared-code.js';
import { HubClient, type DeviceCredentials, type PairingInput } from '../packages/hub-client/index.js';

const code = '24681357', rotatedCode = '75248613';
const admin = 'test_shared_code_admin_abcdefghijklmnopqrstuvwxyz';
async function setup(enabled = true) {
  const dir = await mkdtemp(join(tmpdir(), 'share-code-')), sharedCodePath = join(dir, 'shared-code.json');
  if (enabled) await saveSharedCodeVerifier(sharedCodePath, code);
  const options = { dbPath: join(dir, 'hub.sqlite'), adminToken: admin, port: 0, sharedCodePath };
  let hub = await createHub(options);
  async function raw(path: string, body?: unknown, headers: Record<string, string> = {}) {
    return fetch(hub.url + path, { method: body === undefined ? 'GET' : 'POST', headers: { 'content-type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  }
  async function api<T = Record<string, unknown>>(path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    const response = await raw(path, body, headers); assert.equal(response.ok, true, `${path}: ${response.status} ${response.ok ? '' : await response.text()}`); return response.json() as Promise<T>;
  }
  async function start(deviceName = '朋友的电脑') {
    const verifier = randomBytes(48).toString('base64url');
    const pair = await api<DevicePairingResponse>('/client/v2/device-pairings', { deviceName, platform: 'darwin', clientVersion: 'test-shared-code', requestedScopes: ['consumer', 'donor'], codeChallengeMethod: 'S256', codeChallenge: createHash('sha256').update(verifier).digest('base64url') });
    return { pair, body: { deviceCode: pair.deviceCode, codeVerifier: verifier, sharedCode: code } };
  }
  async function redeem(started: Awaited<ReturnType<typeof start>>) { return api<ClientAuthResponse>('/client/v2/device-pairings/token', { deviceCode: started.body.deviceCode, codeVerifier: started.body.codeVerifier }); }
  return { dir, sharedCodePath, raw, api, start, redeem, get hub() { return hub; }, async restart() { await hub.close(); hub = await createHub(options); }, async close() { await hub.close(); await rm(dir, { recursive: true, force: true }); } };
}

test('shared code approves an ordinary member atomically and retries do not duplicate identity or grant sources', async () => {
  const f = await setup(); try {
    const adminMember = f.hub.store.listMembers()[0]!;
    const source = f.hub.store.createSource({ ownerId: adminMember.id, name: '私人来源', kind: 'mock', accountBinding: 'mock:private', policy: policySchema.parse({ allowedMemberIds: [adminMember.id], models: ['mock-codex'] }) });
    const started = await f.start(adminMember.name);
    const [first, retry] = await Promise.all([f.raw('/client/v2/device-pairings/join', { ...started.body, sharedCode: '2468-1357' }), f.raw('/client/v2/device-pairings/join', { ...started.body, sharedCode: '2468 1357' })]);
    assert.equal(first.status, 200); assert.equal(retry.status, 200);
    const response = await first.json(); assert.equal(response.pairing.status, 'approved'); assert.equal(response.accessToken, undefined); assert.equal(first.headers.has('set-cookie'), false);
    assert.deepEqual(await retry.json(), response); assert.equal(f.hub.store.listMembers().length, 2);
    const auth = await f.redeem(started); assert.equal(auth.member.role, 'member'); assert.notEqual(auth.member.id, adminMember.id); assert.equal(auth.member.name, adminMember.name);
    assert.deepEqual(auth.device.scopes, ['consumer', 'donor']);
    assert.deepEqual((await f.api<{ sources: unknown[] }>('/client/v2/sources', undefined, { authorization: `Bearer ${auth.accessToken}` })).sources, []);
    assert.deepEqual(f.hub.store.getSource(source.id)!.policy.allowedMemberIds, [adminMember.id]); assert.equal(f.hub.store.listGrants().length, 0);
    assert.equal((await f.raw('/control/dashboard', undefined, { authorization: `Bearer ${auth.accessToken}` })).status, 401);
    const another = await f.start(adminMember.name); await f.api('/client/v2/device-pairings/join', another.body); assert.notEqual((await f.redeem(another)).member.id, auth.member.id);
    f.hub.store.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    const database = await readFile(join(f.dir, 'hub.sqlite')); assert.equal(database.includes(Buffer.from(code)), false); assert.equal(database.includes(Buffer.from(auth.accessToken)), false);
  } finally { await f.close(); }
});

test('wrong code, wrong PKCE, expired and cancelled pairings create no member and cannot bypass pairing state', async () => {
  const f = await setup(); try {
    const started = await f.start();
    assert.equal((await f.raw('/client/v2/device-pairings/join', { ...started.body, sharedCode: '00000000' })).status, 401);
    assert.equal((await f.raw('/client/v2/device-pairings/join', { ...started.body, codeVerifier: 'X'.repeat(64) })).status, 401);
    assert.equal(f.hub.store.listMembers().length, 1);
    await f.api('/client/v2/device-pairings/cancel', { deviceCode: started.body.deviceCode, codeVerifier: started.body.codeVerifier });
    assert.equal((await f.raw('/client/v2/device-pairings/join', started.body)).status, 409);
    const expired = await f.start(); f.hub.store.db.prepare("UPDATE client_objects SET data=json_set(data,'$.expiresAt',?) WHERE kind='pairing' AND id=?").run(Date.now() - 1, expired.pair.pairingId);
    assert.equal((await f.raw('/client/v2/device-pairings/join', expired.body)).status, 409);
    const denied = await f.start(); f.hub.store.db.prepare("UPDATE client_objects SET data=json_set(data,'$.status','denied') WHERE kind='pairing' AND id=?").run(denied.pair.pairingId);
    assert.equal((await f.raw('/client/v2/device-pairings/join', denied.body)).status, 409);
    assert.equal(f.hub.store.listMembers().length, 1);
  } finally { await f.close(); }
});

test('failed-code throttle persists across Hub restart, is shared by browser/native, and success does not reset it', async () => {
  const f = await setup(); try {
    const started = await f.start();
    for (let i = 0; i < 2; i++) assert.equal((await f.raw('/client/v2/device-pairings/join', { ...started.body, sharedCode: '00000000' }, { 'x-forwarded-for': `192.0.2.${i}` })).status, 401);
    await f.api('/client/v2/device-pairings/join', started.body); await f.redeem(started);
    const second = await f.start();
    for (let i = 0; i < 3; i++) assert.equal((await f.raw(`/control/v2/device-pairings/${second.pair.userCode}/join`, { sharedCode: '00000000' }, { origin: f.hub.url })).status, 401);
    const limited = await f.raw('/client/v2/device-pairings/join', second.body); assert.equal(limited.status, 429); assert.equal((await limited.json()).error.code, 'SHARE_RATE_LIMITED');
    await f.restart(); assert.equal((await f.raw('/client/v2/device-pairings/join', second.body, { 'x-forwarded-for': '198.51.100.1' })).status, 429);
    const rows = f.hub.store.db.prepare("SELECT data FROM client_objects WHERE kind='auth-rate'").all(); assert.equal(rows.length, 1); assert.equal(JSON.parse(String(rows[0]!.data)).failedAt.length, 5);
    // Advance only the persistent limiter, not system clocks or pairing expiry.
    f.hub.store.db.prepare("UPDATE client_objects SET data=? WHERE kind='auth-rate' AND id='shared-code'").run(JSON.stringify({ failedAt: [Date.now() - 61_000], blockedUntil: Date.now() - 1 }));
    await f.api('/client/v2/device-pairings/join', second.body); assert.equal((await f.redeem(second)).member.role, 'member');
  } finally { await f.close(); }
});

test('native join rejects Origin and cross-site requests; browser join requires same-origin and issues no session', async () => {
  const f = await setup(); try {
    const started = await f.start();
    for (const headers of [{ origin: f.hub.url }, { origin: 'https://attacker.invalid' }, { 'sec-fetch-site': 'cross-site' }] as Record<string, string>[]) assert.equal((await f.raw('/client/v2/device-pairings/join', started.body, headers)).status, 403);
    const path = `/control/v2/device-pairings/${started.pair.userCode}/join`;
    for (const headers of [{}, { origin: 'https://attacker.invalid' }, { origin: f.hub.url.replace('http:', 'https:') }, { origin: f.hub.url, 'sec-fetch-site': 'cross-site' }] as Record<string, string>[]) assert.equal((await f.raw(path, { sharedCode: code }, headers)).status, 403);
    const response = await f.raw(path, { sharedCode: code }, { origin: f.hub.url }); assert.equal(response.status, 200); assert.equal(response.headers.has('set-cookie'), false); assert.deepEqual(Object.keys(await response.json()), ['pairing']);
    assert.equal((await f.raw(path, { sharedCode: code }, { origin: f.hub.url })).status, 200); assert.equal(f.hub.store.listMembers().length, 2);
    assert.equal((await f.redeem(started)).member.role, 'member');
  } finally { await f.close(); }
});

test('shared-code configuration is optional, verifier-only, and live rotation leaves existing devices working', async () => {
  const f = await setup(false); try {
    assert.equal((await f.api<{ pairing: { sharedCodeAvailable: boolean } }>('/client/v2/meta')).pairing.sharedCodeAvailable, false);
    const started = await f.start(); const disabled = await f.raw('/client/v2/device-pairings/join', started.body); assert.equal(disabled.status, 409); assert.equal((await disabled.json()).error.code, 'SHARE_SHARED_CODE_DISABLED'); assert.equal(f.hub.store.listMembers().length, 1);
    await saveSharedCodeVerifier(f.sharedCodePath, code); const meta = await f.api<{ pairing: { sharedCodeAvailable: boolean } }>('/client/v2/meta'); assert.equal(meta.pairing.sharedCodeAvailable, true); assert.equal(JSON.stringify(meta).includes(code), false);
    await f.api('/client/v2/device-pairings/join', started.body); const auth = await f.redeem(started);
    const original = await readFile(f.sharedCodePath, 'utf8'); assert.equal(original.includes(code), false); assert.deepEqual(Object.keys(JSON.parse(original)).sort(), ['hash', 'salt', 'version']); assert.equal((await stat(f.sharedCodePath)).mode & 0o777, 0o600);
    await assert.rejects(saveSharedCodeVerifier(f.sharedCodePath, rotatedCode), { code: 'EEXIST' }); assert.equal(await readFile(f.sharedCodePath, 'utf8'), original);
    await saveSharedCodeVerifier(f.sharedCodePath, rotatedCode, true); const second = await f.start(); assert.equal((await f.raw('/client/v2/device-pairings/join', second.body)).status, 401);
    await f.api('/client/v2/device-pairings/join', { ...second.body, sharedCode: rotatedCode }); assert.equal((await f.redeem(second)).member.role, 'member');
    assert.equal((await f.raw('/client/v2/me', undefined, { authorization: `Bearer ${auth.accessToken}` })).status, 200);
    await unlink(f.sharedCodePath); assert.equal((await f.api<{ pairing: { sharedCodeAvailable: boolean } }>('/client/v2/meta')).pairing.sharedCodeAvailable, false);
  } finally { await f.close(); }
});

test('verifier file rejects malformed configuration, symlinks, and public file permissions', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'share-code-files-')), path = join(dir, 'shared-code.json');
  try {
    await saveSharedCodeVerifier(path, code); const valid = await readFile(path, 'utf8');
    await chmod(path, 0o644); await assert.rejects(loadSharedCodeVerifier(path), { code: 'SHARE_SHARED_CODE_CONFIG_INVALID' });
    await chmod(path, 0o600); await writeFile(path, '{"version":1,"salt":"x","hash":"bad"}'); await assert.rejects(loadSharedCodeVerifier(path), { code: 'SHARE_SHARED_CODE_CONFIG_INVALID' });
    await writeFile(path, valid); const link = join(dir, 'linked.json'); await symlink(path, link); await assert.rejects(loadSharedCodeVerifier(link), { code: 'SHARE_SHARED_CODE_CONFIG_INVALID' });
    await assert.rejects(createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: admin, port: 0, sharedCodePath: link }), { code: 'SHARE_SHARED_CODE_CONFIG_INVALID' });
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('CLI sets and rotates through stdin without printing plaintext or overwriting on set', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'share-code-cli-'));
  async function run(action: string, input: string) {
    return new Promise<{ exit: number | null; output: string }>((resolve, reject) => {
      const child = spawn(process.execPath, ['--import', 'tsx', 'apps/cli/index.ts', 'shared-code', action, '--data-dir', dir], { stdio: ['pipe', 'pipe', 'pipe'] }); let output = '';
      child.stdout.on('data', chunk => { output += String(chunk); }); child.stderr.on('data', chunk => { output += String(chunk); }); child.once('error', reject); child.once('exit', exit => resolve({ exit, output })); child.stdin.end(input);
    });
  }
  try {
    const first = await run('set', code + '\n'); assert.equal(first.exit, 0); assert.equal(first.output.includes(code), false);
    const duplicate = await run('set', rotatedCode); assert.equal(duplicate.exit, 1); assert.equal(duplicate.output.includes(rotatedCode), false);
    const second = await run('rotate', rotatedCode); assert.equal(second.exit, 0); assert.equal(second.output.includes(rotatedCode), false);
    assert.ok(await loadSharedCodeVerifier(join(dir, 'shared-code.json')));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('real HubClient joins without browser, retries a wrong code, persists identities and restores after restart', async () => {
  const f = await setup(); try {
    const saved: (DeviceCredentials | null)[] = [];
    const client = new HubClient({ baseUrl: f.hub.url, onCredentials: credentials => { saved.push(credentials); } });
    const input: PairingInput = { deviceName: '同名朋友电脑', platform: 'darwin', clientVersion: 'shared-code-test', requestedScopes: ['consumer', 'donor'] };
    await assert.rejects(client.joinWithSharedCode(input, '00000000'), { code: 'SHARE_SHARED_CODE_INVALID' });
    assert.equal(client.getCredentials(), null); assert.equal(saved.length, 0); assert.equal(f.hub.store.listMembers().length, 1);
    assert.equal(f.hub.store.db.prepare("SELECT count(*) AS n FROM client_objects WHERE kind='pairing'").get()!.n, 1);
    const first = await client.joinWithSharedCode(input, '2468-1357'); assert.equal(first.status, 'approved'); assert.equal(saved.length, 1);
    assert.equal(f.hub.store.db.prepare("SELECT count(*) AS n FROM client_objects WHERE kind='pairing'").get()!.n, 1, 'Correcting a code must reuse the original PKCE request');
    assert.equal(first.status === 'approved' && first.member.role, 'member'); assert.equal(JSON.stringify(saved).includes(code), false);
    const other = new HubClient({ baseUrl: f.hub.url }); const second = await other.joinWithSharedCode(input, code);
    assert.equal(second.status, 'approved'); assert.notEqual(other.getCredentials()!.memberId, client.getCredentials()!.memberId);
    const restoredCredentials = saved[0]!; assert.ok(restoredCredentials); await f.restart();
    const restored = new HubClient({ baseUrl: f.hub.url, credentials: restoredCredentials });
    const me = await restored.request<{ member: { id: string; role: string } }>('GET', '/client/v2/me'); assert.equal(me.member.id, restoredCredentials.memberId); assert.equal(me.member.role, 'member');
  } finally { await f.close(); }
});

test('real HubClient reuses approved PKCE pairing when the join response is lost', async () => {
  const f = await setup(); try {
    let dropJoin = true;
    const client = new HubClient({ baseUrl: f.hub.url, fetch: async (input, init) => {
      const response = await fetch(input, init);
      if (String(input).endsWith('/device-pairings/join') && dropJoin) { dropJoin = false; assert.equal(response.status, 200); await response.text(); throw new TypeError('simulated connection loss'); }
      return response;
    } });
    const input: PairingInput = { deviceName: '响应丢失测试', platform: 'darwin', clientVersion: 'test', requestedScopes: ['consumer'] };
    await assert.rejects(client.joinWithSharedCode(input, code)); assert.equal(f.hub.store.listMembers().length, 2); assert.equal(client.getCredentials(), null);
    assert.equal((await client.joinWithSharedCode(input, code)).status, 'approved'); assert.equal(f.hub.store.listMembers().length, 2); assert.ok(client.getCredentials());
  } finally { await f.close(); }
});
