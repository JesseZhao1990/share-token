import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHub } from '../apps/hub/index.js';
import { WorkerProcess } from '../apps/desktop/main/worker.js';
import { HubClient } from '../packages/hub-client/index.js';
import { policySchema, ShareError } from '../packages/protocol/index.js';
import { restoreClientError, serializeClientError } from '../packages/protocol/client-errors.js';
import type { DonorSnapshot } from '../packages/client-core/donor.js';
import { saveSharedCodeVerifier } from '../packages/storage/shared-code.js';

// Opt in only for synthetic regression fixtures; these tests never call a real upstream.
const previousExperimentalSubscription = process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION;
process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = '1';
after(() => { if (previousExperimentalSubscription === undefined) delete process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION; else process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = previousExperimentalSubscription; });

const sensitive = 'NEVER_EXPOSE_SECRET_fixture_refresh_and_upstream_body';

test('client error transport preserves only allowlisted codes/status and always replaces messages locally', () => {
  for (const code of ['SHARE_SOURCE_EXISTS', 'SHARE_SOURCE_OWNED_ELSEWHERE', 'SHARE_MEMBER_INVALID', 'SHARE_POLICY_CONFLICT', 'SHARE_AUTH_INVALID', 'SHARE_HUB_CONNECTION_FAILED', 'SHARE_HUB_TRUST_INVALID']) {
    const wire = serializeClientError(new ShareError(code, sensitive, 422));
    assert.equal(wire.code, code); assert.equal(wire.status, 422); assert.equal(JSON.stringify(wire).includes(sensitive), false);
    const restored = restoreClientError({ ...wire, message: sensitive, stack: sensitive, extra: sensitive });
    assert.ok(restored instanceof ShareError); assert.equal(restored.code, code); assert.equal(restored.status, 422); assert.equal(restored.message, wire.message);
  }
  assert.equal(restoreClientError({ code: 'CERT_HAS_EXPIRED', message: sensitive }).code, 'SHARE_HUB_TLS_FAILED');
  assert.equal(restoreClientError({ code: 'ECONNRESET', message: sensitive }).code, 'SHARE_HUB_CONNECTION_FAILED');
  assert.equal(restoreClientError({ code: 'SHARE_SOURCE_EXISTS', status: 200, message: sensitive }).status, 409);
  for (const value of [new Error(sensitive), new ShareError('UNRECOGNIZED_PRIVATE_ERROR', sensitive, 401), { code: '__proto__', message: sensitive }, { get code() { throw new Error(sensitive); } }]) {
    const safe = serializeClientError(value); assert.equal(safe.code, 'SHARE_CLIENT_ERROR'); assert.equal(safe.status, 500); assert.equal(JSON.stringify(safe).includes(sensitive), false);
  }
});

async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'share-worker-errors-')), codePath = join(dir, 'shared-code.json');
  await saveSharedCodeVerifier(codePath, '13246857');
  const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: 'worker_error_admin_abcdefghijklmnopqrstuvwxyz', port: 0, sharedCodePath: codePath });
  // Run the actual production host in fresh child processes, resolving source .js imports through
  // tsx only in this test bootstrap. No checked-in dist artifact or fake IPC facade is exercised.
  const bootstrap = join(dir, 'worker.mjs');
  await writeFile(bootstrap, `import { register } from ${JSON.stringify(import.meta.resolve('tsx/esm/api'))}; register(); await import(${JSON.stringify(pathToFileURL(resolve('apps/client-worker/host.ts')).href)});`);
  const direct = new HubClient({ baseUrl: hub.url });
  await direct.joinWithSharedCode({ deviceName: 'Worker fixture', platform: 'test', clientVersion: 'test', requestedScopes: ['consumer', 'donor'] }, '13246857');
  const credentials = direct.getCredentials()!, persisted: unknown[] = [], events: unknown[] = [];
  const consumer = new WorkerProcess(process.execPath, bootstrap, 'consumer', undefined, async value => { persisted.push(value); });
  const donor = new WorkerProcess(process.execPath, bootstrap, 'donor', (method, path, body) => consumer.request('hub.request', { method, path, body }));
  donor.on('event', event => events.push(event));
  await consumer.request('connect', { hubUrl: hub.url, credentials });
  await donor.request('init', { hubUrl: hub.url, stateDir: dir });
  return { dir, hub, consumer, donor, credentials, events, persisted,
    policy: policySchema.parse({ allowedMemberIds: [credentials.memberId], models: ['gpt-fixture-codex'] }),
    async close() { await donor.close(); await consumer.close(); await hub.close(); await rm(dir, { recursive: true, force: true }); } };
}

async function subscriptionFixture(dir: string) {
  const binary = join(dir, 'fake-codex'), accountId = 'worker-private-account', userId = 'worker-private-user';
  const jwt = `header.${Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, sub: userId })).toString('base64url')}.signature`;
  const auth = { auth_mode: 'chatgpt', OPENAI_API_KEY: null, tokens: { account_id: accountId, access_token: jwt, refresh_token: sensitive, id_token: jwt } };
  const rateLimits = { limitId: 'codex', primary: { usedPercent: 12, windowDurationMins: 300, resetsAt: Math.floor(Date.now() / 1000) + 3600 } };
  await writeFile(binary, `#!${process.execPath}
const fs=require('node:fs'),path=require('node:path'),readline=require('node:readline');
if(process.argv.includes('--version')) { console.log('codex-cli 0.153.4'); process.exit(0); }
const send=x=>process.stdout.write(JSON.stringify(x)+'\\n');
readline.createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);
if(m.method==='initialize'){fs.writeFileSync(path.join(process.env.CODEX_HOME,'auth.json'),JSON.stringify(${JSON.stringify(auth)}),{mode:0o600});send({id:m.id,result:{userAgent:'fixture'}});return;}
if(m.method==='initialized')return;
if(m.method==='account/read'){send({id:m.id,result:{account:{type:'chatgpt',email:'fixture@example.invalid',planType:'plus'},requiresOpenaiAuth:true}});return;}
if(m.method==='model/list'){send({id:m.id,result:{data:[{model:'gpt-fixture-codex',hidden:false}],nextCursor:null}});return;}
if(m.method==='account/rateLimits/read'){send({id:m.id,result:{accountId:${JSON.stringify(accountId)},rateLimits:${JSON.stringify(rateLimits)}}});return;}
send({id:m.id,error:{message:'Unexpected fixture request'}});});
`, { mode: 0o700 });
  return { binary, codexHome: join(dir, 'codex-account'), binding: `codex:${createHash('sha256').update(JSON.stringify([accountId, userId])).digest('hex')}` };
}

test('real consumer and donor workers save a new member subscription without taking over the old member source', async () => {
  const f = await fixture(); try {
    const account = await subscriptionFixture(f.dir);
    const status = await f.donor.request<{ authenticated: boolean }>('subscription.init', account); assert.equal(status.authenticated, true);
    const owner = f.hub.store.listMembers().find(member => member.role === 'admin')!;
    const source = f.hub.store.createSource({ name: 'Existing subscription', kind: 'subscription', ownerId: owner.id, accountBinding: account.binding, policy: policySchema.parse({ models: ['gpt-fixture-codex'], allowedMemberIds: [owner.id] }) });
    const before = structuredClone(source);
    const saved = await f.donor.request<DonorSnapshot>('configure', { name: 'My subscription', kind: 'subscription', policy: f.policy });
    assert.equal(saved.policySync, 'synced'); assert.equal(saved.lastError, null);
    assert.equal(saved.source?.ownerId, f.credentials.memberId); assert.notEqual(saved.config?.sourceId, source.id);
    const retried = await f.donor.request<DonorSnapshot>('configure', { name: 'My subscription', kind: 'subscription', policy: f.policy });
    assert.equal(retried.config?.sourceId, saved.config?.sourceId);
    const snapshot = await f.donor.request<DonorSnapshot>('snapshot');
    assert.deepEqual(f.hub.store.getSource(source.id), before); assert.equal(f.hub.store.listSources().length, 2); assert.equal(f.hub.store.listRequests().length, 0);
    assert.equal(JSON.stringify([snapshot, f.events]).includes(sensitive), false);
  } finally { await f.close(); }
});

test('real donor→main→consumer→Hub round trips sanitize malicious server messages and retain action codes/status', async () => {
  const f = await fixture(); try {
    const original = f.hub.store.createSource.bind(f.hub.store);
    const fixtureInput = { name: 'Sanitization fixture', kind: 'mock', accountBinding: 'mock:safe-fixture', policy: f.policy };
    for (const code of ['SHARE_MEMBER_INVALID', 'SHARE_POLICY_CONFLICT', 'SHARE_HUB_TRUST_INVALID', 'PRIVATE_ARBITRARY_ERROR']) {
      f.hub.store.createSource = () => { throw new ShareError(code, sensitive + ' bearer=secret-not-owned-by-client', 422); };
      const expected = serializeClientError(new ShareError(code, sensitive, 422));
      await assert.rejects(f.donor.request('configure', fixtureInput), error => {
        assert.ok(error instanceof ShareError); assert.equal(error.code, expected.code); assert.equal(error.status, expected.status); assert.equal(error.message, expected.message); assert.equal(error.message.includes(sensitive), false); return true;
      });
      const state = await f.donor.request<DonorSnapshot>('snapshot'); assert.deepEqual(state.lastError, { code: expected.code, message: expected.message });
    }
    f.hub.store.createSource = original;
    f.hub.store.deactivateMember(f.credentials.memberId);
    await assert.rejects(f.donor.request('configure', fixtureInput), { code: 'SHARE_AUTH_INVALID', status: 401 });
    assert.equal((await f.donor.request<DonorSnapshot>('snapshot')).lastError?.code, 'SHARE_AUTH_INVALID');
    assert.equal(f.persisted.length, 1, 'The consumer owner persists identity invalidation once');
    assert.equal(JSON.stringify(f.events).includes(sensitive), false); assert.equal(JSON.stringify(f.events).includes('PRIVATE_ARBITRARY_ERROR'), false);
  } finally { await f.close(); }
});

test('worker network failure remains actionable and preserves ambiguous-operation status through donor proxy', async () => {
  const f = await fixture(); try {
    await f.hub.close();
    await assert.rejects(f.donor.request('configure', { name: 'Offline fixture', kind: 'mock', accountBinding: 'mock:offline', policy: f.policy }), error => {
      assert.ok(error instanceof ShareError); assert.equal(error.code, 'SHARE_HUB_CONNECTION_FAILED'); assert.equal(error.status, 503); assert.match(error.message, /刷新状态后再决定/); return true;
    });
    assert.equal((await f.donor.request<DonorSnapshot>('snapshot')).lastError?.code, 'SHARE_HUB_CONNECTION_FAILED');
  } finally { await f.close(); }
});
