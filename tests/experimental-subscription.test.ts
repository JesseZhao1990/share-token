import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CodexSubscriptionAccount, SubscriptionAdapter, MockAdapter, experimentalSubscriptionEnabled, assertExperimentalSubscriptionEnabled } from '../packages/upstream/index.js';
import { ConsumerController } from '../packages/client-core/consumer.js';
import type { HubClient } from '../packages/hub-client/index.js';
import { DonorController } from '../packages/client-core/donor.js';
import { WorkerProcess } from '../apps/desktop/main/worker.js';
import { serializeClientError } from '../packages/protocol/client-errors.js';

const disabled = { code: 'SHARE_EXPERIMENTAL_SUBSCRIPTION_DISABLED', status: 403 };
const request = { requestId: 'request_disabled', operation: 'responses' as const, model: 'gpt-fixture', body: Buffer.from('{"model":"gpt-fixture","stream":true,"store":false,"input":[]}') };
function withoutOptIn(t: test.TestContext) {
  const previous = process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION;
  delete process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION;
  t.after(() => { if (previous === undefined) delete process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION; else process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = previous; });
}

test('only the exact local operator value 1 opts in; default and truthy alternatives stay disabled', t => {
  withoutOptIn(t);
  for (const value of [undefined, '', '0', 'true', 'TRUE', 'yes', ' 1', '1 ', '01']) {
    if (value === undefined) delete process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION;
    else process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = value;
    assert.equal(experimentalSubscriptionEnabled(), false);
    assert.throws(assertExperimentalSubscriptionEnabled, disabled);
  }
  process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = '1';
  assert.equal(experimentalSubscriptionEnabled(), true);
  assert.doesNotThrow(assertExperimentalSubscriptionEnabled);
  const safe = serializeClientError({ ...disabled, message: 'untrusted private details' });
  assert.equal(safe.code, disabled.code); assert.equal(safe.status, 403);
  assert.match(safe.message, /不代表获得上游授权/);
});

test('disabled account operations never create a login directory or start a Codex process', async t => {
  withoutOptIn(t);
  const dir = await mkdtemp(join(tmpdir(), 'share-subscription-disabled-'));
  const marker = join(dir, 'spawned'), home = join(dir, 'account'), binary = join(dir, 'fake-codex');
  await writeFile(binary, `#!${process.execPath}\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)},'started');\n`, { mode: 0o700 });
  const account = new CodexSubscriptionAccount({ codexHome: home, binary });
  t.after(async () => { await account.close(); await rm(dir, { recursive: true, force: true }); });
  assert.equal((await account.inspect()).lastError?.code, disabled.code);
  for (const operation of [() => account.startLogin(), () => account.cancelLogin(), () => account.logout()]) await assert.rejects(operation(), disabled);
  await assert.rejects(access(home), { code: 'ENOENT' });
  await assert.rejects(access(marker), { code: 'ENOENT' });
});

test('disabled adapter refuses inspection, quota and inference before any credential or transport access', async t => {
  withoutOptIn(t);
  let inspected = 0, transmitted = 0;
  const account = { inspect: async () => { inspected++; throw new Error('Must not inspect credentials'); } } as unknown as CodexSubscriptionAccount;
  const transport: typeof fetch = async () => { transmitted++; throw new Error('Must never call an upstream'); };
  const adapter = new SubscriptionAdapter({ account, accountBinding: 'codex:fixture', models: ['gpt-fixture'], transport });
  await assert.rejects(adapter.inspect(), disabled);
  await assert.rejects(adapter.readQuota(), disabled);
  await assert.rejects(adapter.open(request, new AbortController().signal), disabled);
  await assert.rejects(new SubscriptionAdapter().open(request, new AbortController().signal), disabled);
  assert.equal(inspected, 0); assert.equal(transmitted, 0);
  const mock = new MockAdapter({ models: ['gpt-fixture'] });
  assert.equal((await mock.inspect()).kind, 'mock');
  const result = await mock.open(request, new AbortController().signal);
  const pieces: Uint8Array[] = []; for await (const piece of result.body) pieces.push(piece);
  assert.match(Buffer.concat(pieces).toString(), /Mock fixture/); assert.equal(mock.calls, 1);
});

test('disabled donor rejects a subscription config before account inspection, adapter creation or Hub write', async t => {
  withoutOptIn(t);
  const dir = await mkdtemp(join(tmpdir(), 'share-donor-disabled-'));
  let inspected = 0, factories = 0, hubRequests = 0;
  const donor = new DonorController({ stateDir: dir, hub: { baseUrl: 'http://127.0.0.1:8787', request: async () => { hubRequests++; throw new Error('Must not write to Hub'); } },
    subscriptionAccount: { inspect: async () => { inspected++; throw new Error('Must not inspect credentials'); } },
    adapterFactory: () => { factories++; return new MockAdapter(); } });
  t.after(async () => { await donor.close(); await rm(dir, { recursive: true, force: true }); });
  assert.equal(donor.snapshot().subscriptionAvailable, false);
  await assert.rejects(donor.configure({ kind: 'subscription', policy: { models: ['gpt-fixture'], allowedMemberIds: ['friend'] } }), disabled);
  assert.equal(inspected, 0); assert.equal(factories, 0); assert.equal(hubRequests, 0);
  assert.equal(donor.snapshot().configured, false);
});

test('production worker IPC blocks subscription initialization before even executing the selected binary', async t => {
  withoutOptIn(t);
  const dir = await mkdtemp(join(tmpdir(), 'share-worker-subscription-disabled-'));
  const marker = join(dir, 'spawned'), binary = join(dir, 'fake-codex'), bootstrap = join(dir, 'worker.mjs');
  await writeFile(binary, `#!${process.execPath}\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)},'started');console.log('codex-cli 0.153.4');\n`, { mode: 0o700 });
  await writeFile(bootstrap, `import { register } from ${JSON.stringify(import.meta.resolve('tsx/esm/api'))}; register(); await import(${JSON.stringify(pathToFileURL(resolve('apps/client-worker/host.ts')).href)});`);
  const worker = new WorkerProcess(process.execPath, bootstrap, 'donor');
  t.after(async () => { await worker.close(); await rm(dir, { recursive: true, force: true }); });
  await assert.rejects(worker.request('subscription.init', { binary, codexHome: join(dir, 'account') }), disabled);
  await assert.rejects(worker.request('subscription.login'), disabled);
  await assert.rejects(worker.request('subscription.status'), disabled);
  await assert.rejects(access(marker), { code: 'ENOENT' });
  await assert.rejects(readFile(join(dir, 'account', 'auth.json')), { code: 'ENOENT' });
});


test('disabled consumer rejects a remote subscription source before creating a session or launching Codex', async t => {
  withoutOptIn(t);
  let writes = 0, launches = 0;
  const hub = { onCredentialsInvalidated: () => () => undefined, request: async (method: string, path: string) => {
    if (method !== 'GET') { writes++; throw new Error('Must not create a subscription session'); }
    if (path === '/client/v2/grants') return { grants: [{ id: 'grant_fixture', sourceId: 'source_fixture', models: ['gpt-fixture'], revoked: false, expiresAt: null }] };
    if (path === '/client/v2/sources') return { sources: [{ id: 'source_fixture', kind: 'subscription', clientMode: 'subscription-v1-compatibility' }] };
    throw new Error('Unexpected metadata request');
  } } as unknown as HubClient;
  const controller = new ConsumerController({ hub, launcher: { async start() { launches++; throw new Error('Must not launch Codex'); } } });
  t.after(() => controller.close());
  await assert.rejects(controller.create({ grantId: 'grant_fixture', model: 'gpt-fixture', cwd: '/fixture/local-project', codexPath: '/fixture/codex' }), disabled);
  assert.equal(writes, 0); assert.equal(launches, 0); assert.deepEqual(controller.snapshot(), []);
});
