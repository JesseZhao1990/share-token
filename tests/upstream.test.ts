import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MockAdapter, HttpAdapter, ResponseObserver, normalizeCodexQuota, CodexQuotaReader, type UpstreamResponse } from '../packages/upstream/index.js';

async function collect(response: UpstreamResponse): Promise<Buffer> { const chunks: Uint8Array[] = []; for await (const chunk of response.body) chunks.push(chunk); return Buffer.concat(chunks); }
const request = (body: object, operation: 'responses' | 'compact' = 'responses') => ({ requestId: 'request_1', operation, model: 'mock-codex', body: Buffer.from(JSON.stringify({ model: 'mock-codex', ...body })) });
const signal = () => new AbortController().signal;

test('mock is explicit synthetic data and only an opted-in function tool is returned', async () => {
  const tools = [{ type: 'function', name: 'read_fixture', parameters: { type: 'object', properties: {} } }];
  const safeDefault = new MockAdapter();
  const defaultResult = JSON.parse((await collect(await safeDefault.open(request({ tools, stream: false }), signal()))).toString());
  assert.equal(defaultResult.output[0].type, 'message');
  assert.equal(defaultResult.metadata.share_adapter, 'mock');
  const adapter = new MockAdapter({ toolName: 'read_fixture' });
  const first = await adapter.open(request({ tools, stream: true }), signal());
  const bytes = await collect(first);
  const observer = new ResponseObserver(true);
  for (const byte of bytes) observer.feed(Uint8Array.of(byte));
  assert.equal(observer.finish(200), 'COMPLETED');
  assert.equal(observer.completedItemIds.size, 1);
  assert.equal(observer.usage.inputTokens, 12);
  assert.match(bytes.toString(), /function_call_arguments.done/);
  const next = await adapter.open(request({ tools, input: [{ type: 'function_call_output', call_id: 'call_fixture', output: 'fixture content' }] }), signal());
  const nextJson = JSON.parse((await collect(next)).toString());
  assert.match(nextJson.output[0].content[0].text, /consumer-side tool result/);
  assert.equal(adapter.calls, 2);
});

test('SSE observes UTF-8 split chunks, usage and response references without changing data', async () => {
  const bytes = await collect(await new MockAdapter().open(request({ stream: true }), signal()));
  const observer = new ResponseObserver(true);
  for (let i = 0; i < bytes.length; i += 3) observer.feed(bytes.subarray(i, i + 3));
  assert.equal(observer.finish(200), 'COMPLETED');
  assert.equal(observer.usage.outputTokens, 8);
  assert.equal(observer.responseIds.size, 2);
  assert.match(bytes.toString(), /这是合成输出/);
});

test('EOF, DONE-only and invalid completion never count as completed', async () => {
  for (const bytes of [Buffer.from('data: [DONE]\n\n'), Buffer.from('data: {"type":"response.completed"}\n\n'), await collect(await new MockAdapter({ mode: 'truncate' }).open(request({ stream: true }), signal()))]) {
    const observer = new ResponseObserver(true); observer.feed(bytes); assert.equal(observer.finish(200), 'UNKNOWN');
  }
  const invalidUtf8 = new ResponseObserver(true); invalidUtf8.feed(Uint8Array.of(0xff)); assert.equal(invalidUtf8.finish(200), 'UNKNOWN');
  const failed = new ResponseObserver(false); failed.feed(Buffer.from('not json')); assert.equal(failed.finish(429), 'FAILED_KNOWN');
});

test('nonstream response and explicit compaction fixture have observable terminals', async () => {
  for (const operation of ['responses', 'compact'] as const) {
    const output = await new MockAdapter().open(request({ stream: false }, operation), signal());
    const observer = new ResponseObserver(false, operation); observer.feed(await collect(output));
    assert.equal(observer.finish(output.status), 'COMPLETED'); assert.equal(observer.usage.cachedTokens, 0);
  }
});

test('API fixture uses fixed paths, local credential, identity encoding and refuses redirect', async t => {
  const received: { path: string; auth: string | undefined; encoding: string | undefined; body: string }[] = [];
  const server = createServer(async (req, res) => {
    let body = ''; for await (const bytes of req) body += bytes;
    received.push({ path: req.url!, auth: req.headers.authorization, encoding: req.headers['accept-encoding'], body });
    if (req.url?.startsWith('/redirect/')) { res.writeHead(302, { location: '/redirected' }); res.end(); return; }
    res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'secret=never-forward' });
    res.end(JSON.stringify({ id: 'resp_api_fixture', status: 'completed', output: [], usage: { input_tokens: 1, output_tokens: 2 } }));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); delete process.env.SHARE_TEST_FIXTURE_KEY; });
  const address = server.address(); assert(address && typeof address !== 'string');
  process.env.SHARE_TEST_FIXTURE_KEY = 'local-fixture-secret';
  const baseUrl = `http://127.0.0.1:${address.port}/v1`;
  const adapter = new HttpAdapter({ baseUrl, apiKeyEnv: 'SHARE_TEST_FIXTURE_KEY', accountBinding: 'fixture:account', models: ['mock-codex'] });
  const output = await adapter.open(request({ input: 'fixture' }), signal());
  await collect(output);
  assert.equal(output.headers['set-cookie'], undefined);
  assert.deepEqual(received[0], { path: '/v1/responses', auth: 'Bearer local-fixture-secret', encoding: 'identity', body: Buffer.from(request({ input: 'fixture' }).body).toString() });
  const redirect = new HttpAdapter({ baseUrl: `http://127.0.0.1:${address.port}/redirect`, apiKeyEnv: 'SHARE_TEST_FIXTURE_KEY', accountBinding: 'fixture:account', models: ['mock-codex'] });
  await assert.rejects(redirect.open(request({}), signal()));
  assert(!received.some(item => item.path === '/redirected'));
  process.env.SHARE_TEST_FIXTURE_KEY = 'changed-secret';
  assert.equal((await adapter.inspect()).verified, false);
});

const bucket = (usedPercent = 10) => ({ limitId: 'codex', primary: { usedPercent, windowDurationMins: 300, resetsAt: 2_000_000_000 }, secondary: { usedPercent: 20, windowDurationMins: 10080, resetsAt: 2_000_100_000 } });
test('quota prefers buckets and fails closed for unknown shape, null fields, extra credits', () => {
  const result = normalizeCodexQuota({ rateLimits: bucket(95), rateLimitsByLimitId: { codex: bucket(12) }, accountId: 'not-uploaded' }, 1000);
  assert.equal(result.status, 'available'); assert.equal(result.windows[0]?.usedPercent, 12); assert.equal(result.fetchedAt, 1000);
  assert.equal(JSON.stringify(result).includes('not-uploaded'), false);
  for (const value of [
    { rateLimits: { ...bucket(), newUninterpretedWindow: { remaining: 100 } } },
    { rateLimits: { ...bucket(), primary: { ...bucket().primary, windowDurationMins: null } } },
    { rateLimits: { ...bucket(), primary: null, secondary: null } },
    { rateLimits: bucket(), rateLimitsByLimitId: {} },
    { rateLimits: { ...bucket(), credits: { hasCredits: true, unlimited: false, balance: '10' } } },
    { rateLimits: { ...bucket(), individualLimit: { remainingPercent: 50 } } },
  ]) assert.equal(normalizeCodexQuota(value).status, 'unknown');
});

test('quota subprocess sends only initialize, initialized and rateLimits/read', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'share-quota-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const binary = join(dir, 'fake-codex'); const log = join(dir, 'methods.log');
  await writeFile(binary, `#!${process.execPath}\nconst fs = require('node:fs');const readline=require('node:readline');readline.createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);fs.appendFileSync(${JSON.stringify(log)},m.method+'\\n');if(m.method==='initialize')process.stdout.write(JSON.stringify({id:m.id,result:{userAgent:'fixture'}})+'\\n');if(m.method==='account/rateLimits/read')process.stdout.write(JSON.stringify({id:m.id,result:${JSON.stringify({ rateLimits: bucket() })}})+'\\n');});\n`, { mode: 0o700 });
  const result = await new CodexQuotaReader({ binary, timeoutMs: 3000 }).read();
  assert.equal(result.status, 'available');
  assert.deepEqual((await readFile(log, 'utf8')).trim().split('\n'), ['initialize', 'initialized', 'account/rateLimits/read']);
});


test('quota reader fails closed on a structurally invalid RPC frame', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'share-quota-invalid-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const binary = join(dir, 'fake-codex');
  await writeFile(binary, `#!${process.execPath}\nprocess.stdin.once('data',()=>process.stdout.write('null\\n'));setTimeout(()=>{},5000);\n`, { mode: 0o700 });
  assert.equal((await new CodexQuotaReader({ binary, timeoutMs: 1000 }).read()).status, 'unknown');
});


test('API fixture withholds upstream errors that echo the contributor credential', async t => {
  const secret = 'fixture-secret-never-forward'; process.env.SHARE_REJECTION_FIXTURE_KEY = secret;
  const server = createServer((req, res) => { res.writeHead(401, { 'content-type': 'application/json', 'x-request-id': secret, 'retry-after': '15' }); res.end(JSON.stringify({ error: { message: `Invalid key ${req.headers.authorization}` } })); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); delete process.env.SHARE_REJECTION_FIXTURE_KEY; });
  const address = server.address(); assert(address && typeof address !== 'string');
  const adapter = new HttpAdapter({ baseUrl: `http://127.0.0.1:${address.port}/v1`, apiKeyEnv: 'SHARE_REJECTION_FIXTURE_KEY', accountBinding: 'fixture:safe-error', models: ['mock-codex'] });
  const response = await adapter.open(request({}), signal()); const bytes = await collect(response);
  assert.equal(response.status, 401); assert.equal(response.headers['retry-after'], '15');
  assert.equal(JSON.stringify(response.headers).includes(secret), false); assert.equal(bytes.toString().includes(secret), false);
  assert.equal(JSON.parse(bytes.toString()).error.code, 'SHARE_UPSTREAM_REJECTED');
});
