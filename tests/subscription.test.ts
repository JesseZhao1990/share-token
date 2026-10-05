import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { getEventListeners } from 'node:events';
import { chmod, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { CodexSubscriptionAccount, SubscriptionAdapter, ResponseObserver, type UpstreamRequest, type UpstreamResponse } from '../packages/upstream/index.js';
import { createHub } from '../apps/hub/index.js';
import { createRelay } from '../apps/relay/index.js';
import { MAX_BODY_BYTES, policySchema, ShareError, type Source, type Grant, type Member } from '../packages/protocol/index.js';

// Opt in only for synthetic regression fixtures; these tests never call a real upstream.
const previousExperimentalSubscription = process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION;
process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = '1';
after(() => { if (previousExperimentalSubscription === undefined) delete process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION; else process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = previousExperimentalSubscription; });

const id = 'fixture-account-private';
const binding = (accountId = id, userId = 'fixture-user') => `codex:${createHash('sha256').update(JSON.stringify([accountId, userId])).digest('hex')}`;
const fixtureExpiry = Math.floor(Date.now() / 1000) + 3600;
const jwt = (tag = 'access', exp = fixtureExpiry) => `header.${Buffer.from(JSON.stringify({ exp, fixture: tag, sub: 'fixture-user' })).toString('base64url')}.signature`;
const tokens = (accountId = id, accessToken = jwt()) => ({ auth_mode: 'chatgpt', OPENAI_API_KEY: null, tokens: { account_id: accountId, access_token: accessToken, refresh_token: 'PRIVATE_REFRESH_TOKEN', id_token: jwt('id') } });
const quota = { rateLimits: { limitId: 'codex', primary: { usedPercent: 12, windowDurationMins: 300, resetsAt: Math.floor(Date.now() / 1000) + 3600 }, secondary: { usedPercent: 20, windowDurationMins: 10080, resetsAt: Math.floor(Date.now() / 1000) + 36000 }, credits: { hasCredits: false, unlimited: false, balance: null } }, accountId: id };
const request = (extra: object = {}, operation: 'responses' | 'compact' = 'responses'): UpstreamRequest => ({ requestId: 'request_subscription_test', operation, model: 'gpt-fixture-codex', body: Buffer.from(JSON.stringify({ model: 'gpt-fixture-codex', stream: true, store: false, instructions: 'fixture', input: [], ...extra })) });
const completedSse = 'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_fixture","status":"completed","output":[],"usage":{"input_tokens":2,"output_tokens":3}}}\n\n';
async function collect(response: UpstreamResponse): Promise<Buffer> { const parts: Uint8Array[] = []; for await (const part of response.body) parts.push(part); return Buffer.concat(parts); }

async function fixture(t: test.TestContext, initial: Record<string, unknown> = {}, options: { timeoutMs?: number } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'share-subscription-test-'));
  const home = join(dir, 'isolated-account');
  const binary = join(dir, 'fake-codex');
  const stateFile = join(dir, 'state.json'); const logFile = join(dir, 'rpc.jsonl');
  let state: Record<string, unknown> = { auth: tokens(), quota, ...initial };
  const update = async (change: Record<string, unknown>) => { state = { ...state, ...change }; await writeFile(stateFile, JSON.stringify(state)); };
  await update({});
  await writeFile(binary, `#!${process.execPath}
const fs=require('node:fs'),path=require('node:path'),readline=require('node:readline');
const stateFile=${JSON.stringify(stateFile)},logFile=${JSON.stringify(logFile)},home=process.env.CODEX_HOME,authFile=path.join(home,'auth.json');
const state=()=>JSON.parse(fs.readFileSync(stateFile,'utf8'));
const writeAuth=a=>fs.writeFileSync(authFile,JSON.stringify(a),{mode:0o600});
const send=x=>process.stdout.write(JSON.stringify(x)+'\\n');
readline.createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line),s=state();
 fs.appendFileSync(logFile,JSON.stringify({method:m.method,params:m.params,envNames:Object.keys(process.env),home,args:process.argv.slice(2)})+'\\n');
 if(m.method==='initialize') {
  if(s.auth)writeAuth(s.auth);
  if(s.initialize==='hang')return;
  if(s.initialize==='invalid'){process.stdout.write('null\\n');return;}
  const reply=()=>send({id:m.id,result:{userAgent:'fixture'}});
  if(s.initializeDelayMs)setTimeout(reply,s.initializeDelayMs);else reply();
  return;
 }
 if(m.method==='initialized')return;
 if(s.errorMethod===m.method){send({id:m.id,error:{message:'PRIVATE_REFRESH_TOKEN '+JSON.stringify(s.auth)}});return;}
 if(m.method==='account/read') {if(m.params?.refreshToken){if(s.refreshFailure){send({id:m.id,error:{message:'PRIVATE_REFRESH_TOKEN'}});return;}if(s.refreshedAuth)writeAuth(s.refreshedAuth);}send({id:m.id,result:{account:fs.existsSync(authFile)?{type:s.accountType||'chatgpt',email:'private@example.invalid',planType:'plus'}:null,requiresOpenaiAuth:true}});return;}
 if(m.method==='model/list'){send({id:m.id,result:{data:s.models||[{model:'gpt-fixture-codex',hidden:false},{model:'hidden-model',hidden:true}],nextCursor:null}});return;}
 if(m.method==='account/rateLimits/read'){send({id:m.id,result:s.quota});return;}
 if(m.method==='account/login/start'){send({id:m.id,result:{type:'chatgpt',loginId:'login_fixture',authUrl:s.authUrl||'https://auth.openai.com/oauth/authorize?state=fixture'}});if(s.loginCompletes)setTimeout(()=>{writeAuth(s.loginAuth);send({method:'account/login/completed',params:{loginId:'login_fixture',success:true}})},20);return;}
 if(m.method==='account/login/cancel'){send({id:m.id,result:{status:'canceled'}});return;}
 if(m.method==='account/logout'){try{fs.unlinkSync(authFile)}catch{}send({id:m.id,result:{}});return;}
 send({id:m.id,error:{message:'unexpected '+m.method}});
});
`, { mode: 0o700 });
  // Functional checks need headroom for subprocess startup under concurrent CI load.
  const account = new CodexSubscriptionAccount({ codexHome: home, binary, timeoutMs: options.timeoutMs ?? 5000 });
  t.after(async () => { await account.close(); await rm(dir, { recursive: true, force: true }); });
  return { account, home, binary, dir, update, writeAuth: (auth: object) => writeFile(join(home, 'auth.json'), JSON.stringify(auth), { mode: 0o600 }), log: async () => (await readFile(logFile, 'utf8')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line) as { method: string; params?: Record<string, unknown>; envNames: string[]; home: string; args: string[] }) };
}

test('account uses an isolated official RPC client and never exposes credentials or identity', async t => {
  const previous = process.env.OPENAI_API_KEY; process.env.OPENAI_API_KEY = 'AMBIENT_API_SECRET';
  t.after(() => { if (previous === undefined) delete process.env.OPENAI_API_KEY; else process.env.OPENAI_API_KEY = previous; });
  const f = await fixture(t); const status = await f.account.inspect();
  assert.equal(status.authenticated, true); assert.equal(status.accountBinding, binding());
  assert.deepEqual(status.models, ['gpt-fixture-codex']); assert.equal(status.quota.status, 'available');
  const publicText = JSON.stringify(status);
  for (const secret of [id, 'private@example.invalid', 'PRIVATE_REFRESH_TOKEN', jwt(), 'AMBIENT_API_SECRET']) assert.equal(publicText.includes(secret), false);
  const logs = await f.log();
  assert.deepEqual(logs.map(row => row.method), ['initialize', 'initialized', 'account/read', 'model/list', 'account/rateLimits/read']);
  assert.equal(logs[0]?.home, f.home); assert.equal(logs[0]?.envNames.includes('OPENAI_API_KEY'), false);
  assert(logs[0]?.args.includes('cli_auth_credentials_store="file"'));
  assert(logs[0]?.args.includes('forced_login_method="chatgpt"'));
  assert(logs.every(row => !/thread|turn|reset|exec/.test(row.method)));
});

test('login, completion, cancellation and logout are official account operations only', async t => {
  const f = await fixture(t, { auth: null, loginCompletes: true, loginAuth: tokens() });
  assert.equal((await f.account.inspect()).authenticated, false);
  const login = await f.account.startLogin(); assert.equal(new URL(login.authUrl).hostname, 'auth.openai.com');
  await new Promise(resolve => setTimeout(resolve, 40));
  assert.equal((await f.account.inspect()).authenticated, true);
  await f.account.logout(); assert.equal((await f.account.inspect()).authenticated, false);
  await f.update({ loginCompletes: false }); await f.account.startLogin(); await f.account.cancelLogin();
  assert((await f.log()).some(row => row.method === 'account/login/cancel' && row.params?.loginId === 'login_fixture'));
  await f.account.close(); assert.equal((await f.account.inspect()).lastError?.code, 'SHARE_CODEX_CLOSED');
});

test('login rejects an unexpected authentication website', async t => {
  const f = await fixture(t, { auth: null, authUrl: 'https://attacker.invalid/steal' });
  await assert.rejects(f.account.startLogin(), { code: 'SHARE_CODEX_LOGIN_URL_INVALID' });
});

test('login still rejects an unexpected authentication website after slow RPC initialization', async t => {
  const f = await fixture(t, { auth: null, authUrl: 'https://attacker.invalid/steal', initializeDelayMs: 1250 });
  await assert.rejects(f.account.startLogin(), { code: 'SHARE_CODEX_LOGIN_URL_INVALID' });
  assert((await f.log()).some(row => row.method === 'account/login/start'));
});

test('default or nonempty unowned Codex homes and unsafe auth files are refused', async t => {
  assert.throws(() => new CodexSubscriptionAccount({ codexHome: join(homedir(), '.codex') }), { code: 'SHARE_CODEX_HOME_INVALID' });
  const f = await fixture(t); await mkdir(f.home, { mode: 0o700 }); await writeFile(join(f.home, 'unrelated'), 'keep');
  assert.equal((await f.account.inspect()).lastError?.code, 'SHARE_CODEX_HOME_NOT_OWNED');
  assert.equal(await readFile(join(f.home, 'unrelated'), 'utf8'), 'keep');
  const unsafe = await fixture(t); await unsafe.account.inspect(); await chmod(join(unsafe.home, 'auth.json'), 0o644);
  assert.equal((await unsafe.account.inspect()).lastError?.code, 'SHARE_CODEX_CREDENTIALS_UNSAFE');
  await rm(join(unsafe.home, 'auth.json')); await symlink(join(f.home, 'unrelated'), join(unsafe.home, 'auth.json'));
  assert.equal((await unsafe.account.inspect()).lastError?.code, 'SHARE_CODEX_CREDENTIALS_UNSAFE');
});

test('RPC failures and invalid framing expose only fixed sanitized errors', async t => {
  for (const initial of [{ errorMethod: 'account/rateLimits/read' }, { initialize: 'invalid' }]) {
    const f = await fixture(t, initial); const status = await f.account.inspect();
    assert.equal(status.authenticated, false); assert(status.lastError);
    assert.equal(JSON.stringify(status).includes('PRIVATE_REFRESH_TOKEN'), false);
  }
});

test('RPC initialization that never responds reports a sanitized timeout', async t => {
  const f = await fixture(t, { initialize: 'hang' }, { timeoutMs: 1000 });
  const status = await f.account.inspect();
  assert.equal(status.authenticated, false);
  assert.equal(status.lastError?.code, 'SHARE_CODEX_TIMEOUT');
  assert.equal(JSON.stringify(status).includes('PRIVATE_REFRESH_TOKEN'), false);
});

test('account change and mismatched quota account fail closed', async t => {
  const f = await fixture(t); await f.account.inspect();
  await f.writeAuth(tokens('different-account'));
  assert.equal((await f.account.inspect()).lastError?.code, 'SHARE_ACCOUNT_CHANGED');
  await f.update({ quota: { ...quota, accountId: 'different-account' } });
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => { assert.fail('must not send'); } });
  assert.equal((await adapter.inspect()).verified, false);
  assert.equal((await adapter.readQuota()).status, 'unknown');
  await assert.rejects(adapter.open(request(), new AbortController().signal), { code: 'SHARE_ACCOUNT_CHANGED' });
});

test('subscription forwards Responses and compact to a fixed origin with local auth only', async t => {
  const f = await fixture(t); await f.account.inspect();
  const observed: Array<{ url: string; init: RequestInit }> = [];
  const raw = 'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_fixture","status":"completed","output":[],"usage":{"input_tokens":2,"output_tokens":3}}}\n\n';
  const transport: typeof fetch = async (url, init) => { observed.push({ url: String(url), init: init! }); return String(url).endsWith('/compact') ? Response.json({ id: 'resp_compact', object: 'response.compaction', output: [{ type: 'compaction', encrypted_content: 'fixture' }] }) : new Response(raw, { status: 200, headers: { 'content-type': 'text/event-stream', 'set-cookie': 'private-cookie', 'chatgpt-account-id': id, 'x-request-id': 'request-safe' } }); };
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport });
  assert.equal((await adapter.inspect()).verified, true);
  const tools = [{ type: 'namespace', name: 'fixture', tools: [{ type: 'function', name: 'read_file', parameters: { type: 'object' } }] }];
  const body = request({ tools, input: [{ type: 'function_call_output', call_id: 'call_fixture', output: 'consumer result' }], include: ['reasoning.encrypted_content'] });
  const result = await adapter.open(body, new AbortController().signal);
  assert.equal((await collect(result)).toString(), raw);
  assert.equal(result.headers['set-cookie'], undefined); assert.equal(result.headers['chatgpt-account-id'], undefined);
  assert.equal(observed[0]?.url, 'https://chatgpt.com/backend-api/codex/responses');
  const headers = new Headers(observed[0]?.init.headers);
  assert.equal(headers.get('authorization'), `Bearer ${jwt()}`); assert.equal(headers.get('chatgpt-account-id'), id);
  assert.equal(observed[0]?.init.redirect, 'error'); assert.deepEqual(observed[0]?.init.body, Buffer.from(body.body));
  await collect(await adapter.open(request({ stream: undefined }, 'compact'), new AbortController().signal));
  assert.equal(observed[1]?.url, 'https://chatgpt.com/backend-api/codex/responses/compact');
  assert.equal(JSON.stringify(result.headers).includes(jwt()), false);
});

test('expired auth refreshes before dispatch and never changes the bound account', async t => {
  const f = await fixture(t, { auth: tokens(id, jwt('expired', 1)), refreshedAuth: tokens(id, jwt('refreshed')) });
  let calls = 0;
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async (_url, init) => { calls++; assert.equal(new Headers(init?.headers).get('authorization'), `Bearer ${jwt('refreshed')}`); return new Response(completedSse, { headers: { 'content-type': 'text/event-stream' } }); } });
  await collect(await adapter.open(request(), new AbortController().signal));
  assert.equal(calls, 1); assert.equal((await f.log()).filter(row => row.method === 'account/read' && row.params?.refreshToken === true).length, 1);
  const changed = await fixture(t, { auth: tokens(id, jwt('expired', 1)), refreshedAuth: tokens('another-account', jwt('refreshed')) });
  const changedAdapter = new SubscriptionAdapter({ account: changed.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => { assert.fail('must not dispatch after account switch'); } });
  await assert.rejects(changedAdapter.open(request(), new AbortController().signal), { code: 'SHARE_ACCOUNT_CHANGED' });
});

test('401 is redacted and refreshes for later requests without replaying the rejected POST', async t => {
  const f = await fixture(t, { refreshedAuth: tokens(id, jwt('refreshed')) }); let calls = 0;
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async (_url, init) => {
    calls++;
    if (calls === 1) return new Response(JSON.stringify({ error: `${jwt()} PRIVATE_REFRESH_TOKEN ${id}` }), { status: 401, headers: { 'x-request-id': jwt(), 'retry-after': '7' } });
    assert.equal(new Headers(init?.headers).get('authorization'), `Bearer ${jwt('refreshed')}`); return new Response(completedSse, { headers: { 'content-type': 'text/event-stream' } });
  } });
  const response = await adapter.open(request(), new AbortController().signal);
  assert.equal(response.status, 401); assert.equal(calls, 1); assert.equal(response.headers['retry-after'], '7');
  const exposed = JSON.stringify(response.headers) + (await collect(response)).toString();
  for (const secret of [jwt(), 'PRIVATE_REFRESH_TOKEN', id]) assert.equal(exposed.includes(secret), false);
  await collect(await adapter.open(request(), new AbortController().signal)); assert.equal(calls, 2);
});

test('429 has no refresh, replay, paid fallback or account switch and remains a known failure', async t => {
  const f = await fixture(t); let calls = 0;
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => { calls++; return new Response('PRIVATE_REFRESH_TOKEN', { status: 429, headers: { 'retry-after': '60' } }); } });
  const response = await adapter.open(request(), new AbortController().signal); const body = await collect(response);
  assert.equal(response.status, 429); assert.equal(response.headers['retry-after'], '60'); assert.equal(calls, 1);
  const observer = new ResponseObserver(false); observer.feed(body); assert.equal(observer.finish(response.status), 'FAILED_KNOWN');
  assert.equal((await f.log()).filter(row => row.params?.refreshToken === true).length, 0);
});

test('cancel reaches fetch and cancels its stream; network errors do not retry', async t => {
  const f = await fixture(t); let calls = 0; let canceled = false;
  const controller = new AbortController();
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async (_url, init) => {
    calls++; assert.equal(init?.signal, controller.signal);
    return new Response(new ReadableStream({ start(c) { c.enqueue(Buffer.from('data: fixture\n\n')); }, cancel() { canceled = true; } }), { headers: { 'content-type': 'text/event-stream' } });
  } });
  const response = await adapter.open(request(), controller.signal); const iterator = response.body[Symbol.asyncIterator]();
  await iterator.next(); controller.abort(); await assert.rejects(iterator.next()); assert.equal(canceled, true); assert.equal(calls, 1);
  const failing = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => { calls++; throw new Error('network gone'); } });
  await assert.rejects(failing.open(request(), new AbortController().signal), /network gone/); assert.equal(calls, 2);
  const alreadyAborted = new AbortController(); alreadyAborted.abort(); await assert.rejects(failing.open(request(), alreadyAborted.signal)); assert.equal(calls, 2);
});

test('unsupported nonstream, stored/background requests fail before transport', async t => {
  const f = await fixture(t);
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => { assert.fail('unsupported request must not send'); } });
  for (const body of [{ stream: false }, { store: true }, { background: true }, { model: 'not-bound' }]) {
    const response = await adapter.open(request(body), new AbortController().signal); assert.equal(response.status, 400);
  }
});

test('different users in the same workspace have different fixed bindings', async t => {
  const f = await fixture(t); await f.account.inspect();
  const auth = tokens();
  auth.tokens.id_token = `header.${Buffer.from(JSON.stringify({ sub: 'another-user' })).toString('base64url')}.signature`;
  await f.writeAuth(auth);
  assert.equal((await f.account.inspect()).accountBinding, binding(id, 'another-user'));
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => { assert.fail('must not use another user quota'); } });
  assert.equal((await adapter.inspect()).verified, false);
  await assert.rejects(adapter.open(request(), new AbortController().signal), { code: 'SHARE_ACCOUNT_CHANGED' });
});

test('SSE failures are redacted across chunk boundaries while ordinary events stay identical', async t => {
  const f = await fixture(t);
  const regular = 'event: response.created\r\ndata: {"type":"response.created","response":{"id":"resp_ok","status":"in_progress"}}\r\n\r\n';
  const failure = `event: response.failed\ndata: ${JSON.stringify({ type: 'response.failed', response: { id: jwt(), status: 'failed', error: { message: `${jwt()} PRIVATE_REFRESH_TOKEN private@example.invalid` } } })}\n\n`;
  const bytes = Buffer.from(regular + failure);
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => new Response(new ReadableStream({ start(controller) { for (let i = 0; i < bytes.length; i += 3) controller.enqueue(bytes.subarray(i, i + 3)); controller.close(); } }), { headers: { 'content-type': 'text/event-stream' } }) });
  const result = await collect(await adapter.open(request(), new AbortController().signal));
  assert.equal(result.toString().startsWith(regular), true);
  for (const secret of [jwt(), 'PRIVATE_REFRESH_TOKEN', 'private@example.invalid']) assert.equal(result.includes(Buffer.from(secret)), false);
  const observer = new ResponseObserver(true); observer.feed(result); assert.equal(observer.finish(200), 'FAILED_KNOWN');
});

test('failed refresh blocks the rejected credential and a later login can recover without restarting adapter', async t => {
  const f = await fixture(t, { refreshFailure: true }); let calls = 0;
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => { calls++; return new Response('secret', { status: 401 }); } });
  await collect(await adapter.open(request(), new AbortController().signal));
  await assert.rejects(adapter.inspect(), { code: 'SHARE_UPSTREAM_AUTH_REQUIRED' }); assert.equal((await adapter.readQuota()).status, 'unknown');
  await collect(await adapter.open(request(), new AbortController().signal)); assert.equal(calls, 1);
  await f.writeAuth(tokens(id, jwt('new-login')));
  assert.equal((await adapter.inspect()).verified, true); assert.equal((await adapter.readQuota()).status, 'available');
});

test('temporary account RPC errors reject admission without reporting an account replacement', async t => {
  const f = await fixture(t);
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'] });
  assert.equal((await adapter.inspect()).verified, true);
  await f.update({ errorMethod: 'model/list' }); await assert.rejects(adapter.inspect(), { code: 'SHARE_CODEX_RPC_FAILED' });
  await f.update({ errorMethod: null }); assert.equal((await adapter.inspect()).verified, true);
  await f.account.logout(); await assert.rejects(adapter.inspect(), { code: 'SHARE_UPSTREAM_AUTH_REQUIRED' });
});

test('unexpected successful HTTP formats and compact errors never expose diagnostic bytes', async t => {
  const f = await fixture(t); const secret = jwt();
  for (const [operation, response] of [
    ['responses', new Response(`<html>${secret}</html>`, { headers: { 'content-type': 'text/html' } })],
    ['responses', Response.json({ error: { message: secret } })],
    ['compact', Response.json({ error: { message: secret } })],
    ['compact', Response.json({ id: 'resp_compact', object: 'response.compaction', output: [{ type: 'compaction', encrypted_content: secret }] })],
    ['compact', Response.json({ id: 'resp_compact', object: 'response.compaction', output: [] })],
  ] as const) {
    const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => response });
    await assert.rejects(adapter.open(request({}, operation), new AbortController().signal), error => {
      assert.ok(error instanceof ShareError); assert.equal(error.code, 'SHARE_UPSTREAM_PROTOCOL_INVALID'); assert.equal(error.message.includes(secret), false); return true;
    });
  }
  for (const raw of [`: ${secret}\n\n`, `: ${secret}\ndata: [DONE]\n\n`]) {
    const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => new Response(raw, { headers: { 'content-type': 'text/event-stream' } }) });
    await assert.rejects(collect(await adapter.open(request(), new AbortController().signal)), { code: 'SHARE_UPSTREAM_PROTOCOL_INVALID' });
  }
});

test('headerless Responses validates a complete cross-chunk JSON event before exposing a bounded live SSE stream', async t => {
  const f = await fixture(t);
  const created = 'event: response.created\r\ndata: {"type":"response.created","response":{"id":"resp_fixture","status":"in_progress"}}\r\n\r\n';
  const delta = 'event: response.output_text.delta\ndata: {"type":"response.output_text.delta","delta":"你好"}\n\n';
  let stream!: ReadableStreamDefaultController<Uint8Array>, calls = 0;
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => {
    calls++; return new Response(new ReadableStream<Uint8Array>({ start(controller) {
      stream = controller; const bytes = Buffer.from(created); for (let i = 0; i < bytes.length; i += 3) controller.enqueue(bytes.subarray(i, i + 3));
    } }));
  } });
  const opened = await adapter.open(request(), new AbortController().signal);
  assert.equal(opened.status, 200); assert.equal(opened.headers['content-type'], 'text/event-stream');
  const iterator = opened.body[Symbol.asyncIterator](), first = await iterator.next(); assert.equal(first.done, false); assert.match(Buffer.from(first.value!).toString(), /response.created/);
  // The upstream remains open: obtaining the first event must not wait for completion or buffer all output.
  const tail = Buffer.from(delta + completedSse); for (let i = 0; i < tail.length; i += 2) stream.enqueue(tail.subarray(i, i + 2)); stream.close();
  const pieces: Uint8Array[] = [first.value!]; for (;;) { const next = await iterator.next(); if (next.done) break; pieces.push(next.value); }
  const bytes = Buffer.concat(pieces), observer = new ResponseObserver(true); observer.feed(bytes);
  assert.equal(observer.finish(200), 'COMPLETED'); assert.equal(bytes.toString().includes('你好'), true); assert.equal(calls, 1);
  const emptyHeader = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => new Response(Buffer.from(completedSse), { headers: { 'content-type': '   ' } }) });
  assert.equal((await collect(await emptyHeader.open(request(), new AbortController().signal))).toString(), completedSse);
});

test('headerless HTML, bare error JSON, empty and truncated events fail closed without exposing content or retrying', async t => {
  const f = await fixture(t), secret = jwt(); let calls = 0;
  for (const raw of [`<html>${secret} PRIVATE_REFRESH_TOKEN</html>\n\n`, JSON.stringify({ error: { message: secret + ' PRIVATE_REFRESH_TOKEN' } }), '', 'data: [DONE]\n\n', `event: error\ndata: {"type":"error","message":"${secret}`, 'event: response.created\ndata: {"type":"response.created"}\n\n', 'data: {"type":"response.future_extension.delta","delta":{"value":1}}\n\n', `event: response.created\ndata: {"type":"not_a_response","message":"${secret}"}\n\n`]) {
    const before = calls;
    const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => { calls++; return new Response(Buffer.from(raw)); } });
    await assert.rejects(adapter.open(request(), new AbortController().signal), error => {
      assert.ok(error instanceof ShareError); assert.equal(error.code, 'SHARE_UPSTREAM_PROTOCOL_INVALID'); assert.equal(error.message.includes(secret), false); assert.equal(error.message.includes('PRIVATE_REFRESH_TOKEN'), false); return true;
    });
    assert.equal(calls, before + 1);
  }
  const truncated = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => new Response(Buffer.from('data: {"type":"response.created","response":{"id":"resp_fixture"}}\n\ndata: {"type":"response.output_text.delta","delta":"PRIVATE_REFRESH_TOKEN')) });
  const response = await truncated.open(request(), new AbortController().signal); let exposed = '';
  await assert.rejects(async () => { for await (const piece of response.body) exposed += Buffer.from(piece).toString(); }, { code: 'SHARE_UPSTREAM_PROTOCOL_INVALID' });
  assert.equal(exposed.includes('PRIVATE_REFRESH_TOKEN'), false);
});

test('headerless Responses preserves annotation and future event fields after a verified lifecycle event', async t => {
  const f = await fixture(t);
  const events = [
    { type: 'response.created', response: { id: 'resp_fixture', status: 'in_progress' } },
    { type: 'response.output_text.annotation.added', annotation: { type: 'url_citation', url: 'https://example.invalid/reference', title: 'fixture' }, extension: { value: ['retained'] } },
    { type: 'response.future_extension.delta', delta: { field: 'future structured delta' }, new_field: true },
    { type: 'response.completed', response: { id: 'resp_fixture', status: 'completed', output: [] } },
  ];
  const raw = events.map(event => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join('');
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => new Response(Buffer.from(raw)) });
  const result = await collect(await adapter.open(request(), new AbortController().signal));
  assert.equal(result.toString(), raw);
});

test('headerless detection redacts failure events and aborts/cancels pending and oversized probes', async t => {
  const f = await fixture(t);
  const failed = `event: response.failed\ndata: ${JSON.stringify({ type: 'response.failed', response: { id: 'resp_fixture', error: { message: jwt() + ' PRIVATE_REFRESH_TOKEN' } } })}\n\n`;
  const failureAdapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => new Response(Buffer.from(failed)) });
  const failedBytes = await collect(await failureAdapter.open(request(), new AbortController().signal));
  assert.equal(failedBytes.includes(Buffer.from(jwt())), false); assert.equal(failedBytes.includes(Buffer.from('PRIVATE_REFRESH_TOKEN')), false);
  let canceled = false, started!: () => void; const ready = new Promise<void>(resolveReady => { started = resolveReady; }); const controller = new AbortController();
  const pending = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => new Response(new ReadableStream({ start() { started(); }, cancel() { canceled = true; } })) });
  const opening = pending.open(request(), controller.signal), rejected = assert.rejects(opening); await ready; controller.abort(); await rejected; assert.equal(canceled, true);
  let oversizedCanceled = false;
  const oversized = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => new Response(new ReadableStream({ start(stream) { stream.enqueue(Buffer.alloc(MAX_BODY_BYTES + 1, 65)); }, cancel() { oversizedCanceled = true; } })) });
  await assert.rejects(oversized.open(request(), new AbortController().signal), { code: 'SHARE_UPSTREAM_PROTOCOL_INVALID' }); assert.equal(oversizedCanceled, true);
});

test('an opened headerless stream releases its reader and listeners when returned or aborted before consumption', async t => {
  const f = await fixture(t);
  for (const action of ['return', 'abort'] as const) {
    const controller = new AbortController(); let canceled = false;
    const upstream = new ReadableStream<Uint8Array>({
      start(stream) { stream.enqueue(Buffer.from('data: {"type":"response.created","response":{"id":"resp_fixture"}}\n\n')); },
      cancel() { canceled = true; },
    });
    const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => new Response(upstream) });
    const opened = await adapter.open(request(), controller.signal);
    assert.equal(upstream.locked, true);
    const iterator = opened.body[Symbol.asyncIterator]();
    if (action === 'return') await iterator.return!();
    else {
      controller.abort();
      // Abort also closes the eagerly started generator even when the caller never reads it.
      for (let attempt = 0; upstream.locked && attempt < 20; attempt++) await new Promise<void>(resolve => setImmediate(resolve));
      await assert.rejects(iterator.next());
    }
    assert.equal(canceled, true); assert.equal(upstream.locked, false);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  }
});

test('headerless compact accepts only the existing strict compaction schema and parser errors throw rather than synthesize rejection', async t => {
  const f = await fixture(t);
  const raw = JSON.stringify({ id: 'resp_compact', object: 'response.compaction', output: [{ type: 'compaction', encrypted_content: 'opaque-fixture' }] });
  const valid = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => new Response(Buffer.from(raw)) });
  const result = await valid.open(request({}, 'compact'), new AbortController().signal); assert.equal(result.headers['content-type'], 'application/json'); assert.equal((await collect(result)).toString(), raw);
  for (const raw of ['', '<html>PRIVATE_REFRESH_TOKEN</html>', '{"error":{"message":"PRIVATE_REFRESH_TOKEN"}}', '{"object":"response.compaction","id":"resp_compact","output":[]}', '{"object":"response.compaction"']) {
    const invalid = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: ['gpt-fixture-codex'], transport: async () => new Response(Buffer.from(raw)) });
    await assert.rejects(invalid.open(request({}, 'compact'), new AbortController().signal), { code: 'SHARE_UPSTREAM_PROTOCOL_INVALID' });
  }
});

test('a successful upstream compact with invalid format records UNKNOWN in a real Hub/Relay and cannot replay', async t => {
  const f = await fixture(t), admin = 'subscription_protocol_admin_abcdefghijklmnopqrstuvwxyz'; let calls = 0;
  const hub = await createHub({ dbPath: join(f.dir, 'hub.sqlite'), adminToken: admin, port: 0 }); let relay: Awaited<ReturnType<typeof createRelay>> | undefined;
  t.after(async () => { await relay?.close(); await hub.close(); });
  async function api<T>(path: string, body?: unknown): Promise<T> {
    const response = await fetch(hub.url + path, { method: body ? 'POST' : 'GET', headers: { authorization: `Bearer ${admin}`, 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
    assert.equal(response.ok, true); return response.json() as Promise<T>;
  }
  const { member } = await api<{ member: Member }>('/control/session'); const policy = policySchema.parse({ allowedMemberIds: [member.id], models: ['gpt-fixture-codex'] });
  const { source, relayToken } = await api<{ source: Source; relayToken: string }>('/control/sources', { name: 'Subscription protocol fixture', kind: 'subscription', accountBinding: binding(), policy });
  const { token } = await api<{ grant: Grant; token: string }>('/control/grants', { sourceId: source.id, label: 'fixture', models: policy.models });
  const adapter = new SubscriptionAdapter({ account: f.account, accountBinding: binding(), models: policy.models, transport: async () => { calls++; return Response.json({ error: { message: 'PRIVATE_REFRESH_TOKEN' } }); } });
  relay = await createRelay({ hubUrl: hub.url, token: relayToken, sourceId: source.id, nodeId: 'subscription-fixture', dbPath: join(f.dir, 'relay.sqlite'), policy, adapter }); await relay.waitUntilReady();
  const infer = () => fetch(hub.url + '/v1/responses/compact', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: Buffer.from(request({}, 'compact').body) });
  const result = await infer(); const body = await result.text(); assert.equal(result.status, 409); assert.equal(body.includes('PRIVATE_REFRESH_TOKEN'), false);
  assert.equal(hub.store.listRequests()[0]!.state, 'UNKNOWN'); assert.equal(hub.store.listRequests()[0]!.errorCode, 'SHARE_RESULT_UNKNOWN'); assert.equal(calls, 1);
  const again = await infer(); await again.text(); assert.equal(again.status, 409); assert.equal(calls, 1);
});
