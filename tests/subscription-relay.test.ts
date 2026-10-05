import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { getEventListeners } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { createHub } from '../apps/hub/index.js';
import { createRelay, type RelayHandle } from '../apps/relay/index.js';
import { HubClient } from '../packages/hub-client/index.js';
import { ClientStore } from '../packages/storage/client.js';
import { CodexSubscriptionAccount, SubscriptionAdapter } from '../packages/upstream/index.js';
import { policySchema, type Grant } from '../packages/protocol/index.js';
import type { ClientSession, ClientSourceResponse, RelayLeaseResponse, RunLeaseResponse } from '../packages/protocol/client.js';

// Opt in only for synthetic regression fixtures; these tests never call a real upstream.
const previousExperimentalSubscription = process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION;
process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = '1';
after(() => { if (previousExperimentalSubscription === undefined) delete process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION; else process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = previousExperimentalSubscription; });

const MODEL = 'gpt-fixture-codex';

async function eventually(check: () => boolean, description: string) {
  for (let attempt = 0; attempt < 500; attempt++) { if (check()) return; await delay(10); }
  assert.fail(description);
}

/** Real account manager, adapter, Hub and Relay; only account RPC and provider HTTP are fixtures. */
async function fixture(t: test.TestContext, response: (privateFixture: string, signal: AbortSignal) => Response) {
  const dir = await mkdtemp(join(tmpdir(), 'share-subscription-relay-'));
  let hub: Awaited<ReturnType<typeof createHub>> | undefined;
  let relay: RelayHandle | undefined;
  let account: CodexSubscriptionAccount | undefined;
  t.after(async () => {
    await relay?.close(); await hub?.close(); await account?.close();
    await rm(dir, { recursive: true, force: true });
  });
  const accountId = 'subscription-relay-fixture-account', userId = 'subscription-relay-fixture-user';
  const accessToken = `header.${Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, sub: userId })).toString('base64url')}.signature`;
  const privateFixture = `${accessToken} PRIVATE_SUBSCRIPTION_RELAY_REFRESH ${accountId}`;
  const auth = { auth_mode: 'chatgpt', OPENAI_API_KEY: null, tokens: { account_id: accountId, access_token: accessToken, refresh_token: 'PRIVATE_SUBSCRIPTION_RELAY_REFRESH', id_token: accessToken } };
  const quota = { accountId, rateLimits: { limitId: 'codex', primary: { usedPercent: 10, windowDurationMins: 300, resetsAt: Math.floor(Date.now() / 1000) + 3600 }, secondary: null } };
  const binary = join(dir, 'fixture-codex');
  await writeFile(binary, `#!${process.execPath}
const fs=require('node:fs'),path=require('node:path'),readline=require('node:readline');
const send=value=>process.stdout.write(JSON.stringify(value)+'\\n');
readline.createInterface({input:process.stdin}).on('line',line=>{const message=JSON.parse(line);
 if(message.method==='initialize'){fs.writeFileSync(path.join(process.env.CODEX_HOME,'auth.json'),JSON.stringify(${JSON.stringify(auth)}),{mode:0o600});send({id:message.id,result:{userAgent:'fixture'}});return;}
 if(message.method==='initialized')return;
 if(message.method==='account/read'){send({id:message.id,result:{account:{type:'chatgpt',planType:'plus'},requiresOpenaiAuth:true}});return;}
 if(message.method==='model/list'){send({id:message.id,result:{data:[{model:${JSON.stringify(MODEL)},hidden:false}],nextCursor:null}});return;}
 if(message.method==='account/rateLimits/read'){send({id:message.id,result:${JSON.stringify(quota)}});return;}
 send({id:message.id,error:{message:'Unexpected fixture RPC'}});
});
`, { mode: 0o700 });
  account = new CodexSubscriptionAccount({ codexHome: join(dir, 'isolated-account'), binary, timeoutMs: 3000 });
  const status = await account.inspect(); assert.equal(status.authenticated, true); assert.ok(status.accountBinding); assert.equal(status.quota.status, 'available');
  let upstreamCalls = 0;
  const adapter = new SubscriptionAdapter({ account, accountBinding: status.accountBinding, models: [MODEL], transport: async (url, init) => {
    upstreamCalls++;
    assert.equal(String(url), 'https://chatgpt.com/backend-api/codex/responses');
    assert.equal(init?.method, 'POST'); assert.equal(init?.redirect, 'error');
    assert.equal(new Headers(init?.headers).get('authorization'), `Bearer ${accessToken}`);
    const signal = init?.signal; assert.ok(signal);
    return response(privateFixture, signal);
  } });
  hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: 'subscription_relay_fixture_admin_abcdefghijklmnopqrstuvwxyz', port: 0 });
  const store = new ClientStore(hub.store), member = hub.store.createMember('Subscription relay fixture');
  const verifier = randomBytes(48).toString('base64url');
  const pairing = store.createPairing({ deviceName: 'Fixture device', platform: 'test', clientVersion: 'test', requestedScopes: ['consumer', 'donor'], codeChallenge: createHash('sha256').update(verifier).digest('base64url') }, hub.url);
  store.approvePairing(pairing.userCode, member); const device = store.redeemPairing(pairing.deviceCode, verifier);
  const client = new HubClient({ baseUrl: hub.url, credentials: { accessToken: device.accessToken, refreshToken: device.refreshToken, expiresAt: Date.now() + device.expiresIn * 1000, refreshExpiresAt: device.refreshExpiresAt, deviceId: device.device.id, memberId: member.id } });
  const policy = policySchema.parse({ allowedMemberIds: [member.id], models: [MODEL] });
  const { source } = await client.request<ClientSourceResponse>('POST', '/client/v2/sources', { name: 'Subscription HTTP fixture', kind: 'subscription', accountBinding: status.accountBinding, policy });
  await client.request('POST', `/client/v2/sources/${source.id}/policy-acks`, { revision: 1 });
  const lease = await client.request<RelayLeaseResponse>('POST', `/client/v2/sources/${source.id}/relay-leases`, {});
  const dbPath = join(dir, 'relay.sqlite');
  const relayOptions = { hubUrl: hub.url, token: lease.token, sourceId: source.id, nodeId: 'subscription-fixture-node', dbPath, policy, adapter, heartbeatMs: 100 };
  relay = await createRelay(relayOptions); await relay.waitUntilReady();
  const { grant } = await client.request<{ grant: Grant }>('POST', '/client/v2/grants', { sourceId: source.id, label: 'Fixture consumer', models: [MODEL] });
  const { session } = await client.request<{ session: ClientSession }>('POST', '/client/v2/sessions', { grantId: grant.id, modelScope: [MODEL] });
  const run = await client.request<RunLeaseResponse>('POST', `/client/v2/sessions/${session.id}/leases`, {});
  const hubInstance = hub;
  return {
    hub: hubInstance, source, client, get relay() { return relay!; }, get upstreamCalls() { return upstreamCalls; },
    infer(operationId = randomUUID()) { return fetch(`${hubInstance.url}/v1/responses`, {
      method: 'POST', signal: AbortSignal.timeout(5000), headers: { authorization: `Bearer ${run.token}`, 'content-type': 'application/json', 'x-share-operation-id': operationId },
      body: JSON.stringify({ model: MODEL, input: 'Synthetic relay integration only', instructions: 'fixture', stream: true, store: false }),
    }); },
    ack(requestId: string, operationId: string) { return client.request('POST', `/client/v2/requests/${requestId}/delivery-ack`, { operationId, outcome: 'transport_finished' }); },
    attempt(requestId: string) {
      const db = new DatabaseSync(dbPath, { readOnly: true });
      try { return db.prepare('SELECT state,error_code FROM relay_attempts WHERE request_id=?').get(requestId) as { state: string; error_code: string | null } | undefined; }
      finally { db.close(); }
    },
    assertNoPrivateBytes(text: string) { for (const secret of [accessToken, accountId, 'PRIVATE_SUBSCRIPTION_RELAY_REFRESH']) assert.equal(text.includes(secret), false); },
    async restartRelay() {
      await relay!.close();
      await eventually(() => !hubInstance.store.getSource(source.id)!.online, 'Old relay should disconnect before replacement');
      relay = await createRelay(relayOptions); await relay.waitUntilReady();
    },
  };
}

test('headerless valid subscription SSE completes through real Hub and Relay without replay', async t => {
  const completed = { type: 'response.completed', response: { id: 'resp_headerless_fixture', status: 'completed', output: [], usage: { input_tokens: 2, output_tokens: 3 } } };
  const protocolEvents = `event: response.created\ndata: {"type":"response.created","response":{"id":"resp_headerless_fixture","status":"in_progress"}}\n\nevent: response.completed\ndata: ${JSON.stringify(completed)}\n\n`;
  const raw = `: fixture heartbeat\n\n${protocolEvents}`;
  const f = await fixture(t, () => {
    const bytes = Buffer.from(raw);
    const result = new Response(new ReadableStream<Uint8Array>({ start(controller) { for (let offset = 0; offset < bytes.length; offset += 7) controller.enqueue(bytes.subarray(offset, offset + 7)); controller.close(); } }));
    assert.equal(result.headers.get('content-type'), null); return result;
  });
  const operationId = randomUUID(), response = await f.infer(operationId);
  assert.equal(response.status, 200); assert.match(response.headers.get('content-type') ?? '', /^text\/event-stream/i);
  // Only parsed protocol events pass headerless detection; comments are not model output.
  assert.equal(await response.text(), protocolEvents);
  const requestId = response.headers.get('x-share-request-id')!; assert.ok(requestId);
  await eventually(() => f.hub.store.getRequest(requestId)?.state === 'COMPLETED', 'Hub should record completed subscription SSE');
  await f.ack(requestId, operationId);
  assert.equal(f.attempt(requestId)?.state, 'COMPLETED');
  assert.equal(f.hub.store.getRequest(requestId)!.usage.outputTokens, 3);
  assert.equal(f.relay.snapshot().unknownCount, 0); assert.equal(f.upstreamCalls, 1);
  const duplicate = await f.infer(operationId);
  assert.equal(duplicate.status, 409); assert.equal((await duplicate.json() as { error: { code: string } }).error.code, 'SHARE_OPERATION_EXISTS');
  assert.equal(f.upstreamCalls, 1);
});

test('malformed successful subscription response stays durable UNKNOWN and blocks replay after Relay restart', async t => {
  const f = await fixture(t, privateFixture => new Response(Buffer.from(`<html>${privateFixture}</html>`)));
  const operationId = randomUUID(), response = await f.infer(operationId);
  assert.equal(response.status, 409);
  const text = await response.text(); f.assertNoPrivateBytes(text);
  assert.equal((JSON.parse(text) as { error: { code: string } }).error.code, 'SHARE_RESULT_UNKNOWN');
  const requestId = response.headers.get('x-share-request-id')!; assert.ok(requestId);
  await eventually(() => f.relay.snapshot().activeRequestId === null, 'Relay should finish the uncertain attempt');
  assert.equal(f.hub.store.getRequest(requestId)!.state, 'UNKNOWN');
  assert.deepEqual({ ...f.attempt(requestId) }, { state: 'UNKNOWN', error_code: 'SHARE_UPSTREAM_PROTOCOL_INVALID' });
  assert.equal(f.hub.store.getSource(f.source.id)!.frozen, true);
  assert.equal(f.relay.snapshot().unknownCount, 1); assert.deepEqual(f.relay.snapshot().freezeReasons, ['unknown']);
  for (const operation of [operationId, randomUUID()]) {
    const rejected = await f.infer(operation); assert.equal(rejected.status, 409); f.assertNoPrivateBytes(await rejected.text());
  }
  assert.equal(f.upstreamCalls, 1); assert.equal(f.hub.store.listRequests().length, 1);
  await f.restartRelay();
  assert.equal(f.relay.snapshot().unknownCount, 1); assert.deepEqual(f.relay.snapshot().freezeReasons, ['unknown']);
  assert.throws(() => f.relay.resume(), { code: 'SHARE_SOURCE_FROZEN' });
  const repeated = await f.infer(operationId); assert.equal(repeated.status, 409); await repeated.text();
  assert.equal(f.attempt(requestId)?.state, 'UNKNOWN'); assert.equal(f.hub.store.getRequest(requestId)!.state, 'UNKNOWN');
  assert.equal(f.upstreamCalls, 1); assert.equal(f.hub.store.listRequests().length, 1);
});

test('an actual upstream HTTP 429 remains a known subscription failure through Hub and Relay', async t => {
  const f = await fixture(t, privateFixture => new Response(privateFixture, { status: 429, headers: { 'retry-after': '60' } }));
  const operationId = randomUUID(), response = await f.infer(operationId);
  assert.equal(response.status, 429); assert.equal(response.headers.get('retry-after'), '60');
  const text = await response.text(); f.assertNoPrivateBytes(text);
  assert.equal((JSON.parse(text) as { error: { code: string } }).error.code, 'SHARE_UPSTREAM_RATE_LIMITED');
  const requestId = response.headers.get('x-share-request-id')!; assert.ok(requestId);
  await eventually(() => f.hub.store.getRequest(requestId)?.state === 'FAILED_KNOWN', 'HTTP rejection should remain a known failed attempt');
  await f.ack(requestId, operationId);
  assert.equal(f.attempt(requestId)?.state, 'FAILED_KNOWN'); assert.equal(f.relay.snapshot().unknownCount, 0);
  assert.equal(f.hub.store.getSource(f.source.id)!.frozen, false); assert.equal(f.upstreamCalls, 1);
  const duplicate = await f.infer(operationId); assert.equal(duplicate.status, 409); await duplicate.text();
  assert.equal(f.upstreamCalls, 1);
});

test('Relay cancels a prefetched subscription response when response.head fails before body consumption', async t => {
  let upstreamSignal: AbortSignal | undefined, upstreamBody: ReadableStream<Uint8Array> | undefined, cancellations = 0;
  const f = await fixture(t, (_privateFixture, signal) => {
    upstreamSignal = signal;
    upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        // The adapter prefetches this event and returns while the provider connection stays open.
        controller.enqueue(Buffer.from('event: response.created\ndata: {"type":"response.created","response":{"id":"resp_abandoned_fixture","status":"in_progress"}}\n\n'));
      },
      cancel() { cancellations++; },
    });
    return new Response(upstreamBody);
  });
  const send = WebSocket.prototype.send; let failedHeads = 0, responseChunks = 0;
  t.mock.method(WebSocket.prototype, 'send', function (this: WebSocket, ...args: unknown[]) {
    if (typeof args[0] === 'string') {
      const frame = JSON.parse(args[0]) as { type?: string };
      if (frame.type === 'response.head') { failedHeads++; throw new Error('Synthetic response.head send failure'); }
      if (frame.type === 'response.chunk') responseChunks++;
    }
    return Reflect.apply(send, this, args);
  });
  const response = await f.infer();
  assert.equal(response.status, 409);
  assert.equal((await response.json() as { error: { code: string } }).error.code, 'SHARE_RESULT_UNKNOWN');
  const requestId = response.headers.get('x-share-request-id')!; assert.ok(requestId);
  await eventually(() => f.relay.snapshot().activeRequestId === null, 'Abandoned request should release the Relay attempt');
  assert.equal(failedHeads, 1); assert.equal(responseChunks, 0); assert.equal(f.upstreamCalls, 1);
  assert.equal(upstreamSignal?.aborted, true, 'Exiting before for-await must abort the provider request');
  await eventually(() => cancellations === 1 && upstreamBody?.locked === false, 'Aborted prefetched reader should cancel and release its lock');
  assert.equal(getEventListeners(upstreamSignal!, 'abort').length, 0);
  assert.equal(f.attempt(requestId)?.state, 'UNKNOWN'); assert.equal(f.hub.store.getRequest(requestId)?.state, 'UNKNOWN');
});
