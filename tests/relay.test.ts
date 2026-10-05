import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { WebSocketServer, WebSocket } from 'ws';
import { createRelay, resolveRelayUnknown } from '../apps/relay/index.js';
import { MockAdapter, type UpstreamAdapter } from '../packages/upstream/index.js';
import { MAX_BUFFER_BYTES, CHUNK_BYTES, ShareError, policySchema, type RelayFrame, type HubFrame } from '../packages/protocol/index.js';

async function harness(adapter: UpstreamAdapter, { credit = true, allow = true, initialPaused }: { credit?: boolean; allow?: boolean; initialPaused?: boolean } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'share-relay-test-'));
  const server = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  await new Promise<void>(resolve => server.once('listening', resolve));
  const address = server.address(); assert(typeof address === 'object' && address);
  let peer: WebSocket | null = null;
  let epoch = 0;
  const frames: RelayFrame[] = [];
  const send = (frame: HubFrame) => { assert(peer); peer.send(JSON.stringify(frame)); };
  server.on('connection', (ws, req) => {
    assert.equal(req.url, '/relay/v1'); assert.equal(req.headers.authorization, 'Bearer relay-test-key');
    peer = ws; epoch++;
    ws.on('message', data => {
      const frame = JSON.parse(data.toString()) as RelayFrame; frames.push(frame);
      if (frame.type === 'hello') send({ v: 1, type: 'welcome', sourceId: 'source_1', fence: epoch });
      if (credit && frame.type === 'request.accepted') send({ v: 1, type: 'window.update', requestId: frame.requestId, fence: epoch, bytes: MAX_BUFFER_BYTES });
      if (credit && frame.type === 'response.chunk') send({ v: 1, type: 'window.update', requestId: frame.requestId, fence: epoch, bytes: Buffer.from(frame.data, 'base64').length });
    });
  });
  const opts = { hubUrl: `http://127.0.0.1:${address.port}`, token: 'relay-test-key', sourceId: 'source_1', nodeId: 'node_1', dbPath: join(dir, 'relay.sqlite'), policy: policySchema.parse({ models: ['mock-codex'], allowedMemberIds: allow ? ['member_1'] : [] }), adapter, heartbeatMs: 100, initialPaused };
  let relay = await createRelay(opts); await relay.waitUntilReady();
  const open = (requestId = 'request_1', overrides: object = {}) => send({ v: 1, type: 'request.open', requestId, fence: epoch, sourceId: 'source_1', grantId: 'grant_1', memberId: 'member_1', model: 'mock-codex', operation: 'responses', body: Buffer.from(JSON.stringify({ model: 'mock-codex', input: 'synthetic fixture', stream: true, ...overrides })).toString('base64'), deadline: Date.now() + 10_000 });
  const until = async <T extends RelayFrame['type']>(type: T, predicate: (frame: Extract<RelayFrame, { type: T }>) => boolean = () => true): Promise<Extract<RelayFrame, { type: T }>> => {
    for (let i = 0; i < 400; i++) {
      const result = frames.find(frame => frame.type === type && predicate(frame as Extract<RelayFrame, { type: T }>));
      if (result) return result as Extract<RelayFrame, { type: T }>;
      await delay(10);
    }
    throw new Error(`Timeout waiting for ${type}: ${frames.map(f => f.type).join(',')}`);
  };
  return {
    frames, open, send, until, dbPath: opts.dbPath, get fence() { return epoch; }, get relay() { return relay; }, disconnect: () => peer?.terminate(),
    restart: async () => { await relay.close(); relay = await createRelay(opts); await relay.waitUntilReady(); },
    close: async () => { await relay.close(); for (const client of server.clients) client.terminate(); await new Promise<void>(resolve => server.close(() => resolve())); await rm(dir, { recursive: true, force: true }); },
  };
}

test('relay forwards the complete stream, records usage and never replays a durable id after restart', async t => {
  const adapter = new MockAdapter(); const h = await harness(adapter); t.after(() => h.close());
  h.open(); const end = await h.until('response.end');
  assert.equal(end.state, 'COMPLETED'); assert.equal(end.usage.inputTokens, 12); assert.equal(adapter.calls, 1);
  const chunks = h.frames.filter(f => f.type === 'response.chunk');
  assert(chunks.length > 1); assert(chunks.every(f => Buffer.from(f.data, 'base64').length <= CHUNK_BYTES));
  const output = Buffer.concat(chunks.map(f => Buffer.from(f.data, 'base64'))).toString();
  assert.match(output, /response.completed/); assert.match(output, /这是合成输出/);
  const originalChunkCount = chunks.length;
  await h.restart(); h.open();
  const status = await h.until('status.result');
  assert.equal(status.state, 'COMPLETED'); assert.equal(adapter.calls, 1);
  assert.equal(h.frames.filter(f => f.type === 'response.chunk').length, originalChunkCount);
});

test('relay enforces local member policy and never starts rejected inference', async t => {
  const adapter = new MockAdapter(); const h = await harness(adapter, { allow: false }); t.after(() => h.close());
  h.open(); const end = await h.until('response.end');
  assert.equal(end.state, 'CANCELLED_NOT_SENT'); assert.equal(end.errorCode, 'SHARE_MEMBER_NOT_ALLOWED'); assert.equal(adapter.calls, 0);
});

test('relay checks account binding before each request and freezes on a changed identity', async t => {
  const adapter = new MockAdapter({ accountBinding: 'mock:first' }); const h = await harness(adapter); t.after(() => h.close());
  adapter.options.accountBinding = 'mock:second'; h.open();
  const end = await h.until('response.end'); assert.equal(end.errorCode, 'SHARE_ACCOUNT_CHANGED'); assert.equal(adapter.calls, 0);
  await h.until('heartbeat', frame => frame.paused);
});

test('temporary account inspection failures cancel before sending and recover without an identity freeze or replay', async t => {
  const base = new MockAdapter();
  let unavailable = false;
  const adapter: UpstreamAdapter = {
    inspect: async () => {
      if (unavailable) throw new ShareError('SHARE_CODEX_UNAVAILABLE', 'Account service temporarily unavailable', 503);
      return base.inspect();
    },
    readQuota: () => base.readQuota(),
    open: (request, signal) => base.open(request, signal),
  };
  const h = await harness(adapter); t.after(() => h.close());
  unavailable = true; h.open('temporary_failure');
  const rejected = await h.until('response.end', frame => frame.requestId === 'temporary_failure');
  assert.equal(rejected.state, 'CANCELLED_NOT_SENT'); assert.equal(rejected.errorCode, 'SHARE_CODEX_UNAVAILABLE');
  assert.equal(base.calls, 0); assert.deepEqual(h.relay.snapshot().freezeReasons, []);
  unavailable = false; await h.restart(); h.open('temporary_failure');
  assert.equal((await h.until('status.result', frame => frame.requestId === 'temporary_failure')).state, 'CANCELLED_NOT_SENT');
  assert.equal(base.calls, 0); h.open('after_recovery');
  assert.equal((await h.until('response.end', frame => frame.requestId === 'after_recovery')).state, 'COMPLETED');
  assert.equal(base.calls, 1); assert.deepEqual(h.relay.snapshot().freezeReasons, []);
});

test('credit windows bound output: no chunk is sent before consumer credit', async t => {
  const adapter = new MockAdapter(); const h = await harness(adapter, { credit: false }); t.after(() => h.close());
  h.open(); await h.until('response.head'); await delay(40);
  assert.equal(h.frames.some(frame => frame.type === 'response.chunk'), false);
  h.send({ v: 1, type: 'window.update', requestId: 'request_1', fence: h.fence, bytes: MAX_BUFFER_BYTES });
  assert.equal((await h.until('response.end')).state, 'COMPLETED');
});

test('truncated stream stays UNKNOWN, freezes new work, and does not automatically replay', async t => {
  const adapter = new MockAdapter({ mode: 'truncate' }); const h = await harness(adapter); t.after(() => h.close());
  h.open(); assert.equal((await h.until('response.end')).state, 'UNKNOWN');
  h.open('request_2'); const rejected = await h.until('response.end', frame => frame.requestId === 'request_2');
  assert.equal(rejected.state, 'CANCELLED_NOT_SENT'); assert.equal(rejected.errorCode, 'SHARE_RESULT_UNKNOWN'); assert.equal(adapter.calls, 1);
  await h.restart(); h.send({ v: 1, type: 'status.query', requestId: 'request_1', fence: h.fence });
  assert.equal((await h.until('status.result')).state, 'UNKNOWN'); assert.equal(adapter.calls, 1);
});

test('disconnect after sending intent is durable UNKNOWN and reconnect only returns status', async t => {
  const adapter = new MockAdapter({ mode: 'hang' }); const h = await harness(adapter); t.after(() => h.close());
  h.open(); await h.until('attempt.started'); h.disconnect();
  for (let i = 0; i < 200 && h.fence < 2; i++) await delay(10);
  assert.equal(h.fence, 2); await delay(30);
  h.send({ v: 1, type: 'status.query', requestId: 'request_1', fence: h.fence });
  assert.equal((await h.until('status.result')).state, 'UNKNOWN'); assert.equal(adapter.calls, 1);
});

test('cancel aborts the local stream but does not claim that upstream incurred no usage', async t => {
  const adapter = new MockAdapter({ mode: 'hang' }); const h = await harness(adapter); t.after(() => h.close());
  h.open(); await h.until('attempt.started'); h.send({ v: 1, type: 'cancel.request', requestId: 'request_1', fence: h.fence, reason: 'test user cancel' });
  assert.equal((await h.until('response.end')).state, 'UNKNOWN'); assert.equal(adapter.calls, 1);
});


test('unknown acknowledgement is explicit, persists separately, and preserves the old UNKNOWN', async t => {
  const adapter = new MockAdapter({ mode: 'truncate' }); const h = await harness(adapter); t.after(() => h.close());
  h.open(); await h.until('response.end');
  assert.throws(() => resolveRelayUnknown(h.dbPath, true), /Stop the relay/);
  assert.throws(() => h.relay.resolveUnknown({ acknowledge: false as true }), /old request remains UNKNOWN/);
  const result = h.relay.resolveUnknown({ acknowledge: true }); assert.equal(result.acknowledged, 1);
  assert.match(result.warning, /may still be executing/);
  adapter.options.mode = 'normal'; await h.restart(); h.open('request_2');
  assert.equal((await h.until('response.end', f => f.requestId === 'request_2')).state, 'COMPLETED');
  h.send({ v: 1, type: 'status.query', requestId: 'request_1', fence: h.fence });
  assert.equal((await h.until('status.result')).state, 'UNKNOWN'); assert.equal(adapter.calls, 2);
});


test('observed upstream completion remains known if cancellation arrives before transport EOF', async t => {
  const base = new MockAdapter();
  const adapter: UpstreamAdapter = {
    inspect: () => base.inspect(), readQuota: () => base.readQuota(),
    async open(request, signal) {
      const response = await base.open(request, signal);
      return { ...response, body: (async function* () {
        yield* response.body;
        await delay(10_000, undefined, { signal });
      })() };
    },
  };
  const h = await harness(adapter); t.after(() => h.close()); h.open();
  await h.until('response.chunk', frame => Buffer.from(frame.data, 'base64').toString().includes('event: response.completed'));
  h.send({ v: 1, type: 'cancel.request', requestId: 'request_1', fence: h.fence, reason: 'cancel after completion event' });
  const result = await h.until('response.end'); assert.equal(result.state, 'COMPLETED'); assert.equal(result.usage.inputTokens, 12);
});


test('offline acknowledgement requires an existing stopped journal and does not erase unknown evidence', async t => {
  const adapter = new MockAdapter({ mode: 'truncate' }); const h = await harness(adapter); t.after(() => h.close());
  h.open(); await h.until('response.end'); await h.relay.close();
  assert.throws(() => resolveRelayUnknown(h.dbPath, false), /old request remains UNKNOWN/);
  assert.equal(resolveRelayUnknown(h.dbPath, true).acknowledged, 1);
  assert.equal(resolveRelayUnknown(h.dbPath, true).acknowledged, 0);
  await h.restart(); h.send({ v: 1, type: 'status.query', requestId: 'request_1', fence: h.fence });
  assert.equal((await h.until('status.result')).state, 'UNKNOWN');
  assert.throws(() => resolveRelayUnknown(join(tmpdir(), 'nonexistent-share-relay-journal'), true), /existing relay journal/);
});


test('drain lets the current upstream finish and rejects new work without cancellation', async t => {
  const adapter = new MockAdapter({ delayMs: 10 }); const h = await harness(adapter); t.after(() => h.close());
  h.open(); await h.until('attempt.started'); h.relay.drain();
  assert.equal(h.relay.snapshot().draining, true); assert.equal(h.relay.snapshot().paused, true);
  assert.equal((await h.until('response.end')).state, 'COMPLETED');
  assert.equal(h.relay.snapshot().draining, false);
  h.open('drained_request'); assert.equal((await h.until('response.end', f => f.requestId === 'drained_request')).state, 'CANCELLED_NOT_SENT');
  assert.equal(adapter.calls, 1); h.relay.resume(); h.open('resumed_request');
  assert.equal((await h.until('response.end', f => f.requestId === 'resumed_request')).state, 'COMPLETED'); assert.equal(adapter.calls, 2);
});

test('initial pause and explicit drain survive restart; resume is an explicit action', async t => {
  const adapter = new MockAdapter(); const h = await harness(adapter, { initialPaused: true }); t.after(() => h.close());
  assert.equal(h.relay.snapshot().paused, true); h.open();
  assert.equal((await h.until('response.end')).state, 'CANCELLED_NOT_SENT'); assert.equal(adapter.calls, 0);
  h.relay.resume(); h.open('enabled_request'); assert.equal((await h.until('response.end', f => f.requestId === 'enabled_request')).state, 'COMPLETED');
  h.relay.drain(); await h.restart(); assert.equal(h.relay.snapshot().paused, true);
  assert.equal(JSON.stringify(h.relay.snapshot()).includes('relay-test-key'), false);
});

test('policy tightening applies locally and expansion requires explicit confirmation', async t => {
  const adapter = new MockAdapter(); const h = await harness(adapter); t.after(() => h.close());
  const before = h.relay.snapshot().policy;
  h.relay.updatePolicy({ ...before, allowedMemberIds: [] }); h.open();
  assert.equal((await h.until('response.end')).state, 'CANCELLED_NOT_SENT'); assert.equal(adapter.calls, 0);
  assert.throws(() => h.relay.updatePolicy(before), /explicit local confirmation/);
  h.relay.updatePolicy(before, { confirmExpansion: true }); h.open('approved_request');
  assert.equal((await h.until('response.end', f => f.requestId === 'approved_request')).state, 'COMPLETED');
  assert.equal(h.relay.snapshot().policyRevision, 3);
});

test('acknowledging unknown never clears identity freeze, including across restart', async t => {
  const adapter = new MockAdapter({ accountBinding: 'mock:identity' }); const h = await harness(adapter); t.after(() => h.close());
  adapter.options.accountBinding = 'mock:different'; h.open(); await h.until('response.end');
  assert.deepEqual(h.relay.snapshot().freezeReasons, ['identity']);
  h.relay.resolveUnknown({ acknowledge: true }); assert.throws(() => h.relay.resume(), /blocking source condition/);
  adapter.options.accountBinding = 'mock:identity'; await h.restart();
  assert.deepEqual(h.relay.snapshot().freezeReasons, ['identity']); h.relay.resolveUnknown({ acknowledge: true });
  assert.throws(() => h.relay.resume(), /blocking source condition/); assert.equal(adapter.calls, 0);
});
