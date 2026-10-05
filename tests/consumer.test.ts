import test, { after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HubClient, type DeviceCredentials } from '../packages/hub-client/index.js';
import { ConsumerController, createConsumerBridge, type ConsumerEvent, type LauncherInput, type CodexLauncher } from '../packages/client-core/consumer.js';
import { MAX_BODY_BYTES, ShareError, policySchema } from '../packages/protocol/index.js';
import { serializeClientError } from '../packages/protocol/client-errors.js';
import { ClientStore } from '../packages/storage/client.js';
import { createHub } from '../apps/hub/index.js';
import { createRelay } from '../apps/relay/index.js';
import { MockAdapter } from '../packages/upstream/index.js';
import type { ClientAuthResponse, ClientSourceResponse, RelayLeaseResponse } from '../packages/protocol/client.js';
import type { Grant } from '../packages/protocol/index.js';

// Opt in only for synthetic regression fixtures; these tests never call a real upstream.
const previousExperimentalSubscription = process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION;
process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = '1';
after(() => { if (previousExperimentalSubscription === undefined) delete process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION; else process.env.SHARE_TOKEN_ENABLE_EXPERIMENTAL_SUBSCRIPTION = previousExperimentalSubscription; });

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
async function until(check: () => boolean, timeout = 3000): Promise<void> { const deadline = Date.now() + timeout; while (!check()) { if (Date.now() > deadline) throw new Error('condition timed out'); await delay(10); } }
async function jsonBody(req: IncomingMessage): Promise<any> { const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(Buffer.from(chunk)); return JSON.parse(Buffer.concat(chunks).toString() || '{}'); }
function json(res: ServerResponse, value: unknown, status = 200) { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); }
async function httpFixture(handler: (req: IncomingMessage, res: ServerResponse) => Promise<void> | void) {
  const server = createServer((req, res) => { void Promise.resolve(handler(req, res)).catch(error => { if (!res.headersSent) json(res, { error: { code: 'TEST_FAILURE', message: String(error) } }, 500); else res.destroy(); }); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, async close() { await new Promise<void>(resolve => { server.close(() => resolve()); server.closeAllConnections(); }); } };
}
function credentials(expiresAt = Date.now() + 300000): DeviceCredentials { return { accessToken: 'test_device_access_secret', refreshToken: 'test_refresh_secret', expiresAt, refreshExpiresAt: Date.now() + 3600000, deviceId: 'device-a', memberId: 'member-a' }; }
function authResponse() { return { accessToken: 'test_next_access_secret', refreshToken: 'test_next_refresh_secret', tokenType: 'Bearer', expiresIn: 300, refreshExpiresAt: Date.now() + 3600000, device: { id: 'device-a', memberId: 'member-a', name: 'Test Mac', platform: 'darwin', clientVersion: 'test', scopes: ['consumer'], status: 'active', createdAt: Date.now(), lastSeen: Date.now() }, member: { id: 'member-a', name: 'A', role: 'member', active: true, createdAt: Date.now() } }; }
function completedSse(text = '中文测试') { return `event: response.output_text.delta\ndata: ${JSON.stringify({ type: 'response.output_text.delta', delta: text })}\n\nevent: response.completed\ndata: ${JSON.stringify({ type: 'response.completed', response: { id: 'resp-1', status: 'completed', output: [], usage: { input_tokens: 3, output_tokens: 5 } } })}\n\n`; }

test('HubClient rejects unsafe roots and redirects without forwarding device credentials', async () => {
  for (const url of ['http://example.com', 'https://user:secret@example.com', 'https://example.com/path', 'https://example.com?token=x', 'wss://example.com']) assert.throws(() => new HubClient({ baseUrl: url }));
  let redirected = 0;
  const destination = await httpFixture((_req, res) => { redirected++; json(res, {}); });
  const hub = await httpFixture((_req, res) => { res.writeHead(307, { location: `${destination.url}/stolen` }); res.end(); });
  try {
    const client = new HubClient({ baseUrl: hub.url, credentials: credentials() });
    await assert.rejects(client.request('GET', '/client/v2/me'), { code: 'SHARE_HUB_REDIRECT_REJECTED' });
    assert.equal(redirected, 0);
    await assert.rejects(client.request('GET', '//example.com/client/v2/me'), { code: 'SHARE_PATH_UNSUPPORTED' });
  } finally { await hub.close(); await destination.close(); }
});

test('HubClient rotates refresh once for concurrent calls, and never retries an ambiguous refresh', async () => {
  let refreshes = 0; let fail = false; const persisted: (DeviceCredentials | null)[] = [];
  const hub = await httpFixture(async (req, res) => {
    if (req.url === '/client/v2/auth/refresh') { refreshes++; await jsonBody(req); if (fail) { req.socket.destroy(); return; } await delay(30); json(res, authResponse()); return; }
    assert.equal(req.headers.authorization, 'Bearer test_next_access_secret'); json(res, { ok: true });
  });
  try {
    const client = new HubClient({ baseUrl: hub.url, credentials: credentials(Date.now() - 1), onCredentials: value => { persisted.push(value); } });
    await Promise.all([client.request('GET', '/client/v2/me'), client.request('GET', '/client/v2/me'), client.request('GET', '/client/v2/me')]);
    assert.equal(refreshes, 1); assert.equal(persisted.length, 1);
    fail = true;
    await assert.rejects(client.refresh(), { code: 'SHARE_REPAIR_REQUIRED' });
    assert.equal(refreshes, 2); assert.equal(client.getCredentials(), null); assert.equal(persisted.at(-1), null);
    await assert.rejects(client.request('GET', '/client/v2/me'), { code: 'SHARE_REPAIR_REQUIRED' });
    assert.equal(refreshes, 2);
  } finally { await hub.close(); }
});

test('device pairing keeps verifier/device code private and persists before reporting approval', async () => {
  let challenge = ''; let persisted = false; let polls = 0;
  const hub = await httpFixture(async (req, res) => {
    const body = await jsonBody(req);
    if (req.url === '/client/v2/device-pairings') { challenge = body.codeChallenge; assert.equal(body.codeChallengeMethod, 'S256'); json(res, { pairingId: 'pair-1', deviceCode: 'private-device-code', userCode: 'ABCD-EFGH', verificationUri: '/device', verificationUriComplete: '/device?user_code=ABCD-EFGH', expiresAt: Date.now() + 60000, interval: 1 }); return; }
    if (req.url === '/client/v2/device-pairings/token') { polls++; assert.equal(body.deviceCode, 'private-device-code'); assert.equal(createHash('sha256').update(body.codeVerifier).digest('base64url'), challenge); json(res, authResponse()); return; }
    json(res, {});
  });
  try {
    const client = new HubClient({ baseUrl: hub.url, onCredentials: async () => { await delay(15); persisted = true; } });
    const display = await client.startPairing({ deviceName: 'My Mac', platform: 'darwin', clientVersion: 'test', requestedScopes: ['consumer'] });
    assert.equal(JSON.stringify(display).includes('private-device-code'), false); assert.equal('codeVerifier' in display, false);
    assert.equal((await client.pollPairing()).status, 'pending'); assert.equal(polls, 0);
    await delay(1020);
    const result = await client.pollPairing(); assert.equal(result.status, 'approved'); assert.equal(persisted, true);
    assert.equal(JSON.stringify(result).includes('test_next_access_secret'), false);
    assert.equal(client.getCredentials()?.deviceId, 'device-a');
  } finally { await hub.close(); }
});

test('device 401 clears and persists owned credentials once, while old responses and permission errors preserve newer login', async () => {
  const persisted: (DeviceCredentials | null)[] = []; let invalidations = 0; let release!: () => void; let started = false;
  const hub = await httpFixture(async (req, res) => {
    if (req.url?.endsWith('/delayed')) { started = true; await new Promise<void>(resolve => { release = resolve; }); }
    json(res, { error: { code: 'SHARE_AUTH_INVALID', message: 'Revoked' } }, req.url?.endsWith('/forbidden') ? 403 : 401);
  });
  try {
    const client = new HubClient({ baseUrl: hub.url, credentials: credentials(), onCredentials: async value => { await delay(5); persisted.push(value); } });
    client.onCredentialsInvalidated(() => { invalidations++; });
    await assert.rejects(client.request('GET', '/client/v2/forbidden'), { status: 403 }); assert.ok(client.getCredentials());
    const late = client.request('GET', '/client/v2/delayed'); const lateCheck = assert.rejects(late, { status: 401 }); await until(() => started);
    const fresh = { ...credentials(), accessToken: 'fresh-login-access', refreshToken: 'fresh-login-refresh' }; await client.setCredentials(fresh); release(); await lateCheck;
    assert.equal(client.getCredentials()?.accessToken, fresh.accessToken); assert.equal(invalidations, 0);
    await Promise.all([assert.rejects(client.request('GET', '/client/v2/me'), { status: 401 }), assert.rejects(client.request('GET', '/client/v2/me'), { status: 401 })]);
    assert.equal(client.getCredentials(), null); assert.equal(invalidations, 1); assert.equal(persisted.filter(value => value === null).length, 1);
  } finally { await hub.close(); }
});

test('cancelling a pairing during token redemption does not save the returned credentials', async () => {
  let release!: () => void; let tokenStarted = false; let revoked = 0; let saved = 0;
  const hub = await httpFixture(async (req, res) => {
    if (req.url === '/client/v2/device-pairings') { json(res, { pairingId: 'pair-race', deviceCode: 'private-code', userCode: 'ABCD-EFGH', verificationUri: '/device', verificationUriComplete: '/device', expiresAt: Date.now() + 60000, interval: 1 }); return; }
    if (req.url?.endsWith('/token')) { tokenStarted = true; await new Promise<void>(resolve => { release = resolve; }); json(res, authResponse()); return; }
    if (req.method === 'DELETE') revoked++; json(res, {});
  });
  try {
    const client = new HubClient({ baseUrl: hub.url, onCredentials: value => { if (value) saved++; } });
    await client.startPairing({ deviceName: 'Race Mac', platform: 'darwin', clientVersion: 'test', requestedScopes: ['consumer'] }); await delay(1020);
    const polling = client.pollPairing(); const rejected = assert.rejects(polling, { code: 'PAIRING_CANCELLED' }); await until(() => tokenStarted); await client.cancelPairing(); release(); await rejected;
    assert.equal(saved, 0); assert.equal(client.getCredentials(), null); assert.equal(revoked, 1);
  } finally { await hub.close(); }
});

async function bridgeFixture(mode: 'normal' | 'gzip' | 'hang' | 'truncate' | 'terminal-paused' | 'terminal-truncated' | 'terminal-tail-malformed' | 'terminal-tail-oversized' = 'normal') {
  const calls: { headers: IncomingMessage['headers']; body: any; operationId: string }[] = [];
  const acks: any[] = []; let upstreamClosed = false;
  let releaseEof!: () => void, terminalStaged = false, upstreamFinished = false;
  const eofGate = new Promise<void>(resolve => { releaseEof = resolve; });
  const hub = await httpFixture(async (req, res) => {
    if (req.url === '/v1/responses' || req.url === '/v1/responses/compact') {
      const body = await jsonBody(req); const operationId = String(req.headers['x-share-operation-id']); calls.push({ headers: req.headers, body, operationId });
      req.on('close', () => { /* request upload can close normally */ }); res.on('close', () => { upstreamClosed = true; });
      const headers: Record<string, string> = { 'content-type': 'text/event-stream', 'x-share-request-id': 'request-1', 'set-cookie': 'secret=upstream', 'x-untrusted-route': 'do-not-forward' };
      if (mode === 'gzip') { const bytes = gzipSync(completedSse()); res.writeHead(200, { ...headers, 'content-encoding': 'gzip', 'content-length': String(bytes.length) }); res.end(bytes); return; }
      res.writeHead(200, headers);
      if (mode === 'hang') { res.write('event: response.created\ndata: {"type":"response.created","response":{"id":"resp-1","status":"in_progress"}}\n\n'); return; }
      if (mode === 'truncate') { res.end('data: {"type":"response.output_text.delta","delta":"partial"}\n\n'); return; }
      if (mode.startsWith('terminal-')) {
        const raw = completedSse(), at = raw.indexOf('event: response.completed'), terminal = raw.slice(at);
        res.write(raw.slice(0, at)); await delay(10);
        if (mode === 'terminal-truncated') { res.write(terminal.slice(0, -2)); await delay(20); res.destroy(); return; }
        res.write(terminal); terminalStaged = true;
        if (mode === 'terminal-paused') await eofGate;
        if (mode === 'terminal-tail-malformed') res.write('data: {broken-json}\n\n');
        if (mode === 'terminal-tail-oversized') res.write(Buffer.alloc(MAX_BODY_BYTES + 1, 32));
        upstreamFinished = true; res.end(); return;
      }
      const bytes = Buffer.from(completedSse()); for (const byte of bytes) res.write(Buffer.from([byte])); res.end(); return;
    }
    if (req.url?.endsWith('/delivery-ack')) { acks.push(await jsonBody(req)); assert.equal(req.headers.authorization, 'Bearer test_device_access_secret'); json(res, { request: { id: 'request-1' } }); return; }
    if (req.url?.includes('/operations/')) { json(res, { request: { id: 'request-1' } }); return; }
    json(res, { error: { code: 'TEST_NOT_FOUND' } }, 404);
  });
  const hubClient = new HubClient({ baseUrl: hub.url, credentials: credentials() });
  const bridge = await createConsumerBridge({ hub: hubClient, sessionId: 'session-1', leaseId: 'lease-1', model: 'mock-codex', getLeaseToken: async () => 'private-lease-token', maxBodyBytes: 1024 });
  const post = (options: { model?: string; signal?: AbortSignal; headers?: Record<string, string>; path?: string; body?: string } = {}) => fetch(bridge.url + (options.path ?? '/responses'), { method: 'POST', headers: { authorization: `Bearer ${bridge.localKey}`, 'content-type': 'application/json', ...options.headers }, body: options.body ?? JSON.stringify({ model: options.model ?? 'mock-codex', input: 'private prompt', stream: true }), signal: options.signal });
  return { hub, bridge, calls, acks, post, releaseEof, terminalStaged: () => terminalStaged, upstreamFinished: () => upstreamFinished, upstreamClosed: () => upstreamClosed, async close() { releaseEof(); await bridge.close(); await hub.close(); } };
}

test('loopback bridge authenticates exact Host, denies browser/path/model injection and limits bodies', async () => {
  const f = await bridgeFixture();
  try {
    assert.equal((await f.post({ headers: { origin: 'https://evil.example' } })).status, 403);
    const wrongHost = await new Promise<number | undefined>((resolve, reject) => {
      const req = httpRequest(`${f.bridge.url}/responses`, { method: 'POST', headers: { host: 'evil.example', authorization: `Bearer ${f.bridge.localKey}`, 'content-type': 'application/json' } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
      req.on('error', reject); req.end(JSON.stringify({ model: 'mock-codex' }));
    });
    assert.equal(wrongHost, 403);
    assert.equal((await f.post({ headers: { authorization: 'Bearer wrong-key' } })).status, 401);
    assert.equal((await f.post({ path: '/responses?url=https://evil.example' })).status, 404);
    assert.equal((await f.post({ model: 'other-model' })).status, 403);
    assert.equal((await f.post({ headers: { 'content-encoding': 'gzip' } })).status, 415);
    assert.equal((await f.post({ body: 'x'.repeat(1025) })).status, 413);
    assert.equal(f.calls.length, 0);
  } finally { await f.close(); }
});

test('bridge streams split UTF-8/SSE, substitutes only the lease credential and ACKs local transport', async () => {
  const f = await bridgeFixture();
  try {
    const response = await f.post({ headers: { cookie: 'consumer_cookie=private', 'x-route-url': 'https://evil.example' } });
    assert.equal(response.status, 200); assert.equal(await response.text(), completedSse());
    assert.equal(response.headers.get('set-cookie'), null); assert.equal(response.headers.get('x-untrusted-route'), null);
    await until(() => f.acks.length === 1);
    assert.equal(f.calls.length, 1); assert.equal(f.calls[0]!.headers.authorization, 'Bearer private-lease-token');
    assert.equal(f.calls[0]!.headers.cookie, undefined); assert.equal(f.calls[0]!.headers['x-route-url'], undefined);
    assert.deepEqual(f.acks[0], { operationId: f.calls[0]!.operationId, outcome: 'transport_finished' });
    assert.equal(f.bridge.snapshot().blocked, false);
    assert.equal(JSON.stringify(f.bridge.snapshot()).includes(f.bridge.localKey), false);
  } finally { await f.close(); }
});

test('bridge removes obsolete content-encoding and length after fetch decompresses SSE', async () => {
  const f = await bridgeFixture('gzip');
  try { const response = await f.post(); assert.equal(response.headers.get('content-encoding'), null); assert.equal(response.headers.get('content-length'), null); assert.equal(await response.text(), completedSse()); await until(() => f.acks.length === 1); }
  finally { await f.close(); }
});

test('Codex closing immediately after its completed event is delivered does not freeze the next turn', async () => {
  const f = await bridgeFixture('terminal-paused'); let received = '', destroyedAfterTerminal = false;
  const terminal = completedSse().slice(completedSse().indexOf('event: response.completed'));
  try {
    const nativeFinished = new Promise<void>((resolve, reject) => {
      const req = httpRequest(`${f.bridge.url}/responses`, { method: 'POST', headers: { authorization: `Bearer ${f.bridge.localKey}`, 'content-type': 'application/json' } }, res => {
        res.on('data', chunk => {
          received += chunk.toString();
          if (received.includes(terminal)) {
            destroyedAfterTerminal = true;
            res.destroy(); resolve(); // Official Codex stops at Completed instead of HTTP EOF.
          }
        });
        res.on('error', error => { if (!destroyedAfterTerminal) reject(error); });
      });
      req.on('error', reject); req.end(JSON.stringify({ model: 'mock-codex', stream: true }));
    });
    await until(() => f.terminalStaged() && received.includes('response.output_text.delta'));
    await delay(20);
    assert.equal(received.includes('response.completed'), false); assert.equal(f.acks.length, 0); assert.equal(f.upstreamFinished(), false);
    f.releaseEof(); await nativeFinished;
    await until(() => f.acks.length === 1 && !f.bridge.snapshot().active);
    assert.equal(received, completedSse()); assert.equal(f.upstreamFinished(), true);
    assert.equal(f.acks[0].outcome, 'transport_finished'); assert.equal(f.bridge.snapshot().blocked, false);
    const next = await f.post(); assert.equal(next.status, 200); await next.text();
    await until(() => f.acks.length === 2); assert.equal(f.calls.length, 2); assert.equal(f.bridge.snapshot().blocked, false);
  } finally { await f.close(); }
});

test('a terminal observed upstream but still withheld locally cannot acknowledge a canceled consumer', async () => {
  const f = await bridgeFixture('terminal-paused');
  try {
    const cancellation = new AbortController(), response = await f.post({ signal: cancellation.signal });
    const reader = response.body!.getReader(), first = await reader.read();
    assert.equal(Buffer.from(first.value!).includes(Buffer.from('response.completed')), false);
    await until(() => f.terminalStaged()); cancellation.abort(); await reader.cancel().catch(() => undefined);
    await until(() => f.acks.length === 1); assert.equal(f.acks[0].outcome, 'lost');
    assert.equal(f.bridge.snapshot().blocked, true); assert.equal((await f.post()).status, 409); assert.equal(f.calls.length, 1);
  } finally { await f.close(); }
});

test('terminal transport truncation, malformed trailing events and excessive tails remain blocked', async () => {
  for (const mode of ['terminal-truncated', 'terminal-tail-malformed', 'terminal-tail-oversized'] as const) {
    const f = await bridgeFixture(mode);
    try {
      const response = await f.post(); await response.text().catch(() => undefined);
      await until(() => f.acks.length === 1);
      assert.equal(f.acks[0].outcome, mode === 'terminal-tail-malformed' ? 'transport_finished' : 'lost');
      assert.equal(f.bridge.snapshot().blocked, true); assert.equal((await f.post()).status, 409); assert.equal(f.calls.length, 1);
    } finally { await f.close(); }
  }
});

test('local cancellation aborts Hub transfer, records lost delivery and blocks implicit replay', async () => {
  const f = await bridgeFixture('hang');
  try {
    const cancellation = new AbortController(); const response = await f.post({ signal: cancellation.signal }); const reader = response.body!.getReader(); await reader.read(); cancellation.abort(); await reader.cancel().catch(() => undefined);
    await until(() => f.acks.some(ack => ack.outcome === 'lost'));
    await until(() => f.upstreamClosed());
    assert.equal(f.bridge.snapshot().blocked, true); assert.equal((await f.post()).status, 409); assert.equal(f.calls.length, 1);
  } finally { await f.close(); }
});

test('HTTP EOF without a Responses terminal is retained as unknown and not replayed', async () => {
  const f = await bridgeFixture('truncate');
  try { const response = await f.post(); await response.text(); await until(() => f.acks.length === 1); assert.equal(f.bridge.snapshot().blocked, true); assert.equal((await f.post()).status, 409); assert.equal(f.calls.length, 1); }
  finally { await f.close(); }
});

test('lost ACK response retries only delivery metadata and never repeats model execution', async () => {
  let calls = 0; let ackCalls = 0; const events: string[] = [];
  const hub = await httpFixture(async (req, res) => {
    await jsonBody(req);
    if (req.url?.endsWith('/delivery-ack')) { ackCalls++; if (ackCalls === 1) { req.socket.destroy(); return; } json(res, {}); return; }
    calls++; res.writeHead(200, { 'content-type': 'text/event-stream', 'x-share-request-id': 'ack-request' }); res.end(completedSse());
  });
  const bridge = await createConsumerBridge({ hub: new HubClient({ baseUrl: hub.url, credentials: credentials() }), sessionId: 'ack-session', leaseId: 'ack-lease', model: 'mock-codex', getLeaseToken: async () => 'lease', onEvent: event => events.push(event.type) });
  try {
    const response = await fetch(`${bridge.url}/responses`, { method: 'POST', headers: { authorization: `Bearer ${bridge.localKey}`, 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-codex', stream: true }) }); await response.text();
    await until(() => events.includes('request.attention')); assert.equal(bridge.snapshot().pendingDeliveryAcks, 1);
    await until(() => events.includes('request.finished')); assert.equal(bridge.snapshot().pendingDeliveryAcks, 0); assert.equal(calls, 1); assert.equal(ackCalls, 2);
  } finally { await bridge.close(); await hub.close(); }
});

test('slow local consumers apply stream backpressure and cannot receive an early delivery ACK', async () => {
  let acked = false;
  const hub = await httpFixture(async (req, res) => {
    if (req.url?.endsWith('/delivery-ack')) { await jsonBody(req); acked = true; json(res, {}); return; }
    await jsonBody(req); res.writeHead(200, { 'content-type': 'text/event-stream', 'x-share-request-id': 'large-request' });
    const chunk = `data: ${JSON.stringify({ type: 'response.output_text.delta', delta: 'x'.repeat(32 * 1024) })}\n\n`;
    for (let i = 0; i < 512; i++) if (!res.write(chunk)) await new Promise<void>(resolve => res.once('drain', resolve));
    res.end(completedSse('done'));
  });
  const bridge = await createConsumerBridge({ hub: new HubClient({ baseUrl: hub.url, credentials: credentials() }), sessionId: 'slow-session', leaseId: 'slow-lease', model: 'mock-codex', getLeaseToken: async () => 'lease-secret' });
  try {
    let bytes = 0;
    await new Promise<void>((resolve, reject) => {
      const req = httpRequest(`${bridge.url}/responses`, { method: 'POST', headers: { authorization: `Bearer ${bridge.localKey}`, 'content-type': 'application/json' } }, res => {
        res.pause(); setTimeout(() => { try { assert.equal(acked, false); } catch (error) { reject(error); } res.on('data', chunk => { bytes += chunk.length; }); res.resume(); }, 150);
        res.on('end', resolve); res.on('error', reject);
      });
      req.on('error', reject); req.end(JSON.stringify({ model: 'mock-codex', stream: true }));
    });
    assert.ok(bytes > 16 * 1024 * 1024); await until(() => acked);
  } finally { await bridge.close(); await hub.close(); }
});

for (const kind of ['mock', 'subscription'] as const) test(`ConsumerController pins ${kind} source/session/lease and owns only its terminal lifecycle`, async () => {
  const policy = policySchema.parse({ models: ['mock-codex'], allowedMemberIds: ['member-a'] });
  const grant = { id: 'grant-1', memberId: 'member-a', sourceId: 'source-1', label: 'A', models: ['mock-codex'], revoked: false, frozen: false, expiresAt: null, createdAt: Date.now() };
  const session = { id: 'session-1', memberId: 'member-a', grantId: 'grant-1', sourceId: 'source-1', modelScope: ['mock-codex'], state: 'open', frozen: false, createdAt: Date.now() };
  const lease = { id: 'lease-1', sessionId: 'session-1', deviceId: 'device-a', epoch: 1, state: 'active', expiresAt: Date.now() + 300000, createdAt: Date.now() };
  let closes = 0; let sessionCloses = 0; let starts = 0; let stops = 0; let launch: LauncherInput | null = null; const events: ConsumerEvent[] = []; const writes: string[] = [];
  const hub = await httpFixture(async (req, res) => {
    if (req.url === '/client/v2/grants') { json(res, { grants: [grant] }); return; }
    if (req.url === '/client/v2/sources') { json(res, { sources: [{ id: 'source-1', kind, clientMode: `${kind}-v1-compatibility`, policy }] }); return; }
    const body = await jsonBody(req);
    if (req.url === '/client/v2/sessions') { assert.equal(body.grantId, grant.id); assert.deepEqual(body.modelScope, ['mock-codex']); assert.equal('cwd' in body, false); json(res, { session }); return; }
    if (req.url === '/client/v2/sessions/session-1/leases') { json(res, { lease, token: 'private-lease-token', expiresIn: 300 }); return; }
    if (req.url === '/client/v2/run-leases/lease-1/close') { closes++; json(res, { lease: { ...lease, state: 'closed' } }); return; }
    if (req.url === '/client/v2/sessions/session-1/close') { sessionCloses++; json(res, { session: { ...session, state: 'closed' } }); return; }
    json(res, {});
  });
  const client = new HubClient({ baseUrl: hub.url, credentials: credentials() });
  const controller = new ConsumerController({ hub: client, onEvent: event => events.push(event), launcher: { async start(input) { starts++; launch = input; input.onData('mock terminal ready'); return { pid: 123, write: data => writes.push(data), resize: () => undefined, async stop() { stops++; input.onExit({ exitCode: 0 }); } }; } } });
  try {
    const snapshot = await controller.create({ grantId: grant.id, model: 'mock-codex', cwd: '/test/local-project', codexPath: '/test/owned-codex' });
    assert.equal(snapshot.state, 'running'); assert.equal(snapshot.sourceId, 'source-1'); assert.equal(snapshot.sessionId, 'session-1'); assert.equal(starts, 1);
    assert.equal((launch as LauncherInput | null)?.model, 'mock-codex');
    const serialized = JSON.stringify([controller.snapshot(), events]);
    for (const secret of ['private-lease-token', 'test_device_access_secret', 'test_refresh_secret', (launch as LauncherInput | null)?.localKey ?? 'unused']) assert.equal(serialized.includes(secret), false);
    controller.write(snapshot.sessionId, 'hello\r'); assert.deepEqual(writes, ['hello\r']);
    assert.throws(() => controller.resize(snapshot.sessionId, 1, 1), { code: 'SHARE_TERMINAL_SIZE_INVALID' });
    assert.throws(() => controller.write('someone-elses-session', 'x'), { code: 'SHARE_SESSION_NOT_FOUND' });
    await controller.stop(snapshot.sessionId); await controller.stop(snapshot.sessionId);
    assert.equal(stops, 1); assert.equal(closes, 1); assert.equal(sessionCloses, 1); assert.equal(controller.snapshot()[0]!.state, 'stopped');
  } finally { await controller.close(); await hub.close(); }
});

test('Controller.close waits for an in-flight launch and stops the newly returned owned PTY', async () => {
  let launchStarted = false; let release!: () => void; let stops = 0; let leaseCloses = 0; let sessionCloses = 0;
  const hub = await httpFixture(async (req, res) => {
    if (req.url === '/client/v2/grants') { json(res, { grants: [{ id: 'grant', sourceId: 'source', models: ['mock-codex'], revoked: false, expiresAt: null }] }); return; }
    if (req.url === '/client/v2/sources') { json(res, { sources: [{ id: 'source', kind: 'mock', clientMode: 'mock-v1-compatibility' }] }); return; }
    if (req.url === '/client/v2/sessions') { json(res, { session: { id: 'session', grantId: 'grant', sourceId: 'source', modelScope: ['mock-codex'] } }); return; }
    if (req.url?.endsWith('/leases')) { json(res, { lease: { id: 'lease', sessionId: 'session', deviceId: 'device-a', epoch: 1, state: 'active', expiresAt: Date.now() + 300000 }, token: 'private-lease', expiresIn: 300 }); return; }
    if (req.url === '/client/v2/run-leases/lease/close') leaseCloses++;
    if (req.url === '/client/v2/sessions/session/close') sessionCloses++;
    json(res, {});
  });
  const controller = new ConsumerController({ hub: new HubClient({ baseUrl: hub.url, credentials: credentials() }), launcher: { async start(input) { launchStarted = true; await new Promise<void>(resolve => { release = resolve; }); return { pid: 555, write() {}, resize() {}, async stop() { stops++; input.onExit({ exitCode: 0 }); } }; } } });
  try {
    const creating = controller.create({ grantId: 'grant', model: 'mock-codex', cwd: '/mock', codexPath: '/mock/codex' }); await until(() => launchStarted);
    let closed = false; const closing = controller.close().then(() => { closed = true; }); await delay(20); assert.equal(closed, false);
    release(); await creating; await closing;
    assert.equal(stops, 1); assert.equal(leaseCloses, 1); assert.equal(sessionCloses, 1); assert.equal(controller.snapshot()[0]?.state, 'stopped');
  } finally { await controller.close(); await hub.close(); }
});

async function startupFixture(t: TestContext, launcher: CodexLauncher) {
  const dir = await mkdtemp(join(tmpdir(), 'consumer-startup-regression-'));
  const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: 'consumer_startup_test_admin_abcdefghijklmnopqrstuvwxyz', port: 0 });
  const clients = new ClientStore(hub.store), member = hub.store.createMember('Synthetic terminal member');
  const verifier = randomBytes(48).toString('base64url');
  const pair = clients.createPairing({ deviceName: 'Synthetic terminal device', platform: 'test', clientVersion: 'test', requestedScopes: ['consumer', 'donor'], codeChallenge: createHash('sha256').update(verifier).digest('base64url') }, hub.url);
  clients.approvePairing(pair.userCode, member);
  const auth = clients.redeemPairing(pair.deviceCode, verifier);
  const client = new HubClient({ baseUrl: hub.url, credentials: { accessToken: auth.accessToken, refreshToken: auth.refreshToken, expiresAt: Date.now() + auth.expiresIn * 1000, refreshExpiresAt: auth.refreshExpiresAt, memberId: member.id, deviceId: auth.device.id } });
  const policy = policySchema.parse({ models: ['mock-codex'], allowedMemberIds: [member.id] });
  const { source } = await client.request<ClientSourceResponse>('POST', '/client/v2/sources', { name: 'Synthetic terminal source', kind: 'mock', accountBinding: 'mock:terminal-regression', policy });
  await client.request('POST', `/client/v2/sources/${source.id}/policy-acks`, { revision: 1 });
  const { grant } = await client.request<{ grant: Grant }>('POST', '/client/v2/grants', { sourceId: source.id, label: 'Synthetic terminal grant', models: ['mock-codex'] });
  const events: ConsumerEvent[] = [];
  const controller = new ConsumerController({ hub: client, launcher, onEvent: event => events.push(event) });
  t.after(async () => { await controller.close(); assert.equal(hub.store.listRequests().length, 0); await hub.close(); await rm(dir, { recursive: true, force: true }); });
  const create = () => controller.create({ grantId: grant.id, model: 'mock-codex', cwd: dir, codexPath: join(dir, 'synthetic-codex') });
  function assertClosed() {
    const view = controller.snapshot()[0]!;
    assert.equal(clients.getRun(view.leaseId)?.state, 'closed');
    assert.equal(clients.getSession(view.sessionId)?.state, 'closed');
    assert.equal(view.pid, null);
    assert.equal(hub.store.listRequests().length, 0);
  }
  return { controller, client, events, create, assertClosed };
}

for (const known of [true, false]) test(`startup ${known ? 'classified' : 'unknown'} errors survive cleanup without exposing native error contents`, async t => {
  const secret = 'PRIVATE_native_error_must_not_reach_the_UI';
  const code = known ? 'SHARE_CODEX_START_DENIED' : 'SHARE_TERMINAL_START_FAILED';
  let launch: LauncherInput | undefined;
  const f = await startupFixture(t, { async start(input) { launch = input; throw known ? new ShareError(code, secret, 403) : new Error(secret); } });
  await assert.rejects(f.create(), error => error instanceof ShareError && error.code === code && error.message === serializeClientError({ code }).message);
  const failed = f.controller.snapshot()[0]!;
  assert.equal(failed.state, 'failed'); assert.equal(failed.errorCode, code);
  assert.equal(failed.message, serializeClientError({ code }).message);
  assert.equal(failed.terminalStarted, false); assert.equal(failed.exitCode, null); assert.equal(failed.exitSignal, null);
  f.assertClosed();
  await assert.rejects(fetch(`${launch!.baseUrl}/models`, { headers: { authorization: `Bearer ${launch!.localKey}` } }));
  await f.controller.stop(failed.sessionId);
  assert.equal(f.controller.snapshot()[0]?.message, failed.message, 'Repeated stop must not erase the startup diagnosis.');
  assert.equal(f.controller.snapshot()[0]?.state, 'failed');
  assert.equal(JSON.stringify(f.events).includes(secret), false);
});

for (const exit of [{ exitCode: 23 }, { exitCode: 0, signal: 15 }, { exitCode: 0 }]) test(`a terminal exiting before start resolves preserves exit ${JSON.stringify(exit)} and never becomes running`, async t => {
  let stops = 0;
  const f = await startupFixture(t, { async start(input) {
    input.onData('Synthetic terminal exited before launch completed.'); input.onExit(exit);
    return { pid: 654321, write() {}, resize() {}, async stop() { stops++; input.onExit({ exitCode: 0 }); } };
  } });
  const result = await f.create(), failed = exit.exitCode !== 0 || !!exit.signal;
  assert.equal(result.state, failed ? 'failed' : 'stopped');
  assert.equal(result.errorCode, failed ? 'SHARE_CODEX_EXITED' : null);
  assert.equal(result.message, failed ? serializeClientError({ code: 'SHARE_CODEX_EXITED' }).message : null);
  assert.equal(result.exitCode, exit.exitCode); assert.equal(result.exitSignal, exit.signal ?? null);
  assert.equal(result.terminalStarted, true); assert.equal(stops, 1);
  assert.equal(f.events.some(event => event.type === 'session.updated' && event.session.state === 'running'), false);
  assert.equal(f.events.filter(event => event.type === 'terminal.exit').length, 1, 'Cleanup must not replace the original exit with its own exit callback.');
  f.assertClosed();
});

test('an unexpected nonzero exit after startup keeps its failure while an explicit stop signal remains a normal stop', async t => {
  for (const explicitStop of [false, true]) {
    let launch: LauncherInput | undefined;
    const f = await startupFixture(t, { async start(input) {
      launch = input;
      return { pid: 654322, write() {}, resize() {}, async stop() { input.onExit({ exitCode: 0, signal: 15 }); } };
    } });
    const result = await f.create(); assert.equal(result.state, 'running');
    if (explicitStop) await f.controller.stop(result.sessionId);
    else { launch!.onExit({ exitCode: 23 }); await until(() => f.controller.snapshot()[0]?.state === 'failed'); await f.controller.stop(result.sessionId); }
    const final = f.controller.snapshot()[0]!;
    assert.equal(final.state, explicitStop ? 'stopped' : 'failed');
    assert.equal(final.errorCode, explicitStop ? null : 'SHARE_CODEX_EXITED');
    assert.equal(final.exitCode, explicitStop ? 0 : 23);
    assert.equal(final.exitSignal, explicitStop ? 15 : null);
    assert.equal(final.terminalStarted, true);
    f.assertClosed();
  }
});

test('terminal cleanup uncertainty is appended to the original exit failure without leaking native exception text', async t => {
  let launch: LauncherInput | undefined;
  const f = await startupFixture(t, { async start(input) {
    launch = input;
    return { pid: 654323, write() {}, resize() {}, async stop() { throw new Error('PRIVATE_native_stop_exception'); } };
  } });
  const result = await f.create();
  launch!.onExit({ exitCode: 23 });
  await f.controller.stop(result.sessionId);
  const view = f.controller.snapshot()[0]!;
  assert.equal(view.state, 'attention');
  assert.equal(view.errorCode, 'SHARE_CODEX_EXITED');
  assert.ok(view.message?.startsWith(serializeClientError({ code: 'SHARE_CODEX_EXITED' }).message));
  assert.match(view.message!, /本机 Codex 退出尚未确认/);
  assert.equal(JSON.stringify(f.events).includes('PRIVATE_native_stop_exception'), false);
});

test('a lost Hub close response remains visible alongside the original classified launch failure', async t => {
  const f = await startupFixture(t, { async start() { throw new ShareError('SHARE_CODEX_START_DENIED', 'PRIVATE_start_denial', 403); } });
  const request = f.client.request.bind(f.client);
  f.client.request = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
    const result = await request<T>(method, path, body);
    if (path.startsWith('/client/v2/sessions/') && path.endsWith('/close')) throw new Error('PRIVATE_close_response_lost');
    return result;
  };
  await assert.rejects(f.create(), { code: 'SHARE_CODEX_START_DENIED' });
  const view = f.controller.snapshot()[0]!;
  assert.equal(view.state, 'failed'); assert.equal(view.errorCode, 'SHARE_CODEX_START_DENIED');
  assert.ok(view.message?.startsWith(serializeClientError({ code: 'SHARE_CODEX_START_DENIED' }).message));
  assert.match(view.message!, /Hub 的会话或运行授权关闭尚未确认/);
  assert.equal(JSON.stringify(f.events).includes('PRIVATE_'), false);
  f.assertClosed();
});

for (const kind of ['mock', 'subscription'] as const) test(`consumer ${kind} bridge integrates with Hub v2 and Relay; revoke stops its owned terminal`, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'share-consumer-v2-'));
  const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: 'test_admin_abcdefghijklmnopqrstuvwxyz', port: 0 });
  let relay: Awaited<ReturnType<typeof createRelay>> | undefined;
  let controller: ConsumerController | undefined;
  async function raw(path: string, body?: unknown, headers: Record<string, string> = {}, method = body === undefined ? 'GET' : 'POST') {
    const response = await fetch(hub.url + path, { method, headers: { 'content-type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    assert.equal(response.ok, true, `${path} ${response.status} ${response.ok ? '' : await response.text()}`); return response;
  }
  try {
    const login = await raw('/control/login', { token: 'test_admin_abcdefghijklmnopqrstuvwxyz' }); const cookie = login.headers.get('set-cookie')!.split(';')[0]!; const logged = await login.json() as { csrfToken: string };
    const verifier = 'test-private-verifier-for-consumer-v2'.repeat(2);
    const pair = await (await raw('/client/v2/device-pairings', { deviceName: 'Consumer test', platform: 'darwin', clientVersion: 'test', requestedScopes: ['consumer', 'donor'], codeChallengeMethod: 'S256', codeChallenge: createHash('sha256').update(verifier).digest('base64url') })).json() as { userCode: string; deviceCode: string };
    await raw(`/control/v2/device-pairings/${pair.userCode}/approve`, { approvedScopes: ['consumer', 'donor'] }, { cookie, 'x-csrf-token': logged.csrfToken });
    const auth = await (await raw('/client/v2/device-pairings/token', { deviceCode: pair.deviceCode, codeVerifier: verifier })).json() as ClientAuthResponse;
    const client = new HubClient({ baseUrl: hub.url, credentials: { accessToken: auth.accessToken, refreshToken: auth.refreshToken, expiresAt: Date.now() + auth.expiresIn * 1000, refreshExpiresAt: auth.refreshExpiresAt, memberId: auth.member.id, deviceId: auth.device.id } });
    const policy = policySchema.parse({ models: ['mock-codex'], allowedMemberIds: [auth.member.id] });
    const { source } = await client.request<ClientSourceResponse>('POST', '/client/v2/sources', { name: 'Consumer synthetic test', kind, accountBinding: `${kind}:consumer-test`, policy });
    await client.request('POST', `/client/v2/sources/${source.id}/policy-acks`, { revision: 1 });
    const relayLease = await client.request<RelayLeaseResponse>('POST', `/client/v2/sources/${source.id}/relay-leases`, {});
    const adapter = new MockAdapter({ accountBinding: source.accountBinding, models: policy.models });
    if (kind === 'subscription') { const inspect = adapter.inspect.bind(adapter), readQuota = adapter.readQuota.bind(adapter); adapter.inspect = async () => ({ ...await inspect(), kind: 'subscription' }); adapter.readQuota = async () => ({ ...await readQuota(), origin: 'codex' }); }
    relay = await createRelay({ hubUrl: hub.url, token: relayLease.token, sourceId: source.id, nodeId: 'consumer-integration', dbPath: join(dir, 'relay.sqlite'), policy, adapter }); await relay.waitUntilReady();
    const { grant } = await client.request<{ grant: Grant }>('POST', '/client/v2/grants', { sourceId: source.id, label: 'Consumer integration', models: policy.models });
    let launch: LauncherInput | undefined; let stops = 0;
    controller = new ConsumerController({ hub: client, launcher: { async start(input) { launch = input; return { pid: 321, write() {}, resize() {}, async stop() { stops++; input.onExit({ exitCode: 0 }); } }; } } });
    const session = await controller.create({ grantId: grant.id, model: 'mock-codex', cwd: dir, codexPath: '/fixture/codex' });
    const response = await fetch(`${launch!.baseUrl}/responses`, { method: 'POST', headers: { authorization: `Bearer ${launch!.localKey}`, 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-codex', input: 'mock integration only', stream: true }) });
    assert.equal(response.status, 200); assert.match(await response.text(), /response.completed/);
    await until(() => controller!.snapshot()[0]?.state === 'running');
    const records = await client.request<{ requests: { sessionId: string; consumerDelivery: string }[] }>('GET', '/client/v2/requests');
    assert.equal(records.requests[0]?.sessionId, session.sessionId); assert.equal(records.requests[0]?.consumerDelivery, 'transport_finished'); assert.equal(adapter.calls, 1);
    await client.request('DELETE', `/client/v2/devices/${auth.device.id}`);
    await assert.rejects(client.request('GET', '/client/v2/me'), { status: 401 });
    await until(() => controller!.snapshot()[0]?.state === 'stopped'); assert.equal(stops, 1); assert.equal(client.getCredentials(), null);
    await assert.rejects(fetch(`${launch!.baseUrl}/models`, { headers: { authorization: `Bearer ${launch!.localKey}` } }));
  } finally { await controller?.close(); await relay?.close(); await hub.close(); await rm(dir, { recursive: true, force: true }); }
});

for (const source of [
  { kind: 'subscription', clientMode: 'unavailable' },
  { kind: 'subscription', clientMode: 'mock-v1-compatibility' },
  { kind: 'mock', clientMode: 'subscription-v1-compatibility' },
  { kind: 'mock' },
  { kind: 'api_fixture', clientMode: 'subscription-v1-compatibility' },
]) test(`consumer rejects unsupported or mismatched channel ${JSON.stringify(source)}`, async () => {
  let created = false;
  const server = await httpFixture(async (req, res) => {
    if (req.url === '/client/v2/grants') return json(res, { grants: [{ id: 'grant', sourceId: 'source', models: ['model'], revoked: false, expiresAt: null }] });
    if (req.url === '/client/v2/sources') return json(res, { sources: [{ id: 'source', ...source }] });
    created = true; return json(res, {}, 500);
  });
  const controller = new ConsumerController({ hub: new HubClient({ baseUrl: server.url, credentials: credentials() }), launcher: { start: async () => { throw new Error('No launcher expected'); } } });
  try { await assert.rejects(controller.create({ grantId: 'grant', model: 'model', cwd: '/local', codexPath: '/local/codex' }), /通道/); assert.equal(created, false); }
  finally { await controller.close(); await server.close(); }
});
