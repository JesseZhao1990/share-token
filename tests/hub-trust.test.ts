import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer, type Server } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Socket, type AddressInfo } from 'node:net';
import type { Duplex } from 'node:stream';
import { WebSocketServer } from 'ws';
import { HubClient, createHubFetch, validateHubTrustProfile, type HubTrustProfile } from '../packages/hub-client/index.js';
import { createRelay } from '../apps/relay/index.js';
import { MockAdapter } from '../packages/upstream/index.js';
import { policySchema } from '../packages/protocol/index.js';

const ip = '10.20.30.40';

async function fixture(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), 'share-token-trust-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const keyPath = join(directory, 'server.key');
  execFileSync('openssl', ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', keyPath], { stdio: 'ignore' });
  const certificate = async (name: string, settings: { san?: string; ca?: boolean; eku?: string; ku?: string; days?: string } = {}) => {
    const certPath = join(directory, `${name}.pem`);
    execFileSync('openssl', ['req', '-x509', '-new', '-key', keyPath, '-days', settings.days ?? '2', '-out', certPath,
      '-subj', `/CN=${ip}`, '-addext', `subjectAltName=IP:${settings.san ?? ip}`,
      '-addext', `basicConstraints=critical,CA:${settings.ca ? 'TRUE' : 'FALSE'}`,
      '-addext', `keyUsage=critical,${settings.ku ?? 'digitalSignature,keyEncipherment'}`,
      '-addext', `extendedKeyUsage=${settings.eku ?? 'serverAuth'}`], { stdio: 'ignore' });
    return readFile(certPath, 'utf8');
  };
  const cert = await certificate('server'); const key = await readFile(keyPath, 'utf8');
  const profile: HubTrustProfile = { version: 1, hubUrl: `https://${ip}`, certificatePem: cert };
  return { directory, certificate, cert, key, keyPath, profile };
}

async function listen(t: TestContext, server: Server) {
  // Only the TCP dial is rerouted: native TLS still validates the original private IP and exact certificate.
  const connect = Socket.prototype.connect;
  t.mock.method(Socket.prototype, 'connect', function (this: Socket, ...args: unknown[]) {
    const options = args[0];
    if (options && typeof options === 'object' && !Array.isArray(options) && (options as { host?: string }).host === ip) args[0] = { ...options, host: '127.0.0.1' };
    return Reflect.apply(connect, this, args);
  });
  const sockets = new Set<Duplex>(); server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(() => new Promise<void>(resolve => { for (const socket of sockets) socket.destroy(); server.closeAllConnections(); server.close(() => resolve()); }));
  return `https://${ip}:${(server.address() as AddressInfo).port}`;
}

test('Hub trust profile validates a single private-IP leaf and derives a public fingerprint', async t => {
  const { profile, cert } = await fixture(t);
  const result = validateHubTrustProfile({ ...profile, hubUrl: `${profile.hubUrl}:443/`, label: '朋友的 Hub', fingerprint256: 'untrusted input' });
  assert.equal(result.hubUrl, profile.hubUrl); assert.equal(result.certificatePem, cert);
  assert.match(result.fingerprint256, /^[0-9A-F]{2}(?::[0-9A-F]{2}){31}$/);
  assert.deepEqual(validateHubTrustProfile(result), result);
  for (const hubUrl of ['http://10.1.2.3', 'https://127.0.0.1', 'https://8.8.8.8', 'https://100.64.0.1', 'https://172.32.0.1', 'https://example.com',
    'https://010.1.2.3', 'https://0x0a010203', 'https://10.1.2.3/../', 'https://10.1.2.3/path', 'https://10.1.2.3/?q=1', 'https://10.1.2.3#x',
    'https://u:p@10.1.2.3', 'https://10.1.2.3:0', 'https://10.1.2.3:65536', 'https://10.1.2.3\\other']) assert.throws(() => validateHubTrustProfile({ ...profile, hubUrl }));
  assert.throws(() => validateHubTrustProfile({ ...profile, label: 'line\nbreak' }));
  assert.throws(() => new HubClient({ baseUrl: 'https://10.1.2.3', hubTrust: profile }));
});

test('Hub trust profile rejects wrong SAN, CA, signing keys, client purpose, mixed PEM, and expired certificates', async t => {
  const { profile, certificate, key } = await fixture(t);
  for (const [name, settings] of [
    ['san', { san: '192.168.222.111' }], ['ca', { ca: true }], ['client', { eku: 'clientAuth' }],
    ['signing', { ku: 'digitalSignature,keyCertSign' }], ['unsigned', { ku: 'keyEncipherment' }],
  ] as const) { const cert = await certificate(name, settings); assert.throws(() => validateHubTrustProfile({ ...profile, certificatePem: cert }), /Hub|SAN|TLS/, name); }
  assert.throws(() => validateHubTrustProfile({ ...profile, certificatePem: profile.certificatePem + profile.certificatePem }));
  assert.throws(() => validateHubTrustProfile({ ...profile, certificatePem: profile.certificatePem + key }));
  const x509 = new X509Certificate(profile.certificatePem);
  const clock = t.mock.method(Date, 'now', () => Date.parse(x509.validTo) + 1000);
  assert.throws(() => validateHubTrustProfile(profile), /过期/);
  clock.mock.mockImplementation(() => Date.parse(x509.validFrom) - 1000);
  assert.throws(() => validateHubTrustProfile(profile), /尚未生效/); clock.mock.restore();
});

test('pinned fetch uses real TLS for JSON and byte POSTs, streams incrementally, and never follows redirects', async t => {
  const { profile, cert, key } = await fixture(t);
  const requests: { path: string; body: Buffer; authorization: string | undefined }[] = [];
  const server = createServer({ cert, key }, async (request, response) => {
    const parts: Buffer[] = []; for await (const part of request) parts.push(Buffer.from(part));
    requests.push({ path: request.url!, body: Buffer.concat(parts), authorization: request.headers.authorization });
    if (request.url === '/redirect') { response.writeHead(302, { location: 'https://10.1.2.3/leak' }); response.end(); }
    else if (request.url === '/stream') { response.writeHead(200, { 'content-type': 'text/event-stream' }); response.write('data: first\n\n'); setTimeout(() => response.end('data: last\n\n'), 200); }
    else { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ ok: true, received: Buffer.concat(parts).toString('utf8') })); }
  });
  const hubUrl = await listen(t, server); const fetchHub = createHubFetch({ ...profile, hubUrl });
  await assert.rejects(fetch(hubUrl), /fetch failed/, 'system trust is unchanged');
  const client = new HubClient({ baseUrl: hubUrl, hubTrust: { ...profile, hubUrl } });
  assert.deepEqual(await client.meta(), { ok: true, received: '' });
  const post = await fetchHub(`${hubUrl}/post`, { method: 'POST', body: new Uint8Array([65, 66]), headers: { authorization: 'Bearer local-test' } });
  assert.equal((await post.json()).received, 'AB');
  const stream = await fetchHub(`${hubUrl}/stream`); const reader = stream.body!.getReader();
  assert.equal(Buffer.from((await reader.read()).value!).toString(), 'data: first\n\n');
  assert.equal(Buffer.from((await reader.read()).value!).toString(), 'data: last\n\n'); assert.equal((await reader.read()).done, true);
  const redirected = await fetchHub(`${hubUrl}/redirect`); assert.equal(redirected.status, 302); await redirected.body?.cancel();
  const before = requests.length;
  await assert.rejects(fetchHub('https://10.1.2.3/leak', { headers: { authorization: 'Bearer must-not-leak' } }), /origin/);
  await assert.rejects(fetchHub(hubUrl, { headers: { host: 'other.example' } }), /header/);
  assert.equal(requests.length, before); assert.equal(requests.find(row => row.path === '/post')?.authorization, 'Bearer local-test');
});

test('pinned fetch rejects a different certificate using the same key and cancels live streaming requests', async t => {
  const { profile, certificate, key, cert } = await fixture(t);
  const different = await certificate('different');
  let received = 0;
  const wrong = createServer({ cert: different, key }, (_request, response) => { received++; response.end('wrong'); });
  const wrongUrl = await listen(t, wrong);
  await assert.rejects(createHubFetch({ ...profile, hubUrl: wrongUrl })(wrongUrl)); assert.equal(received, 0, 'a wrong certificate receives no HTTP request');
  let closed!: () => void; const serverClosed = new Promise<void>(resolve => { closed = resolve; });
  const server = createServer({ cert, key }, (_request, response) => { response.writeHead(200); response.write('start'); response.on('close', closed); });
  const hubUrl = await listen(t, server); const fetchHub = createHubFetch({ ...profile, hubUrl });
  const controller = new AbortController(); const response = await fetchHub(hubUrl, { signal: controller.signal });
  const reader = response.body!.getReader(); assert.equal(Buffer.from((await reader.read()).value!).toString(), 'start');
  controller.abort(); await assert.rejects(reader.read(), /aborted/); await serverClosed;
  await assert.rejects(fetchHub(hubUrl, { signal: AbortSignal.abort() }), /abort/i);
  const cancelled = await fetchHub(hubUrl); await cancelled.body!.cancel();
});

test('pinned fetch rejects the same private IP on a different port before sending a request', async t => {
  const { profile, cert, key } = await fixture(t);
  let allowedRequests = 0; let differentPortRequests = 0;
  const allowed = createServer({ cert, key }, (_request, response) => { allowedRequests++; response.end('allowed'); });
  const other = createServer({ cert, key }, (_request, response) => { differentPortRequests++; response.end('must not receive credentials'); });
  const hubUrl = await listen(t, allowed); const differentPortUrl = await listen(t, other);
  assert.equal(new URL(hubUrl).hostname, new URL(differentPortUrl).hostname);
  assert.notEqual(new URL(hubUrl).port, new URL(differentPortUrl).port);
  const fetchHub = createHubFetch({ ...profile, hubUrl });
  await assert.rejects(fetchHub(`${differentPortUrl}/client/v2/me`, { headers: { authorization: 'Bearer port-bound-secret' } }), /origin/);
  assert.equal(differentPortRequests, 0, 'the same IP does not authorize another port to receive credentials');
  assert.equal(allowedRequests, 0);
  assert.equal(await (await fetchHub(hubUrl)).text(), 'allowed');
  assert.equal(allowedRequests, 1); assert.equal(differentPortRequests, 0);
});

test('pinned fetch backpressures large responses instead of buffering the whole stream', async t => {
  const { profile, cert, key } = await fixture(t); let written = 0;
  const total = 64 * 1024 * 1024; const chunk = Buffer.alloc(64 * 1024, 65);
  let closed!: () => void; const serverClosed = new Promise<void>(resolve => { closed = resolve; });
  const server = createServer({ cert, key }, (_request, response) => {
    response.on('close', closed);
    const pump = () => {
      while (!response.destroyed && written < total) {
        written += chunk.length;
        if (!response.write(chunk)) { response.once('drain', pump); return; }
      }
      if (written === total) response.end();
    };
    pump();
  });
  const hubUrl = await listen(t, server); const fetchHub = createHubFetch({ ...profile, hubUrl });
  const response = await fetchHub(hubUrl);
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.ok(written < total, 'an unread response must stop its producer before the entire payload is buffered');
  await response.body!.cancel(); await serverClosed;
});

test('Relay uses the same certificate pin for an authenticated WSS handshake', async t => {
  const { profile, cert, key } = await fixture(t);
  const server = createServer({ cert, key }); const hubUrl = await listen(t, server);
  const wss = new WebSocketServer({ server }); let authorized = false;
  wss.on('connection', (socket, request) => { authorized = request.headers.authorization === 'Bearer relay-test'; socket.on('message', data => { if (JSON.parse(data.toString()).type === 'hello') socket.send(JSON.stringify({ v: 1, type: 'welcome', sourceId: 'source-test', fence: 1 })); }); });
  t.after(() => { for (const socket of wss.clients) socket.terminate(); wss.close(); });
  const relay = await createRelay({ hubUrl, hubCertificate: profile.certificatePem, sourceId: 'source-test', nodeId: 'node-test', token: 'relay-test', dbPath: ':memory:', policy: policySchema.parse({ models: ['mock-codex'] }), adapter: new MockAdapter() });
  t.after(() => relay.close()); await relay.waitUntilReady(); assert.equal(authorized, true); assert.equal(relay.snapshot().connected, true);
  await assert.rejects(createRelay({ hubUrl: 'http://127.0.0.1:4387', hubCertificate: profile.certificatePem, sourceId: 'source-test', nodeId: 'node-test', token: 'relay-test', dbPath: ':memory:', policy: policySchema.parse({ models: ['mock-codex'] }), adapter: new MockAdapter() }), /HTTPS/);
});

test('Relay rejects a different WSS leaf before any HTTP upgrade or credential reaches the server', async t => {
  const { profile, key, certificate } = await fixture(t);
  const different = await certificate('wss-replacement-with-same-key');
  let upgrades = 0; let requests = 0; let tlsFailures = 0;
  const server = createServer({ cert: different, key }, (_request, response) => { requests++; response.end('must not receive credentials'); });
  server.on('upgrade', (_request, socket) => { upgrades++; socket.destroy(); });
  server.on('tlsClientError', () => { tlsFailures++; });
  const hubUrl = await listen(t, server);
  const relay = await createRelay({ hubUrl, hubCertificate: profile.certificatePem, sourceId: 'source-test', nodeId: 'node-test', token: 'wss-secret-must-not-leak', dbPath: ':memory:', policy: policySchema.parse({ models: ['mock-codex'] }), adapter: new MockAdapter() });
  t.after(() => relay.close());
  await assert.rejects(relay.waitUntilReady(), /valid welcome within 10 seconds/);
  assert.ok(tlsFailures > 0, 'the relay attempted a real TLS handshake and rejected the certificate');
  assert.equal(upgrades, 0, 'TLS rejection precedes the HTTP upgrade carrying the relay credential');
  assert.equal(requests, 0); assert.equal(relay.snapshot().connected, false);
  await relay.close();
});
