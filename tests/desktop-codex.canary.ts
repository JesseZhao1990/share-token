/** Manual native CLI → desktop Bridge → Hub v2 → DonorController → synthetic SSE canary.
 * Run with the bundled Node 24: node_modules/node/bin/node --import tsx tests/desktop-codex.canary.ts
 * This never loads provider credentials or calls a paid/subscription model.
 */
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createHub } from '../apps/hub/index.js';
import { codexOverrides } from '../apps/cli/profile.js';
import { HubClient } from '../packages/hub-client/index.js';
import { createConsumerBridge, detectCodex, type ConsumerBridge } from '../packages/client-core/consumer.js';
import { DonorController } from '../packages/client-core/donor.js';
import { MockAdapter } from '../packages/upstream/index.js';
import { policySchema, type Grant } from '../packages/protocol/index.js';
import { randomToken } from '../packages/protocol/security.js';
import type { ClientRequest, ClientSession, RunLeaseResponse } from '../packages/protocol/client.js';

const dir = await mkdtemp(join(tmpdir(), 'share-desktop-codex-'));
const admin = randomToken();
const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: admin, port: 0 });
const client = new HubClient({ baseUrl: hub.url });
let donor: DonorController | undefined;
let bridge: ConsumerBridge | undefined;
let run: RunLeaseResponse | undefined;
let child: ChildProcess | undefined;
const marker = 'DESKTOP_NATIVE_CODEX_MOCK_OK';
const reportPath = resolve('artifacts/desktop-evidence/native-codex.json');
const secrets = [admin];
const redact = (text: string) => secrets.reduce((value, secret) => value.split(secret).join('[redacted]'), text);
try {
  const installation = (await detectCodex())[0];
  assert.ok(installation, 'Install an official Codex CLI in a supported location before running this optional canary.');
  const login = await fetch(`${hub.url}/control/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: admin }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie')!.split(';')[0]!;
  const browser = await login.json() as { csrfToken: string };
  const pairing = await client.startPairing({ deviceName: 'Native CLI canary', platform: process.platform, clientVersion: '0.2.0-canary', requestedScopes: ['consumer', 'donor'] });
  const approved = await fetch(`${hub.url}/control/v2/device-pairings/${encodeURIComponent(pairing.userCode)}/approve`, { method: 'POST', headers: { cookie, 'x-csrf-token': browser.csrfToken, 'content-type': 'application/json' }, body: JSON.stringify({ approvedScopes: ['consumer', 'donor'] }) });
  assert.equal(approved.status, 200);
  await delay(pairing.interval * 1000 + 20);
  const paired = await client.pollPairing(); assert.equal(paired.status, 'approved');
  const credentials = client.getCredentials()!; secrets.push(credentials.accessToken, credentials.refreshToken);
  const policy = policySchema.parse({ models: ['mock-codex'], allowedMemberIds: [credentials.memberId] });
  let adapter: MockAdapter | undefined;
  donor = new DonorController({ stateDir: join(dir, 'donor'), hub: client, adapterFactory: config => {
    adapter = new MockAdapter({ accountBinding: config.accountBinding, models: config.policy.models, text: marker }); return adapter;
  } });
  const configured = await donor.configure({ name: 'Native CLI synthetic source', kind: 'mock', policy });
  const started = await donor.start(); assert.equal(started.status, 'sharing');
  const { grant } = await client.request<{ grant: Grant }>('POST', '/client/v2/grants', { sourceId: configured.config!.sourceId, label: 'Native CLI canary', models: policy.models });
  const { session } = await client.request<{ session: ClientSession }>('POST', '/client/v2/sessions', { grantId: grant.id, modelScope: policy.models });
  run = await client.request<RunLeaseResponse>('POST', `/client/v2/sessions/${session.id}/leases`, {}); secrets.push(run.token);
  const bridgeEvents: string[] = [];
  bridge = await createConsumerBridge({ hub: client, sessionId: session.id, leaseId: run.lease.id, model: 'mock-codex', getLeaseToken: async () => run!.token, onEvent: event => bridgeEvents.push(event.type) });
  secrets.push(bridge.localKey);
  const codexHome = join(dir, 'isolated-codex-home'); await mkdir(codexHome, { recursive: true, mode: 0o700 });
  const args = ['exec', '--strict-config', '--ignore-user-config', '--ephemeral', '--skip-git-repo-check', '--json', '-s', 'read-only', '-C', dir,
    ...codexOverrides(bridge.url, 'mock-codex').flatMap(value => ['-c', value]), 'Return the synthetic fixture text. No tools are needed.'];
  // Allowlist the child environment. In particular no account auth, refresh token or Hub lease is inherited.
  child = spawn(installation.path, args, { env: { PATH: `${dirname(process.execPath)}:/usr/bin:/bin:/usr/sbin:/sbin`, HOME: process.env.HOME,
    LANG: 'en_US.UTF-8', TERM: 'xterm-256color', CODEX_HOME: codexHome, SHARE_TOKEN_ACCESS_KEY: bridge.localKey }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '', diagnostics = '';
  child.stdout!.on('data', bytes => { output = (output + bytes.toString()).slice(-128 * 1024); });
  child.stderr!.on('data', bytes => { diagnostics = (diagnostics + bytes.toString()).slice(-128 * 1024); });
  const timer = setTimeout(() => child?.kill('SIGTERM'), 60_000);
  const exited = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolveExit, reject) => {
    child!.once('error', reject); child!.once('close', (code, signal) => resolveExit({ code, signal }));
  }).finally(() => clearTimeout(timer));
  assert.equal(exited.code, 0, `Native CLI did not complete: ${redact(diagnostics.slice(-3000))}`);
  assert.ok(output.includes(marker), `The native CLI did not receive the fixture final text: ${redact(diagnostics.slice(-1500))}`);
  const deadline = Date.now() + 5000;
  while (bridge.snapshot().active || bridge.snapshot().pendingDeliveryAcks) { assert.ok(Date.now() < deadline, 'Consumer delivery ACK did not settle'); await delay(20); }
  const { requests } = await client.request<{ requests: ClientRequest[] }>('GET', '/client/v2/requests');
  const own = requests.filter(request => request.sessionId === session.id);
  assert.equal(adapter!.calls, 1, 'Successful native text canary must use exactly one synthetic upstream call');
  assert.equal(own.length, 1); assert.equal(own[0]!.state, 'COMPLETED'); assert.equal(own[0]!.consumerDelivery, 'transport_finished');
  assert.equal(bridge.snapshot().blocked, false); assert.ok(bridgeEvents.includes('request.finished'));
  const evidence = {
    testedAt: new Date().toISOString(), success: true, client: 'native Codex CLI exec', clientVersion: installation.version,
    platform: process.platform, arch: process.arch, nodeVersion: process.version,
    adapter: 'mock', realProviderRequests: 0, upstreamFixtureCalls: adapter!.calls, nativeProcessExitCode: exited.code,
    finalSyntheticTextReceived: true, isolatedCodexHome: true,
    request: { state: own[0]!.state, relayDelivery: own[0]!.delivery, consumerDelivery: own[0]!.consumerDelivery },
    bridge: bridge.snapshot(), donor: { status: donor.snapshot().status, policySync: donor.snapshot().policySync },
    checks: ['S256 device pairing approved through Hub browser control', 'DonorController policy ACK and temporary Relay lease', 'Native CLI strict provider config', 'Loopback Consumer Bridge local credential', 'Hub v2 fixed session and run lease', 'Donor outbound Relay SSE', 'Native final text and process completion', 'Hub consumer delivery ACK after local HTTP finish'],
    limitations: ['Synthetic text only; no real subscription or paid API inference', 'No native tool-loop, compaction, multi-agent or history resume claim', 'Official Codex desktop App and IDE connector remain unverified', 'This exec canary does not replace the interactive PTY and Electron UI acceptance'],
  };
  const serialized = JSON.stringify(evidence, null, 2) + '\n';
  for (const secret of secrets) assert.equal(serialized.includes(secret), false, 'Evidence must not contain a credential');
  await mkdir(dirname(reportPath), { recursive: true }); await writeFile(reportPath, serialized); process.stdout.write(serialized);
} finally {
  if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  await bridge?.close();
  if (run) await client.request('POST', `/client/v2/run-leases/${run.lease.id}/close`, {}).catch(() => undefined);
  await donor?.close(); await hub.close(); await rm(dir, { recursive: true, force: true });
}
