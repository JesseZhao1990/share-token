/** Optional real-CLI canary against a synthetic upstream. No provider account is used. */
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHub } from '../apps/hub/index.js';
import { createRelay } from '../apps/relay/index.js';
import { codexOverrides } from '../apps/cli/profile.js';
import { MockAdapter } from '../packages/upstream/index.js';
import { policySchema } from '../packages/protocol/index.js';
import { randomToken } from '../packages/protocol/security.js';

const dir = await mkdtemp(join(tmpdir(), 'share-codex-canary-'));
const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken: randomToken(), port: 0 });
let relay: Awaited<ReturnType<typeof createRelay>> | undefined;
try {
  const version = execFileSync('codex', ['--version'], { encoding: 'utf8' }).trim();
  const owner = hub.store.listMembers()[0]!;
  const policy = policySchema.parse({ allowedMemberIds: [owner.id], models: ['mock-codex'] });
  const source = hub.store.createSource({ ownerId: owner.id, name: 'CLI canary', accountBinding: 'mock:canary', kind: 'mock', policy });
  const relayCredential = hub.store.issueCredential('relay', owner.id, { sourceId: source.id });
  const grant = hub.store.createGrant({ memberId: owner.id, sourceId: source.id, label: 'CLI canary', models: policy.models });
  const access = hub.store.issueCredential('grant', owner.id, { grantId: grant.id });
  const marker = 'SHARE_TOKEN_MOCK_CANARY_OK';
  const adapter = new MockAdapter({ accountBinding: source.accountBinding, models: policy.models, text: marker });
  relay = await createRelay({ hubUrl: hub.url, token: relayCredential.token, sourceId: source.id, nodeId: 'canary', dbPath: join(dir, 'relay.sqlite'), policy, adapter });
  await relay.waitUntilReady();
  const args = ['exec', '--strict-config', '--ignore-user-config', '--ephemeral', '--skip-git-repo-check', '--json', '-s', 'read-only', '-C', dir,
    ...codexOverrides(hub.url + '/v1', 'mock-codex').flatMap(value => ['-c', value]), 'Return the synthetic fixture text. No tools are needed.'];
  const child = spawn('codex', args, { env: { ...process.env, SHARE_TOKEN_ACCESS_KEY: access.token }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '', errors = '';
  child.stdout.on('data', bytes => { output = (output + bytes.toString()).slice(-128 * 1024); });
  child.stderr.on('data', bytes => { errors = (errors + bytes.toString()).slice(-128 * 1024); });
  const timer = setTimeout(() => child.kill('SIGTERM'), 60_000);
  const code = await new Promise<number | null>((resolveExit, reject) => { child.once('error', reject); child.once('close', resolveExit); }).finally(() => clearTimeout(timer));
  assert.equal(code, 0, 'Codex synthetic canary failed: ' + (output + '\n' + errors.slice(-2000)).replaceAll(access.token, '[redacted]'));
  assert.match(output, new RegExp(marker));
  assert.equal(adapter.calls, 1, 'Unexpected retry or additional upstream request');
  assert.equal(hub.store.listRequests()[0]?.state, 'COMPLETED');
  const evidence = { testedAt: new Date().toISOString(), client: version, adapter: 'mock', realProviderRequests: 0, upstreamFixtureCalls: adapter.calls,
    execution: hub.store.listRequests()[0]?.state, delivery: hub.store.listRequests()[0]?.delivery,
    checks: ['native CLI provider override with strict config validation', 'HTTP to Hub', 'outbound WebSocket Relay (loopback WS)', 'SSE final text', 'one upstream call on the successful path'],
    limitations: ['text-only CLI canary', 'no real subscription inference', 'no IDE or desktop app validation', 'no native CLI tool or compact validation', 'Codex may retry failures despite provider retry settings'] };
  await mkdir(resolve('artifacts'), { recursive: true });
  await writeFile(resolve('artifacts/codex-canary.json'), JSON.stringify(evidence, null, 2) + '\n');
  process.stdout.write(JSON.stringify(evidence, null, 2) + '\n');
} finally { await relay?.close(); await hub.close(); await rm(dir, { recursive: true, force: true }); }
