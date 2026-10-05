import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHub } from '../apps/hub/index.js';
import { createRelay } from '../apps/relay/index.js';
import { MockAdapter, type MockOptions } from '../packages/upstream/index.js';
import { policySchema, type Source, type Grant, type Member } from '../packages/protocol/index.js';

async function fixture(options: MockOptions = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'share-integration-'));
  const adminToken = 'test_admin_abcdefghijklmnopqrstuvwxyz';
  const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken, port: 0 });
  async function control<T>(path: string, body?: unknown, token = adminToken, method = body === undefined ? 'GET' : 'POST'): Promise<T> {
    const response = await fetch(hub.url + path, { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    assert.equal(response.ok, true, `${path}: ${response.status} ${response.ok ? '' : await response.text()}`);
    return response.json() as Promise<T>;
  }
  const { member: owner } = await control<{ member: Member }>('/control/session');
  const invite = await control<{ token: string }>('/control/invitations', {});
  const friend = await control<{ member: Member; token: string }>('/control/invitations/redeem', { token: invite.token, name: '朋友' });
  const policy = policySchema.parse({ allowedMemberIds: [owner.id, friend.member.id], models: ['mock-codex'] });
  const { source, relayToken } = await control<{ source: Source; relayToken: string }>('/control/sources', { name: '集成模拟来源', kind: 'mock', accountBinding: 'mock:integration', policy });
  const own = await control<{ grant: Grant; token: string }>('/control/grants', { sourceId: source.id, label: 'owner', models: policy.models });
  const other = await control<{ grant: Grant; token: string }>('/control/grants', { sourceId: source.id, label: 'friend', models: policy.models }, friend.token);
  const adapter = new MockAdapter({ ...options, accountBinding: source.accountBinding, models: policy.models });
  const relay = await createRelay({ hubUrl: hub.url, token: relayToken, sourceId: source.id, nodeId: 'integration-node', dbPath: join(dir, 'relay.sqlite'), policy, adapter });
  await relay.waitUntilReady();
  const request = (token: string, body: Record<string, unknown> = {}, operation = 'responses') => fetch(hub.url + '/v1/' + operation, {
    method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-codex', input: 'private-prompt-never-persist-me', ...body }),
  });
  return { dir, hub, relay, adapter, source, own, other, friend, control, request,
    async close() { await relay.close(); await hub.close(); await rm(dir, { recursive: true, force: true }); } };
}

test('HTTP + WebSocket round trip isolates response history and never journals prompt/response bodies', async () => {
  const f = await fixture({ text: 'private-response-never-persist-me' });
  try {
    const first = await f.request(f.own.token);
    assert.equal(first.status, 200);
    const result = await first.json() as { id: string; output: { id: string }[] };
    assert.ok(result.id);
    const next = await f.request(f.own.token, { previous_response_id: result.id, stream: true });
    const stream = await next.text();
    assert.equal(next.status, 200); assert.match(stream, /response.completed/);
    assert.match(stream, /private-response-never-persist-me/);
    const cross = await f.request(f.other.token, { previous_response_id: result.id });
    assert.equal(cross.status, 403); assert.equal(f.adapter.calls, 2);
    const refs = await f.request(f.other.token, { input: [{ type: 'item_reference', id: result.output[0]!.id }] });
    assert.equal(refs.status, 403); assert.equal(f.adapter.calls, 2);
    const compact = await f.request(f.own.token, {}, 'responses/compact');
    assert.equal(compact.status, 200); assert.equal((await compact.json() as { object: string }).object, 'response.compaction');
    assert.equal(f.hub.store.listRequests().length, 3);
    assert.ok(f.hub.store.listRequests().every(row => row.state === 'COMPLETED'));
    f.hub.store.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    for (const file of ['hub.sqlite', 'relay.sqlite']) {
      const bytes = await readFile(join(f.dir, file));
      for (const secret of ['private-prompt-never-persist-me', 'private-response-never-persist-me', f.own.token, f.other.token]) assert.equal(bytes.includes(Buffer.from(secret)), false, `${file} leaked body or credential`);
    }
  } finally { await f.close(); }
});

test('consumer executes the fixture tool locally and returns its result through a pinned grant', async () => {
  const f = await fixture({ toolName: 'read_fixture' });
  try {
    const tools = [{ type: 'function', name: 'read_fixture', parameters: { type: 'object', properties: {} } }];
    const response = await f.request(f.own.token, { tools });
    const first = await response.json() as { id: string; output: { type: string; name: string; call_id: string }[] };
    assert.equal(first.output[0]!.type, 'function_call'); assert.equal(first.output[0]!.name, 'read_fixture');
    // The client fixture executes this operation; neither Hub nor Relay has a tool runner.
    const localResult = 'fixture file contents from the consumer';
    const second = await f.request(f.own.token, { tools, previous_response_id: first.id, input: [{ type: 'function_call_output', call_id: first.output[0]!.call_id, output: localResult }] });
    assert.equal(second.status, 200); assert.match(await second.text(), /received the consumer-side tool result/);
    assert.equal(f.adapter.calls, 2);
  } finally { await f.close(); }
});

test('truncated upstream stream freezes the source and prevents automatic replay', async () => {
  const f = await fixture({ mode: 'truncate', delayMs: 2 });
  try {
    const response = await f.request(f.own.token, { stream: true });
    await response.text().catch(() => 'transport aborted');
    assert.equal(f.hub.store.listRequests()[0]!.state, 'UNKNOWN');
    assert.equal(f.hub.store.getSource(f.source.id)!.frozen, true);
    const retry = await f.request(f.other.token);
    assert.equal(retry.status, 409); assert.equal(f.adapter.calls, 1);
  } finally { await f.close(); }
});

test('pause and credential revocation reject before touching the upstream', async () => {
  const f = await fixture();
  try {
    await f.control(`/control/sources/${f.source.id}/pause`, { paused: true });
    assert.equal((await f.request(f.own.token)).status, 503);
    await f.control(`/control/sources/${f.source.id}/pause`, { paused: false });
    await f.control(`/control/grants/${f.own.grant.id}`, undefined, undefined, 'DELETE');
    assert.equal((await f.request(f.own.token)).status, 403);
    assert.equal(f.adapter.calls, 0);
  } finally { await f.close(); }
});
