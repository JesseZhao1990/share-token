import assert from 'node:assert/strict';
import { chmod, cp, lstat, mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { prepareData } from '../deploy/hub/start.mjs';
import { createHub } from '../dist/apps/hub/index.js';

const temporary = await mkdtemp(join(tmpdir(), 'share-token-deployment-'));
let hub;
try {
  const data = join(temporary, 'data');
  const input = join(temporary, 'shared-code.txt');
  await writeFile(input, '48271936\n', { mode: 0o444 });
  const first = await prepareData(data, input);
  assert.match(first.adminToken, /^st_admin_[A-Za-z0-9_-]{43}$/);
  assert.equal((await lstat(join(data, 'admin.token'))).mode & 0o777, 0o600);
  assert.equal((await lstat(data)).mode & 0o777, 0o700);
  assert.equal((await lstat(first.sharedCodePath)).mode & 0o777, 0o600);
  const verifier = await readFile(first.sharedCodePath, 'utf8');
  assert.equal(verifier.includes('48271936'), false);
  hub = await createHub({ ...first, host: '127.0.0.1', port: 0 });
  const originalMeta = await (await fetch(hub.url + '/client/v2/meta')).json();
  assert.equal(originalMeta.pairing.sharedCodeAvailable, true);
  assert.equal((await fetch(hub.url + '/control/session', { headers: { Authorization: `Bearer ${first.adminToken}` } })).status, 200);
  await hub.close(); hub = undefined;
  // Simulate an unclean container exit whose PID will be reused on restart.
  const db = new DatabaseSync(first.dbPath);
  db.prepare('INSERT OR REPLACE INTO hub_runtime VALUES(1,?,?)').run(process.pid, 'stale-container');
  db.close();
  await chmod(input, 0o600);
  await writeFile(input, '72849316\n');
  const second = await prepareData(data, input);
  assert.equal(second.adminToken, first.adminToken);
  assert.equal(await readFile(second.sharedCodePath, 'utf8'), verifier);
  hub = await createHub({ ...second, host: '127.0.0.1', port: 0 });
  const restartedMeta = await (await fetch(hub.url + '/client/v2/meta')).json();
  assert.equal(restartedMeta.hubId, originalMeta.hubId);
  await hub.close(); hub = undefined;
  // Copy the entire stopped ledger, like the documented offline backup.
  const restoredData = join(temporary, 'restored');
  await cp(data, restoredData, { recursive: true, errorOnExist: true, force: false });
  const restored = await prepareData(restoredData);
  assert.equal(restored.adminToken, first.adminToken);
  hub = await createHub({ ...restored, host: '127.0.0.1', port: 0 });
  const restoredMeta = await (await fetch(hub.url + '/client/v2/meta')).json();
  assert.equal(restoredMeta.hubId, originalMeta.hubId);
  assert.equal(restoredMeta.pairing.sharedCodeAvailable, true);
  await hub.close(); hub = undefined;
  await unlink(join(data, 'admin.token'));
  await assert.rejects(prepareData(data), /missing admin.token/);
  await writeFile(input, 'invalid\n');
  await assert.rejects(prepareData(join(temporary, 'invalid-input'), input), /eight digits/);
  console.log('Hub deployment checks passed: private initialization, persistent identity, restart recovery, full offline restore, verifier preservation and incomplete-restore rejection.');
} finally {
  if (hub) await hub.close();
  await rm(temporary, { recursive: true, force: true });
}
