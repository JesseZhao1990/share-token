import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { PrivateStore } from '../packages/platform/private-store.js';

test('desktop secret store persists only encrypted bytes atomically and refuses unavailable OS storage', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'desktop-secret-')); const path = join(dir, 'secret'); const key = randomBytes(32);
  let available = true;
  const store = new PrivateStore(path, { available: () => available, encrypt(text) { const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, iv); const bytes = Buffer.concat([cipher.update(text), cipher.final()]); return Buffer.concat([iv, cipher.getAuthTag(), bytes]); }, decrypt(bytes) { const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12)); decipher.setAuthTag(bytes.subarray(12, 28)); return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString(); } });
  try {
    assert.equal(await store.read(), null); await store.write({ refreshToken: 'CANARY_DESKTOP_SECRET' });
    assert.equal((await readFile(path)).includes(Buffer.from('CANARY_DESKTOP_SECRET')), false);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.deepEqual(await store.read(), { refreshToken: 'CANARY_DESKTOP_SECRET' });
    available = false; await assert.rejects(store.write({ refreshToken: 'replacement' })); await assert.rejects(store.read());
    available = true; assert.deepEqual(await store.read(), { refreshToken: 'CANARY_DESKTOP_SECRET' });
    await store.clear(); assert.equal(await store.read(), null);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
