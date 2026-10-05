import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createLocalSecretCipher, isLocalSecretCiphertext, LOCAL_SECRET_KEY_FILENAME } from '../packages/platform/local-secret.js';
import { PrivateStore } from '../packages/platform/private-store.js';

async function temporary() { return mkdtemp(join(await realpath(tmpdir()), 'share-local-secret-')); }
const exec = promisify(execFile);

test('local cipher stores only authenticated ciphertext and survives a real process restart without keychain APIs', async () => {
  const dir = await temporary(), keyDir = join(dir, 'local-secrets'), storePath = join(dir, 'credentials');
  try {
    const cipher = await createLocalSecretCipher(keyDir), store = new PrivateStore(storePath, cipher);
    assert.equal(cipher.available(), true);
    const fixture = { refreshToken: 'LOCAL_SECRET_CANARY', label: '朋友的电脑 🔐' };
    await store.write(fixture); const disk = await readFile(storePath);
    assert.equal(isLocalSecretCiphertext(disk), true); assert.equal(disk.includes(Buffer.from(fixture.refreshToken)), false); assert.deepEqual(await store.read(), fixture);
    const key = await readFile(join(keyDir, LOCAL_SECRET_KEY_FILENAME)); assert.equal(key.includes(Buffer.from(fixture.refreshToken)), false);
    assert.equal((await stat(keyDir)).mode & 0o777, 0o700); assert.equal((await stat(join(keyDir, LOCAL_SECRET_KEY_FILENAME))).mode & 0o777, 0o600);
    const script = `import { createLocalSecretCipher } from './packages/platform/local-secret.ts';
      import { PrivateStore } from './packages/platform/private-store.ts';
      const cipher = await createLocalSecretCipher(process.argv[1]);
      const value = await new PrivateStore(process.argv[2], cipher).read();
      process.stdout.write(JSON.stringify({available:cipher.available(),same:value.refreshToken==='LOCAL_SECRET_CANARY',label:value.label}));`;
    const child = await exec(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script, keyDir, storePath], { cwd: resolve('.') });
    assert.deepEqual(JSON.parse(child.stdout), { available: true, same: true, label: fixture.label });
    assert.deepEqual(await readFile(join(keyDir, LOCAL_SECRET_KEY_FILENAME)), key, 'Reopening must preserve the exact existing key');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('cipher uses fresh nonces and rejects tampered headers, IVs, tags, bodies, wrong keys and truncated payloads', async () => {
  const dir = await temporary(); try {
    const cipher = await createLocalSecretCipher(join(dir, 'one')), other = await createLocalSecretCipher(join(dir, 'two'));
    const encrypted = cipher.encrypt('private-value'); assert.notDeepEqual(cipher.encrypt('private-value'), encrypted); assert.equal(cipher.decrypt(encrypted), 'private-value');
    assert.equal(cipher.decrypt(cipher.encrypt('')), '');
    for (const offset of [0, 4, 5, 16, 17, 32, encrypted.length - 1]) {
      const damaged = Buffer.from(encrypted); damaged[offset] = damaged[offset]! ^ 1;
      assert.throws(() => cipher.decrypt(damaged), { code: 'LOCAL_SECRET_DECRYPT_FAILED' });
    }
    for (const damaged of [Buffer.alloc(0), encrypted.subarray(0, 32), encrypted.subarray(0, encrypted.length - 1), Buffer.concat([encrypted, Buffer.from([0])]), Buffer.from('legacy-keychain-data')]) assert.throws(() => cipher.decrypt(damaged), { code: 'LOCAL_SECRET_DECRYPT_FAILED' });
    assert.throws(() => other.decrypt(encrypted), { code: 'LOCAL_SECRET_DECRYPT_FAILED' });
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('concurrent first-time creators all retain one key and decrypt one another', async () => {
  const dir = await temporary(); try {
    const keyDir = join(dir, 'nested', 'local-secrets');
    const ciphers = await Promise.all(Array.from({ length: 24 }, () => createLocalSecretCipher(keyDir)));
    const key = await readFile(join(keyDir, LOCAL_SECRET_KEY_FILENAME));
    for (const [index, cipher] of ciphers.entries()) { const payload = cipher.encrypt(`device-${index}`); for (const peer of ciphers) assert.equal(peer.decrypt(payload), `device-${index}`); }
    await createLocalSecretCipher(keyDir); assert.deepEqual(await readFile(join(keyDir, LOCAL_SECRET_KEY_FILENAME)), key);
    assert.equal((await stat(join(dir, 'nested'))).mode & 0o777, 0o700);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('damaged existing key fails closed without replacing or modifying its bytes', async () => {
  const dir = await temporary(); try {
    const keyDir = join(dir, 'local-secrets'); await createLocalSecretCipher(keyDir); const keyPath = join(keyDir, LOCAL_SECRET_KEY_FILENAME), valid = await readFile(keyPath);
    const changed = Buffer.from(valid); changed[12] = changed[12]! ^ 1;
    for (const damaged of [changed, Buffer.from('broken-key'), Buffer.alloc(0), Buffer.concat([valid, Buffer.from([0])])]) {
      await writeFile(keyPath, damaged); await assert.rejects(createLocalSecretCipher(keyDir), { code: 'LOCAL_SECRET_KEY_INVALID' }); assert.deepEqual(await readFile(keyPath), damaged);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('broad directory or key permissions are rejected without silently changing permissions', async () => {
  const dir = await temporary(); try {
    const keyDir = join(dir, 'local-secrets'); await createLocalSecretCipher(keyDir); const keyPath = join(keyDir, LOCAL_SECRET_KEY_FILENAME), key = await readFile(keyPath);
    await chmod(keyDir, 0o755); await assert.rejects(createLocalSecretCipher(keyDir), { code: 'LOCAL_SECRET_PATH_UNSAFE' }); assert.equal((await stat(keyDir)).mode & 0o777, 0o755);
    await chmod(keyDir, 0o700); await chmod(keyPath, 0o644); await assert.rejects(createLocalSecretCipher(keyDir), { code: 'LOCAL_SECRET_PATH_UNSAFE' }); assert.equal((await stat(keyPath)).mode & 0o777, 0o644); assert.deepEqual(await readFile(keyPath), key);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('key and directory symlinks are rejected without touching their targets', async () => {
  const dir = await temporary(); try {
    const actual = join(dir, 'actual'), cipher = await createLocalSecretCipher(actual), keyPath = join(actual, LOCAL_SECRET_KEY_FILENAME), original = await readFile(keyPath);
    const linked = join(dir, 'linked'); await symlink(actual, linked);
    await assert.rejects(createLocalSecretCipher(linked), { code: 'LOCAL_SECRET_PATH_UNSAFE' });
    await assert.rejects(createLocalSecretCipher(join(linked, 'nested')), { code: 'LOCAL_SECRET_PATH_UNSAFE' });
    const hostileDir = join(dir, 'hostile'); await createLocalSecretCipher(hostileDir); await rm(join(hostileDir, LOCAL_SECRET_KEY_FILENAME)); await symlink(keyPath, join(hostileDir, LOCAL_SECRET_KEY_FILENAME));
    await assert.rejects(createLocalSecretCipher(hostileDir), { code: 'LOCAL_SECRET_PATH_UNSAFE' }); assert.deepEqual(await readFile(keyPath), original);
    assert.equal(cipher.decrypt(cipher.encrypt('still-valid')), 'still-valid');
  } finally { await rm(dir, { recursive: true, force: true }); }
});
