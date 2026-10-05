import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateProfile } from '../apps/cli/profile.js';
import { readSecret, writePrivate } from '../apps/cli/files.js';

test('profiles isolate provider settings without embedding secrets or weakening approvals', () => {
  const text = generateProfile('https://friends.example/v1', 'mock-codex');
  assert.match(text, /requires_openai_auth = false/);
  assert.match(text, /request_max_retries = 0/);
  assert.match(text, /web_search = "disabled"/);
  assert.match(text, /SHARE_TOKEN_ACCESS_KEY = "exclude"/);
  assert.doesNotMatch(text, /approval_policy|danger-full-access|auth\.json/);
  for (const url of ['http://remote.example/v1', 'https://user:password@host/v1', 'file:///etc/passwd', 'https://host/v1?token=a']) assert.throws(() => generateProfile(url, 'mock-codex'));
  assert.throws(() => generateProfile('https://host/v1', 'model"\nsecret=1'));
});
test('credential writer refuses overwrite and reader refuses world-readable files and symlinks', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'share-secrets-'));
  try {
    const file = join(dir, 'token');
    await writePrivate(file, 'st_test_abcdefghijklmnopqrstuvwxyz');
    assert.equal(await readSecret(file), 'st_test_abcdefghijklmnopqrstuvwxyz');
    await assert.rejects(writePrivate(file, 'replacement'));
    await symlink(file, join(dir, 'link'));
    await assert.rejects(readSecret(join(dir, 'link')));
    await chmod(file, 0o644);
    await assert.rejects(readSecret(file));
  } finally { await rm(dir, { recursive: true, force: true }); }
});
