import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { runTestOpenSSL } from './fixtures/openssl.js';
import { X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateHubTrustProfile } from '../packages/hub-client/trust.js';

const { readDesktopHubProfile } = await import(new URL('../scripts/desktop-profile.mjs', import.meta.url).href);

async function fixture(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), 'share-token-desktop-profile-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const certPath = join(directory, 'server.pem');
  const keyPath = join(directory, 'server.key');
  runTestOpenSSL(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', keyPath, '-out', certPath,
    '-subj', '/CN=10.20.30.40', '-addext', 'subjectAltName=IP:10.20.30.40', '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment', '-addext', 'extendedKeyUsage=serverAuth']);
  const certificatePem = await readFile(certPath, 'utf8');
  const profile = { version: 1, hubUrl: 'https://10.20.30.40', certificatePem, label: 'Desktop fixture' };
  const file = join(directory, 'public.connection.json');
  await writeFile(file, JSON.stringify(profile));
  return { directory, file, profile, keyPath };
}

test('generic desktop packages may omit the profile but friend builds fail when it is absent', async () => {
  assert.equal(await readDesktopHubProfile(validateHubTrustProfile), null);
  await assert.rejects(readDesktopHubProfile(validateHubTrustProfile, { args: ['--require-hub-profile'] }), /requires a public Hub profile/);
  for (const args of [['--hub-profile'], ['--hub-profile', '--require-hub-profile'], ['--hub-profile', 'one', '--hub-profile', 'two']]) {
    await assert.rejects(readDesktopHubProfile(validateHubTrustProfile, { args }), /--hub-profile/);
  }
  await assert.rejects(readDesktopHubProfile(validateHubTrustProfile, { args: ['--hub-profile', '/nonexistent/share-token-profile.json'] }), /Cannot read/);
});

test('file and CI JSON profiles validate the certificate and return only canonical public fields', async t => {
  const { directory, profile } = await fixture(t);
  const fromFile = await readDesktopHubProfile(validateHubTrustProfile, { root: directory, args: ['--require-hub-profile', '--hub-profile', 'public.connection.json'] });
  assert.deepEqual(fromFile, profile);
  const fromJson = await readDesktopHubProfile(validateHubTrustProfile, {
    args: ['--require-hub-profile'], env: { SHARE_TOKEN_HUB_PROFILE_JSON: JSON.stringify({ ...profile, hubUrl: profile.hubUrl + ':443/' }) },
  });
  assert.deepEqual(fromJson, profile);
  assert.equal('fingerprint256' in fromJson, false);
  const { label: _label, ...withoutLabel } = profile;
  assert.deepEqual(await readDesktopHubProfile(validateHubTrustProfile, { env: { SHARE_TOKEN_HUB_PROFILE_JSON: JSON.stringify(withoutLabel) } }), withoutLabel);
});

test('conflicting profile sources and invalid JSON fail without exposing input values', async t => {
  const { file, profile } = await fixture(t);
  await assert.rejects(readDesktopHubProfile(validateHubTrustProfile, {
    args: ['--hub-profile', file], env: { SHARE_TOKEN_HUB_PROFILE_JSON: JSON.stringify(profile) },
  }), /not both/);
  for (const value of ['', ' ', '{"token":"secret-do-not-log",', 'x'.repeat(65537), 'null', '[]']) {
    await assert.rejects(readDesktopHubProfile(validateHubTrustProfile, { env: { SHARE_TOKEN_HUB_PROFILE_JSON: value } }), error => {
      assert.ok(error instanceof Error); assert.doesNotMatch(error.message, /secret-do-not-log/); return true;
    });
  }
});

test('private keys, credentials and all unknown fields are rejected for file and CI inputs', async t => {
  const { file, profile, keyPath } = await fixture(t);
  for (const key of ['privateKey', 'token', 'joinCode', 'sharedCode', 'credentials', 'fingerprint256', 'unexpected']) {
    const value = JSON.stringify({ ...profile, [key]: 'secret-do-not-log' });
    await writeFile(file, value);
    for (const options of [{ args: ['--hub-profile', file] }, { env: { SHARE_TOKEN_HUB_PROFILE_JSON: value } }]) {
      await assert.rejects(readDesktopHubProfile(validateHubTrustProfile, options), error => {
        assert.ok(error instanceof Error); assert.match(error.message, /only version/); assert.doesNotMatch(error.message, /secret-do-not-log/); return true;
      });
    }
  }
  const privateKey = await readFile(keyPath, 'utf8');
  for (const certificatePem of [privateKey, profile.certificatePem + privateKey, 'invalid certificate']) {
    await assert.rejects(readDesktopHubProfile(validateHubTrustProfile, { env: { SHARE_TOKEN_HUB_PROFILE_JSON: JSON.stringify({ ...profile, certificatePem }) } }), /公开证书/);
  }
});

test('invalid Hub addresses, certificate SAN mismatches and expired certificates cannot be bundled', async t => {
  const { profile } = await fixture(t);
  for (const hubUrl of ['http://10.20.30.40', 'https://example.test', 'https://10.20.30.41']) {
    await assert.rejects(readDesktopHubProfile(validateHubTrustProfile, { env: { SHARE_TOKEN_HUB_PROFILE_JSON: JSON.stringify({ ...profile, hubUrl }) } }));
  }
  const x509 = new X509Certificate(profile.certificatePem);
  t.mock.method(Date, 'now', () => Date.parse(x509.validTo) + 1000);
  await assert.rejects(readDesktopHubProfile(validateHubTrustProfile, { env: { SHARE_TOKEN_HUB_PROFILE_JSON: JSON.stringify(profile) } }), /过期/);
});
