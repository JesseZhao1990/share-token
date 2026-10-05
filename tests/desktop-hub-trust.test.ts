import test from 'node:test';
import assert from 'node:assert/strict';
import { runTestOpenSSL } from './fixtures/openssl.js';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { acceptsHubCertificate, acceptsHubUrl, assertSavedHubTrust, hubTrustDisplay, loadHubTrustProfile, readHubTrustFile, saveHubTrustProfile } from '../apps/desktop/main/hub-trust.js';
import type { HubTrustProfile } from '../packages/hub-client/trust.js';

async function fixture(t: { after(fn: () => Promise<void>): void }) {
  const directory = await mkdtemp(join(tmpdir(), 'share-desktop-hub-trust-'));
  t.after(() => rm(directory, { force: true, recursive: true }));
  const userData = join(directory, 'app'); await mkdir(userData, { mode: 0o700 });
  async function certificate(suffix: string, ip = '10.20.30.40') {
    const path = join(directory, suffix + '.pem');
    runTestOpenSSL(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', join(directory, suffix + '.key'), '-out', path,
      '-subj', '/CN=Share Token Test', '-addext', `subjectAltName=IP:${ip}`, '-addext', 'basicConstraints=critical,CA:FALSE',
      '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment', '-addext', 'extendedKeyUsage=serverAuth']);
    return readFile(path, 'utf8');
  }
  const profile: HubTrustProfile = { version: 1, hubUrl: 'https://10.20.30.40', certificatePem: await certificate('server'), label: 'Private test Hub' };
  return { directory, userData, certificate, profile };
}

test('desktop connection files are bounded, regular files and stored atomically with private permissions', async t => {
  const { directory, userData, profile } = await fixture(t);
  assert.equal(await loadHubTrustProfile(userData), null);
  const selected = join(directory, 'selected.json'); await writeFile(selected, JSON.stringify(profile));
  const imported = await readHubTrustFile(selected);
  const saved = await saveHubTrustProfile(userData, imported);
  assert.deepEqual(await loadHubTrustProfile(userData), saved);
  assert.equal((await lstat(join(userData, 'hub-trust/connection.json'))).mode & 0o777, 0o600);
  assert.equal((await lstat(join(userData, 'hub-trust'))).mode & 0o777, 0o700);
  const display = hubTrustDisplay(saved);
  assert.equal(display.fingerprint256, new X509Certificate(profile.certificatePem).fingerprint256);
  assert.equal('certificatePem' in display, false, 'Renderer receives only public connection summary, never raw import contents');
  const link = join(directory, 'linked.json'); await symlink(selected, link);
  await assert.rejects(readHubTrustFile(link), /符号链接/);
  const large = join(directory, 'large.json'); await writeFile(large, ' '.repeat(64 * 1024 + 1));
  await assert.rejects(readHubTrustFile(large), /64 KB/);
  await chmod(join(userData, 'hub-trust/connection.json'), 0o644);
  await assert.rejects(loadHubTrustProfile(userData), /权限/);
});

test('desktop trust persistence refuses link replacement and invalid profile rather than silently falling back', async t => {
  const { directory, userData, profile } = await fixture(t);
  await saveHubTrustProfile(userData, profile);
  const path = join(userData, 'hub-trust/connection.json');
  const original = await readFile(path, 'utf8');
  await assert.rejects(saveHubTrustProfile(userData, { ...profile, hubUrl: 'https://10.20.30.41' }), /SAN/);
  assert.equal(await readFile(path, 'utf8'), original);
  const outside = join(directory, 'outside.json'); await writeFile(outside, 'must remain unchanged');
  await rm(path); await symlink(outside, path);
  await assert.rejects(saveHubTrustProfile(userData, profile), /符号链接/);
  assert.equal(await readFile(outside, 'utf8'), 'must remain unchanged');
  await rm(path); await writeFile(path, '{ invalid', { mode: 0o600 });
  await assert.rejects(loadHubTrustProfile(userData));
});

test('isolated Hub browsing accepts only its exact leaf and origin, including port, on HTTPS or WSS', async t => {
  const { profile, certificate } = await fixture(t);
  const pem = profile.certificatePem;
  assert.equal(acceptsHubCertificate(profile, '10.20.30.40', pem), true);
  assert.equal(acceptsHubCertificate(profile, '10.20.30.41', pem), false);
  assert.equal(acceptsHubCertificate(profile, '10.20.30.40', await certificate('rotated')), false, 'Another otherwise valid certificate must fail the leaf pin');
  assert.equal(acceptsHubCertificate(profile, '10.20.30.40', 'not a certificate'), false);
  assert.equal(acceptsHubUrl(profile, profile.hubUrl + '/pair?code=123'), true);
  assert.equal(acceptsHubUrl(profile, 'wss://10.20.30.40/relay', true), true);
  for (const url of ['https://10.20.30.40:8443/', 'https://10.20.30.41/', 'http://10.20.30.40/', 'wss://10.20.30.40/', 'https://user:password@10.20.30.40/', 'file:///tmp/file', 'share://app/index.html', 'javascript:alert(1)', 'data:text/html,test']) assert.equal(acceptsHubUrl(profile, url), false, url);
  assert.equal(acceptsHubUrl(profile, 'wss://10.20.30.40:8443/', true), false);
  const fingerprint = hubTrustDisplay(profile).fingerprint256;
  assert.doesNotThrow(() => assertSavedHubTrust(profile.hubUrl, fingerprint, profile));
  assert.throws(() => assertSavedHubTrust(profile.hubUrl, fingerprint, null), /缺失或已改变/, 'Deleting the profile must not restore credentials using system trust');
  assert.throws(() => assertSavedHubTrust(profile.hubUrl, 'another pin', profile), /缺失或已改变/);
  const now = Date.now;
  try {
    Date.now = () => Date.parse(new X509Certificate(pem).validTo) + 1;
    assert.equal(acceptsHubCertificate(profile, '10.20.30.40', pem), false);
    assert.equal(acceptsHubUrl(profile, profile.hubUrl), false, 'Cached Chromium verification cannot enable requests after expiration');
  } finally { Date.now = now; }
});
