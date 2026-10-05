import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyEntry } from './hub-tls-verify.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const id = randomUUID().replaceAll('-', '').slice(0, 12);
const name = `share-token-smoke-${id}`;
const volume = `${name}-data`;
const image = process.env.HUB_SMOKE_IMAGE ?? 'share-token-hub:smoke';
const temporary = await mkdtemp(join(tmpdir(), 'share-token-container-'));
function docker(args, options = {}) { return execFileSync('docker', args, { cwd: root, encoding: 'utf8', timeout: 60_000, ...options }); }
const pause = ms => new Promise(resolvePause => setTimeout(resolvePause, ms));
let initialized = false;
try {
  try { docker(['info'], { stdio: 'ignore' }); }
  catch { throw new Error('Docker Engine is required for this check. Run it in GitHub Actions or on your own Docker host.'); }
  if (process.env.HUB_SMOKE_SKIP_BUILD !== '1') docker(['build', '-t', image, '.'], { timeout: 15 * 60_000, stdio: 'inherit' });
  docker(['volume', 'create', volume]); initialized = true;
  const input = join(temporary, 'shared-code.txt');
  await writeFile(input, '48271936\n', { mode: 0o644 });
  docker(['run', '-d', '--name', name, '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '-p', '127.0.0.1::4387', '-v', `${volume}:/data`, '--mount', `type=bind,src=${input},dst=/run/secrets/hub_shared_code,readonly`, '-e', 'HUB_SHARED_CODE_FILE=/run/secrets/hub_shared_code', image]);
  const published = docker(['port', name, '4387/tcp']).trim();
  assert.match(published, /^127\.0\.0\.1:\d+$/);
  const origin = `http://${published}`;
  async function healthy() {
    const deadline = Date.now() + 40_000;
    while (Date.now() < deadline) {
      try { const response = await fetch(origin + '/healthz', { signal: AbortSignal.timeout(2000) }); if (response.ok && (await response.json()).ok === true) return; }
      catch { /* Wait for initialization. */ }
      await pause(300);
    }
    throw new Error('Hub did not become healthy. Inspect the container initialization status.');
  }
  await healthy();
  assert.equal(docker(['exec', name, 'id', '-u']).trim(), '1000');
  assert.equal(docker(['exec', name, 'stat', '-c', '%a', '/data/admin.token']).trim(), '600');
  assert.equal(docker(['exec', name, 'stat', '-c', '%a', '/data']).trim(), '700');
  docker(['exec', name, 'node', 'deploy/hub/healthcheck.mjs']);
  const firstTokenHash = docker(['exec', name, 'sha256sum', '/data/admin.token']).split(' ')[0];
  const meta = await (await fetch(origin + '/client/v2/meta')).json();
  assert.equal(meta.apiVersion, 2); assert.equal(meta.pairing.sharedCodeAvailable, true);
  assert.equal((await fetch(origin + '/')).status, 200);
  assert.equal((await fetch(origin + '/pair')).status, 200);
  assert.equal((await fetch(origin + '/client/v2/me')).status, 401);
  const concurrent = spawnSync('docker', ['run', '--rm', '-v', `${volume}:/data`, image], { encoding: 'utf8', timeout: 10_000, stdio: 'pipe' });
  assert.equal(concurrent.error, undefined);
  assert.equal(concurrent.status, 1, 'A second Hub on the volume must be refused by flock.');
  docker(['kill', '--signal', 'KILL', name]);
  docker(['start', name]);
  const restartedOrigin = `http://${docker(['port', name, '4387/tcp']).trim()}`;
  const deadline = Date.now() + 40_000;
  let after;
  while (Date.now() < deadline) {
    try { const response = await fetch(restartedOrigin + '/client/v2/meta', { signal: AbortSignal.timeout(2000) }); if (response.ok) { after = await response.json(); break; } }
    catch { /* Wait for restart. */ }
    await pause(300);
  }
  assert.equal(after?.hubId, meta.hubId);
  assert.equal(docker(['exec', name, 'sha256sum', '/data/admin.token']).split(' ')[0], firstTokenHash);
  const certificateDir = join(temporary, 'certs'); await mkdir(certificateDir);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=hub.test.local', '-addext', 'subjectAltName=DNS:hub.test.local', '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'extendedKeyUsage=serverAuth', '-keyout', join(certificateDir, 'privkey.pem'), '-out', join(certificateDir, 'fullchain.pem')], { stdio: 'ignore' });
  docker(['network', 'create', name]);
  docker(['network', 'connect', '--alias', 'hub', name, name]);
  docker(['run', '-d', '--name', `${name}-nginx`, '--network', name, '-p', '127.0.0.1::443', '-e', 'HUB_DOMAIN=hub.test.local', '-e', 'NGINX_ENVSUBST_FILTER=^HUB_DOMAIN$', '--mount', `type=bind,src=${join(root, 'deploy/hub/nginx.conf.template')},dst=/etc/nginx/templates/default.conf.template,readonly`, '--mount', `type=bind,src=${certificateDir},dst=/etc/nginx/certs,readonly`, 'nginx:stable-alpine']);
  const tlsPublished = docker(['port', `${name}-nginx`, '443/tcp']).trim();
  const tlsPort = Number(tlsPublished.split(':')[1]);
  const certificate = await readFile(join(certificateDir, 'fullchain.pem'));
  const lookup = (_hostname, options, callback) => callback(null, options.all ? [{ address: '127.0.0.1', family: 4 }] : '127.0.0.1', 4);
  let report;
  for (let attempt = 0; attempt < 30; attempt++) {
    try { report = await verifyEntry({ url: `https://hub.test.local:${tlsPort}`, ca: certificate, lookup, timeout: 3000 }); break; }
    catch (error) { if (attempt === 29) throw error; await pause(300); }
  }
  assert.ok(report);
  docker(['exec', `${name}-nginx`, 'nginx', '-t'], { stdio: 'pipe' });
  console.log('Hub container smoke passed: non-root runtime, private data, guarded volume, crash restart persistence, trusted HTTPS, static assets and WSS authentication boundaries.');
} finally {
  for (const container of [`${name}-nginx`, name]) { try { docker(['rm', '-f', container], { stdio: 'ignore' }); } catch { /* Best effort cleanup. */ } }
  try { docker(['network', 'rm', name], { stdio: 'ignore' }); } catch { /* Best effort cleanup. */ }
  if (initialized) { try { docker(['volume', 'rm', volume], { stdio: 'ignore' }); } catch { /* Best effort cleanup. */ } }
  await rm(temporary, { recursive: true, force: true });
}
