import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, lstat, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';

// Deployment tools are standalone .mjs programs and are deliberately outside tsc output.
const configModule: string = '../scripts/hub-tls-config.mjs';
const verifyModule: string = '../scripts/hub-tls-verify.mjs';
const { generateConfiguration, renderConfiguration, validateCertificate, validateHostname, parseArguments } = await import(configModule);
const { verifyEntry, validateOrigin } = await import(verifyModule);
const hostname = 'hub.share-token.test';
const lookup = (_host: string, options: { all?: boolean }, callback: (error: null, ...rest: unknown[]) => void) => {
  if (options.all) callback(null, [{ address: '127.0.0.1', family: 4 }]);
  else callback(null, '127.0.0.1', 4);
};

async function fixture(t: { after(fn: () => Promise<unknown>): void }, target = hostname, san = `DNS:${target}`) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'share-token-tls-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const cert = join(directory, 'server.pem'); const key = join(directory, 'server.key');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', key, '-out', cert,
    '-subj', `/CN=${target}`, '-addext', `subjectAltName=${san}`, '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'extendedKeyUsage=serverAuth'], { stdio: 'ignore' });
  await chmod(key, 0o600);
  return { directory, options: { hostname: target, cert, key, out: join(directory, 'nginx'), user: 'hubtest' } };
}

test('TLS config is an independent prefix with streaming, WSS, privacy, and no retry directives', async t => {
  const { options } = await fixture(t);
  const result = await generateConfiguration(options);
  assert.equal(result.deployed, false);
  const config = await readFile(join(options.out, 'nginx.conf'), 'utf8');
  assert.match(config, /proxy_pass http:\/\/127\.0\.0\.1:4387;/);
  assert.equal((config.match(/proxy_pass/g) ?? []).length, 1);
  assert.match(config, /worker_processes 1;/);
  assert.match(config, /listen 443 ssl;/, 'DNS entries retain their existing listener behavior');
  for (const [directive, name] of [['client_body', 'client'], ['proxy', 'proxy'], ['fastcgi', 'fastcgi'], ['uwsgi', 'uwsgi'], ['scgi', 'scgi']]) {
    assert.ok(config.includes(`${directive}_temp_path ${options.out}/temp/${name};`));
    assert.ok((await lstat(join(options.out, 'temp', name!))).isDirectory());
  }
  for (const text of ['map $http_upgrade $connection_upgrade', 'proxy_set_header Host $http_host;', 'proxy_set_header X-Forwarded-Proto https;',
    'proxy_set_header Upgrade $http_upgrade;', 'proxy_set_header Connection $connection_upgrade;', 'proxy_buffering off;', 'proxy_request_buffering off;',
    'proxy_next_upstream off;', 'proxy_read_timeout 960s;', 'client_max_body_size 8m;', 'ssl_protocols TLSv1.2 TLSv1.3;', 'access_log off;', 'error_log /dev/null crit;']) assert.ok(config.includes(text), text);
  assert.doesNotMatch(config, /\$request_uri|\$request_body|\$http_authorization/);
  const service = await readFile(join(options.out, 'share-token-hub-tls.service'), 'utf8');
  assert.match(service, /User=hubtest/); assert.match(service, /AmbientCapabilities=CAP_NET_BIND_SERVICE/);
  assert.match(service, /ProtectSystem=strict/); assert.match(service, /NoNewPrivileges=true/);
  const commands = await readFile(join(options.out, 'install-commands.sh'), 'utf8');
  assert.ok(commands.includes(`\nsudo systemd-run --quiet --wait --pipe --collect --uid=hubtest --property=AmbientCapabilities=CAP_NET_BIND_SERVICE --property=CapabilityBoundingSet=CAP_NET_BIND_SERVICE --property=NoNewPrivileges=true -- /usr/sbin/nginx -p ${options.out}/ -c nginx.conf -t\n`));
  assert.ok(!commands.includes('sudo /usr/sbin/nginx'), 'precheck must not create root-owned PID files');
  assert.ok(!commands.includes('sudo -u hubtest /usr/sbin/nginx'), 'low-port standalone check needs bind privileges');
  assert.deepEqual(await generateConfiguration(options), result, 'repeated generation is idempotent');
  await writeFile(join(options.out, 'nginx.conf'), 'a different configuration');
  await assert.rejects(generateConfiguration(options), /Refusing to replace/);
  assert.equal(await readFile(join(options.out, 'nginx.conf'), 'utf8'), 'a different configuration');
});

test('private IPv4 entry requires a matching IP SAN and binds only its own interface', async t => {
  const address = '10.20.30.40';
  const { options } = await fixture(t, address, `IP:${address}`);
  const result = await generateConfiguration(options);
  assert.equal(result.certificate.hostname, address);
  const config = await readFile(join(options.out, 'nginx.conf'), 'utf8');
  assert.match(config, /listen 10\.20\.30\.40:443 ssl;/);
  assert.doesNotMatch(config, /listen (?:443|0\.0\.0\.0|\[::\])/);
  assert.match(config, /server_name 10\.20\.30\.40;/);
  assert.match(config, /if \(\$host != 10\.20\.30\.40\) \{ return 421; \}/);
  assert.match(renderConfiguration({ ...options, port: 8443 })['nginx.conf'], /listen 10\.20\.30\.40:8443 ssl;/);
  await assert.rejects(validateCertificate({ ...options, hostname: '10.20.30.41' }), /IP SAN/);

  const dnsOnly = await fixture(t, address, `DNS:${address}`);
  await assert.rejects(generateConfiguration(dnsOnly.options), /IP SAN/, 'numeric DNS SAN must not impersonate an IP SAN');
  const wrongIpWithDns = await fixture(t, address, `IP:10.20.30.41,DNS:${address}`);
  await assert.rejects(validateCertificate(wrongIpWithDns.options), /IP SAN/, 'matching DNS SAN must not mask a wrong IP SAN');
});

test('entry validation allows RFC1918 boundaries and rejects public or noncanonical IP forms before URL normalization', () => {
  for (const address of ['10.0.0.1', '10.255.255.254', '172.16.0.1', '172.31.255.254', '192.168.0.1', '192.168.255.254']) {
    assert.equal(validateHostname(address), address);
    assert.equal(validateOrigin(`https://${address}`), `https://${address}`);
    assert.equal(validateOrigin(`https://${address}:8443/`), `https://${address}:8443`);
  }
  for (const address of ['8.8.8.8', '127.0.0.1', '0.0.0.0', '169.254.1.1', '100.64.0.1', '172.15.255.255', '172.32.0.1', '192.167.1.1', '192.169.1.1',
    '10.1', '10.0.01.1', '010.0.0.1', '0x0a.0.0.1', '167772161', '10.0.0.1.', '10.0.0.999', '10.0.0.1;include', '[fd00::1]', '[::1]']) {
    assert.throws(() => validateHostname(address), /hostname/, address);
    assert.throws(() => validateOrigin(`https://${address}`), /hostname|HTTPS origin/, address);
  }
});

test('TLS generator rejects directive, systemd, shell, hostname, and option injection', async t => {
  const { options } = await fixture(t);
  for (const value of ['good.test;include', 'good.test\nserver', '$(id).test', '*.example.test', 'https://hub.test', 'hub.test:443', '127.0.0.1', 'share.example.com', 'Hub.test']) {
    assert.throws(() => renderConfiguration({ ...options, hostname: value }), /hostname|placeholder/);
  }
  for (const name of ['cert', 'key', 'out', 'nginx']) {
    for (const value of ['/tmp/a;include', '/tmp/a\nb', '/tmp/$variable', '/tmp/%h', '/tmp/a b', '/tmp/a"', '/tmp/../x', '/tmp/./x']) {
      assert.throws(() => renderConfiguration({ ...options, [name]: value }), /path/);
    }
  }
  for (const port of [0, 65536, NaN, 4.5, '443;']) assert.throws(() => renderConfiguration({ ...options, port }), /port/);
  for (const user of ['root', 'person\nExecStart=evil', 'bad user', '$user']) assert.throws(() => renderConfiguration({ ...options, user }), /user/);
  assert.throws(() => parseArguments(['--hostname', hostname, '--hostname', 'other.test'], ['--hostname']), /duplicate/);
  assert.throws(() => parseArguments(['--key'], ['--key']), /Missing/);
  const highPort = renderConfiguration({ ...options, port: 8443 });
  assert.doesNotMatch(highPort['share-token-hub-tls.service'], /CAP_NET_BIND_SERVICE/);
  assert.ok(highPort['install-commands.sh'].includes(`\nsudo -u hubtest /usr/sbin/nginx -p ${options.out}/ -c nginx.conf -t\n`));
  assert.doesNotMatch(highPort['install-commands.sh'], /systemd-run/);
});

test('certificate validation checks SAN, validity, leaf purpose, key match, and private file permissions', async t => {
  const { directory, options } = await fixture(t);
  const certificate = await validateCertificate(options);
  assert.equal(certificate.hostname, hostname);
  await assert.rejects(validateCertificate({ ...options, hostname: 'wrong.share-token.test' }), /SAN/);
  await assert.rejects(validateCertificate({ ...options, now: Date.parse(certificate.validTo) + 1 }), /expired/);
  await assert.rejects(validateCertificate({ ...options, now: Date.parse(certificate.validFrom) - 1 }), /not yet valid/);
  const otherKey = join(directory, 'other.key');
  execFileSync('openssl', ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', otherKey], { stdio: 'ignore' });
  await chmod(otherKey, 0o600);
  await assert.rejects(validateCertificate({ ...options, key: otherKey }), /do not match/);
  await chmod(options.key, 0o644);
  await assert.rejects(validateCertificate(options), /permissions/);
  await chmod(options.key, 0o600);
  const invalid = join(directory, 'invalid.pem'); await writeFile(invalid, 'not a certificate');
  await assert.rejects(validateCertificate({ ...options, cert: invalid }), /PEM/);
  const caCert = join(directory, 'ca.pem');
  execFileSync('openssl', ['req', '-x509', '-new', '-key', options.key, '-days', '2', '-out', caCert, '-subj', '/CN=Test CA', '-addext', 'basicConstraints=critical,CA:TRUE'], { stdio: 'ignore' });
  await assert.rejects(validateCertificate({ ...options, cert: caCert }), /server leaf/);
  const clientCert = join(directory, 'client.pem');
  execFileSync('openssl', ['req', '-x509', '-new', '-key', options.key, '-days', '2', '-out', clientCert, '-subj', `/CN=${hostname}`,
    '-addext', `subjectAltName=DNS:${hostname}`, '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'extendedKeyUsage=clientAuth'], { stdio: 'ignore' });
  await assert.rejects(validateCertificate({ ...options, cert: clientCert }), /server authentication/);
  const chain = join(directory, 'bad-chain.pem');
  await writeFile(chain, await readFile(options.cert, 'utf8') + await readFile(caCert, 'utf8'));
  await assert.rejects(validateCertificate({ ...options, cert: chain }), /chain/);
});

test('generator refuses symlink output and leaves credentials outside its generated files', async t => {
  const { directory, options } = await fixture(t);
  await symlink(directory, options.out);
  await assert.rejects(generateConfiguration(options), /symlink/);
  await rm(options.out); await generateConfiguration(options);
  const key = await readFile(options.key, 'utf8');
  for (const name of ['nginx.conf', 'share-token-hub-tls.service', 'install-commands.sh']) assert.ok(!(await readFile(join(options.out, name), 'utf8')).includes(key));
  await rm(join(options.out, 'nginx.conf')); await symlink(options.cert, join(options.out, 'nginx.conf'));
  await assert.rejects(generateConfiguration(options), /Refusing/);
});

test('HTTPS verifier rejects cleartext, credentials, URL path/query injection, and redirects', async t => {
  for (const value of ['http://hub.test', 'https://user:secret@hub.test', 'https://hub.test/path', 'https://hub.test/?token=secret', 'https://hub.test/#x', 'https://hub.test/../', 'https://hub.test\\evil']) {
    assert.throws(() => validateOrigin(value), /HTTPS origin/);
  }
  const { options } = await fixture(t);
  const cert = await readFile(options.cert); const key = await readFile(options.key);
  const server = createServer({ cert, key }, (_request, response) => { response.writeHead(302, { location: 'https://other.test/' }); response.end(); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const url = `https://${hostname}:${(server.address() as AddressInfo).port}`;
  await assert.rejects(verifyEntry({ url, ca: cert, lookup }), /Redirects are not followed/);
});

test('verifier performs real TLS validation and confirms WSS reaches the Hub rejection boundary', async t => {
  const { options } = await fixture(t);
  const cert = await readFile(options.cert); const key = await readFile(options.key);
  const upgrades: string[] = [];
  let acceptUnauthenticated = false;
  let stylesheetAvailable = true;
  const server = createServer({ cert, key }, (request, response) => {
    const path = request.url;
    if (path === '/healthz') { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ ok: true })); }
    else if (path === '/client/v2/meta') { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ apiVersion: 2, relayProtocolVersion: 1, desktopDataPlane: 'mock-only', subscriptionAvailable: false })); }
    else if (path === '/control/session' || path === '/client/v2/me') { response.writeHead(401); response.end(); }
    else if (path === '/') { response.setHeader('content-type', 'text/html'); response.end('<!doctype html><html><script src="/assets/index.js"></script></html>'); }
    else if (path === '/pair') { response.setHeader('content-type', 'text/html'); response.end('<!doctype html><html><link rel="stylesheet" href="/pair.css"></html>'); }
    else if (path === '/pair.css') { response.setHeader('content-type', stylesheetAvailable ? 'text/css' : 'text/html'); response.end(stylesheetAvailable ? 'body { color: #183d32; }' : '<html>Fallback page</html>'); }
    else { response.writeHead(200); response.end('test'); }
  });
  server.on('upgrade', (request, socket) => {
    upgrades.push(request.headers.origin ? 'origin' : 'relay');
    if (acceptUnauthenticated) { socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'); return; }
    socket.end(`HTTP/1.1 ${request.headers.origin ? '403 Forbidden' : '401 Unauthorized'}\r\nConnection: close\r\n\r\n`);
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const url = `https://${hostname}:${(server.address() as AddressInfo).port}`;
  await assert.rejects(verifyEntry({ url, lookup }), /self-signed|unable to verify/);
  await assert.rejects(verifyEntry({ url: url.replace(hostname, 'wrong.test'), ca: cert, lookup }), /not in the cert|does not match/);
  const result = await verifyEntry({ url, ca: cert, lookup });
  assert.equal(result.tls.authorized, true);
  assert.equal(result.checks.pairingStyles, 1);
  assert.equal(result.checks.unauthenticatedWss, 401); assert.equal(result.checks.browserOriginWss, 403);
  assert.equal(result.capabilities.subscriptionAvailable, false);
  assert.deepEqual(upgrades, ['relay', 'origin']);
  assert.ok(result.limits.some((item: string) => item.includes('SSE timing')));
  stylesheetAvailable = false;
  await assert.rejects(verifyEntry({ url, ca: cert, lookup }), /stylesheet did not return CSS/);
  stylesheetAvailable = true;
  acceptUnauthenticated = true;
  await assert.rejects(verifyEntry({ url, ca: cert, lookup }), /unexpectedly accepted/);
});
