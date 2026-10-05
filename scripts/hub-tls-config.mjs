#!/usr/bin/env node
import { X509Certificate, createPrivateKey } from 'node:crypto';
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { userInfo } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const HELP = `Usage: node scripts/hub-tls-config.mjs --hostname HOST --cert /path/fullchain.pem --key /path/key.pem --out /absolute/prefix [--port 443] [--user USER] [--nginx /usr/sbin/nginx]

Run on the target machine as the account that will run nginx. Existing certificate
and key files are required; no certificate is requested and no service is changed.
The output is a separate nginx prefix, with an installable systemd unit and commands.
Only 127.0.0.1:4387 is used as upstream. Use a reachable domain you control or a
canonical RFC1918 IPv4 address. IPv4 entries bind only the supplied address.
`;

export function parseArguments(args, allowed) {
  const output = {};
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    if (!allowed.includes(flag) || Object.hasOwn(output, flag.slice(2))) throw new Error(`Unknown or duplicate option: ${flag}`);
    const value = args[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${flag}`);
    output[flag.slice(2)] = value;
  }
  return output;
}

export function validateHostname(hostname) {
  if (typeof hostname === 'string' && isIP(hostname) === 4) {
    const [first, second] = hostname.split('.').map(Number);
    if (first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168)) return hostname;
    throw new Error('hostname IPv4 address must be a canonical RFC1918 private address.');
  }
  if (typeof hostname !== 'string' || hostname.length > 253 || hostname !== hostname.toLowerCase() || isIP(hostname)
    || !hostname.includes('.') || !hostname.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error('hostname must be a lowercase DNS name or canonical RFC1918 IPv4 address, without a scheme, port, or wildcard.');
  }
  // WHATWG URLs also accept shortened, octal, hexadecimal, and integer IPv4
  // forms. Reject those rather than letting nginx and the verifier interpret
  // the same input differently. Invalid all-numeric addresses are not DNS names.
  let normalized;
  try { normalized = new URL(`https://${hostname}`).hostname; } catch { /* invalid numeric host */ }
  if (normalized !== hostname || /^[0-9.]+$/.test(hostname)) throw new Error('hostname must not use a noncanonical IPv4 address.');
  if (hostname === 'share.example.com') throw new Error('Replace the documentation placeholder share.example.com with your domain.');
  return hostname;
}

function safePath(value, label) {
  // Restrict both nginx and systemd syntax, including variable/specifier expansion.
  if (typeof value !== 'string' || value === '/' || !isAbsolute(value) || !/^\/[A-Za-z0-9_./+-]+$/.test(value) || value.includes('//')
    || value.split('/').some(part => part === '..' || part === '.')) throw new Error(`${label} must be an absolute path using letters, digits, /, _, ., +, or - only.`);
  return value.replace(/\/$/, '');
}

async function readRegularFile(path, label, maxBytes) {
  const target = await realpath(path);
  safePath(target, `${label} resolved path`);
  const stat = await lstat(target);
  if (!stat.isFile() || stat.size > maxBytes) throw new Error(`${label} must be a regular file of at most ${maxBytes} bytes.`);
  return { data: await readFile(target, 'utf8'), stat };
}

export async function validateCertificate({ hostname, cert, key, now = Date.now() }) {
  validateHostname(hostname); safePath(cert, 'cert'); safePath(key, 'key');
  const certificate = await readRegularFile(cert, 'certificate', 256 * 1024);
  const privateKey = await readRegularFile(key, 'private key', 64 * 1024);
  if ((privateKey.stat.mode & 0o077) !== 0) throw new Error('Private key permissions must exclude group and other access (use chmod 600).');
  const blocks = certificate.data.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!blocks?.length || certificate.data.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim()) {
    throw new Error('cert must contain only PEM certificates, leaf first followed by its intermediate certificates.');
  }
  const chain = blocks.map(block => new X509Certificate(block));
  for (const item of chain) {
    if (!Number.isFinite(Date.parse(item.validFrom)) || !Number.isFinite(Date.parse(item.validTo))
      || now < Date.parse(item.validFrom) || now >= Date.parse(item.validTo)) throw new Error('Certificate is expired or not yet valid.');
  }
  const leaf = chain[0];
  if (leaf.ca) throw new Error('The first certificate must be a server leaf, not a certificate authority.');
  const matches = isIP(hostname) === 4 ? leaf.checkIP(hostname)
    : leaf.checkHost(hostname, { subject: 'never', partialWildcards: false, multiLabelWildcards: false });
  if (!matches) throw new Error('Certificate SAN does not match hostname (IP entries require an IP SAN).');
  if (leaf.keyUsage?.length && !leaf.keyUsage.includes('1.3.6.1.5.5.7.3.1')) throw new Error('Certificate is not valid for TLS server authentication.');
  for (let index = 0; index < chain.length - 1; index++) {
    if (!chain[index + 1].ca || !chain[index].checkIssued(chain[index + 1]) || !chain[index].verify(chain[index + 1].publicKey)) {
      throw new Error('Certificate chain is not correctly ordered or has an invalid signature.');
    }
  }
  let parsedKey;
  try { parsedKey = createPrivateKey(privateKey.data); }
  catch { throw new Error('Private key is invalid or encrypted; unattended nginx requires a readable unencrypted PEM key.'); }
  if (!leaf.checkPrivateKey(parsedKey)) throw new Error('Certificate and private key do not match.');
  return { hostname, fingerprint256: leaf.fingerprint256, validFrom: leaf.validFrom, validTo: leaf.validTo, certificateCount: chain.length };
}

export function renderConfiguration({ hostname, cert, key, out, port = 443, user = userInfo().username, nginx = '/usr/sbin/nginx' }) {
  validateHostname(hostname);
  for (const [label, value] of Object.entries({ cert, key, out, nginx })) safePath(value, label);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('port must be an integer from 1 to 65535.');
  if (!/^[a-z_][a-z0-9_.-]{0,63}$/.test(user) || user === 'root') throw new Error('user must be a non-root service account (pass --user when generating as root).');
  const prefix = out.replace(/\/$/, '');
  const listen = isIP(hostname) === 4 ? `${hostname}:${port}` : port;
  const config = `# Generated by hub-tls-config.mjs. This is a complete, independent nginx configuration.
worker_processes 1;
pid ${prefix}/run/nginx.pid;
# nginx error logs can include request URLs; disable them as well as access logging.
error_log /dev/null crit;
events { worker_connections 1024; }
http {
    access_log off;
    server_tokens off;
    client_body_temp_path ${prefix}/temp/client;
    proxy_temp_path ${prefix}/temp/proxy;
    fastcgi_temp_path ${prefix}/temp/fastcgi;
    uwsgi_temp_path ${prefix}/temp/uwsgi;
    scgi_temp_path ${prefix}/temp/scgi;
    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }
    server {
        listen ${listen} ssl;
        server_name ${hostname};
        if ($host != ${hostname}) { return 421; }
        ssl_certificate ${cert};
        ssl_certificate_key ${key};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_session_tickets off;
        client_max_body_size 8m;
        location / {
            proxy_pass http://127.0.0.1:4387;
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header Forwarded "";
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_cache off;
            gzip off;
            proxy_connect_timeout 10s;
            proxy_read_timeout 960s;
            proxy_send_timeout 960s;
            send_timeout 960s;
            proxy_next_upstream off;
        }
    }
}
`;
  const unit = `[Unit]
Description=Share Token Hub HTTPS and WSS entry
After=network-online.target share-token-hub.service
Wants=network-online.target
Requires=share-token-hub.service
RequiresMountsFor=${prefix} ${cert} ${key}
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=${user}
WorkingDirectory=${prefix}
ExecStartPre=${nginx} -p ${prefix}/ -c nginx.conf -t
ExecStart=${nginx} -p ${prefix}/ -c nginx.conf -g "daemon off;"
ExecReload=${nginx} -p ${prefix}/ -c nginx.conf -s reload
KillSignal=SIGQUIT
TimeoutStopSec=30
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${prefix}/run ${prefix}/temp
RestrictSUIDSGID=true
LockPersonality=true
${port < 1024 ? 'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE' : 'CapabilityBoundingSet='}

[Install]
WantedBy=multi-user.target
`;
  const commands = `#!/bin/sh
set -eu
# Review first. These commands must run on the machine containing the certificate and Hub.
# Install nginx using the operating system package manager if ${nginx} is absent.
# The user ${user} must be able to read the certificate/key and own ${prefix}/run and ${prefix}/temp.
# The default nginx service is not used. Inspect existing listeners before binding port ${port}.
${port < 1024 ? '# nginx -t binds listeners and may create a PID file; run as the final service user.\n# A transient unit provides only the same low-port capability as the installed service.\n' + `sudo systemd-run --quiet --wait --pipe --collect --uid=${user} --property=AmbientCapabilities=CAP_NET_BIND_SERVICE --property=CapabilityBoundingSet=CAP_NET_BIND_SERVICE --property=NoNewPrivileges=true --` : `sudo -u ${user}`} ${nginx} -p ${prefix}/ -c nginx.conf -t
# Refuse to replace a different pre-existing service unit.
if sudo test -L /etc/systemd/system/share-token-hub-tls.service; then
  echo 'Refusing to replace a symlinked service unit.' >&2
  exit 1
fi
if sudo test -e /etc/systemd/system/share-token-hub-tls.service; then
  sudo cmp -- ${prefix}/share-token-hub-tls.service /etc/systemd/system/share-token-hub-tls.service || exit 1
else
  sudo install -o root -g root -m 0644 ${prefix}/share-token-hub-tls.service /etc/systemd/system/share-token-hub-tls.service
fi
sudo systemctl daemon-reload
sudo systemctl enable --now share-token-hub-tls.service
sudo systemctl status share-token-hub-tls.service --no-pager
# After replacing/renewing the certificate at its existing path:
# sudo systemctl reload share-token-hub-tls.service
# Stop only this TLS entry if rollback is necessary (the Hub remains on loopback):
# sudo systemctl disable --now share-token-hub-tls.service
`;
  return { 'nginx.conf': config, 'share-token-hub-tls.service': unit, 'install-commands.sh': commands };
}

export async function generateConfiguration(options) {
  const files = renderConfiguration(options);
  const certificate = await validateCertificate(options);
  const out = safePath(options.out, 'out');
  const existing = await lstat(out).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
  if (existing && (!existing.isDirectory() || existing.isSymbolicLink())) throw new Error('out must be a directory, not a symlink.');
  // Compare every existing output before writing anything. Never overwrite another configuration.
  for (const [name, content] of Object.entries(files)) {
    const path = join(out, name);
    const stat = await lstat(path).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
    if (stat && (!stat.isFile() || stat.isSymbolicLink() || await readFile(path, 'utf8') !== content)) throw new Error(`Refusing to replace a different existing file: ${name}`);
  }
  const directories = ['run', 'temp', 'temp/client', 'temp/proxy', 'temp/fastcgi', 'temp/uwsgi', 'temp/scgi'];
  for (const name of directories) {
    const path = join(out, name);
    const stat = await lstat(path).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
    if (stat && (!stat.isDirectory() || stat.isSymbolicLink())) throw new Error(`Refusing non-directory or symlink: ${name}`);
  }
  await mkdir(out, { recursive: true, mode: 0o700 });
  // Resolve parents as well: a prefix under a symlink can fail systemd's write restrictions.
  if (await realpath(out) !== out) throw new Error('out must use its canonical path, without symlinked parents.');
  for (const name of directories) await mkdir(join(out, name), { mode: 0o700 }).catch(error => { if (error.code !== 'EEXIST') throw error; });
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(out, name), content, { flag: 'wx', mode: 0o600 }).catch(async error => {
      if (error.code !== 'EEXIST') throw error;
      const stat = await lstat(join(out, name));
      if (!stat.isFile() || stat.isSymbolicLink() || await readFile(join(out, name), 'utf8') !== content) throw new Error(`Output changed concurrently: ${name}`);
    });
  }
  return { generated: true, deployed: false, out, certificate, files: Object.keys(files) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.slice(2).includes('--help')) { process.stdout.write(HELP); }
    else {
      if (process.versions.node.split('.')[0] !== '24') throw new Error('Use Node 24 for this deployment tool.');
      const args = parseArguments(process.argv.slice(2), ['--hostname', '--cert', '--key', '--out', '--port', '--user', '--nginx']);
      const options = { ...args, ...(args.port === undefined ? {} : { port: /^\d+$/.test(args.port) ? Number(args.port) : NaN }) };
      process.stdout.write(JSON.stringify(await generateConfiguration(options), null, 2) + '\n');
    }
  } catch (error) { process.stderr.write(`TLS configuration failed: ${error.message}\n`); process.exitCode = 1; }
}
