#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { request } from 'node:https';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArguments, validateHostname } from './hub-tls-config.mjs';

export function validateOrigin(value) {
  const rawOrigin = typeof value === 'string' ? /^https:\/\/([a-z0-9.-]+)(?::[0-9]+)?\/?$/.exec(value) : null;
  let url;
  try { url = new URL(value); } catch { throw new Error('url must be an HTTPS origin.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/'
    || !rawOrigin) throw new Error('url must be an HTTPS origin without credentials, query, fragment, or path.');
  // Validate the caller's spelling before URL canonicalization can conceal
  // an abbreviated, octal, hexadecimal, or integer IPv4 address.
  validateHostname(rawOrigin[1]);
  validateHostname(url.hostname);
  return url.origin;
}

export function probe(origin, path, { ca, headers = {}, lookup, timeout = 10_000, maxBytes = 4 * 1024 * 1024 } = {}) {
  return new Promise((resolveProbe, reject) => {
    let timer;
    const req = request(new URL(path, origin), {
      method: 'GET', ca, headers, lookup, minVersion: 'TLSv1.2', rejectUnauthorized: true, agent: false,
    }, response => {
      let size = 0; const chunks = [];
      const socket = response.socket;
      const peer = socket.getPeerCertificate();
      response.on('data', chunk => { size += chunk.length; if (size > maxBytes) req.destroy(new Error('Response exceeds verification size limit.')); else chunks.push(chunk); });
      response.on('error', reject);
      response.on('end', () => resolveProbe({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString('utf8'), tls: { authorized: socket.authorized, protocol: socket.getProtocol(), fingerprint256: peer.fingerprint256, validTo: peer.valid_to } }));
    });
    req.on('upgrade', (_response, socket) => { socket.destroy(); reject(new Error('Unauthenticated WebSocket was unexpectedly accepted.')); });
    req.on('error', reject);
    req.on('close', () => clearTimeout(timer));
    timer = setTimeout(() => req.destroy(new Error('HTTPS verification timed out.')), timeout);
    req.end();
  });
}

function requireStatus(response, expected, label) {
  if (response.status !== expected) throw new Error(`${label}: expected HTTP ${expected}, got ${response.status}. Redirects are not followed.`);
}

export async function verifyEntry({ url, ca, lookup, timeout }) {
  const origin = validateOrigin(url);
  const settings = { ca, lookup, timeout };
  const health = await probe(origin, '/healthz', settings); requireStatus(health, 200, 'health');
  let healthData; try { healthData = JSON.parse(health.body); } catch { throw new Error('health must return JSON.'); }
  if (healthData.ok !== true) throw new Error('Hub did not report a healthy state.');
  const meta = await probe(origin, '/client/v2/meta', settings); requireStatus(meta, 200, 'meta');
  let metadata; try { metadata = JSON.parse(meta.body); } catch { throw new Error('meta must return JSON.'); }
  if (metadata.apiVersion !== 2 || metadata.relayProtocolVersion !== 1) throw new Error('Unexpected Hub protocol metadata.');
  const page = await probe(origin, '/', settings); requireStatus(page, 200, 'homepage');
  if (!String(page.headers['content-type']).includes('text/html') || !/<(?:!doctype|html)\b/i.test(page.body)) throw new Error('Homepage did not return HTML.');
  const assets = [...new Set([...page.body.matchAll(/(?:src|href)=["'](\/assets\/[A-Za-z0-9_.-]+)["']/g)].map(match => match[1]))];
  if (!assets.length || assets.length > 20) throw new Error('Homepage has no expected build assets or too many assets.');
  for (const path of assets) requireStatus(await probe(origin, path, settings), 200, 'static asset');
  const pairing = await probe(origin, '/pair', settings); requireStatus(pairing, 200, 'pairing page');
  requireStatus(await probe(origin, '/pair.js', settings), 200, 'pairing script');
  const pairingStyles = [...new Set([...pairing.body.matchAll(/href=["'](\/pair\.css)["']/g)].map(match => match[1]))];
  for (const path of pairingStyles) {
    const stylesheet = await probe(origin, path, settings); requireStatus(stylesheet, 200, 'pairing stylesheet');
    if (!String(stylesheet.headers['content-type']).includes('text/css') || !stylesheet.body.trim()) throw new Error('Pairing stylesheet did not return CSS.');
  }
  for (const path of ['/control/session', '/client/v2/me']) requireStatus(await probe(origin, path, settings), 401, 'unauthenticated API');
  const headers = { Upgrade: 'websocket', Connection: 'Upgrade', 'Sec-WebSocket-Key': randomBytes(16).toString('base64'), 'Sec-WebSocket-Version': '13' };
  requireStatus(await probe(origin, '/relay/v1', { ...settings, headers }), 401, 'unauthenticated WSS handshake');
  // The Hub explicitly rejects browser-origin upgrades before authentication. This
  // distinguishes its upgrade handler from an ordinary proxy-generated 401 page.
  requireStatus(await probe(origin, '/relay/v1', { ...settings, headers: { ...headers, Origin: origin } }), 403, 'browser-origin WSS handshake');
  return {
    verifiedAt: new Date().toISOString(), origin, tls: health.tls,
    checks: { health: true, protocolMetadata: true, homepage: true, staticAssets: assets.length, pairingPage: true, pairingStyles: pairingStyles.length, unauthenticatedApis: 401, unauthenticatedWss: 401, browserOriginWss: 403 },
    capabilities: { desktopDataPlane: metadata.desktopDataPlane, subscriptionAvailable: metadata.subscriptionAvailable },
    limits: ['Authenticated relay exchange and model inference were not exercised.', 'SSE timing requires an authenticated streaming request and is not claimed by this check.'],
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.slice(2).includes('--help')) process.stdout.write('Usage: node scripts/hub-tls-verify.mjs --url https://your-domain-or-private-ip [--ca /path/private-ca.pem]\nCertificate verification is always enabled. No credentials are sent and no redirects are followed.\n');
    else {
      if (process.versions.node.split('.')[0] !== '24') throw new Error('Use Node 24 for this deployment tool.');
      const args = parseArguments(process.argv.slice(2), ['--url', '--ca']);
      const ca = args.ca ? await readFile(args.ca) : undefined;
      if (ca && (ca.length > 256 * 1024 || !ca.includes('-----BEGIN CERTIFICATE-----'))) throw new Error('ca must be a PEM certificate bundle of at most 256 KiB.');
      process.stdout.write(JSON.stringify(await verifyEntry({ url: args.url, ca }), null, 2) + '\n');
    }
  } catch (error) { process.stderr.write(`TLS verification failed: ${error.message}\n`); process.exitCode = 1; }
}
