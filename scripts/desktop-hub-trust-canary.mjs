import { _electron as electron } from 'playwright';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:https';
import { createServer as createHttpServer } from 'node:http';
import { connect } from 'node:net';
import { mkdtemp, mkdir, readFile, rm, writeFile, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The local CONNECT fixture changes only the TCP destination, preserving the HTTPS IP identity and Chromium TLS validation.
const address = '10.10.0.99';
const directory = await mkdtemp(join(tmpdir(), 'share-hub-window-canary-'));
const userData = join(directory, 'app'); await mkdir(userData, { mode: 0o700 });
let desktop; let hubPage; let alternateHits = 0;
let server; let alternate; let proxy; let recovery; const tunnels = new Set();
try {
  const keyPath = join(directory, 'server.key'), certPath = join(directory, 'server.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', keyPath, '-out', certPath, '-subj', '/CN=Private TLS UI canary',
    '-addext', `subjectAltName=IP:${address}`, '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment', '-addext', 'extendedKeyUsage=serverAuth'], { stdio: 'ignore' });
  const key = await readFile(keyPath), certificatePem = await readFile(certPath, 'utf8');
  server = createServer({ key, cert: certificatePem }, (_request, response) => { response.writeHead(200, { 'content-type': 'text/html' }); response.end('<!doctype html><title>Untrusted title</title><h1>Private Hub window canary</h1>'); });
  alternate = createServer({ key, cert: certificatePem }, (_request, response) => { alternateHits++; response.writeHead(200, { 'access-control-allow-origin': '*' }); response.end('other origin'); });
  for (const listener of [server, alternate]) await new Promise((resolve, reject) => { listener.once('error', reject); listener.listen(0, '127.0.0.1', resolve); });
  const hubUrl = `https://${address}:${server.address().port}`;
  const alternateUrl = `https://${address}:${alternate.address().port}`;
  const ports = new Set([server.address().port, alternate.address().port]);
  proxy = createHttpServer((_request, response) => { response.writeHead(403); response.end(); });
  proxy.on('connect', (request, socket, head) => {
    const target = new URL('http://' + request.url);
    if (target.hostname !== address || !ports.has(Number(target.port))) { socket.destroy(); return; }
    const upstream = connect(Number(target.port), '127.0.0.1', () => { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); if (head.length) upstream.write(head); socket.pipe(upstream); upstream.pipe(socket); });
    for (const connection of [socket, upstream]) { tunnels.add(connection); connection.on('error', () => { socket.destroy(); upstream.destroy(); }); connection.on('close', () => { tunnels.delete(connection); socket.destroy(); upstream.destroy(); }); }
  });
  await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));

  const file = join(directory, 'connection.json'); await writeFile(file, JSON.stringify({ version: 1, hubUrl, certificatePem, label: 'TLS UI Canary' }));
  async function launch(dataDirectory = userData) {
    desktop = await electron.launch({ args: ['.', '--user-data-dir=' + dataDirectory, '--proxy-server=http://127.0.0.1:' + proxy.address().port], env: { ...process.env, SHARE_TOKEN_TEST_DATA_DIR: dataDirectory }, timeout: 30000 });
    const main = await desktop.firstWindow(); await main.getByRole('button', { name: '使用共享', exact: true }).click(); return main;
  }
  async function stop() {
    if (!desktop) return;
    const child = desktop.process();
    await desktop.evaluate(({ app }) => app.exit(0));
    if (child.exitCode === null) await new Promise(resolve => { child.once('exit', resolve); setTimeout(resolve, 3000).unref(); });
    desktop = null;
  }
  let main = await launch();
  await desktop.evaluate(({ dialog }, path) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [path] }); }, file);
  await main.getByRole('button', { name: '导入内网连接文件', exact: true }).click();
  await main.waitForFunction(async url => (await window.shareToken.state()).hubTrust?.hubUrl === url, hubUrl);
  const state = await main.evaluate(() => window.shareToken.state());
  assert.equal(state.hubTrust.hubUrl, hubUrl); assert.equal(state.hubTrust.label, 'TLS UI Canary');
  assert.equal(JSON.stringify(state).includes('BEGIN CERTIFICATE'), false);
  assert.equal((await lstat(join(userData, 'hub-trust/connection.json'))).mode & 0o777, 0o600);
  const popup = desktop.waitForEvent('window');
  await main.evaluate(() => window.shareToken.openHub());
  hubPage = await popup;
  await hubPage.getByRole('heading', { name: 'Private Hub window canary' }).waitFor();
  assert.equal(await hubPage.evaluate(() => typeof window.shareToken), 'undefined');
  const isolation = await desktop.evaluate(({ BrowserWindow }, target) => {
    const remote = BrowserWindow.getAllWindows().find(window => window.webContents.getURL().startsWith(target));
    const preferences = remote.webContents.getLastWebPreferences();
    return { preload: preferences.preload ?? null, nodeIntegration: preferences.nodeIntegration, sandbox: preferences.sandbox, contextIsolation: preferences.contextIsolation, devTools: preferences.devTools, persistent: remote.webContents.session.isPersistent(), title: remote.getTitle() };
  }, hubUrl);
  assert.equal(isolation.preload, null); assert.equal(isolation.nodeIntegration, false); assert.equal(isolation.sandbox, true);
  assert.equal(isolation.contextIsolation, true); assert.notEqual(isolation.devTools, true); assert.equal(isolation.persistent, false);
  assert.equal(isolation.title, '共享token · ' + hubUrl);
  assert.equal(await hubPage.evaluate(async url => { try { await fetch(url); return true; } catch { return false; } }, alternateUrl), false);
  assert.equal(alternateHits, 0, 'Even another port with the same trusted leaf is blocked before the network request');
  await hubPage.evaluate(url => { window.open(url); }, alternateUrl);
  assert.equal(desktop.windows().length, 2, 'Remote Hub pages cannot open additional windows');
  const unrelated = await desktop.evaluate(async ({ BrowserWindow }, target) => {
    const window = new BrowserWindow({ show: false, webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false } });
    try { await window.loadURL(target); return true; } catch { return false; } finally { window.destroy(); }
  }, hubUrl);
  assert.equal(unrelated, false, 'Default Chromium session must still reject the self-signed certificate');
  const navigation = await desktop.evaluate(async ({ BrowserWindow }, args) => {
    const remote = BrowserWindow.getAllWindows().find(window => window.webContents.getURL().startsWith(args.origin));
    await remote.webContents.executeJavaScript('window.location.href = ' + JSON.stringify(args.target));
    await new Promise(resolve => setTimeout(resolve, 100));
    return { url: remote.webContents.getURL(), title: await remote.webContents.executeJavaScript('document.querySelector("h1").textContent') };
  }, { origin: hubUrl, target: alternateUrl });
  assert.equal(navigation.url, hubUrl + '/'); assert.equal(navigation.title, 'Private Hub window canary');
  assert.equal(alternateHits, 0);

  const hubClosed = hubPage.waitForEvent('close');
  await main.evaluate(() => window.shareToken.logout());
  await hubClosed; hubPage = null;
  await stop();
  main = await launch();
  const restored = await main.evaluate(() => window.shareToken.state());
  assert.deepEqual(restored.hubTrust, state.hubTrust); assert.equal(restored.connected, false);
  await stop();
  // Exercise cancellation and expiry through actual worker HTTP calls. This fixture
  // returns pairing metadata only and never creates a device credential.
  recovery = createHttpServer((request, response) => {
    const json = (status, value) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(value)); };
    const origin = 'http://127.0.0.1:' + recovery.address().port;
    if (request.url === '/client/v2/meta') { json(200, { pairing: true }); return; }
    if (request.url === '/client/v2/device-pairings') { json(200, { pairingId: 'recovery-pair', userCode: 'RECOVERY', deviceCode: 'local-fixture-code', verificationUri: origin + '/', verificationUriComplete: origin + '/', expiresAt: Date.now() + 60000, interval: 1 }); return; }
    if (request.url === '/client/v2/device-pairings/cancel') { response.destroy(); return; }
    if (request.url === '/client/v2/device-pairings/token') { json(400, { error: { code: 'EXPIRED_TOKEN', message: 'Synthetic expired pairing' } }); return; }
    json(404, {});
  });
  await new Promise(resolve => recovery.listen(0, '127.0.0.1', resolve));
  const recoveryData = join(directory, 'recovery-app'); await mkdir(recoveryData, { mode: 0o700 });
  main = await launch(recoveryData);
  await desktop.evaluate(({ shell }) => { shell.openExternal = async () => {}; });
  await main.getByText('高级连接设置', { exact: true }).click();
  await main.getByLabel('Hub 地址', { exact: true }).fill('http://127.0.0.1:' + recovery.address().port);
  await main.getByRole('button', { name: '连接并配对', exact: true }).click();
  await main.locator('.pair-code').waitFor();
  assert.equal(await main.getByRole('button', { name: '导入内网连接文件', exact: true }).count(), 0);
  await main.getByRole('button', { name: '取消配对，返回上一步', exact: true }).click();
  await main.getByRole('button', { name: '连接并配对', exact: true }).waitFor();
  const cancelled = await main.evaluate(() => window.shareToken.state());
  assert.equal(cancelled.pairing, null); assert.match(cancelled.lastError, /本机已取消配对.*远端取消尚未确认/);
  assert.equal(await main.getByRole('button', { name: '导入内网连接文件', exact: true }).isDisabled(), false);
  await main.getByRole('button', { name: '连接并配对', exact: true }).click();
  await main.locator('.pair-code').waitFor();
  await main.getByRole('button', { name: '连接并配对', exact: true }).waitFor();
  assert.equal((await main.evaluate(() => window.shareToken.state())).pairing, null, 'Terminal poll failure releases both renderer and main-process pairing state');

  console.log(JSON.stringify({ ok: true, checks: ['system-selected profile import', '0600 atomic storage', 'public summary only', 'HTTPS self-signed leaf accepted only in isolated session', 'same-certificate different-port network blocked', 'cross-origin navigation and popup blocked', 'no preload or native IPC on remote page', 'default Chromium trust unaffected', 'failed remote cancellation releases local pairing and reports uncertainty', 'terminal polling error releases main pairing state', 'disconnect closes owned Hub window', 'restart restores profile'], realInferenceRequests: 0 }));
  await stop();
} catch (error) {
  if (desktop) console.error('Hub window canary failure:', await desktop.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().map(window => ({ url: window.webContents.getURL(), loading: window.webContents.isLoading() }))).catch(() => []));
  if (desktop?.windows()[0]) console.error((await desktop.windows()[0].locator('body').innerText().catch(() => '')).slice(-1800));
  throw error;
} finally {
  if (desktop) await desktop.evaluate(({ app }) => app.exit(0)).catch(() => {});
  for (const tunnel of tunnels) tunnel.destroy();
  for (const listener of [server, alternate, proxy, recovery]) if (listener) { listener.closeAllConnections(); await new Promise(resolve => listener.close(resolve)); }
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
