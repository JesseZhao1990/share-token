import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes, randomInt } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, unlink, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { networkInterfaces, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { _electron as electron } from 'playwright';
import { createHub } from '../dist/apps/hub/index.js';
import { ClientStore } from '../dist/packages/storage/client.js';
import { policySchema } from '../dist/packages/protocol/index.js';
import { validateHubTrustProfile } from '../dist/packages/hub-client/trust.js';
import { saveHubTrustProfile } from '../dist/apps/desktop/main/hub-trust.js';

// Run after building: node scripts/consumer-start-canary.mjs [executable] [--local-profile|--loopback].
// The default uses temporary pinned TLS; --loopback tests existing invalid-profile recovery
// and manually enters a local HTTP Hub through the UI. Both block the bundled live Hub and
// leave the signed package untouched. Set CONSUMER_START_ZIP to record the tested archive hash.
// The executable fixtures implement only --version and PTY input/output, never model inference.
const loopback = process.argv.includes('--loopback');
const root = process.cwd(), args = process.argv.slice(2).filter(value => !['--local-profile', '--loopback'].includes(value));
assert.ok(args.length <= 1 && args.every(value => !value.startsWith('--')), 'Usage: consumer-start-canary.mjs [executable] [--local-profile|--loopback]');
const packaged = args[0] ? resolve(args[0]) : null;
const archiveSha256 = packaged && process.env.CONSUMER_START_ZIP ? createHash('sha256').update(await readFile(process.env.CONSUMER_START_ZIP)).digest('hex') : null;
const expectedVersion = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).version;
const temporary = await mkdtemp(join(tmpdir(), 'consumer-start-canary-')), profile = join(temporary, 'profile');
const codexHome = join(temporary, 'codex-home'), project = join(temporary, 'private-project-path');
const evidence = join(root, 'artifacts/desktop-evidence'), suffix = packaged ? '-packaged' : '';
const code = String(randomInt(10_000_000, 100_000_000)), adminToken = 'test_' + randomBytes(32).toString('hex');
const exitOutput = 'CANARY_PRIVATE_EXIT_OUTPUT', normalOutput = 'CANARY_PRIVATE_RUNNING_OUTPUT';
const checks = [], screenshots = [], pageErrors = [], requestCounts = {}, sessionResults = [];
const sockets = new Set(); let app, main, hub, tls, hubOrigin, failure;

async function localProfile() {
  const candidates = Object.entries(networkInterfaces()).flatMap(([name, entries]) => (entries ?? []).filter(item => item.family === 'IPv4' && /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(item.address)).map(item => ({ name, address: item.address })));
  const address = (candidates.find(item => !/^(utun|tun|tap)/.test(item.name)) ?? candidates[0])?.address;
  assert.ok(address, 'The isolated TLS fixture requires an existing local RFC1918 IPv4 interface.');
  const keyPath = join(temporary, 'hub.key'), certPath = join(temporary, 'hub.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', keyPath, '-out', certPath,
    '-subj', '/CN=Share Token consumer startup canary', '-addext', `subjectAltName=IP:${address}`, '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment', '-addext', 'extendedKeyUsage=serverAuth'], { stdio: 'ignore' });
  await chmod(keyPath, 0o600); const certificatePem = await readFile(certPath, 'utf8');
  const upstreamPort = Number(new URL(hub.url).port);
  tls = createHttpsServer({ key: await readFile(keyPath), cert: certificatePem, minVersion: 'TLSv1.2' }, (request, response) => {
    if (request.socket.remoteAddress !== address || request.headers.host !== new URL(hubOrigin).host || !request.url?.startsWith('/client/v2/') || request.url.includes('\\')) { response.writeHead(403); response.end(); return; }
    const entry = `${request.method} ${request.url.split('?')[0]}`; requestCounts[entry] = (requestCounts[entry] ?? 0) + 1;
    const upstream = httpRequest({ hostname: '127.0.0.1', port: upstreamPort, method: request.method, path: request.url,
      headers: { ...request.headers, host: new URL(hubOrigin).host, 'x-forwarded-proto': 'https' }, agent: false }, result => { response.writeHead(result.statusCode ?? 502, result.headers); result.pipe(response); });
    upstream.on('error', () => { if (!response.headersSent) response.writeHead(502); response.end(); }); request.on('aborted', () => upstream.destroy()); request.pipe(upstream);
  });
  tls.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); }); tls.on('upgrade', (_req, socket) => socket.destroy());
  await new Promise((resolve, reject) => { tls.once('error', reject); tls.listen(0, address, resolve); });
  hubOrigin = `https://${address}:${tls.address().port}`;
  const trust = validateHubTrustProfile({ version: 1, hubUrl: hubOrigin, certificatePem, label: 'Temporary local startup canary' });
  // Verify TLS through the real app worker: host shells may have different local-network access.
  return trust;
}

async function waitUntil(check, label, timeout = 20_000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) { if (await check()) return; await new Promise(resolve => setTimeout(resolve, 100)); }
  throw new Error(`Timed out: ${label}`);
}
const state = () => main.evaluate(() => window.shareToken.state());
const card = id => main.locator(`.card.session[data-session-id="${id}"]`);
async function waitSession(index, wanted) {
  await waitUntil(async () => (await state()).sessions[index]?.state === wanted, `session ${index} becomes ${wanted}`);
  return (await state()).sessions[index];
}
async function capture(page, name) {
  const path = join(evidence, `consumer-start-${name}${suffix}.png`); const codeInput = page.getByLabel(/^(配对码|匹配码)$/); await page.screenshot({ path, animations: 'disabled', mask: await codeInput.count() ? [codeInput] : [] }); screenshots.push(path);
  const size = await page.evaluate(() => ({ viewport: innerWidth, content: document.documentElement.scrollWidth })); assert.ok(size.content <= size.viewport + 1, `${name}: no horizontal overflow`);
}
async function chooseFile(path) {
  await app.evaluate(({ dialog }, file) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [file] }); }, path);
  const details = main.locator('details').filter({ has: main.getByText('没有找到 Codex 程序？', { exact: true }) });
  if (!await details.getAttribute('open').then(value => value !== null)) await details.locator('summary').click();
  await main.getByRole('button', { name: '手动选择 Codex', exact: true }).click();
}
async function prepareStart(executable, failedSession) {
  if (failedSession) await card(failedSession).getByRole('button', { name: '检查启动设置', exact: true }).click();
  await main.getByRole('heading', { name: '在你自己的电脑上工作', exact: true }).waitFor();
  await chooseFile(executable); await main.getByRole('button', { name: '下一步：准备启动', exact: true }).click();
}
async function closeTerminalWindows() { for (const page of app.windows()) if (page !== main) await page.close(); }
async function reopenTerminal(sessionId) {
  await closeTerminalWindows(); const opening = app.waitForEvent('window', { timeout: 15_000 });
  await card(sessionId).getByRole('button', { name: '查看终端输出', exact: true }).click();
  const terminal = await opening; terminal.on('pageerror', error => pageErrors.push(error.message));
  await terminal.locator('.terminal-mount .xterm').waitFor(); return terminal;
}

try {
  await Promise.all([mkdir(profile, { recursive: true }), mkdir(codexHome), mkdir(project), mkdir(evidence, { recursive: true })]);
  hub = await createHub({ dbPath: join(temporary, 'hub.sqlite'), adminToken, host: '127.0.0.1', port: 0 });
  if (loopback) {
    // Exercise the existing fail-closed saved-profile recovery: an invalid temporary profile
    // prevents fallback to the bundled live Hub. The signed app and its rules are untouched.
    await mkdir(join(profile, 'hub-trust'), { mode: 0o700 });
    await writeFile(join(profile, 'hub-trust', 'connection.json'), '{"canary":"invalid temporary connection"}', { mode: 0o600 });
    hubOrigin = hub.url;
  } else { const trust = await localProfile(); await saveHubTrustProfile(profile, trust); }
  const missingCli = join(temporary, 'selected-then-removed-codex'), exitingCli = join(temporary, 'exit-23-codex'), normalCli = join(temporary, 'interactive-codex');
  const version = `#!/bin/sh\nif [ "$1" = "--version" ]; then printf '%s\\n' 'codex-cli 0.153.4'; exit 0; fi\n`;
  await writeFile(missingCli, version + 'exit 0\n', { mode: 0o755 });
  await writeFile(exitingCli, version + `printf '%s\\n' '${exitOutput}'\nexit 23\n`, { mode: 0o755 });
  await writeFile(normalCli, version + `printf '%s\\n' '${normalOutput}'\nwhile IFS= read -r answer; do printf 'INPUT:%s\\n' "$answer"; if [ "$answer" = 'exit' ]; then exit 0; fi; done\n`, { mode: 0o755 });
  app = await electron.launch({ ...(packaged ? { executablePath: packaged } : {}), args: [...(packaged ? [] : ['.']), '--user-data-dir=' + profile], env: { ...process.env, SHARE_TOKEN_TEST_DATA_DIR: profile, CODEX_HOME: codexHome }, timeout: 30_000 });
  await app.evaluate(({ shell }) => { globalThis.__consumerStartExternalUrls = []; shell.openExternal = async url => { globalThis.__consumerStartExternalUrls.push(url); }; });
  main = await app.firstWindow(); main.setDefaultTimeout(15_000); main.on('pageerror', error => pageErrors.push(error.message));
  const identity = await app.evaluate(({ app }) => ({ version: app.getVersion(), packaged: app.isPackaged, profile: app.getPath('userData') }));
  assert.equal(identity.version, expectedVersion); assert.equal(identity.packaged, !!packaged); assert.equal(await realpath(identity.profile), await realpath(profile));
  await main.getByRole('button', { name: '使用共享', exact: true }).click();
  if (loopback) {
    assert.equal((await state()).hubTrust, null, 'The invalid temporary profile must block bundled-Hub fallback.');
    assert.equal((await state()).connected, false);
    await main.getByText('更多连接方式', { exact: true }).click(); await main.getByLabel('Hub 地址', { exact: true }).fill(hubOrigin);
    checks.push('temporary invalid profile blocks bundled-Hub fallback; real UI connects only to the supported loopback Hub');
  } else assert.equal((await state()).hubTrust?.hubUrl, hubOrigin, 'The isolated local profile must override every bundled default.');
  await main.getByLabel(/^(配对码|匹配码)$/).fill(code); await main.getByRole('button', { name: '加入朋友空间', exact: true }).click();
  await waitUntil(async () => (await state()).connected, 'local Hub pairing finishes');
  const member = (await state()).member, clients = new ClientStore(hub.store);
  const source = hub.store.createSource({ name: '本地启动验证来源', ownerId: member.id, kind: 'mock', accountBinding: 'mock:consumer-start-canary', policy: policySchema.parse({ allowedMemberIds: [member.id], models: ['mock-codex'] }) });
  clients.registerSource(source); hub.store.updateSource(source.id, { online: true });
  await main.getByLabel('来源', { exact: true }).selectOption(source.id); await main.getByRole('button', { name: '下一步：选择项目', exact: true }).click();
  await app.evaluate(({ dialog }, path) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [path] }); }, project);
  await main.getByRole('button', { name: '选择项目目录', exact: true }).click();

  await prepareStart(missingCli); await unlink(missingCli);
  await main.getByRole('button', { name: '启动 Codex', exact: true }).click(); const missing = await waitSession(0, 'failed');
  assert.equal(missing.errorCode, 'SHARE_CODEX_NOT_FOUND'); assert.equal(missing.terminalStarted, false); assert.equal(missing.pid, null);
  await card(missing.sessionId).getByText('启动失败', { exact: true }).waitFor(); assert.match(await card(missing.sessionId).innerText(), /没有找到|检查安装|Codex/);
  assert.equal(await card(missing.sessionId).getByRole('button', { name: /打开终端|查看终端输出/ }).count(), 0); assert.equal(app.windows().length, 1);
  sessionResults.push({ case: 'removed-selected-cli', state: missing.state, errorCode: missing.errorCode, terminalStarted: missing.terminalStarted });
  await card(missing.sessionId).scrollIntoViewIfNeeded(); await capture(main, 'missing-cli'); checks.push('real project/executable selection and start button show failed reason when selected executable disappears; no empty terminal action or window');

  await prepareStart(exitingCli, missing.sessionId); await main.getByRole('button', { name: '启动 Codex', exact: true }).click();
  const exited = await waitSession(1, 'failed'); assert.equal(exited.exitCode, 23); assert.equal(exited.terminalStarted, true); assert.equal(exited.pid, null); assert.ok(exited.errorCode);
  await card(exited.sessionId).getByText('异常退出', { exact: true }).waitFor(); assert.match(await card(exited.sessionId).innerText(), /23/);
  await main.getByText('Codex 会话已启动。可以在下方重新打开终端。', { exact: true }).waitFor({ state: 'hidden' });
  checks.push('quick failure never leaves a successful startup notice after its final state arrives');
  const stoppedTerminal = await reopenTerminal(exited.sessionId); const attachment = await stoppedTerminal.evaluate(() => window.shareToken.terminalAttach());
  assert.equal(attachment.session?.state, 'failed'); assert.equal(attachment.session?.exitCode, 23); assert.ok(attachment.backlog.includes(exitOutput));
  await stoppedTerminal.locator('header span').filter({ hasText: /23/ }).waitFor(); assert.match(await stoppedTerminal.locator('header span').innerText(), /异常退出/);
  await capture(stoppedTerminal, 'exit-23-reopened'); await closeTerminalWindows(); await card(exited.sessionId).scrollIntoViewIfNeeded(); await capture(main, 'exit-23-session');
  sessionResults.push({ case: 'pty-exit-23', state: exited.state, errorCode: exited.errorCode, exitCode: exited.exitCode, terminalStarted: exited.terminalStarted });
  checks.push('real PTY fixture exits 23; session retains failed reason; reopening its terminal preserves exit status and buffered output');

  await prepareStart(normalCli, exited.sessionId); const normalOpening = app.waitForEvent('window', { timeout: 15_000 });
  await main.getByRole('button', { name: '启动 Codex', exact: true }).click(); const normalTerminal = await normalOpening;
  normalTerminal.on('pageerror', error => pageErrors.push(error.message)); await normalTerminal.locator('.terminal-mount .xterm').waitFor();
  const running = await waitSession(2, 'running'); assert.equal(running.terminalStarted, true); assert.ok(running.pid > 0);
  await waitUntil(async () => (await normalTerminal.evaluate(() => window.shareToken.terminalAttach())).backlog.includes(normalOutput), 'normal PTY output arrives');
  await normalTerminal.locator('.xterm-helper-textarea').focus(); await normalTerminal.keyboard.type('exit'); await normalTerminal.keyboard.press('Enter');
  const stopped = await waitSession(2, 'stopped'); assert.equal(stopped.exitCode, 0); assert.equal(stopped.pid, null);
  await normalTerminal.locator('header span').filter({ hasText: /^已结束$/ }).waitFor();
  const normalAttachment = await normalTerminal.evaluate(() => window.shareToken.terminalAttach()); assert.ok(normalAttachment.backlog.includes('INPUT:exit'));
  await capture(normalTerminal, 'normal-exit'); await closeTerminalWindows();
  sessionResults.push({ case: 'interactive-normal-exit', state: stopped.state, errorCode: stopped.errorCode, exitCode: stopped.exitCode, terminalStarted: stopped.terminalStarted });
  checks.push('normal fixture starts in a real PTY, accepts xterm keyboard input and exits cleanly with retained output and ended status');

  const diagnosticsPath = join(temporary, 'diagnostics.json');
  await app.evaluate(({ dialog }, path) => { dialog.showSaveDialog = async () => ({ canceled: false, filePath: path }); }, diagnosticsPath);
  await main.getByRole('navigation').getByRole('button', { name: '设置', exact: true }).click(); await main.getByRole('button', { name: '导出诊断', exact: true }).click();
  await main.getByText('脱敏诊断已导出。', { exact: true }).waitFor(); const diagnosticsText = await readFile(diagnosticsPath, 'utf8'), diagnostics = JSON.parse(diagnosticsText);
  assert.equal(diagnostics.sessions.find(item => item.sessionId === missing.sessionId)?.errorCode, 'SHARE_CODEX_NOT_FOUND');
  assert.equal(diagnostics.sessions.find(item => item.sessionId === exited.sessionId)?.exitCode, 23);
  assert.ok(diagnostics.sessions.find(item => item.sessionId === exited.sessionId)?.errorCode);
  for (const value of [temporary, project, missingCli, exitingCli, normalCli, exitOutput, normalOutput, 'INPUT:exit', code, adminToken, 'refreshToken', 'accessToken']) assert.equal(diagnosticsText.includes(value), false, 'Diagnostic export must omit paths, output, matching codes and credentials.');
  checks.push('diagnostics exported through the UI contain error/exit codes and no file paths, terminal output, matching code or credentials');
  assert.deepEqual(await app.evaluate(() => globalThis.__consumerStartExternalUrls), []); assert.equal(hub.store.listRequests().length, 0); assert.deepEqual(pageErrors, []);
  for (const session of [missing, exited, stopped]) {
    assert.equal(clients.getSession(session.sessionId)?.state, 'closed');
    assert.equal(clients.getRun(session.leaseId)?.state, 'closed');
  }
  checks.push('all three ended/failed local sessions close their Hub session and run lease');
  const workerPids = execFileSync('ps', ['-axo', 'pid=,ppid=,command='], { encoding: 'utf8' }).split('\n').map(line => /^\s*(\d+)\s+(\d+)\s+(.+)$/.exec(line)).filter(row => row && Number(row[2]) === app.process().pid && row[3].includes('/apps/client-worker/host.js')).map(row => Number(row[1]));
  assert.equal(workerPids.length, 2, 'The canary must observe the app-owned consumer and donor workers.');
  await app.evaluate(({ dialog }) => { dialog.showMessageBox = async () => ({ response: 1, checkboxChecked: false }); });
  const quitting = app.waitForEvent('close', { timeout: 15_000 });
  await main.getByRole('button', { name: '退出共享token', exact: true }).click(); await quitting;
  for (const pid of workerPids) assert.throws(() => process.kill(pid, 0), error => error.code === 'ESRCH', 'Application quit must terminate both owned workers.');
  app = null; main = null;
  checks.push('real quit action stops and exits both app-owned workers');
} catch (error) {
  failure = error; if (main) await capture(main, 'failure').catch(() => {});
} finally {
  if (app) {
    const process = app.process(); await app.evaluate(({ app }) => app.exit(0)).catch(() => {});
    await new Promise(resolve => { if (process.exitCode !== null) resolve(); else { process.once('exit', resolve); setTimeout(resolve, 3000).unref(); } });
  }
  if (tls) { for (const socket of sockets) socket.destroy(); tls.closeAllConnections(); await new Promise(resolve => tls.close(resolve)); }
  if (hub) await hub.close(); await rm(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  const report = { appVersion: expectedVersion, time: new Date().toISOString(), packaged: !!packaged, archiveSha256, passed: !failure,
    environment: `real Electron + ${loopback ? 'temporary invalid-profile recovery and UI loopback HTTP connection' : 'temporary local TLS profile'} + isolated Hub + selected synthetic CLI executables in a real PTY; package unchanged`,
    checks, sessionResults, requestCounts, screenshots, pageErrors, realSubscriptionLoginTested: false, modelInferenceRequests: 0,
    ...(failure ? { error: failure.stack ?? String(failure) } : {}) };
  const serialized = JSON.stringify(report, null, 2).replaceAll(code, '[redacted-code]').replaceAll(adminToken, '[redacted-token]');
  await mkdir(evidence, { recursive: true }); await writeFile(join(evidence, `consumer-start-report${suffix}.json`), serialized + '\n'); console.log(serialized);
}
if (failure) process.exitCode = 1;
