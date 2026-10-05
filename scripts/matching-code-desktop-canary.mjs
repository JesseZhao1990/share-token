import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes, randomInt } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { networkInterfaces, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { _electron as electron } from 'playwright';
import { createHub } from '../dist/apps/hub/index.js';
import { createLocalSecretCipher } from '../dist/packages/platform/local-secret.js';
import { createHubFetch, validateHubTrustProfile } from '../dist/packages/hub-client/trust.js';
import { saveHubTrustProfile } from '../dist/apps/desktop/main/hub-trust.js';

// Run after building: node scripts/matching-code-desktop-canary.mjs [executable] [--local-profile].
// The Hub deliberately has no administrator-preconfigured sharedCodePath.
// Every app profile and CODEX_HOME is temporary. No subscription or model is used.
// Bundles with a real connection profile are refused unless --local-profile puts
// a validated, temporary profile ahead of the bundle. That mode binds TLS to an
// existing local RFC1918 interface (the production validator excludes loopback),
// accepts only self-originating traffic, and forwards only to the temporary Hub.
const root = process.cwd();
const arguments_ = process.argv.slice(2);
const localProfileRequested = arguments_.includes('--local-profile');
const positional = arguments_.filter(value => value !== '--local-profile');
assert.ok(positional.length <= 1 && positional.every(value => !value.startsWith('--')), 'Usage: matching-code-desktop-canary.mjs [executable] [--local-profile]');
const packaged = positional[0] ? resolve(positional[0]) : null;
const expectedVersion = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).version;
const temporary = await mkdtemp(join(tmpdir(), 'matching-code-desktop-'));
const evidence = join(root, 'artifacts/desktop-evidence');
const suffix = packaged ? '-packaged' : '';
const sharedCode = String(randomInt(10_000_000, 100_000_000));
const otherCode = String((Number(sharedCode) + 1) % 100_000_000).padStart(8, '0');
const adminToken = 'test_' + randomBytes(32).toString('hex');
const instances = [], checks = [], layouts = [], screenshots = [], pageErrors = [];
let hub, hubOrigin, localProfile, tlsServer, failure, matchingCodeAvailable = false, bundledProfileRefused = false;
let matchingJoins = 0, nativeRestarts = 0, modelInferenceRequests = 0;
const tlsSockets = new Set(), tlsRequestCounts = {};
let nonLocalRequestsRejected = 0;

async function prepareLocalProfile() {
  const candidates = Object.entries(networkInterfaces()).flatMap(([name, addresses]) => (addresses ?? [])
    .filter(value => value.family === 'IPv4' && /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(value.address))
    .map(value => ({ name, address: value.address })));
  const address = (candidates.find(value => !/^(utun|tun|tap)/.test(value.name)) ?? candidates[0])?.address;
  assert.ok(address, '--local-profile needs an existing local RFC1918 IPv4 interface. No app was launched and the default bundled-profile refusal remains in force.');
  const keyPath = join(temporary, 'local-hub.key'), certPath = join(temporary, 'local-hub.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', keyPath, '-out', certPath,
    '-subj', '/CN=Share Token local matching canary', '-addext', `subjectAltName=IP:${address}`,
    '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
    '-addext', 'extendedKeyUsage=serverAuth'], { stdio: 'ignore' });
  await chmod(keyPath, 0o600);
  const key = await readFile(keyPath), certificatePem = await readFile(certPath, 'utf8');
  const upstreamPort = Number(new URL(hub.url).port);
  tlsServer = createHttpsServer({ key, cert: certificatePem, minVersion: 'TLSv1.2' }, (request, response) => {
    if (request.socket.remoteAddress !== address) {
      nonLocalRequestsRejected++;
      response.writeHead(403); response.end('Local canary accepts only its own interface address.'); return;
    }
    if (request.headers.host !== new URL(hubOrigin).host || !request.url?.startsWith('/client/v2/') || request.url.includes('\\')) {
      response.writeHead(403); response.end('Unexpected local canary target.'); return;
    }
    const entry = `${request.method} ${request.url.split('?')[0]}`;
    tlsRequestCounts[entry] = (tlsRequestCounts[entry] ?? 0) + 1;
    // No request URL, Host value or redirect can select another upstream.
    const upstream = httpRequest({ hostname: '127.0.0.1', port: upstreamPort, method: request.method, path: request.url,
      headers: { ...request.headers, host: new URL(hubOrigin).host, 'x-forwarded-proto': 'https' }, agent: false }, result => {
      response.writeHead(result.statusCode ?? 502, result.headers);
      result.pipe(response);
    });
    upstream.on('error', () => { if (!response.headersSent) response.writeHead(502); response.end(); });
    request.on('aborted', () => upstream.destroy());
    request.pipe(upstream);
  });
  tlsServer.on('connection', socket => { tlsSockets.add(socket); socket.once('close', () => tlsSockets.delete(socket)); });
  tlsServer.on('upgrade', (_request, socket) => socket.destroy());
  await new Promise((resolve, reject) => { tlsServer.once('error', reject); tlsServer.listen(0, address, resolve); });
  hubOrigin = `https://${address}:${tlsServer.address().port}`;
  localProfile = validateHubTrustProfile({ version: 1, hubUrl: hubOrigin, certificatePem, label: 'Temporary local matching canary' });
  const metaResponse = await createHubFetch(localProfile)(hubOrigin + '/client/v2/meta', { signal: AbortSignal.timeout(5000) });
  assert.equal(metaResponse.status, 200, 'Local TLS fixture must pass real certificate and exact-leaf validation.');
  await metaResponse.arrayBuffer();
  const rejectedStatus = await new Promise((resolve, reject) => {
    const request = httpsRequest(hubOrigin + '/client/v2/meta', { localAddress: '127.0.0.1', ca: certificatePem, rejectUnauthorized: true, agent: false }, response => {
      response.resume(); response.once('end', () => resolve(response.statusCode));
    });
    request.setTimeout(5000, () => request.destroy(new Error('Local TLS source guard timed out.')));
    request.once('error', reject); request.end();
  });
  assert.equal(rejectedStatus, 403, 'TLS proxy must reject traffic from any source address except its own bound interface.');
  assert.equal(nonLocalRequestsRejected, 1);
  checks.push('temporary pinned TLS profile uses an existing local interface; proxy source guard rejects another local source and forwards only to the loopback fixture');
}

const purposeTitle = purpose => purpose === 'donor' ? '提供共享' : '使用共享';
const codeInput = instance => instance.window.getByLabel(/^(配对码|匹配码)$/);
const memberIds = state => (state.members ?? []).map(member => member.id).sort();
const snapshot = instance => instance.window.evaluate(() => window.shareToken.state());

async function screenshot(instance, label) {
  const path = join(evidence, `matching-code-${label}${suffix}.png`);
  const input = codeInput(instance);
  await instance.window.screenshot({ path, animations: 'disabled', mask: await input.count() ? [input] : [], maskColor: '#dbe5d7' });
  screenshots.push(path);
}

async function launch(profileName) {
  const profile = join(temporary, profileName), codexHome = join(temporary, profileName + '-codex');
  await mkdir(profile, { recursive: true });
  await mkdir(codexHome, { recursive: true });
  if (localProfile) await saveHubTrustProfile(profile, localProfile);
  const app = await electron.launch({
    ...(packaged ? { executablePath: packaged } : {}),
    args: [...(packaged ? [] : ['.']), '--user-data-dir=' + profile],
    env: { ...process.env, SHARE_TOKEN_TEST_DATA_DIR: profile, CODEX_HOME: codexHome },
    timeout: 30_000,
  });
  const instance = { app, profile, profileName, window: null, closed: false, additionalWindows: 0 };
  instances.push(instance);
  await app.evaluate(({ shell }) => {
    globalThis.__matchingCodeExternalUrls = [];
    shell.openExternal = async url => { globalThis.__matchingCodeExternalUrls.push(url); };
  });
  instance.window = await app.firstWindow();
  instance.window.setDefaultTimeout(15_000);
  app.on('window', window => { if (window !== instance.window) instance.additionalWindows++; });
  instance.window.on('pageerror', error => pageErrors.push(error.message));
  const identity = await app.evaluate(({ app }) => ({ version: app.getVersion(), packaged: app.isPackaged, userData: app.getPath('userData') }));
  assert.equal(identity.version, expectedVersion);
  assert.equal(identity.packaged, !!packaged);
  assert.equal(await realpath(identity.userData), await realpath(profile), 'Matching canary must only use its temporary app profile.');
  await instance.window.getByRole('button', { name: '使用共享', exact: true }).waitFor();
  const state = await snapshot(instance);
  if (localProfile) {
    assert.equal(state.hubTrust?.hubUrl, hubOrigin, 'Temporary profile must override any real bundled Hub before app use.');
    assert.equal(state.hubTrust?.fingerprint256, localProfile.fingerprint256);
  } else if (state.hubTrust) {
    bundledProfileRefused = true;
    throw new Error('Matching canary refuses a bundled Hub profile. Use a source/unconfigured build; no remote pairing or join was submitted.');
  }
  if (state.hubUrl) assert.equal(new URL(state.hubUrl).origin, hubOrigin, 'Restored profiles may reconnect only to this canary Hub.');
  return instance;
}

async function noBrowserOpened(instance) {
  assert.equal(instance.additionalWindows, 0);
  assert.equal(instance.app.windows().length, 1);
  assert.deepEqual(await instance.app.evaluate(() => globalThis.__matchingCodeExternalUrls), []);
}

async function verifyIdentity(instance, state) {
  assert.equal(state.connected, true);
  assert.equal(state.hubUrl, hubOrigin, 'Every joined identity must use only the temporary test Hub.');
  if (localProfile) assert.equal(state.hubTrust?.hubUrl, hubOrigin);
  assert.equal(state.matchingRoom, true, 'Joined and restored identities must remain in a matching-code group.');
  assert.equal(state.member.role, 'member');
  assert.ok(state.member.id && state.device.id);
  assert.equal(state.pairing, null, 'Matching code must not require a later browser approval.');
  assert.equal(state.credentialStorage, 'local-encrypted');
  assert.equal((state.requests ?? []).length, 0);
  const serialized = JSON.stringify(state);
  assert.ok(!serialized.includes(sharedCode) && !serialized.includes(otherCode), 'Renderer state must not retain matching codes.');
  assert.ok(!serialized.includes('refreshToken'));
  const path = join(instance.profile, 'local-secrets/device.encrypted');
  const encrypted = await readFile(path);
  if (process.platform !== 'win32') assert.equal((await stat(path)).mode & 0o077, 0);
  const cipher = await createLocalSecretCipher(join(await realpath(instance.profile), 'local-secrets'));
  const plain = cipher.decrypt(encrypted), saved = JSON.parse(plain);
  assert.ok(!plain.includes(sharedCode) && !plain.includes(otherCode), 'Saved credentials must not persist the matching code.');
  assert.equal(saved.credentials.deviceId, state.device.id);
  assert.equal(saved.credentials.memberId, state.member.id);
  assert.equal(typeof saved.credentials.refreshToken, 'string');
  const browserStorageClean = await instance.window.evaluate(codes => {
    const value = JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } });
    return codes.every(code => !value.includes(code));
  }, [sharedCode, otherCode]);
  assert.equal(browserStorageClean, true);
  await noBrowserOpened(instance);
}

async function layout(instance, label) {
  await instance.window.evaluate(() => {
    window.scrollTo(0, 0);
    for (const element of document.querySelectorAll('.onboarding, .onboarding-main')) element.scrollTop = 0;
  });
  const dimensions = await instance.window.evaluate(() => new Promise(resolve => requestAnimationFrame(() => {
    const bounds = selector => {
      const { x, y, right, height } = document.querySelector(selector).getBoundingClientRect();
      return { x, y, right, height };
    };
    const header = document.querySelector('.onboarding > .welcome-bar');
    const brand = header.querySelector('.brand').getBoundingClientRect();
    resolve({ viewport: { width: innerWidth, height: innerHeight }, documentWidth: document.documentElement.scrollWidth,
      header: bounds('.onboarding > .welcome-bar'), panel: bounds('.shared-code-panel'), story: bounds('.onboarding-story'),
      brandUncovered: header.contains(document.elementFromPoint(brand.x + brand.width / 2, brand.y + brand.height / 2)) });
  })));
  assert.ok(dimensions.documentWidth <= dimensions.viewport.width + 1, `${label}: no horizontal overflow.`);
  assert.ok(Math.abs(dimensions.header.y) <= 1 && Math.abs(dimensions.header.height - 87) <= 1);
  assert.equal(dimensions.brandUncovered, true);
  assert.ok(dimensions.panel.x >= 0 && dimensions.panel.right <= dimensions.viewport.width + 1);
  layouts.push({ label, ...dimensions });
  return dimensions;
}

async function verifyAdvancedLayout(instance, code) {
  const page = instance.window;
  const collapsed = await layout(instance, 'default-collapsed');
  await screenshot(instance, 'default-collapsed');
  await page.getByText('更多连接方式', { exact: true }).click();
  const expanded = await layout(instance, 'default-expanded');
  assert.ok(Math.abs(collapsed.story.y - expanded.story.y) <= 1);
  assert.ok(Math.abs(collapsed.panel.y - expanded.panel.y) <= 1);
  await screenshot(instance, 'default-expanded');
  const minimum = await instance.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].getMinimumSize());
  for (const [width, height] of [[980, 680], minimum]) {
    await instance.app.evaluate(({ BrowserWindow }, size) => BrowserWindow.getAllWindows()[0].setSize(...size), [width, height]);
    await layout(instance, `${width}x${height}-expanded`);
    const address = page.getByLabel('Hub 地址', { exact: true });
    await address.scrollIntoViewIfNeeded();
    await address.fill(hubOrigin);
    const name = page.getByLabel('设备名称', { exact: true });
    await name.fill(`Matching canary ${width}x${height}`);
    const button = page.getByRole('button', { name: '连接并配对', exact: true });
    await button.scrollIntoViewIfNeeded();
    await button.click({ trial: true });
    const header = await page.locator('.onboarding > .welcome-bar').boundingBox();
    assert.ok(header && Math.abs(header.y) <= 1 && Math.abs(header.height - 87) <= 1);
    assert.equal(await codeInput(instance).inputValue(), code);
    await screenshot(instance, `${width}x${height}-advanced-controls`);
  }
  await instance.app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(1180, 800));
  await page.getByText('更多连接方式', { exact: true }).click();
  assert.equal(await page.getByLabel('Hub 地址', { exact: true }).isVisible(), false);
  assert.equal(await codeInput(instance).inputValue(), code);
  checks.push('matching input survives advanced connection edits; default, 980x680 and native minimum retain fixed header and reachable controls');
}

async function joinMatching(instance, purpose, code, testLayout = false) {
  const page = instance.window;
  await page.getByRole('button', { name: purposeTitle(purpose), exact: true }).click();
  const input = codeInput(instance);
  await input.waitFor();
  assert.equal(await input.isEnabled(), true);
  await input.click();
  await input.pressSequentially(code);
  assert.equal(await page.getByRole('button', { name: '加入朋友空间', exact: true }).isEnabled(), !!localProfile);
  if (testLayout) await verifyAdvancedLayout(instance, code);
  else {
    await page.getByText('更多连接方式', { exact: true }).click();
    await page.getByLabel('Hub 地址', { exact: true }).fill(hubOrigin);
    await page.getByText('更多连接方式', { exact: true }).click();
  }
  assert.equal(await input.inputValue(), code);
  await screenshot(instance, `${instance.profileName}-entered`);
  await page.getByRole('button', { name: '加入朋友空间', exact: true }).click();
  await page.getByRole('navigation', { name: `${purposeTitle(purpose)}导航`, exact: true }).waitFor();
  const state = await snapshot(instance);
  await verifyIdentity(instance, state);
  matchingJoins++;
  return state;
}

async function assertRoom(instance, expectedMembers) {
  const state = await snapshot(instance);
  assert.deepEqual(memberIds(state), [...expectedMembers].sort(), 'Only members using the same matching code may be visible.');
  await instance.window.getByRole('button', { name: '刷新状态', exact: true }).click();
  return state;
}

async function friendVisible(instance) {
  await instance.window.getByTestId('friend-match-status').filter({ hasText: /朋友已加入/ }).waitFor();
}

async function quit(instance) {
  if (instance.closed) return;
  await instance.app.evaluate(({ dialog }) => { dialog.showMessageBox = async () => ({ response: 1, checkboxChecked: false }); });
  const closed = instance.app.waitForEvent('close', { timeout: 15_000 });
  await instance.window.evaluate(() => window.shareToken.quit()).catch(error => {
    if (!/closed|destroyed|Target/i.test(error.message)) throw error;
  });
  await closed;
  instance.closed = true;
}

try {
  await mkdir(evidence, { recursive: true });
  hub = await createHub({ dbPath: join(temporary, 'hub.sqlite'), adminToken, host: '127.0.0.1', port: 0 });
  assert.equal(new URL(hub.url).hostname, '127.0.0.1');
  hubOrigin = hub.url;
  if (localProfileRequested) await prepareLocalProfile();
  const response = await fetch(hub.url + '/client/v2/meta', { signal: AbortSignal.timeout(5000) });
  assert.equal(response.status, 200);
  const meta = await response.json();
  matchingCodeAvailable = meta.pairing?.matchingCodeAvailable === true;
  assert.equal(matchingCodeAvailable, true, 'Fresh Hub must support arbitrary matching codes without administrator setup.');
  assert.equal(meta.pairing.sharedCodeAvailable, false, 'No administrator-shared-code verifier may be configured in this test.');
  const initialMemberCount = hub.store.listMembers().length;
  checks.push('fresh loopback Hub advertises matchingCodeAvailable without a preconfigured shared code');

  const first = await launch('consumer-first');
  const firstState = await joinMatching(first, 'consumer', sharedCode, true);
  await assertRoom(first, [firstState.member.id]);
  await first.window.getByTestId('friend-match-status').filter({ hasText: /等待朋友输入相同配对码/ }).waitFor();
  assert.equal(hub.store.listMembers().length, initialMemberCount + 1);
  await screenshot(first, 'first-member-connected-alone');
  checks.push('first person immediately enters the connected workspace before the second app is even launched');

  const second = await launch('donor-second');
  const secondState = await joinMatching(second, 'donor', sharedCode);
  assert.notEqual(secondState.member.id, firstState.member.id);
  assert.notEqual(secondState.device.id, firstState.device.id);
  const friends = [firstState.member.id, secondState.member.id];
  await assertRoom(first, friends);
  await assertRoom(second, friends);
  await friendVisible(first);
  await friendVisible(second);
  await screenshot(first, 'consumer-friend-visible');
  await screenshot(second, 'donor-friend-visible');
  checks.push('two independent profiles use the same arbitrary code, see each other and display friend-joined feedback');

  const third = await launch('consumer-other-code');
  const thirdState = await joinMatching(third, 'consumer', otherCode);
  await assertRoom(third, [thirdState.member.id]);
  await third.window.getByTestId('friend-match-status').filter({ hasText: /等待朋友输入相同配对码/ }).waitFor();
  await assertRoom(first, friends);
  await assertRoom(second, friends);
  assert.equal(await third.window.getByTestId('friend-match-status').filter({ hasText: /朋友已加入/ }).count(), 0, 'Unrelated matching code must not display a friend from the first group.');
  assert.equal(hub.store.listMembers().length, initialMemberCount + 3);
  await screenshot(third, 'other-code-isolated');
  checks.push('third profile with a different code sees only itself; original two profiles cannot see the third member');

  await quit(first);
  await quit(second);
  for (const [profileName, purpose, expected] of [['consumer-first', 'consumer', firstState], ['donor-second', 'donor', secondState]]) {
    const restored = await launch(profileName);
    const state = await snapshot(restored);
    await verifyIdentity(restored, state);
    assert.equal(state.member.id, expected.member.id);
    assert.equal(state.device.id, expected.device.id);
    await restored.window.getByRole('button', { name: purposeTitle(purpose), exact: true }).click();
    await restored.window.getByRole('navigation', { name: `${purposeTitle(purpose)}导航`, exact: true }).waitFor();
    assert.equal(await codeInput(restored).count(), 0, 'Restart must not ask either friend for the matching code again.');
    await assertRoom(restored, friends);
    await friendVisible(restored);
    await screenshot(restored, `${profileName}-restored`);
    nativeRestarts++;
  }
  await assertRoom(third, [thirdState.member.id]);
  assert.equal(hub.store.listMembers().length, initialMemberCount + 3, 'Restart must reuse each member instead of creating duplicates.');
  modelInferenceRequests = hub.store.listRequests().length;
  assert.equal(modelInferenceRequests, 0);
  if (localProfile) {
    assert.equal(tlsRequestCounts['POST /client/v2/device-pairings/match'], 3, 'Packaged workers must complete all three matching joins through the local TLS fixture.');
    assert.equal(tlsRequestCounts['POST /client/v2/device-pairings/join'] ?? 0, 0, 'Matching must not fall back to the administrator shared-code endpoint.');
    assert.equal(nonLocalRequestsRejected, 1, 'Only the deliberate source-guard probe should be rejected.');
  }
  assert.deepEqual(pageErrors, []);
  checks.push('both friends restart with their original member/device identities, same isolated group and no matching-code prompt');
  checks.push('matching codes are absent from renderer state, browser storage and decrypted device credentials; no subscription/model calls');
} catch (error) {
  failure = error;
} finally {
  for (const instance of instances) {
    if (instance.closed) continue;
    await quit(instance).catch(async error => {
      failure ??= error;
      const child = instance.app.process();
      await instance.app.evaluate(({ app }) => app.exit(0)).catch(() => {});
      await new Promise(resolve => {
        if (child.exitCode !== null) resolve();
        else { child.once('exit', resolve); setTimeout(resolve, 3000).unref(); }
      });
    });
  }
  if (tlsServer) {
    for (const socket of tlsSockets) socket.destroy();
    tlsServer.closeAllConnections();
    await new Promise(resolve => tlsServer.close(resolve));
  }
  if (hub) await hub.close();
  await rm(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  const report = {
    appVersion: expectedVersion, time: new Date().toISOString(), packaged: !!packaged, passed: !failure,
    environment: localProfile
      ? 'real Electron + temporary validated local-interface TLS profiles + self-only TLS proxy to a loopback Hub without sharedCodePath; application bundle unchanged'
      : 'real Electron + three temporary userData/CODEX_HOME profiles + loopback Hub without sharedCodePath',
    localProfileRequested, localProfileUsed: !!localProfile, tlsRequestCounts, nonLocalRequestsRejected,
    matchingCodeAvailable, administratorPresetCodeRequired: false, bundledProfileRefused,
    matchingJoins, nativeRestarts, modelInferenceRequests, realSubscriptionLoginTested: false,
    externalBrowserWindowsOpened: 0, hubApprovalWindowsOpened: 0,
    checks, layouts, screenshots, pageErrors, ...(failure ? { error: failure.stack ?? String(failure) } : {}),
  };
  const json = JSON.stringify(report, null, 2).replaceAll(sharedCode, '[redacted-code]').replaceAll(otherCode, '[redacted-other-code]').replaceAll(adminToken, '[redacted-token]');
  await mkdir(evidence, { recursive: true });
  await writeFile(join(evidence, `matching-code-report${suffix}.json`), json + '\n');
  console.log(json);
}
if (failure) process.exitCode = 1;
