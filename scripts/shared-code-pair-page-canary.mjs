import assert from 'node:assert/strict';
import { createHash, randomBytes, randomInt } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { chromium } from 'playwright';
import { createHub } from '../dist/apps/hub/index.js';
import { saveSharedCodeVerifier } from '../dist/packages/storage/shared-code.js';

// Build first. This test uses a real ephemeral Hub, browser, and synthetic code;
// no route mocks, deployed Hub, personal identity, or model inference is used.
const scratch = await mkdtemp(join(tmpdir(), 'share-code-page-'));
const sharedCodePath = join(scratch, 'shared-code.json');
const sharedCode = String(randomInt(100_000_000)).padStart(8, '0');
const wrongCode = sharedCode === '00000000' ? '11111111' : '00000000';
const admin = 'test_admin_' + randomBytes(32).toString('hex');
await saveSharedCodeVerifier(sharedCodePath, sharedCode);
const hub = await createHub({ dbPath: join(scratch, 'hub.sqlite'), adminToken: admin, port: 0, sharedCodePath });
const evidence = resolve('artifacts/ux-evidence');
const requests = [], checks = [], pageErrors = [], cspErrors = [], forbiddenUrlValues = [sharedCode, admin];
let browser;

async function api(path, body, status = 200) {
  const response = await fetch(hub.url + path, { method: body === undefined ? 'GET' : 'POST', headers: { 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  assert.equal(response.status, status, `${path} returned ${response.status}`);
  return response.json();
}
async function begin() {
  const codeVerifier = randomBytes(32).toString('base64url');
  const pair = await api('/client/v2/device-pairings', { deviceName: '朋友的 MacBook', platform: 'darwin', clientVersion: 'shared-code-ui-canary', requestedScopes: ['consumer', 'donor'], codeChallengeMethod: 'S256', codeChallenge: createHash('sha256').update(codeVerifier).digest('base64url') }, 201);
  forbiddenUrlValues.push(codeVerifier, pair.deviceCode);
  return { pair, codeVerifier };
}
async function sharedReady(page) {
  await page.locator('#shared-code').waitFor({ state: 'visible' });
  await page.waitForFunction(() => !document.getElementById('shared-submit').disabled);
}

try {
  await mkdir(evidence, { recursive: true });
  const channel = process.env.SHARE_PAIRING_BROWSER_CHANNEL || (existsSync(chromium.executablePath()) ? undefined : 'chrome');
  browser = await chromium.launch({ headless: true, ...(channel ? { channel } : {}) });
  const page = await browser.newPage({ viewport: { width: 1120, height: 820 }, locale: 'zh-CN' });
  page.setDefaultTimeout(10_000);
  page.on('pageerror', error => pageErrors.push(error.message));
  page.on('console', message => { if (/content security policy|refused to (?:load|apply|execute)/i.test(message.text())) cspErrors.push(message.text()); });
  page.on('request', request => {
    requests.push(new URL(request.url()).pathname);
    for (const value of forbiddenUrlValues) assert.equal(request.url().includes(value), false, 'Secrets must never appear in URLs.');
  });
  const first = await begin();
  await page.goto(first.pair.verificationUriComplete);
  await sharedReady(page);
  assert.equal(requests.filter(path => path === '/control/session').length, 0);
  assert.equal(await page.locator('input:visible').count(), 1);
  assert.equal(await page.locator('#token').isVisible(), false);
  await page.screenshot({ path: join(evidence, 'pairing-shared-code-desktop.png'), fullPage: true });
  checks.push('shared-code default needs one field and does not request cookie login');

  await page.locator('#shared-code').fill(wrongCode);
  await page.locator('#shared-submit').click();
  await page.getByText('配对码不正确，请和朋友确认后重新输入。', { exact: true }).waitFor();
  assert.equal(await page.locator('#shared-code').inputValue(), '');
  assert.equal(hub.store.listMembers().length, 1);
  checks.push('wrong code clears the field, shows an inline explanation, and creates no member');

  await page.locator('#other-methods summary').click();
  await page.locator('#token').waitFor({ state: 'visible' });
  await page.waitForFunction(() => !document.getElementById('login-submit').disabled);
  assert.equal(requests.filter(path => path === '/control/session').length, 1);
  await page.locator('#other-methods summary').click();
  await sharedReady(page);
  assert.equal(await page.locator('input:visible').count(), 1);
  checks.push('legacy login loads only after explicitly opening other connection methods');

  await page.locator('#shared-code').fill(sharedCode);
  const joinedResponse = page.waitForResponse(response => response.url().endsWith(`/control/v2/device-pairings/${first.pair.userCode}/join`));
  await page.locator('#shared-submit').click();
  const joined = await joinedResponse;
  assert.equal(joined.status(), 200);
  assert.equal(Object.keys(joined.headers()).includes('set-cookie'), false);
  const joinedBody = await joined.json();
  assert.deepEqual(Object.keys(joinedBody), ['pairing']);
  await page.getByText('已确认连接', { exact: true }).waitFor();
  assert.equal(await page.locator('input:visible').count(), 0);
  assert.equal(await page.evaluate(() => Object.keys(localStorage).length + Object.keys(sessionStorage).length), 0);
  assert.equal(hub.store.listMembers().length, 2);
  await api('/client/v2/device-pairings/token', { deviceCode: first.pair.deviceCode, codeVerifier: 'X'.repeat(43) }, 401);
  const auth = await api('/client/v2/device-pairings/token', { deviceCode: first.pair.deviceCode, codeVerifier: first.codeVerifier });
  forbiddenUrlValues.push(auth.accessToken, auth.refreshToken);
  assert.equal(auth.member.role, 'member');
  assert.deepEqual(auth.device.scopes, ['consumer', 'donor']);
  checks.push('real browser approval returns no cookie or token; only original desktop PKCE redeems ordinary-device identity');

  await page.goto(hub.url + '/pair');
  await page.getByText('请从余量应用发起连接', { exact: true }).waitFor();
  assert.equal(await page.locator('input:visible').count(), 0);
  checks.push('missing device URL directs the user to the app without credential fields');
  await page.goto(hub.url + '/pair?code=%3Cscript%3E');
  await page.getByText('请从余量应用发起连接', { exact: true }).waitFor();
  checks.push('invalid URL device code never becomes an approval target');

  const mobilePair = await begin();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(mobilePair.pair.verificationUriComplete);
  await sharedReady(page);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.screenshot({ path: join(evidence, 'pairing-shared-code-mobile.png'), fullPage: true });
  checks.push('mobile form fits the viewport without horizontal scrolling');

  hub.store.db.prepare("UPDATE client_objects SET data=json_set(data,'$.expiresAt',?) WHERE kind='pairing' AND id=?").run(Date.now() - 1000, mobilePair.pair.pairingId);
  await page.locator('#shared-code').fill(sharedCode);
  await page.locator('#shared-submit').click();
  await page.getByText('这次连接已结束或过期，请回到余量应用重新发起连接。', { exact: true }).waitFor();
  assert.equal(hub.store.listMembers().length, 2);
  checks.push('expired pairing shows a clear restart instruction and cannot create a member');

  await unlink(sharedCodePath);
  await page.goto(mobilePair.pair.verificationUriComplete);
  await page.locator('#token').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#shared-code').isVisible(), false);
  assert.equal(await page.locator('#other-methods summary').isVisible(), false);
  checks.push('disabled shared-code preserves legacy login');
  assert.deepEqual(pageErrors, []);
  assert.deepEqual(cspErrors, []);
  const report = { at: new Date().toISOString(), passed: true, environment: 'real ephemeral loopback Hub + isolated Chrome + synthetic shared code; no route mocks', checks, pageErrors, cspErrors, realSubscriptionLoginTested: false, modelInferenceRequests: 0 };
  await writeFile(join(evidence, 'pairing-shared-code-ui.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
} finally {
  await browser?.close();
  await hub.close();
  await rm(scratch, { recursive: true, force: true });
}
