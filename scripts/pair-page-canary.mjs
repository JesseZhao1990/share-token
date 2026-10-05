import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { chromium } from 'playwright';
import { createHub } from '../dist/apps/hub/index.js';

// Runs against an ephemeral local Hub and synthetic identities only. Build first.
const root = process.cwd();
const evidence = resolve(root, 'artifacts/ux-evidence');
const scratch = await mkdtemp(join(tmpdir(), 'share-pair-ux-'));
const admin = 'test_' + randomBytes(32).toString('hex');
const secrets = [admin];
const version = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).version;
const hub = await createHub({ dbPath: join(scratch, 'hub.sqlite'), adminToken: admin, port: 0 });
const checks = [], screenshots = [], pageErrors = [], cspErrors = [], contexts = [];
let browser;

async function request(path, body, { token, status = 200, method = body === undefined ? 'GET' : 'POST' } = {}) {
  const response = await fetch(hub.url + path, {
    method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const data = await response.json();
  assert.equal(response.status, status, `${path} returned ${response.status} (${data.error?.code ?? 'unexpected response'})`);
  return data;
}

async function pairing(scopes = ['consumer', 'donor']) {
  const verifier = randomBytes(48).toString('base64url');
  const result = await request('/client/v2/device-pairings', {
    deviceName: '林霖的 MacBook', platform: 'darwin', clientVersion: version,
    requestedScopes: scopes, codeChallengeMethod: 'S256', codeChallenge: createHash('sha256').update(verifier).digest('base64url'),
  }, { status: 201 });
  secrets.push(verifier, result.deviceCode);
  return { ...result, verifier };
}

function pairingRecord(pair) {
  return JSON.parse(hub.store.db.prepare("SELECT data FROM client_objects WHERE kind='pairing' AND id=?").get(pair.pairingId).data);
}

async function redeem(pair, status = 200) {
  const auth = await request('/client/v2/device-pairings/token', { deviceCode: pair.deviceCode, codeVerifier: pair.verifier }, { status });
  if (auth.accessToken) secrets.push(auth.accessToken, auth.refreshToken);
  return auth;
}

async function pageInNewContext(viewport = { width: 1440, height: 1000 }) {
  const context = await browser.newContext({ viewport, locale: 'zh-CN', colorScheme: 'light' });
  contexts.push(context);
  const page = await context.newPage();
  page.setDefaultTimeout(10_000);
  page.on('pageerror', error => pageErrors.push(error.message));
  page.on('console', message => { if (/content security policy|refused to (?:load|apply|execute)/i.test(message.text())) cspErrors.push(message.text()); });
  page.on('request', value => { for (const secret of secrets) assert.equal(value.url().includes(secret), false, 'Credentials must never appear in URLs.'); });
  return page;
}

async function screenshot(page, name) {
  // The credential-saved acknowledgement is photographed only after the secret panel closes.
  // Password and credential elements are additionally masked in every artifact.
  const path = join(evidence, `pairing-${name}.png`);
  await page.screenshot({ path, fullPage: true, mask: [page.locator('input[type="password"]'), page.locator('#new-credential')] });
  screenshots.push(path);
}

async function noHorizontalOverflow(page) {
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true, 'Pairing page overflows its viewport.');
}

async function login(page, token = admin) {
  await page.locator('#tab-login').click();
  await page.locator('#token').fill(token);
  await page.locator('#login-submit').click();
}

async function detailsReady(page) {
  await page.locator('#details').waitFor({ state: 'visible' });
  await page.waitForFunction(() => {
    const button = document.getElementById('approve');
    return button && !button.disabled && !button.closest('[hidden]');
  });
}

async function cannotApprove(page) {
  assert.equal(await page.locator('#approve').isVisible() && await page.locator('#approve').isEnabled(), false, 'Finished or invalid pairings must not remain approvable.');
}

try {
  await mkdir(evidence, { recursive: true });
  // Prefer the installed Playwright browser; an existing Chrome installation can
  // provide the isolated temporary browser when the pinned revision is absent.
  const channel = process.env.SHARE_PAIRING_BROWSER_CHANNEL || (existsSync(chromium.executablePath()) ? undefined : 'chrome');
  browser = await chromium.launch({ headless: true, ...(channel ? { channel } : {}) });
  const page = await pageInNewContext();
  const first = await pairing(['consumer']);
  const response = await page.goto(first.verificationUriComplete);
  assert.equal(response.status(), 200);
  assert.match(response.headers()['content-security-policy'], /script-src 'self'/);
  const css = await fetch(hub.url + '/pair.css');
  assert.equal(css.status, 200);
  assert.match(css.headers.get('content-type'), /text\/css/);
  await page.waitForFunction(() => [...document.styleSheets].some(sheet => sheet.href?.endsWith('/pair.css')));
  await noHorizontalOverflow(page);
  await screenshot(page, 'desktop-welcome');
  checks.push('same-origin pair.css loads under production CSP');

  await login(page, 'invalid_synthetic_member_credential');
  await page.locator('#message').filter({ hasText: /.+/ }).waitFor();
  await cannotApprove(page);
  checks.push('invalid member credential leaves pairing unapproved');
  await login(page);
  await detailsReady(page);
  assert.equal(pairingRecord(first).status, 'pending', 'Login and lookup must not implicitly approve the device.');
  assert.equal(await page.locator('#code').inputValue(), first.userCode);
  await screenshot(page, 'desktop-confirm');
  await page.locator('#approve').click();
  await page.locator('#result').waitFor({ state: 'visible' });
  assert.equal(pairingRecord(first).status, 'approved');
  const firstAuth = await redeem(first);
  assert.deepEqual(firstAuth.device.scopes, ['consumer']);
  await screenshot(page, 'desktop-success');
  checks.push('member login automatically loads code; explicit approval and S256 redemption complete');

  const legacy = await pairing(['consumer', 'donor']);
  await page.goto(legacy.verificationUriComplete);
  await detailsReady(page);
  await page.locator('#scopes input[value="consumer"]').uncheck();
  await page.locator('#scopes input[value="donor"]').uncheck();
  assert.equal(await page.locator('#approve').isDisabled(), true);
  await page.locator('#scopes input[value="donor"]').check();
  await page.locator('#approve').click();
  await page.locator('#result').waitFor({ state: 'visible' });
  const legacyAuth = await redeem(legacy);
  assert.deepEqual(legacyAuth.device.scopes, ['donor']);
  checks.push('legacy dual-role requests support a selected permission subset and reject an empty selection');

  // Same authenticated browser, fresh code: session restoration and stale-detail invalidation.
  const stale = await pairing(['consumer']);
  await page.goto(stale.verificationUriComplete);
  await detailsReady(page);
  await page.locator('#change-code').click();
  await page.locator('#code').fill('ZZZZ-ZZZZ');
  await cannotApprove(page);
  await page.locator('#lookup').getByRole('button').click();
  await page.locator('#message').filter({ hasText: /.+/ }).waitFor();
  await cannotApprove(page);
  assert.equal(pairingRecord(stale).status, 'pending');
  checks.push('restored session auto-loads; editing or invalidating a code clears stale approval');

  await page.goto(hub.url + '/pair?code=YYYY-YYYY');
  await page.locator('#message').filter({ hasText: /没有找到|不存在|没有这个/ }).waitFor();
  await page.locator('#lookup-panel').waitFor({ state: 'visible' });
  await cannotApprove(page);
  await page.locator('#code').fill(stale.userCode);
  await page.locator('#lookup-submit').click();
  await detailsReady(page);
  assert.equal(pairingRecord(stale).status, 'pending');
  checks.push('invalid prefilled code retains a visible correction path');

  // Advance only this ephemeral database record; do not sleep five minutes or mock the API.
  const expired = await pairing(['consumer']);
  const expiredData = { ...pairingRecord(expired), expiresAt: Date.now() - 1_000 };
  hub.store.db.prepare("UPDATE client_objects SET data=? WHERE kind='pairing' AND id=?").run(JSON.stringify(expiredData), expired.pairingId);
  await page.goto(expired.verificationUriComplete);
  await page.getByText(/已过期|已到期|已经过期|已经到期/).first().waitFor();
  await cannotApprove(page);
  await screenshot(page, 'expired');
  checks.push('server-expired pairing shows a terminal state and cannot be approved');

  const rejected = await pairing(['donor']);
  await page.goto(rejected.verificationUriComplete);
  await detailsReady(page);
  await page.locator('#deny').click();
  await page.getByText(/已拒绝/).first().waitFor();
  await cannotApprove(page);
  assert.equal(pairingRecord(rejected).status, 'denied');
  await redeem(rejected, 403);
  await page.reload();
  await page.getByText(/已拒绝/).first().waitFor();
  await cannotApprove(page);
  checks.push('rejecting a device persists across reload and rejects S256 redemption');

  const invite = await request('/control/invitations', {}, { token: admin, status: 201 });
  secrets.push(invite.token);
  const invited = await pairing(['consumer']);
  const mobile = await pageInNewContext({ width: 390, height: 844 });
  await mobile.goto(invited.verificationUriComplete);
  await mobile.locator('#tab-invite').click();
  await noHorizontalOverflow(mobile);
  await screenshot(mobile, 'mobile-invitation');
  await mobile.locator('#invitation').fill(invite.token);
  await mobile.locator('#name').fill('小夏');
  await mobile.locator('#invite-submit').click();
  await mobile.locator('#save-credential').waitFor({ state: 'visible' });
  await cannotApprove(mobile);
  const personalToken = await mobile.locator('#new-credential').inputValue();
  assert.ok(personalToken.length >= 24, 'Invite redemption must provide the member credential.');
  secrets.push(personalToken);
  await request('/control/session', undefined, { token: personalToken });
  await mobile.locator('#saved-credential').click();
  await detailsReady(mobile);
  assert.equal(pairingRecord(invited).status, 'pending');
  await noHorizontalOverflow(mobile);
  await screenshot(mobile, 'mobile-confirm');
  await mobile.locator('#approve').click();
  await mobile.locator('#result').waitFor({ state: 'visible' });
  const inviteAuth = await redeem(invited);
  assert.equal(inviteAuth.member.name, '小夏');
  assert.deepEqual(inviteAuth.device.scopes, ['consumer']);
  await request('/control/invitations/redeem', { token: invite.token, name: '不可重复兑换' }, { status: 401 });
  await screenshot(mobile, 'mobile-success');
  checks.push('invitation creates member; saving personal credential precedes explicit approval; invite is single-use');

  const returning = await pageInNewContext();
  const returningPair = await pairing(['consumer']);
  await returning.goto(returningPair.verificationUriComplete);
  await login(returning, personalToken);
  await detailsReady(returning);
  assert.equal(pairingRecord(returningPair).status, 'pending');
  checks.push('saved personal credential signs in from a new browser session');
  assert.deepEqual(pageErrors, []);
  assert.deepEqual(cspErrors, []);
  const report = {
    version, time: new Date().toISOString(), passed: true, browserVersion: browser.version(),
    environment: 'ephemeral loopback Hub + real Chromium; synthetic identities; no remote deployment',
    checks, screenshots, pageErrors, cspErrors,
    realSubscriptionLoginTested: false, modelInferenceRequests: 0,
  };
  const json = JSON.stringify(report, null, 2);
  for (const secret of secrets) assert.equal(json.includes(secret), false, 'Evidence must not contain credentials.');
  await writeFile(join(evidence, 'pairing-report.json'), json + '\n');
  console.log(json);
} finally {
  for (const context of contexts) await context.close().catch(() => {});
  await browser?.close();
  await hub.close();
  await rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
