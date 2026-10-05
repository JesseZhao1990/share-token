import assert from 'node:assert/strict';
import { randomBytes, randomInt } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { _electron as electron } from 'playwright';
import { createHub } from '../dist/apps/hub/index.js';

// Run after building: node scripts/onboarding-canary.mjs [packaged executable].
// Uses a real Electron renderer and temporary app/Codex profiles. Unconfigured
// builds use a loopback Hub; bundles with a connection profile get UI-only checks.
// Never logs in to a subscription, accesses existing credentials or runs inference.
const root = process.cwd();
const packaged = process.argv[2] ? resolve(process.argv[2]) : null;
const expectedVersion = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).version;
const temporary = await mkdtemp(join(tmpdir(), 'share-token-onboarding-'));
const evidence = join(root, 'artifacts/desktop-evidence');
const suffix = packaged ? '-packaged' : '';
const code = String(randomInt(10_000_000, 100_000_000));
const adminToken = 'test_' + randomBytes(32).toString('hex');
const checks = [], screenshots = [], layouts = [], pageErrors = [];
let hub, app, window, minimumSize, failure;
let bundledPublicConnection = false, actualSharedCodeJoinTested = false, legacyDevicePairingTested = false;

async function settleLayout() {
  await window.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function top() {
  await window.evaluate(() => {
    window.scrollTo(0, 0);
    for (const element of document.querySelectorAll('.onboarding, .onboarding-main')) element.scrollTop = 0;
  });
  await settleLayout();
}

async function screenshot(name) {
  const path = join(evidence, `onboarding-${name}${suffix}.png`);
  await window.screenshot({ path, mask: [window.locator('#shared-space-code')], maskColor: '#dbe5d7' });
  screenshots.push(path);
}

async function layout(label) {
  await top();
  const measurements = await window.evaluate(() => {
    const bounds = selector => {
      const element = document.querySelector(selector);
      if (!element) throw new Error(`Missing layout element: ${selector}`);
      const { x, y, width, height, right, bottom } = element.getBoundingClientRect();
      return { x, y, width, height, right, bottom };
    };
    const header = document.querySelector('.onboarding > .welcome-bar');
    const brand = document.querySelector('.onboarding .brand');
    const brandBounds = brand.getBoundingClientRect();
    const hit = document.elementFromPoint(brandBounds.x + brandBounds.width / 2, brandBounds.y + brandBounds.height / 2);
    return {
      viewport: { width: innerWidth, height: innerHeight },
      documentWidth: document.documentElement.scrollWidth,
      bodyWidth: document.body.scrollWidth,
      header: bounds('.onboarding > .welcome-bar'),
      main: bounds('.onboarding-main'),
      story: bounds('.onboarding-story'),
      panel: bounds('.shared-code-panel'),
      input: bounds('#shared-space-code'),
      brandUncovered: !!hit && header.contains(hit),
      advancedOpen: document.querySelector('.more-connections').open,
    };
  });
  assert.ok(measurements.documentWidth <= measurements.viewport.width + 1, `${label}: document must not overflow horizontally.`);
  assert.ok(measurements.bodyWidth <= measurements.viewport.width + 1, `${label}: body must not overflow horizontally.`);
  assert.ok(measurements.header.height >= 86 && measurements.header.height <= 88, `${label}: expanding content must preserve the 87px brand bar.`);
  assert.ok(measurements.header.y >= -1 && measurements.header.y <= 1, `${label}: brand bar must start at the viewport top.`);
  assert.equal(measurements.brandUncovered, true, `${label}: content must not cover the brand bar.`);
  assert.ok(measurements.main.y >= measurements.header.bottom - 1, `${label}: content must begin below the brand bar.`);
  for (const key of ['story', 'panel', 'input']) {
    assert.ok(measurements[key].x >= 0 && measurements[key].right <= measurements.viewport.width + 1, `${label}: ${key} must fit the viewport width.`);
    assert.ok(measurements[key].y >= measurements.header.bottom - 1, `${label}: ${key} must not overlap the brand bar.`);
  }
  layouts.push({ label, ...measurements });
  return measurements;
}

async function reachable(locator) {
  await locator.scrollIntoViewIfNeeded();
  await locator.click({ trial: true });
  const visibleHitTarget = await locator.evaluate(element => {
    const rect = element.getBoundingClientRect();
    const x = rect.x + rect.width / 2, y = rect.y + rect.height / 2;
    const hit = document.elementFromPoint(x, y);
    return x >= 0 && x < innerWidth && y >= 0 && y < innerHeight && !!hit && (element === hit || element.contains(hit));
  });
  assert.equal(visibleHitTarget, true, 'Scrolled control must be visible and receive pointer input.');
  const header = await window.locator('.onboarding > .welcome-bar').boundingBox();
  assert.ok(header && Math.abs(header.y) <= 1 && Math.abs(header.height - 87) <= 1, 'Scrolling advanced controls must keep the brand bar fixed and full height.');
}

async function resize(width, height) {
  const actual = await app.evaluate(({ BrowserWindow }, size) => {
    const main = BrowserWindow.getAllWindows().find(window => window.webContents.getURL().startsWith('share://app/'));
    main.setSize(size.width, size.height);
    return main.getSize();
  }, { width, height });
  assert.deepEqual(actual, [width, height]);
  await settleLayout();
}

async function closeApp() {
  if (!app) return;
  await app.evaluate(({ dialog }) => { dialog.showMessageBox = async () => ({ response: 1, checkboxChecked: false }); });
  const closed = app.waitForEvent('close', { timeout: 15_000 });
  await window.evaluate(() => window.shareToken.quit()).catch(error => {
    if (!/closed|destroyed|Target/i.test(error.message)) throw error;
  });
  await closed;
}

try {
  await mkdir(evidence, { recursive: true });
  const profile = join(temporary, 'profile'), codexHome = join(temporary, 'codex');
  await mkdir(profile, { recursive: true });
  await mkdir(codexHome, { recursive: true });
  app = await electron.launch({
    ...(packaged ? { executablePath: packaged } : {}),
    args: [...(packaged ? [] : ['.']), '--user-data-dir=' + profile],
    env: { ...process.env, SHARE_TOKEN_TEST_DATA_DIR: profile, CODEX_HOME: codexHome },
    timeout: 30_000,
  });
  await app.evaluate(({ shell }) => {
    globalThis.__onboardingExternalUrls = [];
    shell.openExternal = async url => { globalThis.__onboardingExternalUrls.push(url); };
  });
  window = await app.firstWindow();
  window.setDefaultTimeout(15_000);
  window.on('pageerror', error => pageErrors.push(error.message));
  const identity = await app.evaluate(({ app, BrowserWindow }) => ({
    version: app.getVersion(), packaged: app.isPackaged, userData: app.getPath('userData'),
    size: BrowserWindow.getAllWindows()[0].getSize(), minimumSize: BrowserWindow.getAllWindows()[0].getMinimumSize(),
  }));
  assert.equal(identity.version, expectedVersion);
  assert.equal(identity.packaged, !!packaged);
  assert.equal(await realpath(identity.userData), await realpath(profile));
  assert.deepEqual(identity.size, [1180, 800]);
  minimumSize = identity.minimumSize;
  await window.getByRole('button', { name: '使用共享', exact: true }).click();
  await window.getByRole('heading', { name: '输入和朋友约定的配对码', exact: true }).waitFor();
  const initialState = await window.evaluate(() => window.shareToken.state());
  assert.equal(initialState.connected, false);
  assert.equal(initialState.pairing, null, 'Fresh temporary profile must not contain an existing pairing request.');
  bundledPublicConnection = !!initialState.hubTrust;
  let configuredHubUrl;
  if (bundledPublicConnection) {
    // Preserve the packaged profile. Use only a synthetic code to exercise input;
    // never click either network-capable submit button against the bundled Hub.
    configuredHubUrl = initialState.hubTrust.hubUrl;
    assert.ok(configuredHubUrl);
  } else {
    assert.ok(!initialState.hubUrl, 'Fresh unconfigured profile must not have a Hub address.');
    hub = await createHub({ dbPath: join(temporary, 'hub.sqlite'), adminToken, host: '127.0.0.1', port: 0 });
    assert.equal(new URL(hub.url).hostname, '127.0.0.1');
    configuredHubUrl = hub.url;
  }
  const codeInput = window.getByLabel('配对码', { exact: true });
  const joinButton = window.getByRole('button', { name: '加入朋友空间', exact: true });
  const more = window.getByText('更多连接方式', { exact: true });
  const hubInput = window.getByLabel('Hub 地址', { exact: true });
  const nameInput = window.getByLabel('设备名称', { exact: true });
  const connectButton = window.getByRole('button', { name: '连接并配对', exact: true });
  assert.equal(await codeInput.isEnabled(), true, 'Pairing-code input must work with or without bundled Hub configuration.');
  assert.equal(await joinButton.isDisabled(), true, 'Empty code must keep joining disabled even with a bundled Hub profile.');
  await codeInput.click();
  await codeInput.pressSequentially(code);
  assert.equal(await codeInput.inputValue(), code);
  assert.equal(await joinButton.isEnabled(), bundledPublicConnection, 'A complete code enables joining only when a Hub address is configured.');
  const collapsedLayout = await layout('default-collapsed');
  await screenshot('default-collapsed');
  checks.push(bundledPublicConnection
    ? 'bundled connection profile accepts synthetic keyboard input and enables join only after a complete code; no submission performed'
    : 'fresh unconfigured app accepts actual pairing-code keyboard input while join remains disabled');

  await more.click();
  assert.equal(await window.locator('.more-connections').evaluate(element => element.open), true);
  const expandedLayout = await layout('default-expanded');
  assert.ok(Math.abs(expandedLayout.story.y - collapsedLayout.story.y) <= 1, 'Expanding more connection methods must not shift the story vertically.');
  assert.ok(Math.abs(expandedLayout.panel.y - collapsedLayout.panel.y) <= 1, 'Expanding more connection methods must preserve the panel top.');
  await screenshot('default-expanded');
  await reachable(hubInput);
  if (bundledPublicConnection) assert.equal(await hubInput.inputValue(), configuredHubUrl, 'Bundled connection address must be shown unchanged.');
  await hubInput.fill(configuredHubUrl);
  await reachable(nameInput);
  await nameInput.fill('Onboarding canary');
  await reachable(connectButton);
  await screenshot('default-advanced-controls');
  await more.click();
  assert.equal(await hubInput.isVisible(), false);
  assert.equal(await nameInput.isVisible(), false);
  assert.equal(await hubInput.inputValue(), configuredHubUrl, 'Collapsing must preserve the configured Hub address.');
  assert.equal(await nameInput.inputValue(), 'Onboarding canary', 'Collapsing must preserve the edited device name.');
  assert.equal(await codeInput.inputValue(), code, 'Expanding, editing and collapsing must retain the previously typed code.');
  assert.equal(await joinButton.isEnabled(), true);
  checks.push('default-size advanced controls are reachable; editing Hub and device name preserves the code through collapse');

  const sizes = [[980, 680], minimumSize].filter(([width, height], index, all) => all.findIndex(size => size[0] === width && size[1] === height) === index);
  for (const [width, height] of sizes) {
    await resize(width, height);
    if (!await window.locator('.more-connections').evaluate(element => element.open)) await more.click();
    await layout(`${width}x${height}-expanded`);
    await screenshot(`${width}x${height}-expanded`);
    await reachable(hubInput);
    await hubInput.fill(configuredHubUrl);
    await reachable(nameInput);
    await nameInput.fill(`Onboarding ${width}x${height}`);
    await reachable(connectButton);
    await screenshot(`${width}x${height}-advanced-controls`);
    assert.equal(await codeInput.inputValue(), code);
    checks.push(`${width}x${height} expanded view has no horizontal overflow, intact brand bar and reachable editable advanced controls`);
  }

  if (bundledPublicConnection) {
    await reachable(joinButton);
    const unchanged = await window.evaluate(() => window.shareToken.state());
    assert.equal(unchanged.connected, false);
    assert.equal(unchanged.pairing, null);
    assert.equal(unchanged.hubTrust.hubUrl, configuredHubUrl);
    assert.equal(await hubInput.inputValue(), configuredHubUrl);
    assert.deepEqual(await app.evaluate(() => globalThis.__onboardingExternalUrls), []);
    assert.equal(app.windows().length, 1);
    checks.push('packaged layout verification only: bundled address preserved; device pairing and shared-code join were not submitted');
  } else {
    // Actually activate the bottom connection button, then return to code entry.
    // The loopback approval URL is intercepted instead of launching a browser.
    await connectButton.click();
    await window.getByLabel('设备配对码', { exact: true }).waitFor();
    const pairingState = await window.evaluate(() => window.shareToken.state());
    assert.equal(pairingState.connected, false);
    assert.ok(pairingState.pairing);
    const externalUrls = await app.evaluate(() => globalThis.__onboardingExternalUrls);
    assert.equal(externalUrls.length, 1);
    assert.equal(new URL(externalUrls[0]).origin, hub.url);
    await window.getByRole('button', { name: '取消配对，返回上一步', exact: true }).click();
    await codeInput.waitFor();
    assert.equal(await codeInput.inputValue(), code);
    assert.equal((await window.evaluate(() => window.shareToken.state())).pairing, null);
    legacyDevicePairingTested = true;
    checks.push('bottom connection button starts loopback device pairing; cancellation restores the typed code');

    await joinButton.click();
    await window.getByRole('navigation', { name: '使用共享导航', exact: true }).waitFor();
    const joined = await window.evaluate(() => window.shareToken.state());
    assert.equal(joined.connected, true);
    assert.equal(joined.member.role, 'member');
    assert.equal(joined.pairing, null);
    assert.equal(hub.store.listMembers().length, 2);
    assert.equal(app.windows().length, 1);
    assert.equal((await app.evaluate(() => globalThis.__onboardingExternalUrls)).length, 1, 'Shared-code join must not open another browser.');
    actualSharedCodeJoinTested = true;
    checks.push('previously typed code completes a real loopback join with one non-admin member and no new browser window');
  }
  assert.deepEqual(pageErrors, []);
} catch (error) {
  failure = error;
} finally {
  if (app) await closeApp().catch(async error => {
    failure ??= error;
    await app.evaluate(({ app }) => app.exit(0)).catch(() => {});
  });
  if (hub) await hub.close();
  await rm(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  const report = {
    appVersion: expectedVersion, time: new Date().toISOString(), packaged: !!packaged,
    environment: bundledPublicConnection
      ? 'real Electron + temporary userData/CODEX_HOME + bundled profile; no remote pairing/join submission'
      : 'real Electron + temporary userData/CODEX_HOME + loopback Hub',
    verificationMode: bundledPublicConnection ? 'packaged layout verification only' : 'layout and loopback pairing/join verification',
    passed: !failure, nativeMinimumSize: minimumSize,
    bundledPublicConnection, actualSharedCodeJoinTested, legacyDevicePairingTested, syntheticCodeUsed: true,
    realSubscriptionLoginTested: false, modelInferenceRequests: 0,
    checks, layouts, screenshots, pageErrors,
    ...(failure ? { error: failure.stack ?? String(failure) } : {}),
  };
  const json = JSON.stringify(report, null, 2).replaceAll(code, '[redacted-code]').replaceAll(adminToken, '[redacted-token]');
  await mkdir(evidence, { recursive: true });
  await writeFile(join(evidence, `onboarding-report${suffix}.json`), json + '\n');
  console.log(json);
}
if (failure) process.exitCode = 1;
