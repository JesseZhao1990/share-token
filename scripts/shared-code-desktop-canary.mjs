import assert from 'node:assert/strict';
import { randomBytes, randomInt } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { _electron as electron } from 'playwright';
import { createHub } from '../dist/apps/hub/index.js';
import { createLocalSecretCipher } from '../dist/packages/platform/local-secret.js';

// Actual Electron + temporary local Hub. No existing account, real shared code,
// bundled Hub service, subscription login or model inference is accessed.
const root = process.cwd();
const packaged = process.argv[2] ? resolve(process.argv[2]) : null;
const expectedVersion = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).version;
const dir = await mkdtemp(join(tmpdir(), 'share-code-desktop-'));
const evidence = join(root, 'artifacts/desktop-evidence');
const suffix = packaged ? '-packaged' : '';
const code = String(randomInt(10_000_000, 100_000_000));
const adminToken = 'test_' + randomBytes(32).toString('hex');
const hub = await createHub({ dbPath: join(dir, 'hub.sqlite'), adminToken, port: 0 });
const instances = [], checks = [], screenshots = [], pageErrors = [];
const legacyBytes = Buffer.from('opaque-legacy-keychain-credential-fixture');
assert.doesNotMatch(await readFile(join(root, 'dist/apps/desktop/main/index.js'), 'utf8'), /safeStorage\s*[.(]/, 'App must never call the OS Keychain for local credentials.');

async function screenshot(instance, name) {
  const path = join(evidence, `shared-code-${name}${suffix}.png`);
  const field = instance.window.locator('#shared-space-code');
  const mask = await field.count() && await field.inputValue() ? [field] : [];
  await instance.window.screenshot({ path, mask, maskColor: '#dbe5d7' });
  screenshots.push(path);
}

async function launch(profileName) {
  const profile = join(dir, profileName), codexHome = join(dir, profileName + '-codex');
  await mkdir(profile, { recursive: true });
  await mkdir(codexHome, { recursive: true });
  if (profileName === 'consumer-profile') await writeFile(join(profile, 'device.encrypted'), legacyBytes, { mode: 0o600 });
  const app = await electron.launch({
    ...(packaged ? { executablePath: packaged } : {}),
    args: [...(packaged ? [] : ['.']), '--user-data-dir=' + profile],
    env: { ...process.env, SHARE_TOKEN_TEST_DATA_DIR: profile, CODEX_HOME: codexHome }, timeout: 30_000,
  });
  const instance = { app, profile, window: null, additionalWindows: 0, closed: false };
  instances.push(instance);
  await app.evaluate(({ shell }) => {
    globalThis.__sharedCodeExternalUrls = [];
    shell.openExternal = async url => { globalThis.__sharedCodeExternalUrls.push(url); };
  });
  instance.window = await app.firstWindow();
  app.on('window', window => { if (window !== instance.window) instance.additionalWindows++; });
  instance.window.on('pageerror', error => pageErrors.push(error.message));
  instance.window.setDefaultTimeout(15_000);
  const identity = await app.evaluate(({ app }) => ({ version: app.getVersion(), packaged: app.isPackaged, userData: app.getPath('userData') }));
  assert.equal(identity.version, expectedVersion);
  assert.equal(identity.packaged, !!packaged);
  assert.equal(await realpath(identity.userData), await realpath(profile), 'Canary must use only its own temporary userData.');
  await instance.window.getByRole('button', { name: '使用共享', exact: true }).waitFor();
  assert.equal(await instance.window.locator('aside').count(), 0, 'Purpose selection must precede all operational navigation.');
  assert.equal(await instance.window.getByLabel('配对码', { exact: true }).count(), 0, 'No code form before choosing a purpose.');
  return instance;
}

async function configureLocalHub(instance, purpose) {
  const window = instance.window;
  await window.getByRole('button', { name: purpose === 'donor' ? '提供共享' : '使用共享', exact: true }).click();
  await window.getByRole('heading', { name: '输入和朋友约定的配对码', exact: true }).waitFor();
  const before = await window.evaluate(() => window.shareToken.state());
  if (!before.hubTrust) {
    const input = window.getByLabel('配对码', { exact: true });
    assert.equal(await input.isEnabled(), true);
    await input.fill('1234 5678');
    assert.equal(await window.getByRole('button', { name: '加入朋友空间', exact: true }).isDisabled(), true);
  }
  // Source builds intentionally have no bundled connection profile. Set the test
  // loopback address in the existing optional manual path, then return to normal UI.
  await window.getByText('更多连接方式', { exact: true }).click();
  await window.getByLabel('Hub 地址', { exact: true }).fill(hub.url);
  await window.getByText('更多连接方式', { exact: true }).click();
  assert.equal(await window.getByLabel('Hub 地址', { exact: true }).isVisible(), false);
  assert.equal(await window.getByLabel('设备名称', { exact: true }).isVisible(), false);
  assert.equal(await window.locator('input:visible').count(), 1, 'Normal onboarding must expose only one input.');
  assert.equal(await window.getByLabel('配对码', { exact: true }).isEnabled(), true);
  if (!before.hubTrust) assert.equal(await window.getByLabel('配对码', { exact: true }).inputValue(), '1234 5678');
  await window.getByLabel('配对码', { exact: true }).fill('');
  assert.equal(await window.getByRole('button', { name: '加入朋友空间', exact: true }).isDisabled(), true);
  await screenshot(instance, purpose + '-empty');
}

async function noBrowserOpened(instance) {
  assert.equal(instance.additionalWindows, 0, 'Shared-code join must not open a Hub approval window.');
  assert.equal(instance.app.windows().length, 1);
  assert.deepEqual(await instance.app.evaluate(() => globalThis.__sharedCodeExternalUrls), [], 'Shared-code join must not open an external browser.');
}

async function verifyCredentials(instance, state) {
  assert.equal(state.connected, true);
  assert.equal(state.member.role, 'member', 'Code holders must not become administrators.');
  assert.equal(state.pairing, null, 'Shared-code onboarding must not leave browser pairing intent.');
  assert.equal(JSON.stringify(state).includes(code), false, 'State must not reveal the shared code.');
  assert.equal(JSON.stringify(state).includes('refreshToken'), false, 'Renderer state must not expose credentials.');
  const path = join(instance.profile, 'local-secrets/device.encrypted');
  const bytes = await readFile(path);
  assert.equal(bytes.includes(Buffer.from(code)), false);
  assert.equal(bytes.includes(Buffer.from('refreshToken')), false);
  if (process.platform !== 'win32') assert.equal((await stat(path)).mode & 0o077, 0);
  // Only inspect this canary's own temporary credentials. The application no
  // longer reads any OS Keychain item, even when an older credential file exists.
  const cipher = await createLocalSecretCipher(join(await realpath(instance.profile), 'local-secrets'));
  const plain = cipher.decrypt(bytes), saved = JSON.parse(plain);
  const safe = { codeAbsent: !plain.includes(code), sharedCodeFieldAbsent: !plain.includes('sharedCode'),
    hasDeviceCredentials: typeof saved.credentials?.refreshToken === 'string', correctDevice: saved.credentials?.deviceId === state.device.id };
  assert.deepEqual(safe, { codeAbsent: true, sharedCodeFieldAbsent: true, hasDeviceCredentials: true, correctDevice: true });
  assert.equal(state.credentialStorage, 'local-encrypted');
  const storageClean = await instance.window.evaluate(sharedCode => !JSON.stringify({ ...localStorage }).includes(sharedCode) && !JSON.stringify({ ...sessionStorage }).includes(sharedCode), code);
  assert.equal(storageClean, true, 'Pairing code must not be persisted by the renderer.');
  await noBrowserOpened(instance);
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
  const first = await launch('consumer-profile');
  assert.match((await first.window.evaluate(() => window.shareToken.state())).lastError, /重新输入一次配对码/);
  assert.deepEqual(await readFile(join(first.profile, 'device.encrypted')), legacyBytes);
  await screenshot(first, 'purpose-choice');
  await configureLocalHub(first, 'consumer');
  checks.push('startup requires purpose choice; normal connection exposes only one pairing-code input');
  await first.window.getByLabel('配对码', { exact: true }).fill('123');
  assert.equal(await first.window.getByRole('button', { name: '加入朋友空间', exact: true }).isDisabled(), true);
  checks.push('short code cannot submit; the Hub requires no preset code');

  await first.window.getByLabel('配对码', { exact: true }).fill(code.slice(0, 4) + ' - ' + code.slice(4));
  await screenshot(first, 'consumer-entered-masked');
  await first.window.getByRole('button', { name: '加入朋友空间', exact: true }).click();
  await first.window.getByRole('navigation', { name: '使用共享导航', exact: true }).waitFor();
  const firstState = await first.window.evaluate(() => window.shareToken.state());
  await verifyCredentials(first, firstState);
  assert.equal(hub.store.listMembers().length, 2);
  await screenshot(first, 'consumer-connected');
  checks.push('consumer joins with spaces and hyphen normalized; native encrypted credentials omit the shared code');

  const second = await launch('donor-profile');
  await configureLocalHub(second, 'donor');
  await second.window.getByLabel('配对码', { exact: true }).fill(code);
  await second.window.getByRole('button', { name: '加入朋友空间', exact: true }).click();
  await second.window.getByRole('navigation', { name: '提供共享导航', exact: true }).waitFor();
  const secondState = await second.window.evaluate(() => window.shareToken.state());
  await verifyCredentials(second, secondState);
  assert.notEqual(secondState.member.id, firstState.member.id, 'Independent devices must receive distinct member identities.');
  assert.notEqual(secondState.device.id, firstState.device.id);
  assert.equal(hub.store.listMembers().length, 3);
  await screenshot(second, 'donor-connected');
  checks.push('two independent app profiles use the same code and receive distinct non-admin identities without browser windows');

  await quit(first);
  const restored = await launch('consumer-profile');
  const restoredState = await restored.window.evaluate(() => window.shareToken.state());
  await verifyCredentials(restored, restoredState);
  assert.equal(restoredState.member.id, firstState.member.id);
  assert.equal(restoredState.device.id, firstState.device.id);
  assert.equal(hub.store.listMembers().length, 3, 'Restart must restore identity without creating another member.');
  await screenshot(restored, 'restored-purpose-choice');
  await restored.window.getByRole('button', { name: '使用共享', exact: true }).click();
  await restored.window.getByRole('navigation', { name: '使用共享导航', exact: true }).waitFor();
  assert.equal(await restored.window.getByLabel('配对码', { exact: true }).count(), 0, 'Restored device must not ask for the code again.');
  await screenshot(restored, 'restored-connected');
  assert.deepEqual(await readFile(join(restored.profile, 'device.encrypted')), legacyBytes);
  checks.push('no Keychain access; legacy credential file preserved and fresh join restores on restart using local encryption');
  checks.push('native restart preserves purpose-first entry and reconnects the same identity without code entry');

  await quit(restored);
  await quit(second);
  assert.deepEqual(pageErrors, []);
  const report = { appVersion: expectedVersion, time: new Date().toISOString(), packaged: !!packaged,
    environment: 'real Electron desktop + ephemeral loopback Hub; synthetic shared code; no remote deployment',
    passed: true, independentProfiles: 2, membersCreated: 2, administratorMembersCreated: 0, nativeRestarts: 1,
    externalBrowserWindowsOpened: 0, hubApprovalWindowsOpened: 0, realSubscriptionLoginTested: false, modelInferenceRequests: 0,
    checks, pageErrors, screenshots };
  const json = JSON.stringify(report, null, 2);
  assert.equal(json.includes(code), false, 'Evidence must not include the code.');
  assert.equal(json.includes(adminToken), false);
  await writeFile(join(evidence, `shared-code-report${suffix}.json`), json + '\n');
  console.log(json);
} finally {
  for (const instance of instances) {
    if (instance.closed) continue;
    await quit(instance).catch(async () => {
      const child = instance.app.process();
      await instance.app.evaluate(({ app }) => app.exit(0)).catch(() => {});
      await new Promise(resolve => { if (child.exitCode !== null) resolve(); else { child.once('exit', resolve); setTimeout(resolve, 3000).unref(); } });
    });
  }
  await hub.close();
  await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
