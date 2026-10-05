import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm, mkdir, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { _electron as electron } from 'playwright';
import { verifyPreview } from './macos-preview-sign.mjs';
import { readBuildMetadata } from './build-meta.mjs';
import { desktopBrand, verifyDesktopBrand } from './desktop-brand.mjs';
import { readDesktopHubProfile } from './desktop-profile.mjs';
import { validateHubTrustProfile } from '../dist/packages/hub-client/trust.js';

// Exercise the delivered ZIP, not the staging directory. No real device is
// paired, no subscription is accessed, and only temporary profiles are used.
const exec = promisify(execFile);
const metadata = await readBuildMetadata();
const requireHubProfile = process.argv.includes('--require-hub-profile');
const configuredProfile = await readDesktopHubProfile(validateHubTrustProfile, { args: process.argv.slice(2), env: process.env });
const { version } = metadata;
const releasePath = resolve(metadata.report);
const release = JSON.parse(await readFile(releasePath, 'utf8'));
const archive = resolve(release.archive);
assert.equal(release.version, version);
assert.equal(release.archive, metadata.archive);
assert.equal(createHash('sha256').update(await readFile(archive)).digest('hex'), release.sha256);
const dir = await mkdtemp(join(tmpdir(), 'share-token-release-smoke-'));
const appPath = join(dir, desktopBrand.bundleName);
const resourcePath = join(appPath, 'Contents/Resources/app');
let app;
async function stopApp() {
  if (!app) return;
  await app.evaluate(({ dialog }) => { dialog.showMessageBox = async () => ({ response: 1, checkboxChecked: false }); });
  const closed = app.waitForEvent('close', { timeout: 15000 });
  await app.evaluate(({ app }) => app.quit());
  await closed;
  app = null;
}
try {
  await exec('/usr/bin/ditto', ['-x', '-k', archive, dir]);
  const branding = await verifyDesktopBrand(appPath);
  const manifest = JSON.parse(await readFile(join(resourcePath, 'runtime/manifest.json'), 'utf8'));
  assert.doesNotMatch(await readFile(join(resourcePath, 'dist/apps/desktop/main/index.js'), 'utf8'), /safeStorage\s*[.(]/);
  const signatures = await verifyPreview(appPath, manifest.sha256);
  // Deployment profiles are optional. Validate the public profile shipped in
  // this exact ZIP rather than assuming the developer's own Hub address.
  const { readHubTrustFile, hubTrustDisplay } = await import(pathToFileURL(join(resourcePath, 'dist/apps/desktop/main/hub-trust.js')).href);
  const bundledConnectionPath = join(resourcePath, 'dist/apps/desktop/default.connection.json');
  let expectedPublicConnection = null;
  try {
    const connection = await readHubTrustFile(bundledConnectionPath);
    const raw = JSON.parse(await readFile(bundledConnectionPath, 'utf8'));
    assert.ok(Object.keys(raw).every(key => ['version', 'hubUrl', 'certificatePem', 'label'].includes(key)), 'A bundled connection must contain only public connection fields.');
    expectedPublicConnection = hubTrustDisplay(connection);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  assert.ok(!requireHubProfile || expectedPublicConnection, 'A friend distribution must include a validated public connection profile.');
  if (configuredProfile) assert.deepEqual(expectedPublicConnection, hubTrustDisplay(configuredProfile), 'The final ZIP must contain the intended Hub connection profile.');
  // Actual JS execution, native addon loading and PTY helper execution must
  // still work after signing, including the Node runtime's JIT capabilities.
  const nativeScript = `
    const assert = require('node:assert/strict');
    const pty = require('node-pty');
    let sum = 0;
    function hot(i) { return i & 255; }
    for (let i = 0; i < 1000000; i++) sum += hot(i);
    assert.equal(sum, 127493856);
    const terminal = pty.spawn('/bin/sh', ['-c', 'printf SHARE_TOKEN_PTY_OK'], { name: 'xterm', cols: 80, rows: 24, cwd: process.cwd(), env: process.env });
    let output = '';
    const timeout = setTimeout(() => { terminal.kill(); process.exit(2); }, 10000);
    terminal.onData(data => { output += data; });
    terminal.onExit(({ exitCode }) => { clearTimeout(timeout); assert.equal(exitCode, 0); assert.match(output, /SHARE_TOKEN_PTY_OK/); console.log('node-jit-and-native-pty-ok'); });
  `;
  const native = await exec(join(resourcePath, 'runtime/node'), ['-e', nativeScript], { cwd: resourcePath, timeout: 20000 });
  assert.match(native.stdout, /node-jit-and-native-pty-ok/);
  const profile = join(dir, 'profile');
  app = await electron.launch({ executablePath: join(appPath, 'Contents/MacOS', desktopBrand.executableName), args: ['--user-data-dir=' + profile], timeout: 30000 });
  const window = await app.firstWindow();
  const pageErrors = [];
  window.on('pageerror', error => pageErrors.push(error.message));
  const identity = await app.evaluate(({ app }) => ({ name: app.getName(), version: app.getVersion(), packaged: app.isPackaged, profile: app.getPath('userData') }));
  assert.equal(identity.name, desktopBrand.name);
  assert.equal(identity.version, version);
  assert.equal(identity.packaged, true);
  assert.equal(await realpath(identity.profile), await realpath(profile));
  await window.getByRole('button', { name: '使用共享', exact: true }).waitFor();
  await window.getByRole('button', { name: '提供共享', exact: true }).waitFor();
  await window.getByText(desktopBrand.name, { exact: true }).waitFor();
  await window.waitForFunction(() => {
    const image = document.querySelector('.brand-symbol');
    return image instanceof HTMLImageElement && image.complete && image.naturalWidth > 0;
  });
  const brandImage = window.locator('.brand-symbol');
  assert.equal(await brandImage.evaluate(image => image instanceof HTMLImageElement && image.complete && image.naturalWidth > 0), true);
  const welcomeScreenshot = resolve(`artifacts/desktop-evidence/release-${version}-welcome.png`);
  await mkdir(resolve('artifacts/desktop-evidence'), { recursive: true });
  await window.screenshot({ path: welcomeScreenshot });
  await window.getByRole('button', { name: '使用共享', exact: true }).click();
  await window.getByLabel('配对码', { exact: true }).waitFor();
  const state = await window.evaluate(() => window.shareToken.state());
  assert.equal(state.credentialStorage, 'local-encrypted');
  assert.equal(state.version, version);
  assert.equal(state.connected, false);
  assert.deepEqual(state.hubTrust, expectedPublicConnection);
  const visibleOnboardingInputs = await window.locator('input:visible').count();
  assert.equal(visibleOnboardingInputs, 1, 'Advanced connection fields must stay collapsed initially.');
  const pairingInput = window.getByLabel('配对码', { exact: true });
  if (expectedPublicConnection) {
    await window.waitForFunction(() => !document.querySelector('#shared-space-code')?.disabled);
    assert.equal(await pairingInput.isEnabled(), true);
  } else {
    await window.getByText('请在“更多连接方式”中导入朋友提供的连接文件，再加入空间。', { exact: true }).waitFor();
    assert.equal(await pairingInput.isEnabled(), true);
    await window.getByText('更多连接方式', { exact: true }).click();
    const importConnection = window.getByRole('button', { name: '导入内网连接文件', exact: true });
    await importConnection.waitFor();
    assert.equal(await importConnection.isEnabled(), true);
    assert.equal(await window.getByLabel('Hub 地址', { exact: true }).inputValue(), '');
    assert.equal(await window.getByRole('button', { name: '加入朋友空间', exact: true }).isDisabled(), true);
  }
  await pairingInput.fill('1234 5678');
  assert.equal(await pairingInput.inputValue(), '1234 5678');
  assert.equal(await window.getByRole('button', { name: '加入朋友空间', exact: true }).isEnabled(), expectedPublicConnection !== null);
  await pairingInput.fill('');
  const screenshot = resolve(`artifacts/desktop-evidence/release-${version}-extracted.png`);
  await mkdir(resolve('artifacts/desktop-evidence'), { recursive: true });
  await window.screenshot({ path: screenshot });
  assert.deepEqual(pageErrors, []);
  await stopApp();

  let gatekeeper;
  try {
    const result = await exec('/usr/sbin/spctl', ['--assess', '--type', 'execute', '--verbose=2', appPath]);
    gatekeeper = { accepted: true, details: (result.stdout + result.stderr).trim() };
  } catch (error) {
    assert.equal(error.code, 3, 'An assessment rejection is expected for ad-hoc; other tool failures are not.');
    gatekeeper = { accepted: false, exitCode: error.code, details: (error.stdout + error.stderr).replaceAll(appPath, desktopBrand.bundleName).trim() };
  }
  // Regression: changing a sealed JS resource must invalidate the app signature.
  const main = join(resourcePath, 'dist/apps/desktop/main/index.js');
  await writeFile(main, (await readFile(main, 'utf8')) + '\n// signing-regression-probe\n');
  await assert.rejects(exec('/usr/bin/codesign', ['--verify', '--deep', '--strict', appPath]), /resource|modified|invalid|sealed/i);
  const report = { verifiedAt: new Date().toISOString(), version, archiveSha256: release.sha256, signatures, branding, welcomeScreenshot,
    nativeNodeJitAndPty: true, extractedElectronLaunch: true, isolatedProfile: true, noKeychainCredentialAccess: true,
    bundledPublicConnection: expectedPublicConnection !== null,
    onePairingInput: expectedPublicConnection !== null && visibleOnboardingInputs === 1,
    connectionSetupRequired: expectedPublicConnection === null, tamperedResourceRejected: true,
    gatekeeper, notarized: false, friendMacVerified: false, screenshot, pageErrors,
    modelInferenceRequests: 0 };
  await writeFile(resolve(`artifacts/desktop-evidence/release-${version}-verification.json`), JSON.stringify(report, null, 2) + '\n');
  await writeFile(releasePath, JSON.stringify({ ...release, runtimeVerification: report }, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  console.error(error);
  throw error;
} finally {
  if (app) await stopApp().catch(async () => { await app.evaluate(({ app }) => app.exit(1)).catch(() => {}); });
  await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
