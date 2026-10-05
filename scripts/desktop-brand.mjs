import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { basename, join } from 'node:path';

export const desktopBrand = Object.freeze({
  name: '共享token',
  bundleName: '共享token.app',
  // Keep the executable and application identity stable across this visual update.
  executableName: 'Share Token',
  bundleId: 'io.github.jessezhao1990.sharetoken',
  icon: 'apps/desktop/packaging/app-icon.icns',
});

const exec = promisify(execFile);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

export async function verifyDesktopBrand(appPath) {
  const { stdout } = await exec('/usr/bin/plutil', ['-convert', 'json', '-o', '-', join(appPath, 'Contents/Info.plist')]);
  const info = JSON.parse(stdout);
  assert.equal(basename(appPath), desktopBrand.bundleName);
  assert.equal(info.CFBundleName, desktopBrand.name);
  assert.equal(info.CFBundleDisplayName, desktopBrand.name);
  assert.equal(info.CFBundleIdentifier, desktopBrand.bundleId);
  assert.equal(info.CFBundleExecutable, desktopBrand.executableName);
  assert.equal(typeof info.CFBundleIconFile, 'string');
  const iconName = info.CFBundleIconFile.endsWith('.icns') ? info.CFBundleIconFile : `${info.CFBundleIconFile}.icns`;
  assert.equal(basename(iconName), iconName);
  const bytes = await readFile(join(appPath, 'Contents/Resources', iconName));
  assert.equal(bytes.subarray(0, 4).toString(), 'icns');
  assert.equal(hash(bytes), hash(await readFile(desktopBrand.icon)), 'The bundle must contain the custom app icon.');
  const resources = join(appPath, 'Contents/Resources/app');
  const metadata = JSON.parse(await readFile(join(resources, 'package.json'), 'utf8'));
  assert.equal(metadata.productName, desktopBrand.name);
  const png = await readFile(join(resources, 'dist/apps/desktop/brand/app-icon.png'));
  assert.equal(hash(png), hash(await readFile('apps/desktop/packaging/app-icon.png')));
  return { displayName: info.CFBundleDisplayName, bundleName: basename(appPath), bundleId: info.CFBundleIdentifier, customIconSha256: hash(bytes) };
}
