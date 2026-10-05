import { packager } from '@electron/packager';
import { cp, mkdir, rm, writeFile, chmod, readFile, mkdtemp, stat, readdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { signPreview, verifyPreview } from './macos-preview-sign.mjs';
import { validateHubTrustProfile } from '../dist/packages/hub-client/trust.js';
import { readBuildMetadata } from './build-meta.mjs';
import { desktopBrand, verifyDesktopBrand } from './desktop-brand.mjs';
import { readDesktopHubProfile } from './desktop-profile.mjs';
import { stripSourceMaps } from './strip-source-maps.mjs';

if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('This build is validated for macOS arm64 only. Cross-platform packaging is not yet supported.');
const root = process.cwd();
const exec = promisify(execFile);
const metadata = await readBuildMetadata(root);
const hubProfile = await readDesktopHubProfile(validateHubTrustProfile, { args: process.argv.slice(2), env: process.env, root });
const staging = resolve('.share-token/desktop-staging');
await rm(staging, { recursive: true, force: true }); await mkdir(staging, { recursive: true });
await cp('dist', join(staging, 'dist'), { recursive: true });
const sourceMaps = await stripSourceMaps(join(staging, 'dist'));
// An optional deployment-specific public profile removes address/certificate setup for friends.
// Never package a join code or device/admin credential in this public file.
await rm(join(staging, 'dist/apps/desktop/default.connection.json'), { force: true });
if (hubProfile) await writeFile(join(staging, 'dist/apps/desktop/default.connection.json'), JSON.stringify(hubProfile, null, 2));
await mkdir(join(staging, 'runtime'), { recursive: true });
await cp('node_modules/node/bin/node', join(staging, 'runtime/node')); await chmod(join(staging, 'runtime/node'), 0o755);
await cp('apps/desktop/packaging/Node-LICENSE.txt', join(staging, 'runtime/Node-LICENSE.txt'));
for (const name of ['ws', 'zod', 'node-pty']) await cp(join(root, 'node_modules', name), join(staging, 'node_modules', name), { recursive: true });
// This package only runs on Apple Silicon. Do not ship unrelated native code.
for (const name of await readdir(join(staging, 'node_modules/node-pty/prebuilds'))) {
  if (name !== 'darwin-arm64') await rm(join(staging, 'node_modules/node-pty/prebuilds', name), { recursive: true, force: true });
}
await mkdir(join(staging, 'licenses'), { recursive: true });
for (const name of ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md']) await cp(join(root, name), join(staging, name));
await cp(join(root, 'third_party/licenses'), join(staging, 'licenses/third-party'), { recursive: true });
for (const name of ['react', 'react-dom', '@xterm/xterm', '@xterm/addon-fit']) await cp(join(root, 'node_modules', name, 'LICENSE'), join(staging, 'licenses', name.replaceAll('/', '-') + '.txt'));
await writeFile(join(staging, 'package.json'), JSON.stringify({ name: 'share-token-desktop', productName: desktopBrand.name, version: metadata.version, main: 'dist/apps/desktop/main/index.js', type: 'module', private: true }));
await writeFile(join(staging, 'build-info.json'), JSON.stringify({ version: metadata.version, ...metadata.provenance }, null, 2) + '\n');
const nodeBytes = await readFile(join(staging, 'runtime/node'));
const runtimeHash = createHash('sha256').update(nodeBytes).digest('hex');
const runtimeVersion = (await exec(join(staging, 'runtime/node'), ['--version'])).stdout.trim();
if (!/^v24\./.test(runtimeVersion)) throw new Error('The packaged sidecar must run Node.js 24.');
await writeFile(join(staging, 'runtime/manifest.json'), JSON.stringify({ version: runtimeVersion, platform: process.platform, arch: process.arch, sha256: runtimeHash, channel: 'adhoc-development-preview', notarized: false }, null, 2));
const paths = await packager({ dir: staging, out: resolve('artifacts/desktop', metadata.version), name: desktopBrand.name, executableName: desktopBrand.executableName, appBundleId: desktopBrand.bundleId, appVersion: metadata.version, icon: resolve(desktopBrand.icon), extendInfo: { CFBundleDisplayName: desktopBrand.name }, platform: 'darwin', arch: 'arm64', electronVersion: '44.4.3', overwrite: true, asar: false, prune: false, osxSign: false, usageDescription: { NSHumanReadableCopyright: '共享token — open-source desktop preview' } });
for (const path of paths) {
  const appPath = join(path, desktopBrand.bundleName);
  // Packager derives CFBundleDisplayName from executableName after extendInfo.
  // Set the user-facing names explicitly before sealing the bundle signature.
  for (const key of ['CFBundleName', 'CFBundleDisplayName']) {
    await exec('/usr/bin/plutil', ['-replace', key, '-string', desktopBrand.name, join(appPath, 'Contents/Info.plist')]);
  }
  const branding = await verifyDesktopBrand(appPath);
  const signed = await signPreview(appPath, runtimeHash);
  const archiveName = metadata.archiveName;
  const archive = resolve(metadata.archive);
  // The archive is an output of the signing pipeline, never an unsigned intermediate.
  await rm(archive, { force: true });
  await exec('/usr/bin/ditto', ['-c', '-k', '--sequesterRsrc', '--keepParent', appPath, archive]);
  await exec('/usr/bin/unzip', ['-tq', archive]);
  const extracted = await mkdtemp(join(tmpdir(), 'share-token-release-verify-'));
  let archiveVerification;
  try {
    await exec('/usr/bin/ditto', ['-x', '-k', archive, extracted]);
    await verifyDesktopBrand(join(extracted, desktopBrand.bundleName));
    archiveVerification = await verifyPreview(join(extracted, desktopBrand.bundleName), runtimeHash);
  } finally { await rm(extracted, { recursive: true, force: true }); }
  const hash = createHash('sha256').update(await readFile(archive)).digest('hex');
  await writeFile(archive + '.sha256', `${hash}  ${archiveName}\n`);
  const report = {
    schemaVersion: 1, product: 'share-token', distribution: hubProfile ? 'preconfigured' : 'generic',
    version: metadata.version, platform: 'darwin-arm64', signing: 'ad-hoc', notarized: false,
    archive: metadata.archive, size: (await stat(archive)).size, sha256: hash,
    provenance: metadata.provenance, branding, sourceMaps,
    sourceApp: signed, extractedArchive: archiveVerification,
    verifiedAt: new Date().toISOString(),
  };
  await writeFile(resolve(metadata.report), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
}
