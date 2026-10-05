import { sign } from '@electron/osx-sign';
import { open, readdir, readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';

const exec = promisify(execFile);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const machOMagic = new Set(['feedface', 'cefaedfe', 'feedfacf', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca']);

export async function nativeFiles(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    // Do not follow framework symlinks or sign the same executable twice.
    if (entry.isDirectory()) files.push(...await nativeFiles(path));
    else if (entry.isFile()) {
      const file = await open(path, 'r');
      try {
        const buffer = Buffer.alloc(4);
        const { bytesRead } = await file.read(buffer, 0, 4, 0);
        if (bytesRead === 4 && machOMagic.has(buffer.toString('hex'))) files.push(path);
      } finally { await file.close(); }
    }
  }
  return files;
}

export async function verifyPreview(appPath, expectedRuntimeHash) {
  await exec('/usr/bin/codesign', ['--verify', '--deep', '--strict', '--verbose=2', appPath]);
  const binaries = await nativeFiles(join(appPath, 'Contents'));
  // Resource-directory executables are not all covered by codesign's recursive
  // nested-code discovery, so explicitly check Node and native addons too.
  for (const path of binaries) await exec('/usr/bin/codesign', ['--verify', '--strict', path]);
  const runtime = join(appPath, 'Contents/Resources/app/runtime/node');
  const runtimeHash = sha256(await readFile(runtime));
  if (runtimeHash !== expectedRuntimeHash) throw new Error('The signed Node distribution was modified during packaging.');
  return { deepStrictSignatureValid: true, nativeSignaturesVerified: binaries.length, runtimeSha256: runtimeHash };
}

export async function signPreview(appPath, expectedRuntimeHash) {
  appPath = resolve(appPath);
  const runtime = join(appPath, 'Contents/Resources/app/runtime/node');
  await exec('/usr/bin/codesign', ['--verify', '--strict', runtime]);
  if (sha256(await readFile(runtime)) !== expectedRuntimeHash) throw new Error('Bundled Node must match the pinned distribution before signing.');
  const binaries = new Set(await nativeFiles(join(appPath, 'Contents')));
  await sign({
    app: appPath, platform: 'darwin', identity: '-', identityValidation: false,
    preAutoEntitlements: false, preEmbedProvisioningProfile: false, strictVerify: true,
    // Keep Node's upstream Developer ID signature, entitlements and bytes intact.
    // osx-sign otherwise attempts to sign every binary-looking resource, including
    // non-code files. Only Mach-O files and actual bundle containers need signing.
    ignore: path => path === runtime || (!binaries.has(path) && !path.endsWith('.app') && !path.endsWith('.framework')),
    optionsForFile: () => ({
      entitlements: resolve('apps/desktop/packaging/preview-entitlements.plist'),
      hardenedRuntime: false, timestamp: 'none',
    }),
  });
  return verifyPreview(appPath, expectedRuntimeHash);
}
