// Convert the approved PNG artwork into native macOS icon resolutions.
// No image-generation service is required when rebuilding the assets.
import { mkdtemp, mkdir, rm, readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const exec = promisify(execFile);
if (process.platform !== 'darwin') throw new Error('Icon conversion requires macOS sips and iconutil.');
const directory = await mkdtemp(join(tmpdir(), 'share-token-icon-'));
const assets = resolve('apps/desktop/packaging');
try {
  const iconset = join(directory, 'AppIcon.iconset');
  await mkdir(iconset);
  for (const size of [16, 32, 128, 256, 512]) {
    for (const scale of [1, 2]) {
      await exec('/usr/bin/sips', ['-z', String(size * scale), String(size * scale), join(assets, 'app-icon.png'), '--out', join(iconset, `icon_${size}x${size}${scale === 2 ? '@2x' : ''}.png`)]);
    }
  }
  await exec('/usr/bin/iconutil', ['-c', 'icns', iconset, '-o', join(assets, 'app-icon.icns')]);
  const icon = await readFile(join(assets, 'app-icon.icns'));
  if (icon.subarray(0, 4).toString() !== 'icns') throw new Error('Invalid macOS icon.');
  for (const scale of [1, 2]) {
    await exec('/usr/bin/sips', ['-s', 'format', 'png', '-z', String(22 * scale), String(22 * scale), join(assets, 'tray-template.svg'), '--out', join(assets, `trayTemplate${scale === 2 ? '@2x' : ''}.png`)]);
  }
  console.log('Generated macOS app icon at 10 resolutions and template tray icons at 1x/2x.');
} finally { await rm(directory, { recursive: true, force: true }); }
