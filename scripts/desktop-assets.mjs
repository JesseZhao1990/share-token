import { copyFile, mkdir } from 'node:fs/promises';
await mkdir('dist/apps/desktop', { recursive: true });
await copyFile('apps/desktop/preload.cjs', 'dist/apps/desktop/preload.cjs');
await mkdir('dist/apps/desktop/brand', { recursive: true });
for (const name of ['app-icon.png', 'trayTemplate.png', 'trayTemplate@2x.png']) {
  await copyFile(`apps/desktop/packaging/${name}`, `dist/apps/desktop/brand/${name}`);
}
