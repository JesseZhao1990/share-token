import { chmod, access } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const root = process.cwd();
const runtime = join(root, 'node_modules/node/bin', process.platform === 'win32' ? 'node.exe' : 'node');
await access(runtime);
const version = execFileSync(runtime, ['--version'], { encoding: 'utf8' }).trim();
if (!/^v24\./.test(version)) throw new Error('The desktop sidecar requires the pinned Node 24 runtime.');
// node-pty 1.1.0 ships its macOS helper without the executable bit in its npm archive.
if (process.platform === 'darwin') await chmod(join(root, `node_modules/node-pty/prebuilds/darwin-${process.arch}/spawn-helper`), 0o755);
try { await access(require('electron')); }
catch { execFileSync(runtime, [join(root, 'node_modules/electron/install.js')], { stdio: 'inherit' }); }
