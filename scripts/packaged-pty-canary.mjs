import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

// Verifies native PTY and the real packaged NativeCodexLauncher without using
// a Hub, a user profile, real Codex authentication, or any model request.
const exec = promisify(execFile);
const args = process.argv.slice(2);
const versionIndex = args.indexOf('--version');
const version = versionIndex >= 0 ? args[versionIndex + 1] : '1.0.5';
assert.match(version ?? '', /^\d+\.\d+\.\d+$/, 'Pass --version x.y.z');
assert.ok(args.every((arg, index) => arg === '--version' || args[index - 1] === '--version' || index === 0 && !arg.startsWith('--')), 'Unsupported arguments');
const archive = resolve(args[0] && !args[0].startsWith('--') ? args[0] : `artifacts/desktop/Share-Token-${version}-macOS-arm64-preview.zip`);
const release = JSON.parse(await readFile(resolve(`artifacts/desktop/release-${version}.json`), 'utf8'));
assert.equal(release.version, version);
assert.equal(resolve(release.archive), archive);
const expectedArchiveSha256 = version === '1.0.5' ? '5c780d01f02be1fba30a6827570a33f58b1da33fdf0aec5acb969080ad40832f' : release.sha256;
assert.match(expectedArchiveSha256, /^[0-9a-f]{64}$/);
const temporary = await mkdtemp(join(tmpdir(), 'packaged-pty-canary-'));
const evidence = resolve(`artifacts/desktop-evidence/packaged-pty-${version}.json`);
const result = { testedAt: new Date().toISOString(), archive, clientVersion: version, platform: process.platform, arch: process.arch,
  syntheticCliOnly: true, realAccountRead: false, modelRequests: 0, checks: [], nativeFiles: [] };
let stage = 'archive', failure;

async function sha256(path) {
  const hash = createHash('sha256');
  for await (const bytes of createReadStream(path)) hash.update(bytes);
  return hash.digest('hex');
}

try {
  result.archiveSha256 = await sha256(archive);
  assert.equal(result.archiveSha256, expectedArchiveSha256);
  // Match common Downloads/application folder names with both spaces and Unicode.
  const extraction = join(temporary, 'PTY 验收 空格');
  await mkdir(extraction);
  await exec('/usr/bin/ditto', ['-x', '-k', archive, extraction]);
  const bundle = join(extraction, '共享token.app');
  const resources = join(bundle, 'Contents/Resources/app');
  const runtime = join(resources, 'runtime/node');
  const nativeRoot = join(resources, 'node_modules/node-pty/prebuilds/darwin-arm64');
  const helper = join(nativeRoot, 'spawn-helper');
  const addon = join(nativeRoot, 'pty.node');
  assert.equal(JSON.parse(await readFile(join(resources, 'package.json'), 'utf8')).version, version);
  stage = 'native_file_verification';
  await exec('/usr/bin/codesign', ['--verify', '--deep', '--strict', bundle]);
  for (const [name, path] of [['runtime/node', runtime], ['node-pty/pty.node', addon], ['node-pty/spawn-helper', helper]]) {
    const info = await stat(path);
    if (name !== 'node-pty/pty.node') assert.ok(info.mode & 0o111, 'Native executable must have an executable permission bit');
    await exec('/usr/bin/codesign', ['--verify', '--strict', path]);
    const kind = await exec('/usr/bin/file', ['-b', path]);
    const links = await exec('/usr/bin/otool', ['-L', path]);
    const loadCommands = await exec('/usr/bin/otool', ['-l', path]);
    const minimumOS = [...loadCommands.stdout.matchAll(/cmd (?:LC_VERSION_MIN_MACOSX|LC_BUILD_VERSION)[\s\S]*?(?:version|minos) ([0-9.]+)/g)].map(match => match[1]);
    const dependencies = links.stdout.split('\n').slice(1).map(line => line.trim()).filter(Boolean);
    result.nativeFiles.push({ name, bytes: info.size, mode: (info.mode & 0o777).toString(8), signed: true,
      architecture: kind.stdout.trim(), minimumOS, dependencies, sha256: await sha256(path) });
  }
  result.checks.push('ZIP extracted with executable spawn-helper; Node, addon and helper signatures valid');

  const project = join(temporary, '本机项目 with spaces');
  const fixtures = join(temporary, 'fixture programs');
  await mkdir(project); await mkdir(fixtures);
  const fakeCodex = join(fixtures, 'codex-fixture');
  await writeFile(fakeCodex, `#!/usr/bin/env node
if (process.argv.includes('--version')) { console.log('codex-cli 0.153.4'); process.exit(0); }
if (!process.stdin.isTTY || !process.stdout.isTTY) process.exit(11);
if (!process.env.SHARE_TOKEN_ACCESS_KEY) process.exit(12);
if (!process.argv.includes('-c')) process.exit(13);
console.log('PACKAGED_NATIVE_LAUNCHER_READY');
process.stdin.setEncoding('utf8');
process.stdin.on('data', data => { if (data.includes('canary-input')) { console.log('PACKAGED_NATIVE_LAUNCHER_INPUT_OK'); process.exit(0); } });
`, { mode: 0o700 });

  const script = join(temporary, 'native-probe.cjs');
  await writeFile(script, `
const assert = require('node:assert/strict');
const { pathToFileURL } = require('node:url');
const pty = require(${JSON.stringify(join(resources, 'node_modules/node-pty'))});
const timeout = (promise, label) => {
 let timer; return Promise.race([promise, new Promise((_,reject) => { timer=setTimeout(()=>reject(new Error(label+' timed out')),10000); })]).finally(()=>clearTimeout(timer));
};
(async () => {
 let rawOutput='';
 const terminal = pty.spawn('/bin/sh', ['-c', 'printf PACKAGED_RAW_PTY_OK'], {name:'xterm-256color',cols:80,rows:24,cwd:${JSON.stringify(project)},env:process.env});
 terminal.onData(data=>rawOutput+=data);
 const rawExit=await timeout(new Promise(resolve=>terminal.onExit(resolve)),'raw PTY');
 assert.equal(rawExit.exitCode,0); assert.ok(rawOutput.includes('PACKAGED_RAW_PTY_OK'));
 const { NativeCodexLauncher } = await import(pathToFileURL(${JSON.stringify(join(resources, 'dist/packages/client-core/launcher.js'))}).href);
 let output='', resolveReady, resolveExit;
 const ready=new Promise(resolve=>resolveReady=resolve), exited=new Promise(resolve=>resolveExit=resolve);
 let handle;
 try {
  handle=await new NativeCodexLauncher().start({codexPath:${JSON.stringify(fakeCodex)},cwd:${JSON.stringify(project)},model:'synthetic-model',baseUrl:'http://127.0.0.1:1/v1',localKey:'synthetic-local-key-not-a-real-credential',onData(data){output+=data;if(output.includes('PACKAGED_NATIVE_LAUNCHER_READY'))resolveReady();},onExit:resolveExit});
  await timeout(ready,'launcher ready'); handle.resize(120,45); handle.write('canary-input\\r');
  const event=await timeout(exited,'launcher exit'); assert.equal(event.exitCode,0); assert.ok(output.includes('PACKAGED_NATIVE_LAUNCHER_INPUT_OK'));
  console.log(JSON.stringify({rawPty:true,packagedNativeLauncher:true,interactiveInput:true,resize:true,exitCode:event.exitCode,nodeVersion:process.version,architecture:process.arch}));
 } finally { await handle?.stop(); }
})().catch(error=>{console.error(JSON.stringify({failure:error.code||error.name}));process.exitCode=1;});
`);

  stage = 'pty_finder_environment';
  // A Finder-like minimal PATH reproduces machines without Homebrew/npm Node.
  // NativeCodexLauncher must prepend its own signed runtime for /usr/bin/env node.
  const minimal = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'en_US.UTF-8', TMPDIR: temporary };
  const probe = await exec(runtime, [script], { cwd: project, env: minimal, timeout: 30_000, maxBuffer: 64 * 1024 });
  const observed = JSON.parse(probe.stdout.trim());
  assert.equal(observed.rawPty, true); assert.equal(observed.packagedNativeLauncher, true); assert.equal(observed.exitCode, 0);
  result.probe = observed;
  result.checks.push('raw /bin/sh PTY starts with minimal Finder PATH');
  result.checks.push('packaged NativeCodexLauncher detects shebang CLI using bundled Node, opens interactive TTY, writes, resizes and exits cleanly');
  result.checks.push('app path, project path and executable path containing Chinese characters and spaces work');
  stage = 'unchanged_bundle_verification';
  await exec('/usr/bin/codesign', ['--verify', '--deep', '--strict', bundle]);
  for (const [name, path] of [['runtime/node', runtime], ['node-pty/pty.node', addon], ['node-pty/spawn-helper', helper]]) assert.equal(await sha256(path), result.nativeFiles.find(file => file.name === name).sha256);
  result.bundleUnmodified = true;
  result.success = true;
} catch (error) {
  failure = { stage, code: typeof error.code === 'string' ? error.code : error.name };
  result.success = false;
  result.failure = failure;
  process.exitCode = 1;
} finally {
  await mkdir(resolve('artifacts/desktop-evidence'), { recursive: true });
  await writeFile(evidence, JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ event: 'packaged-pty-report', path: evidence, success: result.success, ...(failure ? { failure } : {}) }));
  await rm(temporary, { recursive: true, force: true });
}
