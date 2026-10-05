import { readFile, readdir, lstat } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const directoryIndex = args.indexOf('--directory');
if (directoryIndex !== -1 && !args[directoryIndex + 1]) throw new Error('--directory requires a path');
const root = directoryIndex === -1 ? projectRoot : resolve(args[directoryIndex + 1]);
const releaseDirectory = root !== projectRoot;
const excluded = new Set(['.git', 'node_modules', 'dist', 'artifacts', '.share-token', 'coverage', 'output', '.playwright-cli']);
const findings = [];
let filesChecked = 0;
const companyDomains = new RegExp('\\b(?:[a-z0-9-]+\\.)*(?:' + [
  ['byted', 'org'], ['bytedance', 'net'], ['bytedance', 'com'],
  ['bytegoofy', 'com'], ['douyinask', 'com'], ['jiyunhudong', 'com'],
].map(parts => parts.join('\\.')).join('|') + ')\\b', 'i');
const rules = [
  ['company endpoint', companyDomains],
  ['private machine path', /\/(?:Users|home)\/(?:bytedance|zhaojianxin(?:\.123)?)(?:\/|\b)/i],
  ['legacy release integration', /\bTRON_[A-Z_]+\b|\bCI_PIPELINE_ID\b|\bCI_JOB_ID\b/],
  ['private key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/],
  ['provider key', /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b/],
  ['GitHub credential', /\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/],
  ['cloud access key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
];

function inspect(path, bytes, revision) {
  filesChecked++;
  const prefix = revision ? `${revision}:${path}` : path;
  if (/(?:^|\/)(?:auth\.json|[^/]+\.(?:sqlite(?:-[^/]*)?|db|token|encrypted|pem|key|p12|pfx|connection\.json)|\.env(?:\..*)?)$/i.test(path)
      && !path.endsWith('.env.example')) findings.push({ path: prefix, rule: 'runtime or credential file' });
  if (/^(?:\.codebase|tools\/tron|docs\/website-deploy\/evidence)(?:\/|$)/.test(path)) findings.push({ path: prefix, rule: 'private integration or deployment evidence' });
  const source = bytes.toString('utf8');
  for (const [rule, pattern] of rules) {
    const match = pattern.exec(source);
    if (match) findings.push({ path: prefix, rule, line: source.slice(0, match.index).split('\n').length });
  }
  if (path.endsWith('package-lock.json')) {
    let lock;
    try { lock = JSON.parse(source); } catch { findings.push({ path: prefix, rule: 'invalid lockfile' }); return; }
    for (const [key, value] of Object.entries(lock.packages ?? {})) {
      if (value.resolved && !value.resolved.startsWith('https://registry.npmjs.org/')) findings.push({ path: prefix, rule: `non-public dependency registry: ${key}` });
      if (key && value.resolved && !/^sha512-/.test(value.integrity ?? '')) findings.push({ path: prefix, rule: `missing dependency integrity: ${key}` });
    }
  }
  if (path === '.npmrc' && source.trim() !== 'registry=https://registry.npmjs.org/\nengine-strict=true') findings.push({ path: prefix, rule: 'unexpected npm configuration' });
}

async function walk(directory) {
  for (const name of (await readdir(directory)).sort()) {
    if (!releaseDirectory && excluded.has(name)) continue;
    const file = resolve(directory, name);
    const stat = await lstat(file);
    const path = relative(root, file).split(sep).join('/');
    if (stat.isSymbolicLink()) {
      if (!releaseDirectory) findings.push({ path, rule: 'source symlink' });
      continue;
    }
    if (stat.isDirectory()) await walk(file);
    else if (stat.isFile()) inspect(path, await readFile(file));
    else findings.push({ path, rule: 'unsupported filesystem entry' });
  }
}

await walk(root);
if (!releaseDirectory) {
  for (const file of ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'SECURITY.md', 'CONTRIBUTING.md', 'package-lock.json']) {
    try { await readFile(resolve(root, file)); } catch { findings.push({ path: file, rule: 'required public repository file missing' }); }
  }
}
let revisionsChecked = 0;
if (args.includes('--git-history')) {
  const revisions = execFileSync('git', ['rev-list', '--all'], { cwd: root, encoding: 'utf8' }).trim().split('\n').filter(Boolean);
  const seen = new Set();
  for (const revision of revisions) {
    revisionsChecked++;
    const entries = execFileSync('git', ['ls-tree', '-r', '-z', revision], { cwd: root, maxBuffer: 20 * 1024 * 1024 }).toString('utf8').split('\0').filter(Boolean);
    for (const entry of entries) {
      const [, mode, type, hash, path] = /^(\d+) (\w+) ([a-f0-9]+)\t([\s\S]+)$/.exec(entry) ?? [];
      if (type !== 'blob') continue;
      if (mode === '120000') findings.push({ path: `${revision}:${path}`, rule: 'history symlink' });
      const identity = `${path}:${hash}`;
      if (seen.has(identity)) continue;
      seen.add(identity);
      inspect(path, execFileSync('git', ['cat-file', 'blob', hash], { cwd: root, maxBuffer: 50 * 1024 * 1024 }), revision);
    }
    const metadata = execFileSync('git', ['show', '-s', '--format=%an <%ae>%n%cn <%ce>%n%B', revision], { cwd: root });
    inspect('(commit metadata)', metadata, revision);
  }
}
const report = { passed: findings.length === 0, filesChecked, revisionsChecked, findings,
  scope: 'company endpoints, private paths, forbidden state files, dependency registry/integrity, high-confidence credential patterns',
  limitations: 'A static release check; not a proof that every possible secret or security defect is absent.' };
console.log(JSON.stringify(report, null, 2));
if (!report.passed) process.exitCode = 1;
