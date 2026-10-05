import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { createRequire, isBuiltin } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runtime = /^24\./.test(process.versions.node) ? process.execPath
  : join(root, 'node_modules/node/bin', process.platform === 'win32' ? 'node.exe' : 'node');
const nodeVersion = execFileSync(runtime, ['--version'], { encoding: 'utf8' }).trim();
if (!/^v24\./.test(nodeVersion)) throw new Error('Hub packaging requires the pinned Node 24 runtime.');
const metadata = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(metadata.version)) throw new Error('Invalid package version.');
const createdAt = new Date().toISOString();
const timestamp = createdAt.replace(/[-:.]/g, '');
const outputDir = join(root, 'artifacts/hub');
const archive = join(outputDir, `share-token-hub-${metadata.version}-${timestamp}.tar.gz`);
const temporary = await realpath(await mkdtemp(join(tmpdir(), 'share-token-hub-package-')));
const compiled = join(temporary, 'compiled');
const staging = join(temporary, 'payload');
const modules = ['apps/cli', 'apps/hub', 'apps/relay', 'packages/protocol', 'packages/policy', 'packages/storage', 'packages/upstream', 'packages/hub-client'];
const dependencies = ['ws', 'zod'];
const dependencyMetadata = new Map();

async function files(directory) {
  const output = [];
  for (const name of (await readdir(directory)).sort()) {
    const path = join(directory, name);
    const stat = await lstat(path);
    if (stat.isSymbolicLink()) throw new Error(`Symlinks are not allowed in the Hub artifact: ${relative(staging, path)}`);
    if (stat.isDirectory()) output.push(...await files(path));
    else if (stat.isFile()) output.push(path);
    else throw new Error(`Unsupported artifact entry: ${relative(staging, path)}`);
  }
  return output;
}

function moduleReferences(source, name) {
  const tree = ts.createSourceFile(name, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const references = [];
  const visit = node => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
      if (!ts.isStringLiteralLike(node.moduleSpecifier)) throw new Error(`Non-literal module declaration in ${name}`);
      references.push(node.moduleSpecifier.text);
    }
    if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword || ts.isIdentifier(node.expression) && node.expression.text === 'require')) {
      if (node.arguments.length !== 1 || !ts.isStringLiteralLike(node.arguments[0])) throw new Error(`Non-literal module loading in ${name}`);
      references.push(node.arguments[0].text);
    }
    ts.forEachChild(node, visit);
  };
  visit(tree);
  return references;
}

async function validateClosure(payloadFiles) {
  let checkedModules = 0;
  const optionalPeers = new Set();
  for (const file of payloadFiles) {
    const path = relative(staging, file).split(sep).join('/');
    // Browser files are standalone Vite output, not Node modules.
    if (path.startsWith('dist/web/') || !/\.(?:mjs|cjs|js)$/.test(file)) continue;
    checkedModules++;
    const owner = dependencies.find(name => path.startsWith(`node_modules/${name}/`));
    const require = createRequire(file);
    for (const specifier of moduleReferences(await readFile(file, 'utf8'), path)) {
      if (isBuiltin(specifier)) continue;
      const bare = !specifier.startsWith('.');
      if (bare && !dependencies.includes(specifier.split('/')[0])) {
        if (owner && dependencyMetadata.get(owner)?.peerDependenciesMeta?.[specifier]?.optional === true) {
          optionalPeers.add(`${owner}:${specifier}`);
          continue;
        }
        throw new Error(`Dependency is outside the Hub whitelist: ${path} -> ${specifier}`);
      }
      let target;
      try { target = require.resolve(specifier); }
      catch { throw new Error(`Missing packaged dependency: ${path} -> ${specifier}`); }
      if (!target.startsWith(staging + sep)) throw new Error(`Dependency escapes the Hub artifact: ${path} -> ${specifier}`);
      if (!(await lstat(target)).isFile()) throw new Error(`Dependency is not a regular file: ${path} -> ${specifier}`);
    }
  }
  return { checkedModules, optionalPeersNotRequired: [...optionalPeers].sort() };
}

try {
  // Invoke build tools directly so neither root prebuild nor desktop setup runs.
  execFileSync(runtime, [join(root, 'node_modules/typescript/bin/tsc'), '-p', join(root, 'tsconfig.json'), '--sourceMap', 'false', '--outDir', compiled], { cwd: root, stdio: 'inherit' });
  // Temporary output paths otherwise appear in Vite source maps and disclose
  // the build machine's home directory in a public runtime archive.
  const viteOptions = { configFile: join(root, 'apps/web/vite.config.ts'), build: { outDir: join(compiled, 'web'), sourcemap: false } };
  execFileSync(runtime, ['--input-type=module', '-e', `import { build } from 'vite'; await build(${JSON.stringify(viteOptions)});`], { cwd: root, stdio: 'inherit' });
  await mkdir(staging);
  for (const module of modules) {
    const source = join(compiled, module);
    const destination = join(staging, 'dist', module);
    await mkdir(dirname(destination), { recursive: true });
    await cp(source, destination, { recursive: true, errorOnExist: true, force: false });
  }
  await cp(join(compiled, 'web'), join(staging, 'dist/web'), { recursive: true });
  for (const name of dependencies) {
    const source = join(root, 'node_modules', name);
    const info = JSON.parse(await readFile(join(source, 'package.json'), 'utf8'));
    dependencyMetadata.set(name, info);
    for (const required of Object.keys(info.dependencies ?? {})) {
      if (!dependencies.includes(required)) throw new Error(`Unpackaged dependency: ${name} -> ${required}`);
    }
    await cp(source, join(staging, 'node_modules', name), { recursive: true });
  }
  await writeFile(join(staging, 'package.json'), JSON.stringify({
    name: 'share-token-hub', version: metadata.version, private: true, type: 'module',
    engines: { node: '>=24.0.0 <25' },
    scripts: { start: 'node dist/apps/cli/index.js hub' },
    dependencies: Object.fromEntries(dependencies.map(name => [name, dependencyMetadata.get(name).version])),
  }, null, 2) + '\n');
  // Keep project and dependency notices with the redistributable runtime.
  for (const name of ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md']) {
    await cp(join(root, name), join(staging, name));
  }
  await cp(join(root, 'third_party/licenses'), join(staging, 'third_party/licenses'), { recursive: true });
  const payloadFiles = await files(staging);
  for (const file of payloadFiles) {
    const path = relative(staging, file).split(sep).join('/');
    if (/(?:^|\/)(?:\.env(?:\.[^/]*)?|[^/]+\.(?:token|sqlite(?:-[^/]*)?|db|log)|auth\.json|\.share-token)(?:\/|$)/i.test(path)) throw new Error(`Runtime data found in the Hub artifact: ${path}`);
  }
  const closure = await validateClosure(payloadFiles);
  const hashes = {};
  for (const file of payloadFiles) hashes[relative(staging, file).split(sep).join('/')] = createHash('sha256').update(await readFile(file)).digest('hex');
  await writeFile(join(staging, 'manifest.json'), JSON.stringify({
    name: 'share-token-hub', version: metadata.version, createdAt, buildNode: nodeVersion,
    runtime: 'Node.js 24; install separately for the target operating system and architecture',
    entrypoint: 'dist/apps/cli/index.js', workingDirectory: '.', channel: 'self-hosted-open-source',
    hashAlgorithm: 'sha256', hashScope: 'Every payload file except manifest.json itself',
    dependencies: Object.fromEntries(dependencies.map(name => [name, dependencyMetadata.get(name).version])),
    closure, files: hashes,
  }, null, 2) + '\n');
  await mkdir(outputDir, { recursive: true });
  execFileSync('tar', ['-czf', archive + '.partial', '-C', staging, '.'], { env: { ...process.env, COPYFILE_DISABLE: '1' }, stdio: 'inherit' });
  await rename(archive + '.partial', archive);
  const sha256 = createHash('sha256').update(await readFile(archive)).digest('hex');
  await writeFile(archive + '.sha256', `${sha256}  ${archive.split(sep).at(-1)}\n`);
  console.log(JSON.stringify({ archive, sha256, payloadFiles: payloadFiles.length, ...closure }, null, 2));
} finally {
  await rm(temporary, { recursive: true, force: true });
  await rm(archive + '.partial', { force: true });
}
