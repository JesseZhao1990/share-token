import { readFile, readdir, mkdir, rm, copyFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = resolve(root, 'third_party/licenses');
const lock = JSON.parse(await readFile(resolve(root, 'package-lock.json'), 'utf8'));
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
const rows = [];
const warnings = [];
for (const [path, locked] of Object.entries(lock.packages ?? {}).sort(([a], [b]) => a.localeCompare(b))) {
  if (!path) continue;
  const name = path.split('node_modules/').at(-1);
  const directory = resolve(root, path);
  let metadata;
  try { metadata = JSON.parse(await readFile(resolve(directory, 'package.json'), 'utf8')); }
  catch {
    // Platform-specific optional modules may not be installed on this machine.
    if (!locked.optional) throw new Error(`Missing installed dependency: ${path}`);
    rows.push(`| ${name} | ${locked.version} | ${locked.license ?? 'See upstream package'} | Optional for another platform |`);
    continue;
  }
  if (metadata.version !== locked.version) throw new Error(`Installed dependency differs from lockfile: ${path}`);
  const license = typeof metadata.license === 'string' ? metadata.license : locked.license ?? 'See upstream package';
  const safe = `${name.replaceAll('/', '-')}-${metadata.version}`;
  const files = (await readdir(directory)).filter(name => /^(?:license|licence|copying|copyright|notice)(?:\..*)?$/i.test(name));
  const links = [];
  for (const file of files) {
    const target = `${safe}-${file}`;
    try { await copyFile(resolve(directory, file), resolve(output, target)); }
    catch { continue; }
    links.push(`[${file}](third_party/licenses/${target})`);
  }
  if (!links.length && !locked.dev) warnings.push(`${name}@${metadata.version}`);
  rows.push(`| ${name} | ${metadata.version} | ${license.replaceAll('|', '\\|')} | ${links.join(', ') || 'See upstream package'} |`);
}
await copyFile(resolve(root, 'apps/desktop/packaging/Node-LICENSE.txt'), resolve(output, 'Node-LICENSE.txt'));
const text = `# Third-party notices\n\nThe project source uses the MIT license. Dependencies retain their own licenses.\nThis inventory is generated from the public lockfile and the installed dependency\nversions. It includes development dependencies; optional modules for other\nplatforms may only be listed. Regenerate with \`npm run licenses:generate\` after\ndependency updates and review any missing-license warnings.\n\nThe desktop package includes Electron's LICENSE and Chromium notices, the bundled\n[Node.js license](third_party/licenses/Node-LICENSE.txt), and the notices copied\ninto its resources. The Hub package includes the license texts for its actual\nruntime dependencies.\n\n| Package | Version | License | Text |\n| --- | --- | --- | --- |\n${rows.join('\n')}\n\nBrand artwork under \`apps/desktop/packaging\` was generated for this project.\nIt is included under the project MIT license. OpenAI, Codex, Apple and other\nthird-party names remain their respective owners' names and trademarks.\n`;
await writeFile(resolve(root, 'THIRD_PARTY_NOTICES.md'), text);
console.log(JSON.stringify({ packages: rows.length, missingRuntimeLicenseTexts: warnings }, null, 2));
if (warnings.length) process.exitCode = 1;
