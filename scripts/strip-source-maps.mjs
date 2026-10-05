import { readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const lineMappingComment = /^[\t ]*\/\/[#@][\t ]*sourceMappingURL=.*(?:\r?\n|$)/gm;
const blockMappingComment = /\/\*[#@][\t ]*sourceMappingURL=[\s\S]*?\*\//g;

/** Strip mappings only from the package staging tree; development output stays intact. */
export async function stripSourceMaps(directory) {
  const report = { mapsRemoved: 0, filesWithMappingCommentsRemoved: 0 };
  async function walk(path) {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const file = join(path, entry.name);
      if (entry.isSymbolicLink()) throw new Error('Desktop staged assets must not contain symlinks.');
      if (entry.isDirectory()) { await walk(file); continue; }
      if (!entry.isFile()) throw new Error('Desktop staged assets must be regular files.');
      if (/\.map$/i.test(entry.name)) {
        await rm(file); report.mapsRemoved++; continue;
      }
      if (!/\.(?:[cm]?js|css)$/i.test(entry.name)) continue;
      const original = await readFile(file, 'utf8');
      const cleaned = original
        .replace(lineMappingComment, '')
        .replace(blockMappingComment, '');
      if (cleaned !== original) {
        await writeFile(file, cleaned); report.filesWithMappingCommentsRemoved++;
      }
    }
  }
  await walk(directory);
  return report;
}

/** Check the exact extracted delivery, without changing any signed files. */
export async function assertNoSourceMaps(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const file = join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error('Delivered desktop assets must not contain symlinks.');
    if (entry.isDirectory()) { await assertNoSourceMaps(file); continue; }
    if (!entry.isFile() || /\.map$/i.test(entry.name)) throw new Error('Delivered desktop assets must not contain source maps.');
    if (/\.(?:[cm]?js|css)$/i.test(entry.name)) {
      const source = await readFile(file, 'utf8');
      lineMappingComment.lastIndex = 0; blockMappingComment.lastIndex = 0;
      if (lineMappingComment.test(source) || blockMappingComment.test(source)) throw new Error('Delivered desktop assets must not contain source map annotations.');
    }
  }
}
