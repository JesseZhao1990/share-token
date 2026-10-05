import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { stripSourceMaps, assertNoSourceMaps } = await import(new URL('../scripts/strip-source-maps.mjs', import.meta.url).href);

test('desktop staging removes TS and web source maps plus their annotations without altering development output', async t => {
  const temporary = await mkdtemp(join(tmpdir(), 'share-token-staged-maps-'));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const development = join(temporary, 'development');
  const staging = join(temporary, 'staging');
  await mkdir(join(development, 'web/assets'), { recursive: true });
  const js = 'export const sample = 1;\n//# sourceMappingURL=sample.js.map\n';
  const css = 'body{color:green}/*# sourceMappingURL=index.css.map */\n';
  const mapping = JSON.stringify({ version: 3, sources: ['/fixture-build-root/private/source.ts'], mappings: '' });
  await writeFile(join(development, 'sample.js'), js);
  await writeFile(join(development, 'sample.js.map'), mapping);
  await writeFile(join(development, 'web/assets/index.css'), css);
  await writeFile(join(development, 'web/assets/index.css.map'), mapping);
  await writeFile(join(development, 'web/assets/brand.svg'), '<svg/>');
  await cp(development, staging, { recursive: true });
  await assert.rejects(assertNoSourceMaps(staging), /source map/);
  assert.deepEqual(await stripSourceMaps(staging), { mapsRemoved: 2, filesWithMappingCommentsRemoved: 2 });
  await assertNoSourceMaps(staging);
  assert.equal(await readFile(join(staging, 'sample.js'), 'utf8'), 'export const sample = 1;\n');
  assert.equal(await readFile(join(staging, 'web/assets/index.css'), 'utf8'), 'body{color:green}\n');
  assert.equal((await readdir(staging)).includes('sample.js.map'), false);
  assert.equal((await readdir(join(staging, 'web/assets'))).includes('index.css.map'), false);
  assert.equal(await readFile(join(development, 'sample.js'), 'utf8'), js);
  assert.equal(await readFile(join(development, 'sample.js.map'), 'utf8'), mapping);
  assert.equal(await readFile(join(staging, 'web/assets/brand.svg'), 'utf8'), '<svg/>');
  assert.deepEqual(await stripSourceMaps(staging), { mapsRemoved: 0, filesWithMappingCommentsRemoved: 0 });
  await writeFile(join(staging, 'orphan.js'), 'export const sample = 1;\n//# sourceMappingURL=missing.js.map\n');
  await assert.rejects(assertNoSourceMaps(staging), /annotations/);
});
