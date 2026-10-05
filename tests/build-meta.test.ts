import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { buildMetadata, readBuildMetadata } = await import(new URL('../scripts/build-meta.mjs', import.meta.url).href);
const { validateReleaseReport } = await import(new URL('../scripts/prepare-release.mjs', import.meta.url).href);
const commit = 'a'.repeat(40);

test('public build metadata records source without embedding unrelated environment data', () => {
  const metadata = buildMetadata('0.1.0', { RELEASE_TAG: 'v0.1.0', GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'sample/share-token', GITHUB_RUN_ID: '12345', UNRELATED_PRIVATE_VALUE: 'fixture-never-export' }, commit);
  assert.equal(metadata.archiveName, 'Share-Token-0.1.0-macOS-arm64-preview.zip');
  assert.deepEqual(metadata.provenance, { gitCommit: commit, type: 'github-actions', repository: 'sample/share-token', workflowRunId: '12345', tag: 'v0.1.0' });
  assert.equal(JSON.stringify(metadata).includes('fixture-never-export'), false);
  assert.throws(() => buildMetadata('0.1.0', { RELEASE_TAG: 'v0.2.0' }, commit), /must match/);
  assert.throws(() => buildMetadata('0.1.0', { RELEASE_TAG: 'v0.1.0' }), /Git checkout/);
  assert.throws(() => buildMetadata('../bad'), /Invalid package version/);
  assert.throws(() => buildMetadata('0.1.0', {}, 'bad-commit'), /Invalid Git commit/);
  assert.throws(() => buildMetadata('0.1.0', { GITHUB_ACTIONS: 'true' }, commit), /workflow provenance/);
});

test('tagged releases require the checked-out commit to match the existing tag', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'share-token-public-build-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const git = (...args: string[]) => execFileSync('git', args, { cwd: directory, encoding: 'utf8', stdio: 'pipe' }).trim();
  git('init', '-q');
  git('config', 'user.name', 'Public fixture');
  git('config', 'user.email', 'fixture@example.invalid');
  await writeFile(join(directory, 'package.json'), JSON.stringify({ version: '0.1.0' }));
  git('add', 'package.json'); git('commit', '-qm', 'Initial fixture'); git('tag', 'v0.1.0');
  const tagged = await readBuildMetadata(directory, { RELEASE_TAG: 'v0.1.0' });
  assert.equal(tagged.provenance.gitCommit, git('rev-parse', 'HEAD'));
  await writeFile(join(directory, 'fixture.txt'), 'next commit');
  git('add', 'fixture.txt'); git('commit', '-qm', 'Changed fixture');
  await assert.rejects(readBuildMetadata(directory, { RELEASE_TAG: 'v0.1.0' }), /does not identify/);
});

test('release preparation rejects unverified, altered, or preconfigured archives', () => {
  const metadata = buildMetadata('0.1.0', {}, commit);
  const bytes = Buffer.from('synthetic-zip-fixture');
  const digest = createHash('sha256').update(bytes).digest('hex');
  const report = {
    schemaVersion: 1, product: 'share-token', version: '0.1.0', archive: metadata.archive,
    platform: 'darwin-arm64', distribution: 'generic', signing: 'ad-hoc', notarized: false,
    sha256: digest, size: bytes.length, provenance: metadata.provenance,
    runtimeVerification: { archiveSha256: digest, nativeNodeJitAndPty: true, extractedElectronLaunch: true,
      isolatedProfile: true, tamperedResourceRejected: true, bundledPublicConnection: false,
      notarized: false, modelInferenceRequests: 0 },
  };
  assert.equal(validateReleaseReport(report, metadata, bytes), digest);
  assert.throws(() => validateReleaseReport(report, metadata, Buffer.from('changed')), /does not match/);
  assert.throws(() => validateReleaseReport({ ...report, distribution: 'preconfigured' }, metadata, bytes), /does not match/);
  assert.throws(() => validateReleaseReport({ ...report, runtimeVerification: undefined }, metadata, bytes), /verify:desktop-release/);
  assert.throws(() => validateReleaseReport({ ...report, runtimeVerification: { ...report.runtimeVerification, modelInferenceRequests: 1 } }, metadata, bytes), /verify:desktop-release/);
});

test('tagged provenance rejects dirty source and renames but allows generated licenses and ignored build output', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'share-token-tagged-source-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const git = (...args: string[]) => execFileSync('git', args, { cwd: directory, encoding: 'utf8', stdio: 'pipe' }).trim();
  git('init', '-q'); git('config', 'user.name', 'Public fixture'); git('config', 'user.email', 'fixture@example.invalid');
  await mkdir(join(directory, 'apps'), { recursive: true });
  await mkdir(join(directory, 'third_party/licenses'), { recursive: true });
  await writeFile(join(directory, 'package.json'), JSON.stringify({ version: '0.1.0' }));
  await writeFile(join(directory, '.gitignore'), 'dist/\nartifacts/\n');
  await writeFile(join(directory, 'apps/main.ts'), 'export const sample = true;\n');
  await writeFile(join(directory, 'THIRD_PARTY_NOTICES.md'), 'Original inventory\n');
  await writeFile(join(directory, 'third_party/licenses/fixture.txt'), 'Original generated license fixture\n');
  git('add', '.'); git('commit', '-qm', 'Tagged fixture'); git('tag', 'v0.1.0');
  await writeFile(join(directory, 'apps/main.ts'), 'export const sample = false;\n');
  await assert.rejects(readBuildMetadata(directory, { RELEASE_TAG: 'v0.1.0' }), /committed source/);
  git('restore', 'apps/main.ts');
  await writeFile(join(directory, 'apps/untracked source.ts'), 'export const untracked = true;\n');
  await assert.rejects(readBuildMetadata(directory, { RELEASE_TAG: 'v0.1.0' }), /committed source/);
  await rm(join(directory, 'apps/untracked source.ts'));
  // A staged rename into an allowed generated directory still changes source.
  git('mv', 'apps/main.ts', 'third_party/licenses/moved-source.txt');
  await assert.rejects(readBuildMetadata(directory, { RELEASE_TAG: 'v0.1.0' }), /committed source/);
  git('mv', 'third_party/licenses/moved-source.txt', 'apps/main.ts');
  await writeFile(join(directory, 'THIRD_PARTY_NOTICES.md'), 'Updated platform inventory\n');
  await writeFile(join(directory, 'third_party/licenses/fixture.txt'), 'Updated generated license fixture\n');
  await writeFile(join(directory, 'third_party/licenses/new.txt'), 'Additional platform fixture\n');
  await mkdir(join(directory, 'artifacts'), { recursive: true });
  await writeFile(join(directory, 'artifacts/preview.zip'), 'ignored output fixture');
  assert.equal((await readBuildMetadata(directory, { RELEASE_TAG: 'v0.1.0' })).provenance.tag, 'v0.1.0');
});
