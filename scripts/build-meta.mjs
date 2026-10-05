import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const versionPattern = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;

export function buildMetadata(packageVersion, env = {}, gitCommit = null) {
  if (typeof packageVersion !== 'string' || !versionPattern.test(packageVersion)) throw new Error('Invalid package version.');
  if (gitCommit !== null && !/^[a-f0-9]{40}$/.test(gitCommit)) throw new Error('Invalid Git commit.');
  if (env.RELEASE_TAG !== undefined && env.RELEASE_TAG !== `v${packageVersion}`) throw new Error('RELEASE_TAG must match v<package.json version>.');
  if (env.RELEASE_TAG && gitCommit === null) throw new Error('A tagged release requires a Git checkout.');
  const archiveName = `Share-Token-${packageVersion}-macOS-arm64-preview.zip`;
  const github = env.GITHUB_ACTIONS === 'true';
  const provenance = { gitCommit, type: github ? 'github-actions' : 'local' };
  if (github) {
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY ?? '') || !/^[1-9]\d*$/.test(env.GITHUB_RUN_ID ?? '')) throw new Error('Invalid GitHub workflow provenance.');
    provenance.repository = env.GITHUB_REPOSITORY;
    provenance.workflowRunId = env.GITHUB_RUN_ID;
  }
  if (env.RELEASE_TAG) provenance.tag = env.RELEASE_TAG;
  return {
    version: packageVersion, archiveName,
    archive: `artifacts/desktop/${archiveName}`,
    report: `artifacts/desktop/release-${packageVersion}.json`,
    checksum: `artifacts/desktop/${archiveName}.sha256`,
    provenance,
  };
}

export async function readBuildMetadata(root = process.cwd(), env = process.env) {
  const metadata = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'));
  let gitCommit = null;
  try { gitCommit = (await exec('git', ['rev-parse', 'HEAD'], { cwd: root })).stdout.trim(); }
  catch { if (env.CI || env.GITHUB_ACTIONS === 'true' || env.RELEASE_TAG) throw new Error('CI packaging requires a Git checkout.'); }
  const result = buildMetadata(metadata.version, env, gitCommit);
  if (env.RELEASE_TAG) {
    let tagCommit;
    try { tagCommit = (await exec('git', ['rev-list', '-n', '1', env.RELEASE_TAG], { cwd: root })).stdout.trim(); }
    catch { throw new Error('The release tag must exist in this checkout.'); }
    if (tagCommit !== gitCommit) throw new Error('The release tag does not identify the checked-out commit.');
  }
  return result;
}
