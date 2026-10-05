import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readBuildMetadata } from './build-meta.mjs';

export function validateReleaseReport(report, metadata, bytes) {
  const digest = createHash('sha256').update(bytes).digest('hex');
  if (!report || report.schemaVersion !== 1 || report.product !== 'share-token'
    || report.version !== metadata.version || report.archive !== metadata.archive
    || report.platform !== 'darwin-arm64' || report.distribution !== 'generic'
    || report.signing !== 'ad-hoc' || report.notarized !== false
    || report.sha256 !== digest || report.size !== bytes.byteLength
    || JSON.stringify(report.provenance) !== JSON.stringify(metadata.provenance)) throw new Error('Release report does not match the generic preview archive and source.');
  const verified = report.runtimeVerification;
  if (!verified || verified.archiveSha256 !== digest || !verified.nativeNodeJitAndPty
    || !verified.extractedElectronLaunch || !verified.isolatedProfile
    || !verified.tamperedResourceRejected || verified.bundledPublicConnection !== false
    || verified.notarized !== false || verified.modelInferenceRequests !== 0) throw new Error('Run verify:desktop-release on this exact generic ZIP before preparing release assets.');
  return digest;
}

export async function prepareRelease(root = process.cwd(), env = process.env) {
  const metadata = await readBuildMetadata(root, env);
  const bytes = await readFile(resolve(root, metadata.archive));
  const report = JSON.parse(await readFile(resolve(root, metadata.report), 'utf8'));
  const digest = validateReleaseReport(report, metadata, bytes);
  const checksum = `${digest}  ${metadata.archiveName}\n`;
  if (await readFile(resolve(root, metadata.checksum), 'utf8') !== checksum) throw new Error('Archive checksum file does not match.');
  // Copy only the verified public artifacts; never upload the staging directory.
  const output = resolve(root, 'artifacts/release');
  await rm(output, { recursive: true, force: true });
  await mkdir(output, { recursive: true });
  await cp(resolve(root, metadata.archive), resolve(output, metadata.archiveName));
  await writeFile(resolve(output, metadata.archiveName + '.sha256'), checksum);
  // Only public release identity and verification outcomes belong in this manifest.
  // The local detailed report contains temporary absolute paths and screenshots.
  const manifest = {
    schemaVersion: 1, product: 'share-token', version: metadata.version,
    platform: 'darwin-arm64', distribution: 'generic', signing: 'ad-hoc', notarized: false,
    archive: metadata.archiveName, size: (await stat(resolve(output, metadata.archiveName))).size,
    sha256: digest, provenance: metadata.provenance, verifiedAt: verifiedAt(report),
    verification: { nativeNodeJitAndPty: true, extractedElectronLaunch: true,
      isolatedProfile: true, tamperedResourceRejected: true, modelInferenceRequests: 0,
      friendMacVerified: false, gatekeeperAccepted: report.runtimeVerification.gatekeeper?.accepted === true },
  };
  await writeFile(resolve(output, 'release-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  for (const name of ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md']) await cp(resolve(root, name), resolve(output, name));
  await writeFile(resolve(output, 'release-notes.md'), `Share Token ${metadata.version} — macOS Apple Silicon preview.\n\nThis generic package contains no Hub connection, account, or device credentials. Connect to a Hub you operate or trust.\n\nSigning: ad-hoc. Apple notarization: not completed. Gatekeeper can reject this preview; a successful CI build does not establish trust on another Mac.\n\nThe archive was extracted and verified for signatures, Node/PTY, and an isolated Electron launch using mock-only checks. Real model compatibility and another Mac's installation remain separate acceptance steps.\n\nSource commit: ${metadata.provenance.gitCommit ?? 'unrecorded local checkout'}\n\nSHA-256: ${digest}\n\nSee release-manifest.json and the .sha256 attachment.\n`);
  return { directory: output, archive: basename(metadata.archive), sha256: digest, manifest };
}

function verifiedAt(report) {
  const value = report.runtimeVerification.verifiedAt;
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) throw new Error('Invalid release verification timestamp.');
  return value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  console.log(JSON.stringify(await prepareRelease(), null, 2));
}
