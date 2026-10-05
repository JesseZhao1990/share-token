import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const publicFields = new Set(['version', 'hubUrl', 'certificatePem', 'label']);
const maxProfileBytes = 64 * 1024;

// Inject the shared trust validator so tests can use source before the build,
// while the packager uses the exact compiled validator shipped in the app.
export async function readDesktopHubProfile(validateProfile, { args = [], env = {}, root = process.cwd() } = {}) {
  const fileArguments = args.flatMap((value, index) => value === '--hub-profile' ? [index] : []);
  if (fileArguments.length > 1) throw new Error('Provide --hub-profile only once.');
  const index = fileArguments[0];
  const file = index === undefined ? undefined : args[index + 1];
  if (index !== undefined && (!file || file.startsWith('--'))) throw new Error('--hub-profile requires a public connection file.');
  const suppliedJson = env.SHARE_TOKEN_HUB_PROFILE_JSON !== undefined;
  if (file && suppliedJson) throw new Error('Provide either --hub-profile or SHARE_TOKEN_HUB_PROFILE_JSON, not both.');
  if (!file && !suppliedJson) {
    if (args.includes('--require-hub-profile')) throw new Error('This build requires a public Hub profile: use --hub-profile or SHARE_TOKEN_HUB_PROFILE_JSON.');
    return null;
  }

  let source;
  if (file) {
    try { source = await readFile(resolve(root, file), 'utf8'); }
    catch { throw new Error('Cannot read the --hub-profile public connection file.'); }
  } else source = env.SHARE_TOKEN_HUB_PROFILE_JSON;
  if (typeof source !== 'string' || !source.trim() || Buffer.byteLength(source, 'utf8') > maxProfileBytes) {
    throw new Error('Public Hub profile must be non-empty JSON no larger than 64 KiB.');
  }
  let input;
  // JSON.parse errors can include input excerpts. Never log CI profile contents.
  try { input = JSON.parse(source); }
  catch { throw new Error('Public Hub profile is not valid JSON.'); }
  if (!input || typeof input !== 'object' || Array.isArray(input)
    || Object.keys(input).some(key => !publicFields.has(key))) {
    throw new Error('Public Hub profile allows only version, hubUrl, certificatePem and label; credentials and private keys are forbidden.');
  }
  const profile = validateProfile(input);
  return { version: 1, hubUrl: profile.hubUrl, certificatePem: profile.certificatePem,
    ...(profile.label === undefined ? {} : { label: profile.label }) };
}
