import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID, timingSafeEqual, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { validateHubTrustProfile, type HubTrustProfile } from '../../../packages/hub-client/trust.js';

const MAX_PROFILE_BYTES = 64 * 1024;
export interface HubTrustDisplay { hubUrl: string; label?: string; fingerprint256: string; validTo: string }

function cleanProfile(input: unknown): HubTrustProfile {
  const value = validateHubTrustProfile(input);
  return { version: 1, hubUrl: value.hubUrl, certificatePem: value.certificatePem, ...(value.label ? { label: value.label } : {}) };
}

/** Reads only a selected regular file, with a bounded read and no symlink following. */
export async function readHubTrustFile(path: string): Promise<HubTrustProfile> {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.size > MAX_PROFILE_BYTES) throw new Error('连接文件必须是小于 64 KB 的普通 JSON 文件，不能是符号链接。');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await file.stat();
    if (!opened.isFile() || before.ino !== opened.ino || before.dev !== opened.dev || opened.size > MAX_PROFILE_BYTES) throw new Error('读取期间连接文件发生变化，请重新选择。');
    const bytes = Buffer.alloc(MAX_PROFILE_BYTES + 1);
    let offset = 0;
    while (offset < bytes.length) { const read = await file.read(bytes, offset, bytes.length - offset, null); if (!read.bytesRead) break; offset += read.bytesRead; }
    if (offset > MAX_PROFILE_BYTES) throw new Error('连接文件超过 64 KB。');
    const after = await file.stat();
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) throw new Error('读取期间连接文件发生变化，请重新选择。');
    return cleanProfile(JSON.parse(bytes.subarray(0, offset).toString('utf8')));
  } finally { await file.close(); }
}

async function profileDirectory(userData: string): Promise<string> {
  const root = await lstat(userData);
  if (!root.isDirectory() || root.isSymbolicLink()) throw new Error('应用数据目录不能是符号链接。');
  const path = join(userData, 'hub-trust');
  await mkdir(path, { mode: 0o700 }).catch(error => { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; });
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (process.getuid && stat.uid !== process.getuid()) || (stat.mode & 0o077) !== 0) throw new Error('应用连接目录的所有者或权限无效。');
  return path;
}

export async function loadHubTrustProfile(userData: string): Promise<HubTrustProfile | null> {
  const directory = await profileDirectory(userData);
  const path = join(directory, 'connection.json');
  let stat;
  try { stat = await lstat(path); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
  if ((process.getuid && stat.uid !== process.getuid()) || (stat.mode & 0o077) !== 0) throw new Error('保存的连接文件权限无效。');
  return readHubTrustFile(path);
}

export async function saveHubTrustProfile(userData: string, input: unknown): Promise<HubTrustProfile> {
  const profile = cleanProfile(input);
  const directory = await profileDirectory(userData);
  const path = join(directory, 'connection.json');
  try { const stat = await lstat(path); if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('保存的连接文件不能是符号链接。'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  const temporary = join(directory, `.${randomUUID()}.tmp`);
  try {
    const file = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await file.writeFile(JSON.stringify(profile, null, 2) + '\n', 'utf8'); await file.sync(); } finally { await file.close(); }
    await rename(temporary, path);
    return (await loadHubTrustProfile(userData))!;
  } finally { await rm(temporary, { force: true }); }
}

export function hubTrustDisplay(profile: HubTrustProfile): HubTrustDisplay {
  const certificate = new X509Certificate(profile.certificatePem);
  return { hubUrl: profile.hubUrl, label: profile.label, fingerprint256: certificate.fingerprint256, validTo: certificate.validTo };
}

export function assertSavedHubTrust(hubUrl: string, requiredFingerprint: string | null | undefined, profile: HubTrustProfile | null): void {
  if (!requiredFingerprint) return;
  if (!profile || validateHubTrustProfile(profile).hubUrl !== new URL(hubUrl).origin || hubTrustDisplay(profile).fingerprint256 !== requiredFingerprint) throw new Error('上次配对使用的连接证书缺失或已改变，请重新导入原连接文件并配对。');
}

/** Chromium's certificate callback has no port field; the isolated session also
 * enforces the exact origin and port for every network request below. */
export function acceptsHubCertificate(profile: HubTrustProfile, hostname: string, pem: string): boolean {
  try {
    validateHubTrustProfile(profile);
    const expected = new X509Certificate(profile.certificatePem), peer = new X509Certificate(pem);
    const target = new URL(profile.hubUrl).hostname.replace(/^\[|\]$/g, '');
    if (hostname !== target || peer.raw.length !== expected.raw.length || !timingSafeEqual(peer.raw, expected.raw)) return false;
    if (Date.now() < Date.parse(peer.validFrom) || Date.now() >= Date.parse(peer.validTo)) return false;
    return isIP(target) ? peer.checkIP(target) === target : peer.checkHost(target, { subject: 'never' }) !== undefined;
  } catch { return false; }
}

export function acceptsHubUrl(profile: HubTrustProfile, input: string, allowWebSocket = false): boolean {
  try {
    validateHubTrustProfile(profile);
    const url = new URL(input);
    if (url.username || url.password) return false;
    if (allowWebSocket && url.protocol === 'wss:') url.protocol = 'https:';
    return url.protocol === 'https:' && url.origin === profile.hubUrl;
  } catch { return false; }
}
