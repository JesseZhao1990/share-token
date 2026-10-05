import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { link, mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { ShareError } from '../protocol/index.js';

export interface SharedCodeVerifier { version: 1; salt: string; hash: string }
const invalidFile = () => new ShareError('SHARE_SHARED_CODE_CONFIG_INVALID', '配对码配置必须是当前用户所有、权限为 0600 的有效文件。', 500);
const derive = (code: string, salt: string) => scryptSync(code, Buffer.from(salt, 'hex'), 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
export function normalizeSharedCode(value: string): string | null {
  if (value.length > 128) return null;
  const code = value.replace(/[\s-]/g, '');
  return /^\d{8}$/.test(code) ? code : null;
}
export function createSharedCodeVerifier(value: string): SharedCodeVerifier {
  const code = normalizeSharedCode(value);
  if (!code) throw new ShareError('SHARE_SHARED_CODE_INVALID', '配对码需要 8 位数字。');
  const salt = randomBytes(16).toString('hex');
  return { version: 1, salt, hash: derive(code, salt).toString('hex') };
}
export function matchesSharedCode(value: string, verifier: SharedCodeVerifier): boolean {
  const code = normalizeSharedCode(value);
  return code !== null && timingSafeEqual(derive(code, verifier.salt), Buffer.from(verifier.hash, 'hex'));
}
export async function readPrivateSharedCodeFile(path: string): Promise<string> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > 4096 || (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) || (process.getuid && stat.uid !== process.getuid())) throw invalidFile();
    return await file.readFile('utf8');
  } finally { await file.close(); }
}
export async function loadSharedCodeVerifier(path?: string): Promise<SharedCodeVerifier | null> {
  if (!path) return null;
  let raw: string;
  try { raw = await readPrivateSharedCodeFile(path); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw invalidFile(); }
  let value: unknown; try { value = JSON.parse(raw); } catch { throw invalidFile(); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalidFile();
  const record = value as Record<string, unknown>;
  if (record.version !== 1 || typeof record.salt !== 'string' || !/^[0-9a-f]{32}$/.test(record.salt) || typeof record.hash !== 'string' || !/^[0-9a-f]{64}$/.test(record.hash) || Object.keys(record).some(key => !['version', 'salt', 'hash'].includes(key))) throw invalidFile();
  return { version: 1, salt: record.salt, hash: record.hash };
}
/** Atomic administration-only replacement. Only a salted verifier is persisted. */
export async function saveSharedCodeVerifier(path: string, code: string, rotate = false): Promise<void> {
  const value = createSharedCodeVerifier(code);
  if (rotate && !await loadSharedCodeVerifier(path)) throw new ShareError('SHARE_SHARED_CODE_NOT_CONFIGURED', '尚未配置配对码，请先执行 shared-code set。');
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomBytes(12).toString('hex')}.tmp`;
  const file = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(JSON.stringify(value) + '\n'); await file.sync(); } finally { await file.close(); }
  try {
    if (rotate) await rename(temporary, path);
    else await link(temporary, path); // Fails if already configured; never overwrites on set.
  } finally { await unlink(temporary).catch(error => { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }); }
}
