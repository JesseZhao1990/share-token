import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants, type Stats } from 'node:fs';
import { lstat, mkdir, open, type FileHandle } from 'node:fs/promises';
import { join, parse, resolve, sep } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import type { SecretCipher } from './private-store.js';

export const LOCAL_SECRET_KEY_FILENAME = 'local-secret.key';
const KEY_MAGIC = Buffer.from([0x53, 0x54, 0x4c, 0x4b, 1]); // STLK, format version 1.
const CIPHER_MAGIC = Buffer.from([0x53, 0x54, 0x4c, 0x45, 1]); // STLE, format version 1.
const KEY_BYTES = 32, IV_BYTES = 12, TAG_BYTES = 16;
const KEY_RECORD_BYTES = KEY_MAGIC.length + KEY_BYTES + 32;
const CIPHER_HEADER_BYTES = CIPHER_MAGIC.length + IV_BYTES + TAG_BYTES;

function failure(code: string, message: string): Error & { code: string } { return Object.assign(new Error(message), { code }); }
const unsafePath = () => failure('LOCAL_SECRET_PATH_UNSAFE', '本机登录信息目录或密钥文件的权限不正确，请使用当前用户专用的安全目录。');
const damagedKey = () => failure('LOCAL_SECRET_KEY_INVALID', '本机登录信息密钥损坏，已停止读取；原文件不会被覆盖。');
const damagedCiphertext = () => failure('LOCAL_SECRET_DECRYPT_FAILED', '本机登录信息无法解密或已损坏，请重新连接。');
const isOwned = (stat: Stats) => !process.getuid || stat.uid === process.getuid();
const modeIs = (stat: Stats, mode: number) => process.platform === 'win32' || (stat.mode & 0o777) === mode;
const sameFile = (first: Stats, second: Stats) => first.ino === second.ino && first.dev === second.dev;

/** Parent paths must already be canonical (e.g. realpath macOS /var before appending a directory). */
async function privateDirectory(directory: string): Promise<{ path: string; handle: FileHandle; stat: Stats }> {
  const path = resolve(directory), root = parse(path).root;
  if (path === root) throw unsafePath();
  let current = root;
  for (const part of path.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, part);
    try { await mkdir(current, { mode: 0o700 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    const entry = await lstat(current);
    if (entry.isSymbolicLink() || !entry.isDirectory()) throw unsafePath();
  }
  const before = await lstat(path);
  if (!isOwned(before) || !modeIs(before, 0o700)) throw unsafePath();
  let handle: FileHandle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); }
  catch { throw unsafePath(); }
  const stat = await handle.stat();
  if (!sameFile(before, stat) || !stat.isDirectory() || !isOwned(stat) || !modeIs(stat, 0o700)) { await handle.close(); throw unsafePath(); }
  return { path, handle, stat };
}

function keyRecord(key: Buffer): Buffer {
  const prefix = Buffer.concat([KEY_MAGIC, key]);
  return Buffer.concat([prefix, createHash('sha256').update(prefix).digest()]);
}
function decodeKey(record: Buffer): Buffer {
  if (record.length !== KEY_RECORD_BYTES || !record.subarray(0, KEY_MAGIC.length).equals(KEY_MAGIC)) throw damagedKey();
  const prefix = record.subarray(0, KEY_MAGIC.length + KEY_BYTES);
  if (!timingSafeEqual(createHash('sha256').update(prefix).digest(), record.subarray(prefix.length))) throw damagedKey();
  return Buffer.from(record.subarray(KEY_MAGIC.length, prefix.length));
}
async function readKey(path: string): Promise<Buffer> {
  // O_EXCL publishes the filename before its creator finishes the first write. Concurrent
  // readers wait only for that short write; an invalid existing key is never regenerated.
  for (let attempt = 0; attempt < 40; attempt++) {
    let file: FileHandle;
    try { file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW); }
    catch { throw unsafePath(); }
    let incomplete = false;
    try {
      const stat = await file.stat();
      if (!stat.isFile() || !isOwned(stat) || !modeIs(stat, 0o600) || stat.nlink !== 1) throw unsafePath();
      incomplete = stat.size < KEY_RECORD_BYTES;
      if (stat.size > KEY_RECORD_BYTES) throw damagedKey();
      if (!incomplete) {
        const record = Buffer.alloc(KEY_RECORD_BYTES + 1);
        const { bytesRead } = await file.read(record, 0, record.length, 0);
        if (bytesRead !== KEY_RECORD_BYTES) throw damagedKey();
        return decodeKey(record.subarray(0, bytesRead));
      }
    } finally { await file.close(); }
    if (incomplete && attempt < 39) await delay(25);
  }
  throw damagedKey();
}

export function isLocalSecretCiphertext(value: Buffer): boolean {
  return value.length >= CIPHER_HEADER_BYTES && value.subarray(0, CIPHER_MAGIC.length).equals(CIPHER_MAGIC);
}

/**
 * Encrypts application credentials without invoking a system keychain. The key and ciphertext
 * are protected by this user's filesystem permissions; this does not isolate same-user processes.
 */
export async function createLocalSecretCipher(directory: string): Promise<SecretCipher> {
  const dir = await privateDirectory(directory);
  let key: Buffer;
  try {
    const keyPath = join(dir.path, LOCAL_SECRET_KEY_FILENAME);
    let created: FileHandle | undefined;
    try { created = await open(keyPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw unsafePath(); }
    if (created) {
      try { await created.writeFile(keyRecord(randomBytes(KEY_BYTES))); await created.sync(); }
      finally { await created.close(); }
      await dir.handle.sync();
    }
    key = await readKey(keyPath);
    const after = await lstat(dir.path);
    if (after.isSymbolicLink() || !after.isDirectory() || !sameFile(dir.stat, after) || !isOwned(after) || !modeIs(after, 0o700)) { key.fill(0); throw unsafePath(); }
  } finally { await dir.handle.close(); }
  return {
    available: () => true,
    encrypt(value: string): Buffer {
      const iv = randomBytes(IV_BYTES), cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(CIPHER_MAGIC);
      const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
      return Buffer.concat([CIPHER_MAGIC, iv, cipher.getAuthTag(), ciphertext]);
    },
    decrypt(value: Buffer): string {
      if (!isLocalSecretCiphertext(value)) throw damagedCiphertext();
      try {
        const ivEnd = CIPHER_MAGIC.length + IV_BYTES, tagEnd = ivEnd + TAG_BYTES;
        const decipher = createDecipheriv('aes-256-gcm', key, value.subarray(CIPHER_MAGIC.length, ivEnd));
        decipher.setAAD(CIPHER_MAGIC); decipher.setAuthTag(value.subarray(ivEnd, tagEnd));
        return Buffer.concat([decipher.update(value.subarray(tagEnd)), decipher.final()]).toString('utf8');
      } catch { throw damagedCiphertext(); }
    },
  };
}
