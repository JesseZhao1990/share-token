import { open, mkdir, lstat, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname } from 'node:path';
import { ShareError } from '../../packages/protocol/index.js';

export async function writePrivate(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(value, 'utf8'); await file.sync(); } finally { await file.close(); }
}
export async function readSecret(path: string): Promise<string> {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)) {
    throw new ShareError('SHARE_SECRET_PERMISSIONS', '凭据文件必须是当前用户保护的普通文件（权限 0600）。');
  }
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const actual = await file.stat();
    if (!actual.isFile() || actual.ino !== stat.ino || actual.dev !== stat.dev || actual.size > 4096 || (process.platform !== 'win32' && (actual.mode & 0o077) !== 0) || (process.getuid && actual.uid !== process.getuid())) throw new ShareError('SHARE_SECRET_PERMISSIONS', '凭据文件所有者或文件状态不匹配。');
    const value = (await file.readFile('utf8')).trim();
    if (value.length < 24 || value.length > 512 || /\s/.test(value)) throw new ShareError('SHARE_SECRET_INVALID', '凭据文件内容无效。');
    return value;
  } finally { await file.close(); }
}
export async function readJsonFile(path: string): Promise<unknown> { return JSON.parse(await readFile(path, 'utf8')) as unknown; }
