import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';

export interface SecretCipher { available(): boolean; encrypt(value: string): Buffer; decrypt(value: Buffer): string }

/** The caller supplies an encrypted store; plaintext fallback is never allowed. */
export class PrivateStore {
  constructor(private path: string, private cipher: SecretCipher) {}
  async read<T>(): Promise<T | null> {
    let bytes: Buffer;
    try { bytes = await readFile(this.path); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
    if (!this.cipher.available()) throw new Error('本机凭据存储不可用，请检查应用数据目录。');
    return JSON.parse(this.cipher.decrypt(bytes)) as T;
  }
  async write(value: unknown): Promise<void> {
    if (!this.cipher.available()) throw new Error('本机凭据存储不可用，登录信息未保存。');
    const encrypted = this.cipher.encrypt(JSON.stringify(value));
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const temporary = `${this.path}.${randomUUID()}.tmp`;
    try { await writeFile(temporary, encrypted, { mode: 0o600, flag: 'wx' }); await rename(temporary, this.path); }
    finally { await rm(temporary, { force: true }); }
  }
  async clear(): Promise<void> { await rm(this.path, { force: true }); }
}
