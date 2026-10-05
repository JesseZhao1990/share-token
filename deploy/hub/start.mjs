import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { createHub } from '../../dist/apps/hub/index.js';
import { readSecret, writePrivate } from '../../dist/apps/cli/files.js';
import { loadSharedCodeVerifier, normalizeSharedCode, saveSharedCodeVerifier } from '../../dist/packages/storage/shared-code.js';

/** Called while entrypoint.sh holds the exclusive volume lock. */
export async function prepareData(dataDir, sharedCodeFile = process.env.HUB_SHARED_CODE_FILE) {
  const directory = resolve(dataDir);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const directoryStat = await lstat(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink() || (process.getuid && directoryStat.uid !== process.getuid())) {
    throw new Error('Hub data directory must be an owned, regular directory.');
  }
  await chmod(directory, 0o700);
  const tokenPath = join(directory, 'admin.token');
  let token;
  try { token = await readSecret(tokenPath); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    // Missing credentials next to an existing ledger indicate a partial restore.
    // Avoid silently changing the administrator credential of an existing Hub.
    try { await lstat(join(directory, 'hub.sqlite')); throw new Error('Existing database is missing admin.token; restore the full backup.'); }
    catch (databaseError) { if (databaseError.code !== 'ENOENT') throw databaseError; }
    token = `st_admin_${randomBytes(32).toString('base64url')}`;
    await writePrivate(tokenPath, token + '\n');
    console.log('Initialized administrator credential in the persistent data directory.');
  }
  const verifierPath = join(directory, 'shared-code.json');
  if (sharedCodeFile) {
    // Compose's file-backed secrets can be 0444 and owned by root, so validate
    // this read-only input as a bounded regular file rather than a local token.
    const file = await open(sharedCodeFile, constants.O_RDONLY | constants.O_NOFOLLOW);
    let code;
    try {
      const stat = await file.stat();
      if (!stat.isFile() || stat.size > 128) throw new Error('Shared-code input must be a regular file of at most 128 bytes.');
      code = normalizeSharedCode(await file.readFile('utf8'));
      if (!code) throw new Error('Shared-code input must contain exactly eight digits.');
    } finally { await file.close(); }
    const verifier = await loadSharedCodeVerifier(verifierPath);
    if (!verifier) {
      await saveSharedCodeVerifier(verifierPath, code);
      console.log('Initialized optional shared-code verifier; the plaintext code is not persisted.');
    }
    // Restart never rotates a stored verifier. Rotation is an explicit command.
  }
  const databasePath = join(directory, 'hub.sqlite');
  try {
    const stat = await lstat(databasePath);
    if (!stat.isFile() || stat.isSymbolicLink() || (process.getuid && stat.uid !== process.getuid())) throw new Error('Hub database must be an owned regular file.');
    const db = new DatabaseSync(databasePath);
    try {
      db.exec('PRAGMA busy_timeout=5000');
      if (db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='hub_runtime'").get()) db.exec('DELETE FROM hub_runtime');
    } finally { db.close(); }
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  return { dbPath: databasePath, adminToken: token, sharedCodePath: verifierPath };
}

async function main() {
  process.umask(0o077);
  const options = await prepareData(process.env.HUB_DATA_DIR ?? '/data');
  const hub = await createHub({ ...options, host: '0.0.0.0', port: 4387, staticDir: resolve('dist/web') });
  console.log('Share Token Hub listening on the internal port 4387.');
  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    const forceExit = setTimeout(() => process.exit(1), 25_000);
    forceExit.unref();
    try { await hub.close(); clearTimeout(forceExit); }
    catch { process.exitCode = 1; }
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => { console.error('Hub initialization failed. Check data ownership, secret input and complete backup files.'); process.exitCode = 1; });
}
