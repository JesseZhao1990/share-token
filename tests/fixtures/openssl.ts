import { execFileSync } from 'node:child_process';

let selected: { configured: string | undefined; binary: string } | undefined;

/** Keep generated TLS fixtures independent from macOS's system LibreSSL. */
function fixtureOpenSSL(): string {
  const explicit = process.env.SHARE_TOKEN_TEST_OPENSSL;
  if (selected && selected.configured === explicit) return selected.binary;
  const candidates = explicit ? [explicit] : [
    'openssl',
    ...(process.platform === 'darwin' ? ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl'] : []),
  ];
  for (const binary of candidates) {
    try {
      const version = execFileSync(binary, ['version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
      const match = /^OpenSSL\s+(\d+)\./.exec(version.trim());
      if (match && Number(match[1]) >= 3) { selected = { configured: explicit, binary }; return binary; }
    } catch { /* Try the next explicit modern OpenSSL location. */ }
  }
  throw new Error('TLS fixtures require OpenSSL 3 or newer. Set SHARE_TOKEN_TEST_OPENSSL to its executable path or add it to PATH. On macOS, install Homebrew openssl@3.');
}

export function runTestOpenSSL(args: readonly string[]): void {
  execFileSync(fixtureOpenSSL(), args, { stdio: 'ignore', timeout: 30_000 });
}
