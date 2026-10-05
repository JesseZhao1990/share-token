import test from 'node:test';
import assert from 'node:assert/strict';
import { runTestOpenSSL } from './fixtures/openssl.js';

test('TLS fixture configuration rejects an explicitly selected non-OpenSSL executable without silently falling back', t => {
  const original = process.env.SHARE_TOKEN_TEST_OPENSSL;
  t.after(() => {
    if (original === undefined) delete process.env.SHARE_TOKEN_TEST_OPENSSL;
    else process.env.SHARE_TOKEN_TEST_OPENSSL = original;
  });
  process.env.SHARE_TOKEN_TEST_OPENSSL = process.execPath;
  assert.throws(() => runTestOpenSSL(['version']), /TLS fixtures require OpenSSL 3 or newer.*SHARE_TOKEN_TEST_OPENSSL/);
});
