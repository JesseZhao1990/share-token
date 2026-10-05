import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { RELEASE_API, REPOSITORY, parsePublicRelease, loadPublicRelease } from '../website/releases.js';

function fixture(version = '0.1.0', publishedAt = '2026-10-05T01:00:00Z') {
  const tag = `v${version}`;
  const zip = `Share-Token-${version}-macOS-arm64-preview.zip`;
  return {
    tag_name: tag, draft: false, prerelease: true, published_at: publishedAt,
    html_url: `https://github.com/${REPOSITORY}/releases/tag/${tag}`,
    assets: [zip, zip + '.sha256', 'release-manifest.json'].map(name => ({ name, size: name === zip ? 160_000_000 : 1024,
      browser_download_url: `https://github.com/${REPOSITORY}/releases/download/${tag}/${name}` })),
  };
}

test('website admits published preview assets only from the exact public repository', () => {
  const release = fixture();
  assert.equal(parsePublicRelease(release).version, '0.1.0');
  assert.equal(parsePublicRelease(release).prerelease, true);
  assert.throws(() => parsePublicRelease({ ...release, draft: true }), /release identity/);
  assert.throws(() => parsePublicRelease({ ...release, html_url: 'https://example.invalid/releases/tag/v0.1.0' }), /release page/);
  assert.throws(() => parsePublicRelease({ ...release, assets: release.assets.slice(0, 1) }), /Missing or ambiguous/);
  const differentOrigin = structuredClone(release);
  differentOrigin.assets[0].browser_download_url = 'https://example.invalid/preview.zip';
  assert.throws(() => parsePublicRelease(differentOrigin), /origin or path/);
});

test('private repositories and empty public release lists show no claimed download', async () => {
  assert.deepEqual(await loadPublicRelease(async () => new Response(null, { status: 404 })), { status: 'unavailable' });
  assert.deepEqual(await loadPublicRelease(async () => Response.json([])), { status: 'unavailable' });
  assert.deepEqual(await loadPublicRelease(async () => Response.json([ { ...fixture(), draft: true } ])), { status: 'unavailable' });
  assert.deepEqual(await loadPublicRelease(async () => new Response(null, { status: 403 })), { status: 'unknown' });
  assert.deepEqual(await loadPublicRelease(async () => { throw new Error('Offline fixture'); }), { status: 'unknown' });
});

test('release lookup includes previews and respects publication time instead of version ordering', async () => {
  let observed;
  const result = await loadPublicRelease(async (url, options) => {
    observed = { url, options };
    return Response.json([fixture('0.2.0', '2026-10-04T01:00:00Z'), fixture('0.1.0', '2026-10-05T01:00:00Z')]);
  });
  assert.equal(observed.url, RELEASE_API);
  assert.equal(observed.options.credentials, 'omit');
  assert.equal(result.status, 'available');
  assert.equal(result.release.version, '0.1.0');
});

test('incomplete published releases do not advertise an unconfirmed fallback ZIP', async () => {
  const result = await loadPublicRelease(async () => Response.json([{ ...fixture(), assets: [] }]));
  assert.deepEqual(result, { status: 'unavailable' });
  const markup = await readFile(new URL('../website/index.html', import.meta.url), 'utf8');
  assert.match(markup, /lang="en"/);
  assert.match(markup, /Apple/);
  assert.doesNotMatch(markup, /href="[^"]+\.zip"/);
});
