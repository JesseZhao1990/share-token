export const REPOSITORY = 'JesseZhao1990/share-token';
export const RELEASES_URL = `https://github.com/${REPOSITORY}/releases`;
export const RELEASE_API = `https://api.github.com/repos/${REPOSITORY}/releases?per_page=20`;

function publicAssetUrl(asset, tag, name) {
  if (!asset || asset.name !== name || !Number.isSafeInteger(asset.size) || asset.size <= 0) throw new Error('Missing public release asset.');
  const expected = `https://github.com/${REPOSITORY}/releases/download/${tag}/${name}`;
  if (asset.browser_download_url !== expected) throw new Error('Unexpected release download origin or path.');
  return expected;
}

export function parsePublicRelease(release) {
  if (!release || release.draft !== false || typeof release.prerelease !== 'boolean'
    || !/^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/.test(release.tag_name ?? '')
    || !Array.isArray(release.assets) || typeof release.published_at !== 'string'
    || !Number.isFinite(Date.parse(release.published_at))) throw new Error('Invalid public release identity.');
  const tag = release.tag_name;
  if (release.html_url !== `${RELEASES_URL}/tag/${tag}`) throw new Error('Unexpected release page.');
  const archiveName = `Share-Token-${tag.slice(1)}-macOS-arm64-preview.zip`;
  const find = name => {
    const matches = release.assets.filter(asset => asset?.name === name);
    if (matches.length !== 1) throw new Error('Missing or ambiguous public release asset.');
    return matches[0];
  };
  const archive = find(archiveName);
  return {
    version: tag.slice(1), tag, prerelease: release.prerelease, publishedAt: release.published_at,
    pageUrl: release.html_url, size: archive.size,
    downloadUrl: publicAssetUrl(archive, tag, archiveName),
    checksumUrl: publicAssetUrl(find(archiveName + '.sha256'), tag, archiveName + '.sha256'),
    manifestUrl: publicAssetUrl(find('release-manifest.json'), tag, 'release-manifest.json'),
  };
}

export async function loadPublicRelease(fetcher = globalThis.fetch.bind(globalThis), timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetcher(RELEASE_API, { headers: { Accept: 'application/vnd.github+json' }, credentials: 'omit', cache: 'no-store', signal: controller.signal });
    if (response.status === 404) return { status: 'unavailable' };
    if (!response.ok) throw new Error('Public release API is unavailable.');
    const releases = await response.json();
    if (!Array.isArray(releases)) throw new Error('Invalid public release list.');
    if (releases.length === 0) return { status: 'unavailable' };
    const candidates = releases.filter(release => release?.draft === false)
      .sort((a, b) => Date.parse(b.published_at) - Date.parse(a.published_at));
    for (const release of candidates) {
      try { return { status: 'available', release: parsePublicRelease(release) }; }
      catch { /* A release for another platform or without verified assets is not a preview download. */ }
    }
    return { status: 'unavailable' };
  } catch { return { status: 'unknown' }; }
  finally { clearTimeout(timer); }
}
