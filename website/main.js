import { loadPublicRelease } from './releases.js';

const status = document.querySelector('#release-status');
const detail = document.querySelector('#release-detail');
const assets = document.querySelector('#release-assets');
const result = await loadPublicRelease();
if (result.status === 'available') {
  const release = result.release;
  status.textContent = `公开${release.prerelease ? '预览' : '发布'}版本 ${release.tag} · macOS Apple Silicon`;
  detail.textContent = `Public ${release.prerelease ? 'preview' : 'release'} · ${(release.size / 1_000_000).toFixed(1)} MB · ${release.publishedAt.slice(0, 10)} · 已确认发布身份与附件存在；下载后请校验 SHA-256 / Release identity and attachments checked; verify the downloaded SHA-256.`;
  for (const [label, url, kind] of [
    ['下载 ZIP / Download', release.downloadUrl, 'primary'],
    ['SHA-256 校验文件', release.checksumUrl, 'secondary'],
    ['发布清单 / Manifest', release.manifestUrl, 'secondary'],
  ]) {
    const link = document.createElement('a');
    link.textContent = label;
    link.href = url;
    link.className = `button ${kind}`;
    link.rel = 'noopener noreferrer';
    assets.append(link);
  }
  assets.hidden = false;
} else if (result.status === 'unavailable') {
  status.textContent = '暂无可确认的公开安装包 / No public preview confirmed';
  detail.textContent = '仓库尚未公开，或尚无包含 ZIP、校验文件和清单的公开发布。可先查看源码；此页面不会提供未经确认的下载链接。 / The repository may not be public yet, or no complete preview release is available.';
} else {
  status.textContent = '暂时无法确认发布状态 / Release status unavailable';
  detail.textContent = '网络或 GitHub 查询失败，请打开发布页查看。 / The release check failed; visit GitHub releases to verify availability.';
}
