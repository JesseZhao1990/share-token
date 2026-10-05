# Public builds and releases

This repository uses public npm packages, standard GitHub-hosted runners, and GitHub Releases. All routine checks use mock adapters. No live model account, shared space, device credential, or upstream login belongs in CI.

## A reviewed preview release

1. Complete the source audit and mock checks on the final commit. Keep `package.json` and the root lock-file package version equal.
2. Set the new package version before committing. Create and push an immutable tag `v<package.json version>` only after review. The workflow also supports a manually selected existing tag.
3. The draft workflow checks the tag against the actual checkout, builds a **generic macOS Apple Silicon ZIP**, then extracts that exact archive and verifies signatures, Node/PTY execution, and an isolated Electron launch.
4. It stages only the ZIP, SHA-256 file, redacted `release-manifest.json`, and license notices. Detailed local reports, temporary paths, screenshots, and app data are not uploaded as public assets.
5. Review the resulting **draft prerelease** in GitHub. Download it, compare the manifest and SHA-256, and test installation on another Mac. Publishing the draft is a separate manual action. A workflow run alone is not a public release.

The package is **ad-hoc signed and not Apple-notarized**. No Developer ID certificate or Apple account is used in the workflow. Gatekeeper may reject the preview. Keep that status in the release notes and website until a separate personal Developer ID signing and notarization flow has been implemented and validated.

The public app has bundle ID `io.github.jessezhao1990.sharetoken`; the display name is `共享token` and its executable remains `Share Token`. The generic build embeds no Hub address or certificate. Use a trusted HTTPS domain in advanced connection options. The optional private certificate profile remains limited to RFC1918 IPv4; do not embed a public domain into that profile format.

The standard `macos-14` runner is listed as Apple Silicon in [GitHub’s runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). The workflow independently asserts the actual runtime architecture before packaging. Runner availability and billing depend on the account and repository visibility; review GitHub’s current terms before running CI.

## Local preview verification

On a personal Apple Silicon Mac with Node 24, install from the public npm registry and generate dependency notices:

```bash
npm ci --registry=https://registry.npmjs.org
npm run licenses:generate
npm run typecheck
npm test
npm run test:website
npm run audit:public
npm run desktop:package
npm run verify:desktop-release
npm run release:prepare
```

Outputs are under `artifacts/desktop/` and the upload allowlist is `artifacts/release/`. `release:prepare` refuses a modified archive, absent final-ZIP verification, or a preconfigured space. For a tagged local build, set `RELEASE_TAG=v<version>`; the tag must already identify the current commit. Do not place runtime data in the release directory.

The mock checks do not establish real upstream compatibility, long-running behavior, or installation acceptance on another Mac. Real upstream tests require a separately authorized account and should stay outside CI.

## Static website

`website/` is a standalone, dependency-free static site with Chinese and English introductions. It needs no npm install or build step. Upload the directory directly to a static host such as Cloudflare Pages, or serve its files through GitHub Pages. With a Git-connected Cloudflare Pages project, leave the build command empty and set the output directory to `website`.

The site queries the public GitHub releases API for `JesseZhao1990/share-token`, including published previews. It shows a download only when a published release contains the exact ZIP, checksum, and manifest links from that repository. A private or missing repository, no public release, incomplete assets, API limits, and an offline check produce explicit unavailable/unknown states. Draft releases stay invisible to anonymous visitors. The source repository’s intended URL does not prove that it is already public.

The website links to the integrity files; it does not download and independently validate every ZIP in the browser. `_headers` provides Cloudflare Pages response headers and is ignored by hosts that do not support that file. Deploying this website does not deploy the Hub: HTTPS/WSS forwarding, authorization, and persistent Hub data require a separately hosted server.

## GitHub Pages 官网

仓库同时提供 `.github/workflows/pages.yml`，仅部署 `website/` 静态目录，不包含 Hub、凭据、运行状态或安装包。个人仓库公开后，在 Settings → Pages 选择 GitHub Actions；推送官网修改或手动运行 Public website 即可部署。默认网址为 `https://jessezhao1990.github.io/share-token/`。Cloudflare Pages 也可直接部署同一目录。

官网通过匿名 GitHub API 核验版本和资产的所属仓库、标签、名称和完整性文件存在性。页面提供清单与 SHA-256 文件，用户下载后应校验实际 ZIP；页面不声称已对浏览器下载的所有字节计算过哈希。
