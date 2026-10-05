# 开发指南

使用 Node.js 24、npm 与公共依赖源。仓库 `.npmrc` 只设置公共 registry 和运行时检查；不要向它添加认证令牌。

```sh
npm ci
npm run typecheck
npm test
npm run build
npm run dev
```

安装会准备独立 Node 24、Electron 和 PTY helper。Hub 容器构建使用更小的白名单运行闭包，参见自建指南。CI 不登录模型账户、不调用真实模型。

桌面开发需要图形环境；当前打包范围为 macOS arm64：

```sh
npm run desktop
npm run desktop:package
npm run verify:desktop-release
```

通用包不携带部署配置。公网 Hub 使用有效公信证书并手动填写 HTTPS 根地址；私网自签证书连接文件必须匹配完整来源和精确证书。现有私网连接文件不能直接改成公网域名文件。

检查与证据分层：

1. 单元和模拟集成：`npm test`，不产生真实模型调用。
2. 编译与构建：`npm run typecheck`、`npm run build`。
3. 源码公开审计：`npm run audit:public`，检查公司入口、禁入文件和高置信度凭据特征。
4. Hub 初始化、模拟转发与重启：`npm run hub:deployment:check`。
5. 容器生命周期：`npm run hub:container:smoke`，需要运行中的 Docker。
6. 最终桌面 ZIP：`npm run verify:desktop-release`，需要 macOS arm64 图形环境。

真实推理、原生完整工具循环、长上下文、长期网络表现和其他客户端是独立验收项。默认关闭的实验订阅适配不得因单元测试通过而宣称获准使用。

运行目录、认证文件、数据库、证书私钥、日志和证据仅留在本机。`artifacts/` 保存安装包及检查报告，源码仓库不收录这些文件。

TLS mock tests require OpenSSL 3 or newer. On macOS, install the public Homebrew `openssl@3` package; the test fixtures also accept an explicit `SHARE_TOKEN_TEST_OPENSSL` binary path. CI records the selected public tool version and does not use real certificates or accounts.
