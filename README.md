# 余量 · Share Token

一个可以自行部署的推理网关与本机 Codex 接入工具。Hub 管理成员、授权、固定来源路由与请求状态；Consumer Bridge 和 Relay 分别在使用方和提供方电脑运行，本地工具仍由使用方执行。

**开源首版 0.1.0 默认运行模拟环境。** 模拟模型返回合成结果，不调用真实模型，也不能完成真实编程任务。个人订阅共享属于默认关闭的实验适配；现有 HTTP API 适配器仅供对照测试，尚未作为生产 API 产品验收。

[官网](https://jessezhao1990.github.io/share-token/) · [English](docs/README.en.md) · [自建 Hub](docs/SELF_HOSTING.md) · [开发指南](docs/DEVELOPMENT.md) · [发行流程](docs/RELEASING.md) · [安全边界](SECURITY.md)

## 本地快速开始

需要 Node.js **24 LTS** 和 npm。依赖从公共 npm 获取；不需要公司网络、私有镜像或真实模型账户。

```sh
npm ci
npm run build
npm run dev
```

打开终端显示的本机管理地址（默认 `http://127.0.0.1:4387`），使用本次生成的 `admin.token` 文件登录。每次演示使用独立的 `.share-token/demo-*` 数据目录；凭据保存在本机，不要提交或分享。

另开终端启动桌面界面：

```sh
npm run desktop
```

桌面连接自己的 Hub 地址，再完成设备配对和提供方授权。源码与公共预览包不预设作者运营的 Hub，也不内置配对码、证书私钥或访问凭据。

## 架构与数据

```text
使用方电脑                         自建 Hub                    提供方电脑
Codex CLI → Consumer Bridge → HTTPS 授权与调度 → WSS Relay → 获准的上游
本地项目、终端与工具               SQLite 元数据              本地策略与凭据
```

跨电脑通信需要双方可访问的 HTTPS/WSS Hub。静态官网只提供介绍、文档与下载入口；提供方电脑和 Relay 必须在线。Hub 与 Relay 会在内存中处理请求和响应正文，当前传输不是端到端加密。

设备身份和来源授权彼此独立。同空间配对不会自动开放推理；每个授权固定来源。未知结果进入 `UNKNOWN`，需要核实后恢复，不自动切换账户或重放。

## 开发与验证

```sh
npm run typecheck
npm test
npm run build
npm run audit:public
npm run hub:deployment:check
```

这些检查只使用本地模拟/合成数据。真实模型请求、原生工具循环、长上下文、IDE 扩展和官方 Codex 桌面 App 兼容性需要各自记录验收，不能从模拟检查推导。

桌面打包首版仅覆盖 macOS Apple Silicon；公开预览包为 ad-hoc 签名、未 Apple 公证。源码可先自行构建，安装包应以 Releases 中实际发布的内容和签名说明为准。Windows、Linux 桌面安装包尚未提供。

```sh
npm run desktop:package
npm run verify:desktop-release
npm run hub:package
```

## 实验上游

个人订阅适配默认关闭，默认环境不会启动订阅登录进程、读取其认证文件或发送订阅推理请求。启用前必须独立确认适用的服务授权与条款；软件的 MIT 许可不赋予上游服务权限。详情见 [实验适配说明](docs/EXPERIMENTAL_SUBSCRIPTION.md)。

HTTP `api_fixture` 是显式选择的协议对照通道，没有可靠生产预算、计费或全功能客户端验收；不会自动成为订阅失效时的付费回退。

## 目录

| 路径 | 内容 |
| --- | --- |
| `apps/desktop`、`apps/client-worker` | Electron 界面、终端与固定 Node 工作进程 |
| `apps/hub`、`apps/relay` | 授权调度与出站中继 |
| `apps/web`、`apps/cli` | 管理界面、命令行与模拟 Demo |
| `packages` | 协议、策略、存储、连接与适配器 |
| `deploy`、`compose.yaml` | 自建部署模板 |
| `.github/workflows` | 公共构建检查与草稿发行 |
| `website` | 可独立托管的静态官网 |

## 许可

[MIT](LICENSE)。第三方软件保持原许可，见 [NOTICE](NOTICE) 和 [第三方声明](THIRD_PARTY_NOTICES.md)。这是独立项目，不代表任何上游厂商的官方授权或产品。
