# HTTPS / WSS 入口

客户端连接公网 Hub 时使用有效公信证书。以你自己拥有的域名部署，Hub 占用该域名的根路径；不支持在 `/share-token/` 这样的子路径下反代。

## Docker Compose 入口

[自建 Hub 指南](SELF_HOSTING.md)使用 `deploy/hub/nginx.conf.template`。模板只开放 443，不需要向公网暴露 Hub 的 HTTP 端口。`HUB_DOMAIN` 来自仓库外的 `.env`，证书与私钥从 `deploy/hub/certs/` 只读挂载。

准备 `fullchain.pem`（服务端证书在前，随后为中间证书）和未加密的 `privkey.pem`，它们需要匹配你填写的域名且处于有效期内。只给 `HUB_DOMAIN` 填规范的小写 DNS 名称，不要填写协议、端口、路径、空格或 nginx 语法。使用已有 ACME 客户端签发和续期；如果采用 HTTP-01，证书客户端需要自行处理 80 端口挑战，本模板没有配置该入口。DNS-01 可避免额外监听，但 DNS 服务凭据同样由你安全保管。

nginx 显式透传原始 Host、HTTPS 协议及 WebSocket Upgrade/Connection 头，关闭请求和响应缓冲、缓存、压缩及代理重试，保留 SSE 流式输出。请求体上限 8 MiB，代理读写超时 960 秒，TLS 限定为 1.2/1.3。匹配之外的 Host 被拒绝。访问日志和请求错误日志关闭，避免路径或查询参数进入 nginx 日志；启动、配置预检和退出状态仍可从容器状态判断。

证书目录权限建议 `0700`、私钥 `0600`；Compose 模板中的 nginx 主进程以容器 root 读取私钥，worker 使用 nginx 镜像的默认用户。不要把 nginx 的启动用户改为普通 UID 后仍期待它能读取 host root 所有的 `0600` 私钥。Hub 则始终使用非 root UID 1000。

证书续期后，将新文件放到同一个证书目录并在部署主机上执行：

```bash
docker compose exec -T nginx nginx -t
docker compose exec -T nginx nginx -s reload
node scripts/hub-tls-verify.mjs --url https://hub.your-domain.tld
```

挂载的是整个目录，原子替换文件可以被容器看到。不要只挂载一个会被续期程序替换的 inode。需要从 ACME 存储复制证书时，使用自己的受保护部署钩子；不要把未挂载目标目录中的绝对符号链接当作可用证书。续期钩子应在证书校验和 `nginx -t` 成功后 reload，再从客户端网络检查有效期。

## 已有 nginx / systemd 的个人服务器

如果你不使用 Docker，可从自己的构建环境执行 `npm run hub:package`，将生成的 Hub tar.gz 解压到专用目录，另行安装 Node 24。归档不包含 Node 本体；保持依赖闭包与 LICENSE/NOTICE 文件完整。以个人服务器的专用普通用户初始化并启动 Hub：

```bash
node dist/apps/cli/index.js init --data-dir /absolute/private/data
node dist/apps/cli/index.js hub --host 127.0.0.1 --port 4387 --data-dir /absolute/private/data
```

`init` 仅执行一次，已有文件会拒绝覆盖。Node 24 是必需条件，因为账本使用 `node:sqlite`。参考 `deploy/hub/share-token-hub.service` 的用户级 systemd 单元，替换工作目录与 Node 路径后由你自己的用户安装；不要直接把示例路径安装到已有服务中。

已有 HTTPS nginx 中，在 `http` 块内加入 Upgrade map，并在该域名的 HTTPS `server` 块中使用 `deploy/hub/nginx-location.conf`。Host、证书及现有站点由你管理。替换配置后先运行你实际 nginx 实例的 `nginx -t`，再 reload。

也可在已有证书、Node 24 和 nginx 的前提下，生成单独的配置前缀与 systemd 模板：

```bash
node scripts/hub-tls-config.mjs \
  --hostname hub.your-domain.tld \
  --cert /absolute/path/fullchain.pem \
  --key /absolute/path/privkey.pem \
  --out /absolute/path/share-token-tls \
  --user share-token
```

该生成器验证证书 SAN、有效期、用途、公私钥匹配与证书链，并输出待审阅的配置和安装命令；它不签发证书、改 DNS、改防火墙或自动安装服务。输出目录必须是实际绝对路径，限定 ASCII 字母、数字、`/ _ . + -`；生成用户需要能读取证书私钥，目标 nginx 用户也需要目录和文件访问权限。固定回环 upstream `127.0.0.1:4387`，服务使用普通用户，低于 1024 的监听端口需要模板中限定的绑定能力。已有相同名服务或端口时，先审阅安装命令，避免覆盖自己的其他服务。

## 验收与边界

```bash
node scripts/hub-tls-verify.mjs --url https://hub.your-domain.tld
```

脚本启用证书校验，不跟随重定向，不发送凭据。它检查健康、协议、首页与资产、配对页、未认证 API 的 401，以及 WSS 握手在 Hub 边界的 401（带浏览器 Origin 时为 403）。报告只含状态和公开证书信息。它证明入口、资产与 Upgrade 转发能到达 Hub 拒绝逻辑；还需要用实际配对设备验收 Relay、SSE 和完整模拟请求。

私有 CA 只用于参与者明确配置过信任的网络；可用 `--ca /absolute/path/ca.pem` 给这个验收进程提供公开 CA 文件，这不会改变操作系统或桌面应用的信任设置。不要关闭证书校验来连接公网 Hub。公网通用客户端应直接填写公信 HTTPS origin，无需使用私网 IP 的自签证书连接文件。

参考：[nginx WebSocket 转发](https://nginx.org/en/docs/http/websocket.html)。
