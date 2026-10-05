# 自建 Hub

Hub 负责设备配对、授权、调度和 SQLite 账本；模型请求由参与者电脑上的 Relay 执行。Hub 在转发时能接触请求和响应正文，因此部署者是信任边界。数据库不保存提示词和响应正文，但包含设备、凭据摘要、授权和使用记录。不要部署在不信任的主机上。

本指南使用你自己的 Linux VPS、域名和有效公信证书，依赖公共 npm、Docker 官方镜像和公共 Debian 软件源。它不要求公司账号、VPN、镜像源、CI 或服务器。所有例子均为占位值。首版默认使用模拟上游；部署 Hub 不会启用实验性订阅适配器。

## 准备

- 安装 Docker Engine 和支持 `docker compose up --wait` 的 Docker Compose v2。
- 将你拥有的域名（例如 `hub.your-domain.tld`）指向 VPS 公网 IP。仅配置你确实能服务的 A/AAAA 记录。
- 在个人云账号的网络规则中开放 TCP 443。Hub 的 4387 端口只存在于 Docker 内部网络，无须开放。
- 用你选择的 ACME 客户端或证书服务取得匹配该域名的 fullchain 和私钥。证书签发与自动续期由部署者安排，见 [HTTPS 指南](HTTPS.md)。本模板不自动申请证书、修改 DNS 或开放防火墙。
- 同一 SQLite 数据卷只运行一个 Hub，使用 Linux 本地文件系统；不要把它放在 NFS 上，也不要横向扩容 Hub。

1 核、1–2 GB 内存可以作为几个朋友使用的部署起点，这是估算而不是已验证容量。构建镜像所需内存另算，可以在个人构建环境中提前构建。

## 首次启动

在仓库根目录执行：

```bash
cp deploy/hub/.env.example .env
mkdir -p deploy/hub/certs
chmod 700 deploy/hub/certs
```

编辑 `.env`，把 `HUB_DOMAIN` 设置为你的实际域名；把已有证书放到 `deploy/hub/certs/fullchain.pem`，把未加密私钥放到 `deploy/hub/certs/privkey.pem`。私钥使用 `0600` 权限。证书可以是 `0644`。不要将这些真实文件提交到 Git。

```bash
chmod 600 deploy/hub/certs/privkey.pem
docker compose config --quiet
docker compose up --build --wait --wait-timeout 120
docker compose exec -T nginx nginx -t
```

镜像采用两阶段构建：构建阶段安装锁定的公共依赖并关闭安装脚本，不下载 Electron，也不编译桌面终端模块；运行阶段只包含 Node 24、检查过的 Hub 闭包、`ws`、`zod` 及许可证。Hub 以 UID 1000 运行，根文件系统只读，数据卷目录权限为 `0700`，凭据与 SQLite 文件权限为 `0600`。

首次启动在 `hub-data` 持久卷内生成 `admin.token` 并初始化数据库；以后启动沿用它们。启动器先获取卷内 `.hub.lock` 的独占文件锁，再恢复上次异常退出留下的数据库运行租约，因此重启不会因容器 PID 复用而卡住。第二个标准容器挂载同一卷时会被拒绝。不要绕过容器入口直接启动另一个 Hub，也不要运行两个 Compose 项目指向同一个数据卷。

在部署电脑上将管理员凭据写到私有文件中：

```bash
umask 077
docker compose exec -T hub cat /data/admin.token > "$HOME/share-token-admin.token"
```

通过你自己的安全通道取回该文件，在浏览器打开 `https://你的域名/` 登录管理界面。凭据不要放到 URL、仓库、截图、CI 参数或公开工单中。管理员可以创建一次性邀请。桌面客户端连接时填写这个 HTTPS origin，再使用应用提供的配对流程。

## 可选的共享配对码

默认不设置服务器级共享码，仍可使用邀请和双方匹配流程。如果你的小圈子需要固定的 8 位共享码，使用 Compose secret 文件：

```bash
mkdir -p deploy/hub/secrets
chmod 700 deploy/hub/secrets
read -r -s -p '输入 8 位配对码: ' pairing_code
printf '\n'
printf '%s\n' "$pairing_code" > deploy/hub/secrets/shared-code.txt
unset pairing_code
chmod 644 deploy/hub/secrets/shared-code.txt
```

此处输入命令使用 Bash。父目录 `0700` 保护宿主机文件，文件自身 `0644` 使容器内 UID 1000 可以读取 Compose 的单文件只读挂载。不要将整个 secrets 目录共享给其他用户或容器。

在 `.env` 中追加这一行，然后保持后续操作在该仓库根目录进行：

```dotenv
COMPOSE_FILE=compose.yaml:deploy/hub/compose.shared-code.yaml
```

```bash
docker compose config --quiet
docker compose up --wait --wait-timeout 120
```

启动器仅在首次设置时读取明文码，数据卷只保存带随机盐的 scrypt 校验值。重启不会修改校验值，改变 secret 文件也不会自动轮换；已有设备不会因重启断开。显式轮换：

```bash
read -r -s -p '输入新的 8 位配对码: ' pairing_code
printf '\n'
printf '%s\n' "$pairing_code" | docker compose exec -T hub \
  node dist/apps/cli/index.js shared-code rotate --data-dir /data
printf '%s\n' "$pairing_code" > deploy/hub/secrets/shared-code.txt
unset pairing_code
```

未设置过码时，将命令中的 `rotate` 改为 `set`。关闭服务器级共享码时，先停止服务，移除 `.env` 中的 `COMPOSE_FILE` 行，并从数据卷删除 `shared-code.json` 后重新启动；仅移除 secret 挂载不会删除已经保存的校验值。撤销已配对设备应在管理功能中单独完成。

## 健康检查与公网验收

```bash
docker compose ps
docker compose exec -T hub node deploy/hub/healthcheck.mjs
node scripts/hub-tls-verify.mjs --url https://hub.your-domain.tld
```

最后一个命令需要本地 Node 24，应该从参与者实际使用的网络执行。它开启证书校验，检查健康、协议元信息、首页、静态资产和配对页，并检查未认证 API 与 WSS 握手被正确拒绝。它不会发送管理员或模型凭据，不代表真实 Relay、SSE 或模型推理已经验收。完成配对后，还应使用模拟源验证一次完整请求以及撤销后的拒绝行为。

容器自动健康检查只检查 `/healthz`。`restart: unless-stopped` 会重启退出的进程；健康状态变为 `unhealthy` 本身不会自动重启服务。需要观察状态、排查原因，再决定是否重启。

## 备份与恢复

SQLite 使用 WAL。备份整个数据目录，并停机进行一致性复制；不要在运行中只复制 `hub.sqlite`。备份包含管理员凭据和设备记录，按秘密数据保存，建议加密后放到你自己的另一处存储。HTTPS 私钥和 `.env` 属于另一组部署配置，也应独立安全备份。

```bash
umask 077
mkdir -p backups
docker compose stop nginx hub
docker compose run --rm --no-deps --entrypoint sh hub \
  -c 'cd /data && tar -czf - .' > backups/hub-backup.tar.gz
test -s backups/hub-backup.tar.gz
docker compose up --wait --wait-timeout 120
```

归档使用标准输出，所以不要给备份命令增加 `-t`。重复使用同一文件名会覆盖上次备份，应自行选择带日期的名称。备份失败时仍应保留原卷；排查错误后重新备份，不要把空文件当作有效备份。

恢复时优先在新的个人 VPS 或新的 Compose 项目名下进行。使用相同版本镜像，把证书和 `.env` 配置好，在启动 Hub 之前把完整归档导入空的数据卷：

```bash
docker compose -p share-token-restored build hub
docker compose -p share-token-restored run --rm --no-deps -T --entrypoint sh hub \
  -c 'test -z "$(ls -A /data)" && tar -xzf - -C /data' < backups/hub-backup.tar.gz
docker compose -p share-token-restored up --wait --wait-timeout 120
```

两个项目不要争用宿主机 443；恢复测试应在另一台机器，或先停止原 nginx，再启动恢复后的入口。后续操作始终带上选定的 `-p share-token-restored`。该命令要求恢复目标为空，防止混合两套账本。只导入你自己的可信备份，包含 `admin.token`、SQLite 及可能存在的 WAL/SHM 文件、共享码校验值；不要只导入数据库。启动器遇到已有数据库但缺少管理员凭据会拒绝自动初始化。成功恢复应保留原 Hub ID、设备身份和授权；在旧入口上保留的客户端凭据需要保护。

普通 `docker compose down` 保留命名卷；`down --volumes` 会删除数据，不用于日常更新或重启。

## 更新与回滚

先备份，查看发行说明，再检出已审核的版本：

```bash
docker compose build --pull hub
docker compose pull nginx
docker compose up --wait --wait-timeout 120
node scripts/hub-tls-verify.mjs --url https://hub.your-domain.tld
```

保持 `.env`、证书、数据卷和 secret 独立于源码更新。恢复旧代码前确认是否有数据库迁移；如果存在不兼容迁移，应同时恢复该旧版本对应的完整备份。基础镜像使用 Node 24 和 nginx stable 标签，实际部署可在验证后记录并固定镜像 digest，以便复现和回滚。

本地部署准备检查为 `npm run build && npm run hub:deployment:check`。Docker 集成冒烟为 `npm run hub:container:smoke`，会构建临时镜像、启动非 root Hub、验证异常退出后身份保持、拒绝同卷并发实例，再通过临时 nginx 验证 HTTPS/WSS 边界；结束清理临时容器和卷。该检查使用临时测试证书和模拟部署状态，不部署云服务器，也不验证真实上游。

参考：[Compose 启动与等待选项](https://docs.docker.com/reference/cli/docker/compose/up/)、[Compose secret 文件](https://docs.docker.com/compose/how-tos/use-secrets/)。
