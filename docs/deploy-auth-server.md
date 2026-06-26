# 部署 auth-server（RFC 认证机）

auth-server 跑在国外 RFC 机器上：用户经 HTTPS 反代 + Basic Auth（可叠加 Cloudflare Access）
认证后，它记录来源 IP、生成签名 `allow.json`，并可选地自动 SSH push 给接收端。

## 1. 构建并安装

```bash
bash scripts/build.sh                 # 产出 dist/nft-auth-server 等
sudo ./install.sh --role auth-server  # 安装二进制 + 目录 + systemd 单元（不会启动）
```

`--role auth-server` 会：

- 安装 `/usr/local/bin/nft-auth-server`（已存在则先备份成 `*.bak.<时间戳>`）；
- 创建 `/etc/nft-auth-whitelist`（含 `ssh/` 子目录，`0700`）、`/var/lib/nft-auth-whitelist`、
  `/var/log/nft-auth-whitelist`；
- 安装示例配置为 `/etc/nft-auth-whitelist/server.json`（**已存在则不覆盖**，改写 `.new`）；
- 安装 `/etc/systemd/system/nft-auth-whitelist-server.service` 并 `daemon-reload`（**不 enable/start**）。

## 2. 配置

```bash
sudo vi /etc/nft-auth-whitelist/server.json
```

至少设置强随机的 `username` / `password` / `pull_token` / `hmac_secret`
（`pull_token`、`hmac_secret` 两端必须一致）。监听保持 `127.0.0.1:8088`，由反代终止 TLS。

## 3. HTTPS 反代

**不要在纯 HTTP 下使用 Basic Auth。** 在前面放 Caddy / Nginx（示例见 README §9、§10），
需要在可信反代后读取真实出口 IP 时，配置 `trusted_proxy_cidrs` + `client_ip_headers`。

## 4. 启动

```bash
sudo systemctl enable --now nft-auth-whitelist-server.service
sudo systemctl status nft-auth-whitelist-server.service
```

systemd 单元启用了 `NoNewPrivileges` / `ProtectSystem=strict` / `ProtectHome=true`，并把
`ReadWritePaths` 限定到数据、日志目录；配置目录保持只读。push 私钥放 `/etc/nft-auth-whitelist/ssh/`，
不要依赖 `/root/.ssh`。

## 5. 自动 push（可选）

见 [automatic-push.md](./automatic-push.md)。默认 `push.enabled=false`，不配置即与旧版一致。

## 6. 升级

```bash
bash scripts/build.sh
sudo ./install.sh --update --role auth-server   # 只替换二进制并备份旧的，不动配置
sudo systemctl restart nft-auth-whitelist-server.service
```
