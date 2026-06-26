# nft-auth-whitelist

主项目 **nftables-nat-rust-enhanced** 的 sidecar 配套项目，**不修改主项目**。

用户在 RFC 内网机器上经 HTTPS 认证页登录，auth-server 记录其真实来源公网 IP（带 TTL，默认 `/32`）并签名导出；国内 po0 机器拿到这份白名单，写成本地 `allow.txt` 交给主项目消费。纯 Go 标准库实现，静态编译、依赖少。

## 三个二进制

| 二进制 | 跑在 | 职责 |
| --- | --- | --- |
| `nft-auth-server` | RFC 内网机器 | HTTPS 认证页，记录认证用户来源 IP（带 TTL），导出签名 `allow.json`，可选自动 SSH push |
| `nft-auth-puller` | 国内 po0 | **主动拉取** `allow.json`，校验 HMAC/TTL，导出本地 `allow.txt` |
| `nft-auth-receive` | 国内 po0 | SSH forced-command 接收端，从 stdin 收签名 envelope，导出同样的 `allow.txt`（receive shadow mode） |

白名单送到 po0 有两条路：puller 主动拉，或 auth-server 经 SSH push 给 receive。两者默认都只导出 `allow.txt`，**默认不执行** nft。

## 工作方式

```
用户 → HTTPS Basic Auth / Cloudflare Access (Caddy/Nginx 反代)
     → nft-auth-server      记录来源 IP + TTL，签名
     → allow.json (HMAC-SHA256)
     → po0 拉取 / 接收        校验签名 / TTL / 地址族
     → allow.txt (原子写)     交给 nftables-nat-rust-enhanced 消费
```

po0 **主动拉取**或被动接收，**不暴露**任何改白名单的远程 API；关键动作都写 JSON Lines 审计日志。

和主项目的关系：本项目是 sidecar，不碰主项目的 `/etc/nat.toml` 和 self-nat / self-filter 表。主项目通过自身的 `dynamic_whitelist` 用 `file_sources` 读 `allow.txt` 决定放行，集成点在主项目那边。

## 快速开始

RFC 内网机器（auth-server）：

```bash
bash scripts/build.sh                          # 构建到 dist/
sudo ./install.sh --role auth-server           # 装二进制 + 示例配置，不启动、不覆盖已有配置
sudo vi /etc/nft-auth-whitelist/server.json    # 设强随机 username/password/pull_token/hmac_secret
sudo systemctl enable --now nft-auth-whitelist-server.service   # 放在 HTTPS 反代之后再启
```

接口：`GET /` 只显示确认页（不写白名单），`POST /` 才记录来源 IP；`GET /allow.json`（`Authorization: Bearer <pull_token>`）返回签名 envelope；`GET /health` 返回 `ok`。

po0（puller）：

```bash
sudo ./install.sh --role puller
sudo vi /etc/nft-auth-whitelist/puller.json    # pull_token / hmac_secret 与 RFC 一致
nft-auth-puller --config /etc/nft-auth-whitelist/puller.json --once       # 单次拉取
nft-auth-puller --config /etc/nft-auth-whitelist/puller.json --dry-run    # 只看会写什么，不落盘
```

拉取或验签失败时**保留上一次的 `allow.txt`**、不清空；输出都是原子写（临时文件 + rename）。

## 配置要点

`server.json` 主要字段：`ttl_seconds`（默认 `1209600`，14 天）、`max_entries`（默认 200）、`allow_ipv4` / `allow_ipv6`（默认只 v4）、`allow_cidr_expand_ipv4`（默认关，开了才允许用户选 `/24`）、`trusted_proxy_cidrs` + `client_ip_headers`（反代后取真实 IP 用）、`rate_limit`。完整字段见 `configs/server.example.json`。

`puller.json` 主要字段：`server_url`、`pull_token`、`hmac_secret`、`require_https`（默认 true）、`mode`（默认 `export`）、可选 `nft.*`。见 `configs/puller.example.json`。

## 安全

- **不要在纯 HTTP 下用 Basic Auth。** auth-server 默认只监听 `127.0.0.1:8088`，由 Caddy 或 Nginx 终止 TLS：

  ```caddy
  auth.example.com { reverse_proxy 127.0.0.1:8088 }
  ```
  ```nginx
  location / { proxy_pass http://127.0.0.1:8088; }
  ```

- 只记录认证请求的**来源 IP**，**不允许用户提交任意 IP**。
- 每条记录都有 TTL，到期自动删除，**不会永久加白**。
- 默认只读 `RemoteAddr`；只有 `trusted_proxy_cidrs` 命中的反代才信任 `CF-Connecting-IP` / `X-Forwarded-For`。不要把 `0.0.0.0/0` 或 `::/0` 加进可信代理。
- `password` / `pull_token` / `hmac_secret` 绝不写日志。
- 管理用的 SSH 端口永远不要纳入自动拦截，避免把自己锁在外面。

Cloudflare Access 前门、trusted proxy 的完整配置见 [SECURITY.md](./SECURITY.md) 和 [docs/](./docs/)。

## 投递方式

- **puller（主动拉）**：po0 定时 `--once` 拉 `allow.json`。适合 po0 能主动 HTTPS 访问 RFC。
- **receive shadow mode（被动收）**：auth-server 认证成功后经 **SSH stdin** 把签名 envelope 推给 po0 的 `nft-auth-receive`，这把 key 用 forced command 锁成只能干这一件事，不监听端口、不暴露写 API。适合 po0 出站被封、拉不动的情况：

  ```text
  command="/usr/local/bin/nft-auth-receive -config /etc/nft-auth-whitelist/receive.json",no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA... key-comment
  ```

两条路都校验 HMAC 签名，失败一律拒绝并保留旧 `allow.txt`。自动 push、生产 po0 接入等详细步骤见 [docs/](./docs/)（`deploy-auth-server.md`、`deploy-receive.md`、`deploy-po0-shadow.md`、`public-deployment.md`）。

## 可选 nft guard（默认关闭）

puller / receive 默认 `export` 模式，**默认不执行**任何 `nft` 命令。要让本项目自己下发 nft 规则，需**同时**满足 `mode=nft`（或 `nft.enabled=true`）和命令行 `--apply`。它只管理自己的 `table inet nft_auth_whitelist`，绝不 `flush ruleset`，`policy accept` 只对配置里的受保护端口做「白名单放行、否则 drop」，不碰主项目和其它表。不确定就先 `--dry-run` 看生成的脚本。

## 安装 / 构建

```bash
sudo ./install.sh --role <auth-server|receive|puller>   # 安装；--update 只换二进制；--dry-run 只打印
bash scripts/build.sh        # 三个二进制 → dist/
bash scripts/check.sh        # gofmt + vet + test + 打包 + secret-scan + 安装自检
```

`install.sh` 只复制文件、建目录/用户、可选装 systemd 单元；不自动启动、不 enable nft、不改 sshd / 防火墙、不覆盖已有配置（改写 `<name>.json.new` 供对比）。角色与升级细节见 [docs/](./docs/)。

---

许可证：[LICENSE](./LICENSE)（MIT）。安全说明：[SECURITY.md](./SECURITY.md)。
