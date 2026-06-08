# nft-auth-whitelist

> 与 [nftables-nat-rust-enhanced](https://github.com/) 搭配使用的 **sidecar 配套项目**。
> 用户在国外 RFC 机器上通过 HTTPS 认证页面登录，auth-server 记录其**真实来源公网 IP**（带 TTL，默认 `/32`），
> 国内 po0 机器上的 puller **主动拉取**已认证 IP 列表，默认只导出本地 `allow.txt`。

本项目用 Go 实现，**仅使用标准库**，便于静态编译、低依赖部署。

---

## 1. 项目介绍

`nft-auth-whitelist` 包含两个二进制：

| 二进制 | 运行位置 | 职责 |
| --- | --- | --- |
| `nft-auth-server` | 国外 RFC 机器 | HTTPS 认证页面（Basic Auth / Cloudflare Access 前门），记录来源 IP，带 TTL，导出签名后的 `allow.json` |
| `nft-auth-puller` | 国内 po0 机器 | 定时主动拉取 `allow.json`，校验 HMAC 签名与 TTL，导出本地 `allow.txt` |

设计原则：**安全、简单、可审计**。第一版不追求功能多。

## 2. 工作方式

```
用户
  -> HTTPS Basic Auth 或 Cloudflare Access (Caddy/Nginx 反代)
  -> RFC nft-auth-server         记录来源 IP + TTL
  -> allow.json (HMAC-SHA256 签名)
  -> po0 nft-auth-puller 主动拉取  校验签名 / TTL / 家族
  -> /var/lib/nft-auth-whitelist/allow.txt   (默认只导出，原子写)
  -> 后续可人工或未来集成到 nftables-nat-rust-enhanced
```

- po0 **主动拉取** RFC，**po0 不暴露任何写白名单的远程 API**。
- 所有关键动作都写 JSON Lines 审计日志。

## 3. 和 nftables-nat-rust-enhanced 的关系

- 本项目是 **sidecar，不修改主项目**，不会改写主项目的 `/etc/nat.toml`，也不会触碰主项目的
  self-nat / self-filter 表。
- 第一版默认 **只导出 `allow.txt`** 供人工观察，不直接接管防火墙。
- 如果主项目自身 `access_control=whitelist` 且白名单不包含这些 IP，本 sidecar 导出的 allow
  **不会绕过主项目的限制**。
- 最推荐第一版使用 **export 模式**先观察导出的 IP 是否符合预期。
- 后续如果主项目支持 **URL source whitelist**，再做正式集成；**第一版不做深度集成**。

## 4. 不适合的场景（明确不做）

- ❌ 不接入省市 / 城市 / 运营商 IP 库；不接入 metowolf/iplist；不做「省墙」。
- ❌ 不做 WebUI 管理后台；不做 Telegram Bot 管理面板。
- ❌ 不做多租户；不做负载均衡 / 分流；不做 Proxy Protocol / MPTCP。
- ❌ 不引入数据库（用 JSON 文件存储）。
- ❌ 不自动永久加白；不允许用户提交任意 IP（只用请求来源 IP）。
- ❌ 默认不执行真实 `nft -f`；不自动修改 SSH 配置；不自动 `systemctl restart`。

## 5. 快速开始：RFC 机器 auth-server

```bash
# 1. 构建（在开发机或 RFC 机器）
bash scripts/build.sh           # 输出到 dist/

# 2. 安装二进制与示例配置（不会启动服务，不会覆盖已有配置）
sudo bash scripts/install.sh

# 3. 编辑配置，设置强随机的 username/password/pull_token/hmac_secret
sudo vi /etc/nft-auth-whitelist/server.json

# 4. 在 HTTPS 反代后面跑起来（示例见第 9 节）
/usr/local/bin/nft-auth-server --config /etc/nft-auth-whitelist/server.json
```

接口：

| 路径 | 鉴权 | 说明 |
| --- | --- | --- |
| `GET /` | Basic Auth | 认证成功后记录来源 IP，返回 HTML 显示 CIDR / 过期时间 / TTL |
| `GET /allow.json` | `Authorization: Bearer <pull_token>` | 返回带 HMAC 签名的只读 envelope（puller 首选） |
| `GET /allow.txt` | `Authorization: Bearer <pull_token>` | 纯文本，每行一个 CIDR（无签名，非首选） |
| `GET /health` | 无 | 返回 `ok`，不暴露敏感信息 |

> ⚠️ **不要在纯 HTTP 下使用 Basic Auth。** 默认监听 `127.0.0.1:8088`，必须由 Caddy/Nginx 提供 HTTPS。

## 6. 快速开始：po0 机器 puller

```bash
sudo bash scripts/install.sh
sudo vi /etc/nft-auth-whitelist/puller.json   # 填入与 RFC 一致的 pull_token / hmac_secret

# 单次拉取（systemd timer 用这个）
nft-auth-puller --config /etc/nft-auth-whitelist/puller.json --once

# 只看会写什么、会生成什么 nft 脚本（不落盘、不执行）
nft-auth-puller --config /etc/nft-auth-whitelist/puller.json --dry-run

# 显式开启 nft guard 真实执行（需先在配置里开启，见第 14 节）
nft-auth-puller --config /etc/nft-auth-whitelist/puller.json --once --apply
```

拉取行为：

- 拉取失败：**不清空** 本地 `allow.txt`，保留上一次成功结果，写 `pull.fail` (warn)，不 panic。
- 签名校验失败：**拒绝** 使用新结果，保留旧结果，写 `signature.fail` (error)。
- 过期 entry：不写入 `allow.txt`。
- entries 超过 `max_entries`：**拒绝**整批并 WARN（避免被异常放大），保留旧结果。
- `allow.txt` / `pulled-state.json` 均为 **原子写**（临时文件 + rename）。
- 使用 Go `http.Client`，超时 15 秒；**不使用 curl，不访问任何第三方 IP 查询 API**。

## 7. 配置说明

### server.json（auth-server）

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `listen` | `127.0.0.1:8088` | 监听地址，建议保持本地，由反代暴露 |
| `username` / `password` | — | Basic Auth 凭据，constant-time 比较 |
| `pull_token` | — | puller 拉取用的 Bearer token |
| `hmac_secret` | — | `allow.json` 签名密钥，两端必须一致 |
| `ttl_seconds` | `21600` | 每条记录 TTL，默认 6 小时 |
| `max_entries` | `200` | 超限时清理最旧 / 已过期记录 |
| `allow_ipv4` / `allow_ipv6` | `true` / `false` | 地址族开关；IPv6 默认关闭 |
| `allow_cidr_expand_ipv4` | `false` | 是否允许用户选择 `/24`（默认关闭） |
| `trusted_proxy_cidrs` | `[]` | 可信反代 CIDR；只有 `RemoteAddr` 命中时才读取客户端 IP header |
| `client_ip_headers` | `CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For` | 可信反代命中后的 header 优先级 |
| `trusted_proxies` / `real_ip_header` | `[]` / `""` | 旧配置兼容字段；新部署优先使用上面两个字段 |
| `data_dir` | `/var/lib/nft-auth-whitelist` | JSON 存储目录（无数据库） |
| `audit_log` | — | 审计日志路径，空则写 stderr |
| `rate_limit` | 开启/10 | 每分钟每来源登录失败上限 |

### puller.json（puller）

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `server_url` | — | RFC `allow.json` 地址 |
| `pull_token` / `hmac_secret` | — | 与 RFC 一致 |
| `interval_seconds` | `60` | 循环模式拉取间隔 |
| `output_allow_txt` | — | 导出的 allowlist 路径 |
| `output_state_json` | — | 拉取状态快照路径 |
| `max_entries` | `200` | 超限拒绝 |
| `require_https` | `true` | 为 `true` 时拒绝 `http://` 的 `server_url` |
| `mode` | `export` | `export` 或 `nft` |
| `nft.enabled` | `false` | 可选 nft guard 开关 |
| `nft.table` | `nft_auth_whitelist` | guard 使用的独立 table |
| `nft.protected_tcp_ports` / `protected_udp_ports` | `[]` | 只保护这些端口 |

## 8. 安全注意

- `password` / `pull_token` / `hmac_secret` **绝不写入日志**。
- 登录失败只记录来源 IP，不记录密码。
- **不允许用户提交任意 IP**，只记录认证请求的来源 IP。
- 默认只使用 `RemoteAddr`；只有 `trusted_proxy_cidrs` 命中的反代才可信。
- 不要无条件信任 `CF-Connecting-IP` / `X-Forwarded-For`，也不要把 `0.0.0.0/0` 或 `::/0` 加进可信代理。
- 默认只加 `/32`；`/24` 必须显式开启并有风险提示。
- **不会自动把 IP 永久加白**（全部带 TTL）。
- 详见 [SECURITY.md](./SECURITY.md)。

## 9. HTTPS / 反代建议

**不要在纯 HTTP 下使用 Basic Auth。** 推荐让 auth-server 只监听 `127.0.0.1`，由 Caddy 或 Nginx 终止 TLS：

Caddy 示例：

```caddy
auth.example.com {
    reverse_proxy 127.0.0.1:8088
}
```

Nginx 示例（片段）：

```nginx
location / {
    proxy_pass http://127.0.0.1:8088;
}
```

默认不读取任何客户端 IP header，只使用 `RemoteAddr`。如果需要在 Cloudflare Access / 可信反代后读取真实客户端 IP，见下一节。

## 10. Cloudflare Access front door / trusted proxy mode

适用场景：

- 用 Cloudflare Access 作为外层登录前门，叠加在 auth-server 的 Basic Auth 前面。
- 用户通过 GitHub / Google / OIDC / Email 登录 Access 后访问认证页。
- auth-server 从可信反代转发的 `CF-Connecting-IP` 记录真实出口 IP。

推荐链路：

```text
用户浏览器
  -> Cloudflare Access
  -> Caddy/Nginx
  -> 127.0.0.1:nft-auth-server
  -> allow.json
  -> po0 nft-auth-puller --once --mode export
  -> allow.txt
```

auth-server 配置示例：

```json
{
  "listen": "127.0.0.1:8088",
  "trusted_proxy_cidrs": [
    "127.0.0.1/32",
    "::1/128"
  ],
  "client_ip_headers": [
    "CF-Connecting-IP",
    "X-Real-IP",
    "X-Forwarded-For"
  ]
}
```

JSON 配置文件不能写注释；上面只展示相关字段，实际配置仍需包含 `username` / `password` / `pull_token` / `hmac_secret` 等必填项。

Caddy 示例：

```caddy
auth.example.com {
    reverse_proxy 127.0.0.1:YOUR_AUTH_SERVER_PORT {
        header_up CF-Connecting-IP {http.request.header.CF-Connecting-IP}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

Caddy 的默认转发行是否保留某个 header 取决于你的 Caddy 版本和站点配置；这里保留显式 `header_up`，方便审计和迁移。

Nginx 示例：

```nginx
location / {
    proxy_pass http://127.0.0.1:YOUR_AUTH_SERVER_PORT;
    proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

安全提醒：

- auth-server 推荐只监听 `127.0.0.1`。
- 防火墙不要让公网直连 auth-server。
- 只有 `trusted_proxy_cidrs` 命中的代理才可信。
- 不要无条件信任 `CF-Connecting-IP`。
- 不要把公网来源全部加入 `trusted_proxy_cidrs`。
- 不要把 `0.0.0.0/0` 或 `::/0` 加进 `trusted_proxy_cidrs`；除非只是临时测试，生产不推荐。
- Cloudflare Access 负责外层“人登录”，auth-server 当前仍保留 Basic Auth；nft-auth-whitelist 负责“记录当前出口 IP + 签名白名单”。
- 当前阶段 po0 仍只运行 `nft-auth-puller --once --mode export`，不启用 `--apply`。

## 11. TTL 和 /32 / /24 说明

- 默认 TTL 21600 秒（6 小时），到期自动删除。
- 同一 IP 再次认证成功会**刷新** `expires_at`（续期），并增加 `hit_count`。
- IPv4 默认记录 `/32`。
- 仅当 `allow_cidr_expand_ipv4=true` 时，用户可在页面用 `?scope=24` 选择 `/24`，
  且页面会显示 **风险提示**（`/24` 会放行整段 256 个地址）。
- IPv6 第一版默认关闭；若开启只记录 `/128`，**不会自动扩 `/64`**。

## 12. allow.json 签名说明

`allow.json` 是一个签名 envelope：

```json
{
  "version": 1,
  "issued_at": "2026-01-01T00:00:00Z",
  "expires_at": "2026-01-01T00:05:00Z",
  "entries": [
    {
      "ip": "1.2.3.4",
      "cidr": "1.2.3.4/32",
      "source": "web_auth",
      "created_at": "...",
      "expires_at": "...",
      "last_seen_at": "...",
      "hit_count": 3
    }
  ],
  "signature": "hex-hmac-sha256"
}
```

- `signature` 是对 **去掉 `signature` 字段后的 canonical JSON** 做 `HMAC-SHA256` 的十六进制结果。
- canonical JSON 由固定结构体字段顺序 + 按 CIDR 排序的 entries 生成，**稳定可复现**。
- puller 必须验证签名；签名失败、被篡改、密钥不一致都会被拒绝（已有单元测试覆盖）。

## 13. export 模式（默认）

- `mode=export` 时只写：`allow.txt`、`pulled-state.json`、审计日志。
- **不执行任何 nft 命令。**
- 这是第一版推荐使用方式：先观察导出的 IP 是否符合预期，再考虑后续集成。

## 14. 可选 nft guard 模式（默认关闭）

这是一个**独立保护层**，不能宣称已和 nftables-nat-rust-enhanced 完全集成。

真实执行 `nft` 必须**同时**满足：

1. 配置 `mode=nft` 或 `nft.enabled=true`；
2. 命令行显式传 `--apply`。

guard 行为：

- 只管理本项目自己的表 `table inet nft_auth_whitelist`。
- 先 `nft -c -f -` 检查，再 `nft -f -` 应用。
- **绝不 `flush ruleset`**；不触碰主项目的 self-nat / self-filter 表，也不触碰用户其它表。
- chain 使用 `policy accept`，**只对配置里的 `protected_tcp_ports` / `protected_udp_ports`**
  做「允许来自白名单、否则 drop」。
- **不默认保护所有端口；不默认保护 SSH；不修改 INPUT/FORWARD 策略；不做全局 drop。**

幂等性：脚本开头用 `table ... / delete table ...` 仅重置**本项目自己的表**，这不是 flush ruleset。

如果你不确定，请保持 `--dry-run` 观察生成的脚本，确认无误后再考虑 `--apply`。

## 15. systemd 示例

`systemd/` 下提供 **示例** 单元文件，请先检查再启用：

- `nft-auth-whitelist-server.service` —— RFC auth-server（常驻）。
- `nft-auth-whitelist-puller.service` —— po0 puller（oneshot，`--once`）。
- `nft-auth-whitelist-puller.timer` —— `OnBootSec=30s` / `OnUnitActiveSec=60s`。

```bash
sudo cp systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
# 检查配置无误后再启用：
sudo systemctl enable --now nft-auth-whitelist-server.service        # RFC
sudo systemctl enable --now nft-auth-whitelist-puller.timer          # po0
```

> 安装脚本不会自动 `systemctl restart`，也不会自动启用任何单元。

## 16. 常见问题

- **puller 拉取失败会清空白名单吗？** 不会。失败时保留上一次成功的 `allow.txt`。
- **会自动改防火墙吗？** 默认不会。只有显式 `--apply` 且配置开启 guard 时才会执行 nft。
- **能让用户提交某个 IP 吗？** 不能。只记录认证请求的来源 IP。
- **套了 Cloudflare Access / CDN 怎么办？** auth-server 只应信任你明确配置的反代 CIDR，见第 10 节；不要把公网来源全部加入 `trusted_proxy_cidrs`。
- **会永久加白吗？** 不会。所有记录都有 TTL，默认 6 小时。

## 17. TODO

- [ ] 与 nftables-nat-rust-enhanced 的 URL source whitelist 正式集成（待主项目支持）。
- [ ] 更细的 per-IP 速率限制策略。
- [ ] 可选的 entry 持久化备份 / 历史。

---

许可证：见 [LICENSE](./LICENSE)（MIT）。安全说明：见 [SECURITY.md](./SECURITY.md)。
