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

# 2. 安装二进制与示例配置（不会启动/覆盖已有配置；详见第 19 节角色化安装）
sudo ./install.sh --role auth-server

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
sudo ./install.sh --role puller
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
- The guard hooks local `input` traffic only; it does not protect DNAT traffic traversing `forward`.

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

## 17. Puller file source 模式 / SSH push 工作流

适用场景：

- 国内 po0 转发机被商家**双向封禁** 80 / 443 / 8080 / 8443 / 8000 / 1080（TCP/UDP），不适合主动 HTTPS pull。
- signed `allow.json` 由国外 RFC 认证机生成后，通过 **SSH/scp 推送**到 po0 本地 inbox。
- puller 只在本机**读取文件、校验签名、导出 `allow.txt`**，不发起任何网络请求。

配置：把 `source` 设为 `file` 并填 `input_allow_json`（示例见 `configs/puller-file.example.json`）。

| source | 取值来源 | server_url / pull_token | require_https | HMAC / TTL / max_entries / 家族 / CIDR 校验 | 导出 allow.txt / state.json / 审计 |
| --- | --- | --- | --- | --- | --- |
| `http`（默认，缺省即此） | 主动 GET `server_url` 拉取 | 必填，使用 | 参与校验 | 是 | 是 |
| `file` | 读取本地 `input_allow_json` | 可为空，不使用 | **不参与校验** | 是（与 http 完全一致） | 是 |

示例流程：

1. RFC 日本认证机生成 signed allow.json（仅本机回环，token 走 header）：

```bash
curl -fsS \
  -H "Authorization: Bearer $PULL_TOKEN" \
  http://127.0.0.1:8088/allow.json \
  -o /tmp/nft-auth-allow.json
```

2. RFC 通过 SSH/scp 推送到模拟 po0：

```bash
scp -i /etc/nft-auth-whitelist/ssh/nft_auth_push \
  /tmp/nft-auth-allow.json \
  nftauth@TEST_VPS:/var/lib/nft-auth-whitelist/inbox/allow.json
```

3. 模拟 po0 本地运行（只读文件、校验、导出）：

```bash
nft-auth-puller -config /etc/nft-auth-whitelist/puller-file.json -once
```

4. 查看结果：

```bash
cat /var/lib/nft-auth-whitelist/allow.txt
cat /var/lib/nft-auth-whitelist/pulled-state.json
```

安全说明：

- file source 模式**仍然校验 HMAC 签名**，签名失败、被篡改、密钥不一致一律拒绝。
- 文件不存在 / 读取失败 / JSON 非法 / 签名失败 / 校验失败时，**不清空旧 `allow.txt`**，保留上一次成功结果；`allow.txt` / `pulled-state.json` 仍为原子写（临时文件 + rename），不会出现空文件覆盖。
- 本模式**不启用 `nft apply`**，默认仍是 `export`。
- 把 `allow.json` 直接经 SSH stdin 推给 forced command（无需落地 inbox 再 puller 读）见第 18 节 `nft-auth-receive`。
- 管理入口 **SSH 2222 永远不要纳入自动拦截**，避免锁死自己。

## 18. SSH forced command receive mode（`nft-auth-receive`）

`nft-auth-receive` 是接收端命令，专为 **SSH forced command** 设计：RFC 日本机把 signed `allow.json` 经 **SSH stdin** 推给接收端，接收端**只读 stdin**、校验、导出，**不监听任何端口、不暴露任何写白名单 API**。

与 §17 file source 的区别：file source 需要先把文件 scp 落到 inbox 再由 puller 读；`nft-auth-receive` 直接从 stdin 接收并在校验通过后**自己**原子写 inbox + 导出 `allow.txt`，更适合锁死成「这把 key 只能干这一件事」。

CLI：

```text
nft-auth-receive -config /etc/nft-auth-whitelist/receive.json   # 从 stdin 读 signed allow.json
nft-auth-receive -version                                       # 打印版本
nft-auth-receive -h                                             # 帮助
```

行为（全部在本机完成，无网络请求）：

1. 从 stdin 读取，**限制最大输入** `input_max_bytes`（默认 1 MiB），超限即失败。
2. 解析 JSON；用 `hmac_secret` 校验 **HMAC 签名**。
3. 校验 envelope 顶层 `expires_at`（TTL）、`max_entries`、地址族、CIDR；过期/非法 entry 过滤。
4. **仅在全部校验通过后**：原子写入 `inbox_allow_json` → 导出 `output_allow_txt` → 写 `output_state_json` → 写 `audit_log`。
5. 成功：退出码 0，stdout 输出 `ok entries=N output=...`。
6. 失败：退出码非 0，stderr 输出清晰错误，**不输出 hmac_secret / token / password / Authorization / Cookie 等敏感信息**。

失败安全边界（与 puller 一致）：输入为空 / 超限 / JSON 非法 / 签名错误 / 顶层过期 / IP·CIDR 不合规时**一律失败、不覆盖旧 `inbox`、不覆盖也不清空旧 `allow.txt`**；写入用临时文件 + rename 原子完成，不会出现空文件覆盖。本命令**没有 `-apply`**，永不执行 nft。

### 测试流程（RFC 日本机 → 国外 VPS 模拟 po0）

1. RFC 日本机生成 `allow.json`（token 走 header，不入 URL）：

```bash
PULL_TOKEN="$(python3 - <<'PY'
import json
print(json.load(open("/etc/nft-auth-whitelist/server.json"))["pull_token"])
PY
)"

curl -fsS \
  -H "Authorization: Bearer $PULL_TOKEN" \
  http://127.0.0.1:8088/allow.json \
  -o /tmp/nft-auth-allow.json
```

2. RFC 日本机通过 **SSH stdin** 推送（无需 scp 落地）：

```bash
cat /tmp/nft-auth-allow.json | ssh -i /etc/nft-auth-whitelist/ssh/nft_auth_push \
  nftauth@TEST_VPS
```

如果有自定义端口：

```bash
cat /tmp/nft-auth-allow.json | ssh -i /etc/nft-auth-whitelist/ssh/nft_auth_push \
  -p TEST_VPS_SSH_PORT \
  nftauth@TEST_VPS
```

3. 接收端 `~nftauth/.ssh/authorized_keys` 使用 **forced command** 把这把 key 锁死成只能运行 `nft-auth-receive`：

```text
command="/usr/local/bin/nft-auth-receive -config /etc/nft-auth-whitelist/receive.json",no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA... nft-auth-rfc-to-test-vps
```

forced command 安全边界：

- 该 key **只能执行 `nft-auth-receive`**，不能拿 shell、不能端口转发、不能执行任意命令。
- forced command 是**接真实 po0 前必须启用**的安全边界；当前普通 `authorized_keys` 只允许用于国外 VPS 测试阶段。
- 接收端不监听任何端口，不暴露写白名单 API；推送方只能投喂 signed `allow.json`，签名不对一律拒绝。
- 管理入口 **SSH 2222 永远不要纳入自动拦截**，避免锁死管理入口。

4. 在接收端查看结果：

```bash
cat /var/lib/nft-auth-whitelist/allow.txt
cat /var/lib/nft-auth-whitelist/pulled-state.json
tail -n 20 /var/log/nft-auth-whitelist/receive-audit.log
```

## 19. Auth-server automatic SSH push（v0.4.0）

把第 18 节里**手动**执行的 `curl /allow.json | ssh nftauth@TEST_VPS` 变成 auth-server 在**认证成功后自动**完成：用户认证成功 → 记录 IP → 生成 fresh signed `allow.json` → 通过 **SSH stdin** 推送到配置的接收端（接收端 forced command 自动跑 `nft-auth-receive`）。

推荐链路：

```text
Browser
  -> Cloudflare Access
  -> auth-server（Basic Auth 成功）
  -> automatic ssh push（stdin，不传远端命令）
  -> nft-auth-receive forced command（校验 HMAC/TTL/CIDR）
  -> allow.txt
```

关键行为：

- push **默认关闭**（`push.enabled=false`），不配置时行为与旧版完全一致。
- 复用与 `/allow.json` **完全相同**的 envelope 生成与签名逻辑，接收端用同一个 `hmac_secret` 校验。
- **同步**推送但每个 target 有超时（默认 10s）；多个 target 逐个独立执行，部分成功/失败分别记录与展示。
- push 失败**不影响认证记录**、**不删除 allow entry**、**不返回 500**，页面照常显示认证成功并标注 `Push failed`。
- 调用系统 `ssh`（`os/exec` 参数数组，不经 shell，不做字符串拼接，杜绝注入），**不传远端命令、不使用 scp**。
- audit 记录 `push.start` / `push.success` / `push.fail`（含 target/host/port/duration_ms/exit_status/截断后的 stdout·stderr 摘要），**绝不记录 hmac_secret / pull_token / password / Authorization / Cookie / CF Access token**；输出摘要还会主动 redact 已配置的 secret。

`server.json` push 配置示例：

```json
{
  "push": {
    "enabled": false,
    "timeout_seconds": 10,
    "targets": [
      {
        "name": "receiver-1",
        "user": "nftauth",
        "host": "RECEIVE_HOST",
        "port": 22,
        "identity_file": "/etc/nft-auth-whitelist/ssh/nft_auth_push",
        "strict_host_key_checking": true,
        "known_hosts_file": "/etc/nft-auth-whitelist/ssh/known_hosts"
      }
    ]
  }
}
```

字段：`enabled` 默认 false；`timeout_seconds` 默认 10（≤0 取默认）；`targets` 默认空（enabled=true 但为空启动报错）；`name`/`user`/`host`/`identity_file` 必填；`port` 默认 22；`strict_host_key_checking` 默认 true（缺省即 true，测试环境可显式 false，**真实 po0 必须 true**）；`known_hosts_file` 非空时附加 `-o UserKnownHostsFile=...`。

实际执行等价于（无远端命令，`allow.json` 走 stdin）：

```bash
ssh -i /etc/nft-auth-whitelist/ssh/nft_auth_push -p 22 \
  -o BatchMode=yes -o ConnectTimeout=10 \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/etc/nft-auth-whitelist/ssh/known_hosts \
  nftauth@RECEIVE_HOST
```

接收端 `~nftauth/.ssh/authorized_keys`（forced command）：

```text
command="/usr/local/bin/nft-auth-receive -config /etc/nft-auth-whitelist/receive.json",no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA... nft-auth-rfc-to-test-vps
```

准备 `known_hosts`（`strict_host_key_checking=true` 时必须，否则首次连接会因无法确认指纹而失败）。在 RFC 机器上：

```bash
ssh-keyscan -p 22 RECEIVE_HOST >> /etc/nft-auth-whitelist/ssh/known_hosts
# 或手动 ssh 一次确认 fingerprint
```

启用前先手动验证 forced command 链路可用：

```bash
PULL_TOKEN="$(python3 - <<'PY'
import json
print(json.load(open("/etc/nft-auth-whitelist/server.json"))["pull_token"])
PY
)"
curl -fsS -H "Authorization: Bearer $PULL_TOKEN" http://127.0.0.1:8088/allow.json \
  | ssh -i /etc/nft-auth-whitelist/ssh/nft_auth_push -p 22 nftauth@RECEIVE_HOST
```

确认返回 `ok entries=...` 后，再把 `server.json` 的 `push.enabled` 设为 `true` 并重启 auth-server。

安全提醒：

- 真实 po0 必须 `strict_host_key_checking=true`，并提前准备好 `known_hosts`。
- 接收端 key 必须 **forced command**：不允许 shell、不允许端口转发、不允许任意命令。
- push 失败**不会清空旧 `allow.txt`**（保留行为由接收端 `nft-auth-receive` 保证）。
- 本轮**不启用 nft / `-apply`**；接真实 po0 前先在国外 VPS 测试。
- 管理入口 **SSH 2222 永远不要纳入自动拦截**，避免锁死管理入口。

## 20. 角色化安装 / 升级 / 发布（v0.5.0）

一个根目录脚本 `install.sh` 按**角色**部署；脚本只复制文件、建目录/用户、可选装 systemd 单元，
**绝不**自动启动服务、enable nft/`--apply`、改 `sshd_config`/防火墙、覆盖已有配置，或修改
`authorized_keys`（除非显式传 `--install-authorized-key`）。详见 `docs/`。

### 角色

| 角色 | 机器 | 安装内容 |
| --- | --- | --- |
| `auth-server` | 日本 RFC 认证机 | `nft-auth-server` + 配置/数据/日志目录 + `/etc/systemd/system/nft-auth-server.service`（不 enable/start）。详见 [docs/deploy-auth-server.md](./docs/deploy-auth-server.md) |
| `receive` | 国外 VPS / 未来 po0 | `nft-auth-receive` + `nftauth` 用户 + `inbox` 目录；打印 forced command 示例（按需 SSH 启动，无常驻服务）。详见 [docs/deploy-receive.md](./docs/deploy-receive.md) |
| `puller` | 调试 / 兼容 | `nft-auth-puller` + `puller.json` / `puller-file.json` 示例（默认 export，不启用 nft/apply） |
| `all` | 仅开发/测试 | 安装三个二进制（不建议生产默认） |

### 命令

```bash
sudo ./install.sh --role auth-server
sudo ./install.sh --role receive
sudo ./install.sh --role receive --install-authorized-key /path/to/push_key.pub
sudo ./install.sh --role puller
sudo ./install.sh --update --role auth-server     # 只换二进制（先备份 *.bak.<时间戳>），不动配置
./install.sh --role auth-server --dry-run          # 只打印动作，不改系统（无需 root）
./install.sh --help
```

可选项：`--no-systemd`、`--prefix`、`--config-dir`、`--data-dir`、`--log-dir`、`--user`。
已有配置不会被覆盖：脚本改写 `<name>.json.new` 供对比。

### 私有 GitHub 仓库

先在 GitHub 建一个 **private** 仓库（不要 public），再：

```bash
git remote add origin git@github.com:misaka-cpu/nft-auth-whitelist.git
git push -u origin main          # 当前本地分支可能是 master，按需 git branch -M main
```

> 推送前务必 `bash scripts/secret-scan.sh` 确认无真实密钥/IP 泄露；`dist/`、`*.local.json`、
> 私钥等已被 `.gitignore` 忽略。

仓库公开发布后，可用一键安装（**需仓库可被 curl 访问**）：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nft-auth-whitelist/main/install.sh | bash -s -- --role auth-server
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nft-auth-whitelist/main/install.sh | bash -s -- --role receive
```

（private 仓库的一键安装需自带凭据；离线则用 `scripts/package.sh` 生成的发布包。）

### 构建 / 打包 / 自检

```bash
bash scripts/build.sh                  # 三个二进制 -> dist/
bash scripts/build.sh --all-platforms  # 另出 dist/linux-amd64、dist/linux-arm64
bash scripts/package.sh                # 生成 dist/nft-auth-whitelist-linux-{amd64,arm64}.tar.gz
bash scripts/secret-scan.sh            # 扫描密钥/令牌/私钥泄露（example 占位符放行）
bash scripts/check.sh                  # gofmt + test + vet + build + build.sh + secret-scan + test-install + test-preflight
```

发布包内含 `bin/`、`configs/`、`docs/`、`scripts/preflight-*.sh`、`install.sh`、
`README.md`、`SECURITY.md`，不含任何真实 secret。

### 安全提醒

- 真实 po0 的 push target 必须 `strict_host_key_checking=true`，接收端 key 必须 forced command。
- push / receive 失败都保留旧 `allow.txt`；不启用 nft/`--apply`；不接真实国内 po0前先在国外 VPS 测试。
- **SSH 管理端口（如 2222）永远不要纳入自动拦截。** 不提交任何真实 secret/token/password/私钥/真实 IP。

## 21. Production po0 shadow deployment（v0.6.0）

真实国内 po0 接入前先做 shadow deployment：日本 RFC auth-server 自动 SSH push 到真实 po0，
po0 的 `nft-auth-receive` forced command 只写 `allow.txt` / `pulled-state.json` /
`receive-audit.log`。此阶段**不启用 nft guard、不执行 `-apply`、不修改主项目、不修改
`/etc/nat.toml`、不拦截 SSH 2222**。完整流程见
[docs/deploy-po0-shadow.md](./docs/deploy-po0-shadow.md)。

### A. 在真实 po0 上安装 receive 角色

三选一获取项目：

```bash
# curl 一键安装（仓库可访问时）
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nft-auth-whitelist/main/install.sh | sudo bash -s -- --role receive

# git clone
git clone git@github.com:misaka-cpu/nft-auth-whitelist.git
cd nft-auth-whitelist
bash scripts/build.sh
sudo ./install.sh --role receive

# offline package
tar -xzf nft-auth-whitelist-linux-amd64.tar.gz
cd nft-auth-whitelist
sudo ./install.sh --role receive
```

### B. 编辑 receive.json

```bash
sudo vi /etc/nft-auth-whitelist/receive.json
```

确认：

- `hmac_secret` 与日本 RFC auth-server 一致。
- `audit_log` 指向 `/var/log/nft-auth-whitelist/receive-audit.log`。
- `nft.enabled=false`。
- `mode=export`。

### C. 配置 nftauth authorized_keys forced command

`/home/nftauth/.ssh/authorized_keys` 中的 push 公钥必须锁成 forced command：

```text
command="/usr/local/bin/nft-auth-receive -config /etc/nft-auth-whitelist/receive.json",no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA... nft-auth-rfc-to-po0
```

### D. 在真实 po0 上运行 receive preflight

```bash
bash scripts/preflight-receive.sh
```

默认只读输出 `PASS` / `WARN` / `FAIL`；如只需修复标准数据/日志目录权限，可显式：

```bash
bash scripts/preflight-receive.sh --fix-perms
```

`--fix-perms` 只会处理 `/var/lib/nft-auth-whitelist`、
`/var/lib/nft-auth-whitelist/inbox`、`/var/log/nft-auth-whitelist`，不会修改
`authorized_keys`。

### E. 在日本 RFC 上新增第二个 push target

在 `/etc/nft-auth-whitelist/server.json` 的 `push.targets` 中新增 `po0-shadow`，保持：

- `user=nftauth`。
- `identity_file` 指向 RFC 上的 push 私钥。
- `strict_host_key_checking=true`。
- `known_hosts_file` 指向已固定 po0 指纹的 known_hosts。

### F. 在日本 RFC 上运行 push target preflight

```bash
bash scripts/preflight-push-target.sh --target po0-shadow --ssh-test
```

`--ssh-test` 会请求远端执行 `whoami`。正确结果是 forced command 忽略 `whoami`，
`nft-auth-receive` 因 empty input 返回错误；如果输出 `whoami` 或 `nftauth`，必须 FAIL。

### G. 浏览器认证并检查 Push results

访问日本 RFC 认证页，确认页面中的 Push results 里 `po0-shadow` 为 ok。push 失败不影响认证记录，
也不会清空旧 `allow.txt`。

### H. 在真实 po0 查看旁路产物

```bash
cat /var/lib/nft-auth-whitelist/allow.txt
cat /var/lib/nft-auth-whitelist/pulled-state.json
tail -n 50 /var/log/nft-auth-whitelist/receive-audit.log
```

这些文件在 shadow mode 中只用于观察和审计，不参与防火墙决策。

## 22. TODO

- [ ] 与 nftables-nat-rust-enhanced 的 URL source whitelist 正式集成（待主项目支持）。
- [ ] 更细的 per-IP 速率限制策略。
- [ ] 可选的 entry 持久化备份 / 历史。

---

许可证：见 [LICENSE](./LICENSE)（MIT）。安全说明：见 [SECURITY.md](./SECURITY.md)。
