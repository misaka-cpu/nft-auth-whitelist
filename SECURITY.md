# 安全说明 (SECURITY)

本项目是一个 **sidecar 配套项目**，刻意保持简单、可审计。请在部署前阅读以下安全注意事项。

## 威胁模型与边界

- auth-server 通过 **HTTP Basic Auth** 校验用户，可叠加 Cloudflare Access 作为外层前门，**必须部署在 HTTPS 反代之后**（Caddy / Nginx / 自有反代）。
  在纯 HTTP 下使用 Basic Auth 会以明文形式传输凭据，**禁止这样做**。
- auth-server 默认监听 `127.0.0.1:8088`，不直接暴露公网，依赖反代终止 TLS。
- 只记录 **认证请求的来源 IP**，不接受任何用户自行提交的 IP 参数。
- 每条记录都有 **TTL**（默认 14 天 / 1209600 秒），到期自动删除，**不会永久加白**。
- 默认只记录 IPv4 `/32`。`/24` 扩展必须在配置中显式开启，且页面会显示风险提示。
- po0 上的 puller **主动拉取**，**不暴露任何远程修改白名单的 API**。
- 默认 `mode=export`，只导出 `allow.txt`，**不执行真实 `nft -f`**。
- 可选的 nft guard 必须同时满足「配置开启」+「命令行 `--apply`」才会真正执行。

## 凭据与日志

- `password` / `pull_token` / `hmac_secret` **绝不会写入审计日志或普通日志**。
- 登录失败只记录来源 IP，不记录提交的密码。
- 请为 `username` / `password` / `pull_token` / `hmac_secret` 使用强随机值，并在 RFC 与 po0 两侧保持
  `pull_token` 与 `hmac_secret` 一致。
- 配置文件包含密钥，安装时权限为 `0600`，请勿提交到版本库。

## 真实来源 IP

- 默认使用 `RemoteAddr`，不读取任何客户端 IP header。
- 只有当请求的 `RemoteAddr` 命中配置的 `trusted_proxy_cidrs` 时，才会按
  `client_ip_headers` 优先级读取 `CF-Connecting-IP` / `X-Real-IP` / `X-Forwarded-For`。
- `CF-Connecting-IP` 和 `X-Real-IP` 必须是单个合法 IP；`X-Forwarded-For` 只取第一个合法 IP。
- **不要直接信任公网伪造的 `CF-Connecting-IP` 或 `X-Forwarded-For`**。
- Cloudflare Access 只负责“人登录”；本项目仍只记录认证请求的来源 IP，不接受用户提交任意 IP。
- 如果 auth-server 只监听 `127.0.0.1` 并由本机 Caddy/Nginx 反代，可以把
  `127.0.0.1/32` 和 `::1/128` 配进 `trusted_proxy_cidrs`。
- 不要把公网来源全部加入 `trusted_proxy_cidrs`，也不要在生产中配置 `0.0.0.0/0` 或 `::/0`。

## 签名

- `allow.json` 使用 `hmac_secret` 对去掉 `signature` 字段后的 canonical JSON 做 HMAC-SHA256。
- puller 必须验证签名；验证失败会拒绝新结果并保留上一次成功结果。

## 提交到版本库前（绝不要提交的内容）

仓库只应包含 **占位符** 配置（`configs/*.example.json`），真实配置走 `*.local.json` 或
`/etc/nft-auth-whitelist/*.json`（均已被 `.gitignore` 忽略）。提交前请运行
`bash scripts/secret-scan.sh`，以下内容**绝不能进入 git**：

- `hmac_secret` 的真实值；
- `pull_token` 的真实值；
- Basic Auth `password` 的真实值；
- 任何 SSH 私钥（`id_ed25519` / `*.pem` / `*.key` 等私钥文件）；
- `Authorization: Bearer ...`、`Cookie`、`CF_Authorization` 等真实凭据；
- 真实的 po0 / 接收端 IP、端口、内网拓扑等敏感信息（示例一律用 `RECEIVE_HOST` 占位）。

`scripts/secret-scan.sh` 会对上述模式给出 **error 并以非 0 退出**；example 文件中的占位符
（如 `change-me-hmac-secret`、`RECEIVE_HOST`）是允许的。

## SSH push 与接收端（receive）

- 接收端的 `authorized_keys` **必须使用 forced command**，把推送方那把 key 锁死成只能运行
  `nft-auth-receive`：不允许 shell、不允许端口转发、不允许任意命令
  （`no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding`）。
- 生产 / 真实 po0 的 push target **必须 `strict_host_key_checking=true`**，并提前准备好
  `known_hosts`；`false` 只允许在国外 VPS 测试阶段临时使用。
- push 私钥建议放在 `/etc/nft-auth-whitelist/ssh/` 下（权限 `0600`），**不要依赖 `/root/.ssh`**。
- auth-server 的 push **失败不会影响认证记录、不会删除 allow entry、不会清空旧 `allow.txt`**；
  接收端任何校验失败都保留上一次成功的 `allow.txt`。
- push 的 stdout/stderr 摘要会截断并 redact 已配置 secret，**不会把密钥/令牌写入审计日志或页面**。

## 防火墙与管理入口

- **SSH 管理端口（如 2222）永远不要纳入任何自动拦截规则**，避免把自己锁在门外。
- 本项目默认 `mode=export`，**不启用 nft guard、不执行 `--apply`**；真正改动防火墙必须同时
  「配置开启 guard」+「显式 `--apply`」，且本阶段不接真实国内 po0。

## 报告问题

这是一个示例 / 配套项目，请通过你获取本项目的渠道反馈安全问题，不要在公开 issue 中附带真实密钥或真实 IP。
