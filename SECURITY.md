# 安全说明 (SECURITY)

本项目是一个 **sidecar 配套项目**，刻意保持简单、可审计。请在部署前阅读以下安全注意事项。

## 威胁模型与边界

- auth-server 通过 **HTTP Basic Auth** 校验用户，**必须部署在 HTTPS 反代之后**（Caddy / Nginx / 自有反代）。
  在纯 HTTP 下使用 Basic Auth 会以明文形式传输凭据，**禁止这样做**。
- auth-server 默认监听 `127.0.0.1:8088`，不直接暴露公网，依赖反代终止 TLS。
- 只记录 **认证请求的来源 IP**，不接受任何用户自行提交的 IP 参数。
- 每条记录都有 **TTL**（默认 6 小时 / 21600 秒），到期自动删除，**不会永久加白**。
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

- 默认使用 `RemoteAddr`。
- 只有当请求来自配置的 `trusted_proxies` 时，才会信任 `real_ip_header`（如 `X-Forwarded-For`，只取第一跳）。
- **不要直接信任公网伪造的 `X-Forwarded-For`**。
- 如果套了 Cloudflare / 公共 CDN，服务端看到的可能不是用户真实 IP；建议不要套公共 CDN，
  或仅在可信反代后启用 `real_ip_header`。

## 签名

- `allow.json` 使用 `hmac_secret` 对去掉 `signature` 字段后的 canonical JSON 做 HMAC-SHA256。
- puller 必须验证签名；验证失败会拒绝新结果并保留上一次成功结果。

## 报告问题

这是一个示例 / 配套项目，请通过你获取本项目的渠道反馈安全问题，不要在公开 issue 中附带真实密钥或真实 IP。
