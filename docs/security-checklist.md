# 安全检查清单

部署 / 提交前逐项确认。完整说明见 [../SECURITY.md](../SECURITY.md)。

## 提交到 git 前

- [ ] 运行 `bash scripts/secret-scan.sh`，无 error。
- [ ] 没有真实 `hmac_secret` / `pull_token` / `password`（仓库只放 `*.example.json` 占位符）。
- [ ] 没有 SSH 私钥（`id_*` / `*.pem` / `*.key`）。
- [ ] 没有真实接收端 IP / 端口 / 内网拓扑（示例用 `RECEIVE_HOST`）。
- [ ] 没有 `Authorization: Bearer ...` / `Cookie` / `CF_Authorization` 真实值。
- [ ] 真实配置走 `*.local.json` 或 `/etc/...`（已被 `.gitignore` 忽略）。

## auth-server

- [ ] 部署在 HTTPS 反代之后，未在纯 HTTP 下使用 Basic Auth。
- [ ] 监听 `127.0.0.1`，公网不能直连。
- [ ] `username` / `password` / `pull_token` / `hmac_secret` 为强随机值。
- [ ] 只信任明确配置的 `trusted_proxy_cidrs`，未加入 `0.0.0.0/0` 或 `::/0`。
- [ ] push 私钥放 `/etc/nft-auth-whitelist/ssh/`（`0600`），不依赖 `/root/.ssh`。

## receive / push

- [ ] 接收端 key 为 **forced command**：无 shell、无端口转发、无任意命令。
- [ ] forced command 测试中请求 `whoami` 不会执行；期望看到 receive empty input 类错误。
- [ ] 真实 po0 的 push target `strict_host_key_checking=true`，且已备好 `known_hosts`。
- [ ] `known_hosts` 已固定真实 po0 主机指纹，不依赖首次连接交互确认。
- [ ] `hmac_secret` 未泄露，且 receive 端与日本 RFC auth-server 一致。
- [ ] `allow.txt` 只是旁路文件，未接入自动拦截。
- [ ] receive 端 `nft.enabled=false`，`mode=export`。
- [ ] 没有给 receive 设计或启用 systemd 常驻服务；只通过 SSH forced command 按需启动。
- [ ] 校验失败保留旧 `allow.txt`，不覆盖旧 `inbox`。
- [ ] audit / 页面不含任何 secret / token / password。

## 防火墙 / 主项目

- [ ] 未启用 nft guard，未使用 `--apply`。
- [ ] **SSH 管理端口（如 2222）未纳入任何自动拦截规则。**
- [ ] 未修改 nftables-nat-rust-enhanced 主项目，未改 `/etc/nat.toml`。
- [ ] 未自动改 `authorized_keys`（除非显式 `--install-authorized-key`）/ `sshd_config` / 防火墙。
