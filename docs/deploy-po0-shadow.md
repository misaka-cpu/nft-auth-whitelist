# Production po0 shadow deployment

本文用于把真实国内 po0 先接成 **shadow mode**：RFC 内网机器 auth-server 通过 SSH push 触发
po0 上的 `nft-auth-receive` forced command，接收端只落地 `allow.txt`、
`pulled-state.json` 和 `receive-audit.log`，不影响现有转发业务。

## 什么是 shadow mode

shadow mode 是只观察、不拦截的部署方式：

```text
RFC 内网机器 auth-server
  -> SSH stdin push
  -> 国内 po0 nft-auth-receive forced command
  -> /var/lib/nft-auth-whitelist/allow.txt
  -> /var/lib/nft-auth-whitelist/pulled-state.json
  -> /var/log/nft-auth-whitelist/receive-audit.log
```

此阶段只验证“认证后出口 IP 是否能安全到达真实 po0 并生成旁路白名单”。生成的
`allow.txt` 暂不接入 nftables，不接入主项目，不保护任何端口。

## 为什么先只生成 allow.txt

- 可以验证 `hmac_secret`、TTL、CIDR、地址族过滤和原子写是否正常。
- 可以在真实 po0 上审计 `receive-audit.log`，确认 push 成功/失败不会覆盖旧结果。
- 可以确认 forced command 生效，push key 不能拿 shell，也不能端口转发。
- 可以在不改变现网转发路径的情况下观察真实用户出口 IP。

## 明确保持关闭

- 不启用 nft guard。
- 不执行 `-apply`。
- 不执行任何 `nft` 命令。
- 不修改 nftables-nat-rust-enhanced 主项目。
- 不修改 `/etc/nat.toml`。
- 不拦截 SSH 管理端口 `2222`。
- 不自动修改 `authorized_keys`。
- 不自动修改 `sshd_config`。
- 不开放或调整防火墙。

## 接真实 po0 前的安全检查

在真实 po0 上：

```bash
sudo ./install.sh --role receive
sudo vi /etc/nft-auth-whitelist/receive.json
bash scripts/preflight-receive.sh
```

`receive.json` 必须满足：

- `hmac_secret` 与 RFC 内网机器 auth-server 一致，且不是示例占位符。
- `mode` 为 `export`。
- `nft.enabled=false`。
- `audit_log` 指向 `/var/log/nft-auth-whitelist/receive-audit.log`。

`~nftauth/.ssh/authorized_keys` 必须使用 forced command：

```text
command="/usr/local/bin/nft-auth-receive -config /etc/nft-auth-whitelist/receive.json",no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA... nft-auth-push
```

在 RFC 内网机器上配置第二个 push target，例如 `po0-shadow`，并保持：

- `strict_host_key_checking=true`。
- `known_hosts_file` 已固定真实 po0 主机指纹。
- `identity_file` 存在且权限为 `0600` 或 `0400`。

然后运行：

```bash
bash scripts/preflight-push-target.sh --target po0-shadow --ssh-test
```

`--ssh-test` 会请求远端执行 `whoami`。正确结果不是 `whoami` 成功，而是
`nft-auth-receive` 因 empty input 失败；如果输出 `nftauth` 或 `whoami`，说明 shell 可用，
forced command 没生效，必须停止接入。

## 影子验证

浏览器访问 RFC 内网机器认证页，确认页面的 Push results 中 `po0-shadow` 为 ok。随后在真实 po0：

```bash
cat /var/lib/nft-auth-whitelist/allow.txt
cat /var/lib/nft-auth-whitelist/pulled-state.json
tail -n 50 /var/log/nft-auth-whitelist/receive-audit.log
```

只要仍处于 shadow mode，这些文件只是旁路产物，不参与防火墙决策。

## 回滚方式

- 在 RFC 内网机器 `server.json` 中删除或禁用 `po0-shadow` target，然后重启 auth-server。
- 或从真实 po0 的 `~nftauth/.ssh/authorized_keys` 中移除对应 push 公钥。
- 如需保留审计，可只移动旧 `allow.txt` / `pulled-state.json` / audit log；不需要改主项目。
- 不需要修改 `/etc/nat.toml`，也不需要清理 nft 规则，因为本流程没有创建或应用任何 nft 规则。
