# 部署 receive（接收端 / 模拟 po0）

`nft-auth-receive` 跑在接收端（当前为国外 VPS 测试机，未来的国内 po0）。它**不监听任何端口**，
由 SSH forced command 按需启动：从 stdin 读签名 `allow.json`，校验 HMAC/TTL/CIDR 后原子写
`inbox` 并导出 `allow.txt`。

## 1. 构建并安装

```bash
bash scripts/build.sh
sudo ./install.sh --role receive
```

`--role receive` 会：

- 创建系统用户 `nftauth`（带 home，shell `/bin/bash`——安全由 forced command 保证，不靠 nologin）；
- 创建 `/etc/nft-auth-whitelist`、`/var/lib/nft-auth-whitelist/inbox`、`/var/log/nft-auth-whitelist`
  并把数据/日志目录 chown 给 `nftauth`；
- 安装 `/usr/local/bin/nft-auth-receive`（已存在则先备份）；
- 安装示例配置为 `/etc/nft-auth-whitelist/receive.json`（**已存在则不覆盖**）；
- 打印 forced command authorized_keys 示例（**默认不修改 authorized_keys**）。

## 2. 配置

```bash
sudo vi /etc/nft-auth-whitelist/receive.json     # 设置与 RFC 一致的 hmac_secret
```

## 3. 安装 forced command key

接收端的 `~nftauth/.ssh/authorized_keys` 必须把推送方的 **公钥** 锁成只能运行 receive：

```text
command="/usr/local/bin/nft-auth-receive -config /etc/nft-auth-whitelist/receive.json",no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA... nft-auth-push
```

可以让安装脚本帮你追加（只有显式传参时才会改 authorized_keys）：

```bash
sudo ./install.sh --role receive --install-authorized-key /path/to/push_key.pub
```

它会幂等地追加 forced command 行（已存在同一把 key 则跳过）。

## 4. 验证

从推送方手动投喂一次（详见 [automatic-push.md](./automatic-push.md)）：

```bash
cat /tmp/nft-auth-allow.json | ssh -i /etc/nft-auth-whitelist/ssh/nft_auth_push \
  -p 22 nftauth@RECEIVE_HOST
# 期望输出： ok entries=N output=/var/lib/nft-auth-whitelist/allow.txt
```

确认 `ssh nftauth@RECEIVE_HOST whoami` **不会**给你 shell（forced command 生效）。

## 5. 安全边界

- key 必须 forced command：无 shell、无端口转发、无任意命令。
- 任何校验失败都保留旧 `allow.txt`，不覆盖旧 `inbox`。
- 不启用 nft / `--apply`；**SSH 管理端口（如 2222）不要纳入任何自动拦截**。
