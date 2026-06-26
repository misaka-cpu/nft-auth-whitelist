# auth-server 自动 SSH push

用户点击认证按钮并 POST 认证成功后，auth-server 生成 fresh 签名 `allow.json` 并通过 **SSH stdin** 推送到配置的接收端
（接收端 forced command 自动运行 `nft-auth-receive`）。默认关闭，`push.enabled=false` 时仍只完成认证记录，不自动推送。

链路：

```text
Browser -> Cloudflare Access -> auth-server（Basic Auth + POST /）
  -> automatic ssh push（stdin，不传远端命令、不用 scp）
  -> nft-auth-receive forced command（校验 HMAC/TTL/CIDR）
  -> allow.txt
```

## 1. 准备 push 私钥与 known_hosts

```bash
sudo install -d -m 0700 /etc/nft-auth-whitelist/ssh
sudo ssh-keygen -t ed25519 -N '' -f /etc/nft-auth-whitelist/ssh/nft_auth_push
# 把 /etc/nft-auth-whitelist/ssh/nft_auth_push.pub 装到接收端 forced command（见 deploy-receive.md）

# strict_host_key_checking=true 时必须先确认指纹：
sudo ssh-keyscan -p 22 RECEIVE_HOST >> /etc/nft-auth-whitelist/ssh/known_hosts
```

## 2. 配置 server.json 的 push 块

```json
{
  "push": {
    "enabled": true,
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

字段：`enabled` 默认 false；`timeout_seconds` 默认 10；`name`/`user`/`host`/`identity_file` 必填；
`port` 默认 22；`strict_host_key_checking` 默认 true（**真实 po0 必须 true**）。

## 3. 启用前先手动验证链路

```bash
PULL_TOKEN="$(python3 - <<'PY'
import json
print(json.load(open("/etc/nft-auth-whitelist/server.json"))["pull_token"])
PY
)"
curl -fsS -H "Authorization: Bearer $PULL_TOKEN" http://127.0.0.1:8088/allow.json \
  | ssh -i /etc/nft-auth-whitelist/ssh/nft_auth_push -p 22 nftauth@RECEIVE_HOST
# 期望： ok entries=N output=...
```

确认无误后把 `push.enabled` 设为 `true` 并 `systemctl restart nft-auth-server.service`。

## 4. 行为与安全

- 同步推送、每个 target 各自超时；多个 target 逐个独立执行，部分成功/失败分别记录。
- push 失败**不影响认证记录、不删 entry、不返回 500、不清空旧 `allow.txt`**；页面标注 `Push failed`。
- 调用系统 `ssh`（参数数组，不经 shell，不用 scp，不传远端命令）。
- audit 记 `push.start` / `push.success` / `push.fail`，**绝不记录 secret/token/password**；摘要会 redact。
- **不启用 nft / `--apply`**；**SSH 管理端口不要纳入自动拦截**。
