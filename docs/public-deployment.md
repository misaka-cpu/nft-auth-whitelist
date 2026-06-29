# Public Deployment Guide

本文是公开仓库面向新手的部署入口。文档统一使用 **RFC 内网机器** 这个名字，不绑定某个地区；RFC HK / JP / SG / US 等不同地区机器都按同一套角色理解。

这份教程走推荐的生产链路：用户先通过 Cloudflare Access 进入认证页，auth-server 记录当前出口 IP，然后通过 SSH forced command 把签名白名单推到 po0，po0 再把 `allow.txt` 交给转发/防火墙读取。

## 0. 拓扑和角色

最常见的完整链路：

```text
用户浏览器
  -> Cloudflare Access
  -> HTTPS 反代（Caddy / Nginx）
  -> RFC 内网机器：nft-auth-server
  -> SSH stdin push signed allow.json
  -> po0：nft-auth-receive forced command
  -> /var/lib/nft-auth-whitelist/allow.txt
  -> nftables-nat-rust-enhanced 动态白名单文件源
  -> RFC 内网机器上的真实服务端口
```

三个角色：

| 角色 | 运行位置 | 做什么 |
| --- | --- | --- |
| `auth-server` | RFC 内网机器 | 提供认证页，记录用户当前公网出口 IP，生成签名 allowlist |
| `receive` | po0 | 用 SSH forced command 接收签名 allowlist，导出 `allow.txt` |
| `target guard` | RFC 内网机器 | 用防火墙保护真实服务端口，只允许 po0 的真实出站源访问 |

`target guard` 当前不是本项目的二进制角色；它是部署步骤中的 nftables 规则。公开教程只给安全模板，生产前必须确认 po0 到 RFC 内网机器时 RFC 看到的真实源地址。

## 1. 开始前准备

下面的占位符先替换成你自己的值：

| 占位符 | 含义 |
| --- | --- |
| `AUTH_DOMAIN` | 认证页域名，例如 `auth.example.com` |
| `RFC_PUBLIC_IP` | RFC 内网机器公网 IP |
| `PO0_PUBLIC_IP` | po0 公网 IP |
| `PO0_SSH_PORT` | po0 上给 `nftauth` forced command 使用的 SSH 端口 |
| `FORWARD_PORT` | po0 对外转发端口，例如 `40000` |
| `TARGET_PORT` | RFC 内网机器上的真实服务端口 |
| `PO0_SOURCE_SEEN_BY_RFC` | RFC 内网机器看到的 po0 出站源地址 |

两个重要原则：

- 先让 `receive` 只生成 `allow.txt`，确认认证 IP 能同步到 po0 后，再接入 NAT / 防火墙。
- 不要把 SSH 管理端口放进自动拦截规则。先保留一条独立的管理入口，确认回滚方式可用。

## 2. 安装方式

新手第一次部署，推荐下载 release tarball。这样后面可以直接使用包内的 `scripts/preflight-*.sh` 诊断脚本：

```bash
curl -fsSLO https://github.com/misaka-cpu/nft-auth-whitelist/releases/latest/download/nft-auth-whitelist-linux-amd64.tar.gz
curl -fsSLO https://github.com/misaka-cpu/nft-auth-whitelist/releases/latest/download/nft-auth-whitelist-linux-amd64.tar.gz.sha256
sha256sum -c nft-auth-whitelist-linux-amd64.tar.gz.sha256
tar -xzf nft-auth-whitelist-linux-amd64.tar.gz
cd nft-auth-whitelist
```

ARM64 机器把 `linux-amd64` 换成 `linux-arm64`。

熟练后也可以用一键安装脚本。它只下载 release tarball、校验 `.sha256`、解压并调用包内 `install.sh`；仍然不会自动启动服务、不会改 nft、不会改 SSH 防火墙：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nft-auth-whitelist/main/scripts/install-release.sh \
  | sudo bash -s -- --role auth-server
```

po0 接收端：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nft-auth-whitelist/main/scripts/install-release.sh \
  | sudo bash -s -- --role receive
```

## 3. RFC 内网机器：auth-server

在 RFC 内网机器上安装 auth-server：

```bash
sudo ./install.sh --role auth-server
sudo vi /etc/nft-auth-whitelist/server.json
```

必须改掉示例值：

- `username`
- `password`
- `pull_token`
- `hmac_secret`
- `base_url`

可以用下面的命令生成随机值：

```bash
openssl rand -hex 32
```

建议监听保持本地，只让 Caddy / Nginx 反代访问：

```json
{
  "listen": "127.0.0.1:8088",
  "base_url": "https://AUTH_DOMAIN",
  "trusted_proxy_cidrs": ["127.0.0.1/32", "::1/128"],
  "client_ip_headers": ["CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"]
}
```

只有当前置 Caddy / Nginx 在同一台机器上反代到 `127.0.0.1:8088` 时，才按上面信任本机回环地址。不要把 `0.0.0.0/0` 或 `::/0` 放进 `trusted_proxy_cidrs`。

## 4. Cloudflare Access 设置

Cloudflare 官方文档入口：

- Self-hosted application: <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/>
- Access policies: <https://developers.cloudflare.com/cloudflare-one/access-controls/policies/>
- `CF-Connecting-IP` header: <https://developers.cloudflare.com/fundamentals/reference/http-headers/>

推荐流程：

1. 在 Cloudflare DNS 中把 `AUTH_DOMAIN` 指向 `RFC_PUBLIC_IP`，并开启代理。
2. 在 Zero Trust / Access 中创建 self-hosted application，Public hostname 填 `AUTH_DOMAIN`。
3. 给这个 application 添加 Access policy，例如只允许你的邮箱、GitHub 组织、Google Workspace 用户或 One-time PIN。
4. RFC 内网机器上让 Caddy / Nginx 终止 HTTPS，然后反代到 `127.0.0.1:8088`。
5. 反代显式传递 `CF-Connecting-IP`，auth-server 只在 `trusted_proxy_cidrs` 命中本机反代时读取这个 header。

Caddy 示例：

```caddy
AUTH_DOMAIN {
    reverse_proxy 127.0.0.1:8088 {
        header_up CF-Connecting-IP {http.request.header.CF-Connecting-IP}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

Nginx 示例：

```nginx
location / {
    proxy_pass http://127.0.0.1:8088;
    proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Cloudflare Access 负责“人登录”；本项目负责“记录当前出口 IP + 签名白名单”。两者不是互相替代关系。

## 5. po0：receive forced command

在 po0 上安装 receive：

```bash
sudo ./install.sh --role receive
sudo vi /etc/nft-auth-whitelist/receive.json
```

确认：

- `hmac_secret` 与 RFC 内网机器 auth-server 一致。
- `max_entries` 与 RFC 内网机器 auth-server 保持一致；不确定时两边都保留默认 `200`。
- `mode` 是 `export`。
- `nft.enabled` 是 `false`。
- `output_allow_txt` 指向 `/var/lib/nft-auth-whitelist/allow.txt`。

在 RFC 内网机器上生成专用 push key：

```bash
sudo install -d -m 0700 /etc/nft-auth-whitelist/ssh
sudo ssh-keygen -t ed25519 -N '' -f /etc/nft-auth-whitelist/ssh/nft_auth_push
sudo cat /etc/nft-auth-whitelist/ssh/nft_auth_push.pub
```

把上一步输出的公钥复制到 po0，例如保存成 `/tmp/nft_auth_push.pub`。然后在 po0 上安装 forced command：

```bash
sudo ./install.sh --role receive --install-authorized-key /tmp/nft_auth_push.pub
sudo bash scripts/preflight-receive.sh --config /etc/nft-auth-whitelist/receive.json --user nftauth
```

最终 `~nftauth/.ssh/authorized_keys` 应该是这种形式：

```text
command="/usr/local/bin/nft-auth-receive -config /etc/nft-auth-whitelist/receive.json",no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA... nft-auth-push
```

如果 preflight 报 authorized_keys 没有 forced command，不要继续接入生产。

## 6. RFC 内网机器：配置自动 SSH push

在 RFC 内网机器上固定 po0 的 SSH 主机指纹：

```bash
sudo sh -c 'ssh-keyscan -p PO0_SSH_PORT PO0_PUBLIC_IP > /etc/nft-auth-whitelist/ssh/known_hosts'
sudo chmod 0644 /etc/nft-auth-whitelist/ssh/known_hosts
```

生产环境里，`ssh-keyscan` 得到的指纹应和你从云厂商控制台或首次 SSH 登录时确认的指纹一致；不要在被劫持的网络里盲目信任第一次扫描结果。

然后编辑 `/etc/nft-auth-whitelist/server.json` 的 `push` 块：

```json
{
  "push": {
    "enabled": true,
    "timeout_seconds": 10,
    "targets": [
      {
        "name": "po0",
        "user": "nftauth",
        "host": "PO0_PUBLIC_IP",
        "port": 22,
        "identity_file": "/etc/nft-auth-whitelist/ssh/nft_auth_push",
        "strict_host_key_checking": true,
        "known_hosts_file": "/etc/nft-auth-whitelist/ssh/known_hosts"
      }
    ]
  }
}
```

如果 po0 SSH 不是 22，把 `"port": 22` 改成你的 `PO0_SSH_PORT`。

先做一次手动 push 验证：

```bash
PULL_TOKEN="$(sudo python3 -c 'import json; print(json.load(open("/etc/nft-auth-whitelist/server.json"))["pull_token"])')"
curl -fsS -H "Authorization: Bearer ${PULL_TOKEN}" http://127.0.0.1:8088/allow.json \
  -o /tmp/nft-auth-allow.json
sudo ssh -i /etc/nft-auth-whitelist/ssh/nft_auth_push \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/etc/nft-auth-whitelist/ssh/known_hosts \
  -p PO0_SSH_PORT nftauth@PO0_PUBLIC_IP < /tmp/nft-auth-allow.json
rm -f /tmp/nft-auth-allow.json
```

期望输出类似：

```text
ok entries=N output=/var/lib/nft-auth-whitelist/allow.txt
```

确认无误后启动服务：

```bash
sudo systemctl enable --now nft-auth-whitelist-server.service
curl -fsS http://127.0.0.1:8088/health
```

返回 `ok` 才继续下一步。

## 7. 多端口转发和防火墙

10 多个端口没有问题。推荐做法：

- po0 NAT 里为每个端口配置转发到 RFC 内网机器。
- po0 NAT 的访问控制统一读取 `/var/lib/nft-auth-whitelist/allow.txt`。
- RFC 内网机器上真实服务端口只允许 `PO0_SOURCE_SEEN_BY_RFC` 访问。
- 不要把 SSH 管理端口放进自动拦截规则；先用带回滚的 nft 规则测试。

注意：空白名单会让受保护端口对所有来源都不可达，直到新的认证记录写入或你恢复上一份有效 `allow.txt`。首次部署时先确认至少有一条自己的 CIDR 出现在 `allow.txt`，再把它接入 NAT / guard。

如果 po0 是云厂商 NAT 公网 IP，RFC 内网机器看到的源地址可能不是 po0 公网 IP。先在 RFC 内网机器抓包或看日志确认真实来源，再写 target guard。

## 8. 验证

最少验证六件事：

1. 浏览器通过 Cloudflare Access 访问认证页，页面显示的 CIDR 是你的当前出口 IP。
2. 点击认证按钮后，po0 的 `/var/lib/nft-auth-whitelist/allow.txt` 出现同一个 CIDR。
3. RFC 内网机器上 `journalctl -u nft-auth-whitelist-server.service -n 50 --no-pager` 没有 push 错误。
4. po0 上 `tail -n 50 /var/log/nft-auth-whitelist/receive-audit.log` 能看到 `receive.success`。
5. 未认证来源访问 po0 转发端口超时或 filtered。
6. 未认证来源直连 RFC 内网机器真实服务端口超时或 filtered。

可选验证：

```bash
ping PO0_PUBLIC_IP
nc -vz PO0_PUBLIC_IP FORWARD_PORT
nc -vz RFC_INTERNAL_MACHINE_IP TARGET_PORT
```

如果你禁用了 ICMP echo，ping 不通是预期结果。

## 9. 常见问题

### 认证后 po0 没有更新 allow.txt

先看 RFC 内网机器服务日志：

```bash
sudo journalctl -u nft-auth-whitelist-server.service -n 100 --no-pager
```

再看 po0 接收日志：

```bash
sudo tail -n 100 /var/log/nft-auth-whitelist/receive-audit.log
```

常见原因：

- `hmac_secret` 两边不一致。
- po0 的公钥没有 forced command，或装错用户。
- `known_hosts_file` 里不是当前 po0 的 SSH 指纹。
- `server.json` 的 push `port` 没改成实际 SSH 端口。

### 页面显示的 IP 不是我的真实公网 IP

检查三处：

- Cloudflare Access 前面是否真的走了代理。
- Caddy / Nginx 是否把 `CF-Connecting-IP` 传给 auth-server。
- `trusted_proxy_cidrs` 是否只信任本机反代地址，而不是随便信任所有来源。

### 一启防火墙就把自己锁外面

说明 SSH 管理入口和业务保护规则混在一起了。恢复前不要继续自动化接入：

- 先用云厂商控制台或救援模式恢复 SSH。
- 保留一个独立 SSH 管理端口，不放进动态白名单规则。
- 先在测试机验证 nft 规则，再迁移到年付或生产机器。

### 多个转发端口是否要多份白名单

通常不需要。多个端口共用 `/var/lib/nft-auth-whitelist/allow.txt` 即可。真正要区分的是 RFC 内网机器上每个真实服务端口是否只允许 po0 的真实出站源访问。
