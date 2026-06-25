# Public Deployment Guide

本文是公开仓库面向新手的部署入口。文档统一使用 **RFC 内网机器** 这个名字，不绑定某个地区；RFC HK / JP / SG / US 等不同地区机器都按同一套角色理解。

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

## 1. 推荐安装方式

公开 release 发布后，可以用一键安装脚本。它只下载 release tarball、校验可用的 `.sha256`、解压并调用包内 `install.sh`；安装脚本仍然不会自动启动服务、不会改 nft、不会改 SSH 防火墙。

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nft-auth-whitelist/main/scripts/install-release.sh \
  | sudo bash -s -- --role auth-server
```

po0 接收端：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nft-auth-whitelist/main/scripts/install-release.sh \
  | sudo bash -s -- --role receive
```

更谨慎的手动方式：

```bash
curl -fsSLO https://github.com/misaka-cpu/nft-auth-whitelist/releases/latest/download/nft-auth-whitelist-linux-amd64.tar.gz
curl -fsSLO https://github.com/misaka-cpu/nft-auth-whitelist/releases/latest/download/nft-auth-whitelist-linux-amd64.tar.gz.sha256
sha256sum -c nft-auth-whitelist-linux-amd64.tar.gz.sha256
tar -xzf nft-auth-whitelist-linux-amd64.tar.gz
cd nft-auth-whitelist
sudo ./install.sh --role auth-server
```

ARM64 机器把 `linux-amd64` 换成 `linux-arm64`。

## 2. RFC 内网机器：auth-server

安装：

```bash
sudo ./install.sh --role auth-server
sudo vi /etc/nft-auth-whitelist/server.json
```

必须改掉示例值：

- `username`
- `password`
- `pull_token`
- `hmac_secret`

建议监听保持本地：

```json
{
  "listen": "127.0.0.1:8088",
  "trusted_proxy_cidrs": ["127.0.0.1/32", "::1/128"],
  "client_ip_headers": ["CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"]
}
```

只有当前置 Caddy / Nginx 在同一台机器上反代到 `127.0.0.1:8088` 时，才按上面信任本机回环地址。不要把 `0.0.0.0/0` 或 `::/0` 放进 `trusted_proxy_cidrs`。

## 3. Cloudflare Access 设置

Cloudflare 官方文档入口：

- Self-hosted application: <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/>
- Access policies: <https://developers.cloudflare.com/cloudflare-one/access-controls/policies/>
- `CF-Connecting-IP` header: <https://developers.cloudflare.com/fundamentals/reference/http-headers/>

推荐流程：

1. 在 Cloudflare DNS 中把 `auth.example.com` 指向 RFC 内网机器公网 IP，并开启代理。
2. 在 Zero Trust / Access 中创建 self-hosted application，Public hostname 填 `auth.example.com`。
3. 给这个 application 添加 Access policy，例如只允许你的邮箱、GitHub 组织、Google Workspace 用户或 One-time PIN。
4. RFC 内网机器上让 Caddy / Nginx 终止 HTTPS，然后反代到 `127.0.0.1:8088`。
5. 反代显式传递 `CF-Connecting-IP`，auth-server 只在 `trusted_proxy_cidrs` 命中本机反代时读取这个 header。

Caddy 示例：

```caddy
auth.example.com {
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

## 4. po0：receive forced command

在 po0 上安装 receive：

```bash
sudo ./install.sh --role receive
sudo vi /etc/nft-auth-whitelist/receive.json
```

确认：

- `hmac_secret` 与 RFC 内网机器 auth-server 一致。
- `max_entries` 与 RFC 内网机器 auth-server 保持一致；不确定时两边都保留默认 `200`。
- `mode=export`。
- `nft.enabled=false`。
- `output_allow_txt` 指向 `/var/lib/nft-auth-whitelist/allow.txt`。

把 RFC 内网机器上的 push 公钥装进 `~nftauth/.ssh/authorized_keys`，必须使用 forced command：

```text
command="/usr/local/bin/nft-auth-receive -config /etc/nft-auth-whitelist/receive.json",no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA... nft-auth-push
```

然后运行：

```bash
sudo bash scripts/preflight-receive.sh --config /etc/nft-auth-whitelist/receive.json --user nftauth
```

## 5. 多端口转发

10 多个端口没有问题。推荐做法：

- po0 NAT 里为每个端口配置转发到 RFC 内网机器。
- po0 NAT 的访问控制统一读取 `/var/lib/nft-auth-whitelist/allow.txt`。
- RFC 内网机器上真实服务端口只允许 po0 的真实出站源访问。
- 不要把 SSH 管理端口放进自动拦截规则；先用带回滚的 nft 规则测试。

注意：空白名单会让受保护端口对所有来源都不可达，直到新的认证记录写入或你恢复上一份有效 `allow.txt`。首次部署时先确认至少有一条自己的 CIDR 出现在 `allow.txt`，再把它接入 NAT / guard。

如果 po0 是云厂商 NAT 公网 IP，RFC 内网机器看到的源地址可能不是 po0 公网 IP。先在 RFC 内网机器抓包或看日志确认真实来源，再写 target guard。

## 6. 验证

最少验证四件事：

1. 浏览器通过 Cloudflare Access 访问认证页，页面显示的 CIDR 是你的当前出口 IP。
2. po0 的 `/var/lib/nft-auth-whitelist/allow.txt` 出现同一个 CIDR。
3. 未认证来源访问 po0 转发端口超时或 filtered。
4. 未认证来源直连 RFC 内网机器真实服务端口超时或 filtered。

可选验证：

```bash
ping PO0_PUBLIC_IP
nc -vz PO0_PUBLIC_IP FORWARD_PORT
nc -vz RFC_INTERNAL_MACHINE_IP TARGET_PORT
```

如果你禁用了 ICMP echo，ping 不通是预期结果。
