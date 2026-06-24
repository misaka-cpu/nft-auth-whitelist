# Delivery Checklist

This checklist is for private staging and repeatable delivery. It does not deploy automatically, does not start services automatically, and does not run nft.

## Routine release checks

Use these for every code-only release before copying artifacts to any host:

- [ ] Confirm the Debian development checkout is clean: `git status --short --branch`.
- [ ] Run `bash scripts/check.sh` and require `==> all checks passed`.
- [ ] Confirm `dist/nft-auth-whitelist-linux-amd64.tar.gz` and `dist/nft-auth-whitelist-linux-arm64.tar.gz` exist.
- [ ] Inspect tarball contents with `tar -tzf dist/nft-auth-whitelist-linux-amd64.tar.gz | sed -n '1,120p'`.
- [ ] Confirm the package contains `bin/`, `configs/`, `docs/`, `systemd/`, `scripts/`, `install.sh`, `README.md`, `SECURITY.md`, and `LICENSE`.
- [ ] Confirm the package does not contain `.git`, `dist/`, real configs, SSH keys, or local secret files.

## First-time validation

Use these when staging a new RFC JP or po0 host for the first time. For the detailed real-host SSH push sequence, follow [Real-host SSH Push Checklist](./real-host-ssh-push-checklist.md).

- [ ] Install the RFC JP auth-server role with `sudo ./install.sh --role auth-server`.
- [ ] Edit `/etc/nft-auth-whitelist/server.json` with strong non-placeholder credentials.
- [ ] Put auth-server behind HTTPS reverse proxy before browser use.
- [ ] Run the RFC JP auth-server manually or via a reviewed systemd unit.
- [ ] Perform the RFC JP auth-server browser login and confirm the page records the expected client IP/CIDR.
- [ ] Confirm `/allow.json` contains a signed entry for that IP when fetched with the bearer token.
- [ ] Install the po0 receive role with `sudo ./install.sh --role receive`.
- [ ] Keep receive in export/shadow mode: `mode=export` and `nft.enabled=false`.
- [ ] Configure the receive SSH key as a forced command for `nft-auth-receive`.
- [ ] Run `sudo bash scripts/preflight-receive.sh --config /etc/nft-auth-whitelist/receive.json --user nftauth` on po0.
- [ ] Configure the RFC JP `po0-shadow` push target with strict host key checking and a pinned `known_hosts_file`.
- [ ] Run `bash scripts/preflight-push-target.sh --target po0-shadow --ssh-test` on RFC JP.
- [ ] Log in through the browser again and confirm the page's Push results show `po0-shadow` as ok.
- [ ] On po0, inspect `/var/lib/nft-auth-whitelist/allow.txt`, `/var/lib/nft-auth-whitelist/pulled-state.json`, and `/var/log/nft-auth-whitelist/receive-audit.log`.

## Conditional revalidation

Repeat the RFC JP auth-server browser login validation after changing any of these:

- HTTPS reverse proxy routing;
- Cloudflare Access or other front door settings;
- `trusted_proxy_cidrs`;
- `client_ip_headers`;
- auth-server listen address or proxy placement;
- IP family settings such as `allow_ipv4` or `allow_ipv6`.

A routine code-only release does not need to repeat browser validation when those settings are unchanged and CI/package checks pass.

## Non-actions

- [ ] Do not run nft.
- [ ] Do not use `--apply`.
- [ ] Do not modify nftables-nat-rust-enhanced.
- [ ] Do not edit `/etc/nat.toml`.
- [ ] Do not open or change firewall ports.
- [ ] Do not enable or start services without an explicit manual decision.
- [ ] Do not put SSH management ports such as 2222 into protected nft rules.

## Rollback

- Disable or remove the RFC JP push target from `server.json`, then restart auth-server only after reviewing the config.
- Or remove the corresponding forced-command public key from po0 `authorized_keys`.
- Keep audit logs if investigation is needed.
- No nft cleanup is required for this shadow flow because this checklist never applies nft rules.
