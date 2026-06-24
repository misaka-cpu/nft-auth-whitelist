# Real-host SSH Push Checklist

Use this only after local checks pass and after the reverse-proxy / Cloudflare Access client-IP path has already been validated. This checklist is for the first real RFC JP -> po0/CO shadow push test.

It does not deploy automatically, does not start services automatically, does not edit firewall rules, and does not run nft.

## Preconditions

- [ ] `bash scripts/check.sh` passes on the Debian development checkout.
- [ ] GitHub Actions is green for the commit you plan to test.
- [ ] The release tarball artifact contains the expected binaries, configs, docs, systemd samples, scripts, `install.sh`, `README.md`, `SECURITY.md`, and `LICENSE`.
- [ ] The real reverse proxy / Cloudflare Access IP-recognition path is already validated and its config has not changed.
- [ ] You have an explicit manual decision to touch the real hosts for this test.

## Credential rule

- [ ] Temporary SSH key only. Prefer a new one-time Ed25519 key for the test.
- [ ] Do not use passwords.
- [ ] Do not paste host passwords, root passwords, Cloudflare tokens, pull tokens, HMAC secrets, cookies, or private keys into chat.
- [ ] Do not reuse a personal admin key for the forced-command receiver.
- [ ] Keep the push private key on RFC JP under `/etc/nft-auth-whitelist/ssh/` with `0600` or `0400` permissions.
- [ ] Remove the temporary public key from the receive host after the test if it is not kept for production.

## Receive host preparation

On po0/CO receive host:

- [ ] Install or update only the receive role: `sudo ./install.sh --role receive`.
- [ ] Edit `/etc/nft-auth-whitelist/receive.json` manually.
- [ ] Confirm `hmac_secret` matches RFC JP auth-server and is not a sample value.
- [ ] Confirm `mode=export` and `nft.enabled=false`.
- [ ] Confirm the output paths are the expected shadow paths:
  - `/var/lib/nft-auth-whitelist/allow.txt`
  - `/var/lib/nft-auth-whitelist/pulled-state.json`
  - `/var/log/nft-auth-whitelist/receive-audit.log`
- [ ] Install the temporary push public key as a forced command for `nft-auth-receive`.
- [ ] Confirm the authorized_keys line contains `command="/usr/local/bin/nft-auth-receive -config /etc/nft-auth-whitelist/receive.json"`.
- [ ] Confirm the authorized_keys line contains `no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding`.
- [ ] Run `sudo bash scripts/preflight-receive.sh --config /etc/nft-auth-whitelist/receive.json --user nftauth`.
- [ ] Stop and ask if the preflight reports any FAIL.

## RFC JP push-side preparation

On RFC JP auth-server host:

- [ ] Put the temporary private key in `/etc/nft-auth-whitelist/ssh/`.
- [ ] Pin the receive host key in `known_hosts`; do not rely on interactive first-connect trust.
- [ ] Configure the push target with `strict_host_key_checking=true`.
- [ ] Configure `known_hosts_file` to the pinned known_hosts file.
- [ ] Configure `identity_file` to the temporary private key path.
- [ ] Keep `push.enabled=false` until the manual SSH probe and preflight pass.
- [ ] Run `bash scripts/preflight-push-target.sh --target po0-shadow --ssh-test`.
- [ ] Stop and ask if the forced-command probe prints `nftauth`, `whoami`, opens a shell, or otherwise suggests shell access.

## One-shot shadow validation

Only after both preflights pass:

- [ ] Generate or fetch signed `allow.json` from RFC JP using the bearer token in an HTTP header, not in a URL.
- [ ] Pipe it over SSH stdin to the receive host using the temporary key.
- [ ] Expect `ok entries=N output=/var/lib/nft-auth-whitelist/allow.txt`.
- [ ] On the receive host, inspect:
  - `/var/lib/nft-auth-whitelist/allow.txt`
  - `/var/lib/nft-auth-whitelist/pulled-state.json`
  - `/var/log/nft-auth-whitelist/receive-audit.log`
- [ ] Confirm the expected CIDR appears in `allow.txt`.
- [ ] Confirm the audit log has receive success entries and no secret/token/password values.

## Optional browser-triggered push validation

Only after one-shot shadow validation succeeds:

- [ ] Enable only the reviewed push target in RFC JP `server.json`.
- [ ] Restart auth-server only after reviewing the config diff.
- [ ] Log in through the already-validated browser auth path.
- [ ] Confirm the page's Push results show `po0-shadow` as ok.
- [ ] Re-check receive host `allow.txt`, `pulled-state.json`, and `receive-audit.log`.

## Non-actions

- [ ] Do not run nft.
- [ ] Do not use `--apply`.
- [ ] Do not enable or start services unless there is a separate explicit manual decision.
- [ ] Do not edit `/etc/nat.toml`.
- [ ] Do not modify nftables-nat-rust-enhanced.
- [ ] Do not open or change firewall ports.
- [ ] Do not add SSH management ports such as 2222 to protected nft rules.
- [ ] Do not leave a broad SSH key that can get a shell.

## Rollback

- Disable or remove the RFC JP push target from `server.json`, then restart auth-server only after reviewing the config.
- Remove the temporary public key from the receive host `authorized_keys`.
- Keep audit logs if investigation is needed.
- No nft cleanup is required because this checklist never applies nft rules.
- Stop and ask before deleting logs, changing firewall rules, or changing systemd state.
