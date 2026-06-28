#!/usr/bin/env bash
# Shell tests for v0.6.2 production preflight scripts. Tests use only temp
# directories and fake ssh; they do not connect to public hosts or modify system
# SSH/nft configuration.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
RECEIVE="$ROOT/scripts/preflight-receive.sh"
PUSH="$ROOT/scripts/preflight-push-target.sh"

PASS=0
FAIL=0
TMP=""

ok() { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

expect_ok() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc (expected exit 0)"; fi
}

expect_fail() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then bad "$desc (expected non-zero exit)"; else ok "$desc"; fi
}

setup_tmp() {
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  mkdir -p "$TMP/bin" "$TMP/etc" "$TMP/var/lib/nft-auth-whitelist/inbox" "$TMP/var/log/nft-auth-whitelist" "$TMP/home/.ssh" "$TMP/ssh"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/bin/nft-auth-receive"
  chmod +x "$TMP/bin/nft-auth-receive"
}

write_receive_json() {
  local path="$1"
  local secret_a="unit-test"
  local secret_b="-randomish"
  local secret_c="-receive-secret"
  cat > "$path" <<EOF
{
  "input_max_bytes": 1048576,
  "inbox_allow_json": "$TMP/var/lib/nft-auth-whitelist/inbox/allow.json",
  "hmac_secret": "$secret_a$secret_b$secret_c",
  "output_allow_txt": "$TMP/var/lib/nft-auth-whitelist/allow.txt",
  "output_state_json": "$TMP/var/lib/nft-auth-whitelist/pulled-state.json",
  "max_entries": 200,
  "allow_ipv4": true,
  "allow_ipv6": false,
  "mode": "export",
  "nft": {
    "enabled": false,
    "table": "nft_auth_whitelist",
    "protected_tcp_ports": [],
    "protected_udp_ports": []
  },
  "audit_log": "$TMP/var/log/nft-auth-whitelist/receive-audit.log"
}
EOF
}

write_authorized_keys() {
  local path="$1" mode="$2"
  case "$mode" in
    good)
      cat > "$path" <<'EOF'
command="/usr/local/bin/nft-auth-receive -config /etc/nft-auth-whitelist/receive.json",no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA... nft-auth-push
EOF
      ;;
    no_forced)
      cat > "$path" <<'EOF'
ssh-ed25519 AAAA... nft-auth-push
EOF
      ;;
    missing_no_port)
      cat > "$path" <<'EOF'
command="/usr/local/bin/nft-auth-receive -config /etc/nft-auth-whitelist/receive.json",no-pty,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... nft-auth-push
EOF
      ;;
  esac
  chmod 0600 "$path"
}

write_server_json() {
  local path="$1" strict="$2" identity="$3" known_hosts="$4"
  cat > "$path" <<EOF
{
  "push": {
    "enabled": true,
    "timeout_seconds": 10,
    "targets": [
      {
        "name": "po0-shadow",
        "user": "nftauth",
        "host": "RECEIVE_HOST",
        "port": 22,
        "identity_file": "$identity",
        "strict_host_key_checking": $strict,
        "known_hosts_file": "$known_hosts"
      }
    ]
  }
}
EOF
}

write_fake_ssh() {
  local path="$1" text="$2" rc="$3"
  cat > "$path" <<EOF
#!/usr/bin/env bash
echo "$text"
exit $rc
EOF
  chmod +x "$path"
}

setup_tmp

echo "== help output =="
expect_ok "preflight-receive --help" bash "$RECEIVE" --help
expect_ok "preflight-push-target --help" bash "$PUSH" --help

echo "== preflight-receive =="
receive_json="$TMP/etc/receive.json"
auth_keys="$TMP/home/.ssh/authorized_keys"
write_receive_json "$receive_json"
write_authorized_keys "$auth_keys" good
expect_ok "legal receive shadow environment passes" env PATH="$TMP/bin:$PATH" NFT_AUTH_PREFLIGHT_AUTHORIZED_KEYS="$auth_keys" bash "$RECEIVE" --config "$receive_json" --user root
expect_fail "missing receive.json fails" env PATH="$TMP/bin:$PATH" NFT_AUTH_PREFLIGHT_AUTHORIZED_KEYS="$auth_keys" bash "$RECEIVE" --config "$TMP/etc/missing-receive.json" --user root
write_authorized_keys "$auth_keys" no_forced
expect_fail "authorized_keys without forced command fails" env PATH="$TMP/bin:$PATH" NFT_AUTH_PREFLIGHT_AUTHORIZED_KEYS="$auth_keys" bash "$RECEIVE" --config "$receive_json" --user root
write_authorized_keys "$auth_keys" missing_no_port
expect_fail "authorized_keys missing no-port-forwarding fails" env PATH="$TMP/bin:$PATH" NFT_AUTH_PREFLIGHT_AUTHORIZED_KEYS="$auth_keys" bash "$RECEIVE" --config "$receive_json" --user root

echo "== preflight-push-target =="
identity="$TMP/ssh/nft_auth_push"
known_hosts="$TMP/ssh/known_hosts"
printf 'not-a-real-private-key\n' > "$identity"
chmod 0600 "$identity"
printf 'RECEIVE_HOST ssh-ed25519 AAAA...\n' > "$known_hosts"
server_json="$TMP/etc/server.json"
write_server_json "$server_json" true "$identity" "$known_hosts"
expect_ok "legal server push target passes" bash "$PUSH" --config "$server_json" --target po0-shadow
write_server_json "$server_json" false "$identity" "$known_hosts"
expect_fail "strict_host_key_checking=false fails" bash "$PUSH" --config "$server_json" --target po0-shadow
write_server_json "$server_json" true "$TMP/ssh/missing_identity" "$known_hosts"
expect_fail "missing identity_file fails" bash "$PUSH" --config "$server_json" --target po0-shadow

write_server_json "$server_json" true "$identity" "$known_hosts"
fake_ssh="$TMP/bin/fake-ssh"
write_fake_ssh "$fake_ssh" "nftauth" 0
expect_fail "fake ssh output nftauth fails" env NFT_AUTH_PREFLIGHT_SSH="$fake_ssh" bash "$PUSH" --config "$server_json" --target po0-shadow --ssh-test
write_fake_ssh "$fake_ssh" "nft-auth-receive: empty input" 1
expect_ok "fake ssh empty input passes" env NFT_AUTH_PREFLIGHT_SSH="$fake_ssh" bash "$PUSH" --config "$server_json" --target po0-shadow --ssh-test

echo
echo "test-preflight: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
