#!/usr/bin/env bash
# Local end-to-end shadow smoke test.
# Starts auth-server on 127.0.0.1 with temporary configs, authenticates once,
# fetches signed allow.json, feeds it to nft-auth-receive, and verifies shadow outputs.
set -euo pipefail

cd "$(dirname "$0")/.."

SERVER_BIN="dist/nft-auth-server"
RECEIVE_BIN="dist/nft-auth-receive"

if [[ ! -x "$SERVER_BIN" || ! -x "$RECEIVE_BIN" ]]; then
  echo "==> building local binaries for shadow smoke"
  bash scripts/build.sh
fi

for bin in "$SERVER_BIN" "$RECEIVE_BIN"; do
  if [[ ! -x "$bin" ]]; then
    echo "missing executable: $bin" >&2
    exit 1
  fi
done

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required for local shadow smoke test" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for local shadow smoke test" >&2
  exit 1
fi

tmp="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" >/dev/null 2>&1; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

port="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
base_url="http://127.0.0.1:$port"

username="smoke-user"
password="local-smoke-password-1234567890"
pull_token="local-smoke-pull-token-12345678901234567890"
hmac_secret="local-smoke-hmac-secret-12345678901234567890"

mkdir -p "$tmp/server-data" "$tmp/inbox" "$tmp/out" "$tmp/log"
server_config="$tmp/server.json"
receive_config="$tmp/receive.json"

python3 - "$server_config" "$receive_config" "$port" "$username" "$password" "$pull_token" "$hmac_secret" "$tmp" <<'PY'
import json
import sys

server_config, receive_config, port, username, password, pull_token, hmac_secret, tmp = sys.argv[1:]
server = {
    "listen": f"127.0.0.1:{port}",
    "base_url": f"http://127.0.0.1:{port}",
    "username": username,
    "password": password,
    "pull_token": pull_token,
    "hmac_secret": hmac_secret,
    "ttl_seconds": 300,
    "max_entries": 20,
    "allow_ipv4": True,
    "allow_ipv6": False,
    "allow_cidr_expand_ipv4": False,
    "trusted_proxy_cidrs": [],
    "client_ip_headers": [],
    "data_dir": f"{tmp}/server-data",
    "audit_log": f"{tmp}/log/server-audit.log",
    "rate_limit": {"enabled": True, "max_failures_per_minute": 10},
    "push": {"enabled": False, "timeout_seconds": 10, "targets": []},
}
receive = {
    "input_max_bytes": 1048576,
    "inbox_allow_json": f"{tmp}/inbox/allow.json",
    "hmac_secret": hmac_secret,
    "output_allow_txt": f"{tmp}/out/allow.txt",
    "output_state_json": f"{tmp}/out/pulled-state.json",
    "max_entries": 20,
    "allow_ipv4": True,
    "allow_ipv6": False,
    "mode": "export",
    "nft": {
        "enabled": False,
        "table": "nft_auth_whitelist",
        "protected_tcp_ports": [],
        "protected_udp_ports": [],
    },
    "audit_log": f"{tmp}/log/receive-audit.log",
}
for path, data in ((server_config, server), (receive_config, receive)):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
PY

"$SERVER_BIN" --config "$server_config" >"$tmp/log/server.stdout" 2>"$tmp/log/server.stderr" &
server_pid="$!"

for _ in $(seq 1 50); do
  if curl -fsS "$base_url/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$server_pid" >/dev/null 2>&1; then
    echo "auth-server exited before health check" >&2
    sed -n '1,120p' "$tmp/log/server.stderr" >&2 || true
    exit 1
  fi
  sleep 0.1
done

health="$(curl -fsS "$base_url/health")"
if [[ "$health" != "ok" ]]; then
  echo "unexpected health response: $health" >&2
  exit 1
fi

auth_html="$tmp/auth.html"
curl -fsS -X POST -u "$username:$password" "$base_url/" -o "$auth_html"
if ! grep -qF "127.0.0.1/32" "$auth_html"; then
  echo "auth page did not show 127.0.0.1/32" >&2
  sed -n '1,120p' "$auth_html" >&2
  exit 1
fi

allow_json="$tmp/allow.json"
curl -fsS -H "Authorization: Bearer $pull_token" "$base_url/allow.json" -o "$allow_json"
python3 - "$allow_json" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
entries = data.get("entries") or []
if not any(entry.get("cidr") == "127.0.0.1/32" for entry in entries):
    raise SystemExit("allow.json missing 127.0.0.1/32")
if not data.get("signature"):
    raise SystemExit("allow.json missing signature")
PY

receive_out="$tmp/receive.stdout"
receive_err="$tmp/receive.stderr"
"$RECEIVE_BIN" --config "$receive_config" < "$allow_json" > "$receive_out" 2> "$receive_err"
if ! grep -qF "ok entries=1" "$receive_out"; then
  echo "receive stdout did not report success" >&2
  sed -n '1,120p' "$receive_out" >&2 || true
  sed -n '1,120p' "$receive_err" >&2 || true
  exit 1
fi

allow_txt="$tmp/out/allow.txt"
state_json="$tmp/out/pulled-state.json"
receive_audit="$tmp/log/receive-audit.log"

if ! grep -qxF "127.0.0.1/32" "$allow_txt"; then
  echo "allow.txt missing 127.0.0.1/32" >&2
  sed -n '1,120p' "$allow_txt" >&2 || true
  exit 1
fi

python3 - "$state_json" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
text = json.dumps(data, sort_keys=True)
if "127.0.0.1/32" not in text:
    raise SystemExit("state json missing 127.0.0.1/32")
PY

if ! grep -qF '"action":"receive.success"' "$receive_audit"; then
  echo "receive audit missing receive.success" >&2
  sed -n '1,120p' "$receive_audit" >&2 || true
  exit 1
fi
for secret in "$password" "$pull_token" "$hmac_secret"; do
  if grep -R --exclude='server.json' --exclude='receive.json' -qF "$secret" "$tmp/log" "$tmp/out" "$tmp/inbox" "$receive_out" "$receive_err"; then
    echo "secret leaked into smoke outputs" >&2
    exit 1
  fi
done

help_out="$tmp/receive.help"
"$RECEIVE_BIN" -h > "$help_out" 2>&1 || true
if grep -q -- "--apply\|-apply" "$help_out"; then
  echo "nft-auth-receive help unexpectedly exposes apply" >&2
  sed -n '1,120p' "$help_out" >&2
  exit 1
fi

echo "test-local-shadow: PASS"
