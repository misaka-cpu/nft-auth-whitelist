#!/usr/bin/env bash
# Production preflight for auth-server SSH push targets. It validates server.json
# target settings and can optionally prove that a requested remote command is
# blocked by the receive-side SSH forced command.
set -uo pipefail

CONFIG="/etc/nft-auth-whitelist/server.json"
TARGET=""
SSH_TEST=false
JSON_OUTPUT=false

usage() {
  cat <<'EOF'
Usage:
  scripts/preflight-push-target.sh [options]

Options:
  --config PATH   server.json path (default /etc/nft-auth-whitelist/server.json)
  --target NAME   check only one push target by name
  --ssh-test      run an SSH forced-command probe using remote command 'whoami'
  --json          emit JSON results
  -h, --help      show this help

The SSH probe passes empty stdin and asks for 'whoami'. A correct forced command
should ignore whoami and return an nft-auth-receive empty-input error. If the
probe prints whoami/nftauth or succeeds as a shell command, this script fails.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --ssh-test) SSH_TEST=true; shift ;;
    --json) JSON_OUTPUT=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; echo "try: scripts/preflight-push-target.sh --help" >&2; exit 2 ;;
  esac
done

RESULTS_FILE="$(mktemp)"
TARGETS_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE" "$TARGETS_FILE"' EXIT

PASS=0
WARN=0
FAIL=0

record() {
  local status="$1" check="$2" detail="${3:-}"
  case "$status" in
    PASS) PASS=$((PASS + 1)) ;;
    WARN) WARN=$((WARN + 1)) ;;
    FAIL) FAIL=$((FAIL + 1)) ;;
  esac
  printf '%s\t%s\t%s\n' "$status" "$check" "$detail" >> "$RESULTS_FILE"
  if ! $JSON_OUTPUT; then
    if [[ -n "$detail" ]]; then
      printf '%-4s %s - %s\n' "$status" "$check" "$detail"
    else
      printf '%-4s %s\n' "$status" "$check"
    fi
  fi
}

finish() {
  if $JSON_OUTPUT; then
    python3 - "$RESULTS_FILE" "$PASS" "$WARN" "$FAIL" <<'PY'
import json
import sys

path, passed, warned, failed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
checks = []
with open(path, "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        status, check, detail = (line.split("\t", 2) + ["", ""])[:3]
        checks.append({"status": status, "check": check, "detail": detail})
overall = "FAIL" if failed else ("WARN" if warned else "PASS")
print(json.dumps({
    "overall": overall,
    "pass": passed,
    "warn": warned,
    "fail": failed,
    "checks": checks,
}, ensure_ascii=False, indent=2))
PY
  fi
  [[ "$FAIL" -eq 0 ]]
}

if [[ ! -f "$CONFIG" ]]; then
  record FAIL "server.json exists" "$CONFIG"
  finish
  exit $?
fi
record PASS "server.json exists" "$CONFIG"

if ! command -v python3 >/dev/null 2>&1; then
  record FAIL "python3 available" "needed for JSON validation"
  finish
  exit $?
fi

parse_out="$(python3 - "$CONFIG" "$TARGET" "$TARGETS_FILE" <<'PY' 2>&1
import json
import sys

path, want, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception as exc:
    raise SystemExit(f"invalid json: {exc}")
if not isinstance(data, dict):
    raise SystemExit("top-level JSON value must be an object")
push = data.get("push") or {}
if not isinstance(push, dict):
    raise SystemExit("push must be an object")
targets = push.get("targets") or []
if not isinstance(targets, list):
    raise SystemExit("push.targets must be an array")
enabled = bool(push.get("enabled", False))
print("PUSH_ENABLED\t" + ("true" if enabled else "false"))
print("TARGET_TOTAL\t" + str(len(targets)))
selected = []
for idx, target in enumerate(targets):
    if not isinstance(target, dict):
        continue
    if want and target.get("name") != want:
        continue
    selected.append((idx, target))
print("TARGET_MATCHED\t" + str(len(selected)))
with open(out_path, "w", encoding="utf-8") as out:
    for idx, target in selected:
        missing = []
        for field in ("name", "user", "host", "port", "identity_file", "known_hosts_file"):
            if target.get(field) in ("", None):
                missing.append(field)
        strict = target.get("strict_host_key_checking", True)
        values = [
            str(idx),
            str(target.get("name", "")),
            str(target.get("user", "")),
            str(target.get("host", "")),
            str(target.get("port", "")),
            str(target.get("identity_file", "")),
            "true" if bool(strict) else "false",
            str(target.get("known_hosts_file", "")),
            ",".join(missing),
        ]
        out.write("\t".join(values) + "\n")
PY
)"
parse_rc=$?
if [[ "$parse_rc" -ne 0 ]]; then
  record FAIL "server.json JSON is valid" "$parse_out"
  finish
  exit $?
fi
record PASS "server.json JSON is valid" "parsed"

PUSH_ENABLED="false"
TARGET_TOTAL="0"
TARGET_MATCHED="0"
while IFS=$'\t' read -r key value; do
  case "$key" in
    PUSH_ENABLED) PUSH_ENABLED="$value" ;;
    TARGET_TOTAL) TARGET_TOTAL="$value" ;;
    TARGET_MATCHED) TARGET_MATCHED="$value" ;;
  esac
done <<< "$parse_out"

if [[ "$PUSH_ENABLED" == "true" ]]; then
  record PASS "push.enabled is true" "auth-server will attempt push after auth"
else
  record FAIL "push.enabled is true" "set push.enabled=true for production shadow push"
fi

if [[ "$TARGET_TOTAL" -gt 0 ]]; then
  record PASS "push.targets is non-empty" "$TARGET_TOTAL target(s)"
else
  record FAIL "push.targets is non-empty" "no targets configured"
fi

if [[ -n "$TARGET" ]]; then
  if [[ "$TARGET_MATCHED" -eq 1 ]]; then
    record PASS "requested target exists" "$TARGET"
  else
    record FAIL "requested target exists" "$TARGET"
  fi
elif [[ "$TARGET_MATCHED" -gt 0 ]]; then
  record PASS "targets selected for checking" "$TARGET_MATCHED target(s)"
fi

ssh_bin="${NFT_AUTH_PREFLIGHT_SSH:-ssh}"

check_identity_mode() {
  local path="$1" label="$2" mode perm
  if [[ ! -f "$path" ]]; then
    record FAIL "$label identity_file exists" "$path"
    return 1
  fi
  if [[ ! -r "$path" ]]; then
    record FAIL "$label identity_file readable" "$path"
    return 1
  fi
  mode="$(stat -c '%a' "$path" 2>/dev/null || true)"
  if [[ -z "$mode" ]]; then
    record FAIL "$label identity_file permissions" "cannot stat $path"
    return 1
  fi
  perm=$((8#$mode))
  if (( (perm & 0177) == 0 && (perm & 0400) != 0 )); then
    record PASS "$label identity_file permissions" "$mode"
    return 0
  fi
  record FAIL "$label identity_file permissions" "$mode is too open; use 600 or 400"
  return 1
}

run_ssh_probe() {
  local label="$1" user="$2" host="$3" port="$4" identity="$5" known_hosts="$6" output rc lower first_line
  output="$("$ssh_bin" -n -i "$identity" -p "$port" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$known_hosts" \
    "$user@$host" "whoami" 2>&1)"
  rc=$?
  lower="$(printf '%s' "$output" | tr '[:upper:]' '[:lower:]')"
  first_line="$(printf '%s' "$output" | sed -n '1p')"
  if [[ "$lower" == *nftauth* || "$lower" == *whoami* ]]; then
    record FAIL "$label ssh forced-command probe" "remote command output indicates shell access: $first_line"
  elif [[ "$lower" == *"empty input"* || "$lower" == *"nft-auth-receive:"* ]]; then
    record PASS "$label ssh forced-command probe" "receive rejected empty input, so forced command is active"
  elif [[ "$rc" -eq 0 ]]; then
    record FAIL "$label ssh forced-command probe" "ssh command succeeded; forced command did not reject whoami"
  else
    record FAIL "$label ssh forced-command probe" "unexpected ssh result rc=$rc: $first_line"
  fi
}

while IFS=$'\t' read -r idx name user host port identity strict known_hosts missing; do
  [[ -z "${idx:-}" ]] && continue
  label="target ${name:-#$idx}"
  target_ok=true

  if [[ -z "$missing" ]]; then
    record PASS "$label required fields exist" "name/user/host/port/identity_file/known_hosts_file"
  else
    record FAIL "$label required fields exist" "missing: $missing"
    target_ok=false
  fi

  if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
    record PASS "$label port is valid" "$port"
  else
    record FAIL "$label port is valid" "$port"
    target_ok=false
  fi

  if [[ "$strict" == "true" ]]; then
    record PASS "$label strict_host_key_checking is true" "host key pinning required"
  else
    record FAIL "$label strict_host_key_checking is true" "false is not allowed for production po0 shadow"
    target_ok=false
  fi

  if ! check_identity_mode "$identity" "$label"; then
    target_ok=false
  fi

  if [[ -f "$known_hosts" ]]; then
    if [[ -s "$known_hosts" ]]; then
      record PASS "$label known_hosts_file exists" "$known_hosts"
    else
      record FAIL "$label known_hosts_file exists" "$known_hosts is empty"
      target_ok=false
    fi
  else
    record FAIL "$label known_hosts_file exists" "$known_hosts"
    target_ok=false
  fi

  if $SSH_TEST; then
    if $target_ok; then
      run_ssh_probe "$label" "$user" "$host" "$port" "$identity" "$known_hosts"
    else
      record FAIL "$label ssh forced-command probe" "skipped because target preflight failed"
    fi
  fi
done < "$TARGETS_FILE"

finish
