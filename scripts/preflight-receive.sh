#!/usr/bin/env bash
# Production shadow preflight for the receive side. Default mode is read-only:
# it checks config, paths, the nftauth SSH forced-command boundary, and never
# reads/modifies nft rules, sshd_config, or authorized_keys.
set -uo pipefail

CONFIG="/etc/nft-auth-whitelist/receive.json"
CHECK_USER="nftauth"
FIX_PERMS=false
JSON_OUTPUT=false

usage() {
  cat <<'EOF'
Usage:
  scripts/preflight-receive.sh [options]

Options:
  --config PATH   receive.json path (default /etc/nft-auth-whitelist/receive.json)
  --user NAME     receive SSH/user account (default nftauth)
  --fix-perms     create/fix only the standard data/log directories:
                  /var/lib/nft-auth-whitelist
                  /var/lib/nft-auth-whitelist/inbox
                  /var/log/nft-auth-whitelist
  --json          emit JSON results
  -h, --help      show this help

This script does not execute nft, does not modify sshd_config, and does not
modify authorized_keys.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG="${2:-}"; shift 2 ;;
    --user) CHECK_USER="${2:-}"; shift 2 ;;
    --fix-perms) FIX_PERMS=true; shift ;;
    --json) JSON_OUTPUT=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; echo "try: scripts/preflight-receive.sh --help" >&2; exit 2 ;;
  esac
done

RESULTS_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE"' EXIT

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

is_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

user_exists=false
if is_root; then
  record PASS "current user is root" "required for production receive-side inspection"
else
  record FAIL "current user is root" "run as root on the receive host"
fi

receive_bin="$(command -v nft-auth-receive 2>/dev/null || true)"
if [[ -n "$receive_bin" && -x "$receive_bin" ]]; then
  record PASS "nft-auth-receive executable exists" "$receive_bin"
elif [[ -x /usr/local/bin/nft-auth-receive ]]; then
  record PASS "nft-auth-receive executable exists" "/usr/local/bin/nft-auth-receive"
else
  record FAIL "nft-auth-receive executable exists" "not found in PATH or /usr/local/bin"
fi

if id "$CHECK_USER" >/dev/null 2>&1; then
  user_exists=true
  record PASS "receive user exists" "$CHECK_USER"
else
  record FAIL "receive user exists" "$CHECK_USER"
fi

if $FIX_PERMS; then
  if ! is_root; then
    record FAIL "--fix-perms can run" "must run as root"
  elif ! $user_exists; then
    record FAIL "--fix-perms can run" "user $CHECK_USER does not exist"
  else
    for dir in /var/lib/nft-auth-whitelist /var/lib/nft-auth-whitelist/inbox /var/log/nft-auth-whitelist; do
      if install -d -m 0750 -o "$CHECK_USER" -g "$CHECK_USER" "$dir" 2>/dev/null; then
        record PASS "fixed standard directory permissions" "$dir"
      else
        record FAIL "fixed standard directory permissions" "$dir"
      fi
    done
  fi
fi

HMAC_SECRET=""
INBOX_ALLOW_JSON=""
OUTPUT_ALLOW_TXT=""
OUTPUT_STATE_JSON=""
AUDIT_LOG=""
MODE="export"
NFT_ENABLED="false"

if [[ ! -f "$CONFIG" ]]; then
  record FAIL "receive.json exists" "$CONFIG"
else
  record PASS "receive.json exists" "$CONFIG"
  if ! command -v python3 >/dev/null 2>&1; then
    record FAIL "python3 available" "needed for JSON validation"
  else
    parse_out="$(python3 - "$CONFIG" <<'PY' 2>&1
import json
import sys

path = sys.argv[1]
allowed_top = {
    "input_max_bytes", "inbox_allow_json", "hmac_secret", "output_allow_txt",
    "output_state_json", "max_entries", "allow_ipv4", "allow_ipv6", "mode",
    "nft", "audit_log",
}
allowed_nft = {"enabled", "table", "protected_tcp_ports", "protected_udp_ports"}
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception as exc:
    raise SystemExit(f"invalid json: {exc}")
if not isinstance(data, dict):
    raise SystemExit("top-level JSON value must be an object")
unknown = sorted(set(data) - allowed_top)
if unknown:
    raise SystemExit("unknown receive.json fields: " + ", ".join(unknown))
nft = data.get("nft") or {}
if not isinstance(nft, dict):
    raise SystemExit("nft must be an object")
unknown_nft = sorted(set(nft) - allowed_nft)
if unknown_nft:
    raise SystemExit("unknown nft fields: " + ", ".join(unknown_nft))
def text(name, default=""):
    value = data.get(name, default)
    return "" if value is None else str(value)
print("HMAC_SECRET\t" + text("hmac_secret"))
print("INBOX_ALLOW_JSON\t" + text("inbox_allow_json"))
print("OUTPUT_ALLOW_TXT\t" + text("output_allow_txt"))
print("OUTPUT_STATE_JSON\t" + text("output_state_json"))
print("AUDIT_LOG\t" + text("audit_log"))
print("MODE\t" + text("mode", "export"))
print("NFT_ENABLED\t" + ("true" if bool(nft.get("enabled", False)) else "false"))
PY
)"
    parse_rc=$?
    if [[ "$parse_rc" -ne 0 ]]; then
      record FAIL "receive.json JSON/schema is valid" "$parse_out"
    else
      record PASS "receive.json JSON/schema is valid" "accepted by preflight schema"
      while IFS=$'\t' read -r key value; do
        case "$key" in
          HMAC_SECRET) HMAC_SECRET="$value" ;;
          INBOX_ALLOW_JSON) INBOX_ALLOW_JSON="$value" ;;
          OUTPUT_ALLOW_TXT) OUTPUT_ALLOW_TXT="$value" ;;
          OUTPUT_STATE_JSON) OUTPUT_STATE_JSON="$value" ;;
          AUDIT_LOG) AUDIT_LOG="$value" ;;
          MODE) MODE="$value" ;;
          NFT_ENABLED) NFT_ENABLED="$value" ;;
        esac
      done <<< "$parse_out"
    fi
  fi
fi

secret_lower="$(printf '%s' "$HMAC_SECRET" | tr '[:upper:]' '[:lower:]')"
if [[ -z "$HMAC_SECRET" ]]; then
  record FAIL "hmac_secret is set" "empty or missing"
elif [[ "$secret_lower" == *change-me* || "$secret_lower" == *changeme* || "$secret_lower" == *placeholder* || "$secret_lower" == *replace* || "$secret_lower" == *example* || "$secret_lower" == your-* || "$secret_lower" == "secret" ]]; then
  record FAIL "hmac_secret is not a placeholder" "replace the sample value with the RFC auth-server secret"
elif [[ "${#HMAC_SECRET}" -lt 16 ]]; then
  record WARN "hmac_secret length" "short value; use a strong random secret"
else
  record PASS "hmac_secret is not a placeholder" "value is present and not printed"
fi

if [[ "$MODE" == "export" ]]; then
  record PASS "receive mode is shadow/export" "mode=export"
else
  record FAIL "receive mode is shadow/export" "mode=$MODE; do not use nft mode for po0 shadow"
fi

if [[ "$NFT_ENABLED" == "false" ]]; then
  record PASS "nft guard disabled" "nft.enabled=false"
else
  record FAIL "nft guard disabled" "nft.enabled=true is not allowed for this shadow preflight"
fi

user_can_write() {
  local user="$1" path="$2"
  if [[ ! -e "$path" ]]; then
    return 1
  fi
  if [[ "$(id -un 2>/dev/null || true)" == "$user" ]]; then
    [[ -w "$path" ]]
    return
  fi
  if is_root && command -v runuser >/dev/null 2>&1; then
    runuser -u "$user" -- test -w "$path" >/dev/null 2>&1
    return
  fi
  [[ -w "$path" ]]
}

nearest_existing_dir() {
  local dir="$1"
  while [[ "$dir" != "/" && ! -d "$dir" ]]; do
    dir="$(dirname "$dir")"
  done
  printf '%s\n' "$dir"
}

check_file_target() {
  local label="$1" path="$2" kind="$3" parent ancestor
  if [[ -z "$path" ]]; then
    record FAIL "$label path configured" "missing"
    return
  fi
  parent="$(dirname "$path")"
  if [[ "$kind" == "append" && -e "$path" ]]; then
    if $user_exists && user_can_write "$CHECK_USER" "$path"; then
      record PASS "$label path writable" "$path"
    else
      record FAIL "$label path writable" "$path is not writable by $CHECK_USER"
    fi
    return
  fi
  if [[ -d "$parent" ]]; then
    if $user_exists && user_can_write "$CHECK_USER" "$parent"; then
      record PASS "$label parent writable" "$parent"
    else
      record FAIL "$label parent writable" "$parent is not writable by $CHECK_USER"
    fi
  else
    ancestor="$(nearest_existing_dir "$parent")"
    if $user_exists && user_can_write "$CHECK_USER" "$ancestor"; then
      record WARN "$label parent exists" "$parent missing but can be created under $ancestor"
    else
      record FAIL "$label parent exists" "$parent missing and cannot be created by $CHECK_USER"
    fi
  fi
}

check_file_target "inbox_allow_json" "$INBOX_ALLOW_JSON" "atomic"
check_file_target "output_allow_txt" "$OUTPUT_ALLOW_TXT" "atomic"
check_file_target "output_state_json" "$OUTPUT_STATE_JSON" "atomic"
check_file_target "audit_log" "$AUDIT_LOG" "append"

inbox_dir="$(dirname "${INBOX_ALLOW_JSON:-/var/lib/nft-auth-whitelist/inbox/allow.json}")"
log_dir="$(dirname "${AUDIT_LOG:-/var/log/nft-auth-whitelist/receive-audit.log}")"
if [[ -d "$inbox_dir" ]]; then
  if $user_exists && user_can_write "$CHECK_USER" "$inbox_dir"; then
    record PASS "inbox directory writable by receive user" "$inbox_dir"
  else
    record FAIL "inbox directory writable by receive user" "$inbox_dir"
  fi
else
  record WARN "inbox directory exists" "$inbox_dir missing"
fi
if [[ -d "$log_dir" ]]; then
  if $user_exists && user_can_write "$CHECK_USER" "$log_dir"; then
    record PASS "log directory writable by receive user" "$log_dir"
  else
    record FAIL "log directory writable by receive user" "$log_dir"
  fi
else
  record WARN "log directory exists" "$log_dir missing"
fi

authorized_keys="${NFT_AUTH_PREFLIGHT_AUTHORIZED_KEYS:-}"
if [[ -z "$authorized_keys" ]]; then
  home_dir="$(getent passwd "$CHECK_USER" 2>/dev/null | cut -d: -f6)"
  home_dir="${home_dir:-/home/$CHECK_USER}"
  authorized_keys="$home_dir/.ssh/authorized_keys"
fi

if [[ -f "$authorized_keys" ]]; then
  record PASS "authorized_keys exists" "$authorized_keys"
  active_key_lines="$(grep -Ev '^[[:space:]]*(#|$)' "$authorized_keys" 2>/dev/null || true)"
  command_key_lines="$(printf '%s\n' "$active_key_lines" | grep -F 'command="' || true)"
  receive_key_lines="$(printf '%s\n' "$command_key_lines" | grep -F '/usr/local/bin/nft-auth-receive' || true)"
  if [[ -n "$command_key_lines" ]]; then
    record PASS "authorized_keys uses forced command" "command= present"
  else
    record FAIL "authorized_keys uses forced command" "command= missing"
  fi
  if [[ -n "$receive_key_lines" ]]; then
    record PASS "forced command runs nft-auth-receive" "/usr/local/bin/nft-auth-receive"
  else
    record FAIL "forced command runs nft-auth-receive" "required absolute command missing"
  fi
  for opt in no-pty no-agent-forwarding no-X11-forwarding no-port-forwarding; do
    if [[ -n "$receive_key_lines" ]] && printf '%s\n' "$receive_key_lines" | grep -qF "$opt"; then
      record PASS "authorized_keys contains $opt" "$authorized_keys"
    else
      record FAIL "authorized_keys contains $opt" "$authorized_keys"
    fi
  done
else
  record FAIL "authorized_keys exists" "$authorized_keys"
fi

finish
