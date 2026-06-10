#!/usr/bin/env bash
# Scan for secrets that must never be committed.
#
# By default it scans git-tracked files (so dist/, *.bak, *.new, *.local.json
# are already excluded via .gitignore). Pass one or more paths to scan an
# arbitrary directory/file tree instead (used by the test suite).
#
# Placeholders in *.example.* configs and docs are allowed; only real-looking
# secrets cause a non-zero exit. IPv4 literals are reported as warnings only.
set -uo pipefail

cd "$(dirname "$0")/.."

ERRORS=0
WARNINGS=0

# Files to scan. Exclude this script itself: it necessarily contains the very
# patterns it searches for.
SELF="scripts/secret-scan.sh"

collect_files() {
  if [[ $# -gt 0 ]]; then
    local p
    for p in "$@"; do
      if [[ -d "$p" ]]; then
        find "$p" -type f
      elif [[ -f "$p" ]]; then
        echo "$p"
      fi
    done
  elif git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files
  else
    find . -type f -not -path './.git/*' -not -path './dist/*'
  fi
}

# Placeholder values that are explicitly allowed in example configs/docs.
PLACEHOLDER='change-me|CHANGE_ME|CHANGEME|REPLACE|EXAMPLE|example|RECEIVE_HOST|placeholder|your-|YOUR_|xxx|XXX|<[^>]+>|\$[A-Za-z_]'

err()  { echo "ERROR: $1"; ERRORS=$((ERRORS + 1)); }
warn() { echo "WARN:  $1"; WARNINGS=$((WARNINGS + 1)); }

mapfile -t FILES < <(collect_files "$@" | grep -v -F "$SELF" | sort -u)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "secret-scan: no files to scan"
  exit 0
fi

# 1) Private key material — assembled at runtime so this script and the scanned
#    tree never contain the literal trigger phrase.
KEY_MARK="BEGIN .*PRIVATE""\ KEY"
if grep -nIE "$KEY_MARK" "${FILES[@]}" 2>/dev/null; then
  err "private key material found (see lines above)"
fi

# 2) JSON secret fields assigned a non-placeholder value. Short values (< 12
#    chars) are treated as test fixtures, not real secrets, to avoid flagging
#    dummy data like {"hmac_secret":"secret"} in unit tests. A real secret is
#    long and random; commit those only via gitignored *.local.json files.
scan_secret_field() {
  local field="$1" hits
  hits="$(grep -nIoE "\"$field\"[[:space:]]*:[[:space:]]*\"[^\"]+\"" "${FILES[@]}" 2>/dev/null || true)"
  [[ -z "$hits" ]] && return 0
  while IFS= read -r linehit; do
    [[ -z "$linehit" ]] && continue
    # linehit looks like: path:lineno:"field": "value"
    local value
    value="$(printf '%s' "$linehit" | sed -E 's/.*"'"$field"'"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"
    if [[ -z "$value" ]]; then continue; fi
    if printf '%s' "$value" | grep -qE "$PLACEHOLDER"; then continue; fi
    if [[ "${#value}" -lt 12 ]]; then continue; fi
    err "non-placeholder $field value: $linehit"
  done <<< "$hits"
}
scan_secret_field hmac_secret
scan_secret_field pull_token
scan_secret_field password

# 3) Real-looking bearer tokens / CF Access cookies (not the literal source code
#    'Bearer "+token' concatenations, which have no long token after them).
if grep -nIoE 'Bearer[[:space:]]+[A-Za-z0-9._-]{16,}' "${FILES[@]}" 2>/dev/null \
    | grep -vE "$PLACEHOLDER"; then
  err "bearer token literal found (see lines above)"
fi
if grep -nIoE 'CF_Authorization[=:][[:space:]]*[A-Za-z0-9._-]{16,}' "${FILES[@]}" 2>/dev/null; then
  err "Cloudflare Access token literal found (see lines above)"
fi

# 4) identity_file pointing at a personal ~/.ssh path (should live under the
#    config dir instead).
if grep -nIE 'identity_file.*/root/\.ssh|identity_file.*/home/[^"]*/\.ssh' "${FILES[@]}" 2>/dev/null; then
  err "identity_file points at a personal ~/.ssh path (use $PWD-style config dir)"
fi

# 5) IPv4 literals — warning only, and only in configs/docs/scripts (Go tests are
#    full of intentional fake IPs). Skip loopback, any-address, broadcast, and
#    the RFC 5737 documentation ranges (192.0.2/198.51.100/203.0.113).
IP_RE='([0-9]{1,3}\.){3}[0-9]{1,3}'
IP_SAFE='127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.255|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.'
mapfile -t IP_FILES < <(printf '%s\n' "${FILES[@]}" | grep -E '\.(json|md|sh)$' || true)
ip_hits=""
if [[ ${#IP_FILES[@]} -gt 0 ]]; then
  ip_hits="$(grep -nIoE "$IP_RE" "${IP_FILES[@]}" 2>/dev/null | grep -vE "$IP_SAFE" || true)"
fi
if [[ -n "$ip_hits" ]]; then
  while IFS= read -r h; do
    [[ -z "$h" ]] && continue
    warn "IPv4 literal (verify it is not a real host): $h"
  done <<< "$ip_hits"
fi

echo
echo "secret-scan: scanned ${#FILES[@]} files, $ERRORS error(s), $WARNINGS warning(s)"
if [[ "$ERRORS" -gt 0 ]]; then
  echo "secret-scan: FAILED — high-risk material found. Do NOT commit."
  exit 1
fi
echo "secret-scan: OK"
exit 0
