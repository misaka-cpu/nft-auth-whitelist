#!/usr/bin/env bash
# Verify CI uploads private release tarballs after the local check suite succeeds.
set -uo pipefail

cd "$(dirname "$0")/.."

workflow=".github/workflows/ci.yml"
PASS=0
FAIL=0
ok() { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

contains() {
  grep -qF "$1" "$workflow"
}

if [[ -f "$workflow" ]]; then
  ok "$workflow exists"
else
  bad "$workflow exists"
  echo
  echo "test-ci: $PASS passed, $FAIL failed"
  exit 1
fi

for want in \
  "actions/upload-artifact@v4" \
  "name: nft-auth-whitelist-tarballs" \
  "dist/nft-auth-whitelist-linux-*.tar.gz" \
  "dist/nft-auth-whitelist-linux-*.tar.gz.sha256" \
  "if-no-files-found: error"; do
  if contains "$want"; then
    ok "workflow contains $want"
  else
    bad "workflow missing $want"
  fi
done

check_line="$(grep -nF "bash scripts/check.sh" "$workflow" | head -n 1 | cut -d: -f1)"
upload_line="$(grep -nF "actions/upload-artifact@v4" "$workflow" | head -n 1 | cut -d: -f1)"
if [[ -n "$check_line" && -n "$upload_line" && "$upload_line" -gt "$check_line" ]]; then
  ok "artifact upload runs after scripts/check.sh"
else
  bad "artifact upload must run after scripts/check.sh"
fi

echo
echo "test-ci: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
