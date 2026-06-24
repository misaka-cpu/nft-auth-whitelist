#!/usr/bin/env bash
# Verify release tarballs contain the expected private-delivery file set and no obvious local state.
set -uo pipefail

cd "$(dirname "$0")/.."

PASS=0
FAIL=0
ok() { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

required_paths=(
  "bin/nft-auth-server"
  "bin/nft-auth-puller"
  "bin/nft-auth-receive"
  "configs/server.example.json"
  "configs/puller.example.json"
  "configs/puller-file.example.json"
  "configs/receive.example.json"
  "docs/deploy-checklist.md"
  "docs/deploy-auth-server.md"
  "docs/deploy-po0-shadow.md"
  "docs/deploy-receive.md"
  "docs/security-checklist.md"
  "systemd/nft-auth-whitelist-server.service"
  "systemd/nft-auth-whitelist-puller.service"
  "systemd/nft-auth-whitelist-puller.timer"
  "scripts/preflight-receive.sh"
  "scripts/preflight-push-target.sh"
  "scripts/check.sh"
  "scripts/test-install.sh"
  "scripts/test-preflight.sh"
  "scripts/test-local-shadow.sh"
  "scripts/secret-scan.sh"
  "install.sh"
  "README.md"
  "SECURITY.md"
  "LICENSE"
)

for arch in amd64 arm64; do
  tarball="dist/nft-auth-whitelist-linux-$arch.tar.gz"
  prefix="nft-auth-whitelist/"
  if [[ ! -f "$tarball" ]]; then
    bad "$tarball exists"
    continue
  fi
  list="$(mktemp)"
  if tar -tzf "$tarball" > "$list"; then
    ok "$tarball lists"
  else
    bad "$tarball lists"
    rm -f "$list"
    continue
  fi
  for rel in "${required_paths[@]}"; do
    if grep -qxF "$prefix$rel" "$list"; then
      ok "$arch package contains $rel"
    else
      bad "$arch package missing $rel"
    fi
  done
  for forbidden in "/.git/" "/dist/" ".local.json" "id_ed25519" ".pem"; do
    if grep -qF "$forbidden" "$list"; then
      bad "$arch package excludes $forbidden"
    else
      ok "$arch package excludes $forbidden"
    fi
  done
  rm -f "$list"
done

echo
echo "test-package: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
