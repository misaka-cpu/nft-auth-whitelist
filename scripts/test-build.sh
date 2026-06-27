#!/usr/bin/env bash
# Verify scripts/build.sh cannot leave stale release archives in dist/.
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p dist
for arch in amd64 arm64; do
  printf 'stale tarball for %s\n' "$arch" > "dist/nft-auth-whitelist-linux-$arch.tar.gz"
  printf 'stale checksum for %s\n' "$arch" > "dist/nft-auth-whitelist-linux-$arch.tar.gz.sha256"
done

log="$(mktemp)"
bash scripts/build.sh >"$log" 2>&1 || {
  cat "$log" >&2
  rm -f "$log"
  exit 1
}
rm -f "$log"

failed=false
for arch in amd64 arm64; do
  for suffix in tar.gz tar.gz.sha256; do
    path="dist/nft-auth-whitelist-linux-$arch.$suffix"
    if [[ -e "$path" ]]; then
      echo "FAIL - build.sh left stale release artifact: $path" >&2
      failed=true
    fi
  done
done

if $failed; then
  exit 1
fi

echo "ok - build.sh removes stale release archives"
