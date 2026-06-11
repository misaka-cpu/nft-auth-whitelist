#!/usr/bin/env bash
# Build per-architecture release tarballs into dist/.
#
# Produces:
#   dist/nft-auth-whitelist-linux-amd64.tar.gz
#   dist/nft-auth-whitelist-linux-arm64.tar.gz
#
# Each archive contains: bin/, configs/, docs/, scripts/preflight-*.sh,
# install.sh, README.md, SECURITY.md
# It contains NO secrets and NO real configs (only *.example.json templates).
set -euo pipefail

cd "$(dirname "$0")/.."

NAME="nft-auth-whitelist"
DIST="dist"

echo "==> building all platforms"
bash scripts/build.sh --all-platforms

for arch in amd64 arm64; do
  bindir="$DIST/linux-$arch"
  if [[ ! -d "$bindir" ]]; then
    echo "missing $bindir (build failed?)" >&2
    exit 1
  fi
  stage="$DIST/stage-$arch/$NAME"
  rm -rf "$DIST/stage-$arch"
  mkdir -p "$stage/bin"

  cp "$bindir"/nft-auth-* "$stage/bin/"
  cp -r configs "$stage/configs"
  cp -r docs "$stage/docs"
  mkdir -p "$stage/scripts"
  cp scripts/preflight-receive.sh scripts/preflight-push-target.sh "$stage/scripts/"
  cp install.sh "$stage/install.sh"
  cp README.md SECURITY.md "$stage/"
  chmod +x "$stage/install.sh" "$stage/bin/"* "$stage/scripts/"*.sh

  tarball="$DIST/$NAME-linux-$arch.tar.gz"
  tar -C "$DIST/stage-$arch" -czf "$tarball" "$NAME"
  rm -rf "$DIST/stage-$arch"
  echo "==> wrote $tarball"
done

echo "==> done."
ls -l "$DIST"/*.tar.gz
