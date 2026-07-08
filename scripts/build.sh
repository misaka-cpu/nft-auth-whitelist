#!/usr/bin/env bash
# Build the three binaries into dist/ after formatting, vetting and testing.
# This script does NOT touch systemd, nft, apt, or any system state.
#
# Usage:
#   ./scripts/build.sh                  # build for the host (dist/<name>)
#   ./scripts/build.sh --all-platforms  # also cross-build linux amd64 + arm64
#                                        # into dist/linux-<arch>/<name>
set -euo pipefail

cd "$(dirname "$0")/.."

ALL_PLATFORMS=false
for arg in "$@"; do
  case "$arg" in
    --all-platforms) ALL_PLATFORMS=true ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

DIST="dist"
mkdir -p "$DIST"

# build.sh produces host/cross-platform binaries only. Release archives are
# produced by scripts/package.sh. Remove old archives up front so a fresh build
# can never leave stale tarballs/checksums in dist/ or list them as fresh output.
echo "==> remove stale release archives"
rm -f "$DIST"/nft-auth-whitelist-linux-*.tar.gz \
      "$DIST"/nft-auth-whitelist-linux-*.tar.gz.sha256

echo "==> gofmt"
fmt_out="$(gofmt -l .)"
if [[ -n "$fmt_out" ]]; then
  echo "these files need gofmt:" >&2
  echo "$fmt_out" >&2
  exit 1
fi

echo "==> go vet"
go vet ./...

echo "==> go test"
go test ./...

# Single-source the default version from internal/version/version.go so the
# tarball/ldflags version cannot drift from the value compiled into --version.
DEFAULT_VERSION="$(sed -n 's/.*Version = "\([^"]*\)".*/\1/p' internal/version/version.go | head -n1)"
VERSION="${VERSION:-${DEFAULT_VERSION:-0.7.1}}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w \
  -X github.com/misaka-cpu/nft-auth-whitelist/internal/version.Version=${VERSION} \
  -X github.com/misaka-cpu/nft-auth-whitelist/internal/version.Commit=${COMMIT} \
  -X github.com/misaka-cpu/nft-auth-whitelist/internal/version.Date=${DATE}"

CMDS="nft-auth-server:./cmd/auth-server nft-auth-puller:./cmd/puller nft-auth-receive:./cmd/receive"

build_into() { # build_into <outdir> <goos> <goarch>
  local outdir="$1" goos="$2" goarch="$3" pair name pkg
  mkdir -p "$outdir"
  for pair in $CMDS; do
    name="${pair%%:*}"
    pkg="${pair##*:}"
    echo "==> build $name ($goos/$goarch)"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build -trimpath -ldflags "$LDFLAGS" -o "$outdir/$name" "$pkg"
  done
}

if $ALL_PLATFORMS; then
  for arch in amd64 arm64; do
    build_into "$DIST/linux-$arch" linux "$arch"
  done
  # Also drop host-native binaries at the top level for local install.sh use.
  build_into "$DIST" linux amd64
else
  build_into "$DIST" "${GOOS:-linux}" "${GOARCH:-amd64}"
fi

echo "==> done. artifacts under $DIST/"
find "$DIST" -maxdepth 2 -type f -name 'nft-auth-*' -print
