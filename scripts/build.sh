#!/usr/bin/env bash
# Build both binaries into dist/ after formatting and testing.
# This script does NOT touch systemd, nft, apt, or any system state.
set -euo pipefail

cd "$(dirname "$0")/.."

DIST="dist"
mkdir -p "$DIST"

echo "==> gofmt"
gofmt -l . | (grep -v '^$' && echo "above files need gofmt" && exit 1) || true
gofmt -w .

echo "==> go vet"
go vet ./...

echo "==> go test"
go test ./...

VERSION="${VERSION:-0.1.0}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w \
  -X github.com/misaka-cpu/nft-auth-whitelist/internal/version.Version=${VERSION} \
  -X github.com/misaka-cpu/nft-auth-whitelist/internal/version.Commit=${COMMIT} \
  -X github.com/misaka-cpu/nft-auth-whitelist/internal/version.Date=${DATE}"

echo "==> build auth-server"
CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$DIST/nft-auth-server" ./cmd/auth-server

echo "==> build puller"
CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$DIST/nft-auth-puller" ./cmd/puller

echo "==> build receive"
CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$DIST/nft-auth-receive" ./cmd/receive

echo "==> done. binaries in $DIST/"
ls -l "$DIST"
