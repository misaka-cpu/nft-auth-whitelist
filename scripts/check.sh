#!/usr/bin/env bash
# Run the full local verification suite. Read-only with respect to the system
# (it only builds into dist/ and reads the tree); it changes no system state.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> gofmt -l ."
fmt_out="$(gofmt -l .)"
if [[ -n "$fmt_out" ]]; then
  echo "these files need gofmt:" >&2
  echo "$fmt_out" >&2
  exit 1
fi
echo "    clean"

echo "==> go vet ./..."
go vet ./...

echo "==> go test ./..."
go test ./...

echo "==> go build ./..."
go build ./...

echo "==> scripts/build.sh"
bash scripts/build.sh

echo "==> scripts/secret-scan.sh"
bash scripts/secret-scan.sh

echo "==> scripts/test-install.sh"
bash scripts/test-install.sh

echo
echo "==> all checks passed"
