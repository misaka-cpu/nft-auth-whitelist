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

run_install_tests() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    bash scripts/test-install.sh
  elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo -n bash scripts/test-install.sh
  else
    bash scripts/test-install.sh
  fi
}

echo "==> scripts/test-install.sh"
run_install_tests

echo "==> scripts/test-preflight.sh"
bash scripts/test-preflight.sh

echo
echo "==> all checks passed"
