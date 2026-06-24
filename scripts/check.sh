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

echo "==> scripts/package.sh"
bash scripts/package.sh

echo "==> scripts/test-package.sh"
bash scripts/test-package.sh

echo "==> scripts/test-ci.sh"
bash scripts/test-ci.sh

echo "==> scripts/test-local-shadow.sh"
bash scripts/test-local-shadow.sh

echo "==> scripts/secret-scan.sh"
bash scripts/secret-scan.sh

run_rooted_script() {
  local script="$1"
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    bash "$script"
  elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo -n bash "$script"
  else
    bash "$script"
  fi
}

echo "==> scripts/test-install.sh"
run_rooted_script scripts/test-install.sh

echo "==> scripts/test-preflight.sh"
run_rooted_script scripts/test-preflight.sh

echo
echo "==> all checks passed"
