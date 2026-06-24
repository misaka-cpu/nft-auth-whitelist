#!/usr/bin/env bash
# Static / dry-run tests for install.sh and secret-scan.sh. These never modify
# real system state: dry-run for most checks, and a real run only into throwaway
# temp directories.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
INSTALL="$ROOT/install.sh"
SCAN="$ROOT/scripts/secret-scan.sh"

PASS=0
FAIL=0
ok()   { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

# expect_ok <desc> <cmd...>
expect_ok() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc (expected exit 0)"; fi
}
# expect_fail <desc> <cmd...>
expect_fail() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then bad "$desc (expected non-zero exit)"; else ok "$desc"; fi
}

echo "== install.sh argument handling =="
expect_ok   "install --help"                       bash "$INSTALL" --help
expect_ok   "install --role receive --dry-run"     bash "$INSTALL" --role receive --dry-run
expect_ok   "install --role auth-server --dry-run" bash "$INSTALL" --role auth-server --dry-run
expect_ok   "install --role puller --dry-run"      bash "$INSTALL" --role puller --dry-run
expect_fail "install --role bogus rejected"        bash "$INSTALL" --role bogus
expect_fail "install missing --role rejected"      bash "$INSTALL"
expect_fail "install unknown flag rejected"        bash "$INSTALL" --role all --frobnicate

echo "== auth-server systemd hardening =="
UNIT="$ROOT/systemd/nft-auth-whitelist-server.service"
expect_ok   "sample unit runs with explicit root ownership" grep -q '^User=root$' "$UNIT"
expect_ok   "sample unit runs with explicit root group" grep -q '^Group=root$' "$UNIT"
expect_fail "sample unit has no DynamicUser" grep -q '^DynamicUser=' "$UNIT"
expect_ok   "sample unit restricts writable paths" grep -q '^ReadWritePaths=/var/lib/nft-auth-whitelist /var/log/nft-auth-whitelist$' "$UNIT"
expect_ok   "installer unit uses explicit root ownership" grep -q 'User=root' "$INSTALL"
expect_ok   "installer unit uses strict filesystem protection" grep -q 'ProtectSystem=strict' "$INSTALL"
expect_fail "installer unit does not make config writable" grep -qF 'ReadWritePaths=$DATA_DIR $LOG_DIR $CONFIG_DIR' "$INSTALL"
expect_ok   "server audit log stays under log directory" grep -q '"audit_log": "/var/log/nft-auth-whitelist/server-audit.log"' "$ROOT/configs/server.example.json"
expect_ok   "puller audit log stays under log directory" grep -q '"audit_log": "/var/log/nft-auth-whitelist/puller-audit.log"' "$ROOT/configs/puller.example.json"
expect_ok   "file puller audit log stays under log directory" grep -q '"audit_log": "/var/log/nft-auth-whitelist/puller-audit.log"' "$ROOT/configs/puller-file.example.json"

echo "== install.sh does not overwrite existing config (real run into temp dirs) =="
# Ensure the auth-server binary exists so the real run can copy it.
if [[ ! -x "$ROOT/dist/nft-auth-server" ]]; then
  mkdir -p "$ROOT/dist"
  ( cd "$ROOT" && go build -o "$ROOT/dist/nft-auth-server" ./cmd/auth-server )
fi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
common_args=(--role auth-server --no-systemd
  --prefix "$TMP/usr-local" --config-dir "$TMP/etc"
  --data-dir "$TMP/var-lib" --log-dir "$TMP/var-log")

if bash "$INSTALL" "${common_args[@]}" >/dev/null 2>&1; then
  if [[ -f "$TMP/etc/server.json" ]]; then ok "first run installed server.json"; else bad "server.json not installed"; fi
  # Mark the config, then re-run; it must be preserved and a .new written.
  printf '{"marker":"keep-me"}\n' > "$TMP/etc/server.json"
  if bash "$INSTALL" "${common_args[@]}" >/dev/null 2>&1; then
    if grep -q keep-me "$TMP/etc/server.json"; then ok "existing server.json preserved on re-run"; else bad "server.json was overwritten"; fi
    if [[ -f "$TMP/etc/server.json.new" ]]; then ok "server.json.new written for comparison"; else bad "server.json.new missing"; fi
  else
    bad "second install run failed"
  fi
else
  bad "first install run failed"
fi

echo "== secret-scan.sh =="
expect_ok "secret-scan clean repo passes" bash "$SCAN"

# Build a fake leak in a temp dir WITHOUT writing the trigger phrase verbatim in
# this script (so the clean-repo scan above keeps passing).
LEAKDIR="$(mktemp -d)"
trap 'rm -rf "$TMP" "$LEAKDIR"' EXIT
mark_a="BEGIN OPENSSH"
mark_b="PRIVATE KEY"
printf -- '-----%s %s-----\nzzzfakekeymaterialzzz\n-----END %s-----\n' "$mark_a" "$mark_b" "$mark_b" > "$LEAKDIR/leaked"
expect_fail "secret-scan flags a fake private key" bash "$SCAN" "$LEAKDIR"

echo "== all three commands compile =="
BUILDTMP="$(mktemp -d)"
trap 'rm -rf "$TMP" "$LEAKDIR" "$BUILDTMP"' EXIT
build_ok=true
for pair in "nft-auth-server:./cmd/auth-server" "nft-auth-puller:./cmd/puller" "nft-auth-receive:./cmd/receive"; do
  name="${pair%%:*}"; pkg="${pair##*:}"
  if ! ( cd "$ROOT" && go build -o "$BUILDTMP/$name" "$pkg" ) >/dev/null 2>&1; then
    build_ok=false; echo "    build failed: $name"
  fi
done
$build_ok && ok "server/puller/receive all build" || bad "one or more binaries failed to build"

echo
echo "test-install: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
