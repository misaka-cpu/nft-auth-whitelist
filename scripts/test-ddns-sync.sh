#!/usr/bin/env bash
# Offline tests for scripts/ddns-whitelist-sync.sh using a fake resolver.
set -euo pipefail

cd "$(dirname "$0")/.."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

OUT="$WORK/ddns.txt"
RESOLVER="$WORK/fake-resolver.sh"
ANSWERS="$WORK/answers"

# The fake resolver prints the lines of $ANSWERS/<domain>, or nothing.
mkdir -p "$ANSWERS"
cat > "$RESOLVER" <<EOF
#!/bin/sh
cat "$ANSWERS/\$1" 2>/dev/null
EOF
chmod +x "$RESOLVER"
export NFT_AUTH_DDNS_RESOLVER="$RESOLVER"

fail() { echo "FAIL: $1" >&2; exit 1; }

echo "==> writes /32 entries, sorted and de-duplicated"
printf '203.0.113.7\n203.0.113.7\n198.51.100.9\n' > "$ANSWERS/home.example.test"
bash scripts/ddns-whitelist-sync.sh --out "$OUT" home.example.test >/dev/null
printf '198.51.100.9/32\n203.0.113.7/32\n' | cmp -s - "$OUT" || fail "unexpected /32 output: $(cat "$OUT")"

echo "==> --prefix 24 maps to the /24 network"
bash scripts/ddns-whitelist-sync.sh --out "$OUT" --prefix 24 home.example.test >/dev/null
printf '198.51.100.0/24\n203.0.113.0/24\n' | cmp -s - "$OUT" || fail "unexpected /24 output: $(cat "$OUT")"

echo "==> unchanged content does not rewrite the file"
before="$(stat -c '%Y %i' "$OUT")"
sleep 1.1
bash scripts/ddns-whitelist-sync.sh --out "$OUT" --prefix 24 home.example.test >/dev/null
after="$(stat -c '%Y %i' "$OUT")"
[[ "$before" == "$after" ]] || fail "file was rewritten although nothing changed"

echo "==> multiple domains are unioned"
printf '192.0.2.1\n' > "$ANSWERS/second.example.test"
bash scripts/ddns-whitelist-sync.sh --out "$OUT" home.example.test second.example.test >/dev/null
printf '192.0.2.1/32\n198.51.100.9/32\n203.0.113.7/32\n' | cmp -s - "$OUT" || fail "unexpected union output: $(cat "$OUT")"

echo "==> a resolve failure keeps the old file and exits 1"
keep="$(cat "$OUT")"
rm -f "$ANSWERS/second.example.test"
if bash scripts/ddns-whitelist-sync.sh --out "$OUT" home.example.test second.example.test >/dev/null 2>&1; then
  fail "expected non-zero exit on resolve failure"
fi
[[ "$(cat "$OUT")" == "$keep" ]] || fail "old file must be kept on resolve failure"

echo "==> garbage resolver output is rejected, old file kept"
printf 'not-an-ip\n999.1.1.1\n' > "$ANSWERS/bad.example.test"
if bash scripts/ddns-whitelist-sync.sh --out "$OUT" bad.example.test >/dev/null 2>&1; then
  fail "expected non-zero exit on garbage output"
fi
[[ "$(cat "$OUT")" == "$keep" ]] || fail "old file must be kept on garbage output"

echo "==> usage errors exit 2"
rc=0; bash scripts/ddns-whitelist-sync.sh --out "$OUT" >/dev/null 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || fail "missing domain must exit 2, got $rc"
rc=0; bash scripts/ddns-whitelist-sync.sh --out "$OUT" --prefix 16 x.test >/dev/null 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || fail "bad prefix must exit 2, got $rc"

echo
echo "==> ddns-sync tests passed"
