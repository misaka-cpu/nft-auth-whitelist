#!/usr/bin/env bash
# Resolve DDNS domain(s) to IPv4 and export them as one CIDR per line, for use
# as an EXTRA whitelist file next to allow.txt (nftables-nat-rust-enhanced
# dynamic_whitelist file_sources, or an nft set sync script).
#
# Semantics match the rest of the project:
#   - atomic write (temp file in the same dir + rename), only when the content
#     actually changed;
#   - if ANY domain fails to resolve, the old output file is kept untouched and
#     the script exits non-zero — a DNS blip must never shrink the whitelist.
#
# Usage:
#   scripts/ddns-whitelist-sync.sh --out /var/lib/nft-auth-whitelist/ddns.txt \
#       [--prefix 32|24] home.example.com [more.example.com ...]
#
# Meant to be run from cron or a systemd timer (e.g. every minute).
set -uo pipefail

OUT=""
PREFIX="32"
DOMAINS=()

usage() {
  cat <<'EOF'
Usage:
  scripts/ddns-whitelist-sync.sh --out FILE [--prefix 32|24] DOMAIN [DOMAIN...]

Options:
  --out FILE     output file, one CIDR per line (required)
  --prefix N     32 (default) writes a.b.c.d/32; 24 writes a.b.c.0/24
  -h, --help     show this help

Exit status: 0 = output is up to date (written or unchanged),
             1 = a domain failed to resolve (old output kept), 2 = usage error.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    *) DOMAINS+=("$1"); shift ;;
  esac
done

if [[ -z "$OUT" || "${#DOMAINS[@]}" -eq 0 ]]; then
  usage >&2
  exit 2
fi
if [[ "$PREFIX" != "32" && "$PREFIX" != "24" ]]; then
  echo "error: --prefix must be 32 or 24" >&2
  exit 2
fi

# resolve_v4 prints the IPv4 addresses of one domain, one per line. Tests can
# override the resolver with NFT_AUTH_DDNS_RESOLVER=<command taking a domain>.
resolve_v4() {
  local domain="$1"
  if [[ -n "${NFT_AUTH_DDNS_RESOLVER:-}" ]]; then
    "$NFT_AUTH_DDNS_RESOLVER" "$domain"
    return
  fi
  getent ahostsv4 "$domain" | awk '{print $1}'
}

is_ipv4() {
  local ip="$1" part
  local IFS=.
  # shellcheck disable=SC2086
  set -- $ip
  [[ $# -eq 4 ]] || return 1
  for part in "$@"; do
    [[ "$part" =~ ^[0-9]+$ ]] || return 1
    (( part >= 0 && part <= 255 )) || return 1
  done
  return 0
}

CIDRS=""
for domain in "${DOMAINS[@]}"; do
  ips="$(resolve_v4 "$domain" 2>/dev/null | sort -u)"
  got=0
  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    if ! is_ipv4 "$ip"; then
      continue
    fi
    if [[ "$PREFIX" == "24" ]]; then
      CIDRS+="${ip%.*}.0/24"$'\n'
    else
      CIDRS+="${ip}/32"$'\n'
    fi
    got=1
  done <<< "$ips"
  if [[ "$got" -eq 0 ]]; then
    echo "error: could not resolve an IPv4 address for $domain; keeping old $OUT" >&2
    exit 1
  fi
done

WANT="$(printf '%s' "$CIDRS" | sort -u)"
[[ -n "$WANT" ]] && WANT+=$'\n'

# Compare against the current content; skip the write when nothing changed so
# file-watchers (systemd .path units) are not triggered for no reason.
if [[ -f "$OUT" ]] && printf '%s' "$WANT" | cmp -s - "$OUT"; then
  exit 0
fi

outdir="$(dirname "$OUT")"
tmp="$(mktemp "$outdir/.ddns-sync.XXXXXX")" || exit 1
printf '%s' "$WANT" > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$OUT"
echo "updated $OUT:"
cat "$OUT"
