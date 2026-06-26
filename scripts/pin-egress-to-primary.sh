#!/usr/bin/env bash
# Identify a VPS's PRIMARY (statically-configured) IP — as opposed to a secondary
# "exit" IP that exit-ip-manager bolts on and makes the default egress — and
# optionally pin outbound traffic to a destination so it egresses from that
# primary IP.
#
# Why: when exit-ip-manager makes a secondary IP the default egress, outbound
# connections (e.g. nft-auth-whitelist's SSH push to po0) source from the
# secondary IP. Anchoring on the stable primary IP keeps the receiver's firewall
# allow-list simple and avoids breakage when the secondary IP changes.
#
# Primary IP detection (in order):
#   1. /etc/exit-ip-manager/managed_ips  -> the recorded original IP/gateway
#      (line format: iface|attached_cidr|attached_gw|orig_ip|orig_gw)
#   2. /etc/network/interfaces (+ interfaces.d) -> the static address/gateway
#
# Usage:
#   pin-egress-to-primary.sh                         Identify only (read-only).
#   pin-egress-to-primary.sh --dest <ip>             Pin egress to <ip> via primary (runtime).
#   pin-egress-to-primary.sh --dest <ip> --dry-run   Show the route, change nothing.
#   pin-egress-to-primary.sh --dest <ip> --persist   Also persist (ifupdown post-up).
set -euo pipefail

DEST=""; DRY_RUN=false; PERSIST=false

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dest) DEST="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --persist) PERSIST=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

iface_for() { # iface_for [dest]
  if [ -n "${1:-}" ]; then ip route get "$1" 2>/dev/null; else ip route show default 2>/dev/null; fi \
    | sed -n 's/.* dev \([^ ]\+\).*/\1/p' | head -1
}

IFACE="$(iface_for "$DEST")"
[ -n "$IFACE" ] || { echo "error: cannot determine outgoing interface" >&2; exit 1; }

PRIMARY_IP=""; PRIMARY_GW=""; ATTACHED_IP=""; SRC="managed_ips"
MIPS=/etc/exit-ip-manager/managed_ips
if [ -r "$MIPS" ]; then
  line="$(awk -F'|' -v ifc="$IFACE" 'NF>=5 && $1==ifc {print; exit}' "$MIPS")"
  if [ -n "$line" ]; then
    ATTACHED_IP="$(printf '%s' "$line" | awk -F'|' '{print $2}' | cut -d/ -f1)"
    PRIMARY_IP="$(printf '%s'  "$line" | awk -F'|' '{print $4}')"
    PRIMARY_GW="$(printf '%s'  "$line" | awk -F'|' '{print $5}')"
  fi
fi
if [ -z "$PRIMARY_IP" ]; then
  SRC="interfaces"
  conf="$(cat /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null || true)"
  PRIMARY_IP="$(printf '%s\n' "$conf" | awk -v ifc="$IFACE" \
    '$1=="iface"&&$2==ifc{b=1;next} $1=="iface"{b=0} b&&$1=="address"{print $2;exit}' | cut -d/ -f1)"
  PRIMARY_GW="$(printf '%s\n' "$conf" | awk -v ifc="$IFACE" \
    '$1=="iface"&&$2==ifc{b=1;next} $1=="iface"{b=0} b&&$1=="gateway"{print $2;exit}')"
fi
[ -n "$PRIMARY_IP" ] || { echo "error: could not identify primary IP for $IFACE" >&2; exit 1; }

DEFAULT_SRC="$(ip route show default 2>/dev/null | sed -n 's/.*src \([0-9a-fA-F.:]\+\).*/\1/p' | head -1)"

echo "interface:         $IFACE"
echo "primary IP:        $PRIMARY_IP   (gateway ${PRIMARY_GW:-?}; from $SRC)"
[ -n "$ATTACHED_IP" ] && echo "attached/exit IP:  $ATTACHED_IP   (added by exit-ip-manager)"
echo "default egress src: ${DEFAULT_SRC:-?}"
if [ -n "$ATTACHED_IP" ] && [ "$DEFAULT_SRC" = "$ATTACHED_IP" ]; then
  echo "note: general outbound currently egresses from the ATTACHED IP, not the primary."
fi

[ -n "$DEST" ] || exit 0
[ -n "$PRIMARY_GW" ] || { echo "error: primary gateway unknown; cannot build route" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || $DRY_RUN || { echo "error: must run as root to apply a route" >&2; exit 1; }

ROUTE="ip route replace $DEST via $PRIMARY_GW dev $IFACE src $PRIMARY_IP"
echo; echo "pin $DEST egress via primary IP:"; echo "  $ROUTE"
if $DRY_RUN; then echo "(dry-run: nothing changed)"; exit 0; fi

eval "$ROUTE"
echo "applied -> $(ip route get "$DEST" | head -1)"
echo "reminder: the receiver's firewall must allow this primary IP ($PRIMARY_IP) on the push/SSH port."

if $PERSIST; then
  IF=/etc/network/interfaces
  if [ ! -f "$IF" ] || ! grep -qE "^[[:space:]]*iface[[:space:]]+$IFACE[[:space:]]+inet" "$IF"; then
    echo "warn: $IFACE is not ifupdown-managed in $IF; persist manually for your network stack." >&2
    exit 0
  fi
  d="${DEST%/*}"
  if grep -Eq "ip route replace[[:space:]]+${d}(/[0-9]+)?[[:space:]].*src[[:space:]]+${PRIMARY_IP}([[:space:]]|\$)" "$IF"; then
    echo "persist: an equivalent post-up route already exists in $IF; left unchanged."
  else
    cp -a "$IF" "$IF.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    add="    post-up ip route replace $DEST via $PRIMARY_GW dev $IFACE src $PRIMARY_IP || true"
    awk -v ifc="$IFACE" -v add="$add" \
      '{print} $1=="iface"&&$2==ifc&&$3=="inet"&&!done{print add; done=1}' "$IF" > "$IF.tmp" \
      && mv "$IF.tmp" "$IF"
    echo "persisted post-up route in $IF (backup saved)."
  fi
fi
