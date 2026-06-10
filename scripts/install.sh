#!/usr/bin/env bash
# Install already-built binaries and SAMPLE configs.
#
# This script intentionally does NOT:
#   - run systemctl (no enable/start/restart),
#   - run nft / apt-get / sysctl / reboot,
#   - overwrite existing config files,
#   - modify the nftables-nat-rust-enhanced main project.
# It only copies files and prints the manual next steps.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CFG_DIR="${CFG_DIR:-/etc/nft-auth-whitelist}"
DATA_DIR="${DATA_DIR:-/var/lib/nft-auth-whitelist}"

if [ ! -d dist ]; then
  echo "dist/ not found. Run scripts/build.sh first." >&2
  exit 1
fi

install -d "$BIN_DIR" "$CFG_DIR" "$DATA_DIR"

install_bin() {
  local name="$1"
  if [ -f "dist/$name" ]; then
    install -m 0755 "dist/$name" "$BIN_DIR/$name"
    echo "installed $BIN_DIR/$name"
  fi
}

install_bin nft-auth-server
install_bin nft-auth-puller
install_bin nft-auth-receive

install_cfg() {
  local src="$1" dst="$2"
  if [ -f "$dst" ]; then
    echo "kept existing $dst (not overwritten)"
  else
    install -m 0600 "$src" "$dst"
    echo "installed sample $dst"
  fi
}

install_cfg configs/server.example.json "$CFG_DIR/server.json"
install_cfg configs/puller.example.json "$CFG_DIR/puller.json"
install_cfg configs/receive.example.json "$CFG_DIR/receive.json"

echo
echo "Next steps (do these manually after reviewing the configs):"
echo "  1. Edit $CFG_DIR/server.json and/or $CFG_DIR/puller.json (set strong username/password/pull_token/hmac_secret)."
echo "  2. Put the auth-server behind HTTPS (Caddy/Nginx). Do NOT expose Basic Auth over plain HTTP."
echo "  3. Copy the desired unit files from ./systemd/ into /etc/systemd/system/ and review them."
echo "  4. Only then: systemctl daemon-reload && systemctl enable --now <unit>"
echo
echo "This installer did not start or enable anything."
