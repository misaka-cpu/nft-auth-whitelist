#!/usr/bin/env bash
# Role-based installer / updater for nft-auth-whitelist.
#
# It ONLY copies files, creates directories/users, and (optionally) installs a
# systemd unit. It intentionally does NOT, under any flag:
#   - start/enable/restart services automatically,
#   - run nft / apt-get / sysctl / reboot,
#   - enable the nft guard or --apply,
#   - modify sshd_config, open firewall ports, or touch SSH port 2222,
#   - overwrite an existing config (it writes <name>.json.new instead),
#   - modify authorized_keys UNLESS you pass --install-authorized-key <pubkey>,
#   - write any real secret anywhere.
#
# Usage: see --help.
set -euo pipefail

# ----- defaults ---------------------------------------------------------------
ROLE=""
DO_UPDATE=false
DRY_RUN=false
NO_SYSTEMD=false
AUTH_KEY_FILE=""
PREFIX="/usr/local"
CONFIG_DIR="/etc/nft-auth-whitelist"
DATA_DIR="/var/lib/nft-auth-whitelist"
LOG_DIR="/var/log/nft-auth-whitelist"
SVC_USER="nftauth"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
nft-auth-whitelist installer

Usage:
  ./install.sh --role <auth-server|receive|puller|all> [options]
  ./install.sh --update --role <role> [options]

Roles:
  auth-server   Install nft-auth-server + config/dirs + systemd unit (RFC machine).
  receive       Install nft-auth-receive + nftauth user + inbox dirs (po0 / test VPS).
                Run by an SSH forced command; no resident service is installed.
  puller        Install nft-auth-puller + sample configs (debug / compatibility).
  all           Install all three binaries (development / testing only).

Modes & options:
  --update                       Replace binaries only (backup first), keep configs.
  --no-systemd                   Do not install or touch any systemd unit.
  --install-authorized-key FILE  (receive) Append a forced-command authorized_keys
                                 line for the given PUBLIC key file. Off by default.
  --prefix DIR                   Binary prefix          (default /usr/local -> bin/).
  --config-dir DIR               Config dir             (default /etc/nft-auth-whitelist).
  --data-dir DIR                 Data dir               (default /var/lib/nft-auth-whitelist).
  --log-dir DIR                  Log dir                (default /var/log/nft-auth-whitelist).
  --user NAME                    Service user for receive (default nftauth).
  --dry-run                      Print actions without changing anything (no root needed).
  -h, --help                     Show this help.

This installer never enables/starts services, never enables nft/--apply, and
never overwrites an existing config.
EOF
}

# ----- arg parsing ------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role) ROLE="${2:-}"; shift 2 ;;
    --update) DO_UPDATE=true; shift ;;
    --no-systemd) NO_SYSTEMD=true; shift ;;
    --install-authorized-key) AUTH_KEY_FILE="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --config-dir) CONFIG_DIR="${2:-}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
    --log-dir) LOG_DIR="${2:-}"; shift 2 ;;
    --user) SVC_USER="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; echo "try: ./install.sh --help" >&2; exit 2 ;;
  esac
done

case "$ROLE" in
  auth-server|receive|puller|all) ;;
  "") echo "error: --role is required (auth-server|receive|puller|all)" >&2; exit 2 ;;
  *) echo "error: invalid --role: $ROLE (want auth-server|receive|puller|all)" >&2; exit 2 ;;
esac

BIN_DIR="$PREFIX/bin"

# Binary source: dist/ (from scripts/build.sh) or bin/ (from a release tarball).
if [[ -d "$SCRIPT_DIR/dist" ]]; then
  BINSRC="$SCRIPT_DIR/dist"
elif [[ -d "$SCRIPT_DIR/bin" ]]; then
  BINSRC="$SCRIPT_DIR/bin"
else
  BINSRC="$SCRIPT_DIR/dist"
fi

# ----- helpers ----------------------------------------------------------------
log()  { echo "==> $*"; }
note() { echo "    $*"; }

# run executes a command, or just prints it under --dry-run.
run() {
  if $DRY_RUN; then
    echo "DRY: $*"
  else
    "$@"
  fi
}

require_root() {
  if $DRY_RUN; then return 0; fi
  local uid="${EUID:-$(id -u)}"
  if [[ "$uid" -ne 0 ]]; then
    echo "error: must run as root (or use --dry-run)" >&2
    exit 1
  fi
}

timestamp() { date -u +%Y%m%d-%H%M%S; }

# install_bin <name>: back up an existing binary, then install the new one.
install_bin() {
  local name="$1" src dst
  src="$BINSRC/$name"
  dst="$BIN_DIR/$name"
  if [[ ! -f "$src" ]]; then
    if $DRY_RUN; then
      echo "DRY: would install $name from $src (not built yet)"
      return 0
    fi
    echo "error: $src not found. Run scripts/build.sh first." >&2
    exit 1
  fi
  run install -d "$BIN_DIR"
  if [[ -f "$dst" ]]; then
    run cp -a "$dst" "$dst.bak.$(timestamp)"
    note "backed up existing $dst"
  fi
  run install -m 0755 "$src" "$dst"
  log "installed $dst"
}

# install_cfg <example> <dest> [mode] [owner]: install the sample only if dest
# is absent; otherwise write dest.new and keep the existing file untouched.
install_cfg() {
  local src="$1" dst="$2" mode="${3:-0600}" owner="${4:-}"
  run install -d "$(dirname "$dst")"
  if [[ -f "$dst" ]]; then
    run install -m "$mode" "$src" "$dst.new"
    if [[ -n "$owner" ]]; then run chown "$owner" "$dst.new"; fi
    note "kept existing $dst (wrote $dst.new for comparison)"
  else
    run install -m "$mode" "$src" "$dst"
    if [[ -n "$owner" ]]; then run chown "$owner" "$dst"; fi
    log "installed sample $dst (edit it: set strong secrets)"
  fi
}

fix_cfg_access() { # fix_cfg_access <path> <mode> <owner>
  local dst="$1" mode="$2" owner="$3"
  if $DRY_RUN || [[ -f "$dst" ]]; then
    run chmod "$mode" "$dst"
    run chown "$owner" "$dst"
  fi
}

make_dir() { # make_dir <path> <mode> [owner]
  local path="$1" mode="$2" owner="${3:-}"
  run install -d -m "$mode" "$path"
  if [[ -n "$owner" ]]; then run chown "$owner" "$path"; fi
}

systemd_available() {
  $NO_SYSTEMD && return 1
  command -v systemctl >/dev/null 2>&1
}

# ----- systemd unit (auth-server) --------------------------------------------
install_authserver_unit() {
  local unit="/etc/systemd/system/nft-auth-server.service"
  if ! systemd_available; then
    note "systemd skipped (--no-systemd or systemctl absent). Sample unit in ./systemd/."
    return 0
  fi
  if $DRY_RUN; then
    echo "DRY: write $unit"
  else
    cat > "$unit" <<EOF
[Unit]
Description=nft-auth-whitelist auth server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$BIN_DIR/nft-auth-server --config $CONFIG_DIR/server.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$unit"
  fi
  log "installed $unit"
  run systemctl daemon-reload
  note "NOT enabled/started. Review, then: systemctl enable --now nft-auth-server.service"
}

# ----- authorized_keys (receive, opt-in only) --------------------------------
install_authorized_key() {
  local pub="$1"
  if [[ ! -f "$pub" ]]; then
    echo "error: --install-authorized-key file not found: $pub" >&2
    exit 1
  fi
  local home ssh_dir ak forced line
  home="$(getent passwd "$SVC_USER" 2>/dev/null | cut -d: -f6)"
  home="${home:-/home/$SVC_USER}"
  ssh_dir="$home/.ssh"
  ak="$ssh_dir/authorized_keys"
  forced="command=\"$BIN_DIR/nft-auth-receive -config $CONFIG_DIR/receive.json\",no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding"
  line="$forced $(cat "$pub")"

  make_dir "$ssh_dir" 0700 "$SVC_USER:$SVC_USER"
  if [[ -f "$ak" ]] && grep -qF "$(awk '{print $2}' "$pub")" "$ak" 2>/dev/null; then
    note "authorized_keys already contains this key; left unchanged"
    return 0
  fi
  if $DRY_RUN; then
    echo "DRY: append forced-command line for $pub to $ak"
  else
    umask 077
    printf '%s\n' "$line" >> "$ak"
    chown "$SVC_USER:$SVC_USER" "$ak"
    chmod 0600 "$ak"
  fi
  log "added forced-command authorized_keys entry for $SVC_USER"
}

print_forced_command_hint() {
  cat <<EOF
    Forced-command authorized_keys line for $SVC_USER (paste the PUSH side's PUBLIC key):

      command="$BIN_DIR/nft-auth-receive -config $CONFIG_DIR/receive.json",no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA... nft-auth-push

    (Or re-run with: --install-authorized-key /path/to/push_key.pub)
EOF
}

ensure_user() {
  if $DRY_RUN; then
    echo "DRY: ensure system user $SVC_USER exists (with home, shell /bin/bash)"
    return 0
  fi
  if id "$SVC_USER" >/dev/null 2>&1; then
    note "user $SVC_USER already exists"
  else
    # A login shell is required so the SSH forced command can run; security is
    # enforced by the forced-command authorized_keys entry, not by the shell.
    run useradd --system --create-home --shell /bin/bash "$SVC_USER"
    log "created system user $SVC_USER"
  fi
}

# ----- roles ------------------------------------------------------------------
role_auth_server() {
  log "role: auth-server"
  make_dir "$CONFIG_DIR" 0750
  make_dir "$CONFIG_DIR/ssh" 0700
  make_dir "$DATA_DIR" 0750
  make_dir "$LOG_DIR" 0750
  install_bin nft-auth-server
  install_cfg "$SCRIPT_DIR/configs/server.example.json" "$CONFIG_DIR/server.json"
  install_authserver_unit
  note "push identity_file belongs in $CONFIG_DIR/ssh/ (e.g. $CONFIG_DIR/ssh/nft_auth_push); keep it 0600."
}

role_receive() {
  log "role: receive"
  ensure_user
  make_dir "$CONFIG_DIR" 0750 "root:$SVC_USER"
  make_dir "$DATA_DIR" 0750 "$SVC_USER:$SVC_USER"
  make_dir "$DATA_DIR/inbox" 0750 "$SVC_USER:$SVC_USER"
  make_dir "$LOG_DIR" 0750 "$SVC_USER:$SVC_USER"
  install_bin nft-auth-receive
  install_cfg "$SCRIPT_DIR/configs/receive.example.json" "$CONFIG_DIR/receive.json" 0640 "root:$SVC_USER"
  fix_cfg_access "$CONFIG_DIR/receive.json" 0640 "root:$SVC_USER"
  if [[ -n "$AUTH_KEY_FILE" ]]; then
    install_authorized_key "$AUTH_KEY_FILE"
  else
    print_forced_command_hint
  fi
  note "receive runs on demand via the SSH forced command; no resident service installed."
}

role_puller() {
  log "role: puller (debug / compatibility)"
  make_dir "$CONFIG_DIR" 0750
  make_dir "$DATA_DIR" 0750
  make_dir "$LOG_DIR" 0750
  install_bin nft-auth-puller
  install_cfg "$SCRIPT_DIR/configs/puller.example.json" "$CONFIG_DIR/puller.json"
  install_cfg "$SCRIPT_DIR/configs/puller-file.example.json" "$CONFIG_DIR/puller-file.json"
  note "puller stays in export mode by default; nft/--apply are NOT enabled."
}

# ----- update mode ------------------------------------------------------------
do_update() {
  log "update mode: replacing binaries only (configs untouched)"
  case "$ROLE" in
    auth-server) install_bin nft-auth-server ;;
    receive)     install_bin nft-auth-receive ;;
    puller)      install_bin nft-auth-puller ;;
    all)
      install_bin nft-auth-server
      install_bin nft-auth-puller
      install_bin nft-auth-receive
      ;;
  esac
  note "binaries replaced (old ones saved as *.bak.<timestamp>)."
  note "restart any affected service yourself, e.g.: systemctl restart nft-auth-server.service"
}

# ----- main -------------------------------------------------------------------
require_root

log "nft-auth-whitelist installer"
note "role=$ROLE update=$DO_UPDATE dry-run=$DRY_RUN systemd=$([[ $NO_SYSTEMD == true ]] && echo off || echo on)"
note "prefix=$PREFIX config=$CONFIG_DIR data=$DATA_DIR log=$LOG_DIR user=$SVC_USER"
note "binary source: $BINSRC"

if $DO_UPDATE; then
  do_update
  log "done (update)."
  exit 0
fi

case "$ROLE" in
  auth-server) role_auth_server ;;
  receive)     role_receive ;;
  puller)      role_puller ;;
  all)
    note "role 'all' is for development/testing only, not recommended in production."
    role_auth_server
    role_puller
    role_receive
    ;;
esac

echo
log "done."
note "Reminders: set strong secrets in $CONFIG_DIR/*.json; deploy auth-server behind HTTPS;"
note "keep receive keys as forced commands; nft/--apply stay OFF; do not block your SSH management port."
