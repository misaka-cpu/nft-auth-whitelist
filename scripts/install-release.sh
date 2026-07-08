#!/usr/bin/env bash
# Download a published release tarball, verify it when a .sha256 asset exists,
# then delegate installation to the tarball's install.sh.
#
# This script intentionally does not implement install logic itself. The package
# install.sh remains the single installer and keeps its safety guarantees: no
# service start/enable, no nft apply, no sshd/firewall edits, and no config
# overwrite unless the user explicitly asks for an option supported there.
set -euo pipefail

REPO="${NFT_AUTH_REPO:-misaka-cpu/nft-auth-whitelist}"
VERSION="${NFT_AUTH_VERSION:-latest}"
TMP_PARENT="${TMPDIR:-/tmp}"

usage() {
  cat <<'EOF'
nft-auth-whitelist release installer

Usage:
  curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nft-auth-whitelist/main/scripts/install-release.sh \
    | sudo bash -s -- --role <auth-server|receive|puller|all> [install.sh options]

Installer options consumed by this wrapper:
  --repo OWNER/REPO       GitHub repo (default: misaka-cpu/nft-auth-whitelist)
  --version TAG           Release tag, or "latest" (default: latest)
  --tmp-dir DIR           Parent temp dir (default: $TMPDIR or /tmp)
  -h, --help              Show this help

All other arguments are passed through to the packaged ./install.sh.

Examples:
  sudo bash scripts/install-release.sh --role auth-server
  sudo bash scripts/install-release.sh --version v0.7.0 --role receive
  sudo bash scripts/install-release.sh --role receive --install-authorized-key /tmp/push.pub
EOF
}

install_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --tmp-dir)
      TMP_PARENT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      install_args+=("$@")
      break
      ;;
    *)
      install_args+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$REPO" || "$REPO" != */* ]]; then
  echo "error: --repo must look like OWNER/REPO" >&2
  exit 2
fi
if [[ -z "$VERSION" ]]; then
  echo "error: --version cannot be empty" >&2
  exit 2
fi

os="$(uname -s)"
if [[ "$os" != "Linux" ]]; then
  echo "error: only Linux release tarballs are published (got $os)" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "error: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

name="nft-auth-whitelist"
tarball="$name-linux-$arch.tar.gz"
if [[ "$VERSION" == "latest" ]]; then
  base_url="https://github.com/$REPO/releases/latest/download"
else
  base_url="https://github.com/$REPO/releases/download/$VERSION"
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command: $1" >&2
    exit 1
  fi
}
need_cmd curl
need_cmd tar
need_cmd mktemp

workdir="$(mktemp -d "$TMP_PARENT/nft-auth-install.XXXXXX")"
cleanup() {
  rm -rf "$workdir"
}
trap cleanup EXIT

echo "==> downloading $base_url/$tarball"
curl -fL --proto '=https' --tlsv1.2 -o "$workdir/$tarball" "$base_url/$tarball"

if curl -fL --proto '=https' --tlsv1.2 -o "$workdir/$tarball.sha256" "$base_url/$tarball.sha256"; then
  need_cmd sha256sum
  echo "==> verifying $tarball.sha256"
  (cd "$workdir" && sha256sum -c "$tarball.sha256")
else
  echo "WARN: no .sha256 asset found for $tarball; continuing without checksum verification" >&2
fi

echo "==> extracting"
tar -xzf "$workdir/$tarball" -C "$workdir"

cd "$workdir/$name"
echo "==> running packaged install.sh ${install_args[*]}"
bash ./install.sh "${install_args[@]}"
