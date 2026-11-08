#!/usr/bin/env bash
# Installs emberd on a Linux node. Usage: sudo ./install.sh <path-to-emberd> <your-tailscale-login>
set -euo pipefail

BIN=${1:-}
OWNER=${2:-}
if [ "$(id -u)" -ne 0 ] || [ -z "$BIN" ] || [ -z "$OWNER" ]; then
  echo "usage: sudo $0 <path-to-emberd> <your-tailscale-login>"
  echo "find your login with: tailscale status --json | grep LoginName"
  exit 1
fi
if ! command -v tailscale >/dev/null; then
  echo "Tailscale is not installed. Install it first: https://tailscale.com/download/linux"
  exit 1
fi
for tool in nft ip; do
  if ! command -v "$tool" >/dev/null; then
    echo "Missing '$tool'. On Debian or Ubuntu run: apt install nftables iproute2"
    exit 1
  fi
done

install -m 0755 "$BIN" /usr/local/bin/emberd
install -d -m 0755 /etc/ember
if [ ! -f /etc/ember/config.toml ]; then
  # printf %q is not TOML, so reject anything that could break out of the string.
  case "$OWNER" in
    *\"*|*\\*|*$'\n'*) echo "invalid login"; exit 1 ;;
  esac
  printf 'owners = ["%s"]\n' "$OWNER" > /etc/ember/config.toml
  chmod 0644 /etc/ember/config.toml
fi

HERE=$(cd "$(dirname "$0")" && pwd)
install -m 0644 "$HERE/emberd.service" /etc/systemd/system/emberd.service
systemctl daemon-reload
/usr/local/bin/emberd doctor || echo "Fix the failed checks above, then run: systemctl restart emberd"
systemctl enable --now emberd
echo "emberd is running. Open Ember Panel on a machine logged in to Tailscale as $OWNER."
