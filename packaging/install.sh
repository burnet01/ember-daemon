#!/usr/bin/env bash
# Installs or updates the Ember daemon on a Linux machine.
#
#   curl -fsSL https://burnet01.github.io/ember-daemon/install.sh | sudo bash
#
# Options, passed after `sudo bash -s --`:
#   --auth-key KEY  Log in to Tailscale with this key, so nobody has to open a login link.
#                   The TS_AUTHKEY environment variable works too.
#   --hostname NAME Name for this machine on Tailscale, used with a key.
#   --owner LOGIN   Tailscale login allowed to manage this node. Defaults to the machine's own.
#   --binary PATH   Install this emberd instead of downloading the latest release.
#   --no-auto-update  Don't install new releases by itself.
#
# Everything is inside main so a download cut off halfway can't run part of the script.
set -euo pipefail

RELEASES=https://github.com/burnet01/ember-daemon/releases/latest/download
ASSET=emberd-linux-x86_64
CONFIG=/etc/ember/config.toml
UNIT=/etc/systemd/system/emberd.service
TARGET=/usr/local/bin/emberd

say() { printf '\033[1;38;5;208m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

check_system() {
  [ "$(id -u)" -eq 0 ] || die "run this as root, for example: curl -fsSL <link> | sudo bash"
  [ "$(uname -s)" = Linux ] || die "the daemon only runs on Linux"
  [ "$(uname -m)" = x86_64 ] || [ -n "$BINARY" ] || die "only x86_64 is supported, and this machine is $(uname -m)"
  command -v systemctl >/dev/null || die "systemd is required"
  [ -f /sys/fs/cgroup/cgroup.controllers ] || die "cgroup v2 is required, and this system doesn't use it"
}

install_packages() {
  if command -v apt-get >/dev/null; then
    apt-get update -qq </dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" </dev/null >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q "$@" </dev/null
  elif command -v pacman >/dev/null; then
    pacman -S --noconfirm --needed "$@" </dev/null
  elif command -v zypper >/dev/null; then
    zypper --non-interactive install "$@" </dev/null
  else
    die "couldn't find a package manager. Install these yourself, then run this again: $*"
  fi
}

install_requirements() {
  local missing=()
  command -v nft >/dev/null || missing+=(nftables)
  if ! command -v ip >/dev/null; then
    if command -v dnf >/dev/null; then missing+=(iproute); else missing+=(iproute2); fi
  fi
  if [ "${#missing[@]}" -gt 0 ]; then
    say "Installing ${missing[*]}"
    install_packages "${missing[@]}"
  fi
}

login_with_key() {
  say "Logging in to Tailscale with the key"
  # In a private file, so the key isn't visible in this machine's process list.
  local key_file=$WORK/tailscale-key
  (umask 077; printf '%s' "$AUTH_KEY" >"$key_file")
  local args=(--auth-key="file:$key_file" --timeout=120s)
  if [ -n "$TS_NAME" ]; then args+=(--hostname="$TS_NAME"); fi
  local result=0
  tailscale up "${args[@]}" </dev/null || result=$?
  rm -f "$key_file"
  [ "$result" -eq 0 ] || die "Tailscale didn't accept the key. It may be expired, already used or revoked"
}

setup_tailscale() {
  if ! command -v tailscale >/dev/null; then
    say "Installing Tailscale"
    curl -fsSL https://tailscale.com/install.sh | sh
  fi
  systemctl enable --now tailscaled >/dev/null 2>&1 || true
  if tailscale ip -4 >/dev/null 2>&1; then
    [ -z "$AUTH_KEY" ] || say "Already on Tailscale, so the key wasn't needed"
  elif [ -n "$AUTH_KEY" ]; then
    login_with_key
  else
    say "Log this machine in to Tailscale with the link below"
    tailscale up </dev/null
  fi
  NODE_IP=$(tailscale ip -4 | head -n 1)
  [ -n "$NODE_IP" ] || die "Tailscale has no address on this machine yet"
}

find_owner() {
  if [ -z "$OWNER" ]; then
    OWNER=$(tailscale whois --json "$NODE_IP" | grep -o '"LoginName": *"[^"]*"' | head -n 1 | sed 's/.*: *"\(.*\)"/\1/') || true
  fi
  [ -n "$OWNER" ] || die "couldn't find this machine's Tailscale login. Run again with --owner your@login"
  if [ "$OWNER" = tagged-devices ]; then
    die "this machine uses a Tailscale tag, so it has no person's login. Run again with --owner your@login"
  fi
  # The value goes into a TOML string.
  if ! [[ "$OWNER" =~ ^[^\"\\[:space:][:cntrl:]]+$ ]]; then
    die "that doesn't look like a Tailscale login: $OWNER"
  fi
}

write_config() {
  if [ -f "$CONFIG" ]; then
    say "Keeping the existing $CONFIG"
    OWNER=$(grep -m1 '^owners' "$CONFIG" | sed 's/.*\[ *"\([^"]*\)".*/\1/') || true
    return
  fi
  find_owner
  install -d -m 0755 /etc/ember
  printf 'owners = ["%s"]\n' "$OWNER" >"$CONFIG"
  chmod 0644 "$CONFIG"
}

fetch_binary() {
  if [ -n "$BINARY" ]; then
    NEW=$BINARY
    return
  fi
  say "Downloading the latest release"
  curl -fsSL --retry 3 -o "$WORK/$ASSET" "$RELEASES/$ASSET"
  curl -fsSL --retry 3 -o "$WORK/$ASSET.sha256" "$RELEASES/$ASSET.sha256"
  local expected actual
  expected=$(cut -d ' ' -f 1 "$WORK/$ASSET.sha256")
  actual=$(sha256sum "$WORK/$ASSET" | cut -d ' ' -f 1)
  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    die "the download's checksum doesn't match, so nothing was installed"
  fi
  NEW=$WORK/$ASSET
}

install_binary() {
  CHANGED=1
  if cmp -s "$NEW" "$TARGET"; then
    CHANGED=0
    say "The daemon is already up to date"
    return
  fi
  # Renamed into place, because a running program's file can't be overwritten.
  install -m 0755 "$NEW" "$TARGET.new"
  mv -f "$TARGET.new" "$TARGET"
}

write_unit() {
  cat >"$WORK/emberd.service" <<'EOF'
[Unit]
Description=Ember node daemon
Wants=network-online.target tailscaled.service
After=network-online.target tailscaled.service

[Service]
Type=simple
ExecStart=/usr/local/bin/emberd run
Restart=on-failure
RestartSec=5
# Must exceed the time servers need to stop and save their worlds.
TimeoutStopSec=120
KillMode=mixed
# Servers live in /sys/fs/cgroup/ember, outside this unit, and emberd stops them itself.
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  if ! cmp -s "$WORK/emberd.service" "$UNIT"; then
    install -m 0644 "$WORK/emberd.service" "$UNIT"
    CHANGED=1
  fi
  systemctl daemon-reload
}

start_service() {
  "$TARGET" doctor || say "Some checks above failed. Fix them, then run: sudo systemctl restart emberd"
  systemctl enable emberd >/dev/null 2>&1
  if ! systemctl is-active -q emberd; then
    systemctl start emberd
  elif [ "$CHANGED" -eq 1 ]; then
    say "Restarting the daemon. Running servers stop and come back by themselves"
    "$TARGET" prepare-restart || true
    systemctl restart emberd
  fi
  sleep 2
  if ! systemctl is-active -q emberd; then
    journalctl -u emberd -n 20 --no-pager -o cat >&2 || true
    die "the daemon didn't stay running. The log is above"
  fi
}

setup_auto_update() {
  if [ "$AUTO_UPDATE" -eq 0 ]; then
    systemctl disable --now ember-update.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/ember-update.timer /etc/systemd/system/ember-update.service
    systemctl daemon-reload
    say "Automatic updates are off"
    return
  fi
  "$TARGET" enable-auto-update
}

main() {
  OWNER=""
  BINARY=""
  AUTO_UPDATE=1
  TS_NAME=""
  AUTH_KEY=${TS_AUTHKEY:-}
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --auth-key) [ "$#" -ge 2 ] || die "--auth-key needs a key"; AUTH_KEY=$2; shift 2 ;;
      --hostname) [ "$#" -ge 2 ] || die "--hostname needs a name"; TS_NAME=$2; shift 2 ;;
      --owner) [ "$#" -ge 2 ] || die "--owner needs a login"; OWNER=$2; shift 2 ;;
      --binary) [ "$#" -ge 2 ] || die "--binary needs a path"; BINARY=$2; shift 2 ;;
      --no-auto-update) AUTO_UPDATE=0; shift ;;
      *) die "unknown option: $1" ;;
    esac
  done

  check_system
  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
  install_requirements
  setup_tailscale
  write_config
  fetch_binary
  install_binary
  write_unit
  start_service
  setup_auto_update

  say "Ember is running at $NODE_IP"
  echo "Open Ember Panel on a device logged in to Tailscale as $OWNER, and this node appears by itself."
  if [ "$AUTO_UPDATE" -eq 1 ]; then
    echo "New releases install by themselves within a couple of minutes."
  else
    echo "Run the same command again to update."
  fi
}

main "$@"
