#!/usr/bin/env bash
# Runs ember-probe inside a real sandbox. Requires root and a built debug target.
set -euo pipefail

EMBERD=./target/debug/emberd
PROBE=./target/debug/ember-probe
SECRET=/var/lib/ember-test-secret
LISTEN_PORT=18080

echo "host secret" > "$SECRET"
python3 -m http.server "$LISTEN_PORT" --bind 0.0.0.0 --directory /tmp >/dev/null 2>&1 &
LISTENER=$!
trap 'kill "$LISTENER" 2>/dev/null || true; rm -f "$SECRET"' EXIT
sleep 1

HOST_IP=$(hostname -I | awk '{print $1}')
# Index 16000 of 10.213.0.0/16 puts the sandbox's gateway, this host, at 10.213.250.1.
GATEWAY=10.213.250.1

echo "=== full escape check"
"$EMBERD" sandbox-test --probe "$PROBE" -- \
  --secret "$SECRET" \
  --secret "$PWD/Cargo.toml" \
  --deny "$GATEWAY:$LISTEN_PORT" \
  --deny "$HOST_IP:$LISTEN_PORT" \
  --deny "127.0.0.1:$LISTEN_PORT" \
  --internet 1.1.1.1:443

echo "=== process limit"
OUT=$("$EMBERD" sandbox-test --pids 64 --probe "$PROBE" -- --thread-bomb)
echo "$OUT"
COUNT=$(echo "$OUT" | awk '/^THREADS/ {print $2}')
if [ -z "$COUNT" ] || [ "$COUNT" -gt 64 ] || [ "$COUNT" -lt 5 ]; then
  echo "FAIL: expected the process limit to stop the thread bomb near 64, got '$COUNT'"
  exit 1
fi

echo "=== memory limit"
set +e
OUT=$("$EMBERD" sandbox-test --memory-mb 256 --probe "$PROBE" -- --memory-bomb 2>&1)
CODE=$?
set -e
echo "$OUT"
if [ "$CODE" -eq 0 ] || echo "$OUT" | grep -q SURVIVED; then
  echo "FAIL: the memory bomb survived a 256 MB limit (exit $CODE)"
  exit 1
fi

echo "=== cleanup"
if ip netns list | grep -q '^ember-'; then
  echo "FAIL: network namespaces were left behind"
  exit 1
fi
if [ -d /sys/fs/cgroup/ember/sandbox-test ]; then
  echo "FAIL: cgroup was left behind"
  exit 1
fi
echo "All sandbox checks passed."
