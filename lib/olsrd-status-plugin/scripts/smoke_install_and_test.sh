#!/usr/bin/env bash
# Simple smoke-test for olsrd-status-plugin
# - builds the plugin
# - shows whether the debug symbol is exported
# - optionally installs the .so to a destination
# - attempts a HTTP GET to /status/ping

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

JOBS=${JOBS:-2}
INSTALL_DEST=${INSTALL_DEST:-/usr/lib/olsrd_status.so.1.0}
DO_INSTALL=0

usage(){
  cat <<EOF
Usage: $0 [--install] [--dest /path/to/olsrd_status.so.1.0]

Options:
  --install            Copy built .so to system destination (may require sudo).
  --dest PATH          Override install destination (default $INSTALL_DEST).
  --help               Show this message.

Examples:
  $0                     # build, inspect, try ping against localhost:11080
  $0 --install           # build and install (uses sudo if needed)
  INSTALL_DEST=/custom/path $0 --install
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install) DO_INSTALL=1; shift ;;
    --dest) INSTALL_DEST="$2"; shift 2 ;;
    --help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

echo "[smoke] building plugin..."
make -j${JOBS}

SO=build/olsrd_status.so.1.0
if [[ ! -f "$SO" ]]; then
  echo "[smoke][error] expected $SO not found" >&2
  exit 3
fi

echo "[smoke] file info:"; file "$SO"

echo "[smoke] exported symbols (searching for g_log_request_debug):"
if command -v readelf >/dev/null 2>&1; then
  readelf -Ws "$SO" | grep g_log_request_debug || true
elif command -v nm >/dev/null 2>&1; then
  nm -D "$SO" | grep g_log_request_debug || true
else
  echo "[smoke] no readelf/nm found to inspect symbols"
fi

if [[ $DO_INSTALL -eq 1 ]]; then
  echo "[smoke] installing $SO -> $INSTALL_DEST"
  if [[ $(id -u) -ne 0 ]]; then
    echo "[smoke] using sudo to install (you may be prompted for password)"
    sudo install -m 0755 "$SO" "$INSTALL_DEST"
  else
    install -m 0755 "$SO" "$INSTALL_DEST"
  fi
  echo "[smoke] installed to $INSTALL_DEST"
fi

# Try ping endpoint (non-fatal)
PING_URL="http://127.0.0.1:11080/status/ping"
echo "[smoke] trying $PING_URL (may fail if server not running)..."
if command -v curl >/dev/null 2>&1; then
  set +e
  curl -sS --max-time 2 "$PING_URL" || true
  set -e
else
  echo "[smoke] curl not available; skipping HTTP check"
fi

echo "[smoke] done"
