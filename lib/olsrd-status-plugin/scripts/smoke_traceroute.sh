#!/usr/bin/env bash
# Smoke test for /status/traceroute endpoint
set -euo pipefail
HOST=${1:-193.238.158.74}
PORT=${2:-80}
URL="http://${HOST}:${PORT}/status/traceroute"

echo "Fetching ${URL} ..."
if command -v jq >/dev/null 2>&1; then
  curl -sS --max-time 5 "$URL" | jq .
else
  curl -sS --max-time 5 "$URL" | python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin), indent=2))'
fi
