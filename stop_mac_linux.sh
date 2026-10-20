#!/usr/bin/env bash
# Stop Keystone. Run it with:  bash stop_mac_linux.sh
set -euo pipefail
PORT="${NES_PORT:-8002}"
if ! command -v lsof >/dev/null 2>&1; then
  echo "The lsof command is not installed. Stop Keystone with Ctrl+C in the window where it runs."
  exit 1
fi
PIDS=$(lsof -ti tcp:"$PORT" -sTCP:LISTEN 2>/dev/null || true)
if [ -z "$PIDS" ]; then
  echo "Keystone is not running on port $PORT."
  exit 0
fi
kill $PIDS
echo "Keystone stopped (port $PORT)."
