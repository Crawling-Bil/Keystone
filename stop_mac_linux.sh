#!/usr/bin/env bash
set -euo pipefail
PORT="${NES_PORT:-8002}"
PIDS=$(lsof -ti tcp:"$PORT" 2>/dev/null || true)
if [ -z "$PIDS" ]; then
  echo "No NES process is listening on port $PORT."
  exit 0
fi
kill $PIDS
echo "Stopped NES process on port $PORT."
