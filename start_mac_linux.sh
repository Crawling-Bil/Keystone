#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  echo "NES virtual environment was not found. Run ./setup_mac_linux.sh first."
  exit 1
fi

exec .venv/bin/python run.py
