#!/usr/bin/env bash
# Start Keystone on macOS or Linux. Run it with:  bash start_mac_linux.sh
# The first time, it installs Keystone by itself (a few minutes, needs internet).
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  echo
  echo "First start on this computer: Keystone installs itself now."
  echo "This happens once, takes a few minutes and needs internet."
  bash ./setup_mac_linux.sh
fi

exec .venv/bin/python run.py
