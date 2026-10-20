#!/usr/bin/env bash
# One-time setup for Keystone on macOS or Linux. Run it with:  bash setup_mac_linux.sh
set -euo pipefail
cd "$(dirname "$0")"

find_python() {
  local candidate
  for candidate in "${PYTHON_BIN:-}" python3.13 python3.12 python3.11 python3 python; do
    [ -n "$candidate" ] || continue
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

echo
echo "Keystone setup - one time only (about 2 to 5 minutes, needs internet)"
echo

if ! PYTHON="$(find_python)"; then
  echo "Python 3.11 or newer was not found."
  echo "  macOS:          brew install python@3.12     (or download from https://www.python.org/downloads/macos/)"
  echo "  Debian/Ubuntu:  sudo apt install python3 python3-venv python3-pip"
  echo "Then run this script again. To use a specific Python: PYTHON_BIN=python3.12 bash setup_mac_linux.sh"
  exit 1
fi
echo "Python found: $("$PYTHON" --version)"

if [ ! -x .venv/bin/python ]; then
  rm -rf .venv
  if ! "$PYTHON" -m venv .venv; then
    rm -rf .venv
    echo "Could not create the private Python folder (.venv)."
    echo "On Debian or Ubuntu install the venv package first: sudo apt install python3-venv python3-pip"
    exit 1
  fi
fi

PY=.venv/bin/python
"$PY" -m pip install --upgrade pip >/dev/null 2>&1 || true
echo "Installing packages ..."
if ! "$PY" -m pip install -r requirements-lock.txt; then
  echo
  echo "The pinned package list did not install. Trying the flexible list instead ..."
  "$PY" -m pip install -r requirements.txt
fi

echo
echo "Checking the installation ..."
"$PY" verify_install.py

echo
echo "Setup finished. Start Keystone with:  bash start_mac_linux.sh"
