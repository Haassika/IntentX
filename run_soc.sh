#!/usr/bin/env bash
# Local presentation launcher. Configure host telemetry separately, if available.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
PYTHON_BIN="${INTENTX_PYTHON:-python3}"
"$PYTHON_BIN" -c 'import sys; assert sys.version_info >= (3,11), "Python 3.11+ is required"'
if [ ! -d .venv ]; then
  "$PYTHON_BIN" -m venv .venv
  .venv/bin/python -m pip install -e .
fi
exec .venv/bin/python -m uvicorn intentx.api.app:app --host 127.0.0.1 --port "${INTENTX_PORT:-8000}" --workers 1
