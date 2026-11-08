#!/usr/bin/env bash
# Quickstart Launcher for IntentX Security Assistant
# Works in standard Linux/macOS terminal without any IDE (VS Code / Antigravity).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================================"
echo " IntentX: AI-Powered Explainable Linux Security Assistant"
echo " Kernel-Level Intrusion & Behavioral Threat Detection"
echo "============================================================================"

# 1. Setup virtual environment if not present
if [ ! -d ".venv" ]; then
    echo "[+] Creating Python 3 virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    echo "[+] Installing project dependencies..."
    pip install --upgrade pip
    pip install -e ".[test]" -r requirements.txt
else
    source .venv/bin/activate
fi

# 2. Check if uvicorn server is already running on port 8000
if curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
    echo "[✓] Web server already running on http://127.0.0.1:8000/"
else
    echo "[+] Starting IntentX Web Server on http://127.0.0.1:8000/ ..."
    INTENTX_LIVE_SCORES=runtime/live-scores.json \
    INTENTX_TELEMETRY_STATUS=runtime/telemetry-status.json \
    INTENTX_BEHAVIOR_REPORT=runtime/behavior-report.json \
    python3 -m uvicorn intentx.api.app:app --host 127.0.0.1 --port 8000 > /dev/null 2>&1 &
    SERVER_PID=$!
    echo "[✓] Server started (PID: $SERVER_PID). Open http://127.0.0.1:8000/ in your browser."
    sleep 2
fi

# 3. Launch the Interactive Demonstration Suite
echo ""
echo "Launching Interactive Threat Detection & XAI Demonstration..."
python3 scripts/demo_intrusion_scenario.py "$@"
