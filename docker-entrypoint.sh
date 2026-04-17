#!/bin/bash
# ============================================================
# NeuraTrace Docker Entrypoint
# Launches both the IPC Capture Daemon and the Streamlit Dashboard
# ============================================================
set -e

echo "=============================================="
echo "  NeuraTrace - Starting Services"
echo "=============================================="

# Start IPC Capture Daemon in background (needs NET_ADMIN / NET_RAW caps)
echo "[1/2] Starting IPC Capture Daemon on 127.0.0.1:50051..."
python capture_daemon.py &
DAEMON_PID=$!
echo "      Daemon PID: $DAEMON_PID"

# Brief pause to let daemon bind its socket
sleep 1

# Start Streamlit Dashboard (listen on all interfaces inside container)
echo "[2/2] Starting Streamlit Dashboard on 0.0.0.0:8501..."
exec streamlit run dashboard.py \
    --server.port=8501 \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --browser.gatherUsageStats=false
