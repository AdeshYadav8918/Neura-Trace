# ============================================================
# NeuraTrace - Main Application Container
# Services: Streamlit Dashboard (8501) + IPC Capture Daemon (50051)
# ============================================================

FROM python:3.11-slim

# --- System dependencies ---
# tshark: required by pyshark for packet dissection
# libpcap-dev: required by scapy for raw packet capture
# nmap: optional network mapping utility
# procps: ps command for debugging
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tshark \
    libpcap-dev \
    libpcap0.8 \
    nmap \
    procps \
    curl \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Accept tshark dumpcap permissions non-interactively
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    dpkg-reconfigure -f noninteractive wireshark-common || true

WORKDIR /app

# --- Python dependencies ---
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Application source ---

COPY . .

# --- Data directory (override via NEURATRACE_DATA_DIR env var) ---
RUN mkdir -p /app/data/captures /app/data/uploads /app/data/history

# --- Entrypoint script ---
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Expose Streamlit dashboard and IPC daemon ports
EXPOSE 8501 50051

ENTRYPOINT ["/docker-entrypoint.sh"]
