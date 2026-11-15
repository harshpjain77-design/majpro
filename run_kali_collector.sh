#!/bin/bash
# ====================================================
# ThreadGrid Kali Linux Log Collector Launcher
# Usage: ./run_kali_collector.sh [HOST_IP]
# ====================================================

# Default host IP for VMware NAT mode (change if using Bridged)
HOST_IP="${1:-192.168.80.1}"

echo "[*] Connecting to ThreadGrid SIEM at http://${HOST_IP}:8000..."
python3 -m collectors.linux.collector \
  --journal \
  --api-url "http://${HOST_IP}:8000/api/v1/events/batch" \
  --interval 2
