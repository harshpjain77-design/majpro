#!/bin/bash
# ====================================================
# Trigger Live Attack Telemetry from Kali
# ====================================================

echo "[*] Ensuring SSH service is running..."
sudo systemctl start ssh

echo "[*] Generating 5 failed SSH logins (triggers RULE-001 Brute Force)..."
for i in {1..5}; do
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 fakeuser@127.0.0.1 2>/dev/null
done

echo "[*] Generating privileged shadow file read (triggers RULE-004 Privileged Indicator)..."
sudo cat /etc/shadow >/dev/null 2>&1

echo "[+] Done! Check http://localhost:3000 to see real-time updates."
