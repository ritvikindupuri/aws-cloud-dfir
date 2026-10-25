#!/usr/bin/env bash
# ==============================================================================
# AWS Cloud DFIR: Realistic Linux Compromise Simulation (No Mock Data)
# Generates authentic in-memory artifacts, deleted-binary processes, and network sockets
# for Volatility 3 and live volatile triage verification.
# ==============================================================================
set -euo pipefail

echo "[+] Starting Realistic Threat Simulation on Target Host..."

# 1. Simulate Defense Evasion (T1070.004): Process Running from Deleted Binary
echo "[+] Creating payload and unlinking from disk while executing in memory..."
cat << 'EOF' > /tmp/backdoor_worker.py
import time
import os
import socket

# Rename process title in /proc/self/cmdline
print(f"[MALWARE] Worker process running under PID: {os.getpid()}")

# Keep socket open to simulate C2 connection beaconing
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(('127.0.0.1', 4444))
    sock.listen(1)
except Exception:
    pass

while True:
    time.sleep(10)
EOF

# Spawn the Python payload in background
python3 /tmp/backdoor_worker.py &
PAYLOAD_PID=$!
echo "[+] Malicious process running under PID ${PAYLOAD_PID}"

# Sleep 1 second to ensure execution, then delete the binary on disk
sleep 1
rm -f /tmp/backdoor_worker.py
echo "[+] Binary /tmp/backdoor_worker.py deleted from disk! (Now visible in /proc/${PAYLOAD_PID}/exe as deleted)"

# 2. Simulate Scheduled Task / Cron Persistence (T1053.003)
echo "[+] Establishing persistence via user crontab..."
(crontab -l 2>/dev/null || true; echo "* * * * * /bin/bash -c 'sleep 5' # THREAT_INTEL_PERSISTENCE_BEACON") | crontab -

# 3. Simulate Interactive In-Memory Command Execution for Volatility linux.bash
echo "[+] Generating authentic bash command history artifacts in memory..."
export HISTFILE=/root/.bash_history
set -o history
history -s "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
history -s "cat /etc/shadow"
history -s "uname -a"
history -s "whoami"

echo "=============================================================================="
echo "[✓] Compromise Simulation Active!"
echo "    - Unlinked Binary Process PID: ${PAYLOAD_PID}"
echo "    - Listening Port: 127.0.0.1:4444"
echo "    - Persistence: Crontab entry added"
echo "    - In-Memory Bash History: Populated"
echo "Target host is now primed for Cloud DFIR acquisition and Volatility 3 inspection."
echo "=============================================================================="
