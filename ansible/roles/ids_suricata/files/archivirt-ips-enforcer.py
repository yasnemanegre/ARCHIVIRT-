#!/usr/bin/env python3
"""
ARCHIVIRT IPS Enforcer — Virtual IPS via mirroring
Reads Suricata eve.json drop alerts → applies iptables on host
Author: Yasnemanegre SAWADOGO (SPbSUITD)
"""
import json, subprocess, time, logging, os

EVE_LOG = "/var/log/suricata/eve.json"
HOST_IP = os.environ.get("ARCHIVIRT_HOST_IP", "10.0.3.1")
SSH_KEY = "/home/ubuntu/.ssh/archivirt_key"
BLOCKED = set()
METRICS = "/var/log/suricata/ips_metrics.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [IPS] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/suricata/ips_enforcer.log"),
        logging.StreamHandler()
    ]
)

def block_ip(src_ip, reason):
    if src_ip in BLOCKED:
        return
    cmd = ["ssh", "-i", SSH_KEY,
           "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=3",
           f"archivirt@{HOST_IP}",
           f"sudo iptables -I FORWARD -s {src_ip} -j DROP 2>/dev/null || true"]
    try:
        subprocess.run(cmd, timeout=5, capture_output=True)
        BLOCKED.add(src_ip)
        logging.info(f"BLOCKED {src_ip} — {reason}")
        save_metrics()
    except Exception as e:
        logging.error(f"Failed to block {src_ip}: {e}")

def save_metrics():
    with open(METRICS, 'w') as f:
        json.dump({"blocked_ips": list(BLOCKED),
                   "total_blocked": len(BLOCKED),
                   "timestamp": time.time()}, f)

def tail_eve():
    with open(EVE_LOG, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    action = event.get("alert", {}).get("action", "")
                    if action == "blocked":
                        src_ip = event.get("src_ip", "")
                        sig = event.get("alert", {}).get("signature", "")
                        if src_ip:
                            block_ip(src_ip, sig)
            except json.JSONDecodeError:
                pass

if __name__ == "__main__":
    logging.info("ARCHIVIRT IPS Enforcer started")
    tail_eve()
