#!/usr/bin/env python3
"""
normal_traffic.py — Legitimate traffic simulator for ARCHIVIRT SCN-005 (baseline/FP measurement)
Author: Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
Project: ARCHIVIRT
"""
import subprocess
import time
import json
import argparse
import random
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# ── Action library ────────────────────────────────────────────────────────────
def http_get(target):
    path = random.choice(["/", "/dvwa/", "/index.html", "/about.html"])
    return subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"http://{target}{path}"],
        capture_output=True, text=True, timeout=5
    )

def http_post(target):
    return subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-X", "POST",
         "-d", "username=user&password=pass",
         f"http://{target}/dvwa/login.php"],
        capture_output=True, text=True, timeout=5
    )

def ping_check(target):
    return subprocess.run(
        ["ping", "-c", "3", "-i", "0.5", target],
        capture_output=True, timeout=10
    )

def ssh_banner(target):
    # Just grab SSH banner — not a real login
    return subprocess.run(
        ["nc", "-w", "3", target, "22"],
        input=b"",
        capture_output=True, timeout=5
    )

ACTIONS = [
    ("HTTP GET",  http_get),
    ("HTTP POST", http_post),
    ("PING",      ping_check),
    ("SSH banner",ssh_banner),
]


def run(targets: list, duration: float, output: str):
    start = time.time()
    results = []
    total = 0

    logging.info(f"[*] Normal traffic simulation started | duration={duration}s | targets={targets}")

    while time.time() - start < duration:
        target = random.choice(targets)
        action_name, action_fn = random.choice(ACTIONS)

        try:
            t0 = time.time()
            proc = action_fn(target)
            elapsed_ms = (time.time() - t0) * 1000
            ok = proc.returncode == 0
        except Exception as e:
            ok = False
            elapsed_ms = 0
            logging.warning(f"  [{action_name}] {target} — ERROR: {e}")

        total += 1
        results.append({
            "ts": datetime.utcnow().isoformat(),
            "target": target,
            "action": action_name,
            "ok": ok,
            "latency_ms": round(elapsed_ms, 1),
        })
        logging.info(f"  [{action_name}] {target} — {'OK' if ok else 'FAIL'} ({elapsed_ms:.0f}ms)")

        time.sleep(random.uniform(1.5, 6.0))

    summary = {
        "scenario": "SCN-005_normal_traffic",
        "duration_s": duration,
        "targets": targets,
        "total_actions": total,
        "success_rate": round(sum(1 for r in results if r["ok"]) / max(total, 1) * 100, 1),
        "actions": results,
    }

    with open(output, "w") as f:
        json.dump(summary, f, indent=2)

    logging.info(f"[+] Done. {total} actions executed. Results: {output}")
    print(json.dumps({k: v for k, v in summary.items() if k != "actions"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARCHIVIRT Normal Traffic Simulator (SCN-005)")
    parser.add_argument("--targets", required=True, help="Comma-separated target IPs")
    parser.add_argument("--duration", type=float, default=300.0, help="Duration in seconds")
    parser.add_argument("--output", default="/tmp/normal_traffic_results.json")
    args = parser.parse_args()

    run(args.targets.split(","), args.duration, args.output)
