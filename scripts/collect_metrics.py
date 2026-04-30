#!/usr/bin/env python3
"""
ARCHIVIRT — Metrics Aggregation Script
Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)

Reads raw JSON metrics from run_tests.sh, aggregates per scenario/IDS,
and outputs structured metrics with detection rates, latencies, and resources.
"""

import json
import argparse
import statistics
import os
import sys
from pathlib import Path
from datetime import datetime

# Expected scenario counts (10 runs each, 5 scenarios)
SCENARIOS = {
    "SCN-001": {"name": "Port Scan (Nmap)",       "expected_detections": 10},
    "SCN-002": {"name": "SSH Brute-force (Hydra)", "expected_detections": 10},
    "SCN-003": {"name": "SQLi Exploit (sqlmap)",   "expected_detections": 10},
    "SCN-004": {"name": "Slowloris DDoS",          "expected_detections": 10},
    "SCN-005": {"name": "Normal Traffic Baseline", "expected_detections": 0},  # FP only
}


def load_metrics(metrics_file: str) -> list[dict]:
    """Load raw metrics JSON file."""
    with open(metrics_file) as f:
        return json.load(f)


def aggregate_by_scenario(metrics: list[dict]) -> dict:
    """Group and aggregate metrics by scenario."""
    grouped: dict[str, list] = {}
    for entry in metrics:
        sid = entry["scenario_id"]
        if sid not in grouped:
            grouped[sid] = []
        grouped[sid].append(entry)

    results = {}
    for sid, entries in grouped.items():
        latencies = [e["latency_ms"] for e in entries]
        alerts = [e["alerts_triggered"] for e in entries]
        cpus = [e["resources"]["cpu"] for e in entries if "resources" in e]
        rams = [e["resources"]["ram"] for e in entries if "resources" in e]

        total_runs = len(entries)
        detected_runs = sum(1 for a in alerts if a > 0)
        total_alerts = sum(alerts)

        detection_rate = (detected_runs / total_runs * 100) if total_runs > 0 else 0

        # For SCN-005 (normal traffic), all alerts are false positives
        if sid == "SCN-005":
            fp_rate = (total_alerts / max(1, total_runs)) * 100
            dr = None
        else:
            fp_rate = 0.0
            dr = detection_rate

        results[sid] = {
            "scenario_id": sid,
            "scenario_name": SCENARIOS.get(sid, {}).get("name", sid),
            "total_runs": total_runs,
            "detected_runs": detected_runs,
            "detection_rate_pct": round(dr, 2) if dr is not None else None,
            "total_alerts": total_alerts,
            "false_positive_rate_pct": round(fp_rate, 2),
            "avg_latency_ms": round(statistics.mean(latencies), 1) if latencies else 0,
            "std_latency_ms": round(statistics.stdev(latencies), 2) if len(latencies) > 1 else 0,
            "avg_cpu_pct": round(statistics.mean(cpus), 1) if cpus else 0,
            "avg_ram_mb": round(statistics.mean(rams), 0) if rams else 0,
        }
    return results


def print_table(results: dict, ids_engine: str):
    """Print formatted results table."""
    print(f"\n{'═'*90}")
    print(f"  ARCHIVIRT — Aggregated Results | IDS Engine: {ids_engine.upper()}")
    print(f"{'═'*90}")
    print(f"{'Scenario':<35} {'Det. Rate':>10} {'FP Rate':>8} {'Avg Lat.':>10} {'Avg CPU':>8} {'Avg RAM':>8}")
    print(f"{'─'*35} {'─'*10} {'─'*8} {'─'*10} {'─'*8} {'─'*8}")

    for sid in ["SCN-001", "SCN-002", "SCN-003", "SCN-004", "SCN-005"]:
        if sid not in results:
            continue
        r = results[sid]
        dr = f"{r['detection_rate_pct']:.1f}%" if r['detection_rate_pct'] is not None else "N/A"
        fp = f"{r['false_positive_rate_pct']:.1f}%"
        lat = f"{r['avg_latency_ms']:.1f} ms"
        cpu = f"{r['avg_cpu_pct']:.1f}%"
        ram = f"{int(r['avg_ram_mb'])} MB"
        name = r['scenario_name'][:34]
        print(f"  {name:<33} {dr:>10} {fp:>8} {lat:>10} {cpu:>8} {ram:>8}")

    print(f"{'═'*90}\n")

    # Reproducibility check
    std_devs = [r['std_latency_ms'] for r in results.values() if r['std_latency_ms'] > 0]
    if std_devs:
        avg_std = statistics.mean(std_devs)
        print(f"  Reproducibility (avg std dev): {avg_std:.2f} ms across all scenarios")
        if avg_std < 20:
            print("  ✓ EXCELLENT — std dev < 20ms (article target: < 2% variation)")
        else:
            print("  ⚠ Review reproducibility — higher variance than expected")
    print()


def save_results(results: dict, output_file: str):
    """Save aggregated results to JSON."""
    output = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "framework": "ARCHIVIRT",
        "author": "Яснеманегре САВАДОГО (Аспирант СПБГУПТД)",
        "scenarios": results,
    }
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"  Results saved → {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="ARCHIVIRT Metrics Aggregator"
    )
    parser.add_argument(
        "--metrics",
        required=True,
        help="Path to raw metrics JSON file (output of run_tests.sh)"
    )
    parser.add_argument(
        "--ids-engine",
        default=os.environ.get("IDS_ENGINE", "suricata"),
        help="IDS engine used in this run (snort or suricata)"
    )
    parser.add_argument(
        "--output",
        help="Output JSON file for aggregated results (default: same dir as metrics)"
    )
    args = parser.parse_args()

    if not Path(args.metrics).exists():
        print(f"ERROR: Metrics file not found: {args.metrics}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading metrics: {args.metrics}")
    raw = load_metrics(args.metrics)
    print(f"  {len(raw)} data points loaded")

    results = aggregate_by_scenario(raw)
    print_table(results, args.ids_engine)

    output_file = args.output or args.metrics.replace(".json", "_aggregated.json")
    save_results(results, output_file)


if __name__ == "__main__":
    main()
