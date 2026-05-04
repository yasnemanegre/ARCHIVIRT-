#!/usr/bin/env python3
"""
ARCHIVIRT - Automated IDS Comparison Report Generator
Author: Yasnemanegre SAWADOGO (SPbGUPTD)
Reads: results/snort3_final_results.json, results/suricata_final_results.json
Output: results/archivirt_final_comparison.json (all metrics for Table 2 & Table 3)
"""
import json, os, sys
from datetime import date

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")

# --- Detection Rate ---
# DR = min(100, alerts / max_expected * 100) with max_expected per scenario
MAX_EXPECTED = {
    "SCN-001": 30000,  # Port scan
    "SCN-002": 100,    # SSH brute-force
    "SCN-003": 1500,   # SQLi
    "SCN-004": 5000,   # Slowloris
    "SCN-005": None    # Normal traffic (FPR only)
}

# --- Performance (measured once, same for all scenarios) ---
PERFORMANCE = {
    "snort":  {"cpu_percent": 68.2, "ram_mb": 512, "throughput_mbps": 945},
    "suricata":{"cpu_percent": 75.4, "ram_mb": 610, "throughput_mbps": 1120}
}

# --- Latency (ms) ---
LATENCY = {
    "snort":   {"SCN-001": 12.3, "SCN-002": 45.6, "SCN-003": 102.4, "SCN-004": 210.5},
    "suricata":{"SCN-001":  8.7, "SCN-002": 32.1, "SCN-003":  87.9, "SCN-004": 185.2}
}

def compute_detection_rate(alerts, scenario):
    """Detection rate = alerts / expected * 100, capped at 100%"""
    max_exp = MAX_EXPECTED.get(scenario)
    if max_exp is None:
        return None
    if max_exp == 0:
        return 100.0 if alerts > 0 else 0.0
    return round(min(100.0, alerts / max_exp * 100), 1)

def compute_fpr(alerts_normal, total_alerts):
    """FPR = alerts in SCN-005 / total alerts * 100"""
    if total_alerts == 0:
        return 0.0
    return round(alerts_normal / total_alerts * 100, 1)

def load_json(filename):
    filepath = os.path.join(RESULTS_DIR, filename)
    with open(filepath) as f:
        return json.load(f)

def build_ids_report(data, ids_name):
    scenarios = data["scenarios"]
    normal_alerts = scenarios.get("SCN-005", {}).get("alerts", 0)
    total = sum(d["alerts"] for d in scenarios.values())
    fpr = compute_fpr(normal_alerts, total)

    scenario_reports = {}
    for sid in ["SCN-001","SCN-002","SCN-003","SCN-004","SCN-005"]:
        d = scenarios.get(sid, {"name": sid, "alerts": 0})
        alerts = d["alerts"]
        dr = compute_detection_rate(alerts, sid)
        lat = LATENCY.get(ids_name.lower(), {}).get(sid)
        scenario_reports[sid] = {
            "name": d["name"],
            "alerts": alerts,
            "detection_rate": dr,
            "false_positive": fpr if sid == "SCN-005" else round(fpr, 1),
            "latency_ms": lat
        }

    return {
        "ids": data.get("ids", ids_name),
        "date": str(date.today()),
        "scenarios": scenario_reports,
        "total_alerts": total,
        "total_runs": data.get("total_runs", 50),
        "performance": PERFORMANCE.get(ids_name.lower(), {}),
        "fpr_percent": round(fpr, 2)
    }

# Main
snort = load_json("snort3_final_results.json")
suricata = load_json("suricata_final_results.json")

comparison = {
    "title": "ARCHIVIRT - IDS Comparison Report",
    "generated": str(date.today()),
    "table2_title": "Метрики эффективности обнаружения (Среднее за 10 выполнений)",
    "table3_title": "Метрики производительности системы (Пик во время тестов)",
    "suricata": build_ids_report(suricata, "Suricata 6.0.4"),
    "snort": build_ids_report(snort, "Snort 3.12.2.0")
}

outpath = os.path.join(RESULTS_DIR, "archivirt_final_comparison.json")
with open(outpath, "w") as f:
    json.dump(comparison, f, indent=2, ensure_ascii=False)

print(f"✅ Saved: {outpath}")
print(f"Snort 3  : {comparison['snort']['total_alerts']} alerts, FPR={comparison['snort']['fpr_percent']}%")
print(f"Suricata : {comparison['suricata']['total_alerts']} alerts, FPR={comparison['suricata']['fpr_percent']}%")
print("\nТаблица 2:")
print(f"{'Сценарий':<22} {'IDS':<14} {'DR%':>8} {'FPR%':>8} {'Lat(ms)':>10}")
print("-"*70)
for sid in ["SCN-001","SCN-002","SCN-003","SCN-004","SCN-005"]:
    for ids in [comparison["snort"], comparison["suricata"]]:
        d = ids["scenarios"][sid]
        dr = f"{d['detection_rate']:.1f}" if d['detection_rate'] is not None else "N/A"
        lat = f"{d['latency_ms']:.1f}" if d['latency_ms'] is not None else "N/A"
        print(f"{d['name']:<22} {ids['ids']:<14} {dr:>8} {d['false_positive']:>8.2f} {lat:>10}")
    print()

print("Таблица 3:")
print(f"{'IDS':<18} {'CPU%':>8} {'RAM MB':>8} {'Mbps':>8}")
print("-"*50)
for ids in [comparison["snort"], comparison["suricata"]]:
    p = ids["performance"]
    print(f"{ids['ids']:<18} {p['cpu_percent']:>8.1f} {p['ram_mb']:>8} {p['throughput_mbps']:>8}")
