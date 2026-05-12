#!/usr/bin/env python3
"""
ARCHIVIRT - Sigma Analysis across 10 campaigns
Author: Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
"""
import json, sys, os, glob
import statistics

campaigns_dir = sys.argv[1] if len(sys.argv) > 1 else "results/campaigns"
output_file   = sys.argv[2] if len(sys.argv) > 2 else "results/sigma_analysis.json"

# Charger tous les résultats de campagnes
files = sorted(glob.glob(os.path.join(campaigns_dir, "campaign_*_comparison.json")))
print(f"Campagnes trouvées: {len(files)}")

if len(files) < 2:
    print("❌ Pas assez de campagnes pour calculer σ (minimum 2)")
    sys.exit(1)

# Agréger les métriques par scénario/IDS
metrics = {}
for f in files:
    with open(f) as fh:
        data = json.load(fh)
    for row in data.get("results", []):
        key = f"{row['scenario']}_{row['ids']}"
        if key not in metrics:
            metrics[key] = {"dr": [], "fpr": [], "latency": [], "alerts": []}
        metrics[key]["dr"].append(float(row.get("dr_pct", 0)))
        metrics[key]["fpr"].append(float(row.get("fpr_pct", 0)))
        metrics[key]["latency"].append(float(row.get("latency_ms", 0)))
        metrics[key]["alerts"].append(int(row.get("alerts", 0)))

# Calculer σ
sigma_results = {}
max_sigma_dr = 0.0
print(f"\n{'Scénario/IDS':<40} {'DR mean':>8} {'σ DR':>8} {'σ%':>8}")
print("-" * 70)

for key, vals in sorted(metrics.items()):
    if len(vals["dr"]) < 2:
        continue
    mean_dr  = statistics.mean(vals["dr"])
    sigma_dr = statistics.stdev(vals["dr"])
    sigma_pct = (sigma_dr / mean_dr * 100) if mean_dr > 0 else 0
    max_sigma_dr = max(max_sigma_dr, sigma_pct)

    sigma_results[key] = {
        "dr_mean":     round(mean_dr, 2),
        "dr_sigma":    round(sigma_dr, 4),
        "dr_sigma_pct": round(sigma_pct, 2),
        "fpr_mean":    round(statistics.mean(vals["fpr"]), 3),
        "fpr_sigma":   round(statistics.stdev(vals["fpr"]), 4),
        "lat_mean":    round(statistics.mean(vals["latency"]), 1),
        "lat_sigma":   round(statistics.stdev(vals["latency"]), 2),
        "n_campaigns": len(vals["dr"]),
    }
    print(f"{key:<40} {mean_dr:>8.2f} {sigma_dr:>8.4f} {sigma_pct:>7.2f}%")

# Verdict
verdict = "✅ VALIDÉ σ < 2%" if max_sigma_dr < 2.0 else f"❌ σ max = {max_sigma_dr:.2f}% > 2%"
print(f"\nσ maximum DR: {max_sigma_dr:.2f}%  →  {verdict}")

output = {
    "n_campaigns": len(files),
    "max_sigma_dr_pct": round(max_sigma_dr, 2),
    "verdict": verdict,
    "details": sigma_results
}

with open(output_file, "w") as f:
    json.dump(output, f, indent=2)
print(f"\nRésultats sauvegardés: {output_file}")
