#!/usr/bin/env python3
"""
ARCHIVIRT — HTML Report Generator
Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)

Generates a full HTML report from aggregated metrics JSON,
with tables, charts (matplotlib), and summary statistics.
"""

import json
import argparse
import os
import sys
import base64
from pathlib import Path
from datetime import datetime

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not installed. Charts will be skipped.")

# Article reference data (for comparison)
REFERENCE_DATA = {
    "snort": {
        "SCN-001": {"detection_rate": 100.0, "fp_rate": 0.5, "latency": 12.3},
        "SCN-002": {"detection_rate": 98.5,  "fp_rate": 1.1, "latency": 45.6},
        "SCN-003": {"detection_rate": 85.2,  "fp_rate": 0.3, "latency": 102.4},
        "SCN-004": {"detection_rate": 65.3,  "fp_rate": 0.0, "latency": 210.5},
        "SCN-005": {"detection_rate": None,  "fp_rate": 0.8, "latency": None},
        "cpu_avg": 68.2, "ram_mb": 512, "throughput_mbps": 945,
    },
    "suricata": {
        "SCN-001": {"detection_rate": 100.0, "fp_rate": 0.2, "latency": 8.7},
        "SCN-002": {"detection_rate": 99.8,  "fp_rate": 0.8, "latency": 32.1},
        "SCN-003": {"detection_rate": 92.7,  "fp_rate": 0.4, "latency": 87.9},
        "SCN-004": {"detection_rate": 78.9,  "fp_rate": 0.0, "latency": 185.2},
        "SCN-005": {"detection_rate": None,  "fp_rate": 0.3, "latency": None},
        "cpu_avg": 75.4, "ram_mb": 610, "throughput_mbps": 1120,
    },
}

SCENARIO_NAMES = {
    "SCN-001": "Port Scan",
    "SCN-002": "SSH Brute-force",
    "SCN-003": "SQLi Exploit",
    "SCN-004": "Slowloris DDoS",
    "SCN-005": "Normal Traffic",
}


def generate_detection_chart(results: dict, ids_engine: str) -> str:
    """Generate base64-encoded detection rate bar chart."""
    if not HAS_MATPLOTLIB:
        return ""

    scenarios = ["SCN-001", "SCN-002", "SCN-003", "SCN-004"]
    names = [SCENARIO_NAMES[s] for s in scenarios]

    measured = []
    reference = []
    ref_data = REFERENCE_DATA.get(ids_engine, {})

    for s in scenarios:
        m = results.get(s, {}).get("detection_rate_pct", 0) or 0
        r = ref_data.get(s, {}).get("detection_rate", 0) or 0
        measured.append(m)
        reference.append(r)

    x = np.arange(len(names))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 5))
    bars1 = ax.bar(x - width/2, measured,  width, label="ARCHIVIRT Measured", color="#2563EB", alpha=0.9)
    bars2 = ax.bar(x + width/2, reference, width, label="Article Reference",   color="#16A34A", alpha=0.7)

    ax.set_xlabel("Test Scenario", fontsize=12)
    ax.set_ylabel("Detection Rate (%)", fontsize=12)
    ax.set_title(f"ARCHIVIRT — Detection Rate: {ids_engine.upper()} IDS", fontsize=14, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=15, ha="right")
    ax.set_ylim(0, 110)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    for bar in bars1:
        ax.annotate(f"{bar.get_height():.1f}%",
                    xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=9)

    plt.tight_layout()

    import io
    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=120, bbox_inches="tight")
    buf.seek(0)
    img_b64 = base64.b64encode(buf.read()).decode("utf-8")
    plt.close()
    return img_b64


def generate_latency_chart(results: dict, ids_engine: str) -> str:
    """Generate latency comparison chart."""
    if not HAS_MATPLOTLIB:
        return ""

    scenarios = ["SCN-001", "SCN-002", "SCN-003", "SCN-004"]
    names = [SCENARIO_NAMES[s] for s in scenarios]
    ref_data = REFERENCE_DATA.get(ids_engine, {})

    measured = [results.get(s, {}).get("avg_latency_ms", 0) or 0 for s in scenarios]
    reference = [ref_data.get(s, {}).get("latency", 0) or 0 for s in scenarios]

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(names))
    width = 0.35

    ax.bar(x - width/2, measured,  width, label="ARCHIVIRT Measured", color="#DC2626", alpha=0.9)
    ax.bar(x + width/2, reference, width, label="Article Reference",   color="#EA580C", alpha=0.7)

    ax.set_xlabel("Test Scenario", fontsize=12)
    ax.set_ylabel("Average Latency (ms)", fontsize=12)
    ax.set_title(f"ARCHIVIRT — Detection Latency: {ids_engine.upper()} IDS", fontsize=14, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=15, ha="right")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()

    import io
    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=120, bbox_inches="tight")
    buf.seek(0)
    img_b64 = base64.b64encode(buf.read()).decode("utf-8")
    plt.close()
    return img_b64


def render_html(results: dict, ids_engine: str, chart_det: str, chart_lat: str) -> str:
    """Render full HTML report."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    rows = ""
    for sid in ["SCN-001", "SCN-002", "SCN-003", "SCN-004", "SCN-005"]:
        r = results.get(sid, {})
        dr = f"{r.get('detection_rate_pct', 'N/A'):.1f}%" if r.get("detection_rate_pct") is not None else "N/A"
        fp = f"{r.get('false_positive_rate_pct', 0):.1f}%"
        lat = f"{r.get('avg_latency_ms', 0):.1f} ms"
        cpu = f"{r.get('avg_cpu_pct', 0):.1f}%"
        ram = f"{int(r.get('avg_ram_mb', 0))} MB"
        name = r.get("scenario_name", sid)
        rows += f"""
        <tr>
          <td><b>{sid}</b></td>
          <td>{name}</td>
          <td class="metric">{dr}</td>
          <td class="metric">{fp}</td>
          <td class="metric">{lat}</td>
          <td class="metric">{cpu}</td>
          <td class="metric">{ram}</td>
        </tr>"""

    det_img = f'<img src="data:image/png;base64,{chart_det}" style="max-width:100%;"/>' if chart_det else "<p>Chart unavailable</p>"
    lat_img = f'<img src="data:image/png;base64,{chart_lat}" style="max-width:100%;"/>' if chart_lat else "<p>Chart unavailable</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ARCHIVIRT — Test Report</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background:#f8fafc; color:#1e293b; margin:0; padding:20px; }}
  .header {{ background:linear-gradient(135deg,#1e3a5f,#2563eb); color:white; padding:30px; border-radius:12px; margin-bottom:24px; }}
  .header h1 {{ margin:0; font-size:2rem; }}
  .header p {{ margin:6px 0 0; opacity:0.8; }}
  .card {{ background:white; border-radius:10px; padding:24px; margin-bottom:20px; box-shadow:0 2px 8px rgba(0,0,0,.08); }}
  .card h2 {{ margin-top:0; color:#1e3a5f; border-bottom:2px solid #e2e8f0; padding-bottom:10px; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.9rem; }}
  th {{ background:#1e3a5f; color:white; padding:10px 14px; text-align:left; }}
  td {{ padding:9px 14px; border-bottom:1px solid #e2e8f0; }}
  tr:hover {{ background:#f1f5f9; }}
  .metric {{ font-family:monospace; font-weight:bold; color:#2563eb; text-align:right; }}
  .badge {{ display:inline-block; padding:3px 10px; border-radius:20px; font-size:0.8rem; font-weight:bold; }}
  .badge-snort {{ background:#fef3c7; color:#92400e; }}
  .badge-suricata {{ background:#dbeafe; color:#1d4ed8; }}
  .grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
  .footer {{ text-align:center; color:#94a3b8; font-size:0.85rem; margin-top:30px; }}
  @media(max-width:768px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>🔒 ARCHIVIRT — Test Report</h1>
  <p>IDS Engine: <strong>{ids_engine.upper()}</strong> &nbsp;|&nbsp; Generated: {now}</p>
  <p>Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)</p>
</div>

<div class="card">
  <h2>📊 Detection & Performance Metrics</h2>
  <table>
    <thead>
      <tr>
        <th>Scenario ID</th><th>Name</th>
        <th>Det. Rate</th><th>FP Rate</th>
        <th>Avg Latency</th><th>Avg CPU</th><th>Avg RAM</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</div>

<div class="grid2">
  <div class="card">
    <h2>📈 Detection Rate Chart</h2>
    {det_img}
  </div>
  <div class="card">
    <h2>⏱ Latency Chart</h2>
    {lat_img}
  </div>
</div>

<div class="card">
  <h2>📋 Summary</h2>
  <ul>
    <li><b>Framework:</b> ARCHIVIRT (Automated Reproducible Cyber Hybrid Infrastructure)</li>
    <li><b>Setup time reduction:</b> 85% (manual ~4h → automated ~35min)</li>
    <li><b>Reproducibility:</b> &lt;2% std dev across 10 runs</li>
    <li><b>Host:</b> archivirt@archivirt-lab (192.168.4.11)</li>
    <li><b>Target subnet:</b> 10.0.2.0/24 | Monitor: 10.0.3.0/24 | Attack: 10.0.4.0/24</li>
  </ul>
</div>

<div class="footer">
  ARCHIVIRT &copy; 2024 Яснеманегре САВАДОГО | СПБГУПТД |
  <a href="https://github.com/yasnemanegre/ARCHIVIRT">GitHub</a>
</div>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="ARCHIVIRT Report Generator")
    parser.add_argument("--metrics", required=True, help="Aggregated metrics JSON file")
    parser.add_argument("--output", default="reports/report.html", help="Output HTML file")
    parser.add_argument("--ids-engine", default=os.environ.get("IDS_ENGINE", "suricata"))
    args = parser.parse_args()

    if not Path(args.metrics).exists():
        print(f"ERROR: {args.metrics} not found", file=sys.stderr)
        sys.exit(1)

    with open(args.metrics) as f:
        data = json.load(f)

    # Handle both raw and aggregated formats
    if "scenarios" in data:
        results = data["scenarios"]
    else:
        results = data

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    print("Generating charts...")
    chart_det = generate_detection_chart(results, args.ids_engine)
    chart_lat = generate_latency_chart(results, args.ids_engine)

    print("Rendering HTML report...")
    html = render_html(results, args.ids_engine, chart_det, chart_lat)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Report saved → {args.output}")
    print(f"Open with: python3 -m http.server 8080 --directory {Path(args.output).parent}")


if __name__ == "__main__":
    main()
