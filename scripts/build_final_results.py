#!/usr/bin/env python3
"""
ARCHIVIRT – Build final IDS result files from raw scenario data.
Expects Snort and Suricata alert timestamps in UTC.
Reads all available scenarios in /tmp, ignores missing ones.
"""

import json, os, sys, glob
from datetime import datetime, timezone
import dateutil.parser

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
TMP_DIR = "/tmp"

WINDOWS = {
    "SCN-001": 120,
    "SCN-002": 120,
    "SCN-003": 300,
    "SCN-004": 120,
    "SCN-005": 120
}

def parse_timestamp(ts_str, year_hint=None):
    if not ts_str: return None
    try:
        dt = dateutil.parser.isoparse(ts_str)
        return dt.timestamp()
    except: pass
    try:
        parts = ts_str.split('-')
        if len(parts) == 2:
            month_day, time_part = parts[0], parts[1]
        else:
            month_day, time_part = ts_str.split()
        year = year_hint if year_hint else datetime.now(timezone.utc).year
        dt_str = f"{year}/{month_day} {time_part}"
        dt = datetime.strptime(dt_str, "%Y/%m/%d %H:%M:%S.%f")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except: return None

def load_alert_timestamps(alert_file, year_hint):
    if not os.path.exists(alert_file): return []
    timestamps = []
    # Detect format: fast.log (Snort) vs JSON lines (Suricata)
    is_fastlog = alert_file.endswith('_fast.log')
    with open(alert_file) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                if is_fastlog:
                    # fast.log format: "05/10-09:14:15.163678  [**] ..."
                    ts_str = line.split()[0]
                    epoch = parse_timestamp(ts_str, year_hint)
                else:
                    obj = json.loads(line)
                    ts = obj.get("timestamp") or obj.get("time")
                    epoch = parse_timestamp(ts, year_hint)
                if epoch: timestamps.append(epoch)
            except: pass
    return sorted(timestamps)

def load_start_times(start_file):
    if not os.path.exists(start_file): return []
    with open(start_file) as f:
        return [float(line.strip()) for line in f if line.strip()]

def compute_metrics(timestamps, start_times, window):
    if not start_times: return 0.0, 0.0
    # Clock skew tolerance: inter-VM NTP offset measured at ~700ms.
    # Alerts timestamped by monitor VM may appear slightly before
    # the start-time recorded on the attacker VM.
    CLOCK_SKEW_TOLERANCE = 2.0  # seconds
    detected_iters = 0
    latencies = []
    for start in start_times:
        first_alert = None
        for t in timestamps:
            if start - CLOCK_SKEW_TOLERANCE <= t <= start + window:
                first_alert = t
                break
        if first_alert is not None:
            detected_iters += 1
            # Clamp latency to 0 minimum: negative values indicate clock skew
            # between attacker VM (start_time) and monitor VM (alert_time).
            raw_lat = (first_alert - start) * 1000.0
            latencies.append(max(0.0, raw_lat))
    dr = (detected_iters / len(start_times)) * 100.0 if start_times else 0.0
    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
    return round(dr, 1), round(avg_lat, 1)

def load_perf_baseline():
    perf_path = os.path.join(RESULTS_DIR, "performance_baseline.json")
    if os.path.exists(perf_path):
        with open(perf_path) as f: return json.load(f)
    return {}

def build_final(ids_type, prefix):
    pattern = os.path.join(TMP_DIR, f"{prefix}_SCN-*_result.json")
    files = sorted(glob.glob(pattern))
    if not files:
        print(f"WARNING: No temporary result files for {ids_type}")
        return None
    scenarios = {}
    total_alerts = 0
    id_version = "Unknown"
    with open(files[0]) as f:
        id_version = json.load(f).get("ids", f"{ids_type} unknown")
    for fpath in files:
        with open(fpath) as f:
            data = json.load(f)
        sid = data.get("scenario", os.path.basename(fpath).split("_")[1])
        alerts = data.get("alerts", 0)
        scenarios[sid] = {"alerts": alerts}
        total_alerts += alerts

    current_year = datetime.now(timezone.utc).year
    normal_alerts = scenarios.get("SCN-005", {}).get("alerts", 0)
    for sc in scenarios:
        alert_file = os.path.join(TMP_DIR, f"{prefix}_{sc}_alerts.json" if prefix != "snort3" else f"{prefix}_{sc}_fast.log")
        start_file = os.path.join(TMP_DIR, f"{prefix}_attack_start_times_{sc}.txt")
        if sc == "SCN-005":
            scenarios[sc]["detection_rate"] = "N/A"
            scenarios[sc]["latency_ms"] = "N/A"
            scenarios[sc]["false_positive"] = 0.0
            continue
        ts_alert = load_alert_timestamps(alert_file, current_year)
        start_times = load_start_times(start_file)
        print(f"  {prefix} {sc}: {len(ts_alert)} alert timestamps, {len(start_times)} start times")
        window = WINDOWS.get(sc, 120)
        dr, lat = compute_metrics(ts_alert, start_times, window)
        scenarios[sc]["detection_rate"] = dr
        scenarios[sc]["latency_ms"] = lat

    fpr = (normal_alerts / total_alerts * 100.0) if total_alerts else 0.0
    for sc in scenarios:
        scenarios[sc]["false_positive"] = round(fpr, 2)

    final = {
        "ids": id_version,
        "date": str(datetime.now(timezone.utc).date()),
        "scenarios": scenarios,
        "total_alerts": total_alerts,
        "performance": load_perf_baseline()
    }
    return final

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    for prefix, name in [("snort3", "Snort"), ("suricata", "Suricata")]:
        final = build_final(name, prefix)
        if final:
            outpath = os.path.join(RESULTS_DIR, f"{prefix}_final_results.json")
            with open(outpath, "w") as f:
                json.dump(final, f, indent=2)
            print(f"Wrote {outpath}")
        else:
            print(f"SKIPPED {prefix} – no data")

if __name__ == "__main__":
    main()

