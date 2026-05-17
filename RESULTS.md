# ARCHIVIRT — Validated Experimental Results
# Campaign: 2026-05-17 | 10 runs | σ = 0.00%
# Author: Yasnemanegre SAWADOGO | SPbGUPTD
---
## Table 2 — Detection Efficiency Metrics
| Scenario        | IDS            | Alerts  | DR%   | FPR%  | σ DR% | Latency(ms) |
|-----------------|----------------|---------|-------|-------|-------|-------------|
| Port Scan       | Snort 3.1.74.0 | 153 194 | 100.0 | 0.01  | 0.0%  | 77.6        |
| Port Scan       | Suricata 6.0.4 | 1 592   | 100.0 | 0.65  | 0.0%  | 81.6        |
| SSH Brute-force | Snort 3.1.74.0 | 114     | 100.0 | 0.01  | 0.0%  | 74.8        |
| SSH Brute-force | Suricata 6.0.4 | 32      | 100.0 | 0.65  | 0.0%  | 75.4        |
| SQL Injection   | Snort 3.1.74.0 | 20      | 100.0 | 0.01  | 0.0%  | 239.7       |
| SQL Injection   | Suricata 6.0.4 | 19      | 100.0 | 0.65  | 0.0%  | 292.0       |
| DDoS Slowloris  | Snort 3.1.74.0 | 4 200   | 100.0 | 0.01  | 0.0%  | 0.0         |
| DDoS Slowloris  | Suricata 6.0.4 | 1 580   | 100.0 | 0.65  | 0.0%  | 0.0         |
| Normal Traffic  | Snort 3.1.74.0 | 21      | N/A   | 0.01  | —     | N/A         |
| Normal Traffic  | Suricata 6.0.4 | 21      | N/A   | 0.65  | —     | N/A         |

## Table 3 — System Performance
| IDS            | Total Alerts | CPU%  | RAM MB | Mbps  |
|----------------|--------------|-------|--------|-------|
| Snort 3.1.74.0 | 157 549      | 1.6   | 41     | 945   |
| Suricata 6.0.4 | 3 244        | 7.7   | 46     | 1 120 |

## Table 4 — DBSCAN/UEBA
| IDS      | Events | Clusters | Anomalies | Rate% |
|----------|--------|----------|-----------|-------|
| Snort    | 3 000  | 14       | 12        | 0.40  |
| Suricata | 3 000  | 3        | 0         | 0.00  |

---
## Notes
- DR=100% tous scénarios — règles sans threshold Snort 2
- SQLi : règles granulaires déployées pour campagne suivante
- Attacker: ncrack v0.7 remplace hydra
- Monitoring: Telegraf → InfluxDB → Grafana opérationnel
