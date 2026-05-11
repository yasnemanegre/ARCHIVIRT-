# ARCHIVIRT

**Automated Reproducible Cyber Hybrid Infrastructure for VIRTual SOAR Testing Labs**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.2.0-green.svg)](https://github.com/yasnemanegre/ARCHIVIRT)
[![IaC](https://img.shields.io/badge/IaC-Terraform%20%2B%20Ansible-purple.svg)]()
[![IDS](https://img.shields.io/badge/IDS-Snort%203.12.2.0%20%7C%20Suricata%206.0.4-orange.svg)]()

> **Author:** Yasnemanegre SAWADOGO (PhD Candidate, SPbSUT)
> **Institution:** Saint Petersburg State University of Telecommunications named after prof. M.A. Bonch-Bruevich (СПбГУТ)
> **License:** MIT — [LICENSE](LICENSE)
> **Repository:** https://github.com/yasnemanegre/ARCHIVIRT

---

## Overview

ARCHIVIRT is an open-source **Infrastructure as Code** framework for fully automating the
lifecycle of virtual laboratories designed to evaluate SOAR, SIEM, IDS, and IPS properties.

It uses **Terraform v1.5+** and **Ansible v2.16+** to automatically provision, configure,
execute attack scenarios, collect metrics, and generate reproducible scientific reports —
reducing laboratory setup time by **85%** (from ~4 h to ~35 min) with a standard deviation
of **σ < 2%** across 10 repeated runs.

### Key Results (v2.2.0 — 2026-05-11)

| Metric | Value |
|--------|-------|
| Setup time reduction | **85%** (from ~4 h to ~35 min) |
| Reproducibility (σ) | **< 2%** across 10 runs |
| Snort 3 DR — Port Scan / SSH / DDoS | **100%** |
| Suricata 6 DR — all scenarios | **100%** |
| SQLi detection | Suricata **100%** vs Snort **0%** via signatures (Snort: post-hoc DBSCAN) |
| False positive rate — Snort | **0.00%** (zero on normal traffic) |
| DBSCAN anomalies — Snort / Suricata | **10 (0.33%)** / **18 (0.60%)** |

---

## Architecture

ARCHIVIRT is organised around a **5-layer architecture**:

```
Layer 1 – Physical/Host    : Ubuntu 22.04 LTS (KVM/libvirt hypervisor)
Layer 2 – Orchestration    : Terraform v1.5+ + Ansible v2.16+
Layer 3 – Virtual          : 6 KVM VMs on isolated private networks
Layer 4 – Functional Roles : Targets | Monitor (IDS) | Attacker | Manager
Layer 5 – Data & Metrics   : alert_fast.txt / eve.json → JSON results → Tables 2/3/4
```

### Network Topology

```
Host: archivirt@archivirt-lab (192.168.4.11)
┌──────────────────────────────────────────────────────────────┐
│                      KVM Hypervisor                          │
│                                                              │
│  10.0.2.0/24 ── Targets (×3)                                │
│                  target-01: DVWA v1.10, OpenSSH 8.9         │
│                  target-02: OpenSSH 8.9                      │
│                  target-03: Samba 4.15.9, OpenSSH 8.9       │
│                                                              │
│  10.0.3.0/24 ── Monitor VM                                  │
│                  Snort 3.12.2.0 / Suricata 6.0.4 (passive)  │
│                  ← mirrored traffic from all vnets           │
│                                                              │
│  10.0.4.0/24 ── Attacker VM                                 │
│                  Nmap, sqlmap, Slowloris, tcpreplay          │
│                                                              │
│  10.0.5.0/24 ── Manager VM                                  │
│                  Telegraf, result aggregation                │
│                                                              │
│  All networks: nftables + ebtables isolation                 │
│  No external routing — fully air-gapped lab                  │
└──────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
ARCHIVIRT/
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── architecture.md          # IaC pipeline and layer description
│   ├── installation.md          # Step-by-step installation guide
│   ├── infrastructure.md        # VM layout, network, IDS config reference
│   ├── testing-guide.md         # Scenario descriptions and timing methodology
│   └── figures/                 # Architecture and result figures (7 PNG)
├── terraform/
│   ├── main.tf                  # Provider and core config
│   ├── variables.tf             # VM resources, network parameters
│   ├── networks.tf              # Isolated virtual network definitions
│   ├── vms.tf                   # VM definitions (cloud-init)
│   └── outputs.tf               # IPs and network outputs
├── ansible/
│   ├── site.yml                 # Full initial configuration playbook
│   ├── inventory/hosts.ini      # VM inventory (IPs, groups, SSH key)
│   ├── playbooks/
│   │   ├── run_all_scenarios.yml    # Master campaign playbook
│   │   ├── snort_scenario.yml       # Single Snort 3 scenario
│   │   ├── suricata_scenario.yml    # Single Suricata 6 scenario
│   │   ├── calibrate_performance.yml
│   │   ├── deploy_telegraf.yml
│   │   ├── setup_host.yml
│   │   └── teardown.yml
│   └── roles/
│       ├── common/              # Base packages (all VMs)
│       ├── target/              # Vulnerable services (DVWA, SSH, Samba)
│       ├── ids_snort/           # Snort 3.12.2.0 deployment
│       ├── ids_suricata/        # Suricata 6.0.4 deployment
│       ├── attacker/            # Attack tools (Nmap, sqlmap, Slowloris)
│       └── manager/             # Telegraf, orchestration
├── scripts/
│   ├── archivirt_mirrors.sh     # AF_PACKET traffic mirroring (all vnets → monitor)
│   ├── run_snort.sh             # Snort 3 lifecycle (start/stop, PID-based)
│   ├── run_suricata.sh          # Suricata 6 lifecycle (start/stop, PID-based)
│   ├── build_final_results.py   # DR / FPR / latency from alert_fast.txt / eve.json
│   ├── dbscan_from_fetched.py   # DBSCAN/UEBA behavioural anomaly analysis
│   └── generate_report.py       # Tables 2, 3, 4 → stdout + JSON
├── scenarios/                   # YAML scenario descriptors (MITRE ATT&CK mapped)
├── configs/
│   ├── snort/snort.lua          # Snort 3.12.2.0 config (UTC timestamps enforced)
│   ├── suricata/suricata.yaml   # Suricata 6.0.4 config (workers mode)
│   ├── tools/                   # slowloris.py, normal_traffic.py
│   └── wordlists/               # SSH brute-force wordlists
├── tests/
│   ├── test_deployment.py
│   ├── test_connectivity.py
│   └── test_scenarios.py
├── monitoring/
│   ├── telegraf.conf
│   └── grafana/dashboard.json
└── results/                     # Campaign output (auto-generated)
    ├── snort3_final_results.json
    ├── suricata_final_results.json
    ├── archivirt_final_comparison.json
    ├── dbscan_latest.json
    └── performance_baseline.json
```

---

## Quick Start

### Prerequisites

```bash
# Ubuntu 22.04 LTS with KVM/libvirt
sudo apt update && sudo apt install -y \
    qemu-kvm libvirt-daemon-system libvirt-clients \
    terraform ansible git python3-pip \
    nftables ebtables genisoimage cloud-image-utils

pip3 install numpy scikit-learn python-dateutil pandas PyYAML
```

### Deploy and Run

```bash
# 1. Clone
git clone https://github.com/yasnemanegre/ARCHIVIRT.git
cd ARCHIVIRT

# 2. Provision VMs and networks (~10 min)
cd terraform && terraform init && terraform apply -var-file=../configs/lab.tfvars
cd ..

# 3. Configure all VMs
ansible-playbook ansible/site.yml -i ansible/inventory/hosts.ini

# 4. Run the full evaluation campaign (~35 min)
ansible-playbook ansible/playbooks/run_all_scenarios.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"
```

The pipeline runs automatically:

1. Snort 3.12.2.0 — SCN-001 to SCN-005 (10 iterations each)
2. Suricata 6.0.4 — SCN-001 to SCN-005 (10 iterations each)
3. `build_final_results.py` — DR, FPR, latency computation
4. `dbscan_from_fetched.py` — DBSCAN/UEBA behavioural analysis
5. `generate_report.py` — Tables 2, 3, 4 printed + written to `results/`
6. Automatic cleanup of all `/tmp/` artefacts

### Run a Single Scenario

```bash
ansible-playbook ansible/playbooks/snort_scenario.yml \
  -i ansible/inventory/hosts.ini \
  -e "scenario=SCN-001 ids_prefix=snort3" \
  --ssh-extra-args="-o StrictHostKeyChecking=no"
```

---

## Test Scenarios

| ID | Name | Tool | Target | Iterations |
|----|------|------|--------|------------|
| SCN-001 | Port Scan | Nmap -sS, ports 1–1024, T4 | 10.0.2.11–13 | 10 |
| SCN-002 | SSH Brute-force | Nmap port 22, --min-rate 500 | 10.0.2.11–13 | 10 |
| SCN-003 | SQL Injection | sqlmap against DVWA v1.10 | 10.0.2.11 | 10 |
| SCN-004 | DDoS Slowloris | Python, 150 sockets, 15 s | 10.0.2.11 | 10 |
| SCN-005 | Normal Traffic | curl HTTP GET (FPR baseline) | 10.0.2.11–12 | 10 |

IDS rulesets: **Snort Community** (3 847 rules, 2024-01-15) + **Suricata ET Open** (6 892 rules, 2024-01-15).
Both engines run in **passive IDS mode only** — IPS mode planned for future work.

---

## Experimental Results

> Campaign: 2026-05-11 | Version: v2.2.0 | Hardware: Dell Xeon E5-2690 v4, 16c, 64 GB RAM, NVMe

### Table 2 — Detection Efficiency Metrics (average over 10 runs)

| Scenario | IDS | Alerts | DR% | FPR% | Latency (ms) |
|----------|-----|-------:|----:|-----:|-------------:|
| Port Scan | Snort 3.12.2.0 | 30 562 | **100.0** | 0.00 | 0.0 ★ |
| Port Scan | Suricata 6.0.4 | 41 | **100.0** | 0.69 | 1796.1 |
| SSH Brute-force | Snort 3.12.2.0 | 27 | **100.0** | 0.00 | 427.2 |
| SSH Brute-force | Suricata 6.0.4 | 41 | **100.0** | 0.69 | 2625.5 |
| SQL Injection | Snort 3.12.2.0 | 0 | 0.0 † | 0.00 | — |
| SQL Injection | Suricata 6.0.4 | 1 143 | **100.0** | 0.69 | 0.0 ★ |
| DDoS Slowloris | Snort 3.12.2.0 | 2 664 | **100.0** | 0.00 | 12 839.9 |
| DDoS Slowloris | Suricata 6.0.4 | 11 034 | **100.0** | 0.69 | 0.0 ★ |
| Normal Traffic | Snort 3.12.2.0 | 0 | N/A | 0.00 | N/A |
| Normal Traffic | Suricata 6.0.4 | 85 | N/A | 0.69 | N/A |

> **★ Latency = 0.0 ms** — inter-VM clock skew of ~800 ms (attacker VM vs monitor VM)
> causes alert timestamps to appear before start-time. Raw negative values clamped to 0.
> Both engines subject to identical offset — Snort/Suricata comparison remains valid.
>
> **† SQL Injection Snort DR = 0.0%** via real-time signatures — detection occurs
> post-hoc via DBSCAN anomaly correlation (10 anomalies, 0.33%, see Table 4).

### Table 3 — System Performance Metrics (peak during tests)

| IDS | Total Alerts | CPU% | RAM MB | Mbps |
|-----|-------------:|-----:|-------:|-----:|
| Snort 3.12.2.0 | 33 253 | **1.6** | **41** | 945 |
| Suricata 6.0.4 | 12 344 | 7.7 | 46 | **1 120** |

> CPU and RAM measured via `top` + `/proc/meminfo` collected by Telegraf.

### Table 4 — DBSCAN/UEBA Analysis (sample: 3 000 alerts, ε=0.5, min_samples=5)

| IDS | Events | Clusters | Anomalies | Anomaly Rate% |
|-----|-------:|---------:|----------:|--------------:|
| Snort 3.12.2.0 | 3 000 | 1 | 10 | 0.33 |
| Suricata 6.0.4 | 3 000 | 6 | 18 | 0.60 |

### Key Findings

- **Snort 3.12.2.0** — zero false positives, lowest resource usage (1.6% CPU / 41 MB RAM).
  Single DBSCAN cluster with 10 anomalies (0.33%): homogeneous alert distribution.
  SQL injection not detected via signatures — captured post-hoc by DBSCAN.

- **Suricata 6.0.4** — 100% detection on all attack scenarios. Small FPR (0.69%)
  and higher CPU (7.7%) at the cost of broader coverage. Six DBSCAN clusters
  with 18 anomalies (0.60%): richer alert distribution across the ET Open ruleset.

- **Reproducibility** — σ < 2% across all metrics over 10 runs.
  `terraform destroy/apply` between campaigns guarantees clean-state isolation.

---

## IaC Design Principles

| Principle | Implementation |
|-----------|----------------|
| **Reproducibility** | `terraform destroy/apply` between runs; σ < 2% |
| **Modularity** | Replace any VM role by changing one Ansible variable |
| **Automation** | Zero manual steps: `git clone` → final report |
| **Measurability** | DR, FPR, latency, CPU, RAM, Mbps, DBSCAN — all automated |
| **Isolation** | nftables + ebtables + libvirt `isolated="yes"` |
| **Open science** | MIT License, all config version-controlled |

### Modularity Example

```yaml
# Replace target OS — only one variable change needed:
target_image: "win2019-metasploitable3"   # Ubuntu 22.04 → Windows Server 2019

# Replace attack controller:
attack_controller: "caldera"               # Metasploit → CALDERA
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/installation.md](docs/installation.md) | Step-by-step installation guide |
| [docs/architecture.md](docs/architecture.md) | IaC pipeline and 5-layer architecture |
| [docs/infrastructure.md](docs/infrastructure.md) | VM layout, network, IDS config reference |
| [docs/testing-guide.md](docs/testing-guide.md) | Scenario guide and timing methodology |

---

## Teardown

```bash
ansible-playbook ansible/playbooks/teardown.yml -i ansible/inventory/hosts.ini
cd terraform && terraform destroy -var-file=../configs/lab.tfvars -auto-approve
```

---

## Citation

```bibtex
@article{sawadogo2026archivirt,
  author      = {Sawadogo, Yasnemanegre},
  title       = {ARCHIVIRT: A Framework for Automated Construction, Deployment
                 and Validation of Virtual Laboratories for SOAR Testing},
  institution = {Saint Petersburg State University of Telecommunications
                 named after prof. M.A. Bonch-Bruevich},
  year        = {2026},
  url         = {https://github.com/yasnemanegre/ARCHIVIRT},
  license     = {MIT}
}
```
