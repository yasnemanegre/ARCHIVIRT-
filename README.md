# ARCHIVIRT

**Automated Reproducible Cyber Hybrid Infrastructure for VIRTual SOAR Testing Labs**

> **Author:** Yasnemanegre SAWADOGO (PhD Candidate, SPbSUT)
> **Institution:** Saint Petersburg State University of Telecommunications named after prof. M.A. Bonch-Bruevich
> **License:** MIT — [LICENSE](LICENSE)
> **Repository:** https://github.com/yasnemanegre/ARCHIVIRT

---

## Overview

ARCHIVIRT is an open-source IaC framework for fully automating the lifecycle of virtual
laboratories designed to evaluate SOAR, SIEM, IDS, and IPS properties.
It leverages **Infrastructure as Code** (Terraform v1.5+ / Ansible v2.16+) to automatically
deploy, configure, execute attack scenarios, and collect reproducible metrics.

### Key Metrics

| Metric | Result |
|--------|--------|
| Setup time reduction | **85%** (from ~4 h to ~35 min) |
| Test reproducibility (σ) | **< 2%** across 10 runs |
| SQLi detection — Suricata vs Snort | **100.0% vs 0.0%** (signature-based); Snort detects via DBSCAN post-hoc |

---

## Architecture

ARCHIVIRT is organized around a **5-layer architecture**:

```
Layer 1 – Physical/Host    : Ubuntu Server (KVM hypervisor)
Layer 2 – Orchestration    : Terraform v1.5+ (IaC) + Ansible v2.16+ (configuration)
Layer 3 – Virtual          : KVM/Libvirt VMs on isolated private networks
Layer 4 – Functional Roles : Targets | Monitor (IDS) | Attacker | Manager
Layer 5 – Data & Metrics   : Logs, PCAP, JSON results, Grafana dashboards
```

### Network Topology

```
Host Server: archivirt@archivirt-lab

  ┌──────────────────────────────────────────────────┐
  │                 KVM Hypervisor                   │
  │                                                  │
  │  10.0.2.0/24  ── Target VMs                     │
  │                   (DVWA, OpenSSH 8.9, Samba 4)  │
  │                                                  │
  │  10.0.3.0/24  ── Monitor VM                     │
  │                   (Snort 3.12.2.0 / Suricata 6.0.4) │
  │                                                  │
  │  10.0.4.0/24  ── Attacker VM                    │
  │                   (Nmap, sqlmap, Slowloris)      │
  │                                                  │
  │  10.0.5.0/24  ── Manager VM                     │
  │                   (Orchestration, Metrics)       │
  │                                                  │
  │  All networks isolated — no external routing     │
  └──────────────────────────────────────────────────┘
```

Network isolation enforced via `nftables` (no forwarding outside libvirt network
`192.168.100.0/24`) and `ebtables` (ARP restricted per subnet).

---

## Repository Structure

```
ARCHIVIRT/
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── architecture.md          # Full architecture documentation
│   ├── installation.md          # Step-by-step installation guide
│   ├── testing-guide.md         # Test scenarios guide
│   └── figures/                 # Architecture and result figures (7)
├── terraform/
│   ├── main.tf                  # Provider and core config
│   ├── variables.tf             # All configurable variables
│   ├── networks.tf              # Virtual network definitions
│   ├── vms.tf                   # VM definitions
│   └── outputs.tf               # Output values (IPs, etc.)
├── ansible/
│   ├── site.yml                 # Initial configuration playbook
│   ├── inventory/hosts.ini      # VM inventory
│   ├── playbooks/
│   │   ├── run_all_scenarios.yml    # Master campaign playbook
│   │   ├── snort_scenario.yml       # Single Snort scenario
│   │   ├── suricata_scenario.yml    # Single Suricata scenario
│   │   ├── calibrate_performance.yml
│   │   ├── deploy_telegraf.yml
│   │   ├── setup_host.yml
│   │   └── teardown.yml
│   └── roles/
│       ├── common/              # Base configuration (all VMs)
│       ├── target/              # Vulnerable services setup
│       ├── ids_snort/           # Snort 3 deployment
│       ├── ids_suricata/        # Suricata 6 deployment
│       ├── attacker/            # Attack tools installation
│       └── manager/             # Orchestration & analysis
├── scripts/
│   ├── archivirt_mirrors.sh     # Traffic mirroring setup (vnet → monitor)
│   ├── run_snort.sh             # Snort lifecycle (start/stop/PID)
│   ├── run_suricata.sh          # Suricata lifecycle (start/stop/PID)
│   ├── build_final_results.py   # DR, FPR, latency computation from raw alerts
│   ├── dbscan_from_fetched.py   # DBSCAN/UEBA anomaly analysis
│   └── generate_report.py       # Table 2/3/4 report generator
├── scenarios/
│   ├── port_scan.yml
│   ├── ssh_bruteforce.yml
│   ├── sqli_exploit.yml
│   ├── slowloris_ddos.yml
│   └── normal_traffic.yml
├── configs/
│   ├── snort/snort.lua          # Snort 3.12.2.0 config (UTC timestamps)
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
└── results/                     # Generated by campaign (gitignored *.json except dashboard)
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
# Ubuntu 22.04 LTS host with KVM/libvirt
sudo apt update && sudo apt install -y \
    terraform ansible \
    qemu-kvm libvirt-daemon-system \
    python3-pip git

pip3 install pandas scikit-learn numpy python-dateutil
```

### Deploy the Full Laboratory

```bash
git clone https://github.com/yasnemanegre/ARCHIVIRT.git
cd ARCHIVIRT

# 1. Provision infrastructure (VMs + networks)
cd terraform && terraform init && terraform apply -var-file=../configs/lab.tfvars

# 2. Configure all VMs
ansible-playbook ansible/site.yml -i ansible/inventory/hosts.ini

# 3. Run the full evaluation campaign (Snort + Suricata, 5 scenarios each)
ansible-playbook ansible/playbooks/run_all_scenarios.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"
```

The final report is printed to the terminal and written to `results/archivirt_final_comparison.json`.

---

## Test Scenarios

| ID | Scenario | Tool | Target |
|----|----------|------|--------|
| SCN-001 | Port Scan | Nmap -sS, ports 1–1024 | 10.0.2.11–13 |
| SCN-002 | SSH Brute-force | Nmap port 22 | 10.0.2.11–13 |
| SCN-003 | SQL Injection | sqlmap (DVWA v1.10) | 10.0.2.11 |
| SCN-004 | DDoS Slowloris | Python, 150 sockets | 10.0.2.11 |
| SCN-005 | Normal Traffic | curl (HTTP GET) | 10.0.2.11–12 |

Each scenario runs **10 iterations** with `terraform destroy/apply` between full campaigns
to guarantee environment isolation and reproducibility (σ < 2%).

---

## Experimental Results

> Results from automated campaign — 2026-05-11.
> IDS mode: **passive IDS only** (no IPS/inline blocking tested in this version).
> Rules: Snort Community Ruleset (3 847 rules) + Suricata ET Open (6 892 rules).

### Table 2: Detection Efficiency Metrics

> **Latency definition:** interval between attack tool launch (after warmup phase)
> and first IDS alert. Includes tool process startup overhead (~2 s for nmap,
> <50 ms for sqlmap after warmup). Both IDS engines are subject to the same
> systematic offset, so Snort/Suricata comparison remains valid.

| Scenario | IDS | Alerts | DR% | FPR% | Latency (ms) |
|----------|-----|--------|-----|------|--------------|
| Port Scan | Snort 3.12.2.0 | 30 757 | 100.0 | 0.00 | 2414.2 |
| Port Scan | Suricata 6.0.4 | 26 | 100.0 | 0.67 | 2470.5 |
| SSH Brute-force | Snort 3.12.2.0 | 27 | 98.5 | 0.00 | 2277.7 |
| SSH Brute-force | Suricata 6.0.4 | 30 | 100.0 | 0.67 | 3074.9 |
| SQL Injection | Snort 3.12.2.0 | 0 | 0.0 | 0.00 | — |
| SQL Injection | Suricata 6.0.4 | 1 150 | 100.0 | 0.67 | 13.4 |
| DDoS Slowloris | Snort 3.12.2.0 | 2 990 | 100.0 | 0.00 | 13 824.3 |
| DDoS Slowloris | Suricata 6.0.4 | 10 909 | 100.0 | 0.67 | 947.4 |
| Normal Traffic | Snort 3.12.2.0 | 0 | N/A | 0.00 | N/A |
| Normal Traffic | Suricata 6.0.4 | 82 | N/A | 0.67 | N/A |

### Table 3: System Performance Metrics (Peak during tests)

| IDS | Total Alerts | CPU% | RAM MB | Mbps |
|-----|--------------|------|--------|------|
| Snort 3.12.2.0 | 33 774 | 1.6 | 41 | 945 |
| Suricata 6.0.4 | 12 197 | 7.7 | 46 | 1 120 |

### Table 4: DBSCAN/UEBA Analysis Results

DBSCAN analysis is performed on a random sample of **3 000 alerts** per IDS engine
(ε = 0.5, min_samples = 5, execution time < 2 s).

| IDS | Events | Clusters | Anomalies | Anomaly Rate% |
|-----|--------|----------|-----------|---------------|
| Snort 3.12.2.0 | 3 000 | 3 | 9 | 0.30 |
| Suricata 6.0.4 | 3 000 | 0 | 0 | 0.00 |

**Key findings:**
- Snort generates **zero false positives** on normal traffic (SCN-005) with lower resource usage (1.6% CPU / 41 MB RAM).
- Suricata achieves **higher overall detection**, especially for SQL injection (100.0% vs 0.0% via signatures), at the cost of a small FPR (0.67%) and higher CPU (7.7%).
- Snort SQL injection: 0 real-time signature alerts. Detection occurs post-hoc via DBSCAN anomaly correlation — 9 anomalous events (0.30%) across 3 behavioural clusters.
- Suricata alert distribution is fully homogeneous (0 anomalies, 0 clusters), indicating deterministic and rule-consistent detection behaviour.

---

## Citation

```bibtex
@article{sawadogo2026archivirt,
  author    = {Sawadogo, Yasnemanegre},
  title     = {ARCHIVIRT: A Framework for Automated Construction, Deployment
               and Validation of Virtual Laboratories for SOAR Testing},
  institution = {Saint Petersburg State University of Telecommunications},
  year      = {2026},
  url       = {https://github.com/yasnemanegre/ARCHIVIRT},
  license   = {MIT}
}
```1~# ARCHIVIRT

**Automated Reproducible Cyber Hybrid Infrastructure for VIRTual SOAR Testing Labs**

> **Author:** Yasnemanegre SAWADOGO (PhD Candidate, SPbSUT)
> **Institution:** Saint Petersburg State University of Telecommunications named after prof. M.A. Bonch-Bruevich
> **License:** MIT — [LICENSE](LICENSE)
> **Repository:** https://github.com/yasnemanegre/ARCHIVIRT

---

## Overview

ARCHIVIRT is an open-source IaC framework for fully automating the lifecycle of virtual
laboratories designed to evaluate SOAR, SIEM, IDS, and IPS properties.
It leverages **Infrastructure as Code** (Terraform v1.5+ / Ansible v2.16+) to automatically
deploy, configure, execute attack scenarios, and collect reproducible metrics.

### Key Metrics

| Metric | Result |
|--------|--------|
| Setup time reduction | **85%** (from ~4 h to ~35 min) |
| Test reproducibility (σ) | **< 2%** across 10 runs |
| SQLi detection — Suricata vs Snort | **100.0% vs 0.0%** (signature-based); Snort detects via DBSCAN post-hoc |

---

## Architecture

ARCHIVIRT is organized around a **5-layer architecture**:

```
Layer 1 – Physical/Host    : Ubuntu Server (KVM hypervisor)
Layer 2 – Orchestration    : Terraform v1.5+ (IaC) + Ansible v2.16+ (configuration)
Layer 3 – Virtual          : KVM/Libvirt VMs on isolated private networks
Layer 4 – Functional Roles : Targets | Monitor (IDS) | Attacker | Manager
Layer 5 – Data & Metrics   : Logs, PCAP, JSON results, Grafana dashboards
```

### Network Topology

```
Host Server: archivirt@archivirt-lab

  ┌──────────────────────────────────────────────────┐
  │                 KVM Hypervisor                   │
  │                                                  │
  │  10.0.2.0/24  ── Target VMs                     │
  │                   (DVWA, OpenSSH 8.9, Samba 4)  │
  │                                                  │
  │  10.0.3.0/24  ── Monitor VM                     │
  │                   (Snort 3.12.2.0 / Suricata 6.0.4) │
  │                                                  │
  │  10.0.4.0/24  ── Attacker VM                    │
  │                   (Nmap, sqlmap, Slowloris)      │
  │                                                  │
  │  10.0.5.0/24  ── Manager VM                     │
  │                   (Orchestration, Metrics)       │
  │                                                  │
  │  All networks isolated — no external routing     │
  └──────────────────────────────────────────────────┘
```

Network isolation enforced via `nftables` (no forwarding outside libvirt network
`192.168.100.0/24`) and `ebtables` (ARP restricted per subnet).

---

## Repository Structure

```
ARCHIVIRT/
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── architecture.md          # Full architecture documentation
│   ├── installation.md          # Step-by-step installation guide
│   ├── testing-guide.md         # Test scenarios guide
│   └── figures/                 # Architecture and result figures (7)
├── terraform/
│   ├── main.tf                  # Provider and core config
│   ├── variables.tf             # All configurable variables
│   ├── networks.tf              # Virtual network definitions
│   ├── vms.tf                   # VM definitions
│   └── outputs.tf               # Output values (IPs, etc.)
├── ansible/
│   ├── site.yml                 # Initial configuration playbook
│   ├── inventory/hosts.ini      # VM inventory
│   ├── playbooks/
│   │   ├── run_all_scenarios.yml    # Master campaign playbook
│   │   ├── snort_scenario.yml       # Single Snort scenario
│   │   ├── suricata_scenario.yml    # Single Suricata scenario
│   │   ├── calibrate_performance.yml
│   │   ├── deploy_telegraf.yml
│   │   ├── setup_host.yml
│   │   └── teardown.yml
│   └── roles/
│       ├── common/              # Base configuration (all VMs)
│       ├── target/              # Vulnerable services setup
│       ├── ids_snort/           # Snort 3 deployment
│       ├── ids_suricata/        # Suricata 6 deployment
│       ├── attacker/            # Attack tools installation
│       └── manager/             # Orchestration & analysis
├── scripts/
│   ├── archivirt_mirrors.sh     # Traffic mirroring setup (vnet → monitor)
│   ├── run_snort.sh             # Snort lifecycle (start/stop/PID)
│   ├── run_suricata.sh          # Suricata lifecycle (start/stop/PID)
│   ├── build_final_results.py   # DR, FPR, latency computation from raw alerts
│   ├── dbscan_from_fetched.py   # DBSCAN/UEBA anomaly analysis
│   └── generate_report.py       # Table 2/3/4 report generator
├── scenarios/
│   ├── port_scan.yml
│   ├── ssh_bruteforce.yml
│   ├── sqli_exploit.yml
│   ├── slowloris_ddos.yml
│   └── normal_traffic.yml
├── configs/
│   ├── snort/snort.lua          # Snort 3.12.2.0 config (UTC timestamps)
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
└── results/                     # Generated by campaign (gitignored *.json except dashboard)
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
# Ubuntu 22.04 LTS host with KVM/libvirt
sudo apt update && sudo apt install -y \
    terraform ansible \
    qemu-kvm libvirt-daemon-system \
    python3-pip git

pip3 install pandas scikit-learn numpy python-dateutil
```

### Deploy the Full Laboratory

```bash
git clone https://github.com/yasnemanegre/ARCHIVIRT.git
cd ARCHIVIRT

# 1. Provision infrastructure (VMs + networks)
cd terraform && terraform init && terraform apply -var-file=../configs/lab.tfvars

# 2. Configure all VMs
ansible-playbook ansible/site.yml -i ansible/inventory/hosts.ini

# 3. Run the full evaluation campaign (Snort + Suricata, 5 scenarios each)
ansible-playbook ansible/playbooks/run_all_scenarios.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"
```

The final report is printed to the terminal and written to `results/archivirt_final_comparison.json`.

---

## Test Scenarios

| ID | Scenario | Tool | Target |
|----|----------|------|--------|
| SCN-001 | Port Scan | Nmap -sS, ports 1–1024 | 10.0.2.11–13 |
| SCN-002 | SSH Brute-force | Nmap port 22 | 10.0.2.11–13 |
| SCN-003 | SQL Injection | sqlmap (DVWA v1.10) | 10.0.2.11 |
| SCN-004 | DDoS Slowloris | Python, 150 sockets | 10.0.2.11 |
| SCN-005 | Normal Traffic | curl (HTTP GET) | 10.0.2.11–12 |

Each scenario runs **10 iterations** with `terraform destroy/apply` between full campaigns
to guarantee environment isolation and reproducibility (σ < 2%).

---

## Experimental Results

> Results from automated campaign — 2026-05-11.
> IDS mode: **passive IDS only** (no IPS/inline blocking tested in this version).
> Rules: Snort Community Ruleset (3 847 rules) + Suricata ET Open (6 892 rules).

### Table 2: Detection Efficiency Metrics

> **Latency definition:** interval between attack tool launch (after warmup phase)
> and first IDS alert. Includes tool process startup overhead (~2 s for nmap,
> <50 ms for sqlmap after warmup). Both IDS engines are subject to the same
> systematic offset, so Snort/Suricata comparison remains valid.

| Scenario | IDS | Alerts | DR% | FPR% | Latency (ms) |
|----------|-----|--------|-----|------|--------------|
| Port Scan | Snort 3.12.2.0 | 30 757 | 100.0 | 0.00 | 2414.2 |
| Port Scan | Suricata 6.0.4 | 26 | 100.0 | 0.67 | 2470.5 |
| SSH Brute-force | Snort 3.12.2.0 | 27 | 98.5 | 0.00 | 2277.7 |
| SSH Brute-force | Suricata 6.0.4 | 30 | 100.0 | 0.67 | 3074.9 |
| SQL Injection | Snort 3.12.2.0 | 0 | 0.0 | 0.00 | — |
| SQL Injection | Suricata 6.0.4 | 1 150 | 100.0 | 0.67 | 13.4 |
| DDoS Slowloris | Snort 3.12.2.0 | 2 990 | 100.0 | 0.00 | 13 824.3 |
| DDoS Slowloris | Suricata 6.0.4 | 10 909 | 100.0 | 0.67 | 947.4 |
| Normal Traffic | Snort 3.12.2.0 | 0 | N/A | 0.00 | N/A |
| Normal Traffic | Suricata 6.0.4 | 82 | N/A | 0.67 | N/A |

### Table 3: System Performance Metrics (Peak during tests)

| IDS | Total Alerts | CPU% | RAM MB | Mbps |
|-----|--------------|------|--------|------|
| Snort 3.12.2.0 | 33 774 | 1.6 | 41 | 945 |
| Suricata 6.0.4 | 12 197 | 7.7 | 46 | 1 120 |

### Table 4: DBSCAN/UEBA Analysis Results

DBSCAN analysis is performed on a random sample of **3 000 alerts** per IDS engine
(ε = 0.5, min_samples = 5, execution time < 2 s).

| IDS | Events | Clusters | Anomalies | Anomaly Rate% |
|-----|--------|----------|-----------|---------------|
| Snort 3.12.2.0 | 3 000 | 3 | 9 | 0.30 |
| Suricata 6.0.4 | 3 000 | 0 | 0 | 0.00 |

**Key findings:**
- Snort generates **zero false positives** on normal traffic (SCN-005) with lower resource usage (1.6% CPU / 41 MB RAM).
- Suricata achieves **higher overall detection**, especially for SQL injection (100.0% vs 0.0% via signatures), at the cost of a small FPR (0.67%) and higher CPU (7.7%).
- Snort SQL injection: 0 real-time signature alerts. Detection occurs post-hoc via DBSCAN anomaly correlation — 9 anomalous events (0.30%) across 3 behavioural clusters.
- Suricata alert distribution is fully homogeneous (0 anomalies, 0 clusters), indicating deterministic and rule-consistent detection behaviour.

---

## Citation

```bibtex
@article{sawadogo2026archivirt,
  author    = {Sawadogo, Yasnemanegre},
  title     = {ARCHIVIRT: A Framework for Automated Construction, Deployment
               and Validation of Virtual Laboratories for SOAR Testing},
  institution = {Saint Petersburg State University of Telecommunications},
  year      = {2026},
  url       = {https://github.com/yasnemanegre/ARCHIVIRT},
  license   = {MIT}
}
```
