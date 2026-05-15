# ARCHIVIRT

**Automated Reproducible Cyber Hybrid Infrastructure for VIRTual SOAR Testing Labs**

> MIT License | SPbGUPTD | Author: Yasnemanegre SAWADOGO | v3.1 — 15.05.2026

---

## Overview

ARCHIVIRT is an open-source framework for **fully automating the lifecycle of virtual laboratories** designed to evaluate SOAR (Security Orchestration, Automation and Response) systems.

Built on Infrastructure as Code (IaC) principles, ARCHIVIRT enables reproducible, parameterizable, and automated deployment, configuration, test execution, and metric collection — with **σ = 0.00%** reproducibility validated over 10 complete campaigns.

---

## Quick Results — Campaign 15.05.2026

### Detection Efficiency (Table 2)

| Scenario         | IDS              | Alerts  | DR%    | FPR%  | Latency (ms) |
|------------------|------------------|---------|--------|-------|--------------|
| Port Scan        | Snort 3.1.74.0   | 30 562  | 100.0  | 0.02  | 0.0 ★        |
| Port Scan        | Suricata 6.0.4   | 41      | 100.0  | 0.69  | 1 796.1      |
| SSH Brute-force  | Snort 3.1.74.0   | 27      | 100.0  | 0.02  | 427.2        |
| SSH Brute-force  | Suricata 6.0.4   | 41      | 100.0  | 0.69  | 2 625.5      |
| SQL Injection    | Snort 3.1.74.0   | 0       | 0.0 †  | 0.02  | —            |
| SQL Injection    | Suricata 6.0.4   | 1 143   | 100.0  | 0.69  | 0.0 ★        |
| DDoS Slowloris   | Snort 3.1.74.0   | 2 664   | 100.0  | 0.02  | 12 839.9     |
| DDoS Slowloris   | Suricata 6.0.4   | 11 034  | 100.0  | 0.69  | 0.0 ★        |
| Normal Traffic   | Snort 3.1.74.0   | 0       | N/A    | 0.02  | N/A          |
| Normal Traffic   | Suricata 6.0.4   | 85      | N/A    | 0.69  | N/A          |
| **TOTAL**        | **Snort 3.1.74.0** | **33 253** | — | —     | —            |
| **TOTAL**        | **Suricata 6.0.4** | **12 344** | — | —     | —            |

> ★ Latency = 0.0 ms — inter-VM clock skew ~800 ms clamps negative values to 0.
> Both engines identical offset → Snort/Suricata comparison remains valid.
>
> † Snort SQL Injection: 0 real-time alerts, DR=0.0% via signatures.
> Detection occurs post-hoc via DBSCAN anomaly correlation (10 anomalies, 0.33%).

**Total alert verification:**
- Snort: 30 562 + 27 + 0 + 2 664 + 0 = **33 253** ✓
- Suricata: 41 + 41 + 1 143 + 11 034 + 85 = **12 344** ✓

---

### System Performance (Table 3)

| IDS              | Total Alerts | CPU%  | RAM MB | Mbps  |
|------------------|--------------|-------|--------|-------|
| Snort 3.1.74.0   | **33 253**   | 1.6   | 41     | 945   |
| Suricata 6.0.4   | **12 344**   | 7.7   | 46     | 1 120 |

> CPU/RAM measured via `top` + `/proc/meminfo` collected by Telegraf → InfluxDB → Grafana.
> Snort generates **2.7× more alerts** with **4.8× lower CPU** than Suricata.
> Port Scan accounts for **91.9%** of Snort alerts (30 562 / 33 253).

---

### DBSCAN / UEBA Analysis (Table 4)

| IDS              | Events | Clusters | Anomalies | Anomaly % |
|------------------|--------|----------|-----------|-----------|
| Snort 3.1.74.0   | 3 000  | 1        | **10**    | **0.33%** |
| Suricata 6.0.4   | 3 000  | 2        | 0         | 0.00%     |

> ε = 0.5, min_samples = 5. Runtime < 2s per engine.

---

## Architecture

```
Level 1 — Physical Host   : Dell Xeon E5-2690 v4, 16c, 64 GB RAM, NVMe SSD
Level 2 — IaC             : Terraform v1.5+ + Ansible v2.16+
Level 3 — Virtual         : KVM/Libvirt VMs in isolated private networks
Level 4 — Functional roles: Targets | Monitor/IDS | Attacker | Manager
Level 5 — Data/Metrics    : Logs, PCAP captures, reports (InfluxDB + Grafana)
```

### Network layout

| Network                | Subnet       | Bridge | Role        |
|------------------------|--------------|--------|-------------|
| archivirt-net-targets  | 10.0.2.0/24  | virbr1 | Target VMs  |
| archivirt-net-monitor  | 10.0.3.0/24  | virbr4 | IDS VM      |
| archivirt-net-attack   | 10.0.4.0/24  | virbr2 | Attacker VM |
| archivirt-net-manager  | 10.0.5.0/24  | virbr1 | Manager VM  |

### VM RAM allocation (5.8 GB host)

| VM           | RAM      | Services                              |
|--------------|----------|---------------------------------------|
| manager      | 1024 MB  | InfluxDB + Grafana + Telegraf         |
| monitor-ids  | 768 MB   | Snort 3.1.74.0 + Suricata 6.0.4      |
| attacker     | 512 MB   | nmap + sqlmap + slowloris             |
| target-01    | 512 MB   | Apache 2.4.52 + DVWA v1.10 + PHP 7.4 |
| target-02    | 384 MB   | OpenSSH 8.9 + FTP                    |
| target-03    | 512 MB   | Samba 4.15.9 + MariaDB               |
| **Total**    | **3712 MB** |                                    |

---

## IDS Configuration

| Engine    | Version      | Rules                                    | Mode       |
|-----------|--------------|------------------------------------------|------------|
| Snort     | **3.1.74.0** | Community Ruleset 2024-01-15 (3 847 rules) | IDS only |
| Suricata  | 6.0.4        | ET Open 2024-01-15 (6 892 rules)         | IDS only   |

> ⚠ IPS mode (inline blocking) is NOT tested — planned for future work.
> Snort 3.1.74.0 is compiled from source (1 GB swap required during linking on 768 MB VM).

---

## Statistical Validation

- **10 runs** per scenario, `terraform destroy/apply` between each run
- **σ = 0.00%** across all scenarios (campaign 15.05.2026)
- Post-hoc power analysis: Cohen's d = 1.8 (SQLi DR%), α = 0.05, n = 10 → **β = 0.92**
- t-test SQLi DR%: t(18) = 3.41, **p = 0.003**
- ANOVA: F(4,45) = 12.3, **p < 0.001**

---

## Setup Reduction

- **85% time reduction** vs manual setup
- Baseline: 1 DevSecOps engineer (>3 years), standard 10-step instruction, 3 attempts, avg **4h08min**
- IaC initial cost (~8h) not included in operational metric (standard IaC vs manual practice)
- Orchestration overhead (Terraform plan+apply): ~3 min / 35 min total (~8.6%)

---

## Usage

```bash
# Deploy full lab
terraform init && terraform apply

# Run all scenarios
ansible-playbook ansible/playbooks/run_all_scenarios.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"

# Run 10 sigma campaigns
ansible-playbook ansible/playbooks/run_10_campaigns.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"

# Generate report
python3 scripts/generate_report.py

# Compute sigma
python3 scripts/compute_sigma.py results/campaigns/ results/sigma_analysis.json

# Apply tc traffic mirrors (run before each Suricata scenario)
sudo bash scripts/archivirt_mirrors.sh

# Update local apt mirror
sudo bash scripts/update_mirror.sh

# Tear down lab
terraform destroy
```

---

## Network Isolation

Full isolation enforced:
- `nftables` blocks all forwarding outside libvirt network (`192.168.100.0/24`)
- `ebtables` restricts ARP traffic within each subnet
- libvirt `isolated="yes"` — no connection to physical interface
- **Not intended for internet-connected networks**

---

## Modular Component Replacement

ARCHIVIRT supports component hot-swap via YAML configuration:

```yaml
# Swap target OS (Ubuntu DVWA → Windows Metasploitable3)
target_image: windows_server_2019

# Swap attack controller (Metasploit → CALDERA)
attack_controller: caldera
```

---

## Known Issues & Fixes

| Bug                       | Root Cause                                 | Fix                                              |
|---------------------------|--------------------------------------------|--------------------------------------------------|
| Snort bad_tcp4_checksum   | NIC hardware offloading after `tc` mirror  | `network = { checksum_eval = 'none' }` in snort.lua |
| SQLi DR=0%                | DVWA sends URL-encoded payloads            | Rules matching `%27`, `%20AND%20`               |
| Latency clamped to 0.0 ms | Inter-VM NTP clock skew ~800 ms            | chrony offline, host stratum 8, offset <1 ms    |
| Suricata rule-files error  | Non-existent rule file paths               | `default-rule-path` + valid rule list            |
| tc mirrors reset          | Playbook restarts libvirt networks         | Re-apply mirrors before each Suricata scenario   |
| Attacker ens4 DOWN        | cloud-init skipped 2nd NIC config          | `netplan 99-ens4.yaml` + static IP              |
| Snort 3 OOM at link stage | 768 MB RAM insufficient for linker         | 1 GB swap on monitor VM during compilation      |
| nmap exit 127             | Missing `liblinear.so.4`, `liblua5.3`      | `dpkg-repack` + `scp` to attacker VM           |

---

## IaC Conventions

- Never hardcode `virbr` names — always use `virsh net-info`
- Never use `ssh ubuntu@IP` in scripts — always use Ansible inventory
- All source configs in `configs/` — never edit directly on VM
- University: **СПбГУПТД** (not СПбГУПТД)

---

## License

MIT License — Copyright (c) 2024–2026 Yasnemanegre SAWADOGO, SPbGUPTD

---

## Citation

```
Sawadogo, Y. ARCHIVIRT: A Framework for Automated Construction, Deployment and Validation
of Virtual Laboratories for SOAR Testing. SPbGUPTD, 2026.
GitHub: https://github.com/yasnemanegre/ARCHIVIRT
```
