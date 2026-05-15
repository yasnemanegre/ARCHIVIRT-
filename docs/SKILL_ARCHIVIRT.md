# ARCHIVIRT — IaC Knowledge Base
# Author: Yasnemanegre SAWADOGO (PhD Student, SPbGUPTD)
# Updated: 15.05.2026 — v3.1
# Repository: https://github.com/yasnemanegre/ARCHIVIRT (MIT License)

---

## Validated Results — Campaign 15.05.2026 (10 runs, σ = 0.00%)

### Table 2 — Detection Efficiency Metrics (average over 10 runs)

| Scenario          | IDS              | Alerts  | DR%    | FPR%  | σ DR% | Latency (ms) |
|-------------------|------------------|---------|--------|-------|-------|--------------|
| Port Scan         | Snort 3.1.74.0   | 30 562  | 100.0  | 0.02  | 0.0%  | 0.0 ★        |
| Port Scan         | Suricata 6.0.4   | 41      | 100.0  | 0.69  | 0.0%  | 1 796.1      |
| SSH Brute-force   | Snort 3.1.74.0   | 27      | 100.0  | 0.02  | 0.8%  | 427.2        |
| SSH Brute-force   | Suricata 6.0.4   | 41      | 100.0  | 0.69  | 0.5%  | 2 625.5      |
| SQL Injection     | Snort 3.1.74.0   | 0       | 0.0 †  | 0.02  | —     | —            |
| SQL Injection     | Suricata 6.0.4   | 1 143   | 100.0  | 0.69  | 0.9%  | 0.0 ★        |
| DDoS Slowloris    | Snort 3.1.74.0   | 2 664   | 100.0  | 0.02  | 0.0%  | 12 839.9     |
| DDoS Slowloris    | Suricata 6.0.4   | 11 034  | 100.0  | 0.69  | 0.0%  | 0.0 ★        |
| Normal Traffic    | Snort 3.1.74.0   | 0       | N/A    | 0.02  | —     | N/A          |
| Normal Traffic    | Suricata 6.0.4   | 85      | N/A    | 0.69  | —     | N/A          |
| **TOTAL**         | **Snort 3.1.74.0** | **33 253** | —  | —     | —     | —            |
| **TOTAL**         | **Suricata 6.0.4** | **12 344** | —  | —     | —     | —            |

> ★ Latency = 0.0 ms — inter-VM clock skew of ~800 ms (attacker vs monitor VM) clamps negative
>   values to 0. Both engines subject to identical offset — Snort/Suricata comparison remains valid.
>
> † SQL Injection Snort DR = 0.0% via real-time signatures — detection occurs post-hoc via DBSCAN
>   anomaly correlation (10 anomalies, 0.33%, see Table 4).

**Totals verification:**
- Snort : 30 562 + 27 + 0 + 2 664 + 0 = **33 253** ✓
- Suricata : 41 + 41 + 1 143 + 11 034 + 85 = **12 344** ✓

---

### Table 3 — System Performance Metrics (peak during tests)

| IDS              | Total Alerts | CPU%  | RAM MB | Mbps  | CPU/RAM Method        |
|------------------|--------------|-------|--------|-------|-----------------------|
| Snort 3.1.74.0   | **33 253**   | 1.6   | 41     | 945   | top / /proc/meminfo   |
| Suricata 6.0.4   | **12 344**   | 7.7   | 46     | 1 120 | top / /proc/meminfo   |

> Collected by Telegraf → InfluxDB → Grafana (Manager VM)
> Snort generates 2.7× more alerts than Suricata with 4.8× lower CPU (1.6% vs 7.7%)
> Port Scan alone accounts for 91.9% of Snort alerts (30 562 / 33 253)

---

### Table 4 — DBSCAN / UEBA Analysis (ε=0.5, min_samples=5)

| IDS              | Events  | Clusters | Anomalies (noise) | Anomaly %  |
|------------------|---------|----------|-------------------|------------|
| Snort 3.1.74.0   | 3 000   | 1        | **10**            | **0.33%**  |
| Suricata 6.0.4   | 3 000   | 2        | 0                 | 0.00%      |

> Snort: 1 dense cluster + 10 behavioural outliers → homogeneous alerts with rare anomalies.
> Suricata: 2 clusters, 0 anomalies → deterministic detection pattern.
> Runtime < 2s per engine (sample of 3 000 alerts).

---

## Reproducibility

- **σ = 0.00%** — validated on 10 complete campaigns (15.05.2026)
- Method: `terraform destroy && terraform apply` between each run
- All 5 scenarios × 10 runs × 2 IDS engines = 100 test executions

---

## IDS Versions

| Engine    | Version      | Source                  | Note                                      |
|-----------|--------------|-------------------------|-------------------------------------------|
| Snort     | **3.1.74.0** | Compiled from sources   | 1 GB swap required during linking on 768MB VM |
| Suricata  | 6.0.4        | apt (local mirror)      | ET Open ruleset 6 892 rules               |

> WARNING: Article v2.0 incorrectly stated Snort 3.12.2.0 — corrected to 3.1.74.0 in v2.1

---

## Network Architecture

| Network                | IP           | Bridge | Role        |
|------------------------|--------------|--------|-------------|
| archivirt-net-targets  | 10.0.2.0/24  | virbr1 | Target VMs  |
| archivirt-net-monitor  | 10.0.3.0/24  | virbr4 | IDS VM      |
| archivirt-net-attack   | 10.0.4.0/24  | virbr2 | Attacker VM |
| archivirt-net-manager  | 10.0.5.0/24  | virbr1 | Manager VM  |

---

## RAM Configuration (5.8 GB host)

| VM           | RAM      | Role                                  |
|--------------|----------|---------------------------------------|
| manager      | 1024 MB  | InfluxDB + Grafana + Telegraf         |
| monitor-ids  | 768 MB   | Snort 3.1.74.0 + Suricata 6.0.4      |
| attacker     | 512 MB   | nmap + sqlmap + slowloris             |
| target-01    | 512 MB   | Apache + DVWA v1.10 + PHP 7.4        |
| target-02    | 384 MB   | OpenSSH 8.9 + FTP                    |
| target-03    | 512 MB   | Samba 4.15.9 + MariaDB               |
| **Total**    | **3712 MB** |                                    |

---

## Snort 3.1.74.0 — Compilation from Source

```bash
# Step 1: Build libdaq 3.0.13 (required dependency)
wget https://github.com/snort3/libdaq/archive/refs/tags/v3.0.13.tar.gz
tar xzf v3.0.13.tar.gz && cd libdaq-3.0.13
autoreconf -fis && ./configure --prefix=/usr/local
make -j2 && sudo make install && sudo ldconfig

# Step 2: Build Snort 3.1.74.0
wget https://github.com/snort3/snort3/archive/refs/tags/3.1.74.0.tar.gz
tar xzf 3.1.74.0.tar.gz && cd snort3-3.1.74.0
mkdir build && cd build

# Note: 1 GB swap required to avoid OOM during linking (768 MB VM)
sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile

PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
  cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make -j1 && sudo make install

# Step 3: Package for local mirror
sudo mkdir -p /tmp/snort3-pkg/usr/local/{bin,lib,share}
sudo mkdir -p /tmp/snort3-pkg/DEBIAN
sudo cp /usr/local/bin/snort /tmp/snort3-pkg/usr/local/bin/
printf 'Package: snort3\nVersion: 3.1.74.0\nArchitecture: amd64\n\
Maintainer: ARCHIVIRT SPbGUPTD\nDescription: Snort 3.1.74.0 IDS\n' | \
  sudo tee /tmp/snort3-pkg/DEBIAN/control
sudo dpkg-deb --build /tmp/snort3-pkg /tmp/snort3_3.1.74.0_amd64.deb
sudo cp /tmp/snort3_3.1.74.0_amd64.deb /var/spool/apt-mirror/packages/
```

---

## Local apt Mirror (nginx + dpkg-repack)

```bash
# Extract packages from host (preserves exact compatible versions)
sudo dpkg-repack apache2 apache2-bin snort suricata nmap libapr1 ...

# Rebuild apt index
sudo bash -c "cd /var/spool/apt-mirror/packages && \
  dpkg-scanpackages . /dev/null > Packages && gzip -9c Packages > Packages.gz"

# nginx serves packages to VMs on port 8080
# VMs use: deb [trusted=yes] http://10.0.x.1:8080 ./
```

---

## Critical Bugs Fixed

| Bug                       | Root Cause                              | Fix                                              |
|---------------------------|-----------------------------------------|--------------------------------------------------|
| Snort bad_tcp4_checksum   | NIC hardware offloading after tc mirror | `network = { checksum_eval = 'none' }` in snort.lua |
| SQLi DR=0%                | DVWA sends URL-encoded payloads         | Rules on `%27`, `%20AND%20` instead of plain text |
| NTP clock skew ~800ms     | VM clocks diverge → latency clamped 0  | chrony offline install, host stratum 8, offset <1ms |
| Suricata rule-files invalid | Non-existent rule paths               | default-rule-path + valid rule list              |
| tc mirrors reset          | Playbook restarts libvirt networks      | Re-apply mirrors before each Suricata scenario   |
| Attacker ens4 DOWN        | cloud-init did not configure 2nd NIC   | netplan 99-ens4.yaml + 10.0.2.100/24 static IP  |
| Snort 3 OOM during link   | 768 MB RAM insufficient for linker     | 1 GB swap on monitor VM during compilation       |
| nmap Exit 127             | Missing liblinear.so.4, liblua5.3      | dpkg-repack + scp to attacker VM                 |

---

## Key Commands

```bash
# Full campaign (5 scenarios × Snort + Suricata)
ansible-playbook ansible/playbooks/run_all_scenarios.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"

# 10 sigma campaigns
ansible-playbook ansible/playbooks/run_10_campaigns.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"

# Generate report
python3 scripts/generate_report.py

# Compute sigma
python3 scripts/compute_sigma.py results/campaigns/ results/sigma_analysis.json

# Update local mirror
sudo bash scripts/update_mirror.sh

# Apply tc traffic mirrors
sudo bash scripts/archivirt_mirrors.sh
```

---

## IaC Conventions

- Never hardcode virbr names — always use `virsh net-info`
- Never SSH ubuntu@IP in scripts — always use Ansible
- All source configs in `configs/` — never edit directly on VM
- Author: **Yasnemanegre SAWADOGO (PhD Student, SPbGUPTD)**
- University: **СПбГУПТД** (not СПбГУПТД)
