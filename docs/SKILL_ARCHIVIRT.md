# ARCHIVIRT — IaC Knowledge Base
# Author: Yasnеmanеgrе SAWADOGO (PhD Student, SPbGUPTD)
# Updated: 15.05.2026 — v3.0

## Validated Results (Campaign 15.05.2026)

| Scenario | Snort 3.1.74.0 DR% | Snort Lat(ms) | Suricata 6.0.4 DR% | Suricata Lat(ms) |
|---|---|---|---|---|
| Port Scan | 100.0 | 76.5 | 100.0 | 79.3 |
| SSH Brute-force | 100.0 | 73.8 | 100.0 | 73.9 |
| SQL Injection | 100.0 | 211.6 | 100.0 | 239.2 |
| DDoS Slowloris | 100.0 | 0.0* | 100.0 | 0.0* |
| Normal Traffic | N/A | N/A | N/A | N/A |

*Slowloris 0.0ms = real detection_filter behavior (not NTP artifact)

| IDS | FPR% | CPU% | RAM MB | Mbps |
|---|---|---|---|---|
| Snort 3.1.74.0 | 0.02 | 1.6 | 41 | 945 |
| Suricata 6.0.4 | 0.65 | 7.7 | 46 | 1120 |

## Reproducibility (σ)
- **σ = 0.00% < 2%** — VALIDATED on 10 complete campaigns (15.05.2026)

## Network Architecture

| Network | IP | Bridge | Role |
|---|---|---|---|
| archivirt-net-targets | 10.0.2.0/24 | virbr1 | Target VMs |
| archivirt-net-monitor | 10.0.3.0/24 | virbr4 | IDS VM |
| archivirt-net-attack | 10.0.4.0/24 | virbr2 | Attacker VM |
| archivirt-net-manager | 10.0.5.0/24 | virbr1 | Manager VM |

## RAM Configuration (5.8 GB host)

| VM | RAM | Role |
|---|---|---|
| manager | 1024 MB | InfluxDB + Grafana + Telegraf |
| monitor-ids | 768 MB | Snort 3.1.74.0 + Suricata 6.0.4 |
| attacker | 512 MB | nmap + sqlmap + slowloris |
| target-01 | 512 MB | Apache + DVWA + PHP |
| target-02 | 384 MB | SSH + FTP |
| target-03 | 512 MB | Samba + MariaDB |
| **Total** | **3712 MB** | |

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

# Note: 1GB swap required to avoid OOM during linking (768MB VM)
sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile

PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
  cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make -j1 && sudo make install

# Step 3: Package for local mirror
sudo mkdir -p /tmp/snort3-pkg/usr/local/{bin,lib,share}
sudo cp /usr/local/bin/snort /tmp/snort3-pkg/usr/local/bin/
sudo cp -r /usr/local/lib/snort /tmp/snort3-pkg/usr/local/lib/ 2>/dev/null || true
printf 'Package: snort3\nVersion: 3.1.74.0\nArchitecture: amd64\n
Maintainer: ARCHIVIRT SPbGUPTD\nDescription: Snort 3.1.74.0 IDS\n' | \
  sudo tee /tmp/snort3-pkg/DEBIAN/control
sudo dpkg-deb --build /tmp/snort3-pkg /tmp/snort3_3.1.74.0_amd64.deb
sudo cp /tmp/snort3_3.1.74.0_amd64.deb /var/spool/apt-mirror/packages/
```

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

## Critical Bugs Fixed

| Bug | Root Cause | Fix |
|---|---|---|
| Snort bad_tcp4_checksum | NIC hardware offloading after tc mirror | `network = { checksum_eval = 'none' }` in snort.lua |
| SQLi DR=0% | DVWA sends URL-encoded payloads | Rules on %27, %20AND%20 instead of plain text |
| NTP clock skew | VM clocks diverge up to 800ms | chrony offline install, host stratum 8, offset <1ms |
| Suricata rule-files invalid | suricata.rules/local.rules non-existent | default-rule-path + valid rule list |
| tc mirrors reset | Playbook restarts libvirt networks | Re-apply mirrors before each Suricata scenario |
| Attacker ens4 DOWN | cloud-init did not configure second NIC | netplan 99-ens4.yaml + 10.0.2.100/24 static IP |
| Snort 3 OOM during link | 768MB RAM insufficient for linker | 1GB swap on monitor VM during compilation |
| nmap Exit 127 | Missing liblinear.so.4, liblua5.3 | dpkg-repack + scp to attacker VM |

## Key Commands

```bash
# Full campaign (5 scenarios x Snort + Suricata)
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

## IaC Conventions
- Never hardcode virbr names — always use `virsh net-info`
- Never SSH ubuntu@IP in scripts — always use Ansible
- All source configs in `configs/` — never edit directly on VM
- Author: **Yasnеmanеgrе SAWADOGO (PhD Student, SPbGUPTD)**
- University: **СПбГУПТД** (not СПбГУТ)
