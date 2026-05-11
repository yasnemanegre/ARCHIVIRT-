# ARCHIVIRT — Complete Installation Guide

> **Server:** `archivirt@archivirt-lab` | IP: `192.168.4.11`
> **Author:** Yasnemanegre SAWADOGO (PhD Candidate, SPbSUT)
> **License:** MIT — https://github.com/yasnemanegre/ARCHIVIRT

---

## Table of Contents

1. [Host Prerequisites](#1-host-prerequisites)
2. [KVM/Libvirt Setup](#2-kvmlibvirt-setup)
3. [Terraform Installation](#3-terraform-installation)
4. [Ansible Installation](#4-ansible-installation)
5. [Python Dependencies](#5-python-dependencies)
6. [Clone Repository](#6-clone-repository)
7. [Network Configuration](#7-network-configuration)
8. [Deploy Infrastructure](#8-deploy-infrastructure)
9. [Configure All VMs](#9-configure-all-vms)
10. [Run the Evaluation Campaign](#10-run-the-evaluation-campaign)
11. [View Reports](#11-view-reports)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Host Prerequisites

ARCHIVIRT requires an Ubuntu Server 22.04 LTS host with hardware virtualisation.

```bash
# Verify Ubuntu version
lsb_release -a
# Expected: Ubuntu 22.04.x LTS

# Check hardware virtualisation support (must be > 0)
egrep -c '(vmx|svm)' /proc/cpuinfo

# Check resources
nproc && free -h
# Recommended: 16+ cores, 64 GB RAM, NVMe SSD
# Reference hardware: Dell server, Intel Xeon E5-2690 v4, 16c, 64 GB, NVMe
```

---

## 2. KVM/Libvirt Setup

```bash
sudo apt update && sudo apt install -y \
    qemu-kvm \
    libvirt-daemon-system \
    libvirt-clients \
    bridge-utils \
    virtinst \
    cpu-checker \
    genisoimage \
    cloud-image-utils \
    nftables \
    ebtables

# Verify KVM
sudo kvm-ok
# Expected: INFO: /dev/kvm exists — KVM acceleration can be used

# Add user to groups
sudo usermod -aG libvirt,kvm archivirt

# Enable and start libvirt
sudo systemctl enable --now libvirtd
sudo systemctl status libvirtd

# Verify
virsh list --all
```

---

## 3. Terraform Installation

```bash
# Install Terraform v1.5+
wget -O- https://apt.releases.hashicorp.com/gpg | \
    sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/hashicorp.list

sudo apt update && sudo apt install -y terraform libvirt-dev

# Verify
terraform --version
# Expected: Terraform v1.5.x or higher
```

---

## 4. Ansible Installation

```bash
# Install Ansible v2.16+
sudo apt install -y software-properties-common
sudo add-apt-repository --yes --update ppa:ansible/ansible
sudo apt install -y ansible

# Verify
ansible --version
# Expected: ansible [core 2.16+]

# Required collections
ansible-galaxy collection install community.general
ansible-galaxy collection install ansible.posix
```

---

## 5. Python Dependencies

```bash
sudo apt install -y python3 python3-pip

# Install required libraries
pip3 install \
    numpy \
    scikit-learn \
    python-dateutil \
    pandas \
    PyYAML \
    pytest \
    paramiko

# Verify
python3 -c "import sklearn, dateutil, numpy, pandas; print('All OK')"
```

---

## 6. Clone Repository

```bash
sudo apt install -y git

cd /home/archivirt
git clone https://github.com/yasnemanegre/ARCHIVIRT.git
cd ARCHIVIRT

# Set execute permissions
chmod +x scripts/*.sh scripts/*.py
```

---

## 7. Network Configuration

ARCHIVIRT uses four isolated KVM virtual networks — no external routing.

```bash
# Networks created automatically by Terraform:
#   archivirt-targets  → 10.0.2.0/24  (Target VMs)
#   archivirt-monitor  → 10.0.3.0/24  (IDS Monitor)
#   archivirt-attack   → 10.0.4.0/24  (Attacker)
#   archivirt-manager  → 10.0.5.0/24  (Manager)

# Verify no IP conflicts
ip route show
virsh net-list --all

# Network isolation is enforced automatically by:
#   - nftables: blocks forwarding outside libvirt network (192.168.100.0/24)
#   - ebtables: restricts ARP traffic per subnet
#   - libvirt isolated="yes": no physical interface bridging
```

---

## 8. Deploy Infrastructure

```bash
cd /home/archivirt/ARCHIVIRT/terraform

# Initialise provider
terraform init

# Review plan
terraform plan -var-file=../configs/lab.tfvars

# Deploy all VMs and networks (~10 min)
terraform apply -var-file=../configs/lab.tfvars -auto-approve

# Verify all VMs are running
virsh list --all
# Expected: 6 VMs running
#   archivirt-manager, archivirt-attacker, archivirt-monitor-ids,
#   archivirt-target-01, archivirt-target-02, archivirt-target-03

cd ..
```

---

## 9. Configure All VMs

```bash
# Run the full Ansible configuration (all roles)
ansible-playbook ansible/site.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"

# This installs and configures:
#   - Common base packages on all VMs
#   - DVWA v1.10 + Apache 2.4.52 + PHP 7.4 on target-01
#   - OpenSSH 8.9 (vulnerable config) on all targets
#   - Samba 4.15.9 on target-03
#   - Snort 3.12.2.0 + Suricata 6.0.4 on monitor VM
#   - Attack tools (Nmap, sqlmap, Slowloris) on attacker VM
#   - Telegraf metrics agent on manager VM

# Deploy Telegraf for CPU/RAM monitoring
ansible-playbook ansible/playbooks/deploy_telegraf.yml \
  -i ansible/inventory/hosts.ini
```

---

## 10. Run the Evaluation Campaign

```bash
# Run deployment validation tests
pytest tests/test_deployment.py -v
pytest tests/test_connectivity.py -v

# Execute the full campaign:
# 5 attack scenarios × 10 iterations × 2 IDS engines
ansible-playbook ansible/playbooks/run_all_scenarios.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"

# The pipeline runs automatically:
#   SCN-001  Port Scan (Nmap -sS, ports 1-1024)
#   SCN-002  SSH Brute-force (Nmap port 22)
#   SCN-003  SQL Injection (sqlmap against DVWA v1.10)
#   SCN-004  DDoS Slowloris (150 sockets, 15s)
#   SCN-005  Normal traffic baseline (curl HTTP GET)
#
# Then: build_final_results.py → dbscan_from_fetched.py → generate_report.py
# Results written to: results/archivirt_final_comparison.json

# Run a single scenario manually (optional)
ansible-playbook ansible/playbooks/snort_scenario.yml \
  -i ansible/inventory/hosts.ini \
  -e "scenario=SCN-001 ids_prefix=snort3" \
  --ssh-extra-args="-o StrictHostKeyChecking=no"
```

---

## 11. View Reports

```bash
# Results are printed to terminal at end of campaign.
# Full JSON report:
cat results/archivirt_final_comparison.json | python3 -m json.tool

# Re-generate report from existing results
python3 scripts/generate_report.py

# Calibrate performance metrics (CPU/RAM/Mbps)
ansible-playbook ansible/playbooks/calibrate_performance.yml \
  -i ansible/inventory/hosts.ini

# Grafana dashboard (optional)
sudo systemctl start telegraf grafana-server
# Access: http://192.168.4.11:3000 (admin / archivirt)
# Import: monitoring/grafana/dashboard.json
```

---

## 12. Troubleshooting

### VM won't start

```bash
sudo journalctl -u libvirtd -f
virsh dominfo archivirt-target-01
virsh start archivirt-target-01 --console
```

### Terraform provider error

```bash
terraform init -upgrade
```

### SSH connection refused from Ansible

```bash
# Get VM IP
virsh domifaddr archivirt-target-01

# Test manually
ssh ubuntu@10.0.2.11 -i ~/.ssh/archivirt_key -o StrictHostKeyChecking=no

# Regenerate key if needed
ssh-keygen -t ed25519 -f ~/.ssh/archivirt_key -N ""
```

### Snort/Suricata not detecting attacks

```bash
# Verify traffic mirroring is active
bash scripts/archivirt_mirrors.sh
# Expected: ✅ Mirror: vnetX -> vnet5 (for all vnets)

# Check promiscuous mode on monitor VM
ssh ubuntu@10.0.3.10
sudo ip link show | grep promisc
```

### View IDS alerts in real-time

```bash
# Snort 3 (per scenario)
ssh ubuntu@10.0.3.10
sudo tail -f /var/log/snort3/SCN-001/alert_fast.txt

# Suricata (per scenario)
sudo tail -f /var/log/suricata/SCN-001/eve.json | python3 -m json.tool
```

### DR = 0% after campaign

```bash
# Check that prefixed start-time files were created
ls /tmp/snort3_attack_start_times_*.txt
ls /tmp/suricata_attack_start_times_*.txt

# Run metrics manually
python3 scripts/build_final_results.py
```

---

## Full Teardown

```bash
# Stop and destroy all VMs and networks
ansible-playbook ansible/playbooks/teardown.yml \
  -i ansible/inventory/hosts.ini

cd terraform
terraform destroy -var-file=../configs/lab.tfvars -auto-approve

# Verify cleanup
virsh list --all
virsh net-list --all
```
