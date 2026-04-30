# ============================================================
# ARCHIVIRT — Lab Configuration Variables
# File: configs/lab.tfvars
# Usage: terraform apply -var-file="../../configs/lab.tfvars"
# Author: Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
# ============================================================

# ── Host server ────────────────────────────────────────────
lab_name    = "archivirt-lab"
host_bridge = "enp0s3"

# ── Ubuntu Cloud Image ─────────────────────────────────────
# Download: https://cloud-images.ubuntu.com/jammy/current/
ubuntu_image_path = "/var/lib/libvirt/images/ubuntu-22.04-server-cloudimg-amd64.img"

# ── Network CIDRs ──────────────────────────────────────────
target_network_cidr  = "10.0.2.0/24"
monitor_network_cidr = "10.0.3.0/24"
attack_network_cidr  = "10.0.4.0/24"
manager_network_cidr = "10.0.5.0/24"

# ── VM IP Assignments ──────────────────────────────────────
manager_ip   = "10.0.5.10"
attacker_ip  = "10.0.4.10"
monitor_ip   = "10.0.3.10"
target_01_ip = "10.0.2.11"
target_02_ip = "10.0.2.12"
target_03_ip = "10.0.2.13"

# ── VM Resource Allocation ─────────────────────────────────
# Match paper config: Dell Xeon 16-core, 64 GB RAM, NVMe SSD
vm_vcpu = 2
vm_ram  = 4096   # MB

# ── IDS Engine Selection ───────────────────────────────────
# Options: "snort" | "suricata"
ids_engine = "suricata"

# ── SSH ────────────────────────────────────────────────────
ssh_public_key_path = "~/.ssh/archivirt_key.pub"
