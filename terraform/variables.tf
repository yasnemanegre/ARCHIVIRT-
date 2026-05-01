# ============================================================
# ARCHIVIRT - Terraform Variables
# Author: Yasnemanegre SAWADOGO (PhD Student, SPbGUPTD)
# ============================================================

# --- Network CIDRs ---
variable "net_targets_cidr"  { default = "10.0.2.0/24" }
variable "net_monitor_cidr"  { default = "10.0.3.0/24" }
variable "net_attack_cidr"   { default = "10.0.4.0/24" }
variable "net_manager_cidr"  { default = "10.0.5.0/24" }

# --- VM IP Addresses ---
variable "ip_manager"   { default = "10.0.5.10" }
variable "ip_attacker"  { default = "10.0.4.10" }
variable "ip_monitor"   { default = "10.0.3.10" }
variable "ip_target_01" { default = "10.0.2.11" }
variable "ip_target_02" { default = "10.0.2.12" }
variable "ip_target_03" { default = "10.0.2.13" }

# --- VM Resources (per role) ---
variable "vm_vcpu"          { default = 2    }
variable "vm_disk_gb"       { default = 20   }
variable "vm_ram_monitor"   { default = 1536 }
variable "vm_ram_manager"   { default = 1536 }
variable "vm_ram_attacker"  { default = 1024 }
variable "vm_ram_target"    { default = 1024 }
variable "vm_ram_target02"  { default = 768  }
variable "vm_memory_mb"     { default = 1024 }
variable "vm_ram"           { default = 1024 }

# --- Storage ---
variable "storage_pool" { default = "default" }

# --- IDS Engine ---
variable "ids_engine" { default = "suricata" }

# --- SSH ---
variable "ssh_public_key_path" { default = "~/.ssh/archivirt_key.pub" }

# --- Lab ---
variable "lab_name"    { default = "archivirt-lab" }
variable "host_bridge" { default = "enp0s3" }
variable "ubuntu_image_path" {
  default = "/var/lib/libvirt/images/ubuntu-22.04-server-cloudimg-amd64.img"
}
