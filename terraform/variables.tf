# ─────────────────────────────────────────────────────────────
# ARCHIVIRT — Terraform Variables
# Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)
# ─────────────────────────────────────────────────────────────

variable "libvirt_uri" {
  description = "Libvirt connection URI (local KVM host)"
  type        = string
  default     = "qemu:///system"
}

variable "storage_pool" {
  description = "Libvirt storage pool name"
  type        = string
  default     = "default"
}

variable "ubuntu_cloud_image_path" {
  description = "Path to Ubuntu 22.04 cloud image on the host"
  type        = string
  default     = "/var/lib/libvirt/images/ubuntu-22.04-server-cloudimg-amd64.img"
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key injected into VMs"
  type        = string
  default     = "~/.ssh/archivirt_key.pub"
}

variable "vm_vcpu" {
  description = "Number of vCPUs per VM"
  type        = number
  default     = 2
}

variable "vm_memory_mb" {
  description = "RAM in MB per VM"
  type        = number
  default     = 4096
}

variable "vm_disk_gb" {
  description = "Disk size in GB per VM"
  type        = number
  default     = 20

}

# ─── Network Variables ────────────────────────────────────────

variable "net_targets_cidr" {
  description = "CIDR for Target VMs subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "net_monitor_cidr" {
  description = "CIDR for IDS/IPS Monitoring subnet"
  type        = string
  default     = "10.0.3.0/24"
}

variable "net_attack_cidr" {
  description = "CIDR for Attacker subnet"
  type        = string
  default     = "10.0.4.0/24"
}

variable "net_manager_cidr" {
  description = "CIDR for Manager/Orchestration subnet"
  type        = string
  default     = "10.0.5.0/24"
}

# ─── Static IP Assignments ────────────────────────────────────

variable "ip_manager" {
  description = "Static IP for Manager VM"
  type        = string
  default     = "10.0.5.10"
}

variable "ip_attacker" {
  description = "Static IP for Attacker VM"
  type        = string
  default     = "10.0.4.10"
}

variable "ip_monitor" {
  description = "Static IP for Monitor (IDS/IPS) VM"
  type        = string
  default     = "10.0.3.10"
}

variable "ip_target_01" {
  description = "Static IP for Target VM 01 (Web/DVWA)"
  type        = string
  default     = "10.0.2.11"
}

variable "ip_target_02" {
  description = "Static IP for Target VM 02 (SSH/FTP)"
  type        = string
  default     = "10.0.2.12"
}

variable "ip_target_03" {
  description = "Static IP for Target VM 03 (SMB/DB)"
  type        = string
  default     = "10.0.2.13"
}

variable "target_count" {
  description = "Number of Target VMs to deploy"
  type        = number
  default     = 3
}

variable "ids_engine" {
  description = "IDS engine to deploy: 'snort' or 'suricata'"
  type        = string
  default     = "suricata"

  validation {
    condition     = contains(["snort", "suricata"], var.ids_engine)
    error_message = "ids_engine must be 'snort' or 'suricata'."
  }
}
