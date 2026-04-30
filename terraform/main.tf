terraform {
  required_version = ">= 1.5.0"

  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.7.6"
    }
  }
}

# ─────────────────────────────────────────────────────────────
# Provider — connects to KVM hypervisor on archivirt-lab host
# ─────────────────────────────────────────────────────────────
provider "libvirt" {
  uri = var.libvirt_uri
}

# ─────────────────────────────────────────────────────────────
# Base OS Image — Ubuntu Server 22.04 LTS Cloud Image
# ─────────────────────────────────────────────────────────────
resource "libvirt_volume" "ubuntu_base" {
  name   = "ubuntu-22.04-base.qcow2"
  pool   = var.storage_pool
  source = var.ubuntu_cloud_image_path
  format = "qcow2"
}
