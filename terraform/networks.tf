# ─────────────────────────────────────────────────────────────
# ARCHIVIRT — Virtual Network Definitions
# Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)
#
# Networks:
#   archivirt-net-targets  → 10.0.2.0/24  Target VMs
#   archivirt-net-monitor  → 10.0.3.0/24  IDS/IPS Monitor
#   archivirt-net-attack   → 10.0.4.0/24  Attacker VM
#   archivirt-net-manager  → 10.0.5.0/24  Manager VM
# ─────────────────────────────────────────────────────────────

# ─── Target Network (10.0.2.0/24) ────────────────────────────
resource "libvirt_network" "targets" {
  name      = "archivirt-net-targets"
  mode      = "none"   # fully isolated — no NAT to host
  addresses = [var.net_targets_cidr]
  autostart = true

  dhcp {
    enabled = false   # static IPs assigned via cloud-init
  }

  dns {
    enabled = false
  }
}

# ─── Monitor Network (10.0.3.0/24) ───────────────────────────
resource "libvirt_network" "monitor" {
  name      = "archivirt-net-monitor"
  mode      = "none"
  addresses = [var.net_monitor_cidr]
  autostart = true

  dhcp {
    enabled = false
  }

  dns {
    enabled = false
  }
}

# ─── Attack Network (10.0.4.0/24) ────────────────────────────
resource "libvirt_network" "attack" {
  name      = "archivirt-net-attack"
  mode      = "none"
  addresses = [var.net_attack_cidr]
  autostart = true

  dhcp {
    enabled = false
  }

  dns {
    enabled = false
  }
}

# ─── Manager Network (10.0.5.0/24) ───────────────────────────
resource "libvirt_network" "manager" {
  name      = "archivirt-net-manager"
  mode      = "nat"   # manager needs external access for package installs
  addresses = [var.net_manager_cidr]
  autostart = true

  dhcp {
    enabled = false
  }

  dns {
    enabled = true
  }
}
