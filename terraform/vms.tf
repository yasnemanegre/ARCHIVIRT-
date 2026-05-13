# ─────────────────────────────────────────────────────────────
# ARCHIVIRT — Virtual Machine Definitions
# Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)
# ─────────────────────────────────────────────────────────────

locals {
  ssh_pub_key = file(pathexpand(var.ssh_public_key_path))

  # cloud-init common user-data template
  cloud_init_common = <<-EOF
    #cloud-config
    users:
      - name: ubuntu
        groups: sudo
        shell: /bin/bash
        sudo: ['ALL=(ALL) NOPASSWD:ALL']
        ssh_authorized_keys:
          - ${local.ssh_pub_key}
    chpasswd:
      list: |
        ubuntu:archivirt123
      expire: false
    package_update: false
    runcmd:
      - mkdir -p /opt/archivirt/packages
      - |
        MIRROR="http://10.0.5.1:8080"
        PKGS="openssh-server net-tools tcpdump curl wget vim htop iproute2 nftables ebtables chrony python3-pip python3-numpy python3-pandas python3-sklearn git"
        cd /opt/archivirt/packages
        for pkg in $PKGS; do
          deb=$(curl -s $$MIRROR/ | grep -o "href=\"[^\"]*$${pkg}[^\"]*\.deb\"" | head -1 | tr -d '\"href=')
          [ -n "$$deb" ] && wget -q "$$MIRROR/$$deb" -O $${pkg}.deb && dpkg -i $${pkg}.deb 2>/dev/null || true
        done
        apt-get install -f -y 2>/dev/null || true
  EOF
}

# ─────────────────────────────────────────────────────────────
# MANAGER VM — Orchestration & Metrics (10.0.5.10)
# ─────────────────────────────────────────────────────────────
resource "libvirt_cloudinit_disk" "manager" {
  name = "archivirt-manager-cloudinit.iso"
  pool = var.storage_pool

  user_data = <<-EOF
    #cloud-config
    hostname: archivirt-manager
    ${local.cloud_init_common}
    runcmd:
      - |
        MIRROR="http://10.0.5.1:8080"
        cd /opt/archivirt/packages
        for pkg in influxdb2 grafana telegraf; do
          deb=$(curl -s $$MIRROR/ | grep -o "href=\"[^\"]*$${pkg}[^\"]*\.deb\"" | head -1 | tr -d '\"href=')
          [ -n "$$deb" ] && wget -q "$$MIRROR/$$deb" -O $${pkg}.deb && dpkg -i $${pkg}.deb 2>/dev/null || true
        done
        apt-get install -f -y 2>/dev/null || true
        systemctl enable influxdb grafana-server telegraf 2>/dev/null || true
  EOF

  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${var.ip_manager}/24]
        gateway4: 10.0.5.1
  EOF
}

resource "libvirt_volume" "manager_disk" {
  name           = "archivirt-manager.qcow2"
  pool           = var.storage_pool
  base_volume_id = libvirt_volume.ubuntu_base.id
  size           = var.vm_disk_gb * 1073741824
}

resource "libvirt_domain" "manager" {
  name   = "archivirt-manager"
  vcpu   = var.vm_vcpu
  memory = var.vm_memory_mb

  cloudinit = libvirt_cloudinit_disk.manager.id

  network_interface {
    network_id = libvirt_network.manager.id
    addresses  = [var.ip_manager]
  }

  disk {
    volume_id = libvirt_volume.manager_disk.id
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  graphics {
    type        = "vnc"
    listen_type = "address"
  }

  autostart = true
}

# ─────────────────────────────────────────────────────────────
# ATTACKER VM — Penetration Testing Tools (10.0.4.10)
# ─────────────────────────────────────────────────────────────
resource "libvirt_cloudinit_disk" "attacker" {
  name = "archivirt-attacker-cloudinit.iso"
  pool = var.storage_pool

  user_data = <<-EOF
    #cloud-config
    hostname: archivirt-attacker
    ${local.cloud_init_common}
    runcmd:
      - MIRROR="http://10.0.4.1:8080" && cd /opt/archivirt/packages && for pkg in nmap sqlmap; do deb=$(curl -s $$MIRROR/ | grep -o "href=\"[^\"]*$${pkg}[^\"]*\.deb\"" | head -1 | tr -d '\"href='); [ -n "$$deb" ] && wget -q "$$MIRROR/$$deb" -O $${pkg}.deb && dpkg -i $${pkg}.deb 2>/dev/null || true; done
  EOF

  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${var.ip_attacker}/24]
        gateway4: 10.0.4.1
      eth1:
        addresses: [10.0.2.100/24]
  EOF
}

resource "libvirt_volume" "attacker_disk" {
  name           = "archivirt-attacker.qcow2"
  pool           = var.storage_pool
  base_volume_id = libvirt_volume.ubuntu_base.id
  size           = var.vm_disk_gb * 1073741824
}

resource "libvirt_domain" "attacker" {
  name   = "archivirt-attacker"
  vcpu   = var.vm_vcpu
  memory = var.vm_memory_mb

  cloudinit = libvirt_cloudinit_disk.attacker.id

  network_interface {
    network_id = libvirt_network.attack.id
    addresses  = [var.ip_attacker]
  }

  # Also connected to target network to reach targets directly
  network_interface {
    network_id = libvirt_network.targets.id
  }

  disk {
    volume_id = libvirt_volume.attacker_disk.id
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  autostart = true
}

# ─────────────────────────────────────────────────────────────
# MONITOR VM — IDS/IPS (Snort or Suricata) (10.0.3.10)
# ─────────────────────────────────────────────────────────────
resource "libvirt_cloudinit_disk" "monitor" {
  name = "archivirt-monitor-cloudinit.iso"
  pool = var.storage_pool

  user_data = <<-EOF
    #cloud-config
    hostname: archivirt-monitor-ids
    ${local.cloud_init_common}
    runcmd:
      - MIRROR="http://10.0.3.1:8080" && cd /opt/archivirt/packages && for pkg in snort suricata; do deb=$(curl -s $$MIRROR/ | grep -o "href=\"[^\"]*$${pkg}[^\"]*\.deb\"" | head -1 | tr -d '\"href='); [ -n "$$deb" ] && wget -q "$$MIRROR/$$deb" -O $${pkg}.deb && dpkg -i $${pkg}.deb 2>/dev/null || true; done
  EOF

  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${var.ip_monitor}/24]
        gateway4: 10.0.3.1
      eth1:
        addresses: [10.0.2.200/24]
  EOF
}

resource "libvirt_volume" "monitor_disk" {
  name           = "archivirt-monitor.qcow2"
  pool           = var.storage_pool
  base_volume_id = libvirt_volume.ubuntu_base.id
  size           = var.vm_disk_gb * 1073741824
}

resource "libvirt_domain" "monitor" {
  name   = "archivirt-monitor-ids"
  vcpu   = var.vm_vcpu
  memory = var.vm_memory_mb

  cloudinit = libvirt_cloudinit_disk.monitor.id

  network_interface {
    network_id = libvirt_network.monitor.id
    addresses  = [var.ip_monitor]
  }

  # Tap interface connected to target network for passive monitoring
  network_interface {
    network_id = libvirt_network.targets.id
  }

  disk {
    volume_id = libvirt_volume.monitor_disk.id
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  autostart = true
}

# ─────────────────────────────────────────────────────────────
# TARGET VMs — Vulnerable Services (10.0.2.11 to 10.0.2.13)
# ─────────────────────────────────────────────────────────────
locals {
  targets = {
    "01" = { ip = var.ip_target_01, hostname = "archivirt-target-01", role = "web" }
    "02" = { ip = var.ip_target_02, hostname = "archivirt-target-02", role = "ssh_ftp" }
    "03" = { ip = var.ip_target_03, hostname = "archivirt-target-03", role = "smb_db" }
  }
}

resource "libvirt_cloudinit_disk" "target" {
  for_each = local.targets

  name = "archivirt-target-${each.key}-cloudinit.iso"
  pool = var.storage_pool

  user_data = <<-EOF
    #cloud-config
    hostname: ${each.value.hostname}
    ${local.cloud_init_common}
    runcmd:
      - MIRROR="http://10.0.2.1:8080" && cd /opt/archivirt/packages && for pkg in apache2 php8.1 php8.1-mysql php8.1-gd libapache2-mod-php8.1 mariadb-server-10.6 samba vsftpd git; do deb=$(curl -s $$MIRROR/ | grep -o "href=\"[^\"]*$${pkg}[^\"]*\.deb\"" | head -1 | tr -d '\"href='); [ -n "$$deb" ] && wget -q "$$MIRROR/$$deb" -O $${pkg}.deb && dpkg -i $${pkg}.deb 2>/dev/null || true; done
  EOF

  network_config = <<-EOF
    version: 2
    ethernets:
      ens3:
        addresses: [${each.value.ip}/24]
        gateway4: 10.0.2.1
  EOF
}

resource "libvirt_volume" "target_disk" {
  for_each = local.targets

  name           = "archivirt-target-${each.key}.qcow2"
  pool           = var.storage_pool
  base_volume_id = libvirt_volume.ubuntu_base.id
  size           = var.vm_disk_gb * 1073741824
}

resource "libvirt_domain" "target" {
  for_each = local.targets

  name   = each.value.hostname
  vcpu   = var.vm_vcpu
  memory = var.vm_memory_mb

  cloudinit = libvirt_cloudinit_disk.target[each.key].id

  network_interface {
    network_id = libvirt_network.targets.id
    addresses  = [each.value.ip]
  }

  disk {
    volume_id = libvirt_volume.target_disk[each.key].id
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  autostart = true
}
