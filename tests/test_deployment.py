"""
ARCHIVIRT — Deployment Validation Tests
Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)

Tests that all VMs are deployed, services are running, and
the infrastructure is ready for test scenarios.

Usage:
    pytest tests/test_deployment.py -v
"""

import subprocess
import pytest
import time

# ── Test configuration ────────────────────────────────────────
VM_IPS = {
    "manager":    "10.0.5.10",
    "attacker":   "10.0.4.10",
    "monitor":    "10.0.3.10",
    "target-01":  "10.0.2.11",
    "target-02":  "10.0.2.12",
    "target-03":  "10.0.2.13",
}

SSH_KEY = "~/.ssh/archivirt_key"
SSH_OPTS = ["-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-i", SSH_KEY]
SSH_USER = "ubuntu"

EXPECTED_VMS = [
    "archivirt-manager",
    "archivirt-attacker",
    "archivirt-monitor-ids",
    "archivirt-target-01",
    "archivirt-target-02",
    "archivirt-target-03",
]


def ssh_run(host_ip: str, command: str, timeout: int = 15) -> subprocess.CompletedProcess:
    """Run a command on a remote VM via SSH."""
    cmd = ["ssh"] + SSH_OPTS + [f"{SSH_USER}@{host_ip}", command]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def virsh_run(command: str) -> subprocess.CompletedProcess:
    """Run a virsh command on the host."""
    return subprocess.run(["virsh"] + command.split(), capture_output=True, text=True)


# ─────────────────────────────────────────────────────────────
# 1. KVM/Libvirt VM Checks
# ─────────────────────────────────────────────────────────────

class TestVMDeployment:
    """Verify all VMs are created and running via libvirt."""

    def test_libvirt_daemon_running(self):
        """Check libvirtd is active."""
        result = subprocess.run(
            ["systemctl", "is-active", "libvirtd"],
            capture_output=True, text=True
        )
        assert result.stdout.strip() == "active", "libvirtd must be running"

    @pytest.mark.parametrize("vm_name", EXPECTED_VMS)
    def test_vm_exists(self, vm_name: str):
        """Each expected VM must exist in libvirt."""
        result = virsh_run(f"domstate {vm_name}")
        assert result.returncode == 0, f"VM '{vm_name}' does not exist: {result.stderr}"

    @pytest.mark.parametrize("vm_name", EXPECTED_VMS)
    def test_vm_running(self, vm_name: str):
        """Each VM must be in 'running' state."""
        result = virsh_run(f"domstate {vm_name}")
        assert "running" in result.stdout, \
            f"VM '{vm_name}' is not running. State: {result.stdout.strip()}"


# ─────────────────────────────────────────────────────────────
# 2. Network Connectivity Tests
# ─────────────────────────────────────────────────────────────

class TestNetworkConnectivity:
    """Verify virtual networks are created correctly."""

    EXPECTED_NETWORKS = [
        "archivirt-net-targets",
        "archivirt-net-monitor",
        "archivirt-net-attack",
        "archivirt-net-manager",
    ]

    @pytest.mark.parametrize("net_name", EXPECTED_NETWORKS)
    def test_network_exists(self, net_name: str):
        """Each virtual network must exist."""
        result = virsh_run(f"net-info {net_name}")
        assert result.returncode == 0, \
            f"Network '{net_name}' does not exist: {result.stderr}"

    @pytest.mark.parametrize("net_name", EXPECTED_NETWORKS)
    def test_network_active(self, net_name: str):
        """Each virtual network must be active."""
        result = virsh_run(f"net-info {net_name}")
        assert "Active:         yes" in result.stdout, \
            f"Network '{net_name}' is not active"


# ─────────────────────────────────────────────────────────────
# 3. SSH Accessibility Tests
# ─────────────────────────────────────────────────────────────

class TestSSHAccess:
    """Verify all VMs are reachable via SSH."""

    @pytest.mark.parametrize("name,ip", VM_IPS.items())
    def test_ssh_reachable(self, name: str, ip: str):
        """Every VM must accept SSH connections."""
        result = ssh_run(ip, "echo 'archivirt-ok'", timeout=15)
        assert result.returncode == 0, \
            f"Cannot SSH to {name} ({ip}): {result.stderr}"
        assert "archivirt-ok" in result.stdout, \
            f"Unexpected SSH response from {name}"

    @pytest.mark.parametrize("name,ip", VM_IPS.items())
    def test_vm_hostname(self, name: str, ip: str):
        """Each VM must report the correct hostname."""
        result = ssh_run(ip, "hostname")
        assert result.returncode == 0
        # hostname should contain the VM role identifier
        expected_part = name.replace("target-", "target-")
        assert expected_part.split("-")[-1] in result.stdout or \
               "archivirt" in result.stdout, \
               f"Unexpected hostname from {name}: {result.stdout.strip()}"


# ─────────────────────────────────────────────────────────────
# 4. Target Services Tests
# ─────────────────────────────────────────────────────────────

class TestTargetServices:
    """Verify vulnerable services are running on target VMs."""

    def test_apache_running_on_target01(self):
        """Apache2 must be running on target-01 (web role)."""
        result = ssh_run(VM_IPS["target-01"], "systemctl is-active apache2")
        assert result.stdout.strip() == "active", \
            f"Apache2 not running on target-01: {result.stdout}"

    def test_http_response_target01(self):
        """DVWA must return HTTP 200 on target-01."""
        # Run curl from attacker VM (which has network access to targets)
        result = ssh_run(
            VM_IPS["attacker"],
            f'curl -s -o /dev/null -w "%{{http_code}}" http://{VM_IPS["target-01"]}/ --max-time 5'
        )
        assert result.returncode == 0
        assert result.stdout.strip() in ["200", "301", "302"], \
            f"HTTP error from target-01: {result.stdout}"

    def test_ssh_service_target02(self):
        """SSH must be active on target-02."""
        result = ssh_run(VM_IPS["target-02"], "systemctl is-active ssh")
        assert result.stdout.strip() == "active"

    def test_vsftpd_running_target02(self):
        """vsftpd (FTP) must be running on target-02."""
        result = ssh_run(VM_IPS["target-02"], "systemctl is-active vsftpd")
        assert result.stdout.strip() == "active", \
            f"vsftpd not running on target-02"

    def test_samba_running_target03(self):
        """Samba (SMB) must be running on target-03."""
        result = ssh_run(VM_IPS["target-03"], "systemctl is-active smbd")
        assert result.stdout.strip() == "active", \
            f"smbd not running on target-03"

    def test_mariadb_running_target03(self):
        """MariaDB must be running on target-03."""
        result = ssh_run(VM_IPS["target-03"], "systemctl is-active mariadb")
        assert result.stdout.strip() == "active", \
            f"mariadb not running on target-03"


# ─────────────────────────────────────────────────────────────
# 5. IDS/IPS Monitor Tests
# ─────────────────────────────────────────────────────────────

class TestIDSMonitor:
    """Verify IDS service is configured and running."""

    def test_ids_service_running(self):
        """Snort 3 or Suricata 6 must be active on the monitor VM."""
        monitor_ip = VM_IPS["monitor"]

        # Try Suricata first
        result = ssh_run(monitor_ip, "systemctl is-active suricata")
        if result.stdout.strip() == "active":
            return

        # Try Snort
        result = ssh_run(monitor_ip, "systemctl is-active snort3")
        assert result.stdout.strip() == "active", \
            "Neither Suricata nor Snort3 is running on the monitor VM"

    def test_monitor_interface_promiscuous(self):
        """Monitor interface must be in promiscuous mode."""
        result = ssh_run(VM_IPS["monitor"], "ip link show eth1")
        assert "PROMISC" in result.stdout, \
            "eth1 is not in promiscuous mode on monitor VM"

    def test_ids_log_file_exists(self):
        """IDS log file must exist."""
        monitor_ip = VM_IPS["monitor"]

        result = ssh_run(monitor_ip,
            "test -f /var/log/suricata/fast.log || test -f /var/log/snort/alert_fast.txt && echo found")
        assert "found" in result.stdout, "No IDS log file found"


# ─────────────────────────────────────────────────────────────
# 6. Attacker VM Tools Tests
# ─────────────────────────────────────────────────────────────

class TestAttackerTools:
    """Verify all attack tools are installed on the attacker VM."""

    REQUIRED_TOOLS = ["nmap", "hydra", "sqlmap", "python3"]

    @pytest.mark.parametrize("tool", REQUIRED_TOOLS)
    def test_tool_installed(self, tool: str):
        """Each attack tool must be in PATH on the attacker VM."""
        result = ssh_run(VM_IPS["attacker"], f"which {tool}")
        assert result.returncode == 0, \
            f"Tool '{tool}' not found on attacker VM"

    def test_slowloris_script_exists(self):
        """Slowloris script must exist on the attacker VM."""
        result = ssh_run(
            VM_IPS["attacker"],
            "test -f /opt/archivirt/attack-scripts/slowloris.py && echo found"
        )
        assert "found" in result.stdout

    def test_normal_traffic_script_exists(self):
        """Normal traffic script must exist on the attacker VM."""
        result = ssh_run(
            VM_IPS["attacker"],
            "test -f /opt/archivirt/attack-scripts/normal_traffic.py && echo found"
        )
        assert "found" in result.stdout


# ─────────────────────────────────────────────────────────────
# 7. Manager VM Tests
# ─────────────────────────────────────────────────────────────

class TestManagerVM:
    """Verify manager VM services are running."""

    def test_influxdb_running(self):
        """InfluxDB must be active on the manager VM."""
        result = ssh_run(VM_IPS["manager"], "systemctl is-active influxdb")
        assert result.stdout.strip() == "active", "InfluxDB not running on manager"

    def test_grafana_running(self):
        """Grafana must be active on the manager VM."""
        result = ssh_run(VM_IPS["manager"], "systemctl is-active grafana-server")
        assert result.stdout.strip() == "active", "Grafana not running on manager"

    def test_telegraf_running(self):
        """Telegraf must be active on the manager VM."""
        result = ssh_run(VM_IPS["manager"], "systemctl is-active telegraf")
        assert result.stdout.strip() == "active", "Telegraf not running on manager"

    def test_python_pandas_installed(self):
        """Pandas must be importable on the manager VM."""
        result = ssh_run(VM_IPS["manager"], "python3 -c 'import pandas; print(\"ok\")'")
        assert "ok" in result.stdout, "pandas not installed on manager VM"
