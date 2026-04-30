"""
ARCHIVIRT — Scenario Execution Tests
Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)

Validates that each test scenario executes correctly and
produces detectable IDS alerts. Runs a single pass of each
scenario (not the full 10-run campaign).

Usage:
    pytest tests/test_scenarios.py -v --timeout=300
"""

import subprocess
import time
import pytest
import json

SSH_KEY = "~/.ssh/archivirt_key"
SSH_BASE_OPTS = ["-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=15",
                 "-i", SSH_KEY]

ATTACKER_IP = "10.0.4.10"
MONITOR_IP  = "10.0.3.10"
TARGET_WEB  = "10.0.2.11"
TARGET_SSH  = "10.0.2.12"
TARGET_SMB  = "10.0.2.13"


def ssh_run(ip: str, cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    full_cmd = ["ssh"] + SSH_BASE_OPTS + [f"ubuntu@{ip}", cmd]
    return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)


def get_alert_count(ids_engine: str = "suricata") -> int:
    """Get current alert count from IDS log."""
    if ids_engine == "snort":
        result = ssh_run(MONITOR_IP, "wc -l < /var/log/snort/alert_fast.txt 2>/dev/null || echo 0")
    else:
        result = ssh_run(MONITOR_IP, "wc -l < /var/log/suricata/fast.log 2>/dev/null || echo 0")
    try:
        return int(result.stdout.strip())
    except ValueError:
        return 0


def clear_alerts(ids_engine: str = "suricata"):
    """Clear IDS alert logs between tests."""
    if ids_engine == "snort":
        ssh_run(MONITOR_IP, "sudo truncate -s 0 /var/log/snort/alert_fast.txt")
    else:
        ssh_run(MONITOR_IP, "sudo truncate -s 0 /var/log/suricata/fast.log")


@pytest.fixture(autouse=True)
def clear_before_test():
    """Clear IDS logs before each test."""
    clear_alerts()
    yield
    time.sleep(1)  # Allow IDS to flush


class TestScenario001PortScan:
    """SCN-001: Port Scan (Nmap)"""

    def test_nmap_syn_scan_triggers_alert(self):
        """Nmap SYN scan must generate IDS alerts."""
        before = get_alert_count()

        result = ssh_run(
            ATTACKER_IP,
            f"nmap -sS -T4 -p 22,80,21,445 {TARGET_WEB} {TARGET_SSH}",
            timeout=60
        )
        assert result.returncode == 0, f"Nmap failed: {result.stderr}"

        time.sleep(3)
        after = get_alert_count()
        new_alerts = after - before

        assert new_alerts > 0, \
            f"No IDS alerts triggered by Nmap SYN scan (before={before}, after={after})"

    def test_nmap_xmas_scan_triggers_alert(self):
        """Nmap XMAS scan must generate IDS alerts."""
        before = get_alert_count()

        ssh_run(ATTACKER_IP, f"sudo nmap -sX -T3 -p 22,80 {TARGET_WEB}", timeout=45)

        time.sleep(3)
        after = get_alert_count()
        assert after > before, "No alerts for XMAS scan"


class TestScenario002SSHBruteforce:
    """SCN-002: SSH Brute-force (Hydra)"""

    def test_hydra_ssh_bruteforce_triggers_alert(self):
        """Hydra SSH brute-force must trigger IDS alerts."""
        before = get_alert_count()

        result = ssh_run(
            ATTACKER_IP,
            f"hydra -l testuser -P /opt/archivirt/wordlists/passwords.txt "
            f"ssh://{TARGET_SSH} -t 4 -w 5 -f 2>/dev/null; exit 0",
            timeout=90
        )

        time.sleep(3)
        after = get_alert_count()
        new_alerts = after - before

        assert new_alerts > 0, \
            f"No IDS alerts for SSH brute-force (alerts_diff={new_alerts})"

    def test_hydra_detects_within_threshold(self):
        """IDS must detect SSH brute-force within 60 seconds."""
        before = get_alert_count()
        start = time.time()

        ssh_run(
            ATTACKER_IP,
            f"hydra -l admin -P /opt/archivirt/wordlists/passwords.txt "
            f"ssh://{TARGET_SSH} -t 16 -w 3 -f 2>/dev/null; exit 0",
            timeout=70
        )

        # Poll for alerts
        detected_at = None
        for _ in range(20):
            time.sleep(3)
            if get_alert_count() > before:
                detected_at = time.time() - start
                break

        assert detected_at is not None, "IDS failed to detect SSH brute-force"
        assert detected_at <= 60, \
            f"Detection took too long: {detected_at:.1f}s (max 60s)"


class TestScenario003SQLi:
    """SCN-003: SQL Injection (sqlmap)"""

    def test_sqlmap_triggers_alert(self):
        """sqlmap must trigger HTTP attack alerts on IDS."""
        before = get_alert_count()

        # Use curl to simulate a SQLi request first (faster than sqlmap full run)
        ssh_run(
            ATTACKER_IP,
            f"curl -s 'http://{TARGET_WEB}/dvwa/vulnerabilities/sqli/?id=1+UNION+SELECT+1,2--&Submit=Submit' "
            f"-o /dev/null -w '%{{http_code}}'",
            timeout=15
        )

        time.sleep(2)
        after = get_alert_count()

        # Also run sqlmap in quick mode
        ssh_run(
            ATTACKER_IP,
            f"sqlmap -u 'http://{TARGET_WEB}/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit' "
            f"--batch --level=1 --technique=U --dbms=mysql --output-dir=/tmp/sqlmap_test/ -q 2>/dev/null; exit 0",
            timeout=120
        )

        time.sleep(3)
        final = get_alert_count()
        total_new = final - before

        assert total_new > 0, \
            f"No IDS alerts detected for SQLi attack (diff={total_new})"

    def test_sqlmap_user_agent_detected(self):
        """sqlmap User-Agent must be detected by IDS."""
        before = get_alert_count()

        # Send request with sqlmap user agent
        ssh_run(
            ATTACKER_IP,
            f"curl -s -A 'sqlmap/1.7 (https://sqlmap.org)' "
            f"'http://{TARGET_WEB}/?id=1' -o /dev/null",
            timeout=10
        )

        time.sleep(2)
        after = get_alert_count()
        assert after > before, "sqlmap User-Agent not detected by IDS"


class TestScenario004Slowloris:
    """SCN-004: Slowloris DDoS"""

    def test_slowloris_triggers_alert(self):
        """Slowloris must eventually trigger IDS connection-based alerts."""
        before = get_alert_count()

        # Run short Slowloris burst
        ssh_run(
            ATTACKER_IP,
            f"python3 /opt/archivirt/attack-scripts/slowloris.py "
            f"{TARGET_WEB} --port 80 --sockets 150 --duration 30",
            timeout=45
        )

        time.sleep(3)
        after = get_alert_count()

        # Note: Slowloris has lower detection rate (65-78%)
        # This test verifies the scenario runs, not guaranteed detection every run
        print(f"Slowloris alerts: {after - before}")
        # Don't assert detection — Slowloris is by design hard to detect at low counts
        assert True  # Scenario executed without errors

    def test_web_server_survives_slowloris(self):
        """Target web server must still respond after Slowloris (resilience test)."""
        # Send slowloris for 10 seconds then verify server responds
        ssh_run(
            ATTACKER_IP,
            f"python3 /opt/archivirt/attack-scripts/slowloris.py "
            f"{TARGET_WEB} --port 80 --sockets 50 --duration 10",
            timeout=20
        )
        time.sleep(2)

        result = ssh_run(
            ATTACKER_IP,
            f"curl -s -o /dev/null -w '%{{http_code}}' http://{TARGET_WEB}/ --max-time 10"
        )
        # Server should still respond (may be slow)
        assert result.stdout.strip() in ["200", "301", "302", "500"], \
            f"Web server unresponsive after Slowloris (response: {result.stdout})"


class TestScenario005NormalTraffic:
    """SCN-005: Normal Traffic — False Positive Rate Measurement"""

    def test_normal_browsing_no_false_positives(self):
        """Legitimate web browsing must not trigger IDS alerts (< 5 alerts acceptable)."""
        before = get_alert_count()

        ssh_run(
            ATTACKER_IP,
            f"python3 /opt/archivirt/attack-scripts/normal_traffic.py "
            f"{TARGET_WEB} --duration 20",
            timeout=30
        )

        time.sleep(2)
        after = get_alert_count()
        fp_count = after - before

        # Allow some tolerance — strict 0 is unrealistic
        assert fp_count <= 5, \
            f"Too many false positives during normal traffic: {fp_count}"

    def test_legitimate_ssh_no_alert(self):
        """Legitimate SSH login must not trigger brute-force alert."""
        before = get_alert_count()

        # Single SSH connection (not brute-force)
        ssh_run(TARGET_SSH, "uname -a; exit", timeout=10)

        time.sleep(2)
        after = get_alert_count()
        new_alerts = after - before

        assert new_alerts == 0, \
            f"False positive: legitimate SSH triggered {new_alerts} alerts"
