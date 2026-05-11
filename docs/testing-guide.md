# ARCHIVIRT Testing Guide

## Prerequisites

- Ubuntu 22.04 LTS host with KVM/libvirt
- Terraform ≥ 1.5, Ansible ≥ 2.16
- Python 3.10+ with `pandas`, `scikit-learn`, `numpy`, `python-dateutil`
- All VMs deployed: `terraform apply` + `ansible-playbook ansible/site.yml`

---

## Running the Full Campaign (recommended)

Executes all 5 attack scenarios for both Snort and Suricata (10 iterations each):

```bash
cd ~/ARCHIVIRT
ansible-playbook ansible/playbooks/run_all_scenarios.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"
```

The pipeline runs automatically:
1. Snort 3.12.2.0 — SCN-001 to SCN-005
2. Suricata 6.0.4 — SCN-001 to SCN-005
3. Metrics computation (`build_final_results.py`)
4. DBSCAN/UEBA analysis (`dbscan_from_fetched.py`)
5. Final report printed to terminal + written to `results/archivirt_final_comparison.json`
6. Cleanup of all `/tmp/` artefacts

---

## Running a Single Scenario

### Snort 3

```bash
ansible-playbook ansible/playbooks/snort_scenario.yml \
  -i ansible/inventory/hosts.ini \
  -e "scenario=SCN-001 ids_prefix=snort3" \
  --ssh-extra-args="-o StrictHostKeyChecking=no"
```

### Suricata 6

```bash
ansible-playbook ansible/playbooks/suricata_scenario.yml \
  -i ansible/inventory/hosts.ini \
  -e "scenario=SCN-001 ids_prefix=suricata" \
  --ssh-extra-args="-o StrictHostKeyChecking=no"
```

> **Important:** always pass `ids_prefix` when running a single scenario manually.
> This ensures start-time files are prefixed correctly and do not overwrite each
> other when both engines are tested in sequence.

---

## Scenario Descriptions

| ID | Name | Tool | Target | Iterations |
|----|------|------|--------|------------|
| SCN-001 | Port Scan | Nmap -sS, ports 1–1024, T4 | 10.0.2.11–13 | 10 |
| SCN-002 | SSH Brute-force | Nmap port 22 | 10.0.2.11–13 | 10 |
| SCN-003 | SQL Injection | sqlmap against DVWA v1.10 | 10.0.2.11 | 10 |
| SCN-004 | DDoS Slowloris | Python, 150 sockets, 15 s | 10.0.2.11 | 10 |
| SCN-005 | Normal Traffic | curl HTTP GET (FPR baseline) | 10.0.2.11–12 | 10 |

### Timing methodology

Each iteration records a start-time with nanosecond precision (`date -u +%s.%N`)
**after** a warmup phase that pre-initialises the attack tool:

- SCN-001/002: `nmap -sL` (DNS resolution only, no traffic)
- SCN-003: `sqlmap --list-tampers` (module pre-load)
- SCN-004: Slowloris launched in background, `sleep 0.5`, then timestamp recorded

This eliminates tool startup overhead from latency measurements.

> **Clock skew note:** an inter-VM NTP offset of ~800 ms between the attacker VM
> (start-time source) and the monitor VM (alert-time source) causes some alert
> timestamps to appear before the recorded start-time. `compute_metrics()` applies
> a 2 s tolerance window and clamps latency to ≥ 0 ms. Both IDS engines are subject
> to the same offset, so Snort/Suricata comparison remains valid.

---

## Calibrating Performance

Measures real CPU, RAM, and throughput under load:

```bash
ansible-playbook ansible/playbooks/calibrate_performance.yml \
  -i ansible/inventory/hosts.ini
```

Output is written to `results/performance_baseline.json` and used by
`build_final_results.py` to populate Table 3.

---

## Generating the Report Manually

```bash
python3 scripts/build_final_results.py   # compute DR, FPR, latency
python3 scripts/dbscan_from_fetched.py   # DBSCAN/UEBA analysis
python3 scripts/generate_report.py       # print Tables 2, 3, 4
```

Output: `results/archivirt_final_comparison.json`

---

## Tearing Down the Laboratory

```bash
ansible-playbook ansible/playbooks/teardown.yml \
  -i ansible/inventory/hosts.ini

cd terraform && terraform destroy -var-file=../configs/lab.tfvars
```

---

## Understanding the Results

### Table 2 — Detection Efficiency Metrics

| Column | Definition |
|--------|------------|
| Alerts | Total alerts generated during the scenario (10 iterations) |
| DR% | Detection rate: fraction of attack iterations producing ≥1 alert within the time window |
| FPR% | False-positive rate: normal traffic alerts / total alerts |
| Latency (ms) | Mean time from attack launch to first alert (see timing methodology above) |

### Table 3 — System Performance Metrics

Peak CPU and RAM measured via `top` and `/proc/meminfo` (collected by Telegraf).
Throughput (Mbps) from `performance_baseline.json`.

### Table 4 — DBSCAN/UEBA Analysis

- Sample: 3 000 alerts randomly drawn from each IDS engine's full alert set.
- Parameters: ε = 0.5, min_samples = 5.
- Anomalies = noise points (no cluster assignment).
- Execution time < 2 s.

---

## Log File Locations

| IDS | Alert log | Timestamp format |
|-----|-----------|-----------------|
| Snort 3.12.2.0 | `/var/log/snort3/SCN-XXX/alert_json.txt` | `MM/DD-HH:MM:SS.ffffff` (UTC) |
| Suricata 6.0.4 | `/var/log/suricata/SCN-XXX/eve.json` | ISO 8601 UTC |

Both formats are parsed automatically by `build_final_results.py`.
