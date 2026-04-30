# ARCHIVIRT — Architecture Documentation

> Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)

---

## Framework Design Principles

ARCHIVIRT is built around four core principles:

| Principle | Description |
|-----------|-------------|
| **Reproducibility** | Any environment can be recreated identically from code definition |
| **Modularity** | Components (targets, IDS, attackers) are interchangeable and independent |
| **Automation** | Minimizes manual intervention from deployment to analysis |
| **Measurability** | Automatically generates quantitative metrics on the environment and IDS under test |

---

## 5-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 5 — Data & Metrics                                       │
│  PCAP files, Logs, JSON metrics, HTML reports, Grafana          │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 4 — Functional Roles                                     │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Target Subnet│  │Monitor Subnet│  │ Attack/Manager Subnet│  │
│  │ 10.0.2.0/24 │  │ 10.0.3.0/24 │  │     10.0.4.0/24      │  │
│  │             │  │             │  │                       │  │
│  │ Web (DVWA)  │  │ Snort 3     │  │ Metasploit            │  │
│  │ SSH Server  │  │    OR       │  │ Nmap                  │  │
│  │ SMB Share   │  │ Suricata 6  │  │ Hydra                 │  │
│  │ FTP Server  │  │             │  │ sqlmap                │  │
│  └──────────────┘  └──────────────┘  │ Slowloris            │  │
│                                      │ CALDERA              │  │
│                                      └──────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Manager VM (10.0.5.10)                                   │  │
│  │ Orchestration • Log Collection • Metrics • Reports       │  │
│  └──────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3 — Virtual (KVM/Libvirt)                                │
│  VMs on isolated private virtual networks (NAT disabled)        │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2 — Orchestration (IaC)                                  │
│  Terraform v1.5+  →  VM & Network Provisioning                  │
│  Ansible          →  Software Configuration                      │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 1 — Physical/Host                                        │
│  Ubuntu Server 22.04 LTS  |  archivirt@archivirt-lab            │
│  IP: 192.168.4.11 (enp0s3) | KVM Hypervisor                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Virtual Machine Inventory

| VM Name | Role | Subnet | IP | vCPU | RAM |
|---------|------|--------|----|------|-----|
| archivirt-manager | Orchestration & Analysis | 10.0.5.0/24 | 10.0.5.10 | 2 | 4 GB |
| archivirt-attacker | Attack controller | 10.0.4.0/24 | 10.0.4.10 | 2 | 4 GB |
| archivirt-monitor | IDS/IPS (Snort or Suricata) | 10.0.3.0/24 | 10.0.3.10 | 2 | 4 GB |
| archivirt-target-01 | Web (DVWA/Apache) | 10.0.2.0/24 | 10.0.2.11 | 2 | 4 GB |
| archivirt-target-02 | SSH/FTP server | 10.0.2.0/24 | 10.0.2.12 | 2 | 4 GB |
| archivirt-target-03 | SMB/database server | 10.0.2.0/24 | 10.0.2.13 | 2 | 4 GB |

---

## Data Flow

```
[Attacker VM] ──→ attacks ──→ [Target VMs]
                                    │
                              (network tap)
                                    │
                                    ▼
                           [Monitor VM (IDS)]
                            Snort 3 / Suricata 6
                                    │
                              alerts + PCAP
                                    │
                                    ▼
                           [Manager VM]
                         Python: collect_metrics.py
                         Pandas: aggregate + analyze
                         Jinja2: generate HTML report
                                    │
                                    ▼
                         [Telegraf → InfluxDB → Grafana]
                           (real-time visualization)
```

---

## IDS Module Architecture

The IDS/IPS module is implemented as interchangeable Ansible roles:

```
ansible/roles/
├── ids_snort/      # Snort 3 — signature-based, lower CPU usage
└── ids_suricata/   # Suricata 6 — multithreaded, higher throughput
```

Switching between IDS engines requires only changing the Ansible tag:
```bash
# Deploy Snort 3
ansible-playbook site.yml --tags ids_snort

# Deploy Suricata 6
ansible-playbook site.yml --tags ids_suricata
```

---

## Test Scenario Pipeline (YAML-driven)

```yaml
# scenarios/ssh_bruteforce.yml
scenario:
  name: "SSH Brute-force"
  tool: hydra
  target_subnet: "10.0.2.0/24"
  runs: 10
  ...
```

```
[YAML Scenario] → [run_tests.sh] → [Attacker VM]
                                         │ executes attack
                                         ▼
                                   [Target VM]
                                         │
                                   [Monitor VM]
                                    records alerts
                                         │
                                   [Manager VM]
                                    collect_metrics.py
                                         │
                                   JSON metrics file
                                         │
                                   generate_report.py
                                         │
                                   HTML / PDF Report
```

---

## Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Hypervisor | KVM/Libvirt | Kernel-integrated |
| IaC provisioning | Terraform + terraform-provider-libvirt | v1.5+ |
| Configuration mgmt | Ansible | v2.14+ |
| Guest OS | Ubuntu Server Cloud | 22.04 LTS |
| IDS option A | Snort | 3.x |
| IDS option B | Suricata | 6.x |
| Attack tool A | Nmap | 7.x |
| Attack tool B | Hydra | 9.x |
| Attack tool C | sqlmap | 1.7+ |
| Attack tool D | Slowloris | Python |
| Analysis | Python + Pandas | 3.10+ |
| Metrics storage | InfluxDB | 2.x |
| Metrics agent | Telegraf | 1.x |
| Visualization | Grafana | 10.x |

---

## Future Roadmap

1. **Cloud Extension** — Terraform providers for AWS, Azure, GCP
2. **AI/ML Integration** — ML-based SOAR testing with UEBA modules (Isolation Forest, DBSCAN)
3. **MITRE ATT&CK Scenarios** — Public shared YAML scenario library aligned to ATT&CK framework
4. **Container Support** — Docker/Podman for lightweight component deployment
5. **Distributed Testing** — Multi-host test orchestration for large-scale scenarios
