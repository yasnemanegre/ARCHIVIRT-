# ARCHIVIRT — Skill Sheet (IaC Knowledge Base)
# Auteur : Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
# Mise à jour : 12.05.2026

## Architecture réseau

| Réseau | IP | Bridge libvirt | Rôle |
|---|---|---|---|
| archivirt-net-targets | 10.0.2.0/24 | virbr3 | VMs cibles (DVWA, SSH, SMB) |
| archivirt-net-monitor | 10.0.3.0/24 | virbr4 | VM IDS (Snort + Suricata) |
| archivirt-net-attack  | 10.0.4.0/24 | virbr2 | VM attaquante |
| archivirt-net-manager | 10.0.5.0/24 | virbr1 | VM manager |

**Important** : les noms virbr sont attribués par libvirt à la création —
non contrôlables via Terraform. Toujours détecter dynamiquement via
`virsh net-info archivirt-net-<nom> | grep Bridge`.

## Interfaces VM IDS (archivirt-monitor-ids)

| Interface VM | vnet host | Réseau | Rôle |
|---|---|---|---|
| ens3 | vnet4 | archivirt-net-monitor (virbr4) | Management/SSH |
| ens4 | vnet5 | archivirt-net-targets (virbr3) | Écoute IDS (miroir trafic) |

**Snort et Suricata écoutent sur ens4** — interface connectée au réseau targets,
qui reçoit le trafic mirroré via `tc mirred`.

## Mirroring trafic (tc mirred)

Script : `scripts/archivirt_mirrors.sh`
- 100% dynamique — aucun virbr hardcodé
- Détecte le bridge targets et attack via `virsh net-info`
- Détecte le vnet monitor via `virsh domiflist archivirt-monitor-ids | grep targets`
- Skip self-mirror automatiquement

```bash
sudo bash scripts/archivirt_mirrors.sh
```

## Bug critique résolu : checksum TCP

**Problème** : Snort 3 rejette tous les paquets mirrorés (`bad_tcp4_checksum`)
car le calcul checksum est fait en hardware (offloading NIC) après le mirror.

**Fix** : ajouter dans `configs/snort/snort.lua` :
```lua
network = { checksum_eval = 'none' }
```

## Bug critique résolu : clock skew inter-VM

**Problème** : latences artificiellement nulles ou négatives (clampées à 0)
car les horloges des VMs divergent jusqu'à ~800ms.

**Fix IaC** :
- Host configuré comme serveur NTP interne (chrony, stratum 8)
- Toutes les VMs synchronisent sur leur gateway : 10.0.{2,3,4,5}.1
- Playbook : `ansible/playbooks/setup_ntp.yml`
- Install offline : `ansible/files/chrony_4.2-2ubuntu2_amd64.deb`

**Résultat** : offset inter-VM < 1ms, latences réelles obtenues.

## Bug critique résolu : règles Snort 3 SQLi

**Problème** : DR=0% sur SQL Injection car DVWA envoie des payloads
URL-encodés (`%27`, `%20AND%20`) et les règles matchaient sur texte décodé.

**Fix** : règles sur patterns URL-encodés dans `configs/snort/snort.lua` :
alert tcp any any -> 10.0.2.0/24 80 (msg:"SQLi quote"; content:"%27"; sid:9000007;)
alert tcp any any -> 10.0.2.0/24 80 (msg:"SQLi AND"; content:"%20AND%20"; sid:9000008;)
## Bug critique résolu : Suricata rule-files

**Problème** : Suricata chargeait `suricata.rules` et `local.rules`
(inexistants) → 0 détections sur Port Scan et SSH.

**Fix** : corriger `configs/suricata/suricata.yaml` :
```yaml
default-rule-path: /etc/suricata/rules
rule-files:
  - tls-events.rules
  - stream-events.rules
  - decoder-events.rules
  - smtp-events.rules
  - http-events.rules
  - http2-events.rules
  - dns-events.rules
  - smb-events.rules
  - kerberos-events.rules
  - archivirt-local.rules
```
**Note** : `dnp3-events.rules` non compilé dans Suricata 6.0.4 sur Ubuntu 22.04.

## Résultats validés (campagne 12.05.2026)

| Scénario | Snort DR% | Snort Lat | Suricata DR% | Suricata Lat |
|---|---|---|---|---|
| Port Scan | 100.0 | 47.5 ms | 100.0 | 50.0 ms |
| SSH Brute-force | 100.0 | 557.0 ms | 100.0 | 50.3 ms |
| SQL Injection | 100.0 | 242.1 ms | 100.0 | 247.2 ms |
| DDoS Slowloris | 100.0 | 0.0 ms* | 100.0 | 0.0 ms* |
| Normal Traffic | N/A | N/A | N/A | N/A |

*Slowloris 0.0ms = comportement réel du detection_filter (seuil déclenché
pendant l'attaque active, pas un artefact).

| IDS | FPR% | CPU% | RAM MB | Mbps |
|---|---|---|---|---|
| Snort 3.12.2.0 | 0.12 | 1.6 | 41 | 945 |
| Suricata 6.0.4 | 0.55 | 7.7 | 46 | 1120 |

## Commandes clés

```bash
# Campagne complète
ansible-playbook ansible/playbooks/run_all_scenarios.yml \
  -i ansible/inventory/hosts.ini \
  --ssh-extra-args="-o StrictHostKeyChecking=no"

# Scénario individuel
ansible-playbook ansible/playbooks/snort_scenario.yml \
  -i ansible/inventory/hosts.ini \
  -e "scenario=SCN-003 ids_prefix=snort3"

# Rapport
python3 scripts/generate_report.py

# NTP sync
ansible-playbook ansible/playbooks/setup_ntp.yml \
  -i ansible/inventory/hosts.ini

# Mirror
sudo bash scripts/archivirt_mirrors.sh
```

## Conventions IaC

- Jamais de `virbr` hardcodé — toujours `virsh net-info`
- Jamais de `ssh ubuntu@IP` dans les scripts — toujours via Ansible
- Tout fichier de config source dans `configs/` — jamais édité directement sur la VM
- Auteur : **Яснеманегре САВАДОГО (Аспирант СПбГУПТД)**
- Université : **СПбГУПТД** (не СПбГУТ)
