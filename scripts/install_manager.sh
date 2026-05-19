#!/bin/bash
# =============================================================================
# ARCHIVIRT - Install monitoring stack on manager VM
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 2.0.0 — 2026-05-19
#
# Installs InfluxDB2 + Grafana + Telegraf from local apt mirror.
# Telegraf collects Suricata metrics from eve.json on monitor VM (10.0.3.10)
# and pushes to InfluxDB2. Grafana visualizes the metrics.
#
# IaC option B: local apt mirror only. Mirror: http://10.0.5.1:8080/
# =============================================================================

set -e

MIRROR="http://10.0.5.1:8080"
INFLUXDB_TOKEN="archivirt-token-2026"
INFLUXDB_ORG="archivirt"
INFLUXDB_BUCKET="archivirt_ids"
MONITOR_IP="10.0.3.10"

# --- Configure local apt mirror ----------------------------------------------
echo "deb [trusted=yes] $MIRROR ./" > /etc/apt/sources.list.d/archivirt-local.list

apt-get update \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  -o Dir::Etc::sourceparts="-" \
  -o APT::Get::List-Cleanup=0 -q 2>/dev/null

# --- Install monitoring stack ------------------------------------------------
apt-get install -y --no-install-recommends \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  influxdb2 grafana telegraf 2>&1 | tail -5

# --- Configure Telegraf for Suricata metrics ---------------------------------
cat > /etc/telegraf/telegraf.conf << TELEGRAFEOF
[global_tags]
  lab = "archivirt"

[agent]
  interval = "10s"
  flush_interval = "10s"

# Input: Suricata EVE JSON from monitor VM via SSH
[[inputs.tail]]
  files = ["/tmp/suricata_eve_*.json"]
  from_beginning = false
  data_format = "json"
  tag_keys = ["event_type", "src_ip", "dest_ip", "proto", "alert.category"]
  json_string_fields = ["alert.signature", "alert.severity"]

# Output: InfluxDB2
[[outputs.influxdb_v2]]
  urls = ["http://localhost:8086"]
  token = "$INFLUXDB_TOKEN"
  organization = "$INFLUXDB_ORG"
  bucket = "$INFLUXDB_BUCKET"

# System metrics
[[inputs.cpu]]
  percpu = false
  totalcpu = true

[[inputs.mem]]

[[inputs.net]]
TELEGRAFEOF

# --- Start services ----------------------------------------------------------
systemctl enable influxdb grafana-server telegraf 2>/dev/null || true
systemctl start influxdb 2>/dev/null || true
sleep 5

# --- Configure InfluxDB2 -----------------------------------------------------
influx setup \
  --username admin \
  --password archivirt2026 \
  --org "$INFLUXDB_ORG" \
  --bucket "$INFLUXDB_BUCKET" \
  --token "$INFLUXDB_TOKEN" \
  --force 2>/dev/null || true

systemctl start grafana-server telegraf 2>/dev/null || true

echo "[ARCHIVIRT] $(which influxd && echo 'influxd OK')"
echo "[ARCHIVIRT] $(which telegraf && echo 'telegraf OK')"
echo "[ARCHIVIRT] $(which grafana-server && echo 'grafana OK')"
echo "[ARCHIVIRT] Grafana: http://10.0.5.10:3000 (admin/admin)"
echo "[ARCHIVIRT] InfluxDB: http://10.0.5.10:8086"
echo "[ARCHIVIRT] Manager installation complete."
