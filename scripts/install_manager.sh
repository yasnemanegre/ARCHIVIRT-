#!/bin/bash
# ARCHIVIRT - Install manager packages via local apt repo
# Author: Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
MIRROR="http://10.0.5.1:8080"
echo "deb [trusted=yes] $MIRROR ./" > /etc/apt/sources.list.d/archivirt-local.list
apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup=0 2>/dev/null
apt-get install -y --no-install-recommends \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  influxdb2 grafana telegraf 2>&1 | tail -5
systemctl enable influxdb grafana-server telegraf 2>/dev/null || true
echo "[ARCHIVIRT] $(which influxd && echo influxd OK) $(which telegraf && echo telegraf OK)"
