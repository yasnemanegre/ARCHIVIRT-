#!/bin/bash
# ARCHIVIRT - Install IDS packages via local apt repo
# Author: Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
MIRROR="http://10.0.3.1:8080"
echo "deb [trusted=yes] $MIRROR ./" > /etc/apt/sources.list.d/archivirt-local.list
apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup=0 2>/dev/null
apt-get install -y --no-install-recommends \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  snort suricata 2>&1 | tail -5
echo "[ARCHIVIRT] $(which snort && echo snort OK) $(which suricata && echo suricata OK)"
