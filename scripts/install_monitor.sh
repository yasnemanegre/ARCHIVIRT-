#!/bin/bash
# ARCHIVIRT - Install IDS packages from local mirror
# Author: Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
MIRROR="http://10.0.3.1:8080"
PKG_DIR="/opt/archivirt/packages"
mkdir -p "$PKG_DIR"
cd "$PKG_DIR"

wget -q "$MIRROR/snort_2.9.15.1-6build1_amd64.deb" -O snort.deb && \
  dpkg -i snort.deb 2>/dev/null || true
wget -q "$MIRROR/suricata_1%3a6.0.4-3_amd64.deb" -O suricata.deb && \
  dpkg -i suricata.deb 2>/dev/null || true
apt-get install -f -y 2>/dev/null || true
echo "ARCHIVIRT monitor packages installed"
