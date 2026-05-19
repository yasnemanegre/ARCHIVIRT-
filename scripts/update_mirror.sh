#!/bin/bash
# =============================================================================
# ARCHIVIRT - Update local apt mirror with all required packages
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 3.1.0 — 2026-05-19
# Uses apt-cache depends --recurse for automatic full dependency resolution.
# =============================================================================
set -e
MIRROR_DIR="/var/spool/apt-mirror/packages"
cd "$MIRROR_DIR"
echo "[ARCHIVIRT] Resolving full dependency tree..."
TOP_PACKAGES="nmap hydra sqlmap hping3 tcpreplay python3-scapy \
  suricata suricata-update snort3 \
  apache2 libapache2-mod-php8.1 php8.1 php8.1-mysql \
  mariadb-server samba vsftpd openssh-server \
  influxdb2 telegraf grafana curl wget git python3"
ALL_DEPS=$(apt-cache depends --recurse --no-recommends --no-suggests \
  --no-conflicts --no-breaks --no-replaces --no-enhances \
  $TOP_PACKAGES 2>/dev/null | grep "^\w" | sort -u | tr '\n' ' ')
echo "[ARCHIVIRT] Downloading all packages and dependencies..."
sudo apt-get install --reinstall --download-only -y $ALL_DEPS 2>&1 | tail -3
sudo cp /var/cache/apt/archives/*.deb . 2>/dev/null || true
# ET Open rules
if which suricata-update > /dev/null 2>&1; then
  suricata-update --suricata-version 6.0.4 \
    --output "$MIRROR_DIR/rules" --no-reload 2>&1 | tail -3
  chmod 640 "$MIRROR_DIR/rules/suricata.rules" 2>/dev/null || true
  chown root:archivirt "$MIRROR_DIR/rules" 2>/dev/null || true
fi
# Rebuild index
dpkg-scanpackages . /dev/null 2>/dev/null | tee Packages > /dev/null
gzip -k -f Packages
echo "[ARCHIVIRT] Mirror: $(grep -c '^Package:' Packages) packages, $(du -sh . | cut -f1)"
