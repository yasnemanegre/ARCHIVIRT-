#!/bin/bash
# ARCHIVIRT - Install attacker packages via local mirror
# Author: Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
MIRROR="http://10.0.4.1:8080"
PKG_DIR="/opt/archivirt/packages"
mkdir -p "$PKG_DIR" && cd "$PKG_DIR"
echo "[ARCHIVIRT] Installing attacker packages..."
wget -q "$MIRROR/nmap_7.91%2Bdfsg1%2Breally7.80%2Bdfsg1-2ubuntu0.1_amd64.deb" -O nmap.deb
wget -q "$MIRROR/sqlmap_1.6.4-2_all.deb" -O sqlmap.deb
dpkg -i --force-depends nmap.deb sqlmap.deb 2>/dev/null || true
apt-get install -f -y 2>/dev/null || true
echo "[ARCHIVIRT] $(which nmap && echo nmap OK) $(which sqlmap && echo sqlmap OK)"
