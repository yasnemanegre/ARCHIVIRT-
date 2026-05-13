#!/bin/bash
# ARCHIVIRT - Install attacker packages from local mirror
MIRROR="http://10.0.4.1:8080"
PKG_DIR="/opt/archivirt/packages"
mkdir -p "$PKG_DIR"
cd "$PKG_DIR"

wget -q "$MIRROR/nmap_7.91%2Bdfsg1%2Breally7.80%2Bdfsg1-2ubuntu0.1_amd64.deb" \
  -O nmap.deb && dpkg -i nmap.deb 2>/dev/null || true
wget -q "$MIRROR/sqlmap_1.6.4-2_all.deb" \
  -O sqlmap.deb && dpkg -i sqlmap.deb 2>/dev/null || true
apt-get install -f -y 2>/dev/null || true
echo "ARCHIVIRT attacker packages installed"
