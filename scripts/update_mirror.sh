#!/bin/bash
# ARCHIVIRT - Update local apt mirror using dpkg-repack
# Author: Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
# Usage: sudo bash update_mirror.sh
set -euo pipefail

MIRROR_DIR="/var/spool/apt-mirror/packages"
mkdir -p "$MIRROR_DIR"
cd "$MIRROR_DIR"

echo "[ARCHIVIRT] Extracting packages via dpkg-repack..."

PACKAGES=(
  # Web server
  apache2 apache2-bin apache2-data apache2-utils
  libapr1 libaprutil1 libaprutil1-dbd-sqlite3
  libaprutil1-dbd-freetds libaprutil1-dbd-odbc libaprutil1-ldap
  # PHP
  libapache2-mod-php8.1 php8.1-cli php8.1-mysql php8.1-gd
  libgd3 libfreetype6 libjpeg8 libpng16-16 libwebp7 libavif13 libxpm4
  # MariaDB
  mariadb-server-10.6 mariadb-client-10.6 libmariadb3
  # Samba
  samba samba-libs samba-common libwbclient0
  libtalloc2 libtevent0 libtdb1 libldb2
  libldap-2.5-0 libsasl2-2
  # FTP/SSH
  vsftpd openssh-server
  # IDS
  snort suricata
  python3-simplejson liblua5.3-0 liblua5.4-0
  # Attack tools
  nmap sqlmap
  # System libs
  libexpat1 libssl3 libpcre3 libpcre2-8-0
  libpcre2-posix3 libc6
  # Monitoring
  telegraf
  # NTP
  chrony
  # Utils
  git curl wget vim htop net-tools iproute2
  tcpdump nftables ebtables
  python3-pip python3-numpy python3-pandas python3-sklearn
)

ok=0; skip=0
for pkg in "${PACKAGES[@]}"; do
  if dpkg-repack "$pkg" 2>/dev/null; then
    ((ok++))
  else
    ((skip++))
  fi
done

echo "[ARCHIVIRT] dpkg-repack: $ok OK, $skip skipped"

# Rebuild apt index
dpkg-scanpackages . /dev/null 2>/dev/null > Packages
gzip -9c Packages > Packages.gz
echo "[ARCHIVIRT] Mirror updated: $(ls *.deb | wc -l) packages"
echo "[ARCHIVIRT] Index: $(grep -c '^Package:' Packages) entries"
