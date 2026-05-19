#!/bin/bash
# =============================================================================
# ARCHIVIRT - Install vulnerable services on target VMs
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 2.0.0 — 2026-05-19
#
# Installs vulnerable services for IDS/IPS testing scenarios:
#   SCN-001: Port Scan    → all services
#   SCN-002: SSH Brute    → OpenSSH 8.9 (vulnerable config)
#   SCN-003: SQL Injection → DVWA v1.10 on Apache 2.4 + PHP 7.4 + MariaDB
#   SCN-004: DDoS Slowloris → Apache HTTP
#   SCN-005: Normal traffic → Apache HTTP
#
# IaC option B: local apt mirror only. Mirror: http://10.0.2.1:8080/
# =============================================================================

set -e

MIRROR="http://10.0.2.1:8080"
TARGET_ROLE="${TARGET_ROLE:-web}"  # web | ssh_ftp | smb_db

# --- Configure local apt mirror ----------------------------------------------
echo "deb [trusted=yes] $MIRROR ./" > /etc/apt/sources.list.d/archivirt-local.list

apt-get update \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  -o Dir::Etc::sourceparts="-" \
  -o APT::Get::List-Cleanup=0 -q 2>/dev/null

# --- Install base packages (all roles) ---------------------------------------
apt-get install -y --no-install-recommends \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  openssh-server curl wget 2>&1 | tail -3

# --- Configure vulnerable SSH (all roles — SCN-002) --------------------------
# OpenSSH 8.9 with password auth enabled, fail2ban disabled
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
systemctl enable ssh && systemctl restart ssh
echo "[ARCHIVIRT] SSH vulnerable config: PasswordAuthentication=yes"

# --- Role-specific installation ----------------------------------------------
case "$TARGET_ROLE" in

  web)
    # DVWA v1.10 on Apache 2.4.52 + PHP 8.1 + MariaDB (SCN-003, SCN-004, SCN-005)
    apt-get install -y --no-install-recommends \
      -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
      apache2 libapache2-mod-php8.1 php8.1 php8.1-mysql php8.1-gd \
      php8.1-xml mariadb-server 2>&1 | tail -3

    # Deploy DVWA from mirror
    if [ -f /tmp/dvwa.tar.gz ] || wget -q "$MIRROR/dvwa.tar.gz" -O /tmp/dvwa.tar.gz 2>/dev/null; then
      tar -xzf /tmp/dvwa.tar.gz -C /var/www/html/ 2>/dev/null || true
    fi

    # DVWA config — low security for SQLi testing
    cp /var/www/html/dvwa/config/config.inc.php.dist \
       /var/www/html/dvwa/config/config.inc.php 2>/dev/null || true
    sed -i "s/\$_DVWA\['db_password'\] = 'p@ssw0rd'/\$_DVWA['db_password'] = ''/" \
      /var/www/html/dvwa/config/config.inc.php 2>/dev/null || true

    # MariaDB setup for DVWA
    systemctl start mariadb
    mysql -u root -e "CREATE DATABASE IF NOT EXISTS dvwa;" 2>/dev/null || true
    mysql -u root -e "GRANT ALL ON dvwa.* TO 'dvwa'@'localhost' IDENTIFIED BY '';" \
      2>/dev/null || true

    systemctl enable apache2 mariadb
    systemctl restart apache2
    echo "[ARCHIVIRT] Web role: Apache2 + PHP8.1 + MariaDB + DVWA installed"
    ;;

  ssh_ftp)
    # OpenSSH + vsftpd (SCN-002)
    apt-get install -y --no-install-recommends \
      -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
      vsftpd 2>&1 | tail -3

    # Vulnerable vsftpd config
    sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf 2>/dev/null || true
    systemctl enable vsftpd && systemctl restart vsftpd
    echo "[ARCHIVIRT] SSH/FTP role: OpenSSH + vsftpd installed"
    ;;

  smb_db)
    # Samba 4.15.9 + MariaDB (SCN-001)
    apt-get install -y --no-install-recommends \
      -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
      samba mariadb-server 2>&1 | tail -3

    # Vulnerable Samba config
    cat >> /etc/samba/smb.conf << 'SMBEOF'
[vulnerable_share]
   path = /srv/samba/vulnerable
   browseable = yes
   read only = no
   guest ok = yes
SMBEOF
    mkdir -p /srv/samba/vulnerable
    chmod 777 /srv/samba/vulnerable

    systemctl enable smbd nmbd mariadb
    systemctl restart smbd nmbd
    echo "[ARCHIVIRT] SMB/DB role: Samba 4.15.9 + MariaDB installed"
    ;;
esac

echo "[ARCHIVIRT] Target installation complete (role=$TARGET_ROLE)."
