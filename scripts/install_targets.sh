#!/bin/bash
# ARCHIVIRT - Install target packages from local mirror
MIRROR="http://10.0.2.1:8080"
PKG_DIR="/opt/archivirt/packages"
mkdir -p "$PKG_DIR"
cd "$PKG_DIR"

for pkg_url in \
  "apache2_2.4.52-1ubuntu4.19_amd64.deb" \
  "libapache2-mod-php8.1_8.1.2-1ubuntu2.23_amd64.deb" \
  "php8.1-cli_8.1.2-1ubuntu2.23_amd64.deb" \
  "php8.1-mysql_8.1.2-1ubuntu2.23_amd64.deb" \
  "php8.1-gd_8.1.2-1ubuntu2.23_amd64.deb" \
  "mariadb-server-10.6_1%3a10.6.23-0ubuntu0.22.04.1_amd64.deb" \
  "samba_2%3a4.15.13+dfsg-0ubuntu1.10_amd64.deb" \
  "vsftpd_3.0.5-0ubuntu1.1_amd64.deb" \
  "git_1%3a2.34.1-1ubuntu1.17_amd64.deb"; do
  name=$(echo "$pkg_url" | cut -d_ -f1)
  wget -q "$MIRROR/$pkg_url" -O "${name}.deb" && \
    dpkg -i "${name}.deb" 2>/dev/null || true
done
apt-get install -f -y 2>/dev/null || true
echo "ARCHIVIRT target packages installed"
