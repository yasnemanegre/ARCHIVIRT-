#!/bin/bash
# ARCHIVIRT - Install target packages via local apt repo
# Author: Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
MIRROR="http://10.0.2.1:8080"
echo "deb [trusted=yes] $MIRROR ./" > /etc/apt/sources.list.d/archivirt-local.list
apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup=0 2>/dev/null
apt-get install -y --no-install-recommends \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  apache2 libapache2-mod-php8.1 php8.1-mysql php8.1-gd \
  mariadb-server samba vsftpd git 2>&1 | tail -5
echo "[ARCHIVIRT] $(which apache2 && echo apache2 OK)"
