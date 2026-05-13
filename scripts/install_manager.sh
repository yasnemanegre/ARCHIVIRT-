#!/bin/bash
# ARCHIVIRT - Install manager packages (InfluxDB, Grafana, Telegraf)
MIRROR="http://10.0.5.1:8080"
PKG_DIR="/opt/archivirt/packages"
mkdir -p "$PKG_DIR"
cd "$PKG_DIR"

wget -q "$MIRROR/influxdb2_2.9.1-1_amd64.deb" -O influxdb2.deb && \
  dpkg -i influxdb2.deb 2>/dev/null || true
wget -q "$MIRROR/grafana_10.4.2_amd64.deb" -O grafana.deb && \
  dpkg -i grafana.deb 2>/dev/null || true
wget -q "$MIRROR/telegraf_1.29.5_amd64.deb" -O telegraf.deb && \
  dpkg -i telegraf.deb 2>/dev/null || true
systemctl enable influxdb grafana-server telegraf 2>/dev/null || true
echo "ARCHIVIRT manager packages installed"
