#!/bin/bash
# Import ARCHIVIRT dashboard into Grafana via API
# Author: Yasnemanegre SAWADOGO (SPbGUPTD)
GRAFANA_URL="http://localhost:3000"
DASHBOARD_FILE="/home/archivirt/ARCHIVIRT/monitoring/grafana/dashboard.json"
USER="admin"
PASSWORD="ARCHIVIRT2026"

# Attendre que Grafana soit prêt
until curl -s -u "${USER}:${PASSWORD}" -o /dev/null -w "%{http_code}" "${GRAFANA_URL}/api/health" | grep -q "200"; do
    echo "Waiting for Grafana..."
    sleep 2
done

# Importer le dashboard
curl -s -u "${USER}:${PASSWORD}" -X POST "${GRAFANA_URL}/api/dashboards/db" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d "{\"dashboard\":$(cat ${DASHBOARD_FILE}),\"overwrite\":true}" \
  && echo -e "\nDashboard ARCHIVIRT importé automatiquement." \
  || echo -e "\nErreur lors de l'import."
