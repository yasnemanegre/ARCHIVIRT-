#!/bin/bash
# =============================================================================
# ARCHIVIRT - Update ET Open rules on host and serve via local mirror
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 1.0.0 — 2026-05-19
#
# Run this script on the HOST (not on VMs) to refresh the ET Open ruleset.
# The host has internet access; VMs use local mirror only (IaC option B).
#
# Output : /var/spool/apt-mirror/packages/rules/suricata.rules
# Served : http://10.0.X.1:8080/rules/suricata.rules (all VM networks)
#
# Usage  : sudo bash scripts/update_et_rules.sh
# Cron   : 0 3 * * 1 root bash /home/archivirt/ARCHIVIRT/scripts/update_et_rules.sh
# =============================================================================

set -e

RULES_DIR="/var/spool/apt-mirror/packages/rules"
RULES_FILE="${RULES_DIR}/suricata.rules"

echo "[ARCHIVIRT] Updating ET Open rules on host ..."

# Ensure suricata-update is installed on host
if ! which suricata-update > /dev/null 2>&1; then
  echo "[ARCHIVIRT] Installing suricata-update on host ..."
  apt-get install -y suricata-update
fi

# Ensure ET Open source is registered
suricata-update list-sources --enabled 2>/dev/null | grep -q "et/open" || \
  suricata-update add-source et/open \
    https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz

# Download/update ET Open rules
suricata-update \
  --suricata-version 6.0.4 \
  --output "${RULES_DIR}" \
  --no-reload \
  2>&1 | tail -10

# Fix permissions — archivirt user must be able to read for Ansible copy
chown -R root:archivirt "${RULES_DIR}"
chmod 750 "${RULES_DIR}"
chmod 640 "${RULES_FILE}"

RULE_COUNT=$(grep -c '^alert' "${RULES_FILE}" 2>/dev/null || echo 0)
echo "[ARCHIVIRT] ET Open rules updated: ${RULE_COUNT} rules -> ${RULES_FILE}"
echo "[ARCHIVIRT] Served via: http://10.0.X.1:8080/rules/suricata.rules"
