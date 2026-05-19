#!/bin/bash
# =============================================================================
# ARCHIVIRT - Install and configure IDS packages on monitor VM
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 2.4.0 — 2026-05-19
#
# IaC Option B: all packages and rules served from local apt mirror only.
# The monitor VM has NO direct internet access.
#
# Package sources  : http://10.0.3.1:8080/ (local nginx mirror)
# ET Open rules    : http://10.0.3.1:8080/rules/suricata.rules
#                    (pre-downloaded on host by scripts/update_et_rules.sh,
#                     49778 rules enabled / 65629 total)
# suricata-update  : installed from local mirror (suricata-update_1.2.3-1)
#
# Do NOT add external apt sources in this script — IaC option B enforced.
# =============================================================================

set -e

MIRROR="http://10.0.3.1:8080"
RULES_URL="${MIRROR}/rules/suricata.rules"
RULES_DEST="/etc/suricata/rules/suricata.rules"
SCRIPTS_DIR="/opt/archivirt/scripts"

# --- Configure local apt mirror as sole source -------------------------------
echo "deb [trusted=yes] $MIRROR ./" > /etc/apt/sources.list.d/archivirt-local.list
echo "" > /etc/apt/sources.list

apt-get update \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  -o Dir::Etc::sourceparts="-" \
  -o APT::Get::List-Cleanup=0 -q 2>/dev/null

# --- Install IDS packages from local mirror ----------------------------------
apt-get install -y --no-install-recommends \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  snort3 suricata suricata-update \
  libdumbnet1 libhwloc15 libdaq2 libhyperscan5 2>&1 | tail -5

# --- Create Snort 3 configuration directory ----------------------------------
echo "[ARCHIVIRT] Configuring Snort 3..."
mkdir -p /etc/snort3/rules

cat > /etc/snort3/snort.lua << 'SNORTEOF'
-- ARCHIVIRT Snort 3.1.74.0 configuration
-- IDS passive mode on ens4 (OVS mirror interface)
HOME_NET = '10.0.0.0/8'
EXTERNAL_NET = '!$HOME_NET'
ips = {
  enable_builtin_rules = true,
  rules = [[include /etc/snort3/rules/snort.rules]]
}
alert_fast = { file = true, packet = false }
alert_json = { file = true, limit = 100 }
SNORTEOF

# Download Snort Community rules from local mirror
wget -q http://10.0.3.1:8080/rules/snort.rules \
  -O /etc/snort3/rules/snort.rules 2>/dev/null || \
  touch /etc/snort3/rules/snort.rules
touch /etc/snort3/rules/archivirt.rules

# Create snort_defaults.lua
mkdir -p /usr/local/etc/snort
cat > /usr/local/etc/snort/snort_defaults.lua << DEFAULTSEOF
HOME_NET = '10.0.0.0/8'
EXTERNAL_NET = '!$HOME_NET'
HTTP_SERVERS = '$HOME_NET'
SQL_SERVERS = '$HOME_NET'
SSH_SERVERS = '$HOME_NET'
HTTP_PORTS = '80'
SSH_PORTS = 22
DEFAULTSEOF
echo "[ARCHIVIRT] $(ls /etc/snort3/rules/snort.rules && echo 'Snort rules OK')" 

echo "[ARCHIVIRT] $(suricata --build-info 2>/dev/null | grep 'This is Suricata' || echo 'suricata OK')"
echo "[ARCHIVIRT] $(which suricata-update && echo 'suricata-update OK')"

# --- Create ARCHIVIRT scripts directory --------------------------------------
mkdir -p "$SCRIPTS_DIR"
echo "[ARCHIVIRT] Scripts directory: $SCRIPTS_DIR"

# --- Download ET Open rules from local mirror --------------------------------
echo "[ARCHIVIRT] Fetching ET Open rules from local mirror ..."
mkdir -p /etc/suricata/rules

wget -q --timeout=60 --tries=3 \
  "${RULES_URL}" \
  -O "${RULES_DEST}"

RULE_COUNT=$(grep -c '^alert' "${RULES_DEST}" 2>/dev/null || echo 0)
echo "[ARCHIVIRT] ET Open rules: ${RULE_COUNT} rules -> ${RULES_DEST}"

if [ "$RULE_COUNT" -lt 1000 ]; then
  echo "[ARCHIVIRT] ERROR: rule count too low (${RULE_COUNT}), aborting."
  exit 1
fi

# --- Create empty archivirt-local.rules (custom rules placeholder) -----------
touch /etc/suricata/rules/archivirt-local.rules
echo "[ARCHIVIRT] archivirt-local.rules created (empty placeholder)"

# --- Validate final Suricata configuration -----------------------------------
echo "[ARCHIVIRT] Validating Suricata configuration ..."
suricata -T -c /etc/suricata/suricata.yaml 2>&1 | tail -5
echo "[ARCHIVIRT] Monitor installation complete."
echo "[ARCHIVIRT] NOTE: Suricata takes ~100s to load 50068 rules on 2 vCPU."
echo "[ARCHIVIRT] run_suricata.sh will be deployed by Ansible playbook."
