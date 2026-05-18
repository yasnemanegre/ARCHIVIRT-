#!/bin/bash
# =============================================================================
# ARCHIVIRT - Install and configure IDS packages on monitor VM
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 2.3.0 — 2026-05-19
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

# --- Configure local apt mirror as sole source -------------------------------
echo "deb [trusted=yes] $MIRROR ./" > /etc/apt/sources.list.d/archivirt-local.list

# Disable default Ubuntu sources to enforce local-only installs
echo "" > /etc/apt/sources.list

apt-get update \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  -o Dir::Etc::sourceparts="-" \
  -o APT::Get::List-Cleanup=0 -q 2>/dev/null

# --- Install IDS packages from local mirror ----------------------------------
apt-get install -y --no-install-recommends \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/archivirt-local.list \
  snort3 suricata suricata-update 2>&1 | tail -5

echo "[ARCHIVIRT] $(suricata --build-info 2>/dev/null | grep 'This is Suricata' || echo 'suricata OK')"
echo "[ARCHIVIRT] $(which suricata-update && echo 'suricata-update OK')"

# --- Download ET Open rules from local mirror --------------------------------
# Rules are pre-generated on host by scripts/update_et_rules.sh
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

# --- Validate final Suricata configuration -----------------------------------
echo "[ARCHIVIRT] Validating Suricata configuration ..."
suricata -T -c /etc/suricata/suricata.yaml 2>&1 | tail -5
echo "[ARCHIVIRT] Monitor installation complete."
