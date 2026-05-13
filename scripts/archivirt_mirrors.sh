#!/bin/bash
# ARCHIVIRT - Auto-detect and apply tc mirrors (fully dynamic, no hardcoded bridges)
# Author: Яснеманегре САВАДОГО (СПбГУПТД)
# Usage: sudo bash archivirt_mirrors.sh
set -euo pipefail

# ── Détecter dynamiquement l'interface monitor (ens4 = archivirt-net-targets) ──
MONITOR_VNET=$(sudo virsh domiflist archivirt-monitor-ids | grep targets | awk '{print $1}')
if [ -z "$MONITOR_VNET" ]; then
  echo "❌ ERREUR: impossible de détecter l'interface monitor (VM archivirt-monitor-ids éteinte?)"
  exit 1
fi
echo "Monitor vnet: $MONITOR_VNET"

# ── Détecter les bridges des réseaux targets et attack via virsh ──────────────
TARGETS_BRIDGE=$(sudo virsh net-info archivirt-net-targets | grep Bridge | awk '{print $2}')
ATTACK_BRIDGE=$(sudo virsh net-info archivirt-net-attack   | grep Bridge | awk '{print $2}')

echo "Bridges détectés: targets=$TARGETS_BRIDGE attack=$ATTACK_BRIDGE"

# ── Appliquer les mirrors sur tous les vnets des deux bridges ─────────────────
for BRIDGE in "$TARGETS_BRIDGE" "$ATTACK_BRIDGE"; do
  for VNET in $(bridge link show | grep "$BRIDGE" | awk '{print $2}' | tr -d ':'); do
    [ "$VNET" = "$MONITOR_VNET" ] && continue  # skip self-mirror
    sudo tc qdisc del dev "$VNET" ingress 2>/dev/null || true
    sudo tc qdisc add dev "$VNET" ingress
    sudo tc filter add dev "$VNET" parent ffff: \
      protocol all u32 match u8 0 0 \
      action mirred egress mirror dev "$MONITOR_VNET"
    echo "✅ Mirror: $VNET ($BRIDGE) -> $MONITOR_VNET"
  done
done
