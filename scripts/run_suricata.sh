#!/bin/bash
# =============================================================================
# run_suricata.sh — Start/stop Suricata for a single ARCHIVIRT scenario
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 2.1.0 — 2026-05-18
#
# Usage:
#   sudo bash run_suricata.sh start|stop SCENARIO_NAME [ids|ips]
#
#   MODE argument is optional — defaults to "ids" for backward compatibility.
#   IDS mode : passive AF-PACKET capture (sniffer-only, no traffic blocking)
#   IPS mode : inline NFQ capture (traffic blocking via iptables NFQUEUE)
#
# NOTE: Suricata is configured via /etc/suricata/suricata.yaml
#       (workers mode + af-packet on ens4).
#       The -i option is still required by Suricata 6.0.4 for live capture.
# =============================================================================

ACTION=$1
SCENARIO=${2:-default}
MODE=${3:-ids}                   # optional: ids (default) or ips

LOG_DIR=/var/log/suricata/${SCENARIO}
PID_FILE=${LOG_DIR}/suricata.pid
CONFIG=/etc/suricata/suricata.yaml
IFACE=ens4                       # live capture interface (af-packet / promisc)
NFQ_QUEUE=0                      # NFQ queue number for IPS inline mode
SURICATA_BIN=/usr/bin/suricata

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 start|stop SCENARIO_NAME [ids|ips]"
    exit 1
fi

case $ACTION in
    start)
        mkdir -p "$LOG_DIR"
        ip link set "$IFACE" up
        ip link set "$IFACE" promisc on
        truncate -s 0 "${LOG_DIR}/eve.json" 2>/dev/null || true

        if [ "$MODE" = "ips" ]; then
            # IPS mode — inline NFQ: iptables routes traffic through Suricata
            echo "[ARCHIVIRT] Starting Suricata IPS (NFQ queue=$NFQ_QUEUE) for $SCENARIO ..."
            iptables -I FORWARD -j NFQUEUE --queue-num $NFQ_QUEUE 2>/dev/null || true
            "$SURICATA_BIN" -c "$CONFIG" -q "$NFQ_QUEUE" -l "$LOG_DIR" \
                > "${LOG_DIR}/suricata_stdout.log" 2>&1 &
        else
            # IDS mode — passive AF-PACKET sniffer (default)
            echo "[ARCHIVIRT] Starting Suricata IDS (AF-PACKET, iface=$IFACE) for $SCENARIO ..."
            "$SURICATA_BIN" -c "$CONFIG" -i "$IFACE" -l "$LOG_DIR" \
                > "${LOG_DIR}/suricata_stdout.log" 2>&1 &
        fi

        SURICATA_PID=$!
        echo $SURICATA_PID > "$PID_FILE"
        sleep 10

        if kill -0 $SURICATA_PID 2>/dev/null; then
            echo "[ARCHIVIRT] Suricata running PID=$SURICATA_PID mode=$MODE logs=$LOG_DIR"
        else
            echo "[ARCHIVIRT] ERROR: Suricata failed to start"
            tail -5 "${LOG_DIR}/suricata_stdout.log"
            exit 1
        fi
        ;;

    stop)
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            echo "[ARCHIVIRT] Stopping Suricata PID=$PID for $SCENARIO ..."
            kill -SIGINT "$PID" 2>/dev/null
            sleep 8
            kill -9 "$PID" 2>/dev/null || true
            rm -f "$PID_FILE"
        else
            echo "[ARCHIVIRT] No PID file for $SCENARIO — killing all suricata"
            pkill -9 -f suricata || true
        fi

        # Remove NFQ iptables rule if IPS mode was active
        iptables -D FORWARD -j NFQUEUE --queue-num $NFQ_QUEUE 2>/dev/null || true

        ALERTS=$(grep -c '"event_type":"alert"' "${LOG_DIR}/eve.json" 2>/dev/null || echo 0)
        echo "[ARCHIVIRT] Suricata stopped. Mode=$MODE Alerts=$ALERTS"
        ;;

    *)
        echo "Invalid action. Use: start|stop"
        exit 1
        ;;
esac
