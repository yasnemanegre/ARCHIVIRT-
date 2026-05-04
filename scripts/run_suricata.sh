#!/bin/bash
# run_suricata.sh - Start/stop Suricata for a single scenario (ARCHIVIRT IaC pipeline)
# Author: Yasnemanegre SAWADOGO (SPbGUPTD)
# Usage: sudo bash run_suricata.sh start|stop SCENARIO_NAME

ACTION=$1
SCENARIO=${2:-default}
LOG_DIR=/var/log/suricata/${SCENARIO}
PID_FILE=${LOG_DIR}/suricata.pid
CONFIG=/etc/suricata/suricata.yaml
IFACE=ens4
SURICATA_BIN=/usr/bin/suricata

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 start|stop SCENARIO_NAME"
    exit 1
fi

case $ACTION in
    start)
        mkdir -p "$LOG_DIR"
        ip link set "$IFACE" up
        ip link set "$IFACE" promisc on
        truncate -s 0 "${LOG_DIR}/eve.json" 2>/dev/null || true
        echo "[ARCHIVIRT] Starting Suricata on $IFACE for $SCENARIO ..."
        "$SURICATA_BIN" -c "$CONFIG" -i "$IFACE" -l "$LOG_DIR" --runmode autofp \
            > "${LOG_DIR}/suricata_stdout.log" 2>&1 &
        SURICATA_PID=$!
        echo $SURICATA_PID > "$PID_FILE"
        sleep 10
        if kill -0 $SURICATA_PID 2>/dev/null; then
            echo "[ARCHIVIRT] Suricata running PID=$SURICATA_PID logs=$LOG_DIR"
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
            ALERTS=$(grep -c '"event_type":"alert"' "${LOG_DIR}/eve.json" 2>/dev/null || echo 0)
            echo "[ARCHIVIRT] Suricata stopped. Alerts: $ALERTS"
        else
            echo "[ARCHIVIRT] No PID file for $SCENARIO — killing all suricata"
            pkill -9 -f suricata || true
            ALERTS=$(grep -c '"event_type":"alert"' "${LOG_DIR}/eve.json" 2>/dev/null || echo 0)
            echo "[ARCHIVIRT] Alerts: $ALERTS"
        fi
        ;;
    *)
        echo "Invalid action. Use: start|stop"
        exit 1
        ;;
esac
