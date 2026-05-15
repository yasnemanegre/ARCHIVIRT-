#!/bin/bash
ACTION=$1
SCENARIO=${2:-default}
LOG_DIR=/var/log/snort3/${SCENARIO}
PID_FILE=${LOG_DIR}/snort.pid
CONFIG=/etc/snort3/snort.lua
IFACE=ens4
SNORT_BIN=/usr/local/bin/snort

case $ACTION in
    start)
        mkdir -p "$LOG_DIR"
        touch "${LOG_DIR}/alert_fast.txt" "${LOG_DIR}/alert_json.txt"
        ip link set "$IFACE" promisc on
        echo "[ARCHIVIRT] Starting Snort 3 on $IFACE for $SCENARIO ..."
        ${SNORT_BIN} -i "$IFACE" -c "$CONFIG" -l "$LOG_DIR" \
          >> "${LOG_DIR}/snort_stdout.log" 2>&1 &
        SNORT_PID=$!
        echo $SNORT_PID > "$PID_FILE"
        sleep 5
        if ps -p $SNORT_PID > /dev/null 2>&1; then
            echo "[ARCHIVIRT] Snort3 running PID=$SNORT_PID logs=$LOG_DIR"
        else
            echo "[ARCHIVIRT] ERROR: Snort3 failed to start"
            tail -5 "${LOG_DIR}/snort_stdout.log"
            exit 1
        fi
        ;;
    stop)
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            kill -SIGINT "$PID" 2>/dev/null
            sleep 5
            kill -9 "$PID" 2>/dev/null || true
            rm -f "$PID_FILE"
            ALERTS=$(wc -l < "${LOG_DIR}/alert_fast.txt" 2>/dev/null || echo 0)
            echo "[ARCHIVIRT] Snort3 stopped. Alerts: $ALERTS"
        else
            echo "[ARCHIVIRT] No PID file for $SCENARIO — killing all snort"
            pkill -9 -f snort || true
        fi
        ;;
esac
