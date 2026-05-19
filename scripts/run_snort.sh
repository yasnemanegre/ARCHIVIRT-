#!/bin/bash
# =============================================================================
# ARCHIVIRT — Start/stop Snort 3 for a single scenario
# =============================================================================
# Author  : Yasnemanegre SAWADOGO (SPbGUPTD)
# License : MIT — https://github.com/yasnemanegre/ARCHIVIRT
# Version : 2.0.0 — 2026-05-19
#
# Usage:
#   sudo bash run_snort.sh start|stop SCENARIO_NAME [ids|ips]
#
# Uses deterministic trigger: polls log for "Snort successfully started"
# instead of fixed sleep — consistent with run_suricata.sh approach.
# =============================================================================

ACTION=$1
SCENARIO=${2:-default}
MODE=${3:-ids}

LOG_DIR=/var/log/snort3/${SCENARIO}
PID_FILE=${LOG_DIR}/snort.pid
CONFIG=/etc/snort3/snort.lua
IFACE=ens4
SNORT_BIN=/usr/local/bin/snort
READY_MSG="Snort successfully started"
READY_TIMEOUT=120

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 start|stop SCENARIO_NAME [ids|ips]"
    exit 1
fi

case $ACTION in
    start)
        mkdir -p "$LOG_DIR"
        touch "${LOG_DIR}/alert_fast.txt" "${LOG_DIR}/alert_json.txt"
        truncate -s 0 "${LOG_DIR}/snort_stdout.log" 2>/dev/null || true
        ip link set "$IFACE" up
        ip link set "$IFACE" promisc on

        echo "[ARCHIVIRT] Starting Snort 3 IDS (iface=$IFACE) for $SCENARIO ..."
        ${SNORT_BIN} -i "$IFACE" -c "$CONFIG" -l "$LOG_DIR" \
          >> "${LOG_DIR}/snort_stdout.log" 2>&1 &

        SNORT_PID=$!
        echo $SNORT_PID > "$PID_FILE"

        # Deterministic wait: poll log for ready message
        echo "[ARCHIVIRT] Waiting for Snort to start (max ${READY_TIMEOUT}s)..."
        WAITED=0
        while [ $WAITED -lt $READY_TIMEOUT ]; do
            sleep 2
            WAITED=$((WAITED + 2))

            if ! kill -0 $SNORT_PID 2>/dev/null; then
                echo "[ARCHIVIRT] ERROR: Snort process died after ${WAITED}s"
                tail -5 "${LOG_DIR}/snort_stdout.log"
                exit 1
            fi

            if grep -q "$READY_MSG" "${LOG_DIR}/snort_stdout.log" 2>/dev/null; then
                echo "[ARCHIVIRT] Snort ready after ${WAITED}s — PID=$SNORT_PID"
                exit 0
            fi
        done

        # Snort may not print ready message — check if process is alive
        if kill -0 $SNORT_PID 2>/dev/null; then
            echo "[ARCHIVIRT] Snort running PID=$SNORT_PID (no ready msg — proceeding)"
            exit 0
        fi

        echo "[ARCHIVIRT] ERROR: Snort failed to start within ${READY_TIMEOUT}s"
        tail -5 "${LOG_DIR}/snort_stdout.log"
        exit 1
        ;;

    stop)
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            echo "[ARCHIVIRT] Stopping Snort PID=$PID for $SCENARIO ..."
            kill -SIGINT "$PID" 2>/dev/null
            sleep 5
            kill -9 "$PID" 2>/dev/null || true
            rm -f "$PID_FILE"
        else
            echo "[ARCHIVIRT] No PID file for $SCENARIO — killing all snort"
            pkill -9 -f snort || true
        fi

        ALERTS=$(wc -l < "${LOG_DIR}/alert_fast.txt" 2>/dev/null || echo 0)
        echo "[ARCHIVIRT] Snort stopped. Alerts=$ALERTS"
        ;;

    *)
        echo "Invalid action. Use: start|stop"
        exit 1
        ;;
esac
