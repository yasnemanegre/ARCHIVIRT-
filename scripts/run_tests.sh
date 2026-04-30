#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ARCHIVIRT — Test Scenario Runner
# Author: Яснеманегре САВАДОГО (Аспирант СПБГУПТД)
#
# Executes all 5 test scenarios × 10 runs each.
# Logs are saved to logs/run_YYYYMMDD_HHMMSS/
# ─────────────────────────────────────────────────────────────

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SCENARIOS_DIR="$ROOT_DIR/scenarios"

ATTACKER_IP="10.0.4.10"
MONITOR_IP="10.0.3.10"
MANAGER_IP="10.0.5.10"
SSH_KEY="$HOME/.ssh/archivirt_key"
SSH_OPTS="-o StrictHostKeyChecking=no -i $SSH_KEY"

# ── Defaults ─────────────────────────────────────────────────
RUNS=10
IDS_ENGINE="${IDS_ENGINE:-suricata}"
RUN_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$ROOT_DIR/logs/run_$RUN_TIMESTAMP"
METRICS_FILE="$LOG_DIR/metrics_raw.json"

log()   { echo -e "${GREEN}[ARCHIVIRT]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
step()  { echo -e "\n${CYAN}── $* ──${NC}"; }
ok()    { echo -e "  ${GREEN}✓${NC} $*"; }
fail()  { echo -e "  ${RED}✗${NC} $*"; }

mkdir -p "$LOG_DIR"

# ── Helper: SSH command on remote host ────────────────────────
remote() {
    local host="$1"; shift
    ssh $SSH_OPTS ubuntu@"$host" "$@" 2>/dev/null
}

# ── Helper: collect IDS alert count ──────────────────────────
collect_alert_count() {
    local ids_host="$MONITOR_IP"
    if [[ "$IDS_ENGINE" == "snort" ]]; then
        remote "$ids_host" "wc -l < /var/log/snort/alert_fast.txt" 2>/dev/null || echo "0"
    else
        remote "$ids_host" "wc -l < /var/log/suricata/fast.log" 2>/dev/null || echo "0"
    fi
}

# ── Helper: clear IDS logs between runs ──────────────────────
clear_ids_logs() {
    if [[ "$IDS_ENGINE" == "snort" ]]; then
        remote "$MONITOR_IP" "sudo truncate -s 0 /var/log/snort/alert_fast.txt" || true
    else
        remote "$MONITOR_IP" "sudo truncate -s 0 /var/log/suricata/fast.log" || true
    fi
}

# ── Helper: collect resource usage ───────────────────────────
collect_resources() {
    local host="$1"
    local cpu ram
    cpu=$(remote "$host" "top -bn1 | grep 'Cpu(s)' | awk '{print \$2}'" | tr -d '%us,')
    ram=$(remote "$host" "free -m | awk 'NR==2{print \$3}'")
    echo "{\"cpu\": $cpu, \"ram\": $ram}"
}

# ── Scenario execution ────────────────────────────────────────
run_scenario() {
    local scenario_id="$1"
    local scenario_name="$2"
    local command="$3"
    local run_num="$4"
    local scenario_log="$LOG_DIR/scenario_${scenario_id}_run${run_num}.log"

    local start_ts
    start_ts=$(date +%s%3N)

    # Clear IDS logs before run
    clear_ids_logs

    # Record alerts before
    local alerts_before
    alerts_before=$(collect_alert_count)

    # Execute attack command on attacker VM
    remote "$ATTACKER_IP" "$command" > "$scenario_log" 2>&1 || true

    # Record timing
    local end_ts
    end_ts=$(date +%s%3N)
    local latency_ms=$((end_ts - start_ts))

    # Sleep briefly to allow IDS to process
    sleep 2

    # Record alerts after
    local alerts_after
    alerts_after=$(collect_alert_count)
    local new_alerts=$((alerts_after - alerts_before))

    # Collect resource metrics from monitor VM
    local resources
    resources=$(collect_resources "$MONITOR_IP")

    echo "{\"scenario_id\": \"$scenario_id\", \"scenario_name\": \"$scenario_name\", \"run\": $run_num, \"alerts_triggered\": $new_alerts, \"latency_ms\": $latency_ms, \"resources\": $resources, \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
}

# ── Scenarios definition ──────────────────────────────────────
declare -A SCENARIO_CMDS
SCENARIO_CMDS["SCN-001"]="nmap -sS -T4 -p 1-1000 10.0.2.0/24"
SCENARIO_CMDS["SCN-002"]="hydra -l testuser -P /opt/archivirt/wordlists/passwords.txt ssh://10.0.2.12 -t 4 -w 5 -f 2>/dev/null; true"
SCENARIO_CMDS["SCN-003"]="sqlmap -u 'http://10.0.2.11/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit' --batch --level=2 --technique=BU --dbms=mysql -q 2>/dev/null; true"
SCENARIO_CMDS["SCN-004"]="python3 /opt/archivirt/attack-scripts/slowloris.py 10.0.2.11 --port 80 --sockets 100 --duration 30"
SCENARIO_CMDS["SCN-005"]="python3 /opt/archivirt/attack-scripts/normal_traffic.py 10.0.2.11 --duration 30"

declare -A SCENARIO_NAMES
SCENARIO_NAMES["SCN-001"]="Port Scan (Nmap)"
SCENARIO_NAMES["SCN-002"]="SSH Brute-force (Hydra)"
SCENARIO_NAMES["SCN-003"]="SQLi Exploit (sqlmap)"
SCENARIO_NAMES["SCN-004"]="Slowloris DDoS"
SCENARIO_NAMES["SCN-005"]="Normal Traffic Baseline"

# ── Main execution ────────────────────────────────────────────
main() {
    echo -e "${CYAN}════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  ARCHIVIRT — Test Campaign Runner${NC}"
    echo -e "  IDS Engine   : $IDS_ENGINE"
    echo -e "  Runs per test: $RUNS"
    echo -e "  Log dir      : $LOG_DIR"
    echo -e "${CYAN}════════════════════════════════════════════${NC}\n"

    # Initialize metrics JSON array
    echo "[" > "$METRICS_FILE"
    local first_entry=true

    for scenario_id in "SCN-001" "SCN-002" "SCN-003" "SCN-004" "SCN-005"; do
        scenario_name="${SCENARIO_NAMES[$scenario_id]}"
        step "Scenario $scenario_id: $scenario_name"

        for run in $(seq 1 "$RUNS"); do
            echo -n "  Run $run/$RUNS ... "
            local start
            start=$(date +%s)

            local result
            result=$(run_scenario \
                "$scenario_id" \
                "$scenario_name" \
                "${SCENARIO_CMDS[$scenario_id]}" \
                "$run")

            local elapsed=$(( $(date +%s) - start ))
            local alerts
            alerts=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['alerts_triggered'])")

            if [[ "$alerts" -gt 0 ]]; then
                ok "DETECTED ($alerts alerts) [${elapsed}s]"
            else
                fail "NOT DETECTED [${elapsed}s]"
            fi

            # Append to metrics file
            if [[ "$first_entry" == false ]]; then
                echo "," >> "$METRICS_FILE"
            fi
            echo "$result" >> "$METRICS_FILE"
            first_entry=false

            # Brief pause between runs
            sleep 3
        done

        echo ""
    done

    echo "]" >> "$METRICS_FILE"

    step "Test campaign complete"
    log "Raw metrics: $METRICS_FILE"
    log "Run: python3 scripts/collect_metrics.py --run-dir $LOG_DIR"
    log "Run: python3 scripts/generate_report.py --metrics $METRICS_FILE"
}

main "$@"
