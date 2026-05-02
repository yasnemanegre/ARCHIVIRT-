#!/bin/bash
# ARCHIVIRT - Metrics Collection Script
# Collects CPU, RAM, latency during IDS testing

IDS=$1  # "suricata" or "snort"
MONITOR_IP="10.0.3.10"
KEY="$HOME/.ssh/archivirt_key"

echo "=== Collecting metrics for $IDS ==="

# 1. CPU and RAM usage during test
ssh -i $KEY -o StrictHostKeyChecking=no ubuntu@$MONITOR_IP \
  "top -bn3 | grep -E 'suricata|snort' | awk '{print \"CPU: \"\$9\"% RAM: \"\$10\"%\"}'"

# 2. Memory in MB
ssh -i $KEY -o StrictHostKeyChecking=no ubuntu@$MONITOR_IP \
  "ps aux | grep -E 'suricata|snort' | grep -v grep | awk '{print \"RAM MB: \"\$6/1024}'"
