#!/usr/bin/env bash
# capture.sh — sample Bob's CPU/memory from `docker stats` while the attack runs.
# Output: CSV (timestamp,cpu_pct,mem_usage) to stdout; redirect to a file.
#
# Usage: ./capture.sh <bob_container_name> [seconds] > stats.csv
set -euo pipefail

CONTAINER="${1:?usage: capture.sh <container> [seconds]}"
DURATION="${2:-60}"

echo "t,cpu_pct,mem"
end=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$end" ]; do
    line=$(docker stats --no-stream --format '{{.CPUPerc}},{{.MemUsage}}' "$CONTAINER")
    echo "$(date +%s),$line"
    sleep 1
done
