#!/usr/bin/env bash
set -euo pipefail

# Endurance test runner — runs standalone integration tests repeatedly for 12 hours
# and keeps per-run logs with pass/fail tracking.
#
# Usage:
#   LATTICE_KUBECONFIG=$(pwd)/management-kubeconfig-ea1501 ./endurance-test.sh
#
# Options:
#   FAIL_FAST=1  — stop on first failure without cleaning up (default)
#   FAIL_FAST=0  — continue past failures for the full duration

FAIL_FAST=${FAIL_FAST:-1}
DURATION_HOURS=${DURATION_HOURS:-12}
DURATION_SECS=$((DURATION_HOURS * 3600))
LOG_DIR="endurance-logs"
mkdir -p "$LOG_DIR"

START_TIME=$(date +%s)
RUN=0
PASS=0
FAIL=0

echo "=== Endurance test starting at $(date) ==="
echo "=== Duration: ${DURATION_HOURS}h | Logs: ${LOG_DIR}/ ==="
echo ""

while true; do
    ELAPSED=$(( $(date +%s) - START_TIME ))
    if [ "$ELAPSED" -ge "$DURATION_SECS" ]; then
        break
    fi

    RUN=$((RUN + 1))
    REMAINING=$(( (DURATION_SECS - ELAPSED) / 60 ))
    LOG_FILE="${LOG_DIR}/run-$(printf '%04d' $RUN).log"

    echo "--- RUN ${RUN} | elapsed=$((ELAPSED/60))m remaining=${REMAINING}m | pass=${PASS} fail=${FAIL} ---"

    if cargo test --features provider-e2e --test e2e standalone -- --ignored --nocapture \
        > "$LOG_FILE" 2>&1; then
        PASS=$((PASS + 1))
        echo "    PASS (log: $LOG_FILE)"
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (log: $LOG_FILE)"
        grep -E "^failures:|FAILED|panicked" "$LOG_FILE" | head -5 || true
        if [ "$FAIL_FAST" = "1" ]; then
            echo ""
            echo "=== FAIL_FAST: stopping after first failure (clusters left for debugging) ==="
            echo "=== Runs: ${RUN} | Pass: ${PASS} | Fail: ${FAIL} ==="
            exit 1
        fi
    fi
done

TOTAL_ELAPSED=$(( $(date +%s) - START_TIME ))
echo ""
echo "=== Endurance test finished at $(date) ==="
echo "=== Runs: ${RUN} | Pass: ${PASS} | Fail: ${FAIL} | Duration: $((TOTAL_ELAPSED/60))m ==="
