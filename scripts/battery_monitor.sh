#!/bin/bash
set -euo pipefail

# sniffer-rt battery monitor
# Monitors power supply voltage/capacity and triggers graceful shutdown
# when battery level is critically low.

CRITICAL_VOLTAGE=3200000   # 3.2V in microvolts
CRITICAL_CAPACITY=10       # 10% remaining
CHECK_INTERVAL=60          # seconds between checks
LOG_FILE="/var/log/srt-battery.log"

log() {
    echo "$(date -Iseconds) [battery] $*" >> "$LOG_FILE"
}

graceful_shutdown() {
    log "CRITICAL: Low battery detected - initiating graceful shutdown"

    # Save final report if srt is available
    if command -v /opt/sniffer/.venv/bin/srt &>/dev/null; then
        /opt/sniffer/.venv/bin/srt report --session-id current --format json \
            --output /opt/sniffer/reports/out/emergency_shutdown_report.json 2>/dev/null || true
        log "Final report saved"
    fi

    sync
    log "Powering off due to low battery"
    poweroff
}

log "Battery monitor started"

while true; do
    # Check voltage_now from any power supply
    for ps_dir in /sys/class/power_supply/*/; do
        if [ ! -d "$ps_dir" ]; then
            continue
        fi

        # Check voltage
        if [ -f "${ps_dir}voltage_now" ]; then
            VOLTAGE=$(cat "${ps_dir}voltage_now" 2>/dev/null || echo "0")
            if [ "$VOLTAGE" -gt 0 ] && [ "$VOLTAGE" -lt "$CRITICAL_VOLTAGE" ]; then
                log "LOW BATTERY: voltage=${VOLTAGE}uV (threshold=${CRITICAL_VOLTAGE}uV)"
                graceful_shutdown
            fi
        fi

        # Check capacity percentage
        if [ -f "${ps_dir}capacity" ]; then
            CAPACITY=$(cat "${ps_dir}capacity" 2>/dev/null || echo "100")
            if [ "$CAPACITY" -lt "$CRITICAL_CAPACITY" ]; then
                log "LOW BATTERY: capacity=${CAPACITY}% (threshold=${CRITICAL_CAPACITY}%)"
                graceful_shutdown
            fi
        fi
    done

    sleep "$CHECK_INTERVAL"
done
