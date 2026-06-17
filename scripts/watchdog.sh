#!/bin/bash
set -euo pipefail

# sniffer-rt hardware watchdog
# Monitors HackRF health, disk space, and tamper GPIO pin.

PROBE_SERVICE="srt-probe.service"
DATA_DIR="/opt/sniffer/data"
TAMPER_GPIO=17
MAX_DISK_PERCENT=90
CAPTURE_RETENTION_DAYS=7
LOG_FILE="/var/log/srt-watchdog.log"

log() {
    echo "$(date -Iseconds) [watchdog] $*" >> "$LOG_FILE"
}

log "Watchdog started"

# Export tamper GPIO if not already exported
if [ ! -d "/sys/class/gpio/gpio${TAMPER_GPIO}" ]; then
    echo "$TAMPER_GPIO" > /sys/class/gpio/export 2>/dev/null || true
    sleep 0.1
    echo "in" > "/sys/class/gpio/gpio${TAMPER_GPIO}/direction" 2>/dev/null || true
fi

while true; do
    # --- Check HackRF ---
    if ! hackrf_info &>/dev/null; then
        log "ERROR: HackRF not detected, restarting $PROBE_SERVICE"
        systemctl restart "$PROBE_SERVICE" || true
        sleep 60
        continue
    fi

    # --- Check disk space ---
    if [ -d "$DATA_DIR" ]; then
        USED=$(df "$DATA_DIR" | awk 'NR==2{print $5}' | tr -d '%')
        if [ "$USED" -gt "$MAX_DISK_PERCENT" ]; then
            log "WARNING: Disk usage at ${USED}%, rotating old captures"
            find "$DATA_DIR" -name "*.cfile" -mtime +"$CAPTURE_RETENTION_DAYS" -delete 2>/dev/null || true
            find "$DATA_DIR" -name "*.raw" -mtime +"$CAPTURE_RETENTION_DAYS" -delete 2>/dev/null || true
        fi
    fi

    # --- Check tamper GPIO ---
    if [ -f "/sys/class/gpio/gpio${TAMPER_GPIO}/value" ]; then
        TAMPER_STATE=$(cat "/sys/class/gpio/gpio${TAMPER_GPIO}/value")
        if [ "$TAMPER_STATE" = "1" ]; then
            log "CRITICAL: Tamper detected on GPIO ${TAMPER_GPIO}! Initiating emergency wipe."
            # Shred sensitive files
            find /opt/sniffer -name "*.key" -exec shred -u {} \; 2>/dev/null || true
            find /opt/sniffer -name "*.pem" -exec shred -u {} \; 2>/dev/null || true
            shred -u /opt/sniffer/.env 2>/dev/null || true
            # Stop probe service
            systemctl stop "$PROBE_SERVICE" 2>/dev/null || true
            # Close LUKS volumes
            for dm in $(ls /dev/mapper/luks-* 2>/dev/null); do
                cryptsetup close "$(basename "$dm")" 2>/dev/null || true
            done
            # Power off immediately
            log "Emergency shutdown initiated"
            sync
            poweroff
        fi
    fi

    # --- Log health status ---
    log "OK: HackRF present, disk=${USED:-?}%, tamper=clear"

    sleep 30
done
