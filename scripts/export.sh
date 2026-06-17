#!/bin/bash
set -euo pipefail

# sniffer-rt air-gapped data export
# Mounts a USB device labeled SRT-EXPORT and copies report data to it.
# Usage: export.sh <device> (e.g., export.sh sda1)

DEVICE="${1:-}"
MOUNT="/media/srt-export"
REPORTS_DIR="/opt/sniffer/reports/out"
LOG_FILE="/var/log/srt-export.log"

log() {
    echo "$(date -Iseconds) [export] $*" >> "$LOG_FILE"
}

if [ -z "$DEVICE" ]; then
    log "ERROR: No device specified"
    echo "Usage: $0 <device>" >&2
    exit 1
fi

DEVICE_PATH="/dev/${DEVICE}"

if [ ! -b "$DEVICE_PATH" ]; then
    log "ERROR: Block device $DEVICE_PATH not found"
    exit 1
fi

log "Export started: device=$DEVICE_PATH"

# Create mount point
mkdir -p "$MOUNT"

# Mount the device
if ! mount "$DEVICE_PATH" "$MOUNT"; then
    log "ERROR: Failed to mount $DEVICE_PATH"
    exit 1
fi

# Copy reports
if [ -d "$REPORTS_DIR" ]; then
    cp -r "$REPORTS_DIR"/* "$MOUNT/" 2>/dev/null || true
    log "Reports copied to $MOUNT"
else
    log "WARNING: Reports directory $REPORTS_DIR not found"
fi

# Optionally copy latest DB dump if available
DB_DUMP="/opt/sniffer/data/db_dump_latest.sql"
if [ -f "$DB_DUMP" ]; then
    cp "$DB_DUMP" "$MOUNT/"
    log "DB dump copied"
fi

# Sync and unmount
sync
umount "$MOUNT"
rmdir "$MOUNT" 2>/dev/null || true

log "Export completed successfully"
