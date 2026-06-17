# Deployment Guide

Instructions for deploying sniffer-rt to a Raspberry Pi for production or field use.

---

## Prerequisites

### Hardware

- **Raspberry Pi 5** (4 GB RAM minimum, 8 GB recommended)
- **NVMe SSD** via M.2 HAT (recommended for capture storage; SD card is too slow)
- **ALFA AWUS036ACH** plugged into USB 2.0 port
- **HackRF One** plugged into USB 2.0 port
- **Official 27W USB-C power supply** (5V / 5A)
- Ethernet cable for initial setup (or WiFi on wlan0 for management)

### Software

- **Raspberry Pi OS Bookworm 64-bit Lite** flashed to NVMe/SD
- SSH enabled
- Network connectivity for initial package installation

### On Your Development PC

- Project passes `python run_all_tests.py --dry-run`
- SSH key configured for passwordless access to the Pi

---

## Automated Deployment

The `deploy_to_pi.sh` script handles the full deployment:

```bash
# Basic usage
./deploy_to_pi.sh pi@192.168.1.100 pi ~/.ssh/id_rsa

# With explicit port and remote directory
./deploy_to_pi.sh --port 22 --remote-dir /opt/sniffer pi@192.168.1.50 srt

# Dry-run (show what would happen without executing)
./deploy_to_pi.sh --dry-run pi@raspberrypi.local pi
```

### What the Script Does

1. Runs local dry-run tests to validate the project
2. rsyncs project files to the Pi (excluding `.venv`, `.git`, `__pycache__`)
3. SSHs to the Pi and runs `deploy/setup.sh`
4. Creates a Python virtual environment on the Pi
5. Installs the package with `pip install -e ".[dev,ble,report]"`
6. Installs udev rules for HackRF and ALFA
7. Installs and enables systemd services
8. Runs `srt selftest` on the Pi to verify

### Script Options

```
Usage: deploy_to_pi.sh [OPTIONS] <pi-host> <pi-user> [ssh-key-path]

Options:
  --dry-run        Show commands without executing
  --port PORT      SSH port (default: 2222)
  --remote-dir DIR Remote installation directory (default: /opt/sniffer)
  --help           Show usage information
```

---

## Post-Deployment Verification

### Check Services

```bash
# SSH to the Pi
ssh pi@192.168.1.100

# Check all sniffer-rt services
systemctl status srt-infra srt-probe srt-watchdog

# Expected output for each:
#   Active: active (running)
```

### Run Self-Test

```bash
srt selftest
# Should report all hardware detected and modules loaded
```

### Access Grafana

Open a browser to:

```
http://<pi-ip>:3000
```

Default credentials: `admin` / `admin` (change on first login)

Dashboards available:
- RF Activity Overview
- WiFi Audit Results
- BLE Device Tracking
- LoRa Traffic Analysis
- System Health

### Test a Scenario

```bash
# Dry-run a scenario to verify configuration
srt scenario scenarios/wifi_full_audit.yaml --dry-run

# Run for real (requires hardware and whitelisted targets)
sudo srt scenario scenarios/wifi_full_audit.yaml
```

---

## Autonomous Operation

### Scenario Loop Mode

For continuous operation, run a scenario in loop mode:

```bash
sudo srt scenario scenarios/wifi_full_audit.yaml --loop --interval 300
```

This runs the scenario repeatedly with a 5-minute pause between iterations. Results are stored in TimescaleDB and visible on Grafana dashboards.

### Systemd Services

Three services manage autonomous operation:

| Service | Purpose |
|---------|---------|
| `srt-infra` | Docker compose stack (TimescaleDB, Grafana, Mosquitto) |
| `srt-probe` | Main scanning/attack orchestrator |
| `srt-watchdog` | Hardware health monitoring and auto-recovery |

Control them with:

```bash
sudo systemctl start srt-probe
sudo systemctl stop srt-probe
sudo systemctl restart srt-probe
journalctl -u srt-probe -f   # Follow logs
```

### Watchdog

The watchdog service monitors:
- USB device connectivity (ALFA, HackRF)
- Bluetooth adapter state
- Disk space usage
- CPU temperature (throttling prevention)
- Service health

If hardware disconnects, the watchdog logs an alert and attempts recovery (interface reset, USB rebind).

### Battery Monitor (Portable Operation)

If running on portable power (USB power bank or battery HAT):

```bash
# Check power status
vcgencmd get_throttled
# 0x0 = no issues
# 0x1 = undervoltage detected (increase supply current)
```

The watchdog will trigger a graceful shutdown if voltage drops below safe levels (configurable in hardware.yaml).

---

## Data Extraction

### USB Export

If configured with udev rules (see `deploy/udev/99-srt-export.rules`):

1. Plug in a USB flash drive
2. The system auto-mounts and exports captured data
3. Remove the drive when the LED stops blinking

### SCP Transfer

```bash
# Copy reports from Pi to your PC
scp -r pi@192.168.1.100:/opt/sniffer/reports/ ./reports/

# Copy database dump
ssh pi@192.168.1.100 "docker exec srt-timescaledb pg_dump -U srt srt_db" > srt_backup.sql

# Copy raw captures
scp pi@192.168.1.100:/opt/sniffer/captures/*.pcap ./captures/
```

### MQTT Streaming

For real-time data access, subscribe to the MQTT broker:

```bash
mosquitto_sub -h <pi-ip> -p 1883 -t "srt/#"
```

---

## Updating the Deployment

### Code Update (No Dependency Changes)

```bash
# From your development PC
rsync -avz --exclude .venv --exclude .git --exclude __pycache__ \
    src/ pi@192.168.1.100:/opt/sniffer/src/

# Restart the probe service
ssh pi@192.168.1.100 "sudo systemctl restart srt-probe"
```

### Full Update (With Dependency Changes)

```bash
# Re-run the deploy script
./deploy_to_pi.sh pi@192.168.1.100 pi ~/.ssh/id_rsa
```

### Configuration Update

```bash
# Sync config files
rsync -avz config/ pi@192.168.1.100:/opt/sniffer/config/
rsync -avz safety/ pi@192.168.1.100:/opt/sniffer/safety/
rsync -avz scenarios/ pi@192.168.1.100:/opt/sniffer/scenarios/

# Restart to pick up changes
ssh pi@192.168.1.100 "sudo systemctl restart srt-probe"
```

---

## Security Considerations

- The Pi stores authorized attack tools; secure physical access
- Use LUKS full-disk encryption for the NVMe SSD (see `deploy/luks/README.md`)
- Disable password SSH login; use key-based authentication only
- Change default Grafana credentials immediately
- The `srt` user group has restricted hardware access via udev rules
- Logs contain target MAC addresses; handle as sensitive data
