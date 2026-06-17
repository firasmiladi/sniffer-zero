# Troubleshooting Guide

Common problems and solutions for the sniffer-rt platform, organized by category.

---

## Hardware Issues

### ALFA Adapter Not Detected

**Symptom:** `lsusb` does not show the Realtek device; `ip link` shows no wlan1.

**Cause:** Driver not installed, USB power insufficient, or adapter not plugged in properly.

**Solution:**
```bash
# 1. Check USB connection
lsusb | grep -i realtek
# Should show: 0bda:8812 or 0bda:881a

# 2. If not visible, try a different USB port or powered hub
# ALFA draws ~500mA; unpowered hubs may not supply enough

# 3. Check kernel messages
dmesg | tail -20 | grep -i rtl

# 4. Reinstall driver
sudo apt install -y realtek-rtl88xxau-dkms
sudo modprobe 88XXau
```

---

### Monitor Mode Fails

**Symptom:** `airmon-ng start wlan1` fails or interface stays in managed mode.

**Cause:** Conflicting processes holding the interface, or wrong driver loaded.

**Solution:**
```bash
# 1. Kill interfering processes
sudo airmon-ng check kill
# This stops NetworkManager, wpa_supplicant, etc.

# 2. Try again
sudo airmon-ng start wlan1

# 3. If that fails, try iw directly
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up

# 4. Verify
iw dev wlan1 info | grep type
# Should show: type monitor

# 5. If "wrong driver" - check which module is loaded
lsmod | grep rtl
# If rtl8xxxu is loaded instead of 88XXau:
sudo rmmod rtl8xxxu
echo "blacklist rtl8xxxu" | sudo tee /etc/modprobe.d/rtl8xxxu.conf
sudo modprobe 88XXau
```

---

### TX Power Low / Limited Range

**Symptom:** Cannot capture frames from APs more than a few meters away.

**Cause:** Regulatory domain limiting TX power, or antenna not connected.

**Solution:**
```bash
# Check current regulatory domain
iw reg get

# Set to a permissive region (lab use only)
sudo iw reg set US

# Check TX power
iwconfig wlan1mon | grep "Tx-Power"

# Set maximum power (if permitted by your region)
sudo iwconfig wlan1mon txpower 30
```

---

### HackRF Not Found

**Symptom:** `hackrf_info` returns "No HackRF boards found."

**Cause:** Firmware issue, USB connection problem, or permission denied.

**Solution:**
```bash
# 1. Check USB connection
lsusb | grep -i "1d50:6089"
# Should show: Great Scott Gadgets HackRF One

# 2. If visible in lsusb but hackrf_info fails, check permissions
ls -la /dev/bus/usb/*/$(lsusb | grep 1d50:6089 | awk '{print $4}' | tr -d ':')
# Add udev rule if needed:
sudo cp deploy/udev/99-srt-export.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
# Replug the device

# 3. Try USB 2.0 port (USB 3.0 can cause interference)

# 4. Update firmware if version is outdated
hackrf_spiflash -w /usr/share/hackrf/hackrf_one_usb.bin
# Replug after flashing
```

---

### HackRF USB Errors / Overflows

**Symptom:** `hackrf_transfer` reports USB transfer errors or sample overflows.

**Cause:** USB bandwidth saturation, especially with other USB devices active.

**Solution:**
```bash
# 1. Reduce sample rate
# Default 20 Msps may be too high with other USB devices
# Try 10 Msps or lower for the specific use case

# 2. Use a dedicated USB bus (not sharing with ALFA)
# On Pi 5: USB ports on opposite sides use different controllers

# 3. Check for USB 3.0 RFI
# If using 2.4 GHz, keep HackRF away from USB 3.0 cables/ports

# 4. Use shorter USB cable (under 50cm)
```

---

### BLE Scan Returns Empty

**Symptom:** `hcitool lescan` or BLE modules find no devices.

**Cause:** Bluetooth service not running, adapter in classic-only mode, or no BLE devices nearby.

**Solution:**
```bash
# 1. Check adapter state
hciconfig hci0
# If DOWN: sudo hciconfig hci0 up

# 2. Restart bluetooth service
sudo systemctl restart bluetooth

# 3. Enable LE mode
sudo btmgmt le on

# 4. Reset the adapter
sudo hciconfig hci0 reset

# 5. Verify with a basic scan
sudo hcitool lescan --duplicates
# Should show nearby BLE devices within 5 seconds
# If still empty, confirm BLE devices are advertising nearby
```

---

## Software Issues

### Module Refuses to Run

**Symptom:** `srt run wifi.krack ...` outputs "REFUSED" without performing the attack.

**Cause:** Authorization or whitelist check failed.

**Solution:**
```bash
# 1. Check whitelist
cat safety/whitelist.yaml
# Ensure your target BSSID is listed under wifi_bssid

# 2. Check authorization
cat authorization/authorization.yaml
# Ensure start_date/end_date cover today
# Ensure authorization is signed (authorized_by field populated)

# 3. Check interface
iwconfig
# Ensure the monitor mode interface exists and is up

# 4. Run with dry-run to see detailed refusal reason
srt run wifi.krack --target AA:BB:CC:DD:EE:FF --dry-run
```

---

### Database Unreachable

**Symptom:** Modules fail with "connection refused" on port 5432, or Grafana shows "No data."

**Cause:** Docker containers not running, or port conflict.

**Solution:**
```bash
# 1. Check Docker containers
docker compose -f infra/docker-compose.yml ps
# All should show "Up"

# 2. If containers are down, start them
docker compose -f infra/docker-compose.yml up -d

# 3. Check for port conflicts
ss -tlnp | grep -E "5432|3000|1883"
# If another service uses the port, stop it or change the compose port mapping

# 4. Verify database connectivity
docker exec srt-timescaledb pg_isready -U srt
# Should output: accepting connections

# 5. Check Docker logs for errors
docker compose -f infra/docker-compose.yml logs timescaledb
```

---

### Permission Denied Errors

**Symptom:** Commands fail with "Operation not permitted" or "Permission denied."

**Cause:** Not running as root, or udev rules not loaded.

**Solution:**
```bash
# 1. Most hardware operations require root
sudo srt run wifi.krack ...

# 2. Install udev rules for non-root access
sudo cp deploy/udev/99-srt-export.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger

# 3. Add user to required groups
sudo usermod -aG srt,bluetooth,docker $USER
# Logout and login for group changes to take effect

# 4. Verify group membership
groups
# Should include: srt bluetooth docker
```

---

### Import Errors / Missing Dependencies

**Symptom:** `ModuleNotFoundError: No module named 'scapy'` or similar.

**Cause:** Virtual environment not activated, or package not installed.

**Solution:**
```bash
# 1. Activate the virtual environment
source .venv/bin/activate

# 2. Verify the package is installed
pip list | grep scapy

# 3. Reinstall if missing
pip install -e ".[dev,ble,report]"

# 4. Verify PYTHONPATH includes src/
echo $PYTHONPATH
# Or run from project root with correct path
python -c "import srt; print(srt.__file__)"
```

---

## Performance Issues

### Raspberry Pi Overheating / Throttling

**Symptom:** Operations slow down, CPU frequency drops, or `vcgencmd` reports throttling.

**Cause:** Sustained CPU load without adequate cooling.

**Solution:**
```bash
# 1. Check current throttle state
vcgencmd get_throttled
# 0x0 = OK
# 0x4 = throttled now
# 0x80000 = soft temperature limit reached

# 2. Check temperature
vcgencmd measure_temp
# Throttling starts at 80C, shutdown at 85C

# 3. Mitigations:
# - Install active cooling (fan) on the Pi 5
# - Add heat sinks to SoC and RAM
# - Reduce USB device polling rate
# - If in an enclosure, ensure ventilation holes

# 4. Lower CPU frequency cap if cooling is not possible
echo "arm_freq=1800" | sudo tee -a /boot/firmware/config.txt
sudo reboot
```

---

### USB Bandwidth Saturation

**Symptom:** Sample drops from HackRF, ALFA disconnects briefly, or USB errors in `dmesg`.

**Cause:** All devices sharing a single USB controller exceed bandwidth.

**Solution:**
```bash
# 1. Check USB topology
lsusb -t
# Look for devices sharing the same bus/hub

# 2. Distribute devices across controllers
# Pi 5 has two USB 3.0 and two USB 2.0 ports on different controllers
# Put HackRF and ALFA on separate controllers

# 3. Reduce HackRF sample rate if not needed
# 20 Msps = 40 MB/s; 8 Msps = 16 MB/s

# 4. Check for errors
dmesg | grep -i "usb\|xhci" | tail -20
```

---

### Disk Full (Captures)

**Symptom:** Capture commands fail, database stops accepting writes.

**Cause:** PCAP captures or database WAL files filling the disk.

**Solution:**
```bash
# 1. Check disk usage
df -h /opt/sniffer
du -sh /opt/sniffer/captures/

# 2. Remove old captures
find /opt/sniffer/captures -name "*.pcap" -mtime +7 -delete

# 3. Compact database
docker exec srt-timescaledb psql -U srt -d srt_db -c "VACUUM FULL;"

# 4. Configure retention policy (already set in TimescaleDB)
# Default: 30 days. Adjust in infra/timescaledb/init/03_retention.sql

# 5. Use NVMe SSD instead of SD card for more capacity
```

---

## Network Issues

### No WiFi Frames Captured

**Symptom:** Scanning shows no APs or clients despite being in range.

**Cause:** Wrong channel, interface not in monitor mode, or interference.

**Solution:**
```bash
# 1. Verify monitor mode is active
iwconfig wlan1mon
# Mode must show "Monitor"

# 2. Set to correct channel
sudo iwconfig wlan1mon channel 6
# Or hop channels:
sudo airodump-ng wlan1mon

# 3. If airodump-ng shows APs, the adapter is working
# The issue may be in the module's channel configuration

# 4. Check for RF interference
# Move antenna away from USB 3.0 ports/cables
# Try a different channel or band (2.4 vs 5 GHz)
```

---

### LoRa No Frames Captured

**Symptom:** HackRF capture returns zero LoRa packets despite devices being active.

**Cause:** Wrong frequency, insufficient gain, wrong antenna, or no LoRa devices in range.

**Solution:**
```bash
# 1. Verify frequency matches your region
# EU: 868.1 MHz | US: 915 MHz | AS: 923 MHz
# Check config/hardware.yaml:
grep frequency config/hardware.yaml

# 2. Check antenna is for the correct band
# An 868 MHz antenna will not work at 915 MHz and vice versa

# 3. Increase gain
# Edit config/hardware.yaml:
#   gain_rf: 40
#   gain_if: 40
#   gain_bb: 32

# 4. Verify HackRF receives anything
hackrf_transfer -r /tmp/test.raw -f 868100000 -s 2000000 -n 4000000
ls -la /tmp/test.raw
# File should be non-zero size

# 5. Confirm LoRa devices are actively transmitting
# Most LoRa devices only transmit periodically (every 30s to 60min)
# Wait or trigger a transmission from your test device
```

---

## Quick Diagnostic Commands

Run these commands to quickly assess system health:

```bash
# Hardware status
lsusb | grep -iE "realtek|great scott"    # ALFA and HackRF
hciconfig hci0                              # BLE adapter
iwconfig 2>/dev/null | grep -A2 wlan       # WiFi interfaces

# Service status
systemctl status srt-infra srt-probe srt-watchdog --no-pager

# System health
vcgencmd measure_temp                      # CPU temperature
vcgencmd get_throttled                     # Throttle state
df -h / /opt/sniffer 2>/dev/null           # Disk usage
free -h                                    # Memory usage

# Network
docker compose -f infra/docker-compose.yml ps  # Docker services
ss -tlnp | grep -E "5432|3000|1883"       # Expected ports
```
