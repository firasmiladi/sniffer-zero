# Installation Guide

Complete installation instructions for the sniffer-rt platform on both development PCs and production Raspberry Pi deployments.

---

## PC Development Setup (Ubuntu / Kali Linux)

### Prerequisites

```bash
# System packages
sudo apt update
sudo apt install -y \
    python3.10 python3-venv python3-pip \
    docker.io docker-compose-plugin \
    hackrf libhackrf-dev \
    aircrack-ng \
    bluez \
    tshark \
    git build-essential

# Add your user to the docker group (logout/login after)
sudo usermod -aG docker $USER
```

### Clone and Install

```bash
git clone <repository-url> sniffer
cd sniffer

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the package with all extras
pip install -e ".[dev,ble,report]"
```

### Start Infrastructure

The platform uses TimescaleDB, Grafana, Mosquitto (MQTT), and ChirpStack:

```bash
docker compose -f infra/docker-compose.yml up -d
```

Verify services are running:

```bash
docker compose -f infra/docker-compose.yml ps
# All services should show "Up"
```

### Verify Installation

```bash
# CLI should respond
srt --help
srt info

# Run the self-test
srt selftest

# Run the full test suite in syntax-only mode (no hardware needed)
python run_all_tests.py --syntax-only
```

---

## Raspberry Pi Production Setup

### Flash the OS

1. Download **Raspberry Pi OS Bookworm 64-bit Lite** (no desktop needed)
2. Flash to NVMe SSD using Raspberry Pi Imager
3. Enable SSH in the imager advanced settings
4. Set hostname, username, and password
5. Boot the Pi with the NVMe hat attached

### Deploy Using the Script

The easiest method is the automated deployment script from your development PC:

```bash
./deploy_to_pi.sh pi@192.168.1.100 pi ~/.ssh/id_rsa
```

This will:
- Validate local project integrity (dry-run tests)
- rsync the project files to the Pi
- Run `deploy/setup.sh` on the Pi
- Install the Python package
- Configure systemd services
- Run the remote self-test

### Manual Deployment

If you prefer manual setup:

```bash
# Copy files to Pi
rsync -avz --exclude .venv --exclude .git --exclude __pycache__ \
    ./ pi@192.168.1.100:/opt/sniffer/

# SSH to Pi
ssh pi@192.168.1.100

# Run setup
cd /opt/sniffer
sudo bash deploy/setup.sh

# Create venv and install
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,ble,report]"

# Verify
srt selftest
```

---

## Configuration

### Hardware Configuration

Edit `config/hardware.yaml` to match your interface names:

```yaml
hardware:
  wifi_interface: "wlan1"              # Your ALFA adapter
  wifi_monitor_interface: "wlan1mon"   # Monitor mode interface
  sdr_backend: "hackrf"               # SDR type
  ble_adapter: "hci0"                 # BLE adapter

  hackrf:
    gain_rf: 40
    gain_if: 32
    gain_bb: 20

  lora:
    frequency_hz: 868100000            # EU868 (use 915000000 for US)
    bandwidth_hz: 125000
    spreading_factor: 7
```

To find your interface names:

```bash
# WiFi adapters
ip link show | grep wlan

# BLE adapters
hciconfig -a
```

### Safety Whitelist

Edit `safety/whitelist.yaml` with your authorized lab targets:

```yaml
whitelist:
  wifi_bssid:
    - "AA:BB:CC:DD:EE:FF"   # Your lab AP MAC
  wifi_client:
    - "11:22:33:44:55:66"   # Your test client MAC
  ble_addr:
    - "AA:BB:CC:DD:EE:FF"   # Your test BLE device
  lora_devaddr:
    - "01020304"             # Your test LoRa device address
```

**Important:** Active attack modules will refuse to run against targets not in this whitelist.

### Authorization

For active attack modules, sign the authorization file at `authorization/authorization.yaml`:

```yaml
authorization:
  scope: "lab-only"
  start_date: "2024-01-01"
  end_date: "2025-12-31"
  authorized_by: "Your Name"
  lab_location: "Building X, Room Y"
  notes: "Authorized for RF security testing in shielded environment"
```

---

## Quick Verification Checklist

After installation, verify each component:

```bash
# 1. CLI works
srt info

# 2. Module registry is populated
srt list

# 3. Syntax validation passes
python run_all_tests.py --syntax-only

# 4. Dry-run modules work (no hardware needed)
python run_all_tests.py --dry-run

# 5. Infrastructure accessible (if Docker is running)
curl -s http://localhost:3000/api/health    # Grafana
docker exec srt-timescaledb pg_isready      # TimescaleDB

# 6. Hardware detected (requires devices plugged in)
srt selftest
```
