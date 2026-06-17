# Lab setup

## Physical requirements

- **Shielded enclosure** (Faraday cage / shielded tent / repurposed shielded
  rack). Attenuation > 60 dB across 400 MHz – 6 GHz strongly recommended.
- Power filter / RF-clean PSU.
- Workbench with grounded mat.
- Emergency stop button wired to TX power supply.
- Posted authorization letter on the cage door.

## Hardware

See `docs/hardware-bom.md` for the canonical BOM.

Minimum operational kit:

- HackRF One + LNA (e.g. Nooelec SAWbird) + SAW filters per band.
- ALFA AWUS036ACH (RTL8812AU) for WiFi monitor mode.
- Raspberry Pi 5 (8 GB) + NVMe SSD (encrypted with LUKS).
- Test laptop with Docker.

## Software baseline

Host VM (per the project brief): **DragonOS FocalX R37.1** (Ubuntu-based,
ships GNU Radio 3.10 + most SDR tools).

For the deployable Pi: **DragonOS arm64** or stock **Raspberry Pi OS** + the
provisioning playbook in `infra/pi-image/`.

## Bring-up checklist

```bash
# 1. SDR sanity
hackrf_info

# 2. Infra
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml ps

# 3. Python tooling
pip install -e ".[dev,ble,report]"
srt info

# 4. Self-test
srt selftest
```

## Lab targets

- `lab/openwrt-ap/` - disposable AP image (WPA2-PSK, WPA2-Enterprise).
- `lab/ble-targets/` - ESP32 BLE peripherals, a Mi Band, an AirTag clone.
- `lab/chirpstack/` - local LoRaWAN network server with disposable devices.

## Operational hygiene

- Always start with a **passive sweep** of the cage to confirm RF leakage is
  acceptable.
- Log every run via `srt run ... --log reports/out/<date>-<scenario>.json`.
- Wipe SSD captures after each engagement (`make wipe`).
