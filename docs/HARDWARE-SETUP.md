# Hardware Setup Guide

Complete hardware setup instructions for the sniffer-rt platform.

---

## ALFA Adapter (WiFi)

The platform uses an ALFA AWUS036ACH (RTL8812AU chipset) for WiFi monitor mode operations.

### Identify the Chipset

```bash
lsusb | grep -i realtek
# Look for:
#   0bda:8812  Realtek RTL8812AU (AWUS036ACH)
#   0bda:881a  Realtek RTL8814AU (AWUS1900)
```

Confirm the interface appeared:

```bash
ip link show | grep wlan
# Typical: wlan1 (wlan0 is usually the built-in adapter)
```

### Driver Installation (Raspberry Pi)

#### Method A: DKMS package (recommended)

```bash
sudo apt update
sudo apt install -y dkms linux-headers-$(uname -r) realtek-rtl88xxau-dkms
```

Reboot after installation:

```bash
sudo reboot
```

#### Method B: Build from source

```bash
sudo apt install -y dkms git build-essential linux-headers-$(uname -r)
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install
```

### Verify Installation

```bash
# Check interface exists
iwconfig
# Should show wlan1 with IEEE 802.11 mode

# Check monitor mode support
iw phy phy1 info | grep -A 8 "Supported interface modes"
# Must list "monitor" in the output
```

### Enable Monitor Mode

```bash
# Kill interfering processes
sudo airmon-ng check kill

# Start monitor mode
sudo airmon-ng start wlan1
# Creates wlan1mon

# Verify
iwconfig wlan1mon
# Mode should show "Monitor"
```

### Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| "Device or resource busy" | NetworkManager holding the interface | `sudo systemctl stop NetworkManager` or `sudo airmon-ng check kill` |
| No monitor mode | Wrong driver loaded (rtl8xxxu instead of 88xxau) | Blacklist generic driver: `echo "blacklist rtl8xxxu" > /etc/modprobe.d/rtl8xxxu.conf` and reinstall 88xxau driver |
| Low TX power | Regulatory domain restriction | `sudo iw reg set US` (or your country code) |
| wlan1 not visible | USB power insufficient | Use a powered USB hub |
| Interface disappears | Kernel OOPs or USB disconnect | Check `dmesg | tail -30` for errors, replug adapter |

---

## HackRF One (SDR)

Used for LoRa sniffing, spectrum analysis, and SDR-based operations.

### Install Tools

```bash
sudo apt install -y hackrf libhackrf-dev libfftw3-dev
```

### Firmware Update

Only needed if `hackrf_info` reports outdated firmware:

```bash
# Download latest firmware from Great Scott Gadgets
hackrf_spiflash -w hackrf_one_usb.bin
# Replug HackRF after flashing
```

### Verify

```bash
hackrf_info
# Expected output:
#   hackrf_info version: 2024.02.1
#   Found HackRF
#   Index: 0
#   Serial number: 0000000000000000XXXXXXXXXXXXXXXX
#   Board ID Number: 2 (HackRF One)
#   Firmware Version: 2024.02.1 (API:1.08)
#   Part ID Number: 0xXXXXXXXX 0xXXXXXXXX
```

### Antenna Selection

| Frequency | Use Case | Antenna |
|-----------|----------|---------|
| 868 MHz (EU) / 915 MHz (US) | LoRa/LoRaWAN sniffing | SMA whip antenna (tuned for 868/915) |
| 2.4 GHz | Spectrum analysis | Dual-band 2.4/5 GHz SMA antenna |
| Wideband | Spectrum survey | Telescopic or discone antenna |

### Gain Settings

The HackRF has three gain stages:

| Stage | Range | Recommended (LoRa) | Notes |
|-------|-------|---------------------|-------|
| RF (LNA) | 0-40 dB | 40 dB | Front-end amplifier |
| IF | 0-40 dB | 32 dB | Intermediate frequency gain |
| BB (VGA) | 0-62 dB | 20 dB | Baseband variable gain |

These are configured in `config/hardware.yaml`:

```yaml
hackrf:
  gain_rf: 40
  gain_if: 32
  gain_bb: 20
```

### USB Considerations

- Use a **USB 2.0** port on the Raspberry Pi (USB 3.0 can cause radio frequency interference at 2.4 GHz)
- If using a USB hub, ensure it is **powered** (HackRF draws up to 500 mA)
- Keep the USB cable short (under 1m) to reduce noise

---

## Raspberry Pi BLE

The built-in Bluetooth adapter on Raspberry Pi 3B+/4/5 is used for BLE operations.

### Verify Built-in Adapter

```bash
hciconfig hci0
# Expected: UP RUNNING
# Type: Primary
# Bus: UART
```

### Enable Bluetooth

```bash
# Ensure the service is running
sudo systemctl start bluetooth
sudo systemctl enable bluetooth

# Power on the adapter
bluetoothctl power on
```

### Kernel Modules

The following modules must be loaded:

```bash
lsmod | grep -E "btusb|hci_uart|bluetooth"
# Expected: bluetooth, hci_uart (Pi built-in), btusb (USB dongles)
```

If modules are missing:

```bash
sudo modprobe bluetooth
sudo modprobe hci_uart
```

### Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| hci0 DOWN | Bluetooth service not running | `sudo systemctl restart bluetooth` |
| Firmware missing | Pi firmware not installed | `sudo apt install -y pi-bluetooth` |
| Scan returns empty | Adapter in classic mode only | `sudo btmgmt le on` |
| "Operation not permitted" | Not running as root | Use `sudo` or add user to `bluetooth` group |

---

## Physical Setup

### Connection Diagram

```
                  +-------------------+
                  |   Raspberry Pi 5  |
                  |                   |
   USB 2.0 ------| Port 1: ALFA      |------ 2.4/5 GHz Antenna
                  |                   |
   USB 2.0 ------| Port 2: HackRF    |------ 868 MHz LoRa Antenna
                  |                   |
   Built-in -----| hci0: BLE         |------ (internal antenna)
                  |                   |
   Ethernet -----| eth0              |------ Lab network
                  |                   |
   NVMe SSD -----| M.2 hat           |------ Data storage
                  +-------------------+
                         |
                    Power Supply
                   (5V / 5A USB-C)
```

### Power Considerations

| Device | Current Draw | Notes |
|--------|-------------|-------|
| ALFA AWUS036ACH | ~500 mA | Higher during TX |
| HackRF One | ~500 mA | Constant when streaming |
| Raspberry Pi 5 | ~1.5 A (idle) to 3 A (load) | Excluding USB peripherals |

**Total estimated draw:** ~4-5 A at peak

**Recommendations:**
- Use the official Raspberry Pi 5 power supply (5V / 5A, 27W USB-C)
- For portable operation: use a powered USB hub with its own supply
- Monitor undervoltage: `vcgencmd get_throttled` (bit 0 = undervoltage detected)

### Antenna Placement

- Keep the ALFA WiFi antenna and HackRF LoRa antenna at least **30 cm apart** to minimize cross-band interference
- Place the HackRF antenna **vertically** for best LoRa reception (most LoRa devices transmit vertically polarized)
- If indoors, position antennas near a window for better signal from outdoor targets
- Avoid placing antennas near USB 3.0 cables or ports (RFI source at 2.4 GHz)
