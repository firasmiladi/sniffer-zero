# BLE: From Capture to Visualization

A complete guide to Bluetooth Low Energy security assessment using sniffer-rt,
covering device discovery, GATT enumeration, vulnerability analysis, and
real-time dashboard visualization.

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Step 1: BLE Adapter Check](#step-1-ble-adapter-check)
- [Step 2: Run BLE Reconnaissance](#step-2-run-ble-reconnaissance)
- [Step 3: Select Target and GATT Enumeration](#step-3-select-target-and-gatt-enumeration)
- [Step 4: Security Assessment](#step-4-security-assessment)
- [Step 5: Pairing Analysis](#step-5-pairing-analysis)
- [Step 6: MAC Randomization Tracking](#step-6-mac-randomization-tracking)
- [Step 7: Demonstrate Unauthorized Write](#step-7-demonstrate-unauthorized-write)
- [Step 8: View in Grafana](#step-8-view-in-grafana)
- [Step 9: Run Full BLE Audit](#step-9-run-full-ble-audit)
- [Step 10: Generate Report](#step-10-generate-report)
- [Tips and Troubleshooting](#tips-and-troubleshooting)

---

## Introduction

In this tutorial, you will learn how to:

- Verify and configure a BLE adapter for scanning
- Discover nearby BLE devices and their advertising data
- Enumerate GATT services and characteristics on a target device
- Assess the security posture of BLE peripherals
- Analyze pairing mechanisms and their weaknesses
- Track devices through MAC address randomization
- Demonstrate unauthorized characteristic writes
- Visualize all findings in Grafana dashboards

BLE is ubiquitous in IoT devices, fitness trackers, smart locks, medical devices,
and industrial sensors. Understanding its security model is essential for any
ISM-band assessment.

---

## Prerequisites

- **Hardware**: Built-in or USB Bluetooth 4.0+ adapter (Intel AX200, CSR 4.0 dongle)
- **Software**: sniffer-rt installed, BlueZ stack (`bluetoothd` running)
- **Infrastructure**: TimescaleDB and Grafana running
- **Authorization**: Target devices listed in `authorization/authorization.yaml`
- **Knowledge**: Basic understanding of BLE concepts (advertising, GATT, pairing)

---

## Step 1: BLE Adapter Check

### Verify Adapter Presence

```bash
hciconfig hci0
```

**Expected output:**

```
hci0:   Type: Primary  Bus: USB
        BD Address: 00:1A:7D:DA:71:13  ACL MTU: 310:10  SCO MTU: 64:8
        UP RUNNING
        RX bytes:574 acl:0 sco:0 events:30 errors:0
        TX bytes:368 acl:0 sco:0 commands:30 errors:0
```

### Bring Adapter Up (if DOWN)

```bash
sudo hciconfig hci0 up
```

### List Available Devices

```bash
hcitool dev
```

**Expected output:**

```
Devices:
        hci0    00:1A:7D:DA:71:13
```

### Verify BLE Support

```bash
hciconfig hci0 features | grep "LE"
```

You should see `LE Supported` in the feature list. If not, your adapter
does not support BLE and you need a compatible dongle.

---

## Step 2: Run BLE Reconnaissance

Scan for advertising BLE devices:

```bash
srt run ble.recon --param duration_s=20
```

The module passively listens for BLE advertising packets, capturing:

- **Device name** (if broadcast in AD data)
- **MAC address** (public or random)
- **RSSI** (signal strength for proximity estimation)
- **Advertising flags** (LE General Discoverable, BR/EDR Not Supported, etc.)
- **Service UUIDs** (advertised services)
- **Manufacturer-specific data** (Apple, Google, Samsung identifiers)
- **TX Power Level** (used for distance calculation)

**Expected output:**

```
[2024-01-15 15:00:01] INFO  ble.recon starting - scanning for 20s
[2024-01-15 15:00:21] INFO  Scan complete
[2024-01-15 15:00:21] INFO  Results:
  Devices discovered:    18
  Public MACs:           5
  Random MACs:           13
  Named devices:         11
  Service UUIDs found:   7 unique
  Manufacturer data:     14 devices

  Notable devices:
    "Smart Lock Pro"     (AA:BB:CC:DD:EE:01) RSSI: -45 dBm - Lock service
    "FitBand-X"          (AA:BB:CC:DD:EE:02) RSSI: -62 dBm - Heart Rate
    "TempSensor-Lab"     (AA:BB:CC:DD:EE:03) RSSI: -38 dBm - Environmental Sensing
```

All discovered devices are stored in TimescaleDB and published to
`srt/headers/ble` via MQTT.

---

## Step 3: Select Target and GATT Enumeration

### Choosing a Target

From the recon results, select a device for deeper analysis. Good candidates:

- Devices with strong RSSI (closer = more reliable connection)
- Devices advertising interesting services (lock, sensor, health)
- Devices with public MAC addresses (easier to reconnect)

### Run GATT Enumeration

```bash
srt run ble.gatt_enum --param target_mac=AA:BB:CC:DD:EE:01
```

This connects to the device and walks the entire GATT profile:

**GATT Structure:**
- **Services**: Groupings of related functionality (identified by UUID)
  - **Characteristics**: Individual data points within a service
    - **Descriptors**: Metadata about the characteristic (format, name)

**Expected output:**

```
[2024-01-15 15:01:00] INFO  ble.gatt_enum connecting to AA:BB:CC:DD:EE:01
[2024-01-15 15:01:02] INFO  Connected - enumerating GATT profile
[2024-01-15 15:01:04] INFO  GATT Profile:

  Service: Generic Access (0x1800)
    Characteristic: Device Name (0x2A00) [READ]
      Value: "Smart Lock Pro"
    Characteristic: Appearance (0x2A01) [READ]
      Value: 0x0000 (Unknown)

  Service: Generic Attribute (0x1801)
    Characteristic: Service Changed (0x2A05) [INDICATE]

  Service: Device Information (0x180A)
    Characteristic: Manufacturer Name (0x2A29) [READ]
      Value: "LockCorp Inc."
    Characteristic: Firmware Revision (0x2A26) [READ]
      Value: "v2.1.3"
    Characteristic: Hardware Revision (0x2A27) [READ]
      Value: "Rev B"

  Service: Custom Lock Service (12345678-1234-1234-1234-123456789abc)
    Characteristic: Lock State (12345678-...-001) [READ, WRITE, NOTIFY]
    Characteristic: PIN Code (12345678-...-002) [WRITE]
    Characteristic: History Log (12345678-...-003) [READ, NOTIFY]

  Total: 4 services, 9 characteristics, 3 descriptors
```

### Interpreting Properties

Each characteristic has properties that determine how it can be accessed:

| Property | Meaning |
|----------|---------|
| READ | Value can be read without special permissions |
| WRITE | Value can be written (command accepted) |
| WRITE_NO_RESP | Write without acknowledgment |
| NOTIFY | Device can push updates to client |
| INDICATE | Like NOTIFY but with acknowledgment |

---

## Step 4: Security Assessment

Assess the security of the discovered GATT profile:

```bash
srt run ble.gatt_security_assessor --param target_mac=AA:BB:CC:DD:EE:01
```

The assessor checks each characteristic for:

- **Readable without encryption**: Sensitive data exposed in cleartext
- **Writable without authentication**: Commands accepted from any device
- **No Secure Connections**: Legacy pairing vulnerable to eavesdropping
- **Sensitive UUID exposure**: Battery level, device info, health data accessible
- **Known vulnerable services**: Comparison against vulnerability database

**Expected output:**

```
[2024-01-15 15:02:00] INFO  ble.gatt_security_assessor analyzing AA:BB:CC:DD:EE:01
[2024-01-15 15:02:03] INFO  Security Assessment Complete:

  Overall Grade: D (Weak)

  Findings:
    [HIGH] Lock State characteristic readable without encryption
    [HIGH] PIN Code writable without authentication
    [MEDIUM] History Log readable without encryption
    [LOW] Device Information exposed (manufacturer, firmware version)
    [INFO] No Secure Connections support detected

  Vulnerable Characteristics: 3/9
  Encryption Required: 0/9 characteristics
  Authentication Required: 0/9 characteristics
```

### Understanding the Grade

| Grade | Criteria |
|-------|----------|
| **A** | All sensitive chars require encryption + authentication |
| **B** | Encryption on sensitive chars, some lacking auth |
| **C** | Mixed - some protection, some gaps |
| **D** | Most characteristics unprotected |
| **F** | No security at all, sensitive data fully exposed |

---

## Step 5: Pairing Analysis

Analyze the device's pairing capabilities:

```bash
srt run ble.pairing_analyzer --param target_mac=AA:BB:CC:DD:EE:01
```

### Pairing Methods

BLE supports four pairing methods based on device IO capabilities:

| Method | MITM Protection | Description |
|--------|-----------------|-------------|
| **Just Works** | None | No user interaction; vulnerable to passive eavesdropping |
| **Passkey Entry** | Yes (weak) | 6-digit PIN; brute-forceable (1M combinations) |
| **Numeric Comparison** | Yes | Both devices display number; user confirms match |
| **Out of Band (OOB)** | Yes | Uses NFC or other channel for key exchange |

**Expected output:**

```
[2024-01-15 15:03:00] INFO  ble.pairing_analyzer connecting to AA:BB:CC:DD:EE:01
[2024-01-15 15:03:02] INFO  Pairing Analysis:

  IO Capabilities: NoInputNoOutput
  Pairing Method: Just Works
  MITM Protection: NOT AVAILABLE
  Secure Connections: NOT SUPPORTED
  BLE Version: 4.2
  Bonding: Supported
  Key Size: 16 bytes

  Vulnerability Assessment:
    [CRITICAL] Just Works pairing - no MITM protection
    [HIGH] Legacy pairing (no Secure Connections) - vulnerable to Crackle attack
    [MEDIUM] No authentication for reconnection
    
  Estimated crack time: <1 second (passive eavesdrop on pairing)
```

---

## Step 6: MAC Randomization Tracking

Analyze how devices use random MAC addresses and attempt to correlate them:

```bash
srt run ble.mac_randomization_tracker
```

Modern devices (iOS, Android) randomize their BLE MAC address to prevent
tracking. This module defeats randomization through fingerprinting:

- **Advertising payload consistency**: Same manufacturer data pattern
- **Advertising interval timing**: Unique per device model/firmware
- **TX power level**: Hardware-specific value
- **Service UUID patterns**: Consistent across MAC rotations
- **Apple Continuity / Google Nearby / Microsoft Swift Pair**: Protocol-specific tracking

**Expected output:**

```
[2024-01-15 15:04:00] INFO  ble.mac_randomization_tracker analyzing 18 devices
[2024-01-15 15:04:05] INFO  MAC Randomization Analysis:

  Total MACs observed:     18
  Identified as random:    13
  Groups correlated:       6 physical devices

  Correlation Groups:
    Group 1 (iPhone, confidence: 0.92):
      - 4A:B2:C3:D4:E5:01 (first seen 14:58)
      - 7F:A1:B2:C3:D4:02 (first seen 15:01)
      - 2E:F3:A4:B5:C6:03 (first seen 15:03)
      Method: Apple Continuity + advertising interval

    Group 2 (Android, confidence: 0.87):
      - 5B:C3:D4:E5:F6:04 (first seen 14:59)
      - 8A:D2:E3:F4:05:06 (first seen 15:02)
      Method: Google Nearby + TX power correlation

  Tracker Beacons Detected:
    - 1 Apple AirTag (FindMy network beacon)
    - 1 Tile tracker (advertising pattern match)
```

---

## Step 7: Demonstrate Unauthorized Write

Test whether a vulnerable characteristic accepts writes without authentication:

```bash
srt run ble.unauth_write --param target_mac=AA:BB:CC:DD:EE:01
```

> **Safety Considerations:**
> - Only run against devices you own or have explicit authorization to test
> - This module writes benign test values that do not cause permanent changes
> - The module reads the current value, writes a test byte, then restores original
> - Results prove the vulnerability exists without causing harm

**Expected output:**

```
[2024-01-15 15:05:00] INFO  ble.unauth_write connecting to AA:BB:CC:DD:EE:01
[2024-01-15 15:05:02] INFO  Testing writable characteristics without auth...

  Characteristic: Lock State (12345678-...-001)
    Original value: 0x01 (locked)
    Test write: 0x00 (unlock command)
    Result: WRITE ACCEPTED - NO AUTHENTICATION REQUIRED
    Restored: 0x01 (re-locked)
    [CRITICAL] Device accepts unauthenticated lock control commands

  Characteristic: PIN Code (12345678-...-002)
    Test write: 0x31 0x32 0x33 0x34 ("1234")
    Result: WRITE ACCEPTED - NO AUTHENTICATION REQUIRED
    [CRITICAL] PIN can be overwritten without authentication

  Summary:
    Writable without auth: 2/9 characteristics
    Critical impact: 2 (lock control + PIN reset)
```

This proves that an attacker within BLE range (typically 10-30 meters) could
unlock the device without any credentials.

---

## Step 8: View in Grafana

### BLE Deep-Dive Dashboard

Navigate to **Dashboards > sniffer-rt - BLE Deep-Dive** (UID: `srt-ble`).

| Panel | Description |
|-------|-------------|
| **BLE Advertising Devices** | Table of all discovered devices with name, MAC, RSSI |
| **MAC Randomization Tracking** | Visual grouping of correlated random MACs |
| **GATT Services Discovered** | List of enumerated services per device |
| **Pairing Events Timeline** | Time series of pairing attempts and outcomes |
| **Vendor Distribution** | Pie chart of manufacturers from OUI/advertising data |

### BLE Advanced Analysis Dashboard

Navigate to **Dashboards > sniffer-rt - BLE Advanced Analysis** (UID: `srt-ble-advanced`).

| Panel | Description |
|-------|-------------|
| **Device Inventory with Security Grades** | All devices with their security grade (A-F) |
| **MAC Randomization Group View** | Stat panel showing unique vs grouped MAC count |
| **GATT Vulnerability Summary** | Table of unprotected characteristics per device |
| **Pairing Method Distribution** | Pie chart of Just Works / Passkey / SC usage |
| **Advertising Interval Analysis** | Time series of advertising intervals per device |
| **Manufacturer Distribution** | Bar chart of device manufacturers |
| **Device Proximity Estimation** | Gauge showing RSSI-to-distance mapping |
| **Tracker Detection** | Table of detected Apple/Tile/Samsung tracker beacons |

---

## Step 9: Run Full BLE Audit

Execute the complete BLE audit scenario:

```bash
srt scenario scenarios/ble_deep_audit.yaml --var target_mac=AA:BB:CC:DD:EE:01
```

This chains all BLE modules in sequence:

1. **ble.recon** (id: `scan`) - Device discovery
2. **ble.gatt_enum** (id: `gatt`) - GATT profile enumeration
3. **ble.gatt_security_assessor** (id: `security`) - Vulnerability assessment
4. **ble.pairing_analyzer** (id: `pairing`) - Pairing mechanism analysis
5. **ble.mac_randomization_tracker** (id: `mac_track`) - MAC correlation
6. **ble.protocol_analyzer** (id: `protocol`) - Protocol-level analysis
7. **ble.unauth_write** - Unauthorized write demonstration
8. **ble.pair_crack** - Pairing key recovery attempt

The scenario uses `bail_on_fail: false`, so it continues even if some steps
fail (e.g., if pairing crack is unsuccessful).

**Expected duration**: 2-4 minutes depending on BLE connection stability.

---

## Step 10: Generate Report

Generate a markdown report for documentation:

```bash
srt report --format markdown --session latest
```

**Expected output:**

```
[2024-01-15 15:10:00] INFO  Generating Markdown report...
[2024-01-15 15:10:01] INFO  Report saved: reports/ble_deep_audit_20240115_150000.md
```

The report includes:

- Device profile (name, MAC, services, firmware version)
- GATT security assessment with vulnerability list
- Pairing analysis results
- MAC randomization findings
- MITRE ATT&CK techniques demonstrated
- Remediation recommendations

---

## Tips and Troubleshooting

### Device Not Connecting

- BLE connections are range-sensitive; move within 5 meters of the target
- Some devices only accept one connection at a time; ensure no phone is connected
- Try resetting the adapter: `sudo hciconfig hci0 reset`
- Increase connection timeout: `--param connect_timeout_s=15`

### BLE Version Differences

| BLE Version | Key Feature | Security Impact |
|-------------|-------------|-----------------|
| 4.0 | Initial LE support | Legacy pairing only, Crackle vulnerable |
| 4.2 | LE Secure Connections | ECDH key exchange, stronger pairing |
| 5.0 | Extended advertising | Larger payloads, 2M PHY |
| 5.1 | Direction finding | AoA/AoD positioning |
| 5.2 | LE Audio, EATT | Enhanced ATT, isochronous channels |

### Range Considerations

- Indoor BLE range: typically 10-30 meters
- Advertising packets: can be received at longer range (50m+)
- GATT connections: require closer proximity for stability
- Walls and obstacles reduce range significantly
- Use RSSI as a rough distance indicator (-30 = very close, -90 = far)

### Adapter Compatibility

Not all Bluetooth adapters support all BLE features:

```bash
# Check LE features
hcitool -i hci0 cmd 0x08 0x0003
```

For best results, use an adapter with Bluetooth 5.0+ support.

---

*Previous: [WiFi: From Capture to Visualization](01-wifi-capture-to-visualization.md)*
*Next: [LoRaWAN: From Capture to Visualization](03-lorawan-capture-to-visualization.md)*
