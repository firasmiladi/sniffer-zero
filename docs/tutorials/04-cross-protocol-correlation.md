# Cross-Protocol Correlation: Multi-Protocol Device Analysis

A guide to correlating device identities across WiFi, BLE, and LoRaWAN
protocols to build a unified picture of the RF environment.

## Table of Contents

- [Introduction](#introduction)
- [Why Correlation Matters](#why-correlation-matters)
- [Correlation Methods](#correlation-methods)
- [Running Multi-Protocol Scans](#running-multi-protocol-scans)
- [Understanding Correlation Results](#understanding-correlation-results)
- [Building a Device Inventory](#building-a-device-inventory)
- [Using the Security Overview Dashboard](#using-the-security-overview-dashboard)
- [Device Graph Visualization](#device-graph-visualization)
- [Practical Example](#practical-example)
- [Advanced Correlation Techniques](#advanced-correlation-techniques)
- [Tips and Troubleshooting](#tips-and-troubleshooting)

---

## Introduction

In this tutorial, you will learn how to:

- Understand why cross-protocol correlation is essential for IoT assessments
- Identify the same physical device appearing on multiple protocols
- Run a full multi-protocol audit with `full_deep_audit.yaml`
- Interpret correlation confidence scores and evidence types
- Build a unified device inventory from WiFi, BLE, and LoRaWAN data
- Use the Security Overview dashboard for cross-protocol visibility
- Understand device relationship graphs

Modern IoT devices often communicate on multiple protocols simultaneously.
A smart building controller might use WiFi for cloud connectivity, BLE for
local configuration, and LoRaWAN for sensor data aggregation. Identifying
these relationships is critical for comprehensive security assessment.

---

## Why Correlation Matters

### Single-Protocol Blind Spots

Assessing protocols in isolation misses critical attack paths:

- A device secure on WiFi may have an unauthenticated BLE interface
- A LoRaWAN sensor with strong encryption may expose data via unencrypted WiFi
- A device's BLE MAC randomization is defeated if its WiFi MAC is visible

### Attack Surface Multiplication

When a device operates on multiple protocols:

- Each protocol represents an independent attack surface
- Compromise on one protocol may enable lateral movement to others
- Physical proximity requirements differ (BLE ~30m, WiFi ~100m, LoRa ~15km)

### Unified Risk Assessment

Correlating findings produces a complete risk picture:

- Aggregate vulnerability count per physical device (not per interface)
- Identify the weakest link in multi-protocol devices
- Map all attack vectors for a single target

---

## Correlation Methods

The sniffer-rt correlation engine (`src/srt/core/correlation.py`) uses three
primary methods:

### 1. OUI (MAC Prefix) Matching

The first three bytes of a MAC address identify the manufacturer (OUI).
If a WiFi device and BLE device share the same OUI, they may be the same
hardware:

```
WiFi:  AA:BB:CC:11:22:33  (OUI: AA:BB:CC -> "IoT Corp")
BLE:   AA:BB:CC:44:55:66  (OUI: AA:BB:CC -> "IoT Corp")
```

Confidence: **Low to Medium** (same manufacturer does not guarantee same device)

### 2. Timing Correlation

Devices that appear and disappear at the same times are likely co-located
or the same physical unit:

```
14:00 - WiFi device appears, BLE device appears
14:15 - WiFi device disappears, BLE device disappears
14:30 - Both reappear simultaneously
```

Confidence: **Medium to High** (synchronized presence strongly suggests
same device or same location)

### 3. Signal Strength Correlation

Co-located devices show correlated RSSI patterns. As you move the receiver,
all interfaces of the same device change RSSI together:

```
Time    WiFi RSSI    BLE RSSI     Correlation
14:00   -45 dBm      -42 dBm     
14:05   -52 dBm      -50 dBm      (both decreased ~7 dB)
14:10   -38 dBm      -35 dBm      (both increased ~14 dB)
```

Confidence: **High** (correlated RSSI changes are strong evidence)

### Combined Evidence

When multiple methods agree, confidence increases:

| Evidence Combination | Typical Confidence |
|---------------------|-------------------|
| OUI only | 0.2 - 0.4 |
| Timing only | 0.4 - 0.6 |
| OUI + Timing | 0.6 - 0.8 |
| OUI + Timing + RSSI | 0.8 - 0.95 |
| All methods + device name match | 0.95 - 1.0 |

---

## Running Multi-Protocol Scans

Execute the full deep audit to collect data across all protocols:

```bash
srt scenario scenarios/full_deep_audit.yaml
```

This scenario runs through three phases:

### Phase 1: WiFi Assessment

- wifi.recon (30s scan across channels 1-13)
- wifi.frame_dissector (deep frame analysis)
- wifi.timing_analyzer (beacon timing analysis)
- wifi.security_assessor (security grading)
- wifi.probe_fingerprinter (client identification)
- wifi.signal_analyzer (signal quality)

### Phase 2: BLE Assessment

- ble.recon (20s advertising scan)
- ble.gatt_enum (GATT enumeration of discovered devices)
- ble.gatt_security_assessor (characteristic security check)
- ble.pairing_analyzer (pairing method assessment)
- ble.mac_randomization_tracker (MAC correlation)
- ble.protocol_analyzer (protocol-level analysis)

### Phase 3: LoRaWAN Assessment

- lora.recon (120s passive capture)
- lora.frame_decoder (full frame decode)
- lora.anomaly_detector (security anomaly scan)
- lora.traffic_profiler (behavioral analysis)
- lora.key_extractor (key recovery attempt)

### Phase 4: Correlation

After all protocol-specific modules complete, the orchestrator runs
cross-protocol correlation automatically, comparing results across all
three protocol datasets.

---

## Understanding Correlation Results

After the full audit completes, examine correlation output:

```bash
srt report --format json --session latest
```

The correlation section of the report:

```json
{
  "correlation": {
    "groups": [
      {
        "group_id": "device_001",
        "confidence": 0.87,
        "evidence": ["oui_match", "timing_correlation"],
        "interfaces": [
          {
            "protocol": "wifi",
            "mac": "AA:BB:CC:11:22:33",
            "ssid": "IoT-Hub-01",
            "security_grade": "C"
          },
          {
            "protocol": "ble",
            "mac": "AA:BB:CC:44:55:66",
            "name": "IoT-Hub-Config",
            "security_grade": "D"
          },
          {
            "protocol": "lora",
            "devaddr": "260B1234",
            "activation": "ABP",
            "anomalies": 2
          }
        ],
        "aggregate_risk": "HIGH",
        "weakest_link": "ble (grade D, unauthenticated writes)"
      }
    ],
    "uncorrelated_devices": 14,
    "total_physical_devices_estimated": 22
  }
}
```

### Key Fields

- **confidence**: 0.0 to 1.0 score indicating correlation certainty
- **evidence**: Array of methods that contributed to the correlation
- **interfaces**: All protocol appearances of this physical device
- **aggregate_risk**: Combined risk level considering all interfaces
- **weakest_link**: The most vulnerable protocol interface

---

## Building a Device Inventory

The correlation engine produces a unified device inventory that maps
physical devices to all their network interfaces:

### Inventory Structure

```
Physical Device: "Smart Building Controller"
├── WiFi Interface
│   ├── MAC: AA:BB:CC:11:22:33
│   ├── SSID: connected to "CorpNet"
│   ├── Security: WPA2-CCMP (Grade B)
│   └── Role: Cloud uplink
├── BLE Interface
│   ├── MAC: AA:BB:CC:44:55:66 (public)
│   ├── Name: "BldgCtrl-Config"
│   ├── Security: Grade D (no auth on config char)
│   └── Role: Local configuration
└── LoRaWAN Interface
    ├── DevAddr: 260B1234
    ├── Activation: ABP
    ├── Security: Counter reset issues
    └── Role: Sensor data aggregation
```

### Why This Matters

With this inventory, you can:

1. **Identify the weakest link**: This device is Grade B on WiFi but Grade D
   on BLE. An attacker would target the BLE interface.
2. **Plan attack chains**: Compromise BLE config interface, change WiFi
   credentials, gain network access.
3. **Prioritize remediation**: Fix the BLE authentication first since it is
   the most exposed interface.

---

## Using the Security Overview Dashboard

Navigate to **Dashboards > sniffer-rt - Security Overview** (UID: `srt-security-overview`).

This dashboard provides cross-protocol visibility:

| Panel | Description |
|-------|-------------|
| **Overall Security Posture** | Single stat showing aggregate security score |
| **Critical Vulnerabilities** | Table of highest-severity findings across all protocols |
| **MITRE ATT&CK Coverage** | Table of techniques triggered during assessment |
| **Active Alerts** | Real-time alert list from all monitoring rules |
| **Protocol Breakdown** | Bar chart of findings count per protocol |
| **Discovery Timeline** | Time series of new device discoveries |
| **Top Vulnerable Devices** | Table of devices sorted by vulnerability count |

### Reading the Security Posture Score

The overall score is calculated as:

```
Score = 100 - (critical_count * 20 + high_count * 10 + medium_count * 5 + low_count * 2)
```

| Score Range | Meaning |
|-------------|---------|
| 80-100 | Good security posture |
| 60-79 | Moderate issues, remediation recommended |
| 40-59 | Significant vulnerabilities present |
| 0-39 | Critical security failures |

### Drilling Down

Click on any device in the "Top Vulnerable Devices" panel to filter all
other panels to that specific device, showing its findings across all
protocols simultaneously.

---

## Device Graph Visualization

The correlation engine builds a graph structure where:

- **Nodes** represent network interfaces (WiFi MAC, BLE MAC, LoRa DevAddr)
- **Edges** represent correlation evidence between interfaces

### Graph Interpretation

```
[WiFi: AA:BB:CC:11:22:33] ----(OUI+timing, 0.87)----> [BLE: AA:BB:CC:44:55:66]
                          \
                           ----(timing, 0.62)---------> [LoRa: 260B1234]
```

Strong edges (confidence > 0.7) indicate high certainty that interfaces
belong to the same device. Weak edges (0.3-0.5) suggest possible
correlation requiring additional evidence.

### Exporting the Graph

The correlation data is stored in the `module_results` table and can be
queried directly:

```sql
SELECT
  fields->>'group_id' as device_group,
  fields->>'protocol' as protocol,
  fields->>'mac' as identifier,
  fields->>'confidence' as confidence
FROM module_results
WHERE module = 'correlation'
  AND ts > now() - interval '1 hour'
ORDER BY fields->>'group_id', fields->>'protocol';
```

---

## Practical Example

### Scenario: IoT Smart Office

Imagine an office with these devices:

1. **Smart Thermostat** - WiFi (cloud API) + BLE (mobile app control)
2. **Door Lock** - BLE (proximity unlock) + LoRaWAN (status to building mgmt)
3. **Environmental Sensor** - LoRaWAN (periodic temperature/humidity)
4. **IP Camera** - WiFi only (video streaming)
5. **Employee Phones** - WiFi + BLE (randomized MACs)

### Running the Assessment

```bash
srt scenario scenarios/full_deep_audit.yaml
```

### Expected Correlation Results

After the full audit:

- **Thermostat**: Correlated via OUI match (WiFi MAC AA:BB:CC:01 and BLE
  MAC AA:BB:CC:02 share same manufacturer OUI). Confidence: 0.82.
  WiFi secured with WPA2 (Grade B), but BLE has no authentication on
  temperature setpoint characteristic (Grade D). Attack path: modify
  thermostat settings via BLE without credentials.

- **Door Lock**: Correlated via timing (BLE advertising and LoRa uplink
  appear/disappear together during power cycles). Confidence: 0.71.
  BLE requires Passkey pairing (Grade B), but LoRaWAN uses ABP with
  counter resets (vulnerability). Attack path: replay LoRa "unlock"
  command if FPort payload is understood.

- **Environmental Sensor**: No cross-protocol correlation (LoRaWAN only).
  Single interface assessment only.

- **IP Camera**: No cross-protocol correlation (WiFi only).
  Single interface assessment only.

- **Phones**: WiFi and BLE MACs correlated via Apple Continuity pattern
  matching (confidence: 0.91). Not a vulnerability, but demonstrates
  tracking capability despite MAC randomization.

### Actionable Findings

From this assessment:

1. Thermostat BLE interface needs authentication on control characteristics
2. Door lock should migrate from ABP to OTAA activation
3. Camera WiFi security is adequate (Grade A with WPA3)
4. Phone tracking is possible despite randomization (privacy concern)

---

## Advanced Correlation Techniques

### Increasing Correlation Accuracy

- **Longer scan durations**: More data points improve timing correlation
  ```bash
  srt scenario scenarios/full_deep_audit.yaml --var wifi_duration=60 --var lora_duration=300
  ```

- **Multiple scan sessions**: Run scans at different times of day to observe
  device presence patterns

- **Physical movement**: Move the receiver to create RSSI variation.
  Devices on the same hardware will show correlated signal changes.

### OUI Database Limitations

- Not all manufacturers register OUIs (some use random local addresses)
- Shared OUIs among product lines produce false positives
- BLE random addresses do not have meaningful OUI
- WiFi randomized MACs (Android 10+, iOS 14+) use local bit

### Handling False Positives

If confidence is below 0.5, treat the correlation as unconfirmed:

- Same OUI alone is insufficient (many vendors use shared chipsets)
- Timing coincidence can occur in busy environments
- Validate with physical inspection when possible

---

## Tips and Troubleshooting

### Low Correlation Confidence

- Increase scan duration for more timing data points
- Ensure all three protocol scans run simultaneously (not sequentially
  with large gaps)
- Add physical movement during scanning for RSSI variation

### Too Many Uncorrelated Devices

- Expected in dense environments (many single-protocol devices exist)
- Focus on devices with multiple interfaces for maximum value
- Phones and laptops rarely appear on LoRaWAN (WiFi + BLE correlation only)

### Time Window Configuration

The default correlation time window is 60 seconds. Adjust for your environment:

- Dense environment with many devices: reduce to 30s to avoid false positives
- Sparse environment: increase to 120s to catch devices with infrequent activity

### Performance with Large Datasets

For assessments with hundreds of devices:

- Run protocol scans in shorter windows and focus on specific targets
- Use the Grafana time range selector to narrow the analysis period
- Export relevant data to CSV for offline analysis

---

*Previous: [LoRaWAN: From Capture to Visualization](03-lorawan-capture-to-visualization.md)*
*Next: [Automated Scenarios](05-automated-scenarios.md)*
