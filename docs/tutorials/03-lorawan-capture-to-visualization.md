# LoRaWAN: From Capture to Visualization

A comprehensive guide to LoRaWAN security assessment using sniffer-rt,
covering passive radio capture with HackRF, frame decoding, anomaly detection,
traffic profiling, and real-time Grafana visualization.

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Step 1: HackRF Setup](#step-1-hackrf-setup)
- [Step 2: Run LoRaWAN Reconnaissance](#step-2-run-lorawan-reconnaissance)
- [Step 3: Frame Decoding](#step-3-frame-decoding)
- [Step 4: View in Grafana](#step-4-view-in-grafana)
- [Step 5: Identify ABP vs OTAA](#step-5-identify-abp-vs-otaa)
- [Step 6: Anomaly Detection](#step-6-anomaly-detection)
- [Step 7: Traffic Profiling](#step-7-traffic-profiling)
- [Step 8: Replay Demonstration](#step-8-replay-demonstration)
- [Step 9: Run Full LoRa Audit](#step-9-run-full-lora-audit)
- [Step 10: Generate Report with MITRE Mapping](#step-10-generate-report-with-mitre-mapping)
- [Tips and Troubleshooting](#tips-and-troubleshooting)

---

## Introduction

In this tutorial, you will learn how to:

- Configure a HackRF One for LoRaWAN frequency capture
- Passively decode LoRa modulated frames from the ISM band
- Parse LoRaWAN MAC layer protocol details
- Identify device types (ABP vs OTAA) from traffic patterns
- Detect anomalies indicating security issues or attacks
- Profile device behavior and duty cycle compliance
- Demonstrate replay attacks against ABP devices
- Visualize all findings in Grafana dashboards

LoRaWAN is widely deployed for IoT applications including smart metering,
asset tracking, agriculture, and industrial monitoring. Its long range
(up to 15 km) and low power make it ideal for distributed sensors, but
security implementations vary widely.

---

## Prerequisites

- **Hardware**: HackRF One with appropriate antenna (868 MHz for EU, 915 MHz for US)
- **Software**: sniffer-rt installed, `gr-lora_sdr` GNU Radio blocks available
- **Infrastructure**: TimescaleDB and Grafana running
- **Authorization**: Target LoRaWAN network in `authorization/authorization.yaml`
- **Knowledge**: Basic understanding of LoRa modulation (SF, BW, CR) and
  LoRaWAN network architecture (end devices, gateways, network server)

---

## Step 1: HackRF Setup

### Verify HackRF Connection

```bash
hackrf_info
```

**Expected output:**

```
hackrf_info version: 2024.02.1
libhackrf version: 0.8
Found HackRF
Index: 0
Serial number: 0000000000000000XXXX
Board ID Number: 2 (HackRF One)
Firmware Version: 2024.02.1
Part ID Number: 0xXXXXXXXX 0xXXXXXXXX
CPLD CRC: 0xXXXXXXXX
```

### Antenna Connection

Connect an antenna tuned for your target frequency band:

- **EU868**: 868.1, 868.3, 868.5 MHz (primary channels)
- **US915**: 902-928 MHz (64 uplink + 8 downlink channels)
- **AS923**: 923.2, 923.4 MHz

> **Important**: Never transmit without an antenna connected - this can damage
> the HackRF PA. For receive-only operation (passive recon), antenna damage risk
> is minimal but signal quality will be poor without one.

### Frequency Plan Reference (EU868)

| Channel | Frequency | Mandatory |
|---------|-----------|-----------|
| 0 | 868.1 MHz | Yes |
| 1 | 868.3 MHz | Yes |
| 2 | 868.5 MHz | Yes |
| 3 | 867.1 MHz | No |
| 4 | 867.3 MHz | No |
| 5 | 867.5 MHz | No |
| 6 | 867.7 MHz | No |
| 7 | 867.9 MHz | No |

All LoRaWAN 1.0/1.1 devices must support channels 0-2. The default scan
targets these three mandatory channels.

---

## Step 2: Run LoRaWAN Reconnaissance

Start passive LoRa frame capture:

```bash
srt run lora.recon --param duration_s=120 --param band=eu868
```

The module uses `gr-lora_sdr` to demodulate LoRa symbols from the raw IQ
stream captured by HackRF. It extracts:

- **DevAddr**: 4-byte device address (identifies the end device)
- **FCnt**: Frame counter (monotonically increasing per device)
- **MType**: Message type (JoinRequest, Data Up/Down, etc.)
- **FPort**: Application port number
- **RSSI**: Received signal strength
- **SF/BW**: Spreading Factor and Bandwidth used

**Expected output:**

```
[2024-01-15 16:00:01] INFO  lora.recon starting - EU868 band, 120s capture
[2024-01-15 16:00:01] INFO  Monitoring: 868.1, 868.3, 868.5 MHz
[2024-01-15 16:00:01] INFO  HackRF configured: sample_rate=2M, gain=40 dB
[2024-01-15 16:02:01] INFO  Capture complete
[2024-01-15 16:02:01] INFO  Results:
  Frames decoded:      47
  Unique DevAddrs:     8
  Join Requests:       2
  Unconfirmed Up:      38
  Confirmed Up:        5
  Downlink frames:     2

  Active Devices:
    DevAddr: 260B1234  FCnt: 1042-1048  SF7/125kHz   (6 frames)
    DevAddr: 260B5678  FCnt: 523-530    SF10/125kHz  (7 frames)
    DevAddr: 260BABCD  FCnt: 0-3        SF12/125kHz  (4 frames, new device?)
    ...
```

> **Note**: LoRaWAN traffic is typically sparse. A 2-minute capture may only
> yield a few frames per device. For thorough analysis, increase duration to
> 10-30 minutes: `--param duration_s=1800`

---

## Step 3: Frame Decoding

Run the detailed frame decoder for full protocol analysis:

```bash
srt run lora.frame_decoder
```

### LoRaWAN Frame Structure

Every LoRaWAN frame follows this structure:

```
PHYPayload = MHDR | MACPayload | MIC
MACPayload = FHDR | FPort | FRMPayload
FHDR = DevAddr | FCtrl | FCnt | FOpts
```

### Message Types (MType)

| MType | Value | Direction | Description |
|-------|-------|-----------|-------------|
| Join Request | 000 | Up | Device requests network join (OTAA) |
| Join Accept | 001 | Down | Network accepts join, provides keys |
| Unconfirmed Data Up | 010 | Up | Sensor data, no ACK required |
| Unconfirmed Data Down | 011 | Down | Commands to device, no ACK |
| Confirmed Data Up | 100 | Up | Sensor data, ACK required |
| Confirmed Data Down | 101 | Down | Commands, ACK required |

### MAC Commands

The frame decoder identifies MAC commands in FOpts or FPort=0 payloads:

| Command | Description | Security Relevance |
|---------|-------------|-------------------|
| LinkCheckReq | Connectivity test | None |
| LinkADRReq | Adjust data rate/power | Can force weak SF |
| DutyCycleReq | Set max duty cycle | Denial of service vector |
| RXParamSetupReq | Change RX parameters | Redirect downlinks |
| DevStatusReq | Request battery/SNR | Information disclosure |
| NewChannelReq | Add frequency channel | Redirect to attacker gateway |
| RXTimingSetupReq | Change RX delay | Timing manipulation |

**Expected output:**

```
[2024-01-15 16:03:00] INFO  lora.frame_decoder analyzing captured frames
[2024-01-15 16:03:01] INFO  Decode Results:

  Frame #1:
    MType: Unconfirmed Data Up
    DevAddr: 260B1234
    FCtrl: ADR=1, ADRACKReq=0, ACK=0, FOptsLen=0
    FCnt: 1042
    FPort: 1
    FRMPayload: [encrypted, 12 bytes]
    MIC: 0xA1B2C3D4

  Frame #2:
    MType: Join Request
    AppEUI: 70B3D57ED0000001
    DevEUI: 0004A30B001F2E3D
    DevNonce: 0x1A2B

  MAC Commands detected: 3
    - LinkADRReq (from network server)
    - DevStatusReq (from network server)
    - LinkCheckAns (from device)
```

---

## Step 4: View in Grafana

### LoRaWAN Deep-Dive Dashboard

Navigate to **Dashboards > sniffer-rt - LoRaWAN Deep-Dive** (UID: `srt-lora`).

| Panel | Description |
|-------|-------------|
| **Active LoRa Devices** | Count of unique DevAddrs seen in time window |
| **FCnt Progression** | Time series of frame counters per device (should be monotonically increasing) |
| **Frame Type Distribution** | Pie chart of MType values |
| **Channel Usage (EU868)** | Bar chart showing which frequencies are used most |
| **Anomaly Alerts** | FCnt rollback and DevNonce reuse events |

### LoRaWAN Advanced Analysis Dashboard

Navigate to **Dashboards > sniffer-rt - LoRaWAN Advanced Analysis** (UID: `srt-lora-advanced`).

| Panel | Description |
|-------|-------------|
| **Device Activity Timeline** | Time series of FCnt per DevAddr over time |
| **Anomaly Event Log** | Table of detected anomalies (rollbacks, replays) |
| **Channel Usage Distribution** | Bar chart of frame count per frequency |
| **SF/DR Distribution** | Pie chart of Spreading Factor usage |
| **Uplink Interval Analysis** | Time series of inter-frame intervals per device |
| **Payload Size Distribution** | Histogram of FRMPayload lengths |
| **Join Request Activity** | Time series of JoinRequest count over time |
| **Network Health Score** | Stat panel computing health from anomaly rate |

### What to Watch For

- **FCnt gaps**: Missing counter values may indicate lost frames or jamming
- **FCnt rollback**: Counter decreasing suggests device reset or replay attack
- **Irregular intervals**: Device sending outside normal schedule
- **Unusual SF**: Device suddenly using higher SF (range issue or manipulation)

---

## Step 5: Identify ABP vs OTAA

Understanding the activation method reveals the security model:

### OTAA (Over-The-Air Activation)

- Device sends **JoinRequest** containing AppEUI, DevEUI, DevNonce
- Network responds with **JoinAccept** containing AppNonce, NetID, DevAddr
- Session keys (NwkSKey, AppSKey) derived from exchange
- **More secure**: Fresh keys per session, DevNonce prevents replay

### ABP (Activation By Personalization)

- Device pre-provisioned with DevAddr, NwkSKey, AppSKey
- No Join procedure - device starts transmitting immediately
- FCnt typically starts from 0 on each power cycle
- **Less secure**: Fixed keys, no counter synchronization

### How to Tell From Traffic

```
If you observe JoinRequest + JoinAccept followed by data frames:
  -> OTAA device (dynamic session keys)

If you observe only data frames with no prior Join:
  -> ABP device (static keys)

If FCnt periodically resets to 0:
  -> Likely ABP with power cycling (no persistent counter)
  -> OR compromised OTAA device
```

ABP devices with counter reset are vulnerable because:
1. No mechanism to detect replayed frames with valid FCnt
2. Network server may accept old frames if counter acceptance window is relaxed
3. Keys never rotate - if compromised, permanently exposed

---

## Step 6: Anomaly Detection

Run the anomaly detector to find security issues:

```bash
srt run lora.anomaly_detector --param analysis_window_s=300
```

The module analyzes captured traffic patterns for:

- **FCnt rollback**: Frame counter decreasing (device reset or replay in progress)
- **FCnt gap**: Large jumps in counter (lost frames or selective jamming)
- **DevNonce reuse**: Same nonce in multiple JoinRequests (replay attempt)
- **Duplicate frames**: Identical frame seen multiple times (active replay)
- **Timing anomalies**: Frames outside expected schedule
- **Unexpected DevAddr**: New device appearing that was not seen during join

**Expected output:**

```
[2024-01-15 16:05:00] INFO  lora.anomaly_detector analyzing 300s window
[2024-01-15 16:05:02] INFO  Anomaly Detection Results:

  Frames analyzed:    47
  Anomalies found:    3

  [WARNING] FCnt Rollback - DevAddr: 260BABCD
    Previous FCnt: 3, Current FCnt: 0
    Timestamp: 2024-01-15T16:01:30Z
    Likely cause: ABP device power cycle (no persistent counter)

  [ALERT] Duplicate Frame - DevAddr: 260B1234
    FCnt: 1045, seen 2 times within 5s
    Timestamp: 2024-01-15T16:01:45Z
    Possible cause: Replay attack or gateway duplicate

  [INFO] FCnt Gap - DevAddr: 260B5678
    Expected: 527, Received: 530 (gap of 3)
    Timestamp: 2024-01-15T16:00:55Z
    Likely cause: Frames lost (interference or distance)
```

---

## Step 7: Traffic Profiling

Profile device behavior patterns:

```bash
srt run lora.traffic_profiler
```

This module builds behavioral profiles for each device:

- **Uplink interval**: How often the device transmits (periodic vs event-driven)
- **Payload patterns**: Consistent sizes suggest sensor readings
- **Duty cycle compliance**: Whether the device respects regional regulations
- **SF/BW/CR usage**: Data rate choices and ADR behavior
- **Active hours**: When the device is most active

**Expected output:**

```
[2024-01-15 16:06:00] INFO  lora.traffic_profiler analyzing device behavior
[2024-01-15 16:06:01] INFO  Traffic Profiles:

  Device: 260B1234
    Type: Periodic sensor
    Uplink interval: 60s (very consistent, std_dev: 0.3s)
    Payload size: 12 bytes (constant)
    SF/BW: SF7/125kHz (ADR active)
    Duty cycle usage: 0.2% (well within 1% limit)
    Active hours: 24/7

  Device: 260B5678
    Type: Event-driven
    Uplink interval: variable (10s - 300s)
    Payload size: 4-48 bytes (varies with event)
    SF/BW: SF10/125kHz (no ADR)
    Duty cycle usage: 0.05%
    Active hours: 08:00-18:00 (business hours only)

  Device: 260BABCD
    Type: ABP with counter issues
    Uplink interval: 120s (periodic)
    Payload size: 8 bytes
    SF/BW: SF12/125kHz (maximum range, low DR)
    Duty cycle usage: 1.8% [VIOLATION - exceeds 1% limit]
    Counter resets: 3 in last hour (power cycling)
```

---

## Step 8: Replay Demonstration

Demonstrate a replay attack against an ABP device:

```bash
srt run lora.replay_abp --param target_devaddr=260BABCD
```

> **Important**: Only perform this against devices you own or have explicit
> authorization to test. Replay attacks transmit radio signals.

### Why ABP Is Vulnerable

ABP devices with counter reset issues are vulnerable because:

1. The device resets FCnt to 0 on power cycle
2. The network server must accept low FCnt values (or disable counter check)
3. An attacker can record a frame and replay it later
4. The replayed frame has a valid MIC (computed with permanent keys)
5. The network server cannot distinguish replay from legitimate retransmission

**Expected output:**

```
[2024-01-15 16:07:00] INFO  lora.replay_abp targeting DevAddr: 260BABCD
[2024-01-15 16:07:01] INFO  Searching for captured frames from target...
[2024-01-15 16:07:01] INFO  Found 4 frames from 260BABCD

  Selected frame for replay:
    FCnt: 1, MType: Unconfirmed Data Up
    Payload: [12 bytes encrypted]
    Original timestamp: 2024-01-15T16:00:45Z

  [SIMULATED] Transmitting replay...
  [INFO] Frame replayed successfully
  [INFO] If network server has relaxed FCnt checking, this frame
         would be accepted and processed as legitimate uplink.

  Vulnerability Confirmed:
    - ABP activation (static keys)
    - FCnt counter resets observed
    - No server-side replay protection evident
```

---

## Step 9: Run Full LoRa Audit

Execute the comprehensive LoRaWAN audit scenario:

```bash
srt scenario scenarios/lora_deep_audit.yaml
```

This chains the following modules:

1. **lora.recon** (id: `capture`, 120s duration) - Passive frame capture
2. **lora.frame_decoder** (id: `decode`) - Full protocol decode
3. **lora.anomaly_detector** (id: `anomaly`) - Security anomaly detection
4. **lora.traffic_profiler** (id: `profile`) - Behavioral analysis
5. **lora.key_extractor** (id: `keys`) - Key recovery attempts
6. **lora.replay_abp** - Replay demonstration

Options: `bail_on_fail: false` (continues even if replay step fails).

**Expected duration**: 4-6 minutes (dominated by 120s capture window).

---

## Step 10: Generate Report with MITRE Mapping

Generate a report with MITRE ATT&CK technique mapping:

```bash
srt report --format json --session latest
```

### MITRE ATT&CK Techniques for LoRaWAN

| Technique ID | Name | Module |
|-------------|------|--------|
| T1040 | Network Sniffing | lora.recon |
| T1499 | Endpoint Denial of Service | lora.replay_abp |
| T1020 | Automated Exfiltration | lora.traffic_profiler |
| T1557 | Adversary-in-the-Middle | lora.key_extractor |

The report maps each module execution to relevant MITRE techniques,
providing context for how the findings relate to real-world attack patterns.

```json
{
  "session_id": "lora_deep_audit_20240115_160000",
  "mitre_mapping": [
    {
      "technique": "T1040",
      "name": "Network Sniffing",
      "module": "lora.recon",
      "evidence": "47 frames passively captured from 8 devices"
    },
    {
      "technique": "T1499",
      "name": "Endpoint Denial of Service",
      "module": "lora.replay_abp",
      "evidence": "ABP replay demonstrated against DevAddr 260BABCD"
    }
  ]
}
```

---

## Tips and Troubleshooting

### No Frames Captured

- **Wrong frequency**: Verify your region (EU868 vs US915 vs AS923)
- **Wrong SF**: Default may not match target devices. Try all SFs:
  `--param spreading_factors=7-12`
- **Gain too low**: Increase HackRF gain: LNA=32, VGA=40 is a good starting point
- **Antenna mismatch**: Use an antenna tuned for your target frequency
- **No devices in range**: LoRa range is long (km) but devices may transmit rarely

### HackRF Gain Settings

```bash
# Recommended starting gains for LoRa reception
# LNA (RF front-end): 0-40 dB in 8 dB steps
# VGA (baseband): 0-62 dB in 2 dB steps

# For nearby devices (< 1 km):
--param lna_gain=16 --param vga_gain=20

# For distant devices (1-5 km):
--param lna_gain=32 --param vga_gain=40

# Maximum sensitivity (risk of saturation from nearby transmitters):
--param lna_gain=40 --param vga_gain=62
```

### Antenna Selection

| Antenna Type | Gain | Best For |
|-------------|------|----------|
| Whip (stock HackRF) | 2 dBi | Close range, general purpose |
| Collinear | 5-8 dBi | Omnidirectional, medium range |
| Yagi | 10-15 dBi | Directional, long range |
| Discone | 2-5 dBi | Wideband, multi-protocol |

For EU868, a quarter-wave whip cut to 86mm (868 MHz quarter wavelength)
provides adequate reception for most urban deployments.

### Timing Considerations

- LoRaWAN devices may only transmit once every few minutes
- Set capture duration proportional to expected traffic:
  - Dense deployment: 60-120s sufficient
  - Sparse deployment: 600-1800s recommended
- Class A devices only transmit when they have data (event-driven may be very sparse)

### Interpreting FCnt Behavior

- **Monotonically increasing**: Normal, healthy operation
- **Reset to 0**: ABP device rebooted (potential vulnerability)
- **Large gaps**: Frames lost (check antenna, interference)
- **Duplicate values**: Possible replay attack in progress

---

*Previous: [BLE: From Capture to Visualization](02-ble-capture-to-visualization.md)*
*Next: [Cross-Protocol Correlation](04-cross-protocol-correlation.md)*
