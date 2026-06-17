# WiFi: From Capture to Visualization

A step-by-step tutorial for performing a complete WiFi security assessment
using sniffer-rt, from initial hardware setup through active exploitation
to final report generation and dashboard visualization.

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Step 1: Hardware Setup](#step-1-hardware-setup)
- [Step 2: Run WiFi Reconnaissance](#step-2-run-wifi-reconnaissance)
- [Step 3: Frame Dissection](#step-3-frame-dissection)
- [Step 4: View Results in Grafana](#step-4-view-results-in-grafana)
- [Step 5: Security Assessment](#step-5-security-assessment)
- [Step 6: Identify Targets](#step-6-identify-targets)
- [Step 7: Run Attack Chain](#step-7-run-attack-chain)
- [Step 8: Analyze Results](#step-8-analyze-results)
- [Step 9: Generate PDF Report](#step-9-generate-pdf-report)
- [Tips and Troubleshooting](#tips-and-troubleshooting)

---

## Introduction

In this tutorial, you will learn how to:

- Configure a USB WiFi adapter for monitor mode
- Perform passive WiFi reconnaissance to discover access points and clients
- Dissect captured frames to understand network structure
- Visualize captured data in real-time with Grafana dashboards
- Assess the security posture of discovered networks
- Execute an automated attack chain against a target network
- Generate professional reports with MITRE ATT&CK mapping

By the end, you will have a complete understanding of the WiFi audit workflow
within sniffer-rt, from raw radio capture to actionable intelligence.

---

## Prerequisites

Before starting, ensure you have:

- **Hardware**: An ALFA AWUS036ACH or similar adapter supporting monitor mode
- **Software**: sniffer-rt installed and configured (see `docs/INSTALLATION.md`)
- **Infrastructure**: TimescaleDB and Grafana running (via `docker-compose up -d`)
- **Authorization**: A signed authorization form (`authorization/authorization.yaml`)
  listing the target networks you are permitted to test
- **Knowledge**: Basic familiarity with 802.11 concepts (SSIDs, BSSIDs, channels)

---

## Step 1: Hardware Setup

### Verify Your Adapter

First, confirm your USB WiFi adapter is recognized:

```bash
iw dev
```

**Expected output:**

```
phy#1
    Interface wlan1
        ifindex 4
        wdev 0x100000001
        addr 00:c0:ca:ab:cd:ef
        type managed
        channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
```

### Enable Monitor Mode

Use `airmon-ng` to switch your adapter into monitor mode:

```bash
sudo airmon-ng start wlan1
```

**Expected output:**

```
PHY     Interface       Driver          Chipset

phy1    wlan1           88XXau          Realtek Semiconductor Corp. RTL8812AU

                (mac80211 monitor mode vif enabled for [phy1]wlan1 on [phy1]wlan1mon)
                (mac80211 station mode vif disabled for [phy1]wlan1)
```

### Verify Monitor Mode

Confirm the interface is now in monitor mode:

```bash
iw dev wlan1mon info
```

**Expected output:**

```
Interface wlan1mon
    ifindex 5
    wdev 0x100000002
    addr 00:c0:ca:ab:cd:ef
    type monitor
    wiphy 1
    channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
```

> **Note**: If your adapter does not support monitor mode natively, check
> `docs/HARDWARE-SETUP.md` for compatible chipset guidance.

---

## Step 2: Run WiFi Reconnaissance

Now perform a passive scan across all 2.4 GHz channels:

```bash
srt run wifi.recon --param duration_s=30 --param channels=1-13
```

This module passively captures:

- **Beacon frames**: Broadcast by APs every ~100ms, contain SSID, capabilities,
  supported rates, and security configuration
- **Probe requests**: Sent by clients searching for known networks (reveals PNL)
- **Probe responses**: AP replies to probe requests with full capabilities
- **Data frames**: Encrypted payloads between associated clients and APs
- **Authentication/Association**: Connection handshake frames

**Expected output:**

```
[2024-01-15 14:30:01] INFO  wifi.recon starting - scanning channels 1-13 for 30s
[2024-01-15 14:30:01] INFO  Hopping channels: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13
[2024-01-15 14:30:31] INFO  Scan complete
[2024-01-15 14:30:31] INFO  Results:
  APs discovered:     12
  Clients seen:       34
  Frames captured:    2847
  Probe requests:     156
  Unique SSIDs:       9 (3 hidden)
[2024-01-15 14:30:31] INFO  Data stored in TimescaleDB - session: wifi_recon_20240115_143001
```

All captured frames are automatically inserted into the `headers` hypertable
via `db.insert_header()` and published to MQTT topic `srt/headers/wifi`.

---

## Step 3: Frame Dissection

Run the frame dissector for detailed 802.11 analysis:

```bash
srt run wifi.frame_dissector --param duration_s=15
```

The frame dissector parses:

- **Information Elements (IEs)**: Every tagged parameter in beacons/probes
- **RSN (Robust Security Network)**: Cipher suites, AKM suites, PMF capability
- **HT/VHT/HE Capabilities**: 802.11n/ac/ax feature support
- **Vendor-Specific IEs**: WPS configuration, Apple AirDrop, Microsoft P2P
- **Country IE**: Regulatory domain and permitted channels/power

**Expected output:**

```
[2024-01-15 14:31:00] INFO  wifi.frame_dissector starting - live capture for 15s
[2024-01-15 14:31:15] INFO  Dissection complete
  Management frames:  412
  Control frames:     187
  Data frames:        963
  Beacons parsed:     298
  IEs extracted:      1547
  RSN elements:       12
  WPS detected:       3 APs
```

Key findings are stored as structured artifacts, allowing downstream modules
to reference discovered capabilities.

---

## Step 4: View Results in Grafana

### Access the Dashboard

Open your browser and navigate to [http://localhost:3000](http://localhost:3000).

Log in with default credentials (`admin` / `admin` on first setup).

### WiFi Deep-Dive Dashboard

Navigate to **Dashboards > sniffer-rt - WiFi Deep-Dive** (UID: `srt-wifi`).

This dashboard provides five core panels:

| Panel | Description |
|-------|-------------|
| **APs Discovered** | Table of all detected access points with SSID, BSSID, channel, encryption |
| **Clients per AP** | Bar chart showing client count per access point |
| **RSSI Over Time** | Time series graph of signal strength for each AP |
| **Frame Type Distribution** | Pie chart of management/control/data frame ratios |
| **Deauth Events** | Timeline of deauthentication frames (attack indicator) |

### WiFi Advanced Analysis Dashboard

Navigate to **Dashboards > sniffer-rt - WiFi Advanced Analysis** (UID: `srt-wifi-advanced`).

This dashboard provides deeper security-focused panels:

| Panel | Description |
|-------|-------------|
| **AP Security Grade Heatmap** | Color-coded security grades (A-F) for each AP |
| **Probe Request Timeline** | Time series of probe SSIDs over time |
| **Client Fingerprint Table** | Device type/OS identification from probe patterns |
| **Deauth Event Timeline** | Deauth frames with alert markers |
| **Channel Utilization** | Bar chart of frame count per channel |
| **Signal Strength Heatmap** | RSSI heatmap per AP over time |
| **Encryption Distribution** | Pie chart of WPA2/WPA3/WEP/OPEN counts |
| **Top Talkers** | Table of most active MACs by frame count |
| **Rogue AP Detection** | SSIDs appearing with multiple BSSIDs |
| **WPS-Enabled AP Alert** | List of APs with WPS enabled (attack surface) |

---

## Step 5: Security Assessment

Run the security assessor to grade each discovered network:

```bash
srt run wifi.security_assessor
```

### Grading System

Each access point receives a letter grade from A to F:

| Grade | Meaning | Typical Configuration |
|-------|---------|----------------------|
| **A** | Excellent | WPA3-SAE, PMF required, no WPS, strong ciphers only |
| **B** | Good | WPA2-CCMP with PMF capable, no WPS |
| **C** | Acceptable | WPA2-CCMP without PMF, no WPS |
| **D** | Weak | WPA2 with TKIP fallback, or WPS enabled |
| **E** | Poor | WPA with TKIP only, weak authentication |
| **F** | Critical | Open network, WEP, or severely misconfigured |

**Expected output:**

```
[2024-01-15 14:32:00] INFO  wifi.security_assessor - grading 12 APs
[2024-01-15 14:32:01] INFO  Results:
  Grade A:  2 APs
  Grade B:  3 APs
  Grade C:  4 APs
  Grade D:  2 APs
  Grade F:  1 AP (OPEN network)

  Common misconfigurations:
    - 3 APs have WPS enabled (downgrade attack vector)
    - 5 APs lack PMF (deauth vulnerability)
    - 2 APs allow TKIP cipher fallback
```

---

## Step 6: Identify Targets

Based on the security assessment, look for networks with:

- **OPEN encryption**: No password required, all traffic visible
- **WPS enabled**: Vulnerable to PIN brute-force (Reaver/Bully)
- **No PMF (Protected Management Frames)**: Vulnerable to deauthentication
- **TKIP fallback**: Legacy cipher with known weaknesses
- **WEP encryption**: Trivially crackable with sufficient IVs

The security report card artifact provides a machine-readable summary:

```bash
# View the last session's security report
srt report --format markdown --session latest
```

Look for entries with `security_grade: D` or worse in the report output.

---

## Step 7: Run Attack Chain

Execute the full WiFi deep audit scenario against a target:

```bash
srt scenario scenarios/wifi_deep_audit.yaml --var target_bssid=AA:BB:CC:DD:EE:FF
```

> **Important**: Only run against networks listed in your
> `authorization/authorization.yaml`. Unauthorized testing is illegal.

This scenario chains the following modules in sequence:

1. **wifi.recon** (id: `recon`) - Targeted scan to confirm AP presence
2. **wifi.frame_dissector** (id: `dissect`) - Deep frame analysis
3. **wifi.timing_analyzer** (id: `timing`) - Beacon timing, rogue detection
4. **wifi.security_assessor** (id: `security`) - Security grading
5. **wifi.deauth** - Send deauthentication to force client reconnection
6. **wifi.handshake_capture** - Capture 4-way WPA handshake
7. **wifi.pmkid** - Extract PMKID from AP (clientless attack)
8. **wifi.psk_crack** - Attempt PSK recovery with wordlist
9. **wifi.probe_fingerprinter** (id: `fingerprint`) - Client device identification
10. **wifi.signal_analyzer** (id: `signal`) - Signal quality analysis

The scenario uses variable substitution: results from step `recon` feed into
subsequent steps via `{{recon.artifacts[0].data[0].bssid}}`.

**Expected duration**: 3-5 minutes depending on handshake capture timing.

---

## Step 8: Analyze Results

After the scenario completes, examine the results:

```bash
srt report --format json --session latest
```

The JSON report structure:

```json
{
  "session_id": "wifi_deep_audit_20240115_143200",
  "scenario": "wifi_deep_audit",
  "timestamp": "2024-01-15T14:32:00Z",
  "results": [
    {
      "module_name": "wifi.recon",
      "status": "success",
      "duration_s": 30.2,
      "artifacts": [...],
      "metrics": {"aps_found": 12, "clients_found": 34}
    },
    {
      "module_name": "wifi.security_assessor",
      "status": "success",
      "artifacts": [{"type": "security_report", "data": {...}}],
      "metrics": {"grade_a": 2, "grade_f": 1}
    }
  ],
  "mitre_mapping": [
    {"technique": "T1040", "name": "Network Sniffing", "module": "wifi.recon"},
    {"technique": "T1557", "name": "Adversary-in-the-Middle", "module": "wifi.evil_twin"},
    {"technique": "T1110", "name": "Brute Force", "module": "wifi.psk_crack"}
  ]
}
```

Key sections to review:

- **results[].status**: Whether each module succeeded or failed
- **results[].artifacts**: Captured data (handshakes, PMKIDs, fingerprints)
- **results[].metrics**: Quantitative measurements
- **mitre_mapping**: MITRE ATT&CK techniques demonstrated

---

## Step 9: Generate PDF Report

Generate a professional PDF report for stakeholders:

```bash
srt report --format pdf --session wifi_deep_audit_20240115_143200
```

**Expected output:**

```
[2024-01-15 14:38:00] INFO  Generating PDF report...
[2024-01-15 14:38:02] INFO  Report saved: reports/wifi_deep_audit_20240115_143200.pdf
  Pages: 12
  Sections: Executive Summary, Findings, MITRE Mapping, Recommendations
```

The PDF is saved to the `reports/` directory. It includes:

- Executive summary with overall risk score
- Detailed findings per module
- MITRE ATT&CK technique coverage matrix
- Remediation recommendations (enable PMF, disable WPS, upgrade to WPA3)

---

## Tips and Troubleshooting

### Adapter Not Entering Monitor Mode

```bash
# Kill interfering processes first
sudo airmon-ng check kill

# Then try again
sudo airmon-ng start wlan1
```

### No Frames Captured

- Verify you are on the correct channel: `iw dev wlan1mon set channel 6`
- Check your adapter supports the band (2.4 GHz vs 5 GHz)
- Ensure the antenna is connected and the adapter LED is active
- Try a fixed channel instead of hopping: `--param channels=6`

### Permission Errors

```bash
# srt requires root for raw socket access
sudo srt run wifi.recon --param duration_s=10
```

### TimescaleDB Connection Failed

```bash
# Verify infrastructure is running
docker compose -f infra/docker-compose.yaml ps

# Check TimescaleDB is accepting connections
docker compose -f infra/docker-compose.yaml logs timescaledb | tail -5
```

### Grafana Shows No Data

- Confirm the time range selector covers your scan period (set to "Last 15 minutes")
- Verify the datasource connection in Grafana: **Settings > Data Sources > TimescaleDB**
- Check that the `headers` table has data:
  ```sql
  SELECT count(*) FROM headers WHERE protocol = 'wifi' AND ts > now() - interval '1 hour';
  ```

### Handshake Not Captured

- Client must be actively connected to the AP
- Try increasing deauth count: `--param deauth_count=5`
- Move closer to both the AP and the target client
- Some clients retry quickly; others may take 30+ seconds

---

*Next tutorial: [BLE: From Capture to Visualization](02-ble-capture-to-visualization.md)*
