# Grafana Dashboard Guide: Real-Time Monitoring and Analysis

A comprehensive guide to using Grafana dashboards with sniffer-rt for
real-time RF monitoring, security analysis, and data exploration.

## Table of Contents

- [Introduction](#introduction)
- [Accessing Grafana](#accessing-grafana)
- [Dashboard Overview](#dashboard-overview)
- [Navigating the Overview Dashboard](#navigating-the-overview-dashboard)
- [WiFi Dashboards](#wifi-dashboards)
- [BLE Dashboards](#ble-dashboards)
- [LoRaWAN Dashboards](#lorawan-dashboards)
- [Security Overview](#security-overview)
- [Attacks and Exploits Dashboard](#attacks-and-exploits-dashboard)
- [Creating Custom Panels](#creating-custom-panels)
- [Setting Up Alerts](#setting-up-alerts)
- [Time Range and Refresh](#time-range-and-refresh)
- [Filtering and Drilling Down](#filtering-and-drilling-down)
- [Exporting Data](#exporting-data)
- [Tips and Troubleshooting](#tips-and-troubleshooting)

---

## Introduction

Grafana provides real-time visualization of all data collected by sniffer-rt.
As modules execute, data flows into TimescaleDB and immediately appears in
the dashboards. This enables:

- Live monitoring during active assessments
- Historical analysis of RF environment changes
- Anomaly detection through visual pattern recognition
- Report generation with embedded visualizations
- Alert-driven notification of security events

The sniffer-rt Grafana deployment includes 9 pre-configured dashboards
covering all protocols and analysis perspectives.

---

## Accessing Grafana

### Default URL and Credentials

Navigate to [http://localhost:3000](http://localhost:3000) in your web browser.

**First-time login:**
- Username: `admin`
- Password: `admin`

You will be prompted to change the password on first login.

### Verifying the Data Source

After login, verify TimescaleDB is connected:

1. Navigate to **Connections > Data Sources**
2. Click on **TimescaleDB**
3. Click **Test** at the bottom of the page
4. You should see: "Database Connection OK"

If the test fails, verify that the TimescaleDB container is running:

```bash
docker compose -f infra/docker-compose.yaml ps timescaledb
```

---

## Dashboard Overview

sniffer-rt ships with 9 dashboards organized by protocol and function:

| Dashboard | UID | Purpose |
|-----------|-----|---------|
| Overview | `srt-overview` | High-level system status across all protocols |
| WiFi Deep-Dive | `srt-wifi` | Core WiFi monitoring (APs, clients, RSSI) |
| WiFi Advanced Analysis | `srt-wifi-advanced` | Security grades, fingerprints, rogue detection |
| BLE Deep-Dive | `srt-ble` | BLE device inventory, advertising, pairing |
| BLE Advanced Analysis | `srt-ble-advanced` | GATT security, MAC tracking, proximity |
| LoRaWAN Deep-Dive | `srt-lora` | LoRa devices, FCnt, channel usage |
| LoRaWAN Advanced Analysis | `srt-lora-advanced` | Anomalies, traffic profiles, join requests |
| Security Overview | `srt-security-overview` | Cross-protocol vulnerability summary |
| Attacks and Exploits | `srt-attacks` | Module execution results and success rates |

Access dashboards via **Dashboards** in the left sidebar menu.

---

## Navigating the Overview Dashboard

Dashboard: **sniffer-rt - Overview** (UID: `srt-overview`)

This is your starting point for situational awareness.

### Panels

| Panel | Type | Description |
|-------|------|-------------|
| **Total Frames Captured** | Stat | Total number of frames in the database |
| **Active Sessions** | Stat | Currently running module sessions |
| **Unique Devices (1h)** | Stat | Distinct device identifiers seen in last hour |
| **Protocols Active** | Stat | Count of protocols with recent data |
| **Frames per Protocol** | Bar chart | Frame count breakdown by WiFi/BLE/LoRa |
| **Recently Seen Devices** | Table | Last 50 devices with timestamp, protocol, identifier |
| **Flow Matrix** | Table | Communication patterns between sources and destinations |

### Usage Pattern

Start with the Overview to answer:
- Is data flowing? (Total Frames increasing)
- Which protocols are active? (Protocols Active stat)
- Are there new devices? (Recently Seen Devices table)

Then drill into protocol-specific dashboards for deeper analysis.

---

## WiFi Dashboards

### WiFi Deep-Dive (srt-wifi)

Core WiFi monitoring dashboard with 5 panels:

**APs Discovered** (Table)
- Lists all detected access points
- Columns: BSSID, SSID, Channel, Encryption, Last Seen, Frame Count
- Sort by any column to find busiest or newest APs

**Clients per AP** (Bar Chart)
- Shows client count for each access point
- Quickly identifies the most popular networks
- High client count = higher value target

**RSSI Over Time** (Time Series)
- Signal strength for each AP over the scan duration
- Stable RSSI = stationary AP
- Fluctuating RSSI = mobile device or interference

**Frame Type Distribution** (Pie Chart)
- Breakdown of Management, Control, and Data frames
- High management ratio = many beacons (low traffic network)
- High data ratio = active usage

**Deauth Events** (Time Series)
- Deauthentication frames over time
- Spikes indicate potential attacks in progress
- Background level = normal client roaming

### WiFi Advanced Analysis (srt-wifi-advanced)

Security-focused WiFi dashboard with 10 panels:

**AP Security Grade Heatmap** (Stat)
- Color-coded grades (A=green, F=red) for each AP
- Quickly spot weak networks at a glance

**Probe Request Timeline** (Time Series)
- Probe SSIDs over time
- Reveals client PNL (Preferred Network List)
- Identify devices searching for specific networks

**Client Fingerprint Table** (Table)
- Device type and OS identification from probe patterns
- Columns: MAC, Device Type, OS, First Seen, Probe Count

**Deauth Event Timeline** (Time Series)
- Deauth frames with alert markers highlighting anomalies
- Correlate with your own attack execution timing

**Channel Utilization** (Bar Chart)
- Frame count per channel
- Identify congested vs quiet channels
- Useful for choosing attack channels

**Signal Strength Heatmap** (Heatmap)
- RSSI values per AP over time as a heat map
- Visual representation of signal stability

**Encryption Distribution** (Pie Chart)
- Breakdown of WPA3/WPA2/WPA/WEP/OPEN across all APs
- Quick assessment of overall network security posture

**Top Talkers** (Table)
- Most active MAC addresses by frame count
- Identifies high-value targets and busy clients

**Rogue AP Detection** (Table)
- SSIDs appearing from multiple BSSIDs
- Indicates possible evil twin or rogue AP deployment

**WPS-Enabled AP Alert** (Table)
- List of APs with WPS active
- Each represents a potential attack vector (PIN brute-force)

---

## BLE Dashboards

### BLE Deep-Dive (srt-ble)

Core BLE monitoring with 5 panels:

**BLE Advertising Devices** (Table)
- All discovered BLE devices with name, MAC, RSSI, services
- Random vs public MAC address indicator

**MAC Randomization Tracking** (Time Series)
- Visual tracking of MAC address changes over time
- Groups correlated addresses visually

**GATT Services Discovered** (Table)
- Enumerated services per device
- Service UUIDs with human-readable names

**Pairing Events Timeline** (Time Series)
- Pairing attempts and outcomes over time
- Success/failure indicators

**Vendor Distribution** (Pie Chart)
- Manufacturer breakdown from advertising data and OUI lookup

### BLE Advanced Analysis (srt-ble-advanced)

Security-focused BLE dashboard with 8 panels:

**Device Inventory with Security Grades** (Table)
- Complete device list with security grade (A-F)
- Sortable by grade to find weakest devices

**MAC Randomization Group View** (Stat)
- Shows unique MAC count vs estimated physical devices
- Higher ratio = more randomization observed

**GATT Vulnerability Summary** (Table)
- Unprotected characteristics per device
- Filterable by severity (Critical/High/Medium/Low)

**Pairing Method Distribution** (Pie Chart)
- Breakdown of Just Works / Passkey / Numeric Comparison / OOB
- Large "Just Works" slice = many vulnerable devices

**Advertising Interval Analysis** (Time Series)
- Advertising intervals per device over time
- Useful for fingerprinting and correlation

**Manufacturer Distribution** (Bar Chart)
- Device count per manufacturer
- Identifies dominant vendors in the environment

**Device Proximity Estimation** (Gauge)
- RSSI-to-distance mapping for selected devices
- Color-coded zones (close/medium/far)

**Tracker Detection** (Table)
- Detected Apple AirTag, Tile, Samsung SmartTag beacons
- Privacy-relevant: identifies tracking devices in the area

---

## LoRaWAN Dashboards

### LoRaWAN Deep-Dive (srt-lora)

Core LoRaWAN monitoring with 5 panels:

**Active LoRa Devices** (Stat)
- Count of unique DevAddrs seen in the time window

**FCnt Progression** (Time Series)
- Frame counter values over time per device
- Should be monotonically increasing
- Gaps = lost frames; decreases = counter reset or replay

**Frame Type Distribution** (Pie Chart)
- Breakdown by MType (JoinRequest, Unconfirmed Up, Confirmed Up, etc.)

**Channel Usage (EU868)** (Bar Chart)
- Frame count per frequency channel
- Even distribution = healthy network; skewed = possible issues

**Anomaly Alerts (FCnt Rollback / DevNonce Reuse)** (Table)
- Security-relevant anomaly events
- Each row links to the specific frame that triggered the alert

### LoRaWAN Advanced Analysis (srt-lora-advanced)

Deep analysis dashboard with 8 panels:

**Device Activity Timeline** (Time Series)
- FCnt per DevAddr over time
- Multiple devices plotted together for comparison

**Anomaly Event Log** (Table)
- All detected anomalies with timestamp, type, DevAddr, details
- Filter by anomaly type for focused investigation

**Channel Usage Distribution** (Bar Chart)
- Detailed frequency usage across all observed channels

**SF/DR Distribution** (Pie Chart)
- Spreading Factor usage breakdown
- SF12 dominant = range issues; SF7 dominant = healthy network

**Uplink Interval Analysis** (Time Series)
- Time between consecutive frames per device
- Regular intervals = periodic sensor; irregular = event-driven

**Payload Size Distribution** (Histogram)
- FRMPayload length distribution
- Helps identify device types by payload pattern

**Join Request Activity** (Time Series)
- JoinRequest count over time
- Spike = new device deployment or rejoin storm

**Network Health Score** (Stat)
- Computed from anomaly rate, counter health, timing regularity
- 0-100 score with color coding (green/yellow/red)

---

## Security Overview

Dashboard: **sniffer-rt - Security Overview** (UID: `srt-security-overview`)

Cross-protocol security summary with 7 panels:

**Overall Security Posture** (Stat)
- Single score representing aggregate security state
- Updated in real-time as new findings arrive

**Critical Vulnerabilities** (Table)
- Highest-severity findings across all protocols
- Columns: Protocol, Device, Finding, Severity, Module

**MITRE ATT&CK Coverage** (Table)
- Techniques triggered during assessment
- Maps to MITRE ATT&CK for IoT framework

**Active Alerts** (Alert List)
- Real-time alert display from all configured rules
- Color-coded by severity (red=critical, orange=warning)

**Protocol Breakdown** (Bar Chart)
- Finding count per protocol
- Shows which protocol has the most vulnerabilities

**Discovery Timeline** (Time Series)
- New device discoveries over time
- Sudden spikes may indicate previously hidden devices

**Top Vulnerable Devices** (Table)
- Devices sorted by total vulnerability count
- Cross-protocol aggregation per physical device

---

## Attacks and Exploits Dashboard

Dashboard: **sniffer-rt - Attack Results** (UID: `srt-attacks`)

Module execution tracking with 8 panels:

| Panel | Type | Description |
|-------|------|-------------|
| **Total Module Executions** | Stat | Count of all module runs |
| **Secrets Captured** | Stat | Handshakes, PMKIDs, keys recovered |
| **Success Rate** | Stat | Percentage of successful module executions |
| **Unique MITRE Techniques** | Stat | Distinct ATT&CK techniques demonstrated |
| **Module Execution Log** | Table | Chronological log of all module runs with status |
| **Success / Failure Rate by Module** | Bar Chart | Per-module success percentage |
| **Risk Distribution** | Pie Chart | Module risk levels (passive/low/medium/high/critical) |
| **MITRE ATT&CK Coverage** | Table | Technique coverage across all modules |

---

## Creating Custom Panels

### Adding a New Panel

1. Open any dashboard
2. Click **Edit** (pencil icon top right)
3. Click **Add** > **Visualization**
4. Select visualization type (Table, Time Series, Stat, etc.)
5. Write your SQL query in the Query editor

### Writing rawSql Queries

All sniffer-rt data lives in the `headers` hypertable with these columns:

| Column | Type | Description |
|--------|------|-------------|
| `ts` | timestamptz | Timestamp of the frame/event |
| `protocol` | text | Protocol name (wifi, ble, lora) |
| `src` | text | Source address (MAC, DevAddr) |
| `dst` | text | Destination address |
| `channel` | int | Channel number |
| `freq_hz` | bigint | Frequency in Hz |
| `rssi_dbm` | int | Signal strength in dBm |
| `fields` | jsonb | Protocol-specific data as JSON |

### Example Queries

**Count frames per protocol in last hour:**

```sql
SELECT
  protocol,
  count(*) as frame_count
FROM headers
WHERE ts > now() - interval '1 hour'
GROUP BY protocol
ORDER BY frame_count DESC;
```

**WiFi APs with client count:**

```sql
SELECT
  src as bssid,
  fields->>'ssid' as ssid,
  count(DISTINCT dst) as client_count,
  avg(rssi_dbm) as avg_rssi
FROM headers
WHERE protocol = 'wifi'
  AND fields->>'frame_type' = 'beacon'
  AND ts > now() - interval '30 minutes'
GROUP BY src, fields->>'ssid'
ORDER BY client_count DESC;
```

**BLE devices by manufacturer:**

```sql
SELECT
  fields->>'manufacturer' as manufacturer,
  count(DISTINCT src) as device_count
FROM headers
WHERE protocol = 'ble'
  AND ts > now() - interval '1 hour'
  AND fields->>'manufacturer' IS NOT NULL
GROUP BY fields->>'manufacturer'
ORDER BY device_count DESC;
```

**LoRa FCnt progression for a specific device:**

```sql
SELECT
  ts as time,
  (fields->>'fcnt')::int as fcnt
FROM headers
WHERE protocol = 'lora'
  AND src = '260B1234'
  AND ts > now() - interval '2 hours'
ORDER BY ts;
```

**Anomalies in the last 24 hours:**

```sql
SELECT
  ts,
  fields->>'anomaly_type' as type,
  src as device,
  fields->>'detail' as detail
FROM headers
WHERE protocol = 'lora'
  AND fields->>'anomaly_type' IS NOT NULL
  AND ts > now() - interval '24 hours'
ORDER BY ts DESC;
```

### Panel Configuration Tips

- Set the datasource to **TimescaleDB** (uid: `TimescaleDB`)
- For time series, ensure your query returns a `time` column
- Use `$__timeFilter(ts)` macro for automatic time range filtering
- Set refresh interval to match your scan frequency

---

## Setting Up Alerts

### How Alerting Works

Grafana alerting is configured via `infra/grafana/provisioning/alerting/rules.yaml`.
Rules define SQL conditions that trigger notifications when met.

### Alert Rule Structure

```yaml
groups:
  - name: srt-security-alerts
    interval: 60s
    rules:
      - uid: alert_uid
        title: "Alert Title"
        condition: C
        data:
          - refId: A
            datasourceUid: TimescaleDB
            model:
              rawSql: |
                SELECT count(*) as value
                FROM headers
                WHERE protocol = 'wifi'
                  AND fields->>'frame_subtype' = 'deauth'
                  AND ts > now() - interval '1 minute'
        annotations:
          summary: "High deauth rate detected"
```

### Pre-Configured Alerts

sniffer-rt ships with alerts for:

- **Deauth flood**: More than 10 deauth frames per minute from same source
- **New unknown device**: Device not seen in previous 24 hours appears
- **LoRa FCnt rollback**: Frame counter decrease detected
- **LoRa DevNonce reuse**: Same DevNonce used in multiple JoinRequests
- **BLE unprotected characteristic**: Sensitive characteristic with no encryption
- **Signal anomaly**: Sudden RSSI change exceeding 20 dB within 1 minute
- **New device not in whitelist**: Unauthorized device detected
- **LoRa ABP replay indicator**: Duplicate frame with same FCnt

### Customizing Thresholds

Edit `infra/grafana/provisioning/alerting/rules.yaml`:

```yaml
# Change deauth threshold from 10 to 5 frames
rawSql: |
  SELECT count(*) as value
  FROM headers
  WHERE protocol = 'wifi'
    AND fields->>'frame_subtype' = 'deauth'
    AND ts > now() - interval '1 minute'
  HAVING count(*) > 5
```

After modifying, restart Grafana to reload the provisioned rules:

```bash
docker compose -f infra/docker-compose.yaml restart grafana
```

### Notification Channels

Configure where alerts are sent:

- **Email**: SMTP configuration in Grafana settings
- **Slack/Discord**: Webhook URL in notification policies
- **MQTT**: Publish alert to `srt/alerts` topic (custom contact point)

---

## Time Range and Refresh

### Selecting Time Ranges

Use the time picker in the top-right corner of any dashboard:

| Option | Use Case |
|--------|----------|
| Last 5 minutes | Active scanning, real-time monitoring |
| Last 15 minutes | Recent scan results |
| Last 1 hour | Current session overview |
| Last 6 hours | Extended monitoring period |
| Last 24 hours | Daily review |
| Last 7 days | Weekly trend analysis |
| Custom range | Specific assessment window |

### Auto-Refresh Intervals

Set the refresh interval to match your scan cadence:

| Interval | Use Case |
|----------|----------|
| 5s | Active real-time monitoring during scanning |
| 30s | Continuous monitoring mode |
| 1m | Normal dashboard viewing |
| Off | Historical analysis (no refresh needed) |

### Relative vs Absolute Time

- **Relative** (e.g., "Last 1 hour"): Dashboard always shows recent data.
  Good for monitoring.
- **Absolute** (e.g., "Jan 15 14:00 - 15:00"): Dashboard shows a fixed
  time window. Good for reviewing specific scan sessions.

---

## Filtering and Drilling Down

### Using Template Variables

Dashboards support variable-based filtering. Common variables:

- **Protocol**: Filter all panels to a specific protocol
- **Device MAC**: Show only data for a specific device
- **Time window**: Adjust the analysis period

### Filtering by Device

In table panels, click a device MAC address to filter the entire dashboard
to that device.

Alternatively, add a manual filter:

1. Click the panel title
2. Select **Explore**
3. Modify the SQL query to add a WHERE clause:
   ```sql
   WHERE src = 'AA:BB:CC:DD:EE:FF'
   ```

### Drilling From Overview to Detail

Recommended workflow:

1. Start at **Overview** dashboard - get the big picture
2. Note interesting devices or protocols
3. Navigate to the protocol-specific dashboard (WiFi/BLE/LoRa)
4. Use the Advanced dashboard for security analysis
5. Check **Security Overview** for cross-protocol correlations
6. Review **Attacks and Exploits** for module execution history

---

## Exporting Data

### CSV Export from Panels

1. Hover over any panel
2. Click the panel title
3. Select **Inspect > Data**
4. Click **Download CSV**

This exports the current query results as a CSV file.

### API Access for Automation

Grafana provides a REST API for programmatic data access:

```bash
# Query a specific panel's data via API
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://localhost:3000/api/ds/query" \
  -H "Content-Type: application/json" \
  -d '{
    "queries": [{
      "datasourceId": 1,
      "rawSql": "SELECT * FROM headers WHERE ts > now() - interval '\''1 hour'\'' LIMIT 100",
      "format": "table"
    }]
  }'
```

### Dashboard Snapshots

Create a snapshot for sharing (read-only, time-frozen):

1. Open the dashboard
2. Click **Share** (share icon)
3. Select **Snapshot**
4. Click **Publish to snapshot**

---

## Tips and Troubleshooting

### Dashboard Not Loading

- **Check Grafana is running**: `docker compose -f infra/docker-compose.yaml ps grafana`
- **Check port binding**: Verify port 3000 is not in use by another service
- **Check provisioning**: Dashboards are auto-loaded from
  `infra/grafana/provisioning/dashboards/json/`

### No Data Displayed

- **Time range**: Ensure the time picker covers your scan period
- **Data source**: Verify TimescaleDB connection in Data Sources settings
- **Protocol filter**: Check you are looking at the correct protocol
- **Module execution**: Confirm modules ran successfully (`srt report --session latest`)
- **Direct query test**:
  ```sql
  SELECT count(*) FROM headers WHERE ts > now() - interval '1 hour';
  ```

### Slow Dashboard Performance

With large datasets (millions of rows), some queries may be slow:

- Narrow the time range to reduce data scanned
- Use TimescaleDB continuous aggregates for long-term views
- Add indexes on commonly filtered fields
- Consider data retention policies to automatically drop old data

### Panel Shows "No Data"

Common causes:
- The module has not been run yet (no data in the table)
- The panel filters on a specific protocol that has no recent data
- JSON field path in the query does not match actual data structure
- The `$__timeFilter` macro is filtering out all rows

### Custom Dashboard Best Practices

- Clone an existing dashboard before modifying (use **Save As**)
- Use meaningful panel titles that describe the insight
- Set appropriate refresh rates (too fast = performance impact)
- Document custom queries in panel descriptions
- Use row-level organization for related panels

---

*Previous: [Automated Scenarios](05-automated-scenarios.md)*
*This is the final tutorial in the series.*
