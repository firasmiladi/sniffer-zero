# Automated Scenarios: Building and Running Audit Workflows

A complete guide to the sniffer-rt scenario system, covering YAML syntax,
variable substitution, step chaining, loop mode, report generation, and
integration with system schedulers.

## Table of Contents

- [Introduction](#introduction)
- [What Are Scenarios](#what-are-scenarios)
- [Scenario YAML Structure](#scenario-yaml-structure)
- [Running a Scenario](#running-a-scenario)
- [Variable Substitution](#variable-substitution)
- [Step Chaining](#step-chaining)
- [Options Deep-Dive](#options-deep-dive)
- [Creating Custom Scenarios](#creating-custom-scenarios)
- [Loop Mode for Continuous Monitoring](#loop-mode-for-continuous-monitoring)
- [Reading Reports](#reading-reports)
- [Combining with Cron and Systemd](#combining-with-cron-and-systemd)
- [Troubleshooting](#troubleshooting)

---

## Introduction

In this tutorial, you will learn how to:

- Understand the scenario system architecture and purpose
- Read and write scenario YAML files
- Run scenarios with custom variable overrides
- Chain module outputs into subsequent steps
- Use loop mode for continuous monitoring deployments
- Interpret generated reports in JSON, Markdown, and PDF formats
- Schedule periodic audits with cron and systemd

Scenarios are the backbone of reproducible security assessments in sniffer-rt.
They encode complete audit workflows as declarative YAML files, ensuring that
assessments are consistent, documented, and repeatable.

---

## What Are Scenarios

A scenario is a YAML file that defines:

1. **What modules to run** (in order)
2. **What parameters to pass** to each module
3. **How modules connect** (outputs of one feeding into the next)
4. **What to do on failure** (bail or continue)
5. **How to report results** (format, destination)

### Why Scenarios Matter

- **Reproducibility**: Same YAML produces same assessment every time
- **Automation**: No manual intervention required during execution
- **Documentation**: The YAML file documents exactly what was tested
- **Sharing**: Teams can share and version-control assessment workflows
- **Compliance**: Prove to auditors exactly what tests were performed

### Available Scenarios

sniffer-rt ships with these pre-built scenarios:

| File | Purpose |
|------|---------|
| `scenarios/wifi_deep_audit.yaml` | Complete WiFi assessment + exploitation chain |
| `scenarios/ble_deep_audit.yaml` | Full BLE device security audit |
| `scenarios/lora_deep_audit.yaml` | LoRaWAN passive analysis + replay |
| `scenarios/full_deep_audit.yaml` | All protocols combined audit |
| `scenarios/continuous_monitor.yaml` | Long-running passive surveillance |

---

## Scenario YAML Structure

Every scenario follows this structure:

```yaml
# Comments describe the scenario purpose
name: scenario_name
description: >
  Multi-line description of what this scenario does,
  what it requires, and what it produces.

variables:
  target_bssid: "AA:BB:CC:DD:EE:FF"
  interface: "wlan0mon"
  duration: "30"

options:
  bail_on_fail: true
  report_format:
    - json
    - markdown
    - pdf
  loop: false
  loop_delay_s: 60
  dry_run: false

steps:
  - id: recon
    module: wifi.recon
    params:
      duration_s: "{{duration}}"
      channels: "1-13"
      interface: "{{interface}}"

  - id: security
    module: wifi.security_assessor
    params:
      target_bssid: "{{recon.artifacts[0].data[0].bssid}}"
```

### Top-Level Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Short identifier for the scenario |
| `description` | Yes | Human-readable explanation |
| `variables` | No | Default variable values |
| `options` | No | Execution behavior configuration |
| `steps` | Yes | Ordered list of modules to execute |

### Step Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | No | Identifier for referencing outputs in later steps |
| `module` | Yes | Registered module name (e.g., `wifi.recon`) |
| `params` | No | Key-value parameters passed to the module |

---

## Running a Scenario

### Basic Execution

```bash
srt scenario scenarios/wifi_deep_audit.yaml
```

This runs the scenario with all default variable values defined in the YAML.

### With Variable Overrides

Override variables from the command line:

```bash
srt scenario scenarios/wifi_deep_audit.yaml --var target_bssid=11:22:33:44:55:66
```

Multiple variables:

```bash
srt scenario scenarios/wifi_deep_audit.yaml \
  --var target_bssid=11:22:33:44:55:66 \
  --var target_channel=11 \
  --var interface=wlan1mon
```

### Dry Run Mode

Preview what would execute without actually running modules:

```bash
srt scenario scenarios/wifi_deep_audit.yaml --var dry_run=true
```

**Expected output:**

```
[DRY RUN] Scenario: wifi_deep_audit
[DRY RUN] Step 1: wifi.recon (id: recon)
  params: duration_s=30, channels=1-13, interface=wlan0mon
[DRY RUN] Step 2: wifi.frame_dissector (id: dissect)
  params: interface=wlan0mon
[DRY RUN] Step 3: wifi.timing_analyzer (id: timing)
  params: {}
...
[DRY RUN] 10 steps would execute. No modules were actually run.
```

---

## Variable Substitution

### Syntax

Variables use double-brace syntax: `{{variable_name}}`

### Resolution Order

When the orchestrator encounters `{{var_name}}`, it resolves in this order:

1. **CLI variables** (`--var key=value`) - highest priority
2. **Scenario variables** (defined in `variables:` block)
3. **Context variables** (set by previous step outputs)

### Examples

Simple variable:

```yaml
variables:
  target_mac: "AA:BB:CC:DD:EE:FF"

steps:
  - module: ble.gatt_enum
    params:
      target_mac: "{{target_mac}}"
```

Variable with CLI override:

```bash
# Overrides the default target_mac
srt scenario scenarios/ble_deep_audit.yaml --var target_mac=11:22:33:44:55:66
```

### Step Output References

Reference outputs from previous steps using their `id`:

```yaml
steps:
  - id: scan
    module: ble.recon
    params:
      duration_s: "20"

  - module: ble.gatt_enum
    params:
      # Use the first device discovered by the scan step
      target_mac: "{{scan.artifacts[0].data[0].mac}}"
```

The orchestrator builds a context dictionary as steps execute. Each step's
`AttackResult` (containing status, artifacts, metrics) is stored under its `id`.

---

## Step Chaining

Step chaining allows complex workflows where later steps depend on earlier
results.

### How It Works

1. Step with `id: recon` runs and produces an `AttackResult`
2. The result is stored in the orchestrator context as `context["recon"]`
3. Later steps reference it via `{{recon.field.subfield}}`
4. The orchestrator resolves the reference before passing params to the module

### Chaining Example: WiFi Deep Audit

```yaml
steps:
  # Step 1: Discover APs
  - id: recon
    module: wifi.recon
    params:
      duration_s: "30"
      channels: "1-13"

  # Step 2: Dissect frames from discovered APs
  - id: dissect
    module: wifi.frame_dissector
    params:
      duration_s: "15"

  # Step 3: Grade security using dissection results
  - id: security
    module: wifi.security_assessor
    params: {}

  # Step 4: Attack the weakest AP found
  - module: wifi.deauth
    params:
      target_bssid: "{{recon.artifacts[0].data[0].bssid}}"
      target_channel: "{{recon.artifacts[0].data[0].channel}}"

  # Step 5: Capture handshake after deauth
  - module: wifi.handshake_capture
    params:
      target_bssid: "{{recon.artifacts[0].data[0].bssid}}"
```

### Available Context Fields

After a step completes, these fields are accessible:

```
{{step_id.status}}              -> "success" or "failure"
{{step_id.artifacts}}           -> List of result artifacts
{{step_id.artifacts[0].type}}   -> Artifact type string
{{step_id.artifacts[0].data}}   -> Artifact data (list or dict)
{{step_id.metrics}}             -> Dict of measurements
{{step_id.metrics.key}}         -> Specific metric value
```

---

## Options Deep-Dive

### bail_on_fail

```yaml
options:
  bail_on_fail: true  # Stop on first module failure
```

- `true`: If any step returns status "failure", the scenario halts immediately.
  Use for critical chains where later steps depend on earlier success.
- `false`: Continue executing remaining steps regardless of individual failures.
  Use when steps are independent or partial results are still valuable.

### report_format

```yaml
options:
  report_format:
    - json      # Machine-readable structured data
    - markdown  # Human-readable formatted text
    - pdf       # Professional document for stakeholders
```

Multiple formats can be specified; all will be generated on completion.

### loop

```yaml
options:
  loop: true
  loop_delay_s: 30
```

- `loop: true`: After completing all steps, restart from the beginning
- `loop_delay_s`: Seconds to wait between iterations
- Runs indefinitely until interrupted (Ctrl+C or SIGTERM)
- Each iteration generates incremental data, not a new report

### dry_run

```yaml
options:
  dry_run: false
```

When `true`, prints what would execute without running any modules.
Useful for validating scenario syntax and variable resolution.

---

## Creating Custom Scenarios

### Step-by-Step Guide

**1. Define your objective:**

What question are you trying to answer? Example: "Is my smart lock
vulnerable to BLE attacks?"

**2. Choose modules:**

Select relevant modules from the registry:

```bash
srt list  # Shows all registered modules with descriptions
```

**3. Create the YAML file:**

```yaml
# scenarios/my_smart_lock_audit.yaml
name: smart_lock_audit
description: >
  Security assessment of BLE smart lock.
  Tests GATT access control, pairing strength,
  and unauthorized write capability.

variables:
  lock_mac: "AA:BB:CC:DD:EE:FF"
  scan_duration: "15"

options:
  bail_on_fail: false
  report_format:
    - json
    - markdown

steps:
  - id: discover
    module: ble.recon
    params:
      duration_s: "{{scan_duration}}"

  - id: enumerate
    module: ble.gatt_enum
    params:
      target_mac: "{{lock_mac}}"

  - id: security
    module: ble.gatt_security_assessor
    params:
      target_mac: "{{lock_mac}}"

  - id: pairing
    module: ble.pairing_analyzer
    params:
      target_mac: "{{lock_mac}}"

  - module: ble.unauth_write
    params:
      target_mac: "{{lock_mac}}"
```

**4. Validate syntax:**

```bash
python -c "import yaml; yaml.safe_load(open('scenarios/my_smart_lock_audit.yaml'))"
```

**5. Test with dry run:**

```bash
srt scenario scenarios/my_smart_lock_audit.yaml --var dry_run=true
```

**6. Execute:**

```bash
srt scenario scenarios/my_smart_lock_audit.yaml --var lock_mac=11:22:33:44:55:66
```

---

## Loop Mode for Continuous Monitoring

The `scenarios/continuous_monitor.yaml` demonstrates continuous passive
surveillance:

```yaml
name: continuous_monitor
description: >
  Continuous passive monitoring with anomaly detection on all protocols.
  Loops indefinitely through WiFi, BLE, and LoRa reconnaissance and
  analysis modules. Ideal for Raspberry Pi deployment with systemd.

options:
  loop: true
  loop_delay_s: 30
  bail_on_fail: false
  report_format:
    - json

steps:
  - module: wifi.recon
    params:
      duration_s: "120"
  - module: wifi.timing_analyzer
    params: {}
  - module: wifi.probe_fingerprinter
    params: {}
  - module: ble.recon
    params:
      duration_s: "60"
  - module: ble.mac_randomization_tracker
    params: {}
  - module: lora.recon
    params:
      duration_s: "120"
  - module: lora.anomaly_detector
    params: {}
  - module: lora.traffic_profiler
    params: {}
```

### How Loop Mode Works

1. All steps execute in order
2. After the last step completes, wait `loop_delay_s` seconds
3. Restart from step 1
4. Each iteration inserts new data into TimescaleDB
5. Grafana dashboards update in real-time as new data arrives
6. Anomaly alerts fire when thresholds are crossed

### Deployment Pattern

For always-on monitoring on a Raspberry Pi:

```bash
# Run as a background service (see systemd section below)
srt scenario scenarios/continuous_monitor.yaml
```

Each loop iteration takes approximately 5-6 minutes:
- WiFi recon: 120s
- WiFi analysis: ~5s
- BLE recon: 60s
- BLE analysis: ~5s
- LoRa recon: 120s
- LoRa analysis: ~5s
- Loop delay: 30s

Total cycle: ~330 seconds (5.5 minutes)

---

## Reading Reports

### JSON Format

The most detailed format, suitable for automation and further processing:

```bash
srt report --format json --session latest
```

```json
{
  "session_id": "wifi_deep_audit_20240115_143200",
  "scenario": "wifi_deep_audit",
  "started_at": "2024-01-15T14:32:00Z",
  "completed_at": "2024-01-15T14:37:45Z",
  "duration_s": 345,
  "status": "completed",
  "results": [
    {
      "step_id": "recon",
      "module_name": "wifi.recon",
      "status": "success",
      "started_at": "2024-01-15T14:32:00Z",
      "duration_s": 30.2,
      "artifacts": [
        {
          "type": "ap_list",
          "data": [
            {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "TargetNet", "channel": 6}
          ]
        }
      ],
      "metrics": {
        "aps_found": 12,
        "clients_found": 34,
        "frames_captured": 2847
      }
    }
  ],
  "mitre_mapping": [
    {"technique": "T1040", "name": "Network Sniffing", "module": "wifi.recon"}
  ],
  "summary": {
    "steps_total": 10,
    "steps_succeeded": 9,
    "steps_failed": 1,
    "critical_findings": 3,
    "high_findings": 5
  }
}
```

### Markdown Format

Human-readable format suitable for documentation:

```bash
srt report --format markdown --session latest
```

Produces a structured document with:
- Executive summary
- Per-module results with formatted tables
- Finding severity badges
- Remediation recommendations

### PDF Format

Professional format for stakeholder delivery:

```bash
srt report --format pdf --session latest
```

Includes all markdown content plus:
- Cover page with assessment metadata
- Table of contents
- Formatted charts and tables
- MITRE ATT&CK matrix visualization
- Digital signature of the assessor

---

## Combining with Cron and Systemd

### Systemd Service (Recommended)

The `deploy/systemd/srt-probe.service` file provides a systemd unit for
running sniffer-rt as a system service:

```bash
# Enable and start the probe service
sudo systemctl enable srt-probe.service
sudo systemctl start srt-probe.service

# Check status
sudo systemctl status srt-probe.service

# View logs
sudo journalctl -u srt-probe.service -f
```

### Cron for Periodic Audits

Schedule a full audit daily at 2 AM:

```bash
# Edit crontab
crontab -e

# Add this line:
0 2 * * * /usr/local/bin/srt scenario /opt/srt/scenarios/wifi_deep_audit.yaml --var target_bssid=AA:BB:CC:DD:EE:FF 2>&1 >> /var/log/srt-audit.log
```

### Weekly Comprehensive Audit

```bash
# Run full deep audit every Sunday at midnight
0 0 * * 0 /usr/local/bin/srt scenario /opt/srt/scenarios/full_deep_audit.yaml 2>&1 >> /var/log/srt-weekly.log
```

### Combining Continuous Monitor + Periodic Audits

A common deployment pattern:

1. **Continuous**: `srt scenario scenarios/continuous_monitor.yaml` runs as
   a systemd service, providing 24/7 passive monitoring and anomaly detection
2. **Weekly**: Cron job runs `full_deep_audit.yaml` once per week for
   comprehensive active assessment with reporting

---

## Troubleshooting

### Module Not Found

```
Error: Module 'wifi.recon2' not registered
```

- Check available modules: `srt list`
- Verify spelling matches exactly (case-sensitive)
- Ensure the module package is in the autodiscover path

### Variable Not Resolved

```
Error: Variable '{{target_mac}}' could not be resolved
```

- Check the variable is defined in `variables:` block or passed via `--var`
- Verify spelling matches exactly (case-sensitive)
- For step references, ensure the referenced step has an `id` field

### Step Reference Failed

```
Error: Cannot resolve '{{recon.artifacts[0].data[0].bssid}}' - step 'recon' has no artifacts
```

- The referenced step may have failed (check `bail_on_fail` setting)
- The step may not have produced the expected output format
- Add `bail_on_fail: true` to stop early when critical steps fail

### bail_on_fail Behavior

When `bail_on_fail: true`:
- Scenario stops at first failure
- Report only contains results up to the failure point
- Exit code is non-zero (useful for CI/CD integration)

When `bail_on_fail: false`:
- All steps execute regardless of individual failures
- Failed steps are recorded with status "failure" in the report
- Exit code is zero unless the scenario itself failed to parse

### YAML Syntax Errors

```
Error: while scanning a simple key...
```

Common YAML mistakes:
- Missing quotes around values containing special characters (`:`, `{`, `}`)
- Incorrect indentation (YAML uses spaces, not tabs)
- Missing `-` before list items in steps

Validate your YAML:

```bash
python -c "import yaml; yaml.safe_load(open('scenarios/my_scenario.yaml')); print('Valid')"
```

---

*Previous: [Cross-Protocol Correlation](04-cross-protocol-correlation.md)*
*Next: [Grafana Dashboard Guide](06-grafana-guide.md)*
