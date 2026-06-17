# Testing Guide

How to use the sniffer-rt test runner to validate the platform before and after deployment.

---

## Overview of `run_all_tests.py`

The test runner at the project root validates the entire platform in 10 sequential phases:

| Phase | Name | What It Validates |
|-------|------|-------------------|
| 1 | Hardware Detection | Checks for ALFA adapter, HackRF, and BLE adapter presence |
| 2 | Syntax Validation | Parses all `.py` files with `ast.parse()` to catch syntax errors |
| 3 | Configuration Validation | Verifies `whitelist.yaml`, `authorization.yaml`, `hardware.yaml`, and scenario YAMLs |
| 4 | Module Registry | Imports all modules and confirms the expected registration count (22+) |
| 5 | Module Dry-Run | Instantiates every module, calls `run()` with `dry_run=True` |
| 6 | Infrastructure Check | Verifies Docker compose parses correctly, checks ports 5432/1883/3000 |
| 7 | Live WiFi Test | Puts ALFA into monitor mode, scans for 5 seconds, checks for captured frames |
| 8 | Live BLE Test | Runs a BLE scan for 3 seconds using hci0 |
| 9 | Live LoRa Test | Captures on 868.1 MHz for 2 seconds using HackRF |
| 10 | Report Generation Test | Generates a mock report to verify the template pipeline |

---

## Running Modes

### Syntax-Only Mode (CI / Quick Check)

Use this when you just want to confirm code is valid Python without executing anything:

```bash
python run_all_tests.py --syntax-only
```

This runs only Phase 2 (syntax validation). Fast, no hardware or root access needed.

**When to use:**
- In CI/CD pipelines
- After editing code, before committing
- Quick sanity check on a new machine

### Dry-Run Mode (Pre-Deployment)

Validates module logic without requiring hardware or root access:

```bash
python run_all_tests.py --dry-run
```

This runs Phases 2-5 (syntax, configuration, registry, dry-run). Modules execute their logic but skip actual hardware operations.

**When to use:**
- Before deploying to the Raspberry Pi
- Testing new module implementations
- Verifying configuration changes

### Full Mode (Final Validation)

Runs all 10 phases including live hardware tests:

```bash
sudo python run_all_tests.py
```

Requires root access (for monitor mode) and hardware connected.

**When to use:**
- Final validation on the target Raspberry Pi
- After hardware changes (new adapter, firmware update)
- Before running a live engagement

### Verbose Output

Add `--verbose` to any mode for detailed output:

```bash
sudo python run_all_tests.py --verbose
python run_all_tests.py --dry-run --verbose
```

---

## Interpreting Results

Each phase reports one of three statuses:

| Status | Meaning | Action |
|--------|---------|--------|
| **PASS** | Phase completed successfully | No action needed |
| **FAIL** | Something broke | Investigate and fix (see troubleshooting below) |
| **SKIP** | Prerequisites not met | Usually hardware not connected or dependency missing |

The final summary shows the overall pass/fail count:

```
  Summary: 8/10 phases passed, 2 skipped
  SKIPPED: Live WiFi Test, Live LoRa Test
  Result: PASS (skips are acceptable without hardware)
```

---

## Troubleshooting Each Phase

### Phase 1: Hardware Detection - SKIP

**Symptom:** All hardware checks report SKIP

**Cause:** Hardware not physically connected

**Solution:** Plug in ALFA adapter and HackRF. For BLE, the built-in Pi adapter should be available automatically.

### Phase 2: Syntax Validation - FAIL

**Symptom:** Reports a specific file with a syntax error

**Cause:** Python syntax error in source code

**Solution:** Fix the reported file. The error message includes the filename and line number:
```
  [FAIL] Syntax Validation -- src/srt/exploit/wifi/krack.py:42 unexpected indent
```

### Phase 3: Configuration Validation - FAIL

**Symptom:** YAML parse error or missing file

**Cause:** Malformed YAML or missing configuration file

**Solution:** Check the reported file for YAML syntax issues. Use an online YAML validator if needed.

### Phase 4: Module Registry - FAIL

**Symptom:** Module count less than expected

**Cause:** Import error in a module file (missing dependency, circular import)

**Solution:** Run with `--verbose` to see the specific ImportError. Check that all module files have correct `@register` decorators.

### Phase 5: Module Dry-Run - FAIL

**Symptom:** A module returns an error during dry-run

**Cause:** Logic error in the module's `run()` method

**Solution:** Run the specific module manually:
```bash
srt run <module-name> --target <bssid> --dry-run
```

### Phase 6: Infrastructure Check - SKIP/FAIL

**Symptom:** Ports not available or Docker compose parse error

**Cause:** Docker not running or infra stack not started

**Solution:**
```bash
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml ps
```

### Phase 7: Live WiFi Test - SKIP

**Symptom:** No frames captured

**Cause:** ALFA not connected, wrong channel, or interface not in monitor mode

**Solution:**
```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan1
sudo airodump-ng wlan1mon   # Should show nearby APs
```

### Phase 8: Live BLE Test - SKIP

**Symptom:** No BLE devices found

**Cause:** Bluetooth service down or no BLE devices nearby

**Solution:**
```bash
sudo systemctl restart bluetooth
sudo hcitool lescan   # Should show nearby BLE devices
```

### Phase 9: Live LoRa Test - SKIP

**Symptom:** No LoRa frames captured

**Cause:** HackRF not connected, wrong frequency, or no LoRa devices transmitting

**Solution:**
```bash
hackrf_info   # Verify HackRF is detected
# Check that LoRa devices are active on the configured frequency
```

### Phase 10: Report Generation - FAIL

**Symptom:** Template rendering fails

**Cause:** Missing template files or Jinja2 not installed

**Solution:** Verify templates exist:
```bash
ls templates/report.html templates/report.css
```

---

## Running from the Bash Wrapper

A convenience shell script is also available:

```bash
# Checks Python version, activates venv, sets PYTHONPATH
./run_all_tests.sh
./run_all_tests.sh --syntax-only
./run_all_tests.sh --dry-run
```

This wrapper handles environment setup automatically and is the recommended way to invoke the test runner on the Raspberry Pi.
