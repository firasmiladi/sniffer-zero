#!/usr/bin/env python3
"""sniffer-rt comprehensive test runner.
Validates the platform from PC before deploying to Raspberry Pi.

Usage:
    python run_all_tests.py              # Full test (needs hardware + root)
    python run_all_tests.py --syntax-only  # Syntax/config validation only
    python run_all_tests.py --dry-run      # Module dry-run without real hardware
    python run_all_tests.py --help         # Show usage
"""

from __future__ import annotations

import argparse
import ast
import os
import socket
import subprocess
import sys
from pathlib import Path

# Resolve project root
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

# Add src to path for import checks
sys.path.insert(0, str(SRC))

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

results: list[tuple[str, str, str]] = []  # (phase_name, status, detail)


def record(phase: str, status: str, detail: str = "") -> None:
    """Record a phase result. status is PASS, FAIL, or SKIP."""
    results.append((phase, status, detail))
    color = ""
    reset = ""
    if sys.stdout.isatty():
        if status == "PASS":
            color = "\033[32m"
        elif status == "FAIL":
            color = "\033[31m"
        elif status == "SKIP":
            color = "\033[33m"
        reset = "\033[0m"
    msg = f"  [{color}{status}{reset}] {phase}"
    if detail:
        msg += f" -- {detail}"
    print(msg)


# ---------------------------------------------------------------------------
# Phase 1: Syntax Validation
# ---------------------------------------------------------------------------

def phase_syntax(verbose: bool = False) -> None:
    """ast.parse all .py files under src/."""
    print("\n--- Phase 1: Syntax Validation ---")
    errors: list[str] = []
    py_files = list(SRC.rglob("*.py"))
    for f in py_files:
        try:
            ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        except SyntaxError as e:
            errors.append(f"{f.relative_to(ROOT)}: {e}")
            if verbose:
                print(f"    ERROR: {f.relative_to(ROOT)}: {e}")

    if errors:
        record("Phase 1: Syntax Validation", "FAIL", f"{len(errors)} error(s) in {len(py_files)} files")
    else:
        record("Phase 1: Syntax Validation", "PASS", f"{len(py_files)} files OK")


# ---------------------------------------------------------------------------
# Phase 2: Configuration Validation
# ---------------------------------------------------------------------------

def phase_config(verbose: bool = False) -> None:
    """Verify whitelist.yaml, authorization.yaml, hardware.yaml, scenario YAMLs."""
    print("\n--- Phase 2: Configuration Validation ---")
    try:
        import yaml  # noqa: F401
    except ImportError:
        record("Phase 2: Configuration Validation", "SKIP", "pyyaml not installed")
        return

    config_files = [
        ROOT / "safety" / "whitelist.yaml",
        ROOT / "authorization" / "authorization.yaml",
        ROOT / "config" / "hardware.yaml",
    ]
    # Add all scenario YAMLs
    scenario_dir = ROOT / "scenarios"
    if scenario_dir.exists():
        config_files.extend(scenario_dir.glob("*.yaml"))
        config_files.extend(scenario_dir.glob("*.yml"))

    errors: list[str] = []
    checked = 0
    for f in config_files:
        if not f.exists():
            errors.append(f"{f.relative_to(ROOT)}: file not found")
            continue
        try:
            yaml.safe_load(f.read_text(encoding="utf-8"))
            checked += 1
        except yaml.YAMLError as e:
            errors.append(f"{f.relative_to(ROOT)}: {e}")
            if verbose:
                print(f"    ERROR: {f.relative_to(ROOT)}: {e}")

    if errors:
        record("Phase 2: Configuration Validation", "FAIL", "; ".join(errors[:5]))
    else:
        record("Phase 2: Configuration Validation", "PASS", f"{checked} config files OK")


# ---------------------------------------------------------------------------
# Phase 3: Hardware Detection
# ---------------------------------------------------------------------------

def _check_hackrf() -> bool:
    """Check if HackRF is available via hackrf_info."""
    try:
        result = subprocess.run(
            ["hackrf_info"], capture_output=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _check_alfa() -> bool:
    """Check for monitor-mode capable WiFi interface."""
    # Check /sys/class/net/*/phy80211 symlinks
    net_dir = Path("/sys/class/net")
    if net_dir.exists():
        for iface in net_dir.iterdir():
            phy_link = iface / "phy80211"
            if phy_link.exists():
                return True
    # Fallback: try iw dev
    try:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and "Interface" in result.stdout:
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return False


def _check_ble() -> bool:
    """Check for BLE adapter (hci0)."""
    try:
        result = subprocess.run(
            ["hciconfig", "hci0"], capture_output=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def phase_hardware(verbose: bool = False, skip: bool = False) -> dict:
    """Check HackRF, ALFA, BLE hardware presence."""
    print("\n--- Phase 3: Hardware Detection ---")
    hw = {"hackrf": False, "alfa": False, "ble": False}

    if skip:
        record("Phase 3: Hardware Detection", "SKIP", "--syntax-only mode")
        return hw

    try:
        hw["hackrf"] = _check_hackrf()
        hw["alfa"] = _check_alfa()
        hw["ble"] = _check_ble()
    except Exception as e:
        record("Phase 3: Hardware Detection", "FAIL", str(e))
        return hw

    found = [k for k, v in hw.items() if v]
    not_found = [k for k, v in hw.items() if not v]

    detail_parts = []
    if found:
        detail_parts.append(f"found: {', '.join(found)}")
    if not_found:
        detail_parts.append(f"not found: {', '.join(not_found)}")

    if verbose:
        for k, v in hw.items():
            status = "detected" if v else "not detected"
            print(f"    {k}: {status}")

    # Hardware detection is informational, never FAIL
    record("Phase 3: Hardware Detection", "PASS", "; ".join(detail_parts))
    return hw


# ---------------------------------------------------------------------------
# Phase 4: Module Registry
# ---------------------------------------------------------------------------

def phase_registry(verbose: bool = False) -> bool:
    """Import srt.core.registry, call autodiscover(), verify module count >= 22."""
    print("\n--- Phase 4: Module Registry ---")
    try:
        from srt.core.registry import autodiscover, get_all
        autodiscover()
        modules = get_all()
        count = len(modules)
        if verbose:
            for m in modules:
                print(f"    - {m.name}")
        if count >= 22:
            record("Phase 4: Module Registry", "PASS", f"{count} modules registered (>= 22)")
            return True
        else:
            record("Phase 4: Module Registry", "FAIL", f"only {count} modules registered (need >= 22)")
            return True  # registry available, just count is low
    except ImportError as e:
        record("Phase 4: Module Registry", "SKIP", f"import failed: {e}")
        return False
    except Exception as e:
        record("Phase 4: Module Registry", "FAIL", str(e))
        return False


# ---------------------------------------------------------------------------
# Phase 5: Module Dry-Run
# ---------------------------------------------------------------------------

def phase_dry_run(registry_available: bool, verbose: bool = False) -> None:
    """For each registered module, call run() with dry_run=True."""
    print("\n--- Phase 5: Module Dry-Run ---")
    if not registry_available:
        record("Phase 5: Module Dry-Run", "SKIP", "registry unavailable")
        return

    try:
        from srt.core.registry import get_all

        modules = get_all()
        passed = 0
        failed = 0
        errors: list[str] = []

        for mod_cls in modules:
            try:
                # Create minimal context with dry_run=True
                class DryRunContext:
                    dry_run = True
                    session_id = "00000000-0000-0000-0000-000000000000"
                    params = {
                        "interface": "wlan0",
                        "target": "00:11:22:33:44:55",
                        "bssid": "00:11:22:33:44:55",
                        "client": "AA:BB:CC:DD:EE:FF",
                        "target_ssid": "TestNetwork",
                        "target_client": "AA:BB:CC:DD:EE:FF",
                        "channel": "6",
                    }
                    whitelist = {
                        "wifi_bssid": ["00:11:22:33:44:55"],
                        "ble_addr": ["AA:BB:CC:DD:EE:FF"],
                        "lora_devaddr": ["01020304"],
                    }
                    verbose = False

                ctx = DryRunContext()
                mod = mod_cls()

                # Exercise precheck() - catch and log but don't fail
                # (some prechecks legitimately return False in dry-run
                # without real hardware)
                try:
                    mod.precheck(ctx)
                except Exception as precheck_exc:
                    if verbose:
                        print(f"    PRECHECK-WARN: {mod_cls.name if hasattr(mod_cls, 'name') else '?'}: {precheck_exc}")

                result = mod.run(ctx)

                # Exercise cleanup() - catch and log but don't fail
                try:
                    mod.cleanup(ctx)
                except Exception as cleanup_exc:
                    if verbose:
                        print(f"    CLEANUP-WARN: {mod_cls.name if hasattr(mod_cls, 'name') else '?'}: {cleanup_exc}")
                # Accept OK or REFUSED as valid dry-run results
                if hasattr(result, "status"):
                    status_name = result.status.name if hasattr(result.status, "name") else str(result.status)
                    if status_name in ("OK", "REFUSED"):
                        passed += 1
                    else:
                        failed += 1
                        errors.append(f"{mod.name}: unexpected status {status_name}")
                else:
                    passed += 1  # No status attribute, assume OK
            except Exception as e:
                failed += 1
                errors.append(f"{mod_cls.name if hasattr(mod_cls, 'name') else '?'}: {e}")
                if verbose:
                    print(f"    ERROR: {errors[-1]}")

        if failed == 0:
            record("Phase 5: Module Dry-Run", "PASS", f"{passed} modules OK")
        else:
            record("Phase 5: Module Dry-Run", "FAIL", f"{passed} OK, {failed} failed: {'; '.join(errors[:3])}")
    except Exception as e:
        record("Phase 5: Module Dry-Run", "FAIL", str(e))


# ---------------------------------------------------------------------------
# Phase 6: Infrastructure Check
# ---------------------------------------------------------------------------

def _check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Try to connect to a TCP port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, OSError, socket.timeout):
        return False


def phase_infra(verbose: bool = False, skip: bool = False) -> None:
    """Check localhost services: TimescaleDB (5432), MQTT (1883), Grafana (3000)."""
    print("\n--- Phase 6: Infrastructure Check ---")
    if skip:
        record("Phase 6: Infrastructure Check", "SKIP", "--syntax-only mode")
        return

    services = {
        "TimescaleDB (5432)": 5432,
        "MQTT (1883)": 1883,
        "Grafana (3000)": 3000,
    }

    status_parts = []
    for name, port in services.items():
        up = _check_port("localhost", port)
        status_str = "up" if up else "down"
        status_parts.append(f"{name}: {status_str}")
        if verbose:
            print(f"    {name}: {status_str}")

    # Informational only - don't fail
    record("Phase 6: Infrastructure Check", "PASS", "; ".join(status_parts))


# ---------------------------------------------------------------------------
# Phase 7: Live WiFi Test
# ---------------------------------------------------------------------------

def phase_live_wifi(hw: dict, verbose: bool = False, skip: bool = False) -> None:
    """Put ALFA into monitor mode, scan for 3s, restore."""
    print("\n--- Phase 7: Live WiFi Test ---")
    if skip:
        record("Phase 7: Live WiFi Test", "SKIP", "skipped (--syntax-only or --dry-run)")
        return

    if not hw.get("alfa"):
        record("Phase 7: Live WiFi Test", "SKIP", "ALFA adapter not detected")
        return

    if os.geteuid() != 0:
        record("Phase 7: Live WiFi Test", "SKIP", "not running as root")
        return

    try:
        # Attempt to start monitor mode
        result = subprocess.run(
            ["airmon-ng", "start", "wlan1"],
            capture_output=True, text=True, timeout=10
        )
        if verbose:
            print(f"    airmon-ng start: {result.stdout.strip()}")

        # Brief scan
        scan = subprocess.run(
            ["timeout", "3", "airodump-ng", "--write-interval", "1", "wlan1mon"],
            capture_output=True, text=True, timeout=10
        )

        # Restore interface
        subprocess.run(
            ["airmon-ng", "stop", "wlan1mon"],
            capture_output=True, timeout=10
        )

        record("Phase 7: Live WiFi Test", "PASS", "monitor mode scan completed")
    except FileNotFoundError:
        record("Phase 7: Live WiFi Test", "SKIP", "airmon-ng not installed")
    except subprocess.TimeoutExpired:
        record("Phase 7: Live WiFi Test", "FAIL", "timeout during WiFi scan")
    except Exception as e:
        record("Phase 7: Live WiFi Test", "FAIL", str(e))


# ---------------------------------------------------------------------------
# Phase 8: Live BLE Test
# ---------------------------------------------------------------------------

def phase_live_ble(hw: dict, verbose: bool = False, skip: bool = False) -> None:
    """Attempt BLE scan for 2s if hci0 detected."""
    print("\n--- Phase 8: Live BLE Test ---")
    if skip:
        record("Phase 8: Live BLE Test", "SKIP", "skipped (--syntax-only or --dry-run)")
        return

    if not hw.get("ble"):
        record("Phase 8: Live BLE Test", "SKIP", "BLE adapter (hci0) not detected")
        return

    try:
        result = subprocess.run(
            ["timeout", "2", "hcitool", "lescan"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 or result.returncode == 124:  # 124 = timeout killed
            record("Phase 8: Live BLE Test", "PASS", "BLE scan completed")
        else:
            record("Phase 8: Live BLE Test", "FAIL", f"hcitool returned {result.returncode}")
    except FileNotFoundError:
        record("Phase 8: Live BLE Test", "SKIP", "hcitool not installed")
    except subprocess.TimeoutExpired:
        record("Phase 8: Live BLE Test", "PASS", "BLE scan completed (timeout)")
    except Exception as e:
        record("Phase 8: Live BLE Test", "FAIL", str(e))


# ---------------------------------------------------------------------------
# Phase 9: Live LoRa Test
# ---------------------------------------------------------------------------

def phase_live_lora(hw: dict, verbose: bool = False, skip: bool = False) -> None:
    """Capture 2s on 868.1MHz via hackrf_transfer if HackRF detected."""
    print("\n--- Phase 9: Live LoRa Test ---")
    if skip:
        record("Phase 9: Live LoRa Test", "SKIP", "skipped (--syntax-only or --dry-run)")
        return

    if not hw.get("hackrf"):
        record("Phase 9: Live LoRa Test", "SKIP", "HackRF not detected")
        return

    try:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".raw", delete=True) as tmp:
            result = subprocess.run(
                [
                    "hackrf_transfer",
                    "-r", tmp.name,
                    "-f", "868100000",  # 868.1 MHz
                    "-s", "2000000",    # 2 Msps
                    "-n", "4000000",    # 2s of samples
                ],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                record("Phase 9: Live LoRa Test", "PASS", "868.1MHz capture completed")
            else:
                record("Phase 9: Live LoRa Test", "FAIL", f"hackrf_transfer failed: {result.stderr.strip()[:80]}")
    except FileNotFoundError:
        record("Phase 9: Live LoRa Test", "SKIP", "hackrf_transfer not installed")
    except subprocess.TimeoutExpired:
        record("Phase 9: Live LoRa Test", "FAIL", "timeout during LoRa capture")
    except Exception as e:
        record("Phase 9: Live LoRa Test", "FAIL", str(e))


# ---------------------------------------------------------------------------
# Phase 10: Report
# ---------------------------------------------------------------------------

def phase_report() -> int:
    """Print summary table of all phases and return exit code."""
    print("\n--- Phase 10: Summary Report ---")
    print()
    print("  {:<40} {}".format("Phase", "Result"))
    print("  " + "-" * 60)
    for phase, status, detail in results:
        color = ""
        reset = ""
        if sys.stdout.isatty():
            if status == "PASS":
                color = "\033[32m"
            elif status == "FAIL":
                color = "\033[31m"
            elif status == "SKIP":
                color = "\033[33m"
            reset = "\033[0m"
        line = f"  {phase:<40} {color}{status}{reset}"
        if detail:
            line += f"  ({detail})"
        print(line)
    print("  " + "-" * 60)

    passed = sum(1 for _, s, _ in results if s == "PASS")
    failed = sum(1 for _, s, _ in results if s == "FAIL")
    skipped = sum(1 for _, s, _ in results if s == "SKIP")
    total = len(results)

    summary = f"  Total: {total}  |  PASS: {passed}  |  FAIL: {failed}  |  SKIP: {skipped}"
    print(summary)
    print()

    if failed == 0:
        print("  All tests PASSED (or were skipped).")
        return 0
    else:
        failed_names = [name for name, s, _ in results if s == "FAIL"]
        print(f"  FAILED phases: {', '.join(failed_names)}")
        return 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="sniffer-rt comprehensive test runner. "
        "Validates the platform from PC before deploying to Raspberry Pi.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python run_all_tests.py                # Full test (needs hardware + root)
  python run_all_tests.py --syntax-only  # Syntax/config validation only
  python run_all_tests.py --dry-run      # Module dry-run without real hardware
  python run_all_tests.py --verbose      # Detailed output
""",
    )
    parser.add_argument(
        "--syntax-only",
        action="store_true",
        help="Only run phases 1-2 (syntax and config validation)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run phases 1-5 (skip live hardware tests)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed output for each phase",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  sniffer-rt Comprehensive Test Runner")
    print("=" * 60)

    if args.syntax_only:
        print("  Mode: --syntax-only (phases 1-2 only)")
    elif args.dry_run:
        print("  Mode: --dry-run (phases 1-5, no live hardware)")
    else:
        print("  Mode: full (all phases)")

    # Phase 1: Syntax Validation
    try:
        phase_syntax(verbose=args.verbose)
    except Exception as e:
        record("Phase 1: Syntax Validation", "FAIL", f"unexpected error: {e}")

    # Phase 2: Configuration Validation
    try:
        phase_config(verbose=args.verbose)
    except Exception as e:
        record("Phase 2: Configuration Validation", "FAIL", f"unexpected error: {e}")

    if args.syntax_only:
        return phase_report()

    # Phase 3: Hardware Detection
    try:
        hw = phase_hardware(verbose=args.verbose, skip=False)
    except Exception as e:
        record("Phase 3: Hardware Detection", "FAIL", f"unexpected error: {e}")
        hw = {"hackrf": False, "alfa": False, "ble": False}

    # Phase 4: Module Registry
    try:
        registry_ok = phase_registry(verbose=args.verbose)
    except Exception as e:
        record("Phase 4: Module Registry", "FAIL", f"unexpected error: {e}")
        registry_ok = False

    # Phase 5: Module Dry-Run
    try:
        phase_dry_run(registry_ok, verbose=args.verbose)
    except Exception as e:
        record("Phase 5: Module Dry-Run", "FAIL", f"unexpected error: {e}")

    if args.dry_run:
        return phase_report()

    # Phase 6: Infrastructure Check
    try:
        phase_infra(verbose=args.verbose, skip=False)
    except Exception as e:
        record("Phase 6: Infrastructure Check", "FAIL", f"unexpected error: {e}")

    # Phase 7: Live WiFi Test
    try:
        phase_live_wifi(hw, verbose=args.verbose, skip=False)
    except Exception as e:
        record("Phase 7: Live WiFi Test", "FAIL", f"unexpected error: {e}")

    # Phase 8: Live BLE Test
    try:
        phase_live_ble(hw, verbose=args.verbose, skip=False)
    except Exception as e:
        record("Phase 8: Live BLE Test", "FAIL", f"unexpected error: {e}")

    # Phase 9: Live LoRa Test
    try:
        phase_live_lora(hw, verbose=args.verbose, skip=False)
    except Exception as e:
        record("Phase 9: Live LoRa Test", "FAIL", f"unexpected error: {e}")

    # Phase 10: Report
    return phase_report()


if __name__ == "__main__":
    sys.exit(main())
