"""Hardware configuration layer for sniffer-rt.

Maps the operator's specific hardware (ALFA adapter for WiFi, HackRF for
LoRa/spectrum, built-in hci0 for BLE) and provides auto-detection with YAML
config fallback.

Usage:
    from srt.core.hardware import load_config, get_wifi_interface

    cfg = load_config("config/hardware.yaml")
    iface = get_wifi_interface(cfg)
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

_DEFAULT_CONFIG_PATH = "config/hardware.yaml"


@dataclass
class HardwareConfig:
    """Hardware configuration for the platform."""

    wifi_interface: str = "wlan1"
    wifi_monitor_interface: str = "wlan1mon"
    sdr_backend: str = "hackrf"
    ble_adapter: str = "hci0"
    hackrf_gain_rf: int = 40
    hackrf_gain_if: int = 32
    hackrf_gain_bb: int = 20
    lora_frequency_hz: int = 868_100_000
    lora_bandwidth_hz: int = 125_000
    lora_spreading_factor: int = 7
    extras: dict[str, Any] = field(default_factory=dict)


def _run_cmd(cmd: list[str], timeout: float = 5.0) -> str:
    """Run a subprocess and return combined stdout+stderr."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.stdout + result.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.debug("hardware.cmd_failed", cmd=cmd, error=str(exc))
        return ""


def _detect_wifi_interface() -> tuple[str, str]:
    """Probe for ALFA or other monitor-mode-capable WiFi interface.

    Checks /sys/class/net/ for wireless interfaces (those with a phy80211
    symlink or wireless/ subdirectory). Falls back to iw dev output.

    Returns (interface_name, monitor_interface_name).
    """
    net_path = Path("/sys/class/net")
    wireless_ifaces: list[str] = []

    if net_path.exists():
        for iface_path in sorted(net_path.iterdir()):
            # A wireless interface has either a phy80211 symlink or wireless/ dir
            if (iface_path / "phy80211").exists() or (iface_path / "wireless").exists():
                wireless_ifaces.append(iface_path.name)

    # Filter out common non-ALFA interfaces (prefer wlan1+ over wlan0)
    if not wireless_ifaces:
        # Fallback: try iw dev
        output = _run_cmd(["iw", "dev"])
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                iface_name = line.split()[-1]
                wireless_ifaces.append(iface_name)

    if not wireless_ifaces:
        log.warning("hardware.no_wifi_interface_found")
        return "wlan1", "wlan1mon"

    # Prefer external adapters (wlan1, wlan2, ...) over built-in (wlan0)
    preferred = [i for i in wireless_ifaces if i != "wlan0"]
    chosen = preferred[0] if preferred else wireless_ifaces[0]

    log.info("hardware.wifi_detected", interface=chosen, all=wireless_ifaces)
    return chosen, f"{chosen}mon"


def _detect_hackrf() -> bool:
    """Check if HackRF is connected via hackrf_info."""
    output = _run_cmd(["hackrf_info"])
    found = "Found HackRF" in output or "Serial number" in output
    if found:
        log.info("hardware.hackrf_detected")
    return found


def _detect_ble_adapter() -> str:
    """Check for BLE adapter via hciconfig."""
    output = _run_cmd(["hciconfig"])
    if "hci0" in output:
        log.info("hardware.ble_detected", adapter="hci0")
        return "hci0"
    # Try hci1, hci2
    for i in range(3):
        if f"hci{i}" in output:
            log.info("hardware.ble_detected", adapter=f"hci{i}")
            return f"hci{i}"
    log.warning("hardware.no_ble_adapter_found")
    return "hci0"


def auto_detect() -> HardwareConfig:
    """Auto-detect connected hardware and return a HardwareConfig.

    Probes for:
      - ALFA WiFi adapter (via /sys/class/net/ wireless interfaces)
      - HackRF One (via hackrf_info subprocess)
      - BLE adapter (via hciconfig)
    """
    log.info("hardware.auto_detect.start")

    wifi_iface, wifi_mon = _detect_wifi_interface()
    sdr_backend = "hackrf" if _detect_hackrf() else "none"
    ble_adapter = _detect_ble_adapter()

    config = HardwareConfig(
        wifi_interface=wifi_iface,
        wifi_monitor_interface=wifi_mon,
        sdr_backend=sdr_backend,
        ble_adapter=ble_adapter,
    )

    log.info(
        "hardware.auto_detect.done",
        wifi=config.wifi_interface,
        sdr=config.sdr_backend,
        ble=config.ble_adapter,
    )
    return config


def load_config(path: str | None = None) -> HardwareConfig:
    """Load hardware configuration from a YAML file.

    Falls back to auto_detect() if the file does not exist or cannot be parsed.

    Args:
        path: Path to the YAML config file. Defaults to config/hardware.yaml.

    Returns:
        HardwareConfig populated from the file or auto-detection.
    """
    config_path = Path(path) if path else Path(_DEFAULT_CONFIG_PATH)

    if not config_path.exists():
        log.info("hardware.config_not_found", path=str(config_path), action="auto_detect")
        return auto_detect()

    try:
        import yaml

        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except ImportError:
        log.warning("hardware.yaml_not_available", action="auto_detect")
        return auto_detect()
    except Exception as exc:
        log.warning("hardware.config_parse_error", path=str(config_path), error=str(exc))
        return auto_detect()

    if not isinstance(data, dict):
        log.warning("hardware.config_invalid_format", path=str(config_path))
        return auto_detect()

    hw = data.get("hardware", data)
    hackrf = hw.get("hackrf", {})
    lora = hw.get("lora", {})

    config = HardwareConfig(
        wifi_interface=hw.get("wifi_interface", "wlan1"),
        wifi_monitor_interface=hw.get("wifi_monitor_interface", "wlan1mon"),
        sdr_backend=hw.get("sdr_backend", "hackrf"),
        ble_adapter=hw.get("ble_adapter", "hci0"),
        hackrf_gain_rf=hackrf.get("gain_rf", 40),
        hackrf_gain_if=hackrf.get("gain_if", 32),
        hackrf_gain_bb=hackrf.get("gain_bb", 20),
        lora_frequency_hz=lora.get("frequency_hz", 868_100_000),
        lora_bandwidth_hz=lora.get("bandwidth_hz", 125_000),
        lora_spreading_factor=lora.get("spreading_factor", 7),
    )

    log.info("hardware.config_loaded", path=str(config_path), wifi=config.wifi_interface)
    return config


def get_wifi_interface(config: HardwareConfig | None = None) -> str:
    """Return the WiFi interface name from config or auto-detection."""
    if config is None:
        config = load_config()
    return config.wifi_interface


def get_sdr_backend(config: HardwareConfig | None = None) -> str:
    """Return the SDR backend name from config or auto-detection."""
    if config is None:
        config = load_config()
    return config.sdr_backend


def get_ble_adapter(config: HardwareConfig | None = None) -> str:
    """Return the BLE adapter name from config or auto-detection."""
    if config is None:
        config = load_config()
    return config.ble_adapter
