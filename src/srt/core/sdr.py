"""Thin abstraction over the SDR backends used by `sniffer-rt`.

The class hierarchy is intentionally minimal: most modules drive flowgraphs or
external CLIs (hcxdumptool, ...) and just need a way to ask
"which radio is plugged in and is it usable for this band".

We expose:
  * ``probe()``   -> list of ``RadioInfo``
  * ``select(band, requires_tx)`` -> a ``RadioInfo`` or ``None``
  * a stub for an inline GNU Radio ``CaptureSource`` we can flesh out later.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

import structlog

log = structlog.get_logger(__name__)


# Coarse band -> (low_mhz, high_mhz) used for capability matching.
BANDS_MHZ: dict[str, tuple[float, float]] = {
    "lora-433": (433.05, 434.79),
    "lora-868": (863.0, 870.0),
    "lora-915": (902.0, 928.0),
    "ble":      (2400.0, 2483.5),
    "wifi-2.4": (2400.0, 2483.5),
    "wifi-5":   (5150.0, 5875.0),
}


@dataclass
class RadioInfo:
    backend: str                       # "hackrf" | "lime" | "soapy" | "alfa-wifi"
    serial: str = ""
    bandwidth_hz: int = 0
    full_duplex: bool = False
    freq_min_hz: int = 0
    freq_max_hz: int = 0
    notes: str = ""

    def covers(self, band: str) -> bool:
        if band not in BANDS_MHZ:
            return False
        low, high = BANDS_MHZ[band]
        return self.freq_min_hz <= int(low * 1e6) and self.freq_max_hz >= int(high * 1e6)


def _run(cmd: list[str], timeout: float = 4.0) -> str:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return out.stdout + out.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.debug("sdr.probe.failed", cmd=cmd, error=str(exc))
        return ""


def _probe_hackrf() -> list[RadioInfo]:
    if not shutil.which("hackrf_info"):
        return []
    text = _run(["hackrf_info"])
    if "Found HackRF" not in text and "Serial number" not in text:
        return []
    serial = ""
    for line in text.splitlines():
        if "Serial number" in line:
            serial = line.split(":", 1)[1].strip()
            break
    return [
        RadioInfo(
            backend="hackrf",
            serial=serial,
            bandwidth_hz=20_000_000,   # 20 MHz, ~10 MHz usable
            full_duplex=False,
            freq_min_hz=1_000_000,
            freq_max_hz=6_000_000_000,
            notes="half-duplex, no GPSDO",
        )
    ]



def _probe_lime() -> list[RadioInfo]:
    if not shutil.which("LimeUtil"):
        return []
    text = _run(["LimeUtil", "--find"])
    if "LimeSDR" not in text:
        return []
    return [
        RadioInfo(
            backend="lime",
            bandwidth_hz=61_440_000,
            full_duplex=True,
            freq_min_hz=100_000,
            freq_max_hz=3_800_000_000,
            notes="LimeSDR class",
        )
    ]


def _probe_alfa() -> list[RadioInfo]:
    """Detect monitor-mode-capable WiFi NICs (ALFA RTL8812AU or similar).

    Checks /sys/class/net/*/phy80211 for wireless interfaces, then
    verifies monitor mode capability via iw. Returns a RadioInfo with
    backend="alfa-wifi" for each capable interface.
    """
    from pathlib import Path

    radios: list[RadioInfo] = []
    net_path = Path("/sys/class/net")

    wireless_ifaces: list[str] = []
    if net_path.exists():
        for iface_path in sorted(net_path.iterdir()):
            if (iface_path / "phy80211").exists() or (iface_path / "wireless").exists():
                wireless_ifaces.append(iface_path.name)

    # Fallback: parse iw dev output
    if not wireless_ifaces:
        output = _run(["iw", "dev"])
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                iface_name = line.split()[-1]
                wireless_ifaces.append(iface_name)

    for iface in wireless_ifaces:
        # Get the PHY name for this specific interface
        phy_name_path = net_path / iface / "phy80211" / "name"
        phy_name = ""
        try:
            phy_name = phy_name_path.read_text().strip()
        except OSError:
            pass

        if not phy_name:
            # Fallback: try to get PHY from /sys/class/net/<iface>/phy80211 symlink
            phy_link = net_path / iface / "phy80211"
            if phy_link.exists():
                try:
                    phy_name = phy_link.resolve().name
                except OSError:
                    pass

        if not phy_name:
            continue

        # Check monitor mode capability for this specific PHY
        phy_output = _run(["iw", "phy", phy_name, "info"])
        supports_monitor = "monitor" in phy_output.lower()

        if supports_monitor:
            radios.append(
                RadioInfo(
                    backend="alfa-wifi",
                    serial=iface,
                    bandwidth_hz=160_000_000,  # 802.11ac 160 MHz
                    full_duplex=False,
                    freq_min_hz=2_400_000_000,
                    freq_max_hz=5_875_000_000,
                    notes=f"WiFi NIC {iface}, monitor-mode capable",
                )
            )
            break  # One entry for the best interface

    if radios:
        log.info("sdr.probe.alfa_detected", interface=radios[0].serial)

    return radios


def probe() -> list[RadioInfo]:
    """Discover SDR hardware available on the host."""
    radios: list[RadioInfo] = []
    radios += _probe_hackrf()
    radios += _probe_lime()
    radios += _probe_alfa()
    log.info("sdr.probe", count=len(radios), backends=[r.backend for r in radios])
    return radios


def select(band: str, requires_tx: bool = False) -> RadioInfo | None:
    """Pick the best radio for a band. Prefers full-duplex when TX is required."""
    radios = probe()
    candidates = [r for r in radios if r.covers(band)]
    if requires_tx:
        full_duplex = [r for r in candidates if r.full_duplex]
        candidates = full_duplex or candidates
    return candidates[0] if candidates else None


# --------------------------------------------------------------------------- #
# Capture source stub - to be wired to GNU Radio in a follow-up phase.        #
# --------------------------------------------------------------------------- #

@dataclass
class CaptureSource:
    """Placeholder for a GNU Radio Python flowgraph wrapper."""

    band: str
    sample_rate_hz: int = 2_000_000
    center_hz: int = 0
    gain_db: int = 30
    sink_path: str = ""
    radio: RadioInfo | None = field(default=None)

    def start(self) -> None:  # pragma: no cover - stub
        raise NotImplementedError("CaptureSource is a scaffold stub")

    def stop(self) -> None:  # pragma: no cover - stub
        return None
