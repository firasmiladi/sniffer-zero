"""HackRF Sweep integration - wraps the hackrf_sweep CLI tool.

Provides structured spectrum data from the HackRF One's sweep mode,
which scans a frequency range and outputs power spectral density.

The hackrf_sweep tool outputs CSV lines:
    date, time, freq_hz_lo, freq_hz_hi, freq_bin_width, num_samples, power_db1, power_db2, ...

Usage:
    sweep = HackRFSweep(freq_start_mhz=2400, freq_end_mhz=2500)
    results = sweep.single_sweep()
    for entry in results:
        print(entry.freq_mhz, entry.power_db)
"""

from __future__ import annotations

import csv
import io
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

import structlog

log = structlog.get_logger(__name__)


@dataclass
class SweepBin:
    """A single frequency bin from a hackrf_sweep output line."""

    freq_hz: float
    power_db: float
    timestamp: datetime


@dataclass
class SweepResult:
    """Complete result from a single hackrf_sweep pass."""

    timestamp: datetime
    freq_start_hz: float
    freq_end_hz: float
    bin_width_hz: float
    bins: list[SweepBin] = field(default_factory=list)
    duration_s: float = 0.0

    @property
    def freq_start_mhz(self) -> float:
        return self.freq_start_hz / 1e6

    @property
    def freq_end_mhz(self) -> float:
        return self.freq_end_hz / 1e6

    @property
    def num_bins(self) -> int:
        return len(self.bins)

    @property
    def peak_power_db(self) -> float:
        if not self.bins:
            return -120.0
        return max(b.power_db for b in self.bins)

    @property
    def avg_power_db(self) -> float:
        if not self.bins:
            return -120.0
        return sum(b.power_db for b in self.bins) / len(self.bins)

    @property
    def noise_floor_db(self) -> float:
        """Estimate noise floor as the median power level."""
        if not self.bins:
            return -120.0
        powers = sorted(b.power_db for b in self.bins)
        mid = len(powers) // 2
        return powers[mid]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-friendly dict."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "freq_start_mhz": self.freq_start_mhz,
            "freq_end_mhz": self.freq_end_mhz,
            "bin_width_hz": self.bin_width_hz,
            "num_bins": self.num_bins,
            "peak_power_db": round(self.peak_power_db, 2),
            "avg_power_db": round(self.avg_power_db, 2),
            "noise_floor_db": round(self.noise_floor_db, 2),
            "duration_s": round(self.duration_s, 3),
            "frequencies_mhz": [round(b.freq_hz / 1e6, 4) for b in self.bins],
            "powers_db": [round(b.power_db, 2) for b in self.bins],
        }

    def get_band_summary(self) -> dict[str, dict[str, Any]]:
        """Group bins by ISM band and compute per-band statistics."""
        bands: dict[str, list[SweepBin]] = {}
        for b in self.bins:
            band_name = _classify_band(b.freq_hz / 1e6)
            if band_name not in bands:
                bands[band_name] = []
            bands[band_name].append(b)

        summary: dict[str, dict[str, Any]] = {}
        for name, band_bins in bands.items():
            powers = [b.power_db for b in band_bins]
            summary[name] = {
                "freq_min_mhz": round(min(b.freq_hz for b in band_bins) / 1e6, 2),
                "freq_max_mhz": round(max(b.freq_hz for b in band_bins) / 1e6, 2),
                "num_bins": len(band_bins),
                "peak_power_db": round(max(powers), 2),
                "avg_power_db": round(sum(powers) / len(powers), 2),
                "noise_floor_db": round(sorted(powers)[len(powers) // 2], 2),
                "signals_above_noise": sum(
                    1 for p in powers if p > sorted(powers)[len(powers) // 2] + 10
                ),
            }
        return summary


def _classify_band(freq_mhz: float) -> str:
    """Classify a frequency into ISM/common band name."""
    if 433 <= freq_mhz <= 435:
        return "ISM_433MHz"
    elif 863 <= freq_mhz <= 870:
        return "ISM_868MHz"
    elif 902 <= freq_mhz <= 928:
        return "ISM_915MHz"
    elif 2400 <= freq_mhz <= 2500:
        return "ISM_2.4GHz"
    elif 5150 <= freq_mhz <= 5350:
        return "U-NII-1_5.2GHz"
    elif 5470 <= freq_mhz <= 5725:
        return "U-NII-2_5.5GHz"
    elif 5725 <= freq_mhz <= 5875:
        return "ISM_5.8GHz"
    elif 5925 <= freq_mhz <= 7125:
        return "WiFi6E_6GHz"
    else:
        return f"Other_{int(freq_mhz)}MHz"


def parse_sweep_line(line: str) -> list[SweepBin] | None:
    """Parse a single CSV line from hackrf_sweep output.

    Format:
        date, time, freq_hz_lo, freq_hz_hi, freq_bin_width, num_samples, db1, db2, ...

    Returns a list of SweepBin entries for all frequency bins in the line,
    or None if the line cannot be parsed.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    try:
        reader = csv.reader(io.StringIO(line))
        fields = next(reader)
        fields = [f.strip() for f in fields]

        if len(fields) < 7:
            return None

        # Parse timestamp
        date_str = fields[0]
        time_str = fields[1]
        try:
            ts = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            try:
                ts = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
            except ValueError:
                ts = datetime.now()

        freq_lo = float(fields[2])
        freq_hi = float(fields[3])
        bin_width = float(fields[4])
        # num_samples = int(fields[5])  # not used directly

        # Power values start at index 6
        power_values = [float(f) for f in fields[6:] if f]
        num_bins = len(power_values)

        if num_bins == 0:
            return None

        # Calculate frequency for each bin
        bins: list[SweepBin] = []
        for i, power_db in enumerate(power_values):
            freq_hz = freq_lo + (i * bin_width)
            bins.append(SweepBin(freq_hz=freq_hz, power_db=power_db, timestamp=ts))

        return bins

    except (ValueError, IndexError, StopIteration) as exc:
        log.debug("hackrf_sweep.parse_error", line=line[:80], error=str(exc))
        return None


class HackRFSweep:
    """Wrapper around the hackrf_sweep CLI tool.

    Parameters
    ----------
    freq_start_mhz : float
        Start frequency in MHz (default: 2400).
    freq_end_mhz : float
        End frequency in MHz (default: 2500).
    bin_width_hz : float
        FFT bin width in Hz (default: 1000000 = 1 MHz).
    lna_gain : int
        LNA gain in dB, 0-40 in steps of 8 (default: 32).
    vga_gain : int
        VGA gain in dB, 0-62 in steps of 2 (default: 20).
    """

    def __init__(
        self,
        freq_start_mhz: float = 2400,
        freq_end_mhz: float = 2500,
        bin_width_hz: float = 1_000_000,
        lna_gain: int = 32,
        vga_gain: int = 20,
    ) -> None:
        self.freq_start_mhz = freq_start_mhz
        self.freq_end_mhz = freq_end_mhz
        self.bin_width_hz = bin_width_hz
        self.lna_gain = lna_gain
        self.vga_gain = vga_gain

        self._process: subprocess.Popen | None = None
        self._stop_event = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._latest_result: SweepResult | None = None
        self._on_sweep_callback: Callable[[SweepResult], None] | None = None

    @property
    def available(self) -> bool:
        """Check if hackrf_sweep is available on the system."""
        return shutil.which("hackrf_sweep") is not None

    @property
    def latest_result(self) -> SweepResult | None:
        """Get the most recent sweep result."""
        return self._latest_result

    def _build_command(self, single: bool = False) -> list[str]:
        """Build the hackrf_sweep command line."""
        cmd = [
            "hackrf_sweep",
            "-f", f"{int(self.freq_start_mhz)}:{int(self.freq_end_mhz)}",
            "-w", str(int(self.bin_width_hz)),
            "-l", str(self.lna_gain),
            "-g", str(self.vga_gain),
        ]
        if single:
            cmd.append("-1")
        return cmd

    def single_sweep(self, timeout: float = 30.0) -> SweepResult:
        """Execute a single sweep and return structured results.

        Uses hackrf_sweep -1 flag for single-pass mode.
        Returns a SweepResult with all frequency bins and power levels.
        """
        if not self.available:
            log.warning("hackrf_sweep.not_available", detail="hackrf_sweep not found in PATH")
            return self._generate_simulated_sweep()

        cmd = self._build_command(single=True)
        log.info("hackrf_sweep.start", cmd=" ".join(cmd))

        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            duration = time.time() - start_time

            if result.returncode != 0 and not result.stdout:
                log.warning(
                    "hackrf_sweep.error",
                    returncode=result.returncode,
                    stderr=result.stderr[:200],
                )
                return self._generate_simulated_sweep()

            return self._parse_output(result.stdout, duration)

        except subprocess.TimeoutExpired:
            log.warning("hackrf_sweep.timeout", timeout=timeout)
            return self._generate_simulated_sweep()
        except FileNotFoundError:
            log.warning("hackrf_sweep.not_found")
            return self._generate_simulated_sweep()

    def start_continuous(
        self,
        callback: Callable[[SweepResult], None] | None = None,
        duration_s: float | None = None,
    ) -> None:
        """Start continuous sweep in a background thread.

        Parameters
        ----------
        callback : callable, optional
            Function called with each SweepResult as it completes.
        duration_s : float, optional
            Max duration in seconds. None = run until stop() is called.
        """
        self._on_sweep_callback = callback
        self._stop_event.clear()

        self._monitor_thread = threading.Thread(
            target=self._continuous_loop,
            args=(duration_s,),
            daemon=True,
            name="hackrf-sweep-continuous",
        )
        self._monitor_thread.start()

    def stop(self) -> None:
        """Stop continuous sweep."""
        self._stop_event.set()
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                if self._process:
                    self._process.kill()
            self._process = None

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        self._monitor_thread = None

    def _continuous_loop(self, duration_s: float | None) -> None:
        """Background thread: run hackrf_sweep continuously and parse output."""
        if not self.available:
            log.warning("hackrf_sweep.continuous.not_available")
            # Run simulated sweeps
            self._simulated_continuous(duration_s)
            return

        cmd = self._build_command(single=False)
        log.info("hackrf_sweep.continuous.start", cmd=" ".join(cmd))

        start_time = time.time()
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            current_bins: list[SweepBin] = []
            sweep_start = time.time()

            for line in iter(self._process.stdout.readline, ""):
                if self._stop_event.is_set():
                    break
                if duration_s and (time.time() - start_time) > duration_s:
                    break

                bins = parse_sweep_line(line)
                if bins:
                    # Detect new sweep pass (frequency goes back to start)
                    if current_bins and bins[0].freq_hz < current_bins[-1].freq_hz:
                        # Complete sweep pass
                        result = self._bins_to_result(current_bins, time.time() - sweep_start)
                        self._latest_result = result
                        if self._on_sweep_callback:
                            self._on_sweep_callback(result)
                        current_bins = []
                        sweep_start = time.time()

                    current_bins.extend(bins)

            # Process remaining bins
            if current_bins:
                result = self._bins_to_result(current_bins, time.time() - sweep_start)
                self._latest_result = result
                if self._on_sweep_callback:
                    self._on_sweep_callback(result)

        except Exception as exc:
            log.error("hackrf_sweep.continuous.error", error=str(exc))
        finally:
            self.stop()

    def _simulated_continuous(self, duration_s: float | None) -> None:
        """Simulated continuous sweep when hardware is not available."""
        import random

        start_time = time.time()
        while not self._stop_event.is_set():
            if duration_s and (time.time() - start_time) > duration_s:
                break

            result = self._generate_simulated_sweep()
            self._latest_result = result
            if self._on_sweep_callback:
                self._on_sweep_callback(result)

            # Wait between sweeps (simulates sweep time)
            self._stop_event.wait(timeout=2.0)

    def _parse_output(self, output: str, duration: float) -> SweepResult:
        """Parse the full output of a hackrf_sweep run."""
        all_bins: list[SweepBin] = []

        for line in output.splitlines():
            bins = parse_sweep_line(line)
            if bins:
                all_bins.extend(bins)

        return self._bins_to_result(all_bins, duration)

    def _bins_to_result(self, bins: list[SweepBin], duration: float) -> SweepResult:
        """Convert a list of SweepBins into a SweepResult."""
        if not bins:
            return SweepResult(
                timestamp=datetime.now(),
                freq_start_hz=self.freq_start_mhz * 1e6,
                freq_end_hz=self.freq_end_mhz * 1e6,
                bin_width_hz=self.bin_width_hz,
                bins=[],
                duration_s=duration,
            )

        return SweepResult(
            timestamp=bins[0].timestamp,
            freq_start_hz=min(b.freq_hz for b in bins),
            freq_end_hz=max(b.freq_hz for b in bins),
            bin_width_hz=self.bin_width_hz,
            bins=bins,
            duration_s=duration,
        )

    def _generate_simulated_sweep(self) -> SweepResult:
        """Generate simulated sweep data when hardware is not available.

        Produces realistic-looking spectrum data with:
        - Background noise floor around -80 to -90 dBm
        - WiFi signals at 2.4 GHz channels
        - BLE signals scattered across 2.4 GHz
        - Random transient signals
        """
        import random

        now = datetime.now()
        bins: list[SweepBin] = []

        freq = self.freq_start_mhz * 1e6
        while freq < self.freq_end_mhz * 1e6:
            # Base noise floor
            noise = random.gauss(-85.0, 3.0)

            # Simulate WiFi signals at standard channels
            freq_mhz = freq / 1e6
            power = noise

            # WiFi 2.4 GHz channels (1, 6, 11 are common)
            if 2400 <= freq_mhz <= 2483:
                for ch_center in [2412, 2437, 2462]:
                    dist = abs(freq_mhz - ch_center)
                    if dist < 11:  # 22 MHz channel width
                        signal_power = -45.0 + (dist * 2.5)
                        power = max(power, signal_power + random.gauss(0, 2))

                # BLE advertising channels (37, 38, 39)
                for ble_freq in [2402, 2426, 2480]:
                    dist = abs(freq_mhz - ble_freq)
                    if dist < 1:
                        ble_power = -60.0 + random.gauss(0, 5)
                        power = max(power, ble_power)

            # LoRa 868 MHz
            elif 863 <= freq_mhz <= 870:
                for lora_ch in [868.1, 868.3, 868.5]:
                    dist = abs(freq_mhz - lora_ch)
                    if dist < 0.125:  # 125 kHz BW
                        lora_power = -70.0 + random.gauss(0, 3)
                        power = max(power, lora_power)

            # ISM 433 MHz
            elif 433 <= freq_mhz <= 435:
                if random.random() < 0.1:
                    power = max(power, -65.0 + random.gauss(0, 5))

            bins.append(SweepBin(freq_hz=freq, power_db=round(power, 2), timestamp=now))
            freq += self.bin_width_hz

        return SweepResult(
            timestamp=now,
            freq_start_hz=self.freq_start_mhz * 1e6,
            freq_end_hz=self.freq_end_mhz * 1e6,
            bin_width_hz=self.bin_width_hz,
            bins=bins,
            duration_s=random.uniform(0.5, 2.0),
        )
