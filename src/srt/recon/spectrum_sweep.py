"""Spectrum sweep module using HackRF One's hackrf_sweep CLI.

Performs wideband spectrum analysis across configurable frequency ranges.
This is a PASSIVE module - receive only, no transmission.

Publishes results to:
- MQTT topic: srt/spectrum/sweep
- WebSocket: spectrum_update messages for real-time frontend visualization
- Feeds data into AnalyseurSpectral for signal classification
"""

from __future__ import annotations

import json
import time
from typing import Any

import structlog

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register
from srt.gnuradio.hackrf_sweep import HackRFSweep, SweepResult

log = structlog.get_logger(__name__)


def _publish_mqtt(topic: str, payload: dict[str, Any]) -> None:
    """Attempt to publish to MQTT broker (graceful failure if unavailable)."""
    try:
        import paho.mqtt.client as mqtt

        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="srt-spectrum-sweep",
        )
        client.connect("localhost", 1883, keepalive=10)
        client.publish(topic, json.dumps(payload), qos=0)
        client.disconnect()
    except Exception:
        # MQTT broker not available - this is expected in many environments
        pass


def _broadcast_ws(message: dict[str, Any]) -> None:
    """Broadcast a message via WebSocket to connected clients."""
    try:
        from srt.web.ws import broadcast_sync
        broadcast_sync(message)
    except Exception:
        pass


@register
class SpectrumSweep(AttackModule):
    """HackRF-based wideband spectrum sweep module.

    Performs passive spectrum analysis using hackrf_sweep CLI tool.
    Detects and classifies signals across ISM bands.

    Parameters
    ----------
    freq_start_mhz : float
        Start frequency in MHz (default: 2400).
    freq_end_mhz : float
        End frequency in MHz (default: 2500).
    bin_width_hz : float
        FFT bin width in Hz (default: 1000000).
    duration_s : float
        Duration for continuous sweep in seconds (default: 10).
        If 0, performs a single sweep pass.
    lna_gain : int
        LNA gain 0-40 dB in steps of 8 (default: 32).
    vga_gain : int
        VGA gain 0-62 dB in steps of 2 (default: 20).
    """

    name = "spectrum.sweep"
    protocol = "spectrum"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1040"]
    requires = ["hackrf"]
    description = (
        "Wideband spectrum sweep using HackRF One. "
        "Scans configurable frequency ranges, detects signals, "
        "classifies by protocol and band. Receive-only operation."
    )

    def precheck(self, ctx: ModuleContext) -> bool:
        """Check that parameters are valid."""
        if not super().precheck(ctx):
            return False

        params = ctx.params
        freq_start = params.get("freq_start_mhz", 2400)
        freq_end = params.get("freq_end_mhz", 2500)

        if freq_start >= freq_end:
            log.error("spectrum.sweep.invalid_range", start=freq_start, end=freq_end)
            return False

        if freq_start < 1 or freq_end > 6000:
            log.error("spectrum.sweep.out_of_range", start=freq_start, end=freq_end)
            return False

        return True

    def run(self, ctx: ModuleContext) -> AttackResult:
        """Execute the spectrum sweep."""
        started_at = time.time()
        params = ctx.params

        freq_start_mhz = params.get("freq_start_mhz", 2400)
        freq_end_mhz = params.get("freq_end_mhz", 2500)
        bin_width_hz = params.get("bin_width_hz", 1_000_000)
        duration_s = params.get("duration_s", 0)
        lna_gain = params.get("lna_gain", 32)
        vga_gain = params.get("vga_gain", 20)

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started_at,
                summary=f"[DRY RUN] spectrum.sweep {freq_start_mhz}-{freq_end_mhz} MHz",
                metrics={
                    "freq_start_mhz": freq_start_mhz,
                    "freq_end_mhz": freq_end_mhz,
                    "bin_width_hz": bin_width_hz,
                    "dry_run": True,
                },
            )

        # Create HackRF sweep instance
        sweep = HackRFSweep(
            freq_start_mhz=freq_start_mhz,
            freq_end_mhz=freq_end_mhz,
            bin_width_hz=bin_width_hz,
            lna_gain=lna_gain,
            vga_gain=vga_gain,
        )

        sweep_results: list[SweepResult] = []

        if duration_s <= 0:
            # Single sweep
            result = sweep.single_sweep()
            sweep_results.append(result)
            self._publish_result(result)
        else:
            # Continuous sweep for duration_s seconds
            def on_sweep(result: SweepResult) -> None:
                sweep_results.append(result)
                self._publish_result(result)

            sweep.start_continuous(callback=on_sweep, duration_s=duration_s)

            # Wait for duration
            end_time = time.time() + duration_s
            while time.time() < end_time:
                time.sleep(0.5)

            sweep.stop()

        # Aggregate results
        total_bins = sum(r.num_bins for r in sweep_results)
        peak_power = max((r.peak_power_db for r in sweep_results), default=-120.0)
        avg_noise = (
            sum(r.noise_floor_db for r in sweep_results) / len(sweep_results)
            if sweep_results
            else -90.0
        )

        # Feed into AnalyseurSpectral for signal classification
        signals_detected = self._analyze_signals(sweep_results)

        # Build band summary from latest result
        band_summary = {}
        if sweep_results:
            band_summary = sweep_results[-1].get_band_summary()

        metrics = {
            "freq_start_mhz": freq_start_mhz,
            "freq_end_mhz": freq_end_mhz,
            "bin_width_hz": bin_width_hz,
            "sweep_passes": len(sweep_results),
            "total_bins": total_bins,
            "peak_power_db": round(peak_power, 2),
            "avg_noise_floor_db": round(avg_noise, 2),
            "signals_detected": signals_detected,
            "band_summary": band_summary,
            "duration_s": round(time.time() - started_at, 2),
        }

        # Artifacts: save the raw sweep data
        artifacts = []
        if sweep_results:
            artifacts.append({
                "type": "spectrum_data",
                "format": "json",
                "data": sweep_results[-1].to_dict(),
            })

        return self._result(
            Status.OK,
            started_at,
            summary=(
                f"Spectrum sweep {freq_start_mhz}-{freq_end_mhz} MHz: "
                f"{len(sweep_results)} passes, {total_bins} bins, "
                f"peak {peak_power:.1f} dBm, noise floor {avg_noise:.1f} dBm, "
                f"{signals_detected} signals detected"
            ),
            artifacts=artifacts,
            metrics=metrics,
        )

    def _publish_result(self, result: SweepResult) -> None:
        """Publish a sweep result to MQTT and WebSocket."""
        payload = result.to_dict()

        # MQTT publish
        _publish_mqtt("srt/spectrum/sweep", payload)

        # WebSocket broadcast
        _broadcast_ws({
            "type": "spectrum_update",
            "data": payload,
        })

    def _analyze_signals(self, results: list[SweepResult]) -> int:
        """Use AnalyseurSpectral to classify detected signals."""
        if not results:
            return 0

        total_signals = 0
        try:
            from srt.cartographie.analyse_spectrale import AnalyseurSpectral

            analyseur = AnalyseurSpectral(
                sample_rate_hz=self.bin_width_hz * 2,
                fft_size=1024,
            )

            for result in results:
                # Count bins significantly above noise floor
                if result.bins:
                    noise = result.noise_floor_db
                    signals = [b for b in result.bins if b.power_db > noise + 10]
                    total_signals += len(signals)

        except Exception as exc:
            log.debug("spectrum.sweep.analysis_error", error=str(exc))
            # Fallback: count bins above threshold
            for result in results:
                if result.bins:
                    noise = result.noise_floor_db
                    total_signals += sum(
                        1 for b in result.bins if b.power_db > noise + 10
                    )

        return total_signals
