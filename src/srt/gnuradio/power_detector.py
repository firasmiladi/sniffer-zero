"""Signal presence detector with threshold-based callbacks.

Monitors a frequency band via osmosdr source and triggers registered
callbacks when signal power exceeds a configurable threshold.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np
import osmosdr
import structlog
from gnuradio import blocks, gr

log = structlog.get_logger(__name__)


@dataclass
class DetectionEvent:
    """Represents a detected signal event."""

    timestamp: float
    """Unix timestamp of detection."""

    frequency: float
    """Center frequency being monitored (Hz)."""

    power_db: float
    """Measured power level in dB."""

    threshold_db: float
    """Threshold that was exceeded."""

    duration_s: float = 0.0
    """Duration of signal presence in seconds (updated on signal end)."""


@dataclass
class DetectorConfig:
    """Configuration for the power detector."""

    frequency: float
    """Center frequency to monitor (Hz)."""

    sample_rate: float = 2e6
    """Sample rate in samples/second."""

    fft_size: int = 1024
    """FFT size for power measurement."""

    threshold_db: float = -40.0
    """Power threshold in dB to trigger detection."""

    averaging: int = 10
    """Number of FFT frames to average for stable measurement."""

    hold_time_s: float = 1.0
    """Minimum time signal must persist to trigger callback."""

    gain: float = 40.0
    """RF gain in dB."""

    device_args: str = "hackrf=0"
    """osmosdr device arguments."""


class PowerDetector:
    """Monitors a frequency and triggers callbacks on signal detection.

    Usage
    -----
    >>> detector = PowerDetector(config)
    >>> detector.on_signal_detected(my_callback)
    >>> detector.on_signal_lost(my_lost_callback)
    >>> detector.start()
    >>> # ... runs until stopped
    >>> detector.stop()

    Parameters
    ----------
    config : DetectorConfig
        Detector configuration.
    """

    def __init__(self, config: DetectorConfig) -> None:
        self.config = config
        self._detect_callbacks: list[Callable[[DetectionEvent], None]] = []
        self._lost_callbacks: list[Callable[[DetectionEvent], None]] = []
        self._running = False
        self._thread: threading.Thread | None = None
        self._current_event: DetectionEvent | None = None
        self._window = np.hanning(config.fft_size)

    def on_signal_detected(self, callback: Callable[[DetectionEvent], None]) -> None:
        """Register a callback for when signal power exceeds threshold.

        Parameters
        ----------
        callback : callable
            Function called with a DetectionEvent when signal is detected.
        """
        self._detect_callbacks.append(callback)

    def on_signal_lost(self, callback: Callable[[DetectionEvent], None]) -> None:
        """Register a callback for when signal drops below threshold.

        Parameters
        ----------
        callback : callable
            Function called with a DetectionEvent when signal is lost.
        """
        self._lost_callbacks.append(callback)

    def _measure_power(self, samples: np.ndarray) -> float:
        """Compute average power in dB from IQ samples.

        Parameters
        ----------
        samples : np.ndarray
            Complex IQ samples (at least fft_size * averaging samples).

        Returns
        -------
        float
            Average power in dB.
        """
        fft_size = self.config.fft_size
        num_frames = min(
            self.config.averaging,
            len(samples) // fft_size,
        )

        if num_frames == 0:
            return -100.0

        power_accum = 0.0
        for i in range(num_frames):
            segment = samples[i * fft_size : (i + 1) * fft_size]
            windowed = segment * self._window
            spectrum = np.fft.fft(windowed, fft_size)
            power_accum += np.mean(np.abs(spectrum) ** 2)

        avg_power = power_accum / num_frames
        return float(10.0 * np.log10(avg_power + 1e-12))

    def _fire_detected(self, event: DetectionEvent) -> None:
        """Notify all detection callbacks."""
        for cb in self._detect_callbacks:
            try:
                cb(event)
            except Exception as exc:
                log.error("detector.callback_error", error=str(exc))

    def _fire_lost(self, event: DetectionEvent) -> None:
        """Notify all signal-lost callbacks."""
        for cb in self._lost_callbacks:
            try:
                cb(event)
            except Exception as exc:
                log.error("detector.callback_error", error=str(exc))

    def _monitor_loop(self) -> None:
        """Main monitoring loop - runs in a background thread."""
        cfg = self.config
        samples_per_read = cfg.fft_size * cfg.averaging

        # Set up GNU Radio flowgraph for continuous capture
        tb = gr.top_block()
        source = osmosdr.source(args=cfg.device_args)
        source.set_sample_rate(cfg.sample_rate)
        source.set_center_freq(cfg.frequency)
        source.set_gain(cfg.gain)
        source.set_bandwidth(cfg.sample_rate)

        # Use a vector sink to accumulate samples for processing
        sink = blocks.vector_sink_c()
        head = blocks.head(gr.sizeof_gr_complex, samples_per_read)

        tb.connect(source, head, sink)

        log.info(
            "detector.monitoring",
            frequency_mhz=cfg.frequency / 1e6,
            threshold_db=cfg.threshold_db,
        )

        while self._running:
            # Reset and capture a batch of samples
            sink.reset()
            head.reset()

            tb.start()
            tb.wait()

            data = np.array(sink.data(), dtype=np.complex64)
            power_db = self._measure_power(data)

            if power_db >= cfg.threshold_db:
                if self._current_event is None:
                    # Signal just appeared
                    self._current_event = DetectionEvent(
                        timestamp=time.time(),
                        frequency=cfg.frequency,
                        power_db=power_db,
                        threshold_db=cfg.threshold_db,
                    )
                    log.info(
                        "detector.signal_detected",
                        power_db=round(power_db, 1),
                        frequency_mhz=cfg.frequency / 1e6,
                    )
                    self._fire_detected(self._current_event)
                else:
                    # Update ongoing event power
                    self._current_event.power_db = max(
                        self._current_event.power_db, power_db
                    )
            else:
                if self._current_event is not None:
                    # Signal just disappeared
                    self._current_event.duration_s = (
                        time.time() - self._current_event.timestamp
                    )
                    log.info(
                        "detector.signal_lost",
                        duration_s=round(self._current_event.duration_s, 2),
                        peak_power_db=round(self._current_event.power_db, 1),
                    )
                    self._fire_lost(self._current_event)
                    self._current_event = None

            # Small sleep to avoid busy-spinning
            time.sleep(0.05)

    def start(self) -> None:
        """Start the detector in a background thread."""
        if self._running:
            log.warning("detector.already_running")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="srt-power-detector",
            daemon=True,
        )
        self._thread.start()
        log.info("detector.started", frequency_mhz=self.config.frequency / 1e6)

    def stop(self) -> None:
        """Stop the detector."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        log.info("detector.stopped")

    @property
    def is_running(self) -> bool:
        """Whether the detector is currently monitoring."""
        return self._running
