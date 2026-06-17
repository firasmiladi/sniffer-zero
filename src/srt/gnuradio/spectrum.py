"""Spectrum analysis utilities for IQ files.

Computes FFT and spectrogram from captured .cfile data using numpy,
and optionally saves PNG visualizations via matplotlib.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import structlog

log = structlog.get_logger(__name__)


@dataclass
class SpectrumResult:
    """Result of spectrum analysis on an IQ file."""

    frequencies: np.ndarray
    """Frequency axis in Hz relative to center."""

    power_db: np.ndarray
    """Power spectral density in dB (averaged over all FFT frames)."""

    spectrogram_db: np.ndarray
    """2D spectrogram array (time x frequency) in dB."""

    time_axis: np.ndarray
    """Time axis in seconds for spectrogram rows."""

    peak_freq_offset: float
    """Frequency offset (Hz) of the strongest signal component."""

    peak_power_db: float
    """Peak power in dB."""


class SpectrumAnalyzer:
    """Analyze IQ captures using FFT and spectrogram computation.

    Parameters
    ----------
    fft_size : int
        FFT size (default 4096).
    overlap : int
        Number of overlapping samples between FFT frames (default fft_size // 2).
    window : str
        Window function name: 'hann', 'hamming', 'blackman', 'rectangular'
        (default 'hann').
    """

    WINDOWS = {
        "hann": np.hanning,
        "hamming": np.hamming,
        "blackman": np.blackman,
        "rectangular": np.ones,
    }

    def __init__(
        self,
        fft_size: int = 4096,
        overlap: int | None = None,
        window: str = "hann",
    ) -> None:
        self.fft_size = fft_size
        self.overlap = overlap if overlap is not None else fft_size // 2
        self.window = window

        if window not in self.WINDOWS:
            raise ValueError(
                f"Unknown window '{window}'. Choose from: {list(self.WINDOWS)}"
            )

        self._window_fn = self.WINDOWS[window](fft_size)

    def load_iq(self, path: str | Path) -> np.ndarray:
        """Load IQ samples from a .cfile (complex64 format).

        Parameters
        ----------
        path : str or Path
            Path to the .cfile.

        Returns
        -------
        np.ndarray
            Complex64 array of IQ samples.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"IQ file not found: {path}")

        samples = np.fromfile(str(path), dtype=np.complex64)
        log.info(
            "spectrum.loaded",
            path=str(path),
            num_samples=len(samples),
            size_mb=round(path.stat().st_size / 1e6, 2),
        )
        return samples

    def compute_psd(
        self, samples: np.ndarray, sample_rate: float
    ) -> tuple[np.ndarray, np.ndarray]:
        """Compute averaged power spectral density.

        Parameters
        ----------
        samples : np.ndarray
            Complex IQ samples.
        sample_rate : float
            Sample rate in Hz.

        Returns
        -------
        tuple[np.ndarray, np.ndarray]
            (frequencies_hz, power_db) arrays.
        """
        step = self.fft_size - self.overlap
        num_frames = max(1, (len(samples) - self.fft_size) // step + 1)

        psd_accum = np.zeros(self.fft_size)

        for i in range(num_frames):
            start = i * step
            segment = samples[start : start + self.fft_size]
            if len(segment) < self.fft_size:
                break

            windowed = segment * self._window_fn
            spectrum = np.fft.fftshift(np.fft.fft(windowed, self.fft_size))
            psd_accum += np.abs(spectrum) ** 2

        psd_accum /= num_frames
        power_db = 10.0 * np.log10(psd_accum + 1e-12)

        frequencies = np.fft.fftshift(
            np.fft.fftfreq(self.fft_size, d=1.0 / sample_rate)
        )

        return frequencies, power_db

    def compute_spectrogram(
        self, samples: np.ndarray, sample_rate: float
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Compute a time-frequency spectrogram.

        Parameters
        ----------
        samples : np.ndarray
            Complex IQ samples.
        sample_rate : float
            Sample rate in Hz.

        Returns
        -------
        tuple[np.ndarray, np.ndarray, np.ndarray]
            (time_axis_s, frequencies_hz, spectrogram_db) where
            spectrogram_db has shape (num_frames, fft_size).
        """
        step = self.fft_size - self.overlap
        num_frames = max(1, (len(samples) - self.fft_size) // step + 1)

        spectrogram = np.zeros((num_frames, self.fft_size))

        for i in range(num_frames):
            start = i * step
            segment = samples[start : start + self.fft_size]
            if len(segment) < self.fft_size:
                break

            windowed = segment * self._window_fn
            spectrum = np.fft.fftshift(np.fft.fft(windowed, self.fft_size))
            spectrogram[i, :] = 10.0 * np.log10(np.abs(spectrum) ** 2 + 1e-12)

        time_axis = np.arange(num_frames) * step / sample_rate
        frequencies = np.fft.fftshift(
            np.fft.fftfreq(self.fft_size, d=1.0 / sample_rate)
        )

        return time_axis, frequencies, spectrogram

    def analyze(self, path: str | Path, sample_rate: float) -> SpectrumResult:
        """Full spectrum analysis of an IQ file.

        Parameters
        ----------
        path : str or Path
            Path to .cfile.
        sample_rate : float
            Sample rate in Hz.

        Returns
        -------
        SpectrumResult
            Complete analysis results.
        """
        samples = self.load_iq(path)
        frequencies, power_db = self.compute_psd(samples, sample_rate)
        time_axis, _, spectrogram_db = self.compute_spectrogram(samples, sample_rate)

        peak_idx = np.argmax(power_db)
        peak_freq_offset = float(frequencies[peak_idx])
        peak_power = float(power_db[peak_idx])

        log.info(
            "spectrum.analyzed",
            peak_freq_offset_khz=round(peak_freq_offset / 1e3, 2),
            peak_power_db=round(peak_power, 1),
            num_frames=len(time_axis),
        )

        return SpectrumResult(
            frequencies=frequencies,
            power_db=power_db,
            spectrogram_db=spectrogram_db,
            time_axis=time_axis,
            peak_freq_offset=peak_freq_offset,
            peak_power_db=peak_power,
        )

    def save_plot(
        self,
        result: SpectrumResult,
        output_path: str | Path,
        center_freq: float = 0.0,
        title: str = "SRT Spectrum Analysis",
    ) -> Path:
        """Save spectrum visualization as PNG.

        Parameters
        ----------
        result : SpectrumResult
            Analysis results from analyze().
        output_path : str or Path
            Output PNG file path.
        center_freq : float
            Center frequency for display labeling (Hz).
        title : str
            Plot title.

        Returns
        -------
        Path
            Path to the saved PNG file.
        """
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        output_path = Path(output_path)
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))

        # PSD plot
        freq_mhz = (result.frequencies + center_freq) / 1e6
        ax1.plot(freq_mhz, result.power_db, linewidth=0.5)
        ax1.set_xlabel("Frequency (MHz)")
        ax1.set_ylabel("Power (dB)")
        ax1.set_title(f"{title} - Power Spectral Density")
        ax1.grid(True, alpha=0.3)

        # Spectrogram
        extent = [
            float(freq_mhz[0]),
            float(freq_mhz[-1]),
            float(result.time_axis[-1]) if len(result.time_axis) > 0 else 0,
            0.0,
        ]
        ax2.imshow(
            result.spectrogram_db,
            aspect="auto",
            extent=extent,
            cmap="viridis",
            origin="upper",
        )
        ax2.set_xlabel("Frequency (MHz)")
        ax2.set_ylabel("Time (s)")
        ax2.set_title(f"{title} - Spectrogram")

        plt.tight_layout()
        plt.savefig(str(output_path), dpi=150, bbox_inches="tight")
        plt.close(fig)

        log.info("spectrum.plot_saved", output=str(output_path))
        return output_path
