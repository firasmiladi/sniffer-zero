"""IQ capture flowgraph using GNU Radio and osmosdr.

Captures raw IQ samples at a configurable center frequency, sample rate,
and duration, saving them to a .cfile (complex64 interleaved I/Q).
"""

from __future__ import annotations

import time
from pathlib import Path

import osmosdr
import structlog
from gnuradio import blocks, gr

log = structlog.get_logger(__name__)


class CaptureFlow(gr.top_block):
    """GNU Radio flowgraph for IQ sample capture via osmosdr source.

    Parameters
    ----------
    frequency : float
        Center frequency in Hz (e.g. 433.92e6 for 433.92 MHz).
    sample_rate : float
        Sample rate in samples/second (e.g. 2e6 for 2 MS/s).
    duration : float
        Capture duration in seconds.
    output_path : str or Path
        Output file path for the .cfile.
    gain : float
        RF gain in dB (default 40).
    device_args : str
        osmosdr device arguments (default "hackrf=0").
    """

    def __init__(
        self,
        frequency: float,
        sample_rate: float,
        duration: float,
        output_path: str | Path,
        gain: float = 40.0,
        device_args: str = "hackrf=0",
    ) -> None:
        super().__init__(name="srt_capture_flow")

        self.frequency = frequency
        self.sample_rate = sample_rate
        self.duration = duration
        self.output_path = Path(output_path)
        self.gain = gain
        self.device_args = device_args

        # Calculate total number of samples to capture
        num_samples = int(sample_rate * duration)

        # Source: osmosdr (supports HackRF, RTL-SDR, etc.)
        self.source = osmosdr.source(args=device_args)
        self.source.set_sample_rate(sample_rate)
        self.source.set_center_freq(frequency)
        self.source.set_gain(gain)
        self.source.set_bandwidth(sample_rate)

        # Head block to limit capture to requested duration
        self.head = blocks.head(gr.sizeof_gr_complex, num_samples)

        # File sink: writes raw complex64 IQ samples
        self.file_sink = blocks.file_sink(
            gr.sizeof_gr_complex,
            str(self.output_path),
            append=False,
        )
        self.file_sink.set_unbuffered(False)

        # Connect the flowgraph: source -> head -> file_sink
        self.connect(self.source, self.head, self.file_sink)

        log.info(
            "capture.configured",
            frequency_mhz=frequency / 1e6,
            sample_rate_msps=sample_rate / 1e6,
            duration_s=duration,
            num_samples=num_samples,
            output=str(self.output_path),
        )

    def run_capture(self) -> Path:
        """Execute the capture and return the output file path.

        Returns
        -------
        Path
            Path to the captured .cfile.
        """
        log.info("capture.start", frequency_mhz=self.frequency / 1e6)
        start_time = time.time()

        self.start()
        self.wait()

        elapsed = time.time() - start_time
        file_size = self.output_path.stat().st_size if self.output_path.exists() else 0

        log.info(
            "capture.complete",
            elapsed_s=round(elapsed, 2),
            file_size_bytes=file_size,
            output=str(self.output_path),
        )
        return self.output_path

    @classmethod
    def quick_capture(
        cls,
        frequency: float,
        duration: float = 5.0,
        output_path: str | Path | None = None,
        sample_rate: float = 2e6,
        gain: float = 40.0,
        device_args: str = "hackrf=0",
    ) -> Path:
        """Convenience method for a one-shot capture.

        Parameters
        ----------
        frequency : float
            Center frequency in Hz.
        duration : float
            Duration in seconds (default 5).
        output_path : str or Path, optional
            Output file. Defaults to /tmp/srt_capture_{freq_mhz}MHz.cfile.
        sample_rate : float
            Sample rate (default 2 MS/s).
        gain : float
            RF gain in dB (default 40).
        device_args : str
            osmosdr device string.

        Returns
        -------
        Path
            Path to the captured .cfile.
        """
        if output_path is None:
            freq_mhz = frequency / 1e6
            output_path = Path(f"/tmp/srt_capture_{freq_mhz:.3f}MHz.cfile")

        flow = cls(
            frequency=frequency,
            sample_rate=sample_rate,
            duration=duration,
            output_path=output_path,
            gain=gain,
            device_args=device_args,
        )
        return flow.run_capture()
