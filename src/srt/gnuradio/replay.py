"""IQ replay flowgraph using GNU Radio and osmosdr.

Reads a .cfile (complex64 interleaved I/Q) and transmits via HackRF
at a configurable center frequency and TX gain.
"""

from __future__ import annotations

import time
from pathlib import Path

import osmosdr
import structlog
from gnuradio import blocks, gr

log = structlog.get_logger(__name__)


class ReplayFlow(gr.top_block):
    """GNU Radio flowgraph for IQ replay via osmosdr sink (HackRF).

    Parameters
    ----------
    input_path : str or Path
        Path to the .cfile containing IQ samples to replay.
    frequency : float
        Transmit center frequency in Hz.
    sample_rate : float
        Sample rate matching the captured file (default 2 MS/s).
    tx_gain : float
        Transmit gain in dB (default 20). Keep low in shielded lab.
    repeat : bool
        Whether to loop the file continuously (default False).
    device_args : str
        osmosdr sink device arguments (default "hackrf=0").
    """

    def __init__(
        self,
        input_path: str | Path,
        frequency: float,
        sample_rate: float = 2e6,
        tx_gain: float = 20.0,
        repeat: bool = False,
        device_args: str = "hackrf=0",
    ) -> None:
        super().__init__(name="srt_replay_flow")

        self.input_path = Path(input_path)
        self.frequency = frequency
        self.sample_rate = sample_rate
        self.tx_gain = tx_gain
        self.repeat = repeat
        self.device_args = device_args

        if not self.input_path.exists():
            raise FileNotFoundError(
                f"IQ capture file not found: {self.input_path}"
            )

        # File source: reads raw complex64 IQ samples
        self.file_source = blocks.file_source(
            gr.sizeof_gr_complex,
            str(self.input_path),
            repeat=repeat,
        )

        # Throttle to maintain correct sample rate timing
        self.throttle = blocks.throttle(gr.sizeof_gr_complex, sample_rate)

        # Sink: osmosdr (HackRF transmit)
        self.sink = osmosdr.sink(args=device_args)
        self.sink.set_sample_rate(sample_rate)
        self.sink.set_center_freq(frequency)
        self.sink.set_gain(tx_gain)
        self.sink.set_bandwidth(sample_rate)

        # Connect: file_source -> throttle -> sink
        self.connect(self.file_source, self.throttle, self.sink)

        # Calculate file duration for logging
        file_size = self.input_path.stat().st_size
        num_samples = file_size // 8  # complex64 = 8 bytes per sample
        duration_s = num_samples / sample_rate

        log.info(
            "replay.configured",
            input=str(self.input_path),
            frequency_mhz=frequency / 1e6,
            sample_rate_msps=sample_rate / 1e6,
            tx_gain_db=tx_gain,
            duration_s=round(duration_s, 2),
            repeat=repeat,
        )

    def run_replay(self) -> None:
        """Execute the replay transmission.

        Blocks until the file has been fully transmitted (or until
        stop() is called if repeat=True).
        """
        log.info(
            "replay.start",
            frequency_mhz=self.frequency / 1e6,
            input=str(self.input_path),
        )
        start_time = time.time()

        self.start()
        self.wait()

        elapsed = time.time() - start_time
        log.info("replay.complete", elapsed_s=round(elapsed, 2))

    @classmethod
    def single_shot(
        cls,
        input_path: str | Path,
        frequency: float,
        sample_rate: float = 2e6,
        tx_gain: float = 20.0,
        device_args: str = "hackrf=0",
    ) -> None:
        """Convenience method for a one-shot replay.

        Parameters
        ----------
        input_path : str or Path
            Path to .cfile to replay.
        frequency : float
            Transmit frequency in Hz.
        sample_rate : float
            Sample rate (default 2 MS/s).
        tx_gain : float
            Transmit gain in dB (default 20).
        device_args : str
            osmosdr device string.
        """
        flow = cls(
            input_path=input_path,
            frequency=frequency,
            sample_rate=sample_rate,
            tx_gain=tx_gain,
            repeat=False,
            device_args=device_args,
        )
        flow.run_replay()
