"""LoRaWAN passive recon: listen on EU868, decode PHY frames, extract headers.

Uses gr-lora_sdr (EPFL) for LoRa demodulation via subprocess, with
hackrf_transfer raw IQ capture as fallback.  Decoded bytes are fed to
the LoRaWANParser for frame-level parsing and anomaly detection.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from collections import defaultdict
from typing import Any

import paho.mqtt.client as mqtt
import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register
from srt.recon.lora.frame_parser import CHANNELS, LoRaWANParser

log = structlog.get_logger(__name__)


@register
class LoraRecon(AttackModule):
    name = "lora.recon"
    protocol = "lora"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1040"]
    requires = ["hackrf"]
    description = (
        "LoRaWAN passive capture on EU868, header extraction,"
        " DevAddr/FCnt logging with anomaly detection."
    )

    def __init__(self) -> None:
        self._parser = LoRaWANParser()
        self._mqtt_client: mqtt.Client | None = None
        self._frames: list[dict[str, Any]] = []
        # Anomaly tracking
        self._dev_nonces: dict[str, list[int]] = defaultdict(list)  # DevEUI -> [nonces]
        self._fcnt_tracker: dict[str, int] = {}  # DevAddr -> last_fcnt
        self._anomalies: list[dict[str, Any]] = []

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def _init_mqtt(self) -> None:
        """Initialize MQTT client for header publishing."""
        try:
            client = mqtt.Client(client_id="srt-lora-recon", protocol=mqtt.MQTTv5)
            client.connect("127.0.0.1", 1883, keepalive=60)
            client.loop_start()
            self._mqtt_client = client
        except Exception as exc:
            log.warning("lora.recon.mqtt_connect_failed", error=str(exc))
            self._mqtt_client = None

    def _publish_mqtt(self, payload: dict[str, Any]) -> None:
        """Publish decoded frame to MQTT topic srt/headers/lora."""
        if self._mqtt_client is None:
            return
        try:
            self._mqtt_client.publish("srt/headers/lora", json.dumps(payload))
        except Exception as exc:
            log.debug("lora.recon.mqtt_publish_error", error=str(exc))

    def _start_gr_lora_rx(
        self, freq_hz: int, sf: int, bw: int, duration: int, output_path: str
    ) -> subprocess.Popen[bytes] | None:
        """Start gr-lora_sdr RX flowgraph via subprocess.

        The gr-lora_sdr package provides a command-line decoder or can be
        invoked via a Python-generated flowgraph.  We use the subprocess
        approach for maximum compatibility.
        """
        # gr-lora_sdr decoder command (EPFL implementation)
        # Usage: lora_rx -f <freq> --sf <sf> --bw <bw> --output <file>
        cmd = [
            "python3", "-c",
            f"""
import sys
try:
    from gnuradio import gr, blocks
    import lora_sdr
except ImportError:
    sys.exit(1)

class lora_rx_fg(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "LoRa RX")
        samp_rate = {bw * 2}
        # Source: HackRF via osmosdr
        try:
            import osmosdr
            src = osmosdr.source(args="hackrf=0")
            src.set_sample_rate(samp_rate)
            src.set_center_freq({freq_hz})
            src.set_gain(40)
        except Exception:
            src = blocks.file_source(gr.sizeof_gr_complex, "{output_path}.raw", False)

        # gr-lora_sdr demodulator
        demod = lora_sdr.frame_sync(samp_rate, {bw}, {sf}, False, [0x12], 0)
        decoder = lora_sdr.dewhitening()
        sink = blocks.file_sink(gr.sizeof_char, "{output_path}")
        sink.set_unbuffered(True)

        self.connect(src, demod, decoder, sink)

fg = lora_rx_fg()
fg.start()
import time
time.sleep({duration})
fg.stop()
fg.wait()
""",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return proc
        except (FileNotFoundError, OSError) as exc:
            log.warning("lora.recon.gr_lora_start_failed", error=str(exc))
            return None

    def _hackrf_capture_fallback(
        self, freq_hz: int, duration: int, output_path: str, sample_rate: int = 2_000_000
    ) -> subprocess.Popen[bytes] | None:
        """Fallback: capture raw IQ via hackrf_transfer -r."""
        cmd = [
            "hackrf_transfer",
            "-r", output_path,
            "-f", str(freq_hz),
            "-s", str(sample_rate),
            "-g", "40",
            "-l", "32",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return proc
        except (FileNotFoundError, OSError) as exc:
            log.warning("lora.recon.hackrf_capture_failed", error=str(exc))
            return None

    def _process_decoded_bytes(
        self, data: bytes, freq_hz: int, sf: int, ctx: ModuleContext
    ) -> None:
        """Parse decoded LoRaWAN frame bytes and store/publish."""
        if len(data) < 5:
            return

        parsed = self._parser.parse(data)
        if "error" in parsed:
            log.debug("lora.recon.parse_error", error=parsed["error"])
            return

        ts = time.time()
        parsed["freq_hz"] = freq_hz
        parsed["sf"] = sf
        parsed["ts"] = ts

        # Track anomalies
        self._detect_anomalies(parsed)

        # Determine src address
        src = parsed.get("dev_addr") or parsed.get("dev_eui") or "unknown"

        # Insert into database
        db.insert_header(
            ts=ts,
            session_id=ctx.session_id,
            protocol="lora",
            src=src,
            freq_hz=freq_hz,
            fields={
                "mtype": parsed.get("mtype_str"),
                "fcnt": parsed.get("fcnt"),
                "fport": parsed.get("fport"),
                "mic": parsed.get("mic"),
                "sf": sf,
                "dev_nonce": parsed.get("dev_nonce"),
                "dev_eui": parsed.get("dev_eui"),
                "app_eui": parsed.get("app_eui"),
            },
        )

        # Publish to MQTT
        mqtt_payload = {
            "ts": ts,
            "protocol": "lora",
            "src": src,
            "mtype": parsed.get("mtype_str"),
            "fcnt": parsed.get("fcnt"),
            "fport": parsed.get("fport"),
            "mic": parsed.get("mic"),
            "sf": sf,
            "freq_hz": freq_hz,
        }
        self._publish_mqtt(mqtt_payload)

        self._frames.append(parsed)
        log.info(
            "lora.recon.frame_decoded",
            mtype=parsed.get("mtype_str"),
            src=src,
            fcnt=parsed.get("fcnt"),
        )

    def _detect_anomalies(self, parsed: dict[str, Any]) -> None:
        """Detect FCnt rollback and DevNonce reuse anomalies."""
        mtype = parsed.get("mtype", -1)

        # DevNonce reuse detection (Join Requests)
        if mtype == 0:
            dev_eui = parsed.get("dev_eui", "")
            dev_nonce = parsed.get("dev_nonce")
            if dev_eui and dev_nonce is not None:
                if dev_nonce in self._dev_nonces[dev_eui]:
                    anomaly = {
                        "type": "dev_nonce_reuse",
                        "dev_eui": dev_eui,
                        "dev_nonce": dev_nonce,
                        "ts": time.time(),
                    }
                    self._anomalies.append(anomaly)
                    log.warning(
                        "lora.recon.anomaly.dev_nonce_reuse",
                        dev_eui=dev_eui,
                        dev_nonce=dev_nonce,
                    )
                self._dev_nonces[dev_eui].append(dev_nonce)

        # FCnt rollback detection (Data frames)
        if mtype in (2, 3, 4, 5):
            dev_addr = parsed.get("dev_addr", "")
            fcnt = parsed.get("fcnt")
            if dev_addr and fcnt is not None:
                last_fcnt = self._fcnt_tracker.get(dev_addr)
                if last_fcnt is not None and fcnt < last_fcnt:
                    anomaly = {
                        "type": "fcnt_rollback",
                        "dev_addr": dev_addr,
                        "expected_min": last_fcnt,
                        "received": fcnt,
                        "ts": time.time(),
                    }
                    self._anomalies.append(anomaly)
                    log.warning(
                        "lora.recon.anomaly.fcnt_rollback",
                        dev_addr=dev_addr,
                        last_fcnt=last_fcnt,
                        received_fcnt=fcnt,
                    )
                self._fcnt_tracker[dev_addr] = fcnt

    def _multi_channel_listen(
        self, duration: int, sf: int, ctx: ModuleContext
    ) -> None:
        """Cycle through EU868 channels, listening on each.

        Splits total duration across the three mandatory channels
        (868.1, 868.3, 868.5 MHz) in round-robin fashion.
        """
        primary_channels = [
            CHANNELS[0],  # 868.1 MHz
            CHANNELS[1],  # 868.3 MHz
            CHANNELS[2],  # 868.5 MHz
        ]
        time_per_channel = max(1, duration // len(primary_channels))

        for freq_hz in primary_channels:
            log.info("lora.recon.channel_switch", freq_hz=freq_hz, duration_s=time_per_channel)

            with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
                tmp_path = tmp.name

            try:
                # Attempt gr-lora_sdr first
                proc = self._start_gr_lora_rx(freq_hz, sf, 125000, time_per_channel, tmp_path)
                if proc is None:
                    # Fallback to raw IQ capture
                    proc = self._hackrf_capture_fallback(
                        freq_hz, time_per_channel, tmp_path
                    )

                if proc is not None:
                    try:
                        proc.wait(timeout=time_per_channel + 5)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                        proc.wait(timeout=3)

                # Read decoded output and parse frames
                if os.path.exists(tmp_path):
                    with open(tmp_path, "rb") as f:
                        data = f.read()
                    # Each frame in gr-lora_sdr output is newline/null separated
                    # Process contiguous frame chunks
                    if data:
                        self._process_decoded_bytes(data, freq_hz, sf, ctx)
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()
        duration = int(ctx.params.get("duration_s", 60))
        sf = int(ctx.params.get("sf", 7))
        band = ctx.params.get("band", "eu868")

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary=f"[DRY-RUN] lora.recon would listen on {band} for {duration}s",
                metrics={"duration_s": duration, "band": band, "sf": sf},
            )

        self._init_mqtt()

        try:
            self._multi_channel_listen(duration, sf, ctx)
        except Exception as exc:
            log.error("lora.recon.listen_error", error=str(exc))
            return self._result(
                Status.FAIL,
                started,
                summary=f"LoRa recon error: {exc}",
            )

        frame_count = len(self._frames)
        unique_devices = len(
            set(
                f.get("dev_addr") or f.get("dev_eui") or ""
                for f in self._frames
            )
            - {""}
        )
        anomaly_count = len(self._anomalies)

        summary = (
            f"lora.recon completed: {frame_count} frames decoded, "
            f"{unique_devices} unique devices, {anomaly_count} anomalies "
            f"over {duration}s on {band}"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "anomalies", "data": self._anomalies[:50]},
            ],
            metrics={
                "frame_count": frame_count,
                "unique_devices": unique_devices,
                "anomaly_count": anomaly_count,
                "duration_s": duration,
                "band": band,
                "sf": sf,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        """Disconnect MQTT and reset state."""
        if self._mqtt_client:
            try:
                self._mqtt_client.loop_stop()
                self._mqtt_client.disconnect()
            except Exception:
                pass
            self._mqtt_client = None
        self._frames.clear()
        self._anomalies.clear()
