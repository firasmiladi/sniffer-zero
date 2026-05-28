"""WiFi passive recon: channel-hop survey, AP/client inventory, OUI lookup.

Wraps iw + scapy for 802.11 frame sniffing.
Emits headers to MQTT + TimescaleDB.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from typing import Any

import paho.mqtt.client as mqtt
import structlog
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap, sniff

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


def _parse_channels(spec: str) -> list[int]:
    """Parse channel spec like '1-13' or '1,6,11' into list of ints."""
    channels: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            channels.extend(range(int(lo), int(hi) + 1))
        else:
            channels.append(int(part))
    return channels


def _get_encryption(pkt: Any) -> str:
    """Extract encryption type from beacon frame."""
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").strip()
    if "privacy" not in cap:
        return "OPEN"
    # Check for RSN (WPA2) or WPA element
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 48:
            return "WPA2"
        if elt.ID == 221 and elt.info and elt.info.startswith(b"\x00\x50\xf2\x01"):
            return "WPA"
        elt = elt.payload.getlayer(Dot11Elt)
    return "WEP"


@register
class WifiRecon(AttackModule):
    name = "wifi.recon"
    protocol = "wifi"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1040", "T1592"]
    requires = ["monitor-mode-nic"]
    description = "Channel-hop survey: AP inventory, client probe requests, OUI lookup."

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._hop_thread: threading.Thread | None = None
        self._aps: dict[str, dict[str, Any]] = {}
        self._clients: set[str] = set()
        self._frame_count: int = 0
        self._mqtt_client: mqtt.Client | None = None

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def _channel_hop(self, iface: str, channels: list[int], dwell_ms: int) -> None:
        """Hop channels in a loop until stop event is set."""
        idx = 0
        while not self._stop_event.is_set():
            ch = channels[idx % len(channels)]
            try:
                subprocess.run(
                    ["iw", "dev", iface, "set", "channel", str(ch)],
                    capture_output=True,
                    timeout=5,
                )
            except (subprocess.SubprocessError, OSError) as exc:
                log.debug("wifi.recon.channel_hop_error", channel=ch, error=str(exc))
            idx += 1
            self._stop_event.wait(dwell_ms / 1000.0)

    def _packet_handler(self, pkt: Any, ctx: ModuleContext) -> None:
        """Process each sniffed 802.11 frame."""
        if not pkt.haslayer(Dot11):
            return

        self._frame_count += 1
        ts = time.time()
        dot11 = pkt.getlayer(Dot11)
        frame_type = dot11.type
        frame_subtype = dot11.subtype

        # Extract RSSI from RadioTap
        rssi: int | None = None
        if pkt.haslayer(RadioTap):
            rssi = getattr(pkt.getlayer(RadioTap), "dBm_AntSignal", None)

        src_mac = dot11.addr2
        dst_mac = dot11.addr1
        bssid = dot11.addr3

        # Beacon frame - AP discovery
        if pkt.haslayer(Dot11Beacon):
            ssid = ""
            elt = pkt.getlayer(Dot11Elt)
            if elt and elt.ID == 0:
                try:
                    ssid = elt.info.decode("utf-8", errors="replace")
                except (AttributeError, UnicodeDecodeError):
                    ssid = ""

            channel: int | None = None
            ds_elt = pkt.getlayer(Dot11Elt)
            while ds_elt:
                if ds_elt.ID == 3 and ds_elt.info:
                    channel = ds_elt.info[0]
                    break
                ds_elt = ds_elt.payload.getlayer(Dot11Elt)

            encryption = _get_encryption(pkt)

            if bssid and bssid not in self._aps:
                self._aps[bssid] = {
                    "ssid": ssid,
                    "channel": channel,
                    "encryption": encryption,
                    "rssi": rssi,
                    "first_seen": ts,
                }
                log.info(
                    "wifi.recon.ap_discovered",
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    encryption=encryption,
                    rssi=rssi,
                )

            fields = {
                "frame_type": "beacon",
                "ssid": ssid,
                "bssid": bssid,
                "encryption": encryption,
            }
            db.insert_header(
                ts=ts,
                session_id=ctx.session_id,
                protocol="wifi",
                src=bssid,
                dst="ff:ff:ff:ff:ff:ff",
                channel=channel,
                rssi_dbm=rssi,
                fields=fields,
            )
            self._publish_mqtt(fields, ts)

        # Probe request - client discovery
        elif pkt.haslayer(Dot11ProbeReq):
            if src_mac:
                self._clients.add(src_mac)
            ssid = ""
            elt = pkt.getlayer(Dot11Elt)
            if elt and elt.ID == 0 and elt.info:
                try:
                    ssid = elt.info.decode("utf-8", errors="replace")
                except (AttributeError, UnicodeDecodeError):
                    ssid = ""

            fields = {
                "frame_type": "probe_request",
                "ssid": ssid,
                "client": src_mac,
            }
            db.insert_header(
                ts=ts,
                session_id=ctx.session_id,
                protocol="wifi",
                src=src_mac,
                dst="ff:ff:ff:ff:ff:ff",
                rssi_dbm=rssi,
                fields=fields,
            )
            self._publish_mqtt(fields, ts)

        # Data frame
        elif frame_type == 2:
            if src_mac:
                self._clients.add(src_mac)
            fields = {
                "frame_type": "data",
                "subtype": frame_subtype,
                "bssid": bssid,
            }
            db.insert_header(
                ts=ts,
                session_id=ctx.session_id,
                protocol="wifi",
                src=src_mac,
                dst=dst_mac,
                rssi_dbm=rssi,
                fields=fields,
            )

    def _publish_mqtt(self, fields: dict[str, Any], ts: float) -> None:
        """Publish frame info to MQTT topic."""
        if self._mqtt_client is None:
            return
        try:
            payload = json.dumps({"ts": ts, **fields})
            self._mqtt_client.publish("srt/headers/wifi", payload)
        except Exception as exc:
            log.debug("wifi.recon.mqtt_publish_error", error=str(exc))

    def _init_mqtt(self) -> None:
        """Initialize MQTT client for publishing."""
        try:
            client = mqtt.Client(client_id="srt-wifi-recon", protocol=mqtt.MQTTv5)
            client.connect("127.0.0.1", 1883, keepalive=60)
            client.loop_start()
            self._mqtt_client = client
        except Exception as exc:
            log.warning("wifi.recon.mqtt_connect_failed", error=str(exc))
            self._mqtt_client = None

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()
        iface = ctx.params.get("interface", "wlan0mon")
        duration = int(ctx.params.get("duration_s", 30))
        channel_spec = ctx.params.get("channels", "1-13")
        dwell_ms = int(ctx.params.get("dwell_ms", 200))

        channels = _parse_channels(channel_spec)

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary=f"[DRY-RUN] wifi.recon channels={channel_spec} duration={duration}s",
                metrics={"duration_s": duration, "channels": channel_spec},
            )

        self._init_mqtt()

        # Start channel hopping thread
        self._stop_event.clear()
        self._hop_thread = threading.Thread(
            target=self._channel_hop,
            args=(iface, channels, dwell_ms),
            daemon=True,
        )
        self._hop_thread.start()

        # Sniff for the specified duration
        try:
            sniff(
                iface=iface,
                prn=lambda pkt: self._packet_handler(pkt, ctx),
                timeout=duration,
                store=False,
                monitor=True,
            )
        except Exception as exc:
            log.error("wifi.recon.sniff_error", error=str(exc))
            self._stop_event.set()
            return self._result(
                Status.FAIL,
                started,
                summary=f"Sniff error: {exc}",
            )

        # Stop channel hopping
        self._stop_event.set()
        if self._hop_thread:
            self._hop_thread.join(timeout=5)

        ap_count = len(self._aps)
        client_count = len(self._clients)
        summary = (
            f"wifi.recon completed: {ap_count} APs discovered, "
            f"{client_count} clients seen, {self._frame_count} frames captured "
            f"over {duration}s on channels {channel_spec}"
        )

        top_aps = [
            {"bssid": k, "ssid": v["ssid"], "channel": v["channel"], "encryption": v["encryption"]}
            for k, v in list(self._aps.items())[:20]
        ]

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[{"type": "ap_list", "data": top_aps}],
            metrics={
                "ap_count": ap_count,
                "client_count": client_count,
                "frame_count": self._frame_count,
                "duration_s": duration,
                "channels": channel_spec,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        """Stop all threads and disconnect MQTT."""
        self._stop_event.set()
        if self._hop_thread and self._hop_thread.is_alive():
            self._hop_thread.join(timeout=5)
        if self._mqtt_client:
            try:
                self._mqtt_client.loop_stop()
                self._mqtt_client.disconnect()
            except Exception:
                pass
            self._mqtt_client = None
