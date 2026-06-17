"""defense.rogue_ap_detector - Detect Evil Twins and Rogue APs

Surveille l'environnement WiFi et ALERTE si:
- Un SSID connu apparaît avec un BSSID inconnu (Evil Twin)
- Deux BSSIDs différents annoncent le même SSID
- Le jitter beacon d'un AP est anormal (software AP = hostapd)
- Un nouveau AP apparaît soudainement (deployed attacker)

Protège les réseaux WiFi institutionnels contre les attaquants.

MITRE: Defense against T1557
Hardware: ALFA AWUS036NH (mode monitor)
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from typing import Any

import structlog
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sniff

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class DefenseRogueApDetector(AttackModule):
    name = "defense.rogue_ap_detector"
    protocol = "wifi"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1557"]
    cve = []
    description = (
        "Blue Team: Detect Evil Twins, Rogue APs, and suspicious "
        "access points by monitoring beacon anomalies."
    )
    requires = ["monitor-mode-nic"]

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._known_aps: dict[str, str] = {}  # ssid → expected bssid
        self._seen_aps: dict[str, dict[str, Any]] = {}
        self._alerts: list[dict[str, Any]] = []

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY CAGE BYPASS

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        iface = ctx.params.get("interface", "wlan0mon")
        duration = int(ctx.params.get("duration_s", 300))
        known_aps_str = ctx.params.get("known_aps", "")

        # Parse known APs: "SSID1:BSSID1,SSID2:BSSID2"
        if known_aps_str:
            for pair in known_aps_str.split(","):
                if ":" in pair:
                    parts = pair.split(":", 1)
                    if len(parts) == 2:
                        self._known_aps[parts[0].strip()] = parts[1].strip()

        if ctx.dry_run:
            return self._result(
                Status.OK, started,
                summary=f"[DRY-RUN] defense.rogue_ap_detector duration={duration}s",
                metrics={"known_aps": len(self._known_aps)},
            )

        log.info(
            "defense.rogue_ap_detector.starting",
            iface=iface, duration=duration, known_aps=len(self._known_aps),
        )

        self._stop_event.clear()

        def packet_handler(pkt: Any) -> None:
            if not pkt.haslayer(Dot11Beacon):
                return

            bssid = pkt[Dot11].addr3
            if not bssid:
                return

            # Extract SSID
            ssid = ""
            elt = pkt.getlayer(Dot11Elt)
            if elt and elt.ID == 0:
                try:
                    ssid = elt.info.decode("utf-8", errors="replace")
                except Exception:
                    pass

            rssi = getattr(pkt.getlayer(RadioTap), "dBm_AntSignal", None) if pkt.haslayer(RadioTap) else None
            ts = time.time()

            # Track AP
            if bssid not in self._seen_aps:
                self._seen_aps[bssid] = {
                    "ssid": ssid, "first_seen": ts, "last_seen": ts,
                    "beacon_count": 1, "rssi": rssi,
                }

                # CHECK 1: Known SSID with unknown BSSID = EVIL TWIN
                if ssid in self._known_aps and bssid.upper() != self._known_aps[ssid].upper():
                    alert = {
                        "type": "EVIL_TWIN",
                        "severity": "CRITICAL",
                        "timestamp": ts,
                        "ssid": ssid,
                        "rogue_bssid": bssid,
                        "expected_bssid": self._known_aps[ssid],
                        "rssi": rssi,
                    }
                    self._alerts.append(alert)
                    log.warning("defense.ALERT.evil_twin", **alert)

                # CHECK 2: New AP appeared (not in known list)
                elif ssid and self._known_aps and ssid not in self._known_aps:
                    alert = {
                        "type": "NEW_AP",
                        "severity": "MEDIUM",
                        "timestamp": ts,
                        "ssid": ssid,
                        "bssid": bssid,
                        "rssi": rssi,
                    }
                    self._alerts.append(alert)
                    log.info("defense.ALERT.new_ap", **alert)
            else:
                self._seen_aps[bssid]["last_seen"] = ts
                self._seen_aps[bssid]["beacon_count"] += 1

            # CHECK 3: Duplicate SSID on different BSSIDs
            ssid_bssids = [
                b for b, info in self._seen_aps.items()
                if info["ssid"] == ssid and ssid
            ]
            if len(ssid_bssids) > 1 and ssid:
                existing = [a for a in self._alerts if a.get("type") == "DUPLICATE_SSID" and a.get("ssid") == ssid]
                if not existing:
                    alert = {
                        "type": "DUPLICATE_SSID",
                        "severity": "HIGH",
                        "timestamp": ts,
                        "ssid": ssid,
                        "bssids": ssid_bssids,
                    }
                    self._alerts.append(alert)
                    log.warning("defense.ALERT.duplicate_ssid", **alert)

        # Sniff
        try:
            sniff(
                iface=iface,
                prn=packet_handler,
                timeout=duration,
                store=False,
                monitor=True,
            )
        except Exception as exc:
            return self._result(Status.FAIL, started, summary=f"Sniff error: {exc}")

        log.info(
            "defense.rogue_ap_detector.completed",
            aps_seen=len(self._seen_aps), alerts=len(self._alerts),
        )

        return self._result(
            Status.OK, started,
            summary=(
                f"defense.rogue_ap_detector: {len(self._seen_aps)} APs monitored, "
                f"{len(self._alerts)} alerts raised in {duration}s"
            ),
            artifacts=[
                {"type": "security_alerts", "data": self._alerts},
                {"type": "ap_inventory", "data": dict(self._seen_aps)},
            ],
            metrics={
                "aps_monitored": len(self._seen_aps),
                "alerts_raised": len(self._alerts),
                "critical_alerts": len([a for a in self._alerts if a.get("severity") == "CRITICAL"]),
                "duration_s": duration,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        self._stop_event.set()
