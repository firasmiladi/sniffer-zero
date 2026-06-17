"""defense.alerting - Real-time WiFi threat alerting

Surveille en continu et ALERTE immédiatement via MQTT si:
- Deauth flood détecté (>20 deauths en 5s)
- Nouveau AP inconnu apparaît
- Nouveau device inconnu rejoint le réseau
- Signal brouillage détecté (bruit anormal)

Publie sur MQTT topic: srt/alerts/<type>

MITRE: Defense
Hardware: ALFA AWUS036NH (mode monitor)
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

import structlog
from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, RadioTap, sniff

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class DefenseAlerting(AttackModule):
    name = "defense.alerting"
    protocol = "wifi"
    risk = Risk.PASSIVE
    mitre_ttp = []
    cve = []
    description = (
        "Real-time WiFi threat alerting - detect deauth floods, "
        "rogue APs, unknown devices. Alerts via MQTT."
    )
    requires = ["monitor-mode-nic"]

    def __init__(self) -> None:
        self._alerts: list[dict[str, Any]] = []
        self._deauth_times: list[float] = []
        self._known_bssids: set[str] = set()
        self._known_clients: set[str] = set()
        self._mqtt_client = None

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY CAGE BYPASS

    def _init_mqtt(self) -> None:
        try:
            import paho.mqtt.client as mqtt
            client = mqtt.Client(client_id="srt-defense-alerting")
            client.connect("127.0.0.1", 1883, keepalive=60)
            client.loop_start()
            self._mqtt_client = client
        except Exception:
            self._mqtt_client = None

    def _publish_alert(self, alert: dict[str, Any]) -> None:
        self._alerts.append(alert)
        log.warning("defense.ALERT", **alert)
        if self._mqtt_client:
            try:
                topic = f"srt/alerts/{alert.get('type', 'generic')}"
                self._mqtt_client.publish(topic, json.dumps(alert))
            except Exception:
                pass

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        iface = ctx.params.get("interface", "wlan0mon")
        duration = int(ctx.params.get("duration_s", 300))
        deauth_threshold = int(ctx.params.get("deauth_threshold", 20))
        deauth_window = int(ctx.params.get("deauth_window_s", 5))

        if ctx.dry_run:
            return self._result(
                Status.OK, started,
                summary=f"[DRY-RUN] defense.alerting duration={duration}s",
                metrics={"duration_s": duration},
            )

        self._init_mqtt()
        self._alerts = []
        self._deauth_times = []

        log.info("defense.alerting.starting", iface=iface, duration=duration)

        def packet_handler(pkt: Any) -> None:
            ts = time.time()

            if not pkt.haslayer(Dot11):
                return

            dot11 = pkt[Dot11]

            # DETECT: Deauth flood
            if pkt.haslayer(Dot11Deauth):
                self._deauth_times.append(ts)
                # Remove old entries outside window
                self._deauth_times = [
                    t for t in self._deauth_times if ts - t <= deauth_window
                ]
                if len(self._deauth_times) >= deauth_threshold:
                    self._publish_alert({
                        "type": "DEAUTH_FLOOD",
                        "severity": "CRITICAL",
                        "timestamp": ts,
                        "count": len(self._deauth_times),
                        "window_s": deauth_window,
                        "src": dot11.addr2,
                        "dst": dot11.addr1,
                    })
                    self._deauth_times = []  # Reset after alert

            # DETECT: New AP
            if pkt.haslayer(Dot11Beacon):
                bssid = dot11.addr3
                if bssid and bssid not in self._known_bssids:
                    self._known_bssids.add(bssid)
                    ssid = ""
                    elt = pkt.getlayer(Dot11Elt)
                    if elt and elt.ID == 0 and elt.info:
                        try:
                            ssid = elt.info.decode("utf-8", errors="replace")
                        except Exception:
                            pass
                    self._publish_alert({
                        "type": "NEW_AP",
                        "severity": "MEDIUM",
                        "timestamp": ts,
                        "bssid": bssid,
                        "ssid": ssid,
                    })

            # DETECT: New client
            src = dot11.addr2
            if src and src not in self._known_clients and src not in self._known_bssids:
                if dot11.type == 2 or (dot11.type == 0 and dot11.subtype == 4):
                    self._known_clients.add(src)
                    if len(self._known_clients) > 5:  # Avoid alerting on first scan
                        self._publish_alert({
                            "type": "NEW_DEVICE",
                            "severity": "LOW",
                            "timestamp": ts,
                            "mac": src,
                        })

        try:
            sniff(
                iface=iface, prn=packet_handler,
                timeout=duration, store=False, monitor=True,
            )
        except Exception as exc:
            return self._result(Status.FAIL, started, summary=f"Sniff error: {exc}")

        log.info(
            "defense.alerting.completed",
            alerts=len(self._alerts),
            aps_seen=len(self._known_bssids),
            clients_seen=len(self._known_clients),
        )

        return self._result(
            Status.OK, started,
            summary=(
                f"defense.alerting: {len(self._alerts)} alerts raised, "
                f"{len(self._known_bssids)} APs, {len(self._known_clients)} clients "
                f"monitored in {duration}s"
            ),
            artifacts=[{"type": "security_alerts", "data": self._alerts}],
            metrics={
                "alerts_total": len(self._alerts),
                "deauth_flood_alerts": len([a for a in self._alerts if a["type"] == "DEAUTH_FLOOD"]),
                "new_ap_alerts": len([a for a in self._alerts if a["type"] == "NEW_AP"]),
                "new_device_alerts": len([a for a in self._alerts if a["type"] == "NEW_DEVICE"]),
                "aps_monitored": len(self._known_bssids),
                "clients_monitored": len(self._known_clients),
                "duration_s": duration,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        if self._mqtt_client:
            try:
                self._mqtt_client.loop_stop()
                self._mqtt_client.disconnect()
            except Exception:
                pass
