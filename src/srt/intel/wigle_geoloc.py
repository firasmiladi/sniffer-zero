"""intel.wigle_geoloc - Geolocate any WiFi AP worldwide via Wigle.net API

Tu captures un BSSID lors d'une opération. Tu le passes à Wigle.
Wigle te retourne les coordonnées GPS exactes de cet AP.
1+ milliard de réseaux WiFi mappés dans le monde.

Usage: Tu interceptes un signal WiFi → tu sais OÙ est l'émetteur physiquement.

MITRE: T1592
Hardware: aucun (requête API)
"""

from __future__ import annotations

import json
import time
from typing import Any

import structlog

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class IntelWigleGeoloc(AttackModule):
    name = "intel.wigle_geoloc"
    protocol = "wifi"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1592"]
    cve = []
    description = "Geolocate WiFi AP by BSSID using Wigle.net database (1B+ networks)."
    requires = []

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY CAGE BYPASS

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        bssid = ctx.params.get("bssid")
        api_name = ctx.params.get("api_name", "")
        api_token = ctx.params.get("api_token", "")

        if not bssid:
            return self._result(
                Status.FAIL, started,
                summary="Missing param 'bssid'. Usage: --param bssid=AA:BB:CC:DD:EE:FF",
            )

        if ctx.dry_run:
            return self._result(
                Status.OK, started,
                summary=f"[DRY-RUN] intel.wigle_geoloc bssid={bssid}",
                metrics={"bssid": bssid},
            )

        log.info("intel.wigle_geoloc.querying", bssid=bssid)

        if not api_name or not api_token:
            return self._result(
                Status.OK, started,
                summary=(
                    f"intel.wigle_geoloc bssid={bssid}: "
                    "API credentials not provided. "
                    "Get free API key at https://wigle.net/account "
                    "Then: --param api_name=AID... --param api_token=..."
                ),
                metrics={"bssid": bssid, "api_configured": False},
            )

        # Query Wigle API
        try:
            import requests
        except ImportError:
            return self._result(
                Status.FAIL, started,
                summary="requests library not installed. Run: pip3 install requests",
            )

        url = "https://api.wigle.net/api/v2/network/search"
        params = {"netid": bssid}
        auth = (api_name, api_token)

        try:
            resp = requests.get(url, params=params, auth=auth, timeout=30)
            data = resp.json()
        except Exception as exc:
            return self._result(Status.FAIL, started, summary=f"Wigle API error: {exc}")

        if not data.get("success") or not data.get("results"):
            return self._result(
                Status.OK, started,
                summary=f"intel.wigle_geoloc bssid={bssid}: not found in Wigle database",
                metrics={"bssid": bssid, "found": False},
            )

        result = data["results"][0]
        lat = result.get("trilat")
        lon = result.get("trilong")
        ssid = result.get("ssid", "unknown")
        last_seen = result.get("lastupdt", "unknown")
        country = result.get("country", "unknown")
        city = result.get("city", "unknown")

        log.info(
            "intel.wigle_geoloc.found",
            bssid=bssid, lat=lat, lon=lon, ssid=ssid, city=city,
        )

        return self._result(
            Status.OK, started,
            summary=(
                f"intel.wigle_geoloc bssid={bssid}: "
                f"LOCATED at {lat},{lon} ({city}, {country}) "
                f"SSID={ssid} last_seen={last_seen}"
            ),
            artifacts=[{
                "type": "geolocation",
                "data": {
                    "bssid": bssid,
                    "latitude": lat,
                    "longitude": lon,
                    "ssid": ssid,
                    "country": country,
                    "city": city,
                    "last_seen": last_seen,
                    "google_maps": f"https://maps.google.com/?q={lat},{lon}",
                },
            }],
            metrics={
                "bssid": bssid,
                "found": True,
                "latitude": lat,
                "longitude": lon,
                "country": country,
            },
        )
