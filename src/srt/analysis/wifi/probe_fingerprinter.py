"""WiFi probe request fingerprinting engine.

Build device fingerprints from probe request IEs, supported rates, and
HT capabilities. Group randomized MACs by fingerprint similarity to track
physical devices across MAC address changes.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)

# Known device probe patterns
DEVICE_SIGNATURES: dict[str, dict[str, Any]] = {
    "apple_ios": {
        "probe_pattern": "directed_then_broadcast",
        "ie_ids_present": [1, 50, 45, 127, 107],
        "description": "Apple iOS device (iPhone/iPad)",
    },
    "apple_macos": {
        "probe_pattern": "broadcast_heavy",
        "ie_ids_present": [1, 50, 45, 127, 221],
        "description": "Apple macOS device",
    },
    "android_generic": {
        "probe_pattern": "mixed",
        "ie_ids_present": [1, 50, 45, 191, 127],
        "description": "Android device (generic)",
    },
    "windows_laptop": {
        "probe_pattern": "directed_heavy",
        "ie_ids_present": [1, 50, 45, 127, 221],
        "description": "Windows laptop/tablet",
    },
    "iot_device": {
        "probe_pattern": "periodic_directed",
        "ie_ids_present": [1],
        "description": "IoT/embedded device (limited IEs)",
    },
}


def _compute_fingerprint(ie_ids: list[int], rates: list[float],
                         ht_present: bool, vht_present: bool,
                         he_present: bool) -> str:
    """Compute a stable fingerprint hash from probe request features."""
    parts = [
        ",".join(str(i) for i in sorted(ie_ids)),
        ",".join(f"{r:.1f}" for r in sorted(rates)),
        f"ht={ht_present}",
        f"vht={vht_present}",
        f"he={he_present}",
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _is_random_mac(mac: str) -> bool:
    """Check if MAC is locally administered (randomized)."""
    if not mac or len(mac) < 2:
        return False
    try:
        first_byte = int(mac.replace(":", "").replace("-", "")[:2], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


@register
class WiFiProbeFingerprinter(AttackModule):
    """Device fingerprinting via probe request analysis.

    Builds fingerprints from probe IEs, supported rates, HT capabilities,
    groups randomized MACs by fingerprint similarity (hash-based clustering),
    identifies device types by probe patterns, and tracks PNL (Preferred
    Network List) from directed probes.
    """

    name = "wifi.probe_fingerprinter"
    protocol = "wifi"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1592.002", "T1018"]
    requires = []
    description = (
        "Device fingerprinting from probe requests: IE-based fingerprints, "
        "MAC randomization grouping, device type identification, PNL tracking."
    )

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def _extract_probe_features(
        self, fields: dict[str, Any]
    ) -> dict[str, Any]:
        """Extract fingerprint features from probe request fields."""
        ie_ids: list[int] = fields.get("ie_ids", [])
        rates: list[float] = fields.get("rates_mbps", [])
        ht_present = fields.get("ht_present", False)
        vht_present = fields.get("vht_present", False)
        he_present = fields.get("he_present", False)

        fingerprint = _compute_fingerprint(ie_ids, rates, ht_present, vht_present, he_present)

        return {
            "fingerprint": fingerprint,
            "ie_ids": ie_ids,
            "rates": rates,
            "ht": ht_present,
            "vht": vht_present,
            "he": he_present,
        }

    def _identify_device_type(self, ie_ids: list[int], rates: list[float]) -> str:
        """Identify device type based on IE patterns."""
        ie_set = set(ie_ids)

        # Apple devices: typically have HT (45), extended caps (127), Apple vendor IE
        if 45 in ie_set and 127 in ie_set and 107 in ie_set:
            return "apple_ios"
        if 45 in ie_set and 191 in ie_set and 127 in ie_set:
            return "android_generic"
        if len(ie_ids) <= 3:
            return "iot_device"
        if 45 in ie_set and 127 in ie_set:
            return "windows_laptop"
        return "unknown"

    def _cluster_by_fingerprint(
        self, devices: dict[str, dict[str, Any]]
    ) -> dict[str, list[str]]:
        """Group MACs by fingerprint to identify same physical device."""
        fp_groups: dict[str, list[str]] = {}
        for mac, info in devices.items():
            fp = info.get("fingerprint", "")
            if fp:
                fp_groups.setdefault(fp, []).append(mac)
        return fp_groups

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary="[DRY-RUN] wifi.probe_fingerprinter would analyze probes",
            )

        devices: dict[str, dict[str, Any]] = {}
        pnl: dict[str, list[str]] = {}  # MAC -> list of probed SSIDs

        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT src, fields
                    FROM headers
                    WHERE session_id = %s AND protocol = 'wifi'
                      AND fields->>'frame_type' = 'probe_request'
                    ORDER BY ts
                    """,
                    (str(ctx.session_id),),
                )
                for row in cur.fetchall():
                    src, fields = row
                    if not src:
                        continue
                    if isinstance(fields, str):
                        import json
                        try:
                            fields = json.loads(fields)
                        except (ValueError, TypeError):
                            fields = {}
                    if not isinstance(fields, dict):
                        fields = {}

                    features = self._extract_probe_features(fields)
                    ie_ids = features.get("ie_ids", [])
                    rates = features.get("rates", [])
                    device_type = self._identify_device_type(ie_ids, rates)

                    devices[src] = {
                        "fingerprint": features["fingerprint"],
                        "device_type": device_type,
                        "is_random_mac": _is_random_mac(src),
                        "ie_count": len(ie_ids),
                        "ht": features["ht"],
                        "vht": features["vht"],
                        "he": features["he"],
                    }

                    # Track PNL (directed probes)
                    ssid = fields.get("ssid", "")
                    if ssid:
                        pnl.setdefault(src, [])
                        if ssid not in pnl[src]:
                            pnl[src].append(ssid)

        except Exception as exc:
            log.warning("wifi.probe_fingerprinter.db_error", error=str(exc))
            return self._result(
                Status.FAIL, started, summary=f"DB query error: {exc}"
            )

        # Cluster random MACs
        clusters = self._cluster_by_fingerprint(devices)

        random_mac_count = sum(1 for d in devices.values() if d.get("is_random_mac"))
        cluster_count = sum(1 for macs in clusters.values() if len(macs) > 1)

        # Device type distribution
        type_dist: dict[str, int] = {}
        for d in devices.values():
            dt = d.get("device_type", "unknown")
            type_dist[dt] = type_dist.get(dt, 0) + 1

        summary = (
            f"Fingerprinted {len(devices)} devices ({random_mac_count} randomized MACs), "
            f"{cluster_count} multi-MAC clusters, "
            f"{sum(len(v) for v in pnl.values())} SSIDs in PNLs"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "device_fingerprints", "data": devices},
                {"type": "mac_clusters", "data": {
                    fp: macs for fp, macs in clusters.items() if len(macs) > 1
                }},
                {"type": "pnl_map", "data": pnl},
                {"type": "device_type_distribution", "data": type_dist},
            ],
            metrics={
                "total_devices": len(devices),
                "random_mac_count": random_mac_count,
                "cluster_count": cluster_count,
                "pnl_ssids": sum(len(v) for v in pnl.values()),
                "device_types": type_dist,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
