"""BLE MAC randomization tracking engine.

Fingerprints devices by manufacturer_data patterns, advertising intervals,
TX power levels; groups random MACs to physical devices; detects Apple
Continuity, Google Nearby, Microsoft Swift Pair, and AirTag patterns.
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

# Known manufacturer data patterns for device identification
APPLE_CONTINUITY_PREFIX = "4c00"  # Company ID 0x004C (Apple)
GOOGLE_NEARBY_PREFIX = "e000"  # Company ID 0x00E0 (Google)
MICROSOFT_SWIFT_PAIR_PREFIX = "0600"  # Company ID 0x0006 (Microsoft)

# Apple Continuity message types
APPLE_MESSAGE_TYPES: dict[int, str] = {
    0x01: "Apple_Proximity_Pairing",
    0x03: "AirPrint",
    0x05: "AirDrop",
    0x06: "HomeKit",
    0x07: "Proximity_Pairing",
    0x08: "Hey_Siri",
    0x09: "AirPlay",
    0x0A: "Magic_Switch",
    0x0B: "Handoff",
    0x0C: "Tethering_Target",
    0x0D: "Tethering_Source",
    0x0E: "Nearby_Action",
    0x0F: "Nearby_Info",
    0x10: "FindMy",
    0x12: "FindMy_AirTag",
}


def _is_random_mac(mac: str) -> bool:
    """Check if MAC is locally administered (randomized)."""
    if not mac or len(mac) < 2:
        return False
    try:
        first_byte = int(mac.replace(":", "").replace("-", "")[:2], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


def _compute_device_fingerprint(
    manufacturer_data: dict[str, str],
    tx_power: int | None,
    service_uuids: list[str],
) -> str:
    """Compute a fingerprint to group random MACs to a physical device."""
    parts: list[str] = []

    # Manufacturer data patterns (company IDs are stable)
    for company_id in sorted(manufacturer_data.keys()):
        data = manufacturer_data[company_id]
        # Use first 4 bytes of manufacturer data (type/length are stable)
        stable_part = data[:8] if len(data) >= 8 else data
        parts.append(f"mfr:{company_id}:{stable_part}")

    # TX power is typically consistent per device
    if tx_power is not None:
        parts.append(f"tx:{tx_power}")

    # Service UUIDs are stable per device type
    for uuid in sorted(service_uuids):
        parts.append(f"svc:{uuid}")

    if not parts:
        return ""

    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _detect_apple_continuity(manufacturer_data: dict[str, str]) -> dict[str, Any] | None:
    """Detect and decode Apple Continuity protocol messages."""
    for company_id, data in manufacturer_data.items():
        if company_id.lower() in ("76", "0x004c", "4c"):
            # Apple manufacturer data
            if len(data) >= 4:
                try:
                    msg_type = int(data[0:2], 16)
                    msg_name = APPLE_MESSAGE_TYPES.get(msg_type, f"Unknown_0x{msg_type:02X}")
                    result: dict[str, Any] = {
                        "protocol": "Apple_Continuity",
                        "message_type": msg_type,
                        "message_name": msg_name,
                    }
                    if msg_type in (0x10, 0x12):
                        result["is_findmy"] = True
                        result["is_airtag"] = msg_type == 0x12
                    return result
                except (ValueError, IndexError):
                    pass
    return None


def _detect_google_nearby(manufacturer_data: dict[str, str]) -> dict[str, Any] | None:
    """Detect Google Nearby protocol."""
    for company_id, data in manufacturer_data.items():
        if company_id.lower() in ("224", "0x00e0", "e0"):
            return {
                "protocol": "Google_Nearby",
                "data_len": len(data) // 2,
            }
    return None


def _detect_microsoft_swift_pair(manufacturer_data: dict[str, str]) -> dict[str, Any] | None:
    """Detect Microsoft Swift Pair protocol."""
    for company_id, data in manufacturer_data.items():
        if company_id.lower() in ("6", "0x0006", "06"):
            if data.startswith("030080"):
                return {
                    "protocol": "Microsoft_Swift_Pair",
                    "data_len": len(data) // 2,
                }
    return None


@register
class BleMacRandomizationTracker(AttackModule):
    """BLE MAC randomization de-anonymization tracker.

    Fingerprints devices by manufacturer_data patterns, advertising intervals,
    TX power; groups multiple random MACs to same physical device; detects
    Apple Continuity/Google Nearby/Microsoft Swift Pair/AirTag patterns.
    """

    name = "ble.mac_randomization_tracker"
    protocol = "ble"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1592.002", "T1018"]
    requires = []
    description = (
        "Track devices across MAC randomization: fingerprint by advertising "
        "patterns, group random MACs, detect Apple/Google/Microsoft protocols."
    )

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary="[DRY-RUN] ble.mac_randomization_tracker would track devices",
            )

        devices: dict[str, dict[str, Any]] = {}
        fingerprint_groups: dict[str, list[str]] = {}

        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT src, fields, ts
                    FROM headers
                    WHERE session_id = %s AND protocol = 'ble'
                    ORDER BY ts
                    """,
                    (str(ctx.session_id),),
                )
                for row in cur.fetchall():
                    mac, fields, ts = row
                    if not mac:
                        continue
                    if isinstance(fields, str):
                        import json
                        try:
                            fields = json.loads(fields)
                        except (ValueError, TypeError):
                            fields = {}
                    if not isinstance(fields, dict):
                        fields = {}

                    manufacturer_data = fields.get("manufacturer_data", {})
                    tx_power = fields.get("tx_power")
                    service_uuids = fields.get("services", [])

                    fp = _compute_device_fingerprint(
                        manufacturer_data, tx_power, service_uuids
                    )

                    is_random = _is_random_mac(mac)

                    # Detect known protocols
                    apple_info = _detect_apple_continuity(manufacturer_data)
                    google_info = _detect_google_nearby(manufacturer_data)
                    ms_info = _detect_microsoft_swift_pair(manufacturer_data)

                    detected_protocol = None
                    if apple_info:
                        detected_protocol = apple_info
                    elif google_info:
                        detected_protocol = google_info
                    elif ms_info:
                        detected_protocol = ms_info

                    devices[mac] = {
                        "fingerprint": fp,
                        "is_random_mac": is_random,
                        "tx_power": tx_power,
                        "manufacturer_data_keys": list(manufacturer_data.keys()),
                        "service_uuids": service_uuids,
                        "detected_protocol": detected_protocol,
                        "last_seen": ts,
                    }

                    if fp:
                        fingerprint_groups.setdefault(fp, [])
                        if mac not in fingerprint_groups[fp]:
                            fingerprint_groups[fp].append(mac)

        except Exception as exc:
            log.warning("ble.mac_randomization_tracker.db_error", error=str(exc))
            return self._result(
                Status.FAIL, started, summary=f"DB query error: {exc}"
            )

        # Filter to multi-MAC clusters (same physical device)
        multi_mac_clusters = {
            fp: macs for fp, macs in fingerprint_groups.items() if len(macs) > 1
        }

        random_count = sum(1 for d in devices.values() if d.get("is_random_mac"))
        apple_count = sum(
            1 for d in devices.values()
            if d.get("detected_protocol", {}) and
            isinstance(d.get("detected_protocol"), dict) and
            d["detected_protocol"].get("protocol") == "Apple_Continuity"
        )
        airtag_count = sum(
            1 for d in devices.values()
            if d.get("detected_protocol") and
            isinstance(d.get("detected_protocol"), dict) and
            d["detected_protocol"].get("is_airtag", False)
        )

        summary = (
            f"MAC tracking: {len(devices)} MACs ({random_count} randomized), "
            f"{len(multi_mac_clusters)} multi-MAC clusters, "
            f"{apple_count} Apple Continuity, {airtag_count} AirTags"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "device_tracking", "data": devices},
                {"type": "multi_mac_clusters", "data": multi_mac_clusters},
            ],
            metrics={
                "total_macs": len(devices),
                "random_macs": random_count,
                "multi_mac_clusters": len(multi_mac_clusters),
                "apple_continuity": apple_count,
                "airtags_detected": airtag_count,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
