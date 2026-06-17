"""BLE advertising and protocol analysis engine.

Full advertising PDU decode for all AD types, connection parameter analysis,
device information extraction, and protocol-level assessment.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)

# BLE Advertising Data Types (AD Types) per Bluetooth SIG
AD_TYPES: dict[int, str] = {
    0x01: "Flags",
    0x02: "Incomplete_16bit_Service_UUIDs",
    0x03: "Complete_16bit_Service_UUIDs",
    0x04: "Incomplete_32bit_Service_UUIDs",
    0x05: "Complete_32bit_Service_UUIDs",
    0x06: "Incomplete_128bit_Service_UUIDs",
    0x07: "Complete_128bit_Service_UUIDs",
    0x08: "Shortened_Local_Name",
    0x09: "Complete_Local_Name",
    0x0A: "TX_Power_Level",
    0x0D: "Class_of_Device",
    0x0E: "Simple_Pairing_Hash_C192",
    0x0F: "Simple_Pairing_Randomizer_R192",
    0x10: "Device_ID",
    0x11: "Security_Manager_OOB_Flags",
    0x12: "Slave_Connection_Interval_Range",
    0x14: "16bit_Service_Solicitation_UUIDs",
    0x15: "128bit_Service_Solicitation_UUIDs",
    0x16: "Service_Data_16bit",
    0x17: "Public_Target_Address",
    0x18: "Random_Target_Address",
    0x19: "Appearance",
    0x1A: "Advertising_Interval",
    0x1B: "LE_Bluetooth_Device_Address",
    0x1C: "LE_Role",
    0x20: "Service_Data_32bit",
    0x21: "Service_Data_128bit",
    0x24: "URI",
    0x25: "Indoor_Positioning",
    0x26: "Transport_Discovery_Data",
    0xFF: "Manufacturer_Specific_Data",
}

# BLE Flags bits
FLAG_BITS: dict[int, str] = {
    0x01: "LE_Limited_Discoverable",
    0x02: "LE_General_Discoverable",
    0x04: "BR_EDR_Not_Supported",
    0x08: "LE_BR_EDR_Controller",
    0x10: "LE_BR_EDR_Host",
}

# BLE Appearance values (subset)
APPEARANCE_MAP: dict[int, str] = {
    0x0000: "Unknown",
    0x0040: "Generic_Phone",
    0x0080: "Generic_Computer",
    0x00C0: "Generic_Watch",
    0x0100: "Generic_Clock",
    0x0140: "Generic_Display",
    0x0180: "Generic_Remote_Control",
    0x01C0: "Generic_Eye_Glasses",
    0x0200: "Generic_Tag",
    0x0240: "Generic_Keyring",
    0x0300: "Generic_Cycling",
    0x0340: "Generic_Running",
    0x0380: "Generic_Fitness",
    0x03C0: "Generic_Sensor",
    0x0440: "Generic_Heart_Rate",
    0x0480: "Generic_Blood_Pressure",
    0x04C0: "Generic_HID",
    0x0540: "Keyboard",
    0x0580: "Mouse",
    0x05C0: "Joystick",
    0x0600: "Gamepad",
    0x0680: "Generic_Outdoor_Sports",
    0x0C40: "Generic_Pulse_Oximeter",
    0x0C80: "Generic_Weight_Scale",
}


def _decode_flags(flags_byte: int) -> list[str]:
    """Decode BLE advertising flags byte."""
    active_flags: list[str] = []
    for bit, name in FLAG_BITS.items():
        if flags_byte & bit:
            active_flags.append(name)
    return active_flags


def _decode_appearance(value: int) -> str:
    """Decode BLE appearance value to human-readable string."""
    return APPEARANCE_MAP.get(value, f"Unknown_0x{value:04X}")


def _parse_advertising_data(raw_hex: str) -> list[dict[str, Any]]:
    """Parse raw advertising data bytes into AD structures."""
    ad_structures: list[dict[str, Any]] = []
    try:
        data = bytes.fromhex(raw_hex)
    except (ValueError, TypeError):
        return ad_structures

    offset = 0
    while offset < len(data):
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            break
        offset += 1
        if offset + length > len(data):
            break

        ad_type = data[offset]
        ad_data = data[offset + 1:offset + length]

        entry: dict[str, Any] = {
            "type": ad_type,
            "type_name": AD_TYPES.get(ad_type, f"Unknown_0x{ad_type:02X}"),
            "length": length - 1,
            "raw_hex": ad_data.hex(),
        }

        # Decode specific types
        if ad_type == 0x01 and ad_data:  # Flags
            entry["flags"] = _decode_flags(ad_data[0])
        elif ad_type in (0x08, 0x09) and ad_data:  # Local Name
            try:
                entry["name"] = ad_data.decode("utf-8", errors="replace")
            except Exception:
                entry["name"] = ad_data.hex()
        elif ad_type == 0x0A and ad_data:  # TX Power Level
            entry["tx_power_dbm"] = int.from_bytes(ad_data[:1], "little", signed=True)
        elif ad_type == 0x19 and len(ad_data) >= 2:  # Appearance
            value = int.from_bytes(ad_data[:2], "little")
            entry["appearance"] = _decode_appearance(value)
            entry["appearance_value"] = value
        elif ad_type == 0x1A and len(ad_data) >= 2:  # Advertising Interval
            interval = int.from_bytes(ad_data[:2], "little")
            entry["adv_interval_ms"] = interval * 0.625

        ad_structures.append(entry)
        offset += length

    return ad_structures


@register
class BleProtocolAnalyzer(AttackModule):
    """BLE advertising and protocol-level analysis.

    Full advertising PDU decode for all AD types (flags, service UUIDs,
    local name, TX power, appearance, manufacturer data), connection
    parameter analysis, and device information extraction.
    """

    name = "ble.protocol_analyzer"
    protocol = "ble"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1040", "T1592.002"]
    requires = []
    description = (
        "BLE protocol analysis: full advertising PDU decode, AD type parsing, "
        "connection parameters, device information extraction."
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
                summary="[DRY-RUN] ble.protocol_analyzer would decode BLE PDUs",
            )

        device_profiles: dict[str, dict[str, Any]] = {}

        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT src, fields, rssi_dbm
                    FROM headers
                    WHERE session_id = %s AND protocol = 'ble'
                    ORDER BY ts
                    """,
                    (str(ctx.session_id),),
                )
                for row in cur.fetchall():
                    mac, fields, rssi = row
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

                    # Parse raw advertising data if available
                    raw_adv = fields.get("raw_advertising_data", "")
                    ad_structures = _parse_advertising_data(raw_adv) if raw_adv else []

                    name = fields.get("name", "")
                    services = fields.get("services", [])
                    manufacturer_data = fields.get("manufacturer_data", {})
                    tx_power = fields.get("tx_power")

                    # Build device profile
                    profile: dict[str, Any] = {
                        "name": name,
                        "rssi": rssi,
                        "service_uuids": services,
                        "manufacturer_data_keys": list(manufacturer_data.keys()),
                        "tx_power": tx_power,
                        "ad_structures": ad_structures,
                        "ad_type_count": len(ad_structures),
                    }

                    # Extract decoded info from AD structures
                    for ad in ad_structures:
                        if ad.get("type") == 0x01:
                            profile["flags"] = ad.get("flags", [])
                        elif ad.get("type") == 0x19:
                            profile["appearance"] = ad.get("appearance", "Unknown")
                        elif ad.get("type") == 0x1A:
                            profile["adv_interval_ms"] = ad.get("adv_interval_ms")

                    # Connection parameter analysis
                    conn_interval_min = fields.get("conn_interval_min")
                    conn_interval_max = fields.get("conn_interval_max")
                    if conn_interval_min is not None:
                        profile["connection_params"] = {
                            "interval_min_ms": conn_interval_min * 1.25,
                            "interval_max_ms": (conn_interval_max or conn_interval_min) * 1.25,
                            "latency": fields.get("slave_latency", 0),
                            "supervision_timeout_ms": fields.get("supervision_timeout", 0) * 10,
                        }

                    device_profiles[mac] = profile

        except Exception as exc:
            log.warning("ble.protocol_analyzer.db_error", error=str(exc))
            return self._result(
                Status.FAIL, started, summary=f"DB query error: {exc}"
            )

        # Statistics
        named_count = sum(1 for p in device_profiles.values() if p.get("name"))
        with_services = sum(1 for p in device_profiles.values() if p.get("service_uuids"))

        summary = (
            f"BLE protocol analysis: {len(device_profiles)} devices decoded, "
            f"{named_count} named, {with_services} with service UUIDs"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "ble_device_profiles", "data": device_profiles},
            ],
            metrics={
                "total_devices": len(device_profiles),
                "named_devices": named_count,
                "devices_with_services": with_services,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
