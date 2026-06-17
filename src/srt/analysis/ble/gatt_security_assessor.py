"""BLE GATT security assessment engine.

Analyzes GATT profiles from previous ble.gatt_enum results, checks
read/write permissions vs encryption requirements, identifies unprotected
sensitive characteristics, and generates security grades per device.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)

# Sensitive BLE service/characteristic UUIDs
SENSITIVE_SERVICES: dict[int, str] = {
    0x1800: "Generic Access",
    0x1801: "Generic Attribute",
    0x180A: "Device Information",
    0x180D: "Heart Rate",
    0x180F: "Battery Service",
    0x1810: "Blood Pressure",
    0x1812: "Human Interface Device",
    0x1813: "Scan Parameters",
    0x1814: "Running Speed and Cadence",
    0x1816: "Cycling Speed and Cadence",
    0x181C: "User Data",
    0x181E: "Bond Management",
}

SENSITIVE_CHARACTERISTICS: dict[int, str] = {
    0x2A00: "Device Name",
    0x2A01: "Appearance",
    0x2A19: "Battery Level",
    0x2A23: "System ID",
    0x2A24: "Model Number",
    0x2A25: "Serial Number",
    0x2A26: "Firmware Revision",
    0x2A27: "Hardware Revision",
    0x2A28: "Software Revision",
    0x2A29: "Manufacturer Name",
    0x2A37: "Heart Rate Measurement",
    0x2A38: "Body Sensor Location",
    0x2A4D: "Report (HID)",
}

# Permissions that indicate unprotected access
UNPROTECTED_READ_PROPS = {"read", "notify", "indicate"}
UNPROTECTED_WRITE_PROPS = {"write", "write-without-response"}


def _uuid_to_int(uuid_str: str) -> int | None:
    """Convert a UUID string to 16-bit integer if it's a standard BLE UUID."""
    uuid_str = uuid_str.lower().replace("-", "")
    # Standard 16-bit UUIDs: 0000XXXX-0000-1000-8000-00805f9b34fb
    if len(uuid_str) == 4:
        try:
            return int(uuid_str, 16)
        except ValueError:
            return None
    if len(uuid_str) == 32 and uuid_str.endswith("00001000800000805f9b34fb"):
        try:
            return int(uuid_str[4:8], 16)
        except ValueError:
            return None
    return None


def _assess_device(device_mac: str, services: list[dict[str, Any]]) -> dict[str, Any]:
    """Assess a single device's GATT security posture."""
    issues: list[dict[str, Any]] = []
    total_chars = 0
    unprotected_count = 0
    sensitive_exposed = 0

    for service in services:
        service_uuid = service.get("uuid", "")
        svc_int = _uuid_to_int(service_uuid)
        is_sensitive_svc = svc_int in SENSITIVE_SERVICES if svc_int else False

        characteristics = service.get("characteristics", [])
        for char in characteristics:
            total_chars += 1
            char_uuid = char.get("uuid", "")
            char_int = _uuid_to_int(char_uuid)
            properties = set(char.get("properties", []))

            # Check if characteristic is readable/writable without encryption
            requires_encryption = char.get("requires_encryption", False)

            readable_unprotected = bool(
                properties & UNPROTECTED_READ_PROPS and not requires_encryption
            )
            writable_unprotected = bool(
                properties & UNPROTECTED_WRITE_PROPS and not requires_encryption
            )

            if readable_unprotected or writable_unprotected:
                unprotected_count += 1

            is_sensitive_char = char_int in SENSITIVE_CHARACTERISTICS if char_int else False

            if (
                (is_sensitive_svc or is_sensitive_char)
                and (readable_unprotected or writable_unprotected)
            ):
                sensitive_exposed += 1
                char_name = ""
                if char_int and char_int in SENSITIVE_CHARACTERISTICS:
                    char_name = SENSITIVE_CHARACTERISTICS[char_int]
                elif svc_int and svc_int in SENSITIVE_SERVICES:
                    char_name = f"{SENSITIVE_SERVICES[svc_int]} char"

                issues.append({
                    "service_uuid": service_uuid,
                    "char_uuid": char_uuid,
                    "char_name": char_name,
                    "properties": list(properties),
                    "encrypted": requires_encryption,
                    "issue": "sensitive_characteristic_exposed",
                })

    # Grading: A (0 issues), B (1-2), C (3-5), D (6-10), F (>10)
    if sensitive_exposed == 0 and unprotected_count <= 2:
        grade = "A"
    elif sensitive_exposed <= 1 and unprotected_count <= 5:
        grade = "B"
    elif sensitive_exposed <= 3:
        grade = "C"
    elif sensitive_exposed <= 6:
        grade = "D"
    else:
        grade = "F"

    return {
        "device_mac": device_mac,
        "grade": grade,
        "total_characteristics": total_chars,
        "unprotected_characteristics": unprotected_count,
        "sensitive_exposed": sensitive_exposed,
        "issues": issues,
    }


@register
class BleGattSecurityAssessor(AttackModule):
    """BLE GATT profile security assessment.

    Analyzes GATT profiles from previous ble.gatt_enum results in the
    module_results table, checks sensitive UUID exposure, read/write
    permissions vs encryption requirements, and generates a security
    grade per device.
    """

    name = "ble.gatt_security_assessor"
    protocol = "ble"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1592.002", "T1602"]
    requires = []
    description = (
        "GATT security assessment: check characteristic permissions, "
        "identify unprotected sensitive UUIDs, generate per-device grades."
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
                summary="[DRY-RUN] ble.gatt_security_assessor would assess GATT profiles",
            )

        device_assessments: list[dict[str, Any]] = []

        try:
            with db.connect() as conn, conn.cursor() as cur:
                # Query previous ble.gatt_enum results for this session
                cur.execute(
                    """
                    SELECT artifacts
                    FROM module_results
                    WHERE session_id = %s AND module_name = 'ble.gatt_enum'
                    ORDER BY started_at DESC
                    LIMIT 10
                    """,
                    (str(ctx.session_id),),
                )
                for row in cur.fetchall():
                    artifacts = row[0]
                    if isinstance(artifacts, str):
                        import json
                        try:
                            artifacts = json.loads(artifacts)
                        except (ValueError, TypeError):
                            artifacts = []
                    if not isinstance(artifacts, list):
                        continue

                    for artifact in artifacts:
                        if artifact.get("type") == "gatt_profile":
                            device_mac = artifact.get("device_mac", "unknown")
                            services = artifact.get("data", {}).get("services", [])
                            assessment = _assess_device(device_mac, services)
                            device_assessments.append(assessment)

        except Exception as exc:
            log.warning("ble.gatt_security_assessor.db_error", error=str(exc))
            return self._result(
                Status.FAIL, started, summary=f"DB query error: {exc}"
            )

        # Summary statistics
        grade_dist: dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        for a in device_assessments:
            g = a.get("grade", "F")
            grade_dist[g] = grade_dist.get(g, 0) + 1

        total_issues = sum(len(a.get("issues", [])) for a in device_assessments)

        summary = (
            f"GATT security: {len(device_assessments)} devices assessed, "
            f"grades: A={grade_dist['A']} B={grade_dist['B']} C={grade_dist['C']} "
            f"D={grade_dist['D']} F={grade_dist['F']}, "
            f"{total_issues} issues found"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "gatt_security_assessments", "data": device_assessments},
                {"type": "grade_distribution", "data": grade_dist},
            ],
            metrics={
                "devices_assessed": len(device_assessments),
                "grade_distribution": grade_dist,
                "total_issues": total_issues,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
