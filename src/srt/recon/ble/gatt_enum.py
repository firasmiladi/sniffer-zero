"""BLE GATT enumeration: connect to a peripheral and dump services/characteristics.

Uses bleak BleakClient to enumerate the full GATT profile including services,
characteristics, descriptors, and their properties. Assesses security by
identifying characteristics that are writable without authentication.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class BleGattEnum(AttackModule):
    name = "ble.gatt_enum"
    protocol = "ble"
    risk = Risk.ACTIVE_LAB
    mitre_ttp = ["T1592"]
    requires = ["ble-adapter"]
    description = "Connect to BLE peripheral and enumerate GATT services/characteristics."

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        if "target_mac" not in ctx.params:
            return False
        allowed = ctx.whitelist.get("ble_mac", [])
        target = ctx.params["target_mac"]
        if allowed and target.upper() not in [m.upper() for m in allowed]:
            return False
        return True

    async def _enumerate_gatt(self, target: str) -> dict[str, Any]:
        """Connect to target and enumerate GATT profile."""
        from bleak import BleakClient  # type: ignore[import-untyped]

        profile: dict[str, Any] = {
            "target": target,
            "services": [],
            "security_findings": [],
        }

        async with BleakClient(target) as client:
            if not client.is_connected:
                raise RuntimeError(f"Failed to connect to {target}")

            for service in client.services:
                service_info: dict[str, Any] = {
                    "uuid": service.uuid,
                    "description": service.description or "",
                    "characteristics": [],
                }

                for char in service.characteristics:
                    char_info: dict[str, Any] = {
                        "uuid": char.uuid,
                        "description": char.description or "",
                        "handle": char.handle,
                        "properties": char.properties,
                    }
                    service_info["characteristics"].append(char_info)

                    # Security assessment: identify writable without auth
                    if "write" in char.properties or "write-without-response" in char.properties:
                        profile["security_findings"].append({
                            "type": "writable_characteristic",
                            "service_uuid": service.uuid,
                            "char_uuid": char.uuid,
                            "properties": char.properties,
                            "risk": "Characteristic writable without authentication",
                        })

                    if "read" in char.properties:
                        profile["security_findings"].append({
                            "type": "readable_characteristic",
                            "service_uuid": service.uuid,
                            "char_uuid": char.uuid,
                            "properties": char.properties,
                            "risk": "Characteristic readable without authentication",
                        })

                profile["services"].append(service_info)

        return profile

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()
        target = ctx.params["target_mac"]

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary=f"[DRY-RUN] ble.gatt_enum would connect to {target}",
                metrics={"target": target},
            )

        try:
            profile = asyncio.run(self._enumerate_gatt(target))
        except Exception as exc:
            log.error("ble.gatt_enum.error", target=target, error=str(exc))
            return self._result(
                Status.FAIL,
                started,
                summary=f"GATT enumeration failed for {target}: {exc}",
                metrics={"target": target},
            )

        service_count = len(profile["services"])
        char_count = sum(
            len(s["characteristics"]) for s in profile["services"]
        )
        finding_count = len(profile["security_findings"])

        # Insert GATT profile into database
        db.insert_header(
            ts=time.time(),
            session_id=ctx.session_id,
            protocol="ble",
            src=target,
            fields={
                "frame_type": "gatt_enum",
                "service_count": service_count,
                "characteristic_count": char_count,
                "security_findings": finding_count,
            },
        )

        summary = (
            f"ble.gatt_enum on {target}: {service_count} services, "
            f"{char_count} characteristics, {finding_count} security findings"
        )

        log.info(
            "ble.gatt_enum.complete",
            target=target,
            services=service_count,
            characteristics=char_count,
            findings=finding_count,
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[{"type": "gatt_profile", "data": profile}],
            metrics={
                "target": target,
                "service_count": service_count,
                "characteristic_count": char_count,
                "security_finding_count": finding_count,
            },
        )
