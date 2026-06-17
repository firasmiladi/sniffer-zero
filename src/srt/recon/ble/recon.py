"""BLE passive recon: advertising scan, service-UUID enum, vendor lookup.

Uses bleak (cross-platform BLE scanner) for passive advertisement capture.
Emits headers to MQTT + TimescaleDB.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import paho.mqtt.client as mqtt
import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class BleRecon(AttackModule):
    name = "ble.recon"
    protocol = "ble"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1592"]
    requires = ["ble-adapter"]
    description = "BLE advertising scan: MAC, name, service UUIDs, RSSI, vendor."

    def __init__(self) -> None:
        self._devices: dict[str, dict[str, Any]] = {}
        self._mqtt_client: mqtt.Client | None = None

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def _init_mqtt(self) -> None:
        """Initialize MQTT client for publishing."""
        try:
            client = mqtt.Client(client_id="srt-ble-recon", protocol=mqtt.MQTTv5)
            client.connect("127.0.0.1", 1883, keepalive=60)
            client.loop_start()
            self._mqtt_client = client
        except Exception as exc:
            log.warning("ble.recon.mqtt_connect_failed", error=str(exc))
            self._mqtt_client = None

    def _publish_mqtt(self, payload: dict[str, Any]) -> None:
        """Publish device info to MQTT topic."""
        if self._mqtt_client is None:
            return
        try:
            self._mqtt_client.publish("srt/headers/ble", json.dumps(payload))
        except Exception as exc:
            log.debug("ble.recon.mqtt_publish_error", error=str(exc))

    async def _scan(self, duration: int, ctx: ModuleContext) -> None:
        """Async BLE scan using bleak BleakScanner with detection callback."""
        from bleak import BleakScanner  # type: ignore[import-untyped]

        def detection_callback(device: Any, advertisement_data: Any) -> None:
            mac = device.address
            name = advertisement_data.local_name or ""
            rssi = advertisement_data.rssi
            service_uuids = list(advertisement_data.service_uuids or [])
            manufacturer_data = {
                str(k): v.hex() for k, v in (advertisement_data.manufacturer_data or {}).items()
            }
            tx_power = advertisement_data.tx_power

            ts = time.time()

            self._devices[mac] = {
                "name": name,
                "rssi": rssi,
                "service_uuids": service_uuids,
                "manufacturer_data": manufacturer_data,
                "tx_power": tx_power,
                "last_seen": ts,
            }

            # Insert into database
            db.insert_header(
                ts=ts,
                session_id=ctx.session_id,
                protocol="ble",
                src=mac,
                rssi_dbm=rssi,
                fields={
                    "name": name,
                    "services": service_uuids,
                    "manufacturer_data": manufacturer_data,
                    "tx_power": tx_power,
                },
            )

            # Publish to MQTT
            self._publish_mqtt({
                "ts": ts,
                "mac": mac,
                "name": name,
                "rssi": rssi,
                "services": service_uuids,
                "manufacturer_data": manufacturer_data,
                "tx_power": tx_power,
            })

            log.info(
                "ble.recon.device_discovered",
                mac=mac,
                name=name,
                rssi=rssi,
                services=service_uuids,
            )

        scanner = BleakScanner(detection_callback=detection_callback)
        await scanner.start()
        await asyncio.sleep(duration)
        await scanner.stop()

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()
        duration = int(ctx.params.get("duration_s", 20))

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary=f"[DRY-RUN] ble.recon would scan for {duration}s",
                metrics={"duration_s": duration},
            )

        self._init_mqtt()

        try:
            asyncio.run(self._scan(duration, ctx))
        except Exception as exc:
            log.error("ble.recon.scan_error", error=str(exc))
            return self._result(
                Status.FAIL,
                started,
                summary=f"BLE scan error: {exc}",
            )

        device_count = len(self._devices)
        summary = (
            f"ble.recon completed: {device_count} devices discovered "
            f"over {duration}s scan"
        )

        device_list = [
            {
                "mac": mac,
                "name": info["name"],
                "rssi": info["rssi"],
                "services": info["service_uuids"],
                "manufacturer_data": info["manufacturer_data"],
                "tx_power": info["tx_power"],
            }
            for mac, info in list(self._devices.items())[:50]
        ]

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[{"type": "device_list", "data": device_list}],
            metrics={
                "device_count": device_count,
                "duration_s": duration,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        """Disconnect MQTT."""
        if self._mqtt_client:
            try:
                self._mqtt_client.loop_stop()
                self._mqtt_client.disconnect()
            except Exception:
                pass
            self._mqtt_client = None
