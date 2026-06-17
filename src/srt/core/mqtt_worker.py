"""MQTT-to-DB worker for sniffer-rt.

Subscribes to MQTT topics published by recon/exploit modules and persists
parsed frames into TimescaleDB via ``db.insert_header()``.

Topics handled:
  - srt/headers/<protocol>  : normalized frame headers -> insert into DB
  - srt/results/<id>        : module execution results -> log
  - srt/alerts/<severity>   : anomaly alerts -> log with severity
"""

from __future__ import annotations

import json
import time
from typing import Any

import click
import paho.mqtt.client as mqtt
import structlog

from srt.core import db

log = structlog.get_logger(__name__)

# Topic prefixes
_HEADERS_PREFIX = "srt/headers/"
_RESULTS_PREFIX = "srt/results/"
_ALERTS_PREFIX = "srt/alerts/"


def _on_connect(
    client: mqtt.Client,
    userdata: Any,
    flags: dict[str, Any],
    rc: int,
) -> None:
    """Subscribe to all srt topics on (re)connect."""
    if rc == 0:
        log.info("mqtt.connected", broker=userdata.get("broker", "unknown"))
        client.subscribe("srt/headers/#", qos=1)
        client.subscribe("srt/results/#", qos=0)
        client.subscribe("srt/alerts/#", qos=1)
    else:
        log.error("mqtt.connection_failed", rc=rc)


def _on_disconnect(
    client: mqtt.Client,
    userdata: Any,
    rc: int,
) -> None:
    """Log disconnection; paho handles automatic reconnection."""
    if rc != 0:
        log.warning("mqtt.disconnected", rc=rc)


def _on_message(
    client: mqtt.Client,
    userdata: Any,
    msg: mqtt.MQTTMessage,
) -> None:
    """Route incoming messages by topic prefix."""
    topic: str = msg.topic
    try:
        payload: dict[str, Any] = json.loads(msg.payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        log.warning("mqtt.payload_invalid", topic=topic, error=str(exc))
        return

    if topic.startswith(_HEADERS_PREFIX):
        _handle_header(topic, payload)
    elif topic.startswith(_RESULTS_PREFIX):
        _handle_result(topic, payload)
    elif topic.startswith(_ALERTS_PREFIX):
        _handle_alert(topic, payload)
    else:
        log.debug("mqtt.unknown_topic", topic=topic)


def _handle_header(topic: str, payload: dict[str, Any]) -> None:
    """Persist a normalized header record."""
    protocol = topic[len(_HEADERS_PREFIX):]
    db.insert_header(
        ts=payload.get("ts", time.time()),
        session_id=payload.get("session_id"),
        protocol=protocol,
        src=payload.get("src"),
        dst=payload.get("dst"),
        channel=payload.get("channel"),
        freq_hz=payload.get("freq_hz"),
        rssi_dbm=payload.get("rssi_dbm"),
        snr_db=payload.get("snr_db"),
        fields=payload.get("fields", {}),
    )
    log.debug("mqtt.header_inserted", protocol=protocol, src=payload.get("src"))


def _handle_result(topic: str, payload: dict[str, Any]) -> None:
    """Log a module execution result."""
    result_id = topic[len(_RESULTS_PREFIX):]
    log.info(
        "mqtt.result_received",
        result_id=result_id,
        module=payload.get("module_name"),
        status=payload.get("status"),
    )


def _handle_alert(topic: str, payload: dict[str, Any]) -> None:
    """Log an alert with its severity."""
    severity = topic[len(_ALERTS_PREFIX):]
    log.warning(
        "mqtt.alert_received",
        severity=severity,
        message=payload.get("message"),
        source=payload.get("source"),
    )


def run_worker(host: str = "localhost", port: int = 1883) -> None:
    """Create MQTT client and enter the event loop."""
    client = mqtt.Client(
        client_id="srt-mqtt-worker",
        userdata={"broker": f"{host}:{port}"},
    )
    client.on_connect = _on_connect
    client.on_disconnect = _on_disconnect
    client.on_message = _on_message

    # Enable automatic reconnection
    client.reconnect_delay_set(min_delay=1, max_delay=60)

    log.info("mqtt_worker.starting", host=host, port=port)
    client.connect(host, port, keepalive=60)
    client.loop_forever()


@click.command("mqtt-worker")
@click.option("--host", default="localhost", help="MQTT broker hostname")
@click.option("--port", default=1883, type=int, help="MQTT broker port")
def cli(host: str, port: int) -> None:
    """Start the MQTT-to-DB worker daemon."""
    run_worker(host=host, port=port)


if __name__ == "__main__":
    cli()
