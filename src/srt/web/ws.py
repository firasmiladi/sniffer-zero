"""WebSocket endpoint bridging MQTT topics to connected browsers.

Provides /ws/live which:
- Forwards MQTT messages from srt/headers/#, srt/alerts/#, srt/results/#
- Forwards cartography updates when scan cycles complete
- Works gracefully when MQTT broker is not available
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from srt.web.state import get_state

log = structlog.get_logger(__name__)

router = APIRouter()

# MQTT topics to bridge
_MQTT_TOPICS = [
    "srt/headers/#",
    "srt/alerts/#",
    "srt/results/#",
]


@router.websocket("/ws/live")
async def websocket_live(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time data streaming.

    Sends JSON messages with format:
        {"type": "mqtt", "topic": "...", "payload": {...}}
        {"type": "cartography_update", "data": {...}}
    """
    await websocket.accept()
    state = get_state()
    state.add_ws_client(websocket)

    try:
        # Send initial state on connect
        await websocket.send_json({
            "type": "connection",
            "status": "connected",
            "mqtt_available": state.mqtt_connected,
        })

        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for messages from client (ping/pong or commands)
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0,
                )
                # Handle client commands
                await _handle_client_message(websocket, data, state)
            except asyncio.TimeoutError:
                # Send a heartbeat
                await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        log.debug("ws.client_disconnected")
    except Exception as exc:
        log.warning("ws.error", error=str(exc))
    finally:
        state.remove_ws_client(websocket)


async def _handle_client_message(
    websocket: WebSocket, data: str, state: Any
) -> None:
    """Handle incoming messages from WebSocket clients."""
    try:
        message = json.loads(data)
    except json.JSONDecodeError:
        await websocket.send_json({"type": "error", "detail": "Invalid JSON"})
        return

    cmd = message.get("command")
    if cmd == "subscribe":
        # Acknowledge subscription request
        await websocket.send_json({
            "type": "subscribed",
            "topics": message.get("topics", []),
        })
    elif cmd == "subscribe_scenario":
        # Acknowledge scenario subscription
        await websocket.send_json({
            "type": "subscribed_scenario",
            "scenario_name": message.get("scenario_name", ""),
        })
    elif cmd == "get_state":
        # Return current cartography state
        emitters = [
            em.to_dict()
            for em in state.cartographie.emetteurs.values()
        ]
        await websocket.send_json({
            "type": "state_snapshot",
            "emitters": emitters,
            "stats": dict(state.cartographie.stats),
        })
    elif cmd == "ping":
        await websocket.send_json({"type": "pong"})


async def broadcast_to_clients(message: dict[str, Any]) -> None:
    """Broadcast a message to all connected WebSocket clients."""
    state = get_state()
    clients = state.get_ws_clients()
    disconnected = []

    for ws in clients:
        try:
            await ws.send_json(message)
        except Exception:
            disconnected.append(ws)

    # Clean up disconnected clients
    for ws in disconnected:
        state.remove_ws_client(ws)


def broadcast_sync(message: dict[str, Any], loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Broadcast a WebSocket message from a synchronous/background-thread context.

    Parameters
    ----------
    message:
        JSON-serializable dict to send to all connected WS clients.
    loop:
        The asyncio event loop running in the main thread. When provided,
        ``run_coroutine_threadsafe`` targets this loop directly, avoiding the
        unreliable ``asyncio.get_event_loop()`` call from a background thread.
        If *None*, falls back to attempting ``asyncio.get_event_loop()``.
    """
    try:
        target_loop = loop or asyncio.get_event_loop()
        if target_loop.is_running():
            asyncio.run_coroutine_threadsafe(broadcast_to_clients(message), target_loop)
        elif not target_loop.is_closed():
            target_loop.run_until_complete(broadcast_to_clients(message))
    except RuntimeError:
        # No event loop available (e.g., in tests) - skip broadcast
        pass


def start_mqtt_bridge(host: str = "localhost", port: int = 1883) -> None:
    """Start MQTT client in a background thread to bridge messages to WebSocket.

    If the MQTT broker is not available, this function fails gracefully
    and logs a warning.
    """
    state = get_state()

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        log.warning("ws.mqtt_bridge.paho_not_available")
        return

    def on_connect(
        client: Any, userdata: Any, flags: Any, reason_code: Any, properties: Any = None
    ) -> None:
        if reason_code == 0 or (hasattr(reason_code, 'value') and reason_code.value == 0):
            state.mqtt_connected = True
            log.info("ws.mqtt_bridge.connected")
            client.subscribe("srt/headers/#", qos=0)
            client.subscribe("srt/alerts/#", qos=1)
            client.subscribe("srt/results/#", qos=0)
        else:
            log.warning("ws.mqtt_bridge.connect_failed", reason_code=str(reason_code))

    def on_disconnect(
        client: Any, userdata: Any, flags: Any, reason_code: Any, properties: Any = None
    ) -> None:
        state.mqtt_connected = False
        if reason_code != 0 and not (hasattr(reason_code, 'value') and reason_code.value == 0):
            log.warning("ws.mqtt_bridge.disconnected", reason_code=str(reason_code))

    def on_message(client: Any, userdata: Any, msg: Any) -> None:
        try:
            payload = json.loads(msg.payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        message = {
            "type": "mqtt",
            "topic": msg.topic,
            "payload": payload,
        }

        # Schedule broadcast in the event loop
        loop = userdata.get("loop") if isinstance(userdata, dict) else None
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(
                broadcast_to_clients(message), loop
            )

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id="srt-web-bridge",
    )
    client.user_data_set({"loop": None})
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    client.reconnect_delay_set(min_delay=1, max_delay=30)

    state.mqtt_client = client

    def _run() -> None:
        try:
            client.connect(host, port, keepalive=60)
            client.loop_forever()
        except (OSError, ConnectionRefusedError) as exc:
            log.warning("ws.mqtt_bridge.connection_error", error=str(exc))
            state.mqtt_connected = False

    thread = threading.Thread(target=_run, daemon=True, name="mqtt-ws-bridge")
    thread.start()
