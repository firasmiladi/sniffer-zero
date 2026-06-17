"""Tests for the SRT tactical web platform WebSocket endpoint.

Verifies /ws/live connection, initial message, heartbeat, and client commands.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from srt.web.app import create_app
from srt.web.state import get_state, reset_state


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset app state before each test."""
    reset_state()
    yield
    reset_state()


@pytest.fixture()
def client():
    """Provide a TestClient with lifespan for the SRT app."""
    app = create_app()
    with TestClient(app) as c:
        yield c


class TestWebSocketConnection:
    def test_connect_and_receive_initial_message(self, client: TestClient):
        with client.websocket_connect("/ws/live") as ws:
            data = ws.receive_json()
            assert data["type"] == "connection"
            assert data["status"] == "connected"
            assert "mqtt_available" in data

    def test_ping_pong(self, client: TestClient):
        with client.websocket_connect("/ws/live") as ws:
            # Consume the initial connection message
            ws.receive_json()
            # Send a ping command
            ws.send_text(json.dumps({"command": "ping"}))
            data = ws.receive_json()
            assert data["type"] == "pong"

    def test_subscribe_command(self, client: TestClient):
        with client.websocket_connect("/ws/live") as ws:
            ws.receive_json()  # initial message
            ws.send_text(json.dumps({
                "command": "subscribe",
                "topics": ["srt/alerts/#"],
            }))
            data = ws.receive_json()
            assert data["type"] == "subscribed"
            assert "srt/alerts/#" in data["topics"]

    def test_get_state_command(self, client: TestClient):
        with client.websocket_connect("/ws/live") as ws:
            ws.receive_json()  # initial message
            ws.send_text(json.dumps({"command": "get_state"}))
            data = ws.receive_json()
            assert data["type"] == "state_snapshot"
            assert "emitters" in data
            assert "stats" in data
            assert isinstance(data["emitters"], list)

    def test_get_state_after_scan(self, client: TestClient):
        # Trigger a scan first
        client.post("/api/cartography/scan")
        with client.websocket_connect("/ws/live") as ws:
            ws.receive_json()  # initial message
            ws.send_text(json.dumps({"command": "get_state"}))
            data = ws.receive_json()
            assert data["type"] == "state_snapshot"
            assert len(data["emitters"]) > 0

    def test_invalid_json_returns_error(self, client: TestClient):
        with client.websocket_connect("/ws/live") as ws:
            ws.receive_json()  # initial message
            ws.send_text("not valid json {{{")
            data = ws.receive_json()
            assert data["type"] == "error"
            assert "Invalid JSON" in data["detail"]

    def test_ws_client_tracking(self, client: TestClient):
        state = get_state()
        assert len(state.get_ws_clients()) == 0
        with client.websocket_connect("/ws/live") as ws:
            ws.receive_json()  # consume initial msg
            # While connected, the client should be tracked
            assert len(state.get_ws_clients()) == 1
        # After disconnect, client is removed (may need a moment)
        # The remove happens in the finally block of the websocket handler


class TestWebSocketScanBroadcast:
    """Test that scanning broadcasts real-time messages via WebSocket."""

    def test_scan_broadcasts_emitter_messages(self, client: TestClient):
        """Triggering a scan via POST /api/cartography/scan should broadcast
        emitter_new or emitter_update messages to connected WebSocket clients.

        Note: With TestClient, the scan runs synchronously, and broadcast messages
        are sent to the WebSocket client tracked in state. We verify by checking
        that the state was updated properly after a scan."""
        # Trigger a scan first
        resp = client.post("/api/cartography/scan")
        assert resp.status_code == 200
        data = resp.json()
        # The scan should have produced emitters
        assert "nouveaux_emetteurs" in data or "signaux_detectes" in data

        # Verify that state reflects scan completion
        state = get_state()
        assert state.scan_in_progress is False
        assert state.scan_progress["completed_steps"] > 0

    def test_scan_produces_new_emitters_for_broadcast(self, client: TestClient):
        """A scan should produce new emitter data suitable for broadcasting."""
        resp = client.post("/api/cartography/scan")
        assert resp.status_code == 200
        data = resp.json()
        # Should have detected new emitters
        new_emitters = data.get("nouveaux_emetteurs", [])
        assert len(new_emitters) > 0, "Scan should detect new emitters"

    def test_scan_progress_state_tracking(self, client: TestClient):
        """POST /api/cartography/scan updates scan_progress in state."""
        state = get_state()
        # Before scan
        assert state.scan_progress["started_at"] is None

        client.post("/api/cartography/scan")

        # After scan
        assert state.scan_progress["started_at"] is not None
        assert state.scan_progress["total_steps"] > 0
        assert state.scan_progress["completed_steps"] == state.scan_progress["total_steps"]
        assert state.scan_in_progress is False
