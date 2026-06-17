"""Tests for the SRT tactical web platform REST API endpoints.

Verifies all REST API routes return expected structures and status codes.
"""

from __future__ import annotations

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


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health_returns_ok(self, client: TestClient):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "mqtt_connected" in data
        assert "emitters_tracked" in data
        assert "modules_registered" in data

    def test_health_modules_registered(self, client: TestClient):
        resp = client.get("/api/health")
        data = resp.json()
        # Autodiscover should have found modules
        assert data["modules_registered"] > 0


# ---------------------------------------------------------------------------
# Modules endpoints
# ---------------------------------------------------------------------------


class TestModules:
    def test_list_all_modules(self, client: TestClient):
        resp = client.get("/api/modules")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0
        # Each module has required fields
        mod = data[0]
        assert "name" in mod
        assert "protocol" in mod
        assert "risk" in mod
        assert "description" in mod
        assert "mitre_ttp" in mod
        assert "requires" in mod

    def test_filter_modules_by_protocol_wifi(self, client: TestClient):
        resp = client.get("/api/modules/wifi")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        for mod in data:
            assert mod["protocol"] == "wifi"

    def test_filter_modules_by_protocol_ble(self, client: TestClient):
        resp = client.get("/api/modules/ble")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        for mod in data:
            assert mod["protocol"] == "ble"

    def test_filter_modules_by_protocol_lora(self, client: TestClient):
        resp = client.get("/api/modules/lora")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        for mod in data:
            assert mod["protocol"] == "lora"

    def test_filter_unknown_protocol_returns_empty(self, client: TestClient):
        resp = client.get("/api/modules/unknown_proto")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_launch_module_dry_run(self, client: TestClient):
        # Get list of modules first
        resp = client.get("/api/modules")
        modules = resp.json()
        assert len(modules) > 0

        name = modules[0]["name"]
        resp = client.post(
            f"/api/modules/{name}/launch",
            json={"params": {}, "dry_run": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["module_name"] == name
        assert "status" in data
        assert "summary" in data
        assert "duration_s" in data
        assert "artifacts" in data
        assert "metrics" in data

    def test_launch_nonexistent_module(self, client: TestClient):
        resp = client.post(
            "/api/modules/nonexistent_module_xyz/launch",
            json={"params": {}, "dry_run": True},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Cartography endpoints
# ---------------------------------------------------------------------------


class TestCartography:
    def test_emitters_empty_initially(self, client: TestClient):
        resp = client.get("/api/cartography/emitters")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_scan_returns_result_structure(self, client: TestClient):
        resp = client.post("/api/cartography/scan")
        assert resp.status_code == 200
        data = resp.json()
        assert "timestamp" in data
        assert "signaux_detectes" in data
        assert "nouveaux_emetteurs" in data
        assert "emetteurs_mis_a_jour" in data
        assert "alertes" in data

    def test_scan_populates_emitters(self, client: TestClient):
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/emitters")
        assert resp.status_code == 200
        emitters = resp.json()
        assert len(emitters) > 0

    def test_emitters_by_protocol_wifi(self, client: TestClient):
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/emitters/wifi")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        # All returned emitters should be wifi type
        for em in data:
            assert em["classification"]["type"] in ["wifi_access_point", "wifi_client"]

    def test_emitters_by_protocol_ble(self, client: TestClient):
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/emitters/ble")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        for em in data:
            assert em["classification"]["type"] in ["ble_peripheral", "ble_central"]

    def test_emitters_by_protocol_lora(self, client: TestClient):
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/emitters/lora")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        for em in data:
            assert em["classification"]["type"] in ["lora_device", "lora_gateway"]

    def test_stats_endpoint(self, client: TestClient):
        resp = client.get("/api/cartography/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "nb_balayages" in data
        assert "nb_signaux_detectes" in data
        assert "nb_emetteurs_uniques" in data
        assert "nb_alertes" in data

    def test_stats_updated_after_scan(self, client: TestClient):
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/stats")
        data = resp.json()
        assert data["nb_balayages"] >= 1
        assert data["nb_signaux_detectes"] > 0

    def test_alerts_endpoint(self, client: TestClient):
        resp = client.get("/api/cartography/alerts")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_bands_endpoint(self, client: TestClient):
        resp = client.get("/api/cartography/bands")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        # Should have known band categories
        assert "WiFi_2.4" in data or "ISM_868" in data or len(data) > 0

    def test_threats_endpoint(self, client: TestClient):
        resp = client.get("/api/cartography/threats")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert "critique" in data
        assert "haute" in data
        assert "moyenne" in data
        assert "basse" in data


# ---------------------------------------------------------------------------
# Protocol-specific endpoints
# ---------------------------------------------------------------------------


class TestWiFiEndpoints:
    def test_wifi_networks_empty(self, client: TestClient):
        resp = client.get("/api/wifi/networks")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_wifi_networks_after_scan(self, client: TestClient):
        client.post("/api/cartography/scan")
        resp = client.get("/api/wifi/networks")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        # The simulation generates WiFi signals in 2.4 GHz range
        if data:
            net = data[0]
            assert "id" in net
            assert "signal" in net
            assert "threat_level" in net

    def test_wifi_clients(self, client: TestClient):
        resp = client.get("/api/wifi/clients")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestBLEEndpoints:
    def test_ble_devices_empty(self, client: TestClient):
        resp = client.get("/api/ble/devices")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_ble_devices_after_scan(self, client: TestClient):
        client.post("/api/cartography/scan")
        resp = client.get("/api/ble/devices")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        if data:
            dev = data[0]
            assert "id" in dev
            assert "type" in dev
            assert "signal" in dev

    def test_ble_services(self, client: TestClient):
        resp = client.get("/api/ble/services")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestLoRaEndpoints:
    def test_lora_devices_empty(self, client: TestClient):
        resp = client.get("/api/lora/devices")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_lora_devices_after_scan(self, client: TestClient):
        client.post("/api/cartography/scan")
        resp = client.get("/api/lora/devices")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_lora_gateways(self, client: TestClient):
        resp = client.get("/api/lora/gateways")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_lora_traffic(self, client: TestClient):
        resp = client.get("/api/lora/traffic")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_devices" in data
        assert "total_gateways" in data
        assert "total_signals_captured" in data
        assert "devices" in data


# ---------------------------------------------------------------------------
# Scenarios endpoints
# ---------------------------------------------------------------------------


class TestScenarios:
    def test_list_scenarios(self, client: TestClient):
        """GET /api/scenarios returns a non-empty list of scenario objects."""
        resp = client.get("/api/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0
        # Each scenario has the required fields
        sc = data[0]
        assert "name" in sc
        assert "description" in sc
        assert "steps_count" in sc
        assert "category" in sc

    def test_list_scenarios_contains_new_recon(self, client: TestClient):
        """New recon scenarios appear in the listing."""
        resp = client.get("/api/scenarios")
        data = resp.json()
        names = [s["name"] for s in data]
        assert "recon_wifi_complete" in names
        assert "recon_ble_complete" in names
        assert "recon_multi_protocol" in names
        assert "survey_spectral" in names

    def test_list_scenarios_categories(self, client: TestClient):
        """Scenarios have correct category inferred from filename."""
        resp = client.get("/api/scenarios")
        data = resp.json()
        by_name = {s["name"]: s for s in data}
        assert by_name["recon_wifi_complete"]["category"] == "recon"
        assert by_name["recon_ble_complete"]["category"] == "recon"
        assert by_name["survey_spectral"]["category"] == "survey"
        assert by_name["continuous_monitor"]["category"] == "continuous"

    def test_scenario_status_idle(self, client: TestClient):
        """GET /api/scenarios/{name}/status returns idle for non-running scenario."""
        resp = client.get("/api/scenarios/recon_wifi_complete/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_name"] == "recon_wifi_complete"
        assert data["status"] == "idle"

    def test_launch_scenario(self, client: TestClient):
        """POST /api/scenarios/{name}/launch returns 200 with execution info."""
        resp = client.post("/api/scenarios/recon_wifi_complete/launch")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_name"] == "recon_wifi_complete"
        assert data["status"] == "running"
        assert "started_at" in data
        assert data["steps_total"] == 5

    def test_launch_nonexistent_scenario(self, client: TestClient):
        """POST /api/scenarios/{name}/launch returns 404 for unknown scenario."""
        resp = client.post("/api/scenarios/nonexistent_scenario_xyz/launch")
        assert resp.status_code == 404

    def test_scenario_status_after_launch(self, client: TestClient):
        """GET /api/scenarios/{name}/status returns running/completed after launch."""
        import time

        client.post("/api/scenarios/recon_wifi_complete/launch")
        # Give background thread a moment to start
        time.sleep(0.5)
        resp = client.get("/api/scenarios/recon_wifi_complete/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_name"] == "recon_wifi_complete"
        assert data["status"] in ("running", "completed")
        assert data["steps_total"] == 5


# ---------------------------------------------------------------------------
# Cartography timeline and heatmap endpoints
# ---------------------------------------------------------------------------


class TestCartographyTimeline:
    def test_timeline_returns_list(self, client: TestClient):
        """GET /api/cartography/timeline returns a list structure."""
        resp = client.get("/api/cartography/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_timeline_after_scan_has_entries(self, client: TestClient):
        """After a scan, timeline returns emitters with first_seen/last_seen."""
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0
        # Each entry has first_seen and last_seen
        entry = data[0]
        assert "first_seen" in entry
        assert "last_seen" in entry

    def test_timeline_sorted_by_first_seen(self, client: TestClient):
        """Timeline entries are sorted by first_seen (most recent first)."""
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/timeline")
        data = resp.json()
        if len(data) >= 2:
            # Verify descending order
            for i in range(len(data) - 1):
                if data[i]["first_seen"] and data[i + 1]["first_seen"]:
                    assert data[i]["first_seen"] >= data[i + 1]["first_seen"]


class TestCartographyHeatmap:
    def test_heatmap_returns_list(self, client: TestClient):
        """GET /api/cartography/heatmap returns a list structure."""
        resp = client.get("/api/cartography/heatmap")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_heatmap_after_scan_has_points(self, client: TestClient):
        """After a scan, heatmap returns points with lat/lon/intensity."""
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/heatmap")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0
        point = data[0]
        assert "lat" in point
        assert "lon" in point
        assert "intensity" in point
        assert "puissance_dbm" in point
        assert "emitter_id" in point
        # Intensity should be normalized between 0 and 1
        assert 0.0 <= point["intensity"] <= 1.0

    def test_heatmap_point_structure(self, client: TestClient):
        """Heatmap points contain expected fields."""
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/heatmap")
        data = resp.json()
        if len(data) > 0:
            point = data[0]
            assert "type" in point
            assert isinstance(point["lat"], (int, float))
            assert isinstance(point["lon"], (int, float))


class TestScanProgress:
    def test_scan_progress_tracked_in_state(self, client: TestClient):
        """After a scan, scan_progress is tracked in state."""
        client.post("/api/cartography/scan")
        state = get_state()
        assert state.scan_in_progress is False  # Scan has completed
        assert state.scan_progress["total_steps"] > 0
        assert state.scan_progress["completed_steps"] == state.scan_progress["total_steps"]

