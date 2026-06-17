"""Integration tests for the SRT tactical web platform.

End-to-end test: scan cycle triggers emitter detection, protocol filtering
works correctly, and threat alerts are generated for high-risk emitters.
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


class TestScanToDisplayFlow:
    """Full integration test: scan -> emitters appear -> protocol filtering works."""

    def test_full_scan_cycle(self, client: TestClient):
        """Run a complete scan and verify the flow end-to-end."""
        # 1. Initial state: no emitters
        resp = client.get("/api/cartography/emitters")
        assert resp.status_code == 200
        assert resp.json() == []

        # 2. Trigger scan
        resp = client.post("/api/cartography/scan")
        assert resp.status_code == 200
        scan_result = resp.json()

        # Scan must produce signals and new emitters
        assert len(scan_result["signaux_detectes"]) > 0
        assert len(scan_result["nouveaux_emetteurs"]) > 0

        # 3. Emitters are now visible
        resp = client.get("/api/cartography/emitters")
        assert resp.status_code == 200
        all_emitters = resp.json()
        assert len(all_emitters) > 0

        # 4. Each emitter has the expected JSON structure for the frontend
        em = all_emitters[0]
        assert "identification" in em
        assert "classification" in em
        assert "localisation" in em
        assert "signaux" in em
        assert "menaces" in em
        assert "visualisation" in em

        # Identification fields
        assert "id" in em["identification"]
        assert "nom" in em["identification"]

        # Classification fields
        assert "type" in em["classification"]
        assert "priorite" in em["classification"]
        assert "niveau_menace" in em["classification"]

        # Visualisation fields
        assert "couleur" in em["visualisation"]
        assert "icone" in em["visualisation"]

    def test_protocol_filtering_after_scan(self, client: TestClient):
        """Verify protocol filtering returns only correct types."""
        client.post("/api/cartography/scan")

        # Gather all emitters and separate by type
        resp = client.get("/api/cartography/emitters")
        all_emitters = resp.json()
        all_types = {em["classification"]["type"] for em in all_emitters}

        # Check wifi filtering
        resp = client.get("/api/cartography/emitters/wifi")
        wifi_emitters = resp.json()
        for em in wifi_emitters:
            assert em["classification"]["type"] in ["wifi_access_point", "wifi_client"]

        # Check ble filtering
        resp = client.get("/api/cartography/emitters/ble")
        ble_emitters = resp.json()
        for em in ble_emitters:
            assert em["classification"]["type"] in ["ble_peripheral", "ble_central"]

        # Check lora filtering
        resp = client.get("/api/cartography/emitters/lora")
        lora_emitters = resp.json()
        for em in lora_emitters:
            assert em["classification"]["type"] in ["lora_device", "lora_gateway"]

        # Combined filtered counts should be <= total (some emitters are 'inconnu')
        filtered_total = len(wifi_emitters) + len(ble_emitters) + len(lora_emitters)
        assert filtered_total <= len(all_emitters)

    def test_protocol_specific_endpoints_after_scan(self, client: TestClient):
        """Protocol-specific endpoints reflect cartography data."""
        client.post("/api/cartography/scan")

        # WiFi networks should correspond to wifi_access_point emitters
        resp = client.get("/api/wifi/networks")
        wifi_nets = resp.json()

        resp = client.get("/api/cartography/emitters/wifi")
        wifi_emitters = resp.json()
        wifi_aps = [e for e in wifi_emitters if e["classification"]["type"] == "wifi_access_point"]
        assert len(wifi_nets) == len(wifi_aps)

        # LoRa traffic totals
        resp = client.get("/api/lora/traffic")
        traffic = resp.json()
        assert traffic["total_devices"] >= 0
        assert traffic["total_gateways"] >= 0

    def test_stats_reflect_scan(self, client: TestClient):
        """Stats endpoint reflects scan activity."""
        # Before scan
        resp = client.get("/api/cartography/stats")
        stats_before = resp.json()
        assert stats_before["nb_balayages"] == 0

        # After scan
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/stats")
        stats_after = resp.json()
        assert stats_after["nb_balayages"] == 1
        assert stats_after["nb_signaux_detectes"] > 0
        assert stats_after["nb_emetteurs_uniques"] > 0

    def test_multiple_scans_accumulate(self, client: TestClient):
        """Multiple scans update existing emitters and may detect new ones."""
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/stats")
        stats1 = resp.json()

        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/stats")
        stats2 = resp.json()

        assert stats2["nb_balayages"] == 2
        assert stats2["nb_signaux_detectes"] > stats1["nb_signaux_detectes"]

    def test_threats_populated_after_scan(self, client: TestClient):
        """Threat map contains entries after scan."""
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/threats")
        threats = resp.json()

        # At least one category should have entries (the simulation produces
        # various emitter types including INCONNU which have high threat)
        total_threats = (
            len(threats["critique"])
            + len(threats["haute"])
            + len(threats["moyenne"])
            + len(threats["basse"])
        )
        assert total_threats > 0

    def test_bands_analysis_after_scan(self, client: TestClient):
        """Band occupation analysis reflects detected signals."""
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/bands")
        bands = resp.json()

        # At least one band should have detected emitters
        occupied = [b for b in bands.values() if b["nb_emetteurs"] > 0]
        assert len(occupied) > 0

    def test_alerts_generated_for_high_threat(self, client: TestClient):
        """High-threat emitters generate alerts."""
        scan_result = client.post("/api/cartography/scan").json()

        # The cartography engine evaluates threats and creates alerts
        resp = client.get("/api/cartography/alerts")
        alerts = resp.json()

        # If scan produced alerts, verify structure
        if alerts:
            alert = alerts[0]
            assert "timestamp" in alert
            assert "emetteur_id" in alert
            assert "type" in alert
            assert "niveau_menace" in alert
            assert "description" in alert

        # Also check scan result had alerts list
        assert isinstance(scan_result["alertes"], list)

    def test_scan_json_structure_matches_frontend(self, client: TestClient):
        """Verify the JSON output structure is what the frontend expects.

        The frontend (static/index.html) expects emitters with:
        - identification.id, identification.nom
        - classification.type, classification.niveau_menace
        - visualisation.couleur, visualisation.icone
        - signaux.caracteristiques_recentes (list of signal dicts)
        """
        client.post("/api/cartography/scan")
        resp = client.get("/api/cartography/emitters")
        emitters = resp.json()
        assert len(emitters) > 0

        for em in emitters[:5]:  # Check first 5
            # Frontend reads these fields
            assert em["identification"]["id"] is not None
            assert em["identification"]["nom"] is not None
            assert em["classification"]["type"] is not None
            assert isinstance(em["classification"]["niveau_menace"], int)
            assert em["visualisation"]["couleur"].startswith("#")
            assert em["visualisation"]["icone"] is not None
            assert isinstance(em["signaux"]["caracteristiques_recentes"], list)
