"""Cartography engine endpoints.

GET  /api/cartography/emitters           - All tracked emitters
GET  /api/cartography/emitters/{protocol} - Filter by protocol
POST /api/cartography/scan               - Trigger a scan cycle with real-time WS broadcast
GET  /api/cartography/stats              - Global statistics
GET  /api/cartography/alerts             - Recent alerts
GET  /api/cartography/bands              - Band occupation analysis
GET  /api/cartography/threats            - Threat map data
GET  /api/cartography/timeline           - Emitters sorted by detection time
GET  /api/cartography/heatmap            - Signal strength data as lat/lon/intensity
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import APIRouter

from srt.cartographie.core import TypeEmetteur
from srt.web.state import get_state
from srt.web.ws import broadcast_sync, broadcast_to_clients

router = APIRouter(prefix="/api/cartography", tags=["cartography"])

# Mapping from protocol name to TypeEmetteur values
_PROTOCOL_TYPE_MAP = {
    "wifi": [TypeEmetteur.WIFI_AP, TypeEmetteur.WIFI_CLIENT],
    "ble": [TypeEmetteur.BLE_PERIPHERIQUE, TypeEmetteur.BLE_CENTRAL],
    "lora": [TypeEmetteur.LORA_DEVICE, TypeEmetteur.LORA_GATEWAY],
}


def _simple_hash(s: str) -> int:
    """Compute a hash matching the JavaScript simpleHash in map.js.

    This ensures heatmap fallback positions and map marker fallback positions
    are identical for the same emitter ID.

    Algorithm (same as JS):
        hash = 0
        for ch in s:
            hash = ((hash << 5) - hash) + ord(ch)
            hash = hash & 0xFFFFFFFF  # 32-bit signed
        return abs(hash interpreted as signed 32-bit int)
    """
    h = 0
    for ch in s:
        h = ((h << 5) - h) + ord(ch)
        h = h & 0xFFFFFFFF  # keep as 32-bit unsigned
    # Convert to signed 32-bit then take absolute value (matches JS Math.abs)
    if h >= 0x80000000:
        h -= 0x100000000
    return abs(h)


def _run_scan_with_broadcast(loop: asyncio.AbstractEventLoop | None = None) -> dict[str, Any]:
    """Run a cartography scan with real-time WebSocket broadcasting.

    Wraps demarrer_balayage logic to broadcast emitter_new, emitter_update,
    band_update, and scan_progress messages as the scan proceeds.

    Emits incremental scan_progress messages at each frequency step so the
    frontend progress bar updates smoothly instead of jumping from 0% to 100%.
    """
    state = get_state()
    carto = state.cartographie
    config = carto.config

    # Calculate total steps for progress tracking
    total_steps = int(
        (config.freq_fin_mhz - config.freq_debut_mhz) / config.pas_balayage_mhz
    )
    state.scan_in_progress = True
    state.scan_progress = {
        "current_freq_mhz": config.freq_debut_mhz,
        "total_steps": total_steps,
        "completed_steps": 0,
        "started_at": time.time(),
    }

    # Track emitters known before this scan
    known_emitter_ids = set(carto.emetteurs.keys())

    # Perform the scan step-by-step for incremental broadcasting
    resultats_cycle: dict[str, Any] = {
        "timestamp": None,
        "signaux_detectes": [],
        "nouveaux_emetteurs": [],
        "emetteurs_mis_a_jour": [],
        "alertes": [],
    }

    from datetime import datetime
    resultats_cycle["timestamp"] = datetime.now().isoformat()

    freq_actuelle = config.freq_debut_mhz
    step_index = 0
    while freq_actuelle < config.freq_fin_mhz:
        # Generate IQ data (simulation mode)
        iq_data = carto._generer_iq_test(freq_actuelle)

        # Analyze IQ data
        signaux = carto.analyseur.analyser_iq(iq_data, freq_actuelle * 1e6)

        # Process each detected signal
        emitters_before = set(carto.emetteurs.keys())
        for sig in signaux:
            carto._traiter_signal(sig, resultats_cycle)
        emitters_after = set(carto.emetteurs.keys())

        # Broadcast new emitters detected in this step
        new_in_step = emitters_after - emitters_before
        for eid in new_in_step:
            emitter = carto.emetteurs.get(eid)
            if emitter:
                broadcast_sync({
                    "type": "emitter_new",
                    "emitter": emitter.to_dict(),
                }, loop)

        # Broadcast updated emitters in this step
        updated_in_step = emitters_before & emitters_after - known_emitter_ids
        for eid in resultats_cycle.get("emetteurs_mis_a_jour", []):
            if eid in emitters_before:
                emitter = carto.emetteurs.get(eid)
                if emitter:
                    broadcast_sync({
                        "type": "emitter_update",
                        "emitter": emitter.to_dict(),
                    }, loop)

        step_index += 1
        freq_actuelle += config.pas_balayage_mhz

        # Broadcast incremental progress
        state.scan_progress["completed_steps"] = step_index
        state.scan_progress["current_freq_mhz"] = freq_actuelle
        broadcast_sync({
            "type": "scan_progress",
            "current_freq_mhz": freq_actuelle,
            "total_steps": total_steps,
            "completed_steps": step_index,
            "status": "scanning",
        }, loop)

    # Update cartography engine statistics
    carto.stats["nb_balayages"] += 1
    carto.stats["derniere_mise_a_jour"] = datetime.now().isoformat()
    carto.stats["nb_emetteurs_uniques"] = len(carto.emetteurs)

    # Evaluate threats
    carto._evaluer_menaces_globales(resultats_cycle)

    # Archive the scan
    carto.historique_balayages.append(resultats_cycle)

    # Broadcast band update
    try:
        bands = carto._analyser_occupation_bandes()
        broadcast_sync({
            "type": "band_update",
            "bands": bands,
        }, loop)
    except Exception:
        pass

    # Broadcast scan completion
    state.scan_progress["completed_steps"] = total_steps
    state.scan_progress["current_freq_mhz"] = config.freq_fin_mhz
    broadcast_sync({
        "type": "scan_progress",
        "current_freq_mhz": config.freq_fin_mhz,
        "total_steps": total_steps,
        "completed_steps": total_steps,
        "status": "completed",
    }, loop)

    state.scan_in_progress = False
    return resultats_cycle


@router.get("/emitters")
async def get_emitters() -> list[dict[str, Any]]:
    """Return all tracked emitters from the cartography engine."""
    state = get_state()
    emitters = state.cartographie.emetteurs
    return [em.to_dict() for em in emitters.values()]


@router.get("/emitters/{protocol}")
async def get_emitters_by_protocol(protocol: str) -> list[dict[str, Any]]:
    """Return emitters filtered by protocol (wifi, ble, lora)."""
    state = get_state()
    types = _PROTOCOL_TYPE_MAP.get(protocol, [])
    emitters = state.cartographie.emetteurs
    return [
        em.to_dict()
        for em in emitters.values()
        if em.type_emetteur in types
    ]


@router.post("/scan")
async def trigger_scan() -> dict[str, Any]:
    """Trigger a scan cycle on the cartography engine with real-time broadcasting."""
    state = get_state()

    # Capture the running event loop before spawning the background thread
    loop = asyncio.get_running_loop()

    # Broadcast scan start
    config = state.cartographie.config
    total_steps = int(
        (config.freq_fin_mhz - config.freq_debut_mhz) / config.pas_balayage_mhz
    )
    await broadcast_to_clients({
        "type": "scan_progress",
        "current_freq_mhz": config.freq_debut_mhz,
        "total_steps": total_steps,
        "completed_steps": 0,
        "status": "started",
    })

    results = await asyncio.to_thread(_run_scan_with_broadcast, loop)
    return results


@router.get("/stats")
async def get_stats() -> dict[str, Any]:
    """Return global cartography statistics."""
    state = get_state()
    return dict(state.cartographie.stats)


@router.get("/alerts")
async def get_alerts() -> list[dict[str, Any]]:
    """Return recent alerts from the cartography engine."""
    state = get_state()
    return list(state.cartographie.alertes[-100:])


@router.get("/bands")
async def get_bands() -> dict[str, Any]:
    """Return band occupation analysis."""
    state = get_state()
    return state.cartographie._analyser_occupation_bandes()


@router.get("/threats")
async def get_threats() -> dict[str, Any]:
    """Return threat map data."""
    state = get_state()
    return state.cartographie._generer_carte_menaces()


@router.get("/timeline")
async def get_timeline() -> list[dict[str, Any]]:
    """Return emitters sorted by first_seen/last_seen timestamps for timeline view."""
    state = get_state()
    emitters = state.cartographie.emetteurs

    timeline_entries = []
    for em in emitters.values():
        entry = em.to_dict()
        # Ensure first_seen and last_seen fields are present
        entry["first_seen"] = em.premiere_detection
        entry["last_seen"] = em.derniere_detection
        timeline_entries.append(entry)

    # Sort by first_seen (most recent first)
    timeline_entries.sort(
        key=lambda e: e.get("first_seen") or "",
        reverse=True,
    )
    return timeline_entries


@router.get("/heatmap")
async def get_heatmap() -> list[dict[str, Any]]:
    """Return signal strength data as a list of {lat, lon, intensity} points.

    Intensity is normalized from puissance_dbm values.
    """
    state = get_state()
    emitters = state.cartographie.emetteurs

    heatmap_points: list[dict[str, Any]] = []
    for em in emitters.values():
        # Get position data
        lat, lon = None, None
        if hasattr(em, "localisation") and em.localisation:
            pos = getattr(em.localisation, "derniere_position", None)
            if pos:
                lat = getattr(pos, "lat", None) or getattr(pos, "latitude", None)
                lon = getattr(pos, "lon", None) or getattr(pos, "longitude", None)

        # Fallback: derive from emitter ID hash for visualization
        # Uses the same algorithm as map.js simpleHash for consistent positions
        if lat is None or lon is None:
            h = _simple_hash(em.id_unique)
            lat = 48.8566 + ((h % 1000) - 500) / 10000.0
            lon = 2.3522 + (((h >> 10) % 1000) - 500) / 10000.0
            synthetic = True
        else:
            synthetic = False

        # Get signal strength (intensity)
        intensity = -80.0  # default
        if em.caracteristiques_signaux:
            last_sig = em.caracteristiques_signaux[-1]
            intensity = getattr(last_sig, "puissance_dbm", -80.0)

        # Normalize intensity: -100 dBm -> 0.0, -30 dBm -> 1.0
        normalized = max(0.0, min(1.0, (intensity + 100) / 70.0))

        heatmap_points.append({
            "lat": lat,
            "lon": lon,
            "intensity": round(normalized, 3),
            "puissance_dbm": intensity,
            "emitter_id": em.id_unique,
            "type": em.type_emetteur.value if em.type_emetteur else "unknown",
            "synthetic_position": synthetic,
        })

    return heatmap_points
