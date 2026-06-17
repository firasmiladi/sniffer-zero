"""Protocol-specific endpoints for WiFi, BLE, and LoRa data.

WiFi:
  GET /api/wifi/networks  - AP list from last recon
  GET /api/wifi/clients   - Client list

BLE:
  GET /api/ble/devices    - BLE device inventory
  GET /api/ble/services   - Service UUID summary

LoRa:
  GET /api/lora/devices   - LoRa devices
  GET /api/lora/gateways  - Gateways
  GET /api/lora/traffic   - Traffic stats
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from srt.cartographie.core import TypeEmetteur
from srt.web.state import get_state

router = APIRouter(tags=["protocols"])


# --- WiFi endpoints ---

wifi_router = APIRouter(prefix="/api/wifi", tags=["wifi"])


@wifi_router.get("/networks")
async def get_wifi_networks() -> list[dict[str, Any]]:
    """Return WiFi access points from cartography data."""
    state = get_state()
    emitters = state.cartographie.emetteurs
    networks = []
    for em in emitters.values():
        if em.type_emetteur == TypeEmetteur.WIFI_AP:
            networks.append({
                "id": em.id_unique,
                "ssid": em.ssid,
                "mac": em.adresse_mac,
                "name": em.nom,
                "threat_level": em.niveau_menace,
                "last_seen": em.derniere_detection.isoformat() if em.derniere_detection else None,
                "signal": {
                    "frequency_mhz": (
                        em.caracteristiques_signaux[-1].frequence_centre_mhz
                        if em.caracteristiques_signaux else None
                    ),
                    "power_dbm": (
                        em.caracteristiques_signaux[-1].puissance_dbm
                        if em.caracteristiques_signaux else None
                    ),
                },
            })
    return networks


@wifi_router.get("/clients")
async def get_wifi_clients() -> list[dict[str, Any]]:
    """Return WiFi clients from cartography data."""
    state = get_state()
    emitters = state.cartographie.emetteurs
    clients = []
    for em in emitters.values():
        if em.type_emetteur == TypeEmetteur.WIFI_CLIENT:
            clients.append({
                "id": em.id_unique,
                "mac": em.adresse_mac,
                "name": em.nom,
                "threat_level": em.niveau_menace,
                "last_seen": em.derniere_detection.isoformat() if em.derniere_detection else None,
            })
    return clients


# --- BLE endpoints ---

ble_router = APIRouter(prefix="/api/ble", tags=["ble"])


@ble_router.get("/devices")
async def get_ble_devices() -> list[dict[str, Any]]:
    """Return BLE devices from cartography data."""
    state = get_state()
    emitters = state.cartographie.emetteurs
    devices = []
    for em in emitters.values():
        if em.type_emetteur in (TypeEmetteur.BLE_PERIPHERIQUE, TypeEmetteur.BLE_CENTRAL):
            devices.append({
                "id": em.id_unique,
                "mac": em.adresse_mac,
                "name": em.nom,
                "type": em.type_emetteur.value,
                "threat_level": em.niveau_menace,
                "last_seen": em.derniere_detection.isoformat() if em.derniere_detection else None,
                "signal": {
                    "frequency_mhz": (
                        em.caracteristiques_signaux[-1].frequence_centre_mhz
                        if em.caracteristiques_signaux else None
                    ),
                    "power_dbm": (
                        em.caracteristiques_signaux[-1].puissance_dbm
                        if em.caracteristiques_signaux else None
                    ),
                },
            })
    return devices


@ble_router.get("/services")
async def get_ble_services() -> list[dict[str, Any]]:
    """Return BLE service UUID summary (derived from signal characteristics)."""
    state = get_state()
    emitters = state.cartographie.emetteurs
    services: list[dict[str, Any]] = []
    for em in emitters.values():
        if em.type_emetteur in (TypeEmetteur.BLE_PERIPHERIQUE, TypeEmetteur.BLE_CENTRAL):
            services.append({
                "device_id": em.id_unique,
                "device_name": em.nom,
                "protocol": em.caracteristiques_signaux[-1].protocole if em.caracteristiques_signaux else None,
                "modulation": em.caracteristiques_signaux[-1].modulation_type if em.caracteristiques_signaux else None,
            })
    return services


# --- LoRa endpoints ---

lora_router = APIRouter(prefix="/api/lora", tags=["lora"])


@lora_router.get("/devices")
async def get_lora_devices() -> list[dict[str, Any]]:
    """Return LoRa devices from cartography data."""
    state = get_state()
    emitters = state.cartographie.emetteurs
    devices = []
    for em in emitters.values():
        if em.type_emetteur == TypeEmetteur.LORA_DEVICE:
            devices.append({
                "id": em.id_unique,
                "mac": em.adresse_mac,
                "name": em.nom,
                "threat_level": em.niveau_menace,
                "last_seen": em.derniere_detection.isoformat() if em.derniere_detection else None,
                "signal": {
                    "frequency_mhz": (
                        em.caracteristiques_signaux[-1].frequence_centre_mhz
                        if em.caracteristiques_signaux else None
                    ),
                    "power_dbm": (
                        em.caracteristiques_signaux[-1].puissance_dbm
                        if em.caracteristiques_signaux else None
                    ),
                },
            })
    return devices


@lora_router.get("/gateways")
async def get_lora_gateways() -> list[dict[str, Any]]:
    """Return LoRa gateways from cartography data."""
    state = get_state()
    emitters = state.cartographie.emetteurs
    gateways = []
    for em in emitters.values():
        if em.type_emetteur == TypeEmetteur.LORA_GATEWAY:
            gateways.append({
                "id": em.id_unique,
                "mac": em.adresse_mac,
                "name": em.nom,
                "threat_level": em.niveau_menace,
                "last_seen": em.derniere_detection.isoformat() if em.derniere_detection else None,
                "signal": {
                    "frequency_mhz": (
                        em.caracteristiques_signaux[-1].frequence_centre_mhz
                        if em.caracteristiques_signaux else None
                    ),
                    "power_dbm": (
                        em.caracteristiques_signaux[-1].puissance_dbm
                        if em.caracteristiques_signaux else None
                    ),
                },
            })
    return gateways


@lora_router.get("/traffic")
async def get_lora_traffic() -> dict[str, Any]:
    """Return LoRa traffic statistics."""
    state = get_state()
    emitters = state.cartographie.emetteurs
    lora_emitters = [
        em for em in emitters.values()
        if em.type_emetteur in (TypeEmetteur.LORA_DEVICE, TypeEmetteur.LORA_GATEWAY)
    ]

    total_signals = sum(len(em.caracteristiques_signaux) for em in lora_emitters)

    return {
        "total_devices": len([e for e in lora_emitters if e.type_emetteur == TypeEmetteur.LORA_DEVICE]),
        "total_gateways": len([e for e in lora_emitters if e.type_emetteur == TypeEmetteur.LORA_GATEWAY]),
        "total_signals_captured": total_signals,
        "devices": [
            {
                "id": em.id_unique,
                "name": em.nom,
                "signal_count": len(em.caracteristiques_signaux),
                "last_seen": em.derniere_detection.isoformat() if em.derniere_detection else None,
            }
            for em in lora_emitters
        ],
    }
