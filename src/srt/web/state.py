"""Application state singleton for the web platform.

Holds the MoteurCartographie instance, in-memory module results,
emitter cache, and MQTT connection status. Decouples the API from
hardware so it works with simulated data when no hardware is present.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from srt.cartographie.moteur_cartographie import ConfigCartographie, MoteurCartographie


@dataclass
class AppState:
    """Singleton holding shared application state."""

    # Cartography engine
    cartographie: MoteurCartographie = field(default_factory=lambda: MoteurCartographie(ConfigCartographie()))

    # Module execution results (in-memory cache)
    module_results: list[dict[str, Any]] = field(default_factory=list)

    # Scenario execution tracking
    scenario_runs: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Scan tracking
    scan_in_progress: bool = False
    scan_progress: dict[str, Any] = field(default_factory=lambda: {
        "current_freq_mhz": 0.0,
        "total_steps": 0,
        "completed_steps": 0,
        "started_at": None,
    })

    # MQTT connection status
    mqtt_connected: bool = False
    mqtt_client: Any = None

    # WebSocket clients
    ws_clients: list[Any] = field(default_factory=list)
    ws_lock: threading.Lock = field(default_factory=threading.Lock)

    def add_ws_client(self, ws: Any) -> None:
        with self.ws_lock:
            self.ws_clients.append(ws)

    def remove_ws_client(self, ws: Any) -> None:
        with self.ws_lock:
            if ws in self.ws_clients:
                self.ws_clients.remove(ws)

    def get_ws_clients(self) -> list[Any]:
        with self.ws_lock:
            return list(self.ws_clients)


# Module-level singleton
_state: AppState | None = None


def get_state() -> AppState:
    """Get or create the application state singleton."""
    global _state
    if _state is None:
        _state = AppState()
    return _state


def reset_state() -> None:
    """Reset the application state (useful for testing)."""
    global _state
    _state = None
