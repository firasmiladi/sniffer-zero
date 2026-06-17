"""Main FastAPI application for the SRT tactical web platform.

Provides:
- CORS middleware for browser access
- Lifespan management (startup/shutdown for MQTT and cartography engine)
- Static file mounting (when static/ directory exists)
- REST API routers and WebSocket endpoint
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from srt.core import registry
from srt.web.api.cartography import router as cartography_router
from srt.web.api.modules import router as modules_router
from srt.web.api.protocols import ble_router, lora_router, wifi_router
from srt.web.api.scenarios import router as scenarios_router
from srt.web.api.spectrum import router as spectrum_router
from srt.web.state import get_state, reset_state
from srt.web.ws import router as ws_router, start_mqtt_bridge

log = structlog.get_logger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: startup and shutdown logic."""
    log.info("web.startup", message="Starting SRT tactical web platform")

    # Ensure modules are discovered
    registry.autodiscover()

    # Start MQTT bridge (graceful failure if broker unavailable)
    state = get_state()
    start_mqtt_bridge()

    # Store event loop reference for MQTT->WS bridging
    loop = asyncio.get_running_loop()
    if state.mqtt_client:
        state.mqtt_client._userdata["loop"] = loop

    yield

    # Shutdown
    log.info("web.shutdown", message="Shutting down SRT tactical web platform")
    if state.mqtt_client:
        try:
            state.mqtt_client.disconnect()
        except Exception:
            pass
    reset_state()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="SRT Tactical Web Platform",
        description="Centralized RF SIGINT web interface for cartography, module management, and real-time monitoring",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS middleware - allow all origins for tactical tool access
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API routers
    app.include_router(modules_router)
    app.include_router(cartography_router)
    app.include_router(scenarios_router)
    app.include_router(spectrum_router)
    app.include_router(wifi_router)
    app.include_router(ble_router)
    app.include_router(lora_router)
    app.include_router(ws_router)

    # Mount static files if directory exists
    if _STATIC_DIR.exists():
        # Serve index.html at root path
        @app.get("/", response_class=FileResponse)
        async def serve_index():
            return FileResponse(str(_STATIC_DIR / "index.html"))

        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Health check endpoint
    @app.get("/api/health")
    async def health_check() -> dict:
        state = get_state()
        return {
            "status": "ok",
            "mqtt_connected": state.mqtt_connected,
            "emitters_tracked": len(state.cartographie.emetteurs),
            "modules_registered": len(registry.get_all()),
        }

    return app
