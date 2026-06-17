"""Spectrum sweep API endpoints.

POST /api/spectrum/sweep  - Trigger a single HackRF sweep and return results
GET  /api/spectrum/live   - Return latest spectrum data from memory
GET  /api/spectrum/bands  - Return aggregated band occupation from sweep data
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog
from fastapi import APIRouter

from srt.gnuradio.hackrf_sweep import HackRFSweep, SweepResult
from srt.web.ws import broadcast_sync, broadcast_to_clients

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/spectrum", tags=["spectrum"])

# In-memory cache of latest sweep result
_latest_sweep: SweepResult | None = None
_sweep_history: list[dict[str, Any]] = []
_MAX_HISTORY = 50


def reset_spectrum_state() -> None:
    """Reset module-level spectrum state (for testing)."""
    global _latest_sweep, _sweep_history
    _latest_sweep = None
    _sweep_history = []


def _run_sweep(
    freq_start_mhz: float,
    freq_end_mhz: float,
    bin_width_hz: float,
    lna_gain: int,
    vga_gain: int,
    loop: asyncio.AbstractEventLoop | None = None,
) -> dict[str, Any]:
    """Execute a single sweep in a background thread."""
    global _latest_sweep

    sweep = HackRFSweep(
        freq_start_mhz=freq_start_mhz,
        freq_end_mhz=freq_end_mhz,
        bin_width_hz=bin_width_hz,
        lna_gain=lna_gain,
        vga_gain=vga_gain,
    )

    result = sweep.single_sweep()
    _latest_sweep = result

    # Store in history
    result_dict = result.to_dict()
    _sweep_history.append(result_dict)
    if len(_sweep_history) > _MAX_HISTORY:
        _sweep_history.pop(0)

    # Broadcast to WebSocket clients
    broadcast_sync({
        "type": "spectrum_update",
        "data": result_dict,
    }, loop)

    return result_dict


@router.post("/sweep")
async def trigger_sweep(
    freq_start_mhz: float = 2400,
    freq_end_mhz: float = 2500,
    bin_width_hz: float = 1_000_000,
    lna_gain: int = 32,
    vga_gain: int = 20,
) -> dict[str, Any]:
    """Trigger a single HackRF sweep and return spectrum data.

    Parameters are passed as query params:
        POST /api/spectrum/sweep?freq_start_mhz=2400&freq_end_mhz=2500

    Returns the complete sweep result with frequencies and power levels.
    Also broadcasts a spectrum_update WebSocket message.
    """
    # Validate parameters
    if freq_start_mhz >= freq_end_mhz:
        return {"error": "freq_start_mhz must be less than freq_end_mhz"}
    if freq_start_mhz < 1 or freq_end_mhz > 6000:
        return {"error": "Frequency range must be between 1 and 6000 MHz"}

    # Get event loop for WebSocket broadcasting
    loop = asyncio.get_running_loop()

    # Broadcast sweep start
    await broadcast_to_clients({
        "type": "spectrum_update",
        "data": {
            "status": "scanning",
            "freq_start_mhz": freq_start_mhz,
            "freq_end_mhz": freq_end_mhz,
        },
    })

    # Run sweep in background thread (hackrf_sweep is blocking)
    result = await asyncio.to_thread(
        _run_sweep,
        freq_start_mhz,
        freq_end_mhz,
        bin_width_hz,
        lna_gain,
        vga_gain,
        loop,
    )

    return result


@router.get("/live")
async def get_live_spectrum() -> dict[str, Any]:
    """Return the latest spectrum data from the most recent sweep.

    Returns cached data from the last sweep. If no sweep has been performed,
    returns an empty structure with status 'no_data'.
    """
    global _latest_sweep

    if _latest_sweep is None:
        return {
            "status": "no_data",
            "message": "No sweep data available. Run POST /api/spectrum/sweep first.",
            "frequencies_mhz": [],
            "powers_db": [],
        }

    data = _latest_sweep.to_dict()
    data["status"] = "ok"
    return data


@router.get("/bands")
async def get_spectrum_bands() -> dict[str, Any]:
    """Return aggregated band occupation from sweep data.

    Groups frequency bins by ISM band and computes statistics:
    peak power, average power, noise floor, and signal count per band.
    """
    global _latest_sweep

    if _latest_sweep is None:
        return {
            "status": "no_data",
            "bands": {},
            "message": "No sweep data available. Run POST /api/spectrum/sweep first.",
        }

    band_summary = _latest_sweep.get_band_summary()

    return {
        "status": "ok",
        "timestamp": _latest_sweep.timestamp.isoformat(),
        "freq_range_mhz": [_latest_sweep.freq_start_mhz, _latest_sweep.freq_end_mhz],
        "total_bins": _latest_sweep.num_bins,
        "bands": band_summary,
    }


@router.get("/history")
async def get_sweep_history(limit: int = 10) -> dict[str, Any]:
    """Return recent sweep history.

    Parameters
    ----------
    limit : int
        Number of recent sweeps to return (default: 10, max: 50).
    """
    limit = min(limit, _MAX_HISTORY)
    return {
        "status": "ok",
        "count": len(_sweep_history),
        "sweeps": _sweep_history[-limit:],
    }
