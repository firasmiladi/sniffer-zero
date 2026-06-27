"""Scenario management API endpoints.

GET  /api/scenarios              - List all available YAML scenarios
POST /api/scenarios/{name}/launch - Launch a scenario in background
GET  /api/scenarios/{name}/status - Get scenario execution status
"""

from __future__ import annotations

import asyncio
import time
import threading
from pathlib import Path
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from srt.core.orchestrator import Orchestrator, Scenario
from srt.web.state import get_state
from srt.web.ws import broadcast_sync

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])

# Scenarios directory at project root
_SCENARIOS_DIR = Path(__file__).resolve().parents[4] / "scenarios"

# Category inference from filename prefix
_CATEGORY_PREFIXES = {
    "wifi_": "wifi",
    "ble_": "ble",
    "lora_": "lora",
    "full_": "full",
    "continuous_": "continuous",
    "recon_": "recon",
    "survey_": "survey",
    "autonomous_": "autonomous",
    "lab_": "lab",
    "cartographie_": "cartographie",
}

# Maximum number of completed scenario runs to keep in memory
_MAX_COMPLETED_RUNS = 100


def _infer_category(filename: str) -> str:
    """Infer scenario category from filename prefix."""
    for prefix, category in _CATEGORY_PREFIXES.items():
        if filename.startswith(prefix):
            return category
    return "other"


def _evict_completed_runs(state: Any) -> None:
    """Evict oldest completed runs when the limit is exceeded.

    Keeps at most _MAX_COMPLETED_RUNS completed/failed runs. Running runs
    are never evicted.
    """
    completed = [
        (name, info)
        for name, info in state.scenario_runs.items()
        if info.get("status") in ("completed", "failed")
    ]
    if len(completed) <= _MAX_COMPLETED_RUNS:
        return

    # Sort by started_at ascending (oldest first)
    completed.sort(key=lambda x: x[1].get("started_at", 0))
    to_evict = len(completed) - _MAX_COMPLETED_RUNS
    for name, _ in completed[:to_evict]:
        del state.scenario_runs[name]


class ScenarioInfo(BaseModel):
    name: str
    description: str
    steps_count: int
    category: str


class ScenarioStatusResponse(BaseModel):
    scenario_name: str
    status: str
    started_at: float | None = None
    steps_total: int = 0
    steps_completed: int = 0
    current_step: str | None = None
    results: list[dict[str, Any]] = []


class ScenarioLaunchResponse(BaseModel):
    scenario_name: str
    status: str
    started_at: float
    steps_total: int


@router.get("", response_model=list[ScenarioInfo])
async def list_scenarios() -> list[ScenarioInfo]:
    """List all available YAML scenarios with metadata."""
    scenarios: list[ScenarioInfo] = []

    if not _SCENARIOS_DIR.exists():
        return scenarios

    for yaml_file in sorted(_SCENARIOS_DIR.glob("*.yaml")):
        try:
            scenario = Scenario.load(yaml_file)
            category = _infer_category(yaml_file.stem)
            scenarios.append(
                ScenarioInfo(
                    name=scenario.name,
                    description=scenario.description.strip(),
                    steps_count=len(scenario.steps),
                    category=category,
                )
            )
        except Exception as exc:
            log.warning("scenarios.parse_error", file=str(yaml_file), error=str(exc))
            continue

    return scenarios


@router.post("/{name}/launch", response_model=ScenarioLaunchResponse)
async def launch_scenario(name: str) -> ScenarioLaunchResponse:
    """Launch a scenario by name in a background thread.

    The scenario runs asynchronously and progress is tracked in app state.
    """
    # Find the scenario file
    scenario_path = _SCENARIOS_DIR / f"{name}.yaml"
    if not scenario_path.exists():
        raise HTTPException(status_code=404, detail=f"Scenario '{name}' not found")

    try:
        scenario = Scenario.load(scenario_path)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse scenario: {exc}")

    state = get_state()

    # Check if already running
    existing = state.scenario_runs.get(name)
    if existing and existing.get("status") == "running":
        raise HTTPException(status_code=409, detail=f"Scenario '{name}' is already running")

    # Capture the running event loop before spawning the background thread
    loop = asyncio.get_running_loop()

    started_at = time.time()
    run_info: dict[str, Any] = {
        "scenario_name": name,
        "status": "running",
        "started_at": started_at,
        "steps_total": len(scenario.steps),
        "steps_completed": 0,
        "current_step": None,
        "results": [],
    }
    state.scenario_runs[name] = run_info

    # Evict oldest completed runs if limit exceeded
    _evict_completed_runs(state)

    # Run scenario in background thread
    def _run_scenario() -> None:
        try:
            orch = Orchestrator(dry_run=False, operator="web-ui")
            for i, step in enumerate(scenario.steps):
                run_info["current_step"] = step.module
                run_info["steps_completed"] = i

                # Broadcast progress via WebSocket
                progress_msg = {
                    "type": "scenario_progress",
                    "scenario_name": name,
                    "step_index": i,
                    "module": step.module,
                    "status": "running",
                    "timestamp": time.time(),
                }
                broadcast_sync(progress_msg, loop)

                try:
                    from srt.core.registry import get as registry_get
                    cls = registry_get(step.module)
                    instance = cls()
                    result = orch.run_module(instance, params=step.params)
                    run_info["results"].append({
                        "module": step.module,
                        "status": result.status.value,
                        "summary": result.summary,
                    })
                except Exception as exc:
                    run_info["results"].append({
                        "module": step.module,
                        "status": "error",
                        "summary": str(exc),
                    })

            run_info["steps_completed"] = len(scenario.steps)
            run_info["current_step"] = None
            run_info["status"] = "completed"

            # Broadcast completion
            broadcast_sync({
                "type": "scenario_progress",
                "scenario_name": name,
                "step_index": len(scenario.steps),
                "module": None,
                "status": "completed",
                "timestamp": time.time(),
            }, loop)
        except Exception as exc:
            log.exception("scenarios.run_failed", scenario=name)
            run_info["status"] = "failed"
            run_info["current_step"] = None

    thread = threading.Thread(
        target=_run_scenario, daemon=True, name=f"scenario-{name}"
    )
    thread.start()

    return ScenarioLaunchResponse(
        scenario_name=name,
        status="running",
        started_at=started_at,
        steps_total=len(scenario.steps),
    )


@router.get("/{name}/status", response_model=ScenarioStatusResponse)
async def get_scenario_status(name: str) -> ScenarioStatusResponse:
    """Get the current execution status of a scenario."""
    state = get_state()
    run_info = state.scenario_runs.get(name)

    if run_info is None:
        # No run recorded - return idle status
        return ScenarioStatusResponse(
            scenario_name=name,
            status="idle",
        )

    return ScenarioStatusResponse(
        scenario_name=run_info["scenario_name"],
        status=run_info["status"],
        started_at=run_info.get("started_at"),
        steps_total=run_info.get("steps_total", 0),
        steps_completed=run_info.get("steps_completed", 0),
        current_step=run_info.get("current_step"),
        results=run_info.get("results", []),
    )
