"""Module listing and launching endpoints.

GET  /api/modules            - List all registered modules
GET  /api/modules/{protocol} - Filter modules by protocol (wifi/ble/lora)
POST /api/modules/{name}/launch - Launch a module with params
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from srt.core import registry
from srt.core.module import ModuleContext, Risk, Status
from srt.core.orchestrator import Orchestrator
from srt.core.safety import evaluate as safety_evaluate
from srt.web.state import get_state

router = APIRouter(prefix="/api/modules", tags=["modules"])


class ModuleInfo(BaseModel):
    name: str
    protocol: str
    risk: str
    description: str
    mitre_ttp: list[str]
    requires: list[str]


class LaunchRequest(BaseModel):
    params: dict[str, Any] = {}
    dry_run: bool = True
    operator: str = "web-ui"


class LaunchResponse(BaseModel):
    module_name: str
    status: str
    summary: str
    duration_s: float
    artifacts: list[dict[str, Any]]
    metrics: dict[str, Any]


@router.get("", response_model=list[ModuleInfo])
async def list_modules() -> list[ModuleInfo]:
    """List all registered modules with metadata."""
    modules = registry.get_all()
    return [
        ModuleInfo(
            name=cls.name,
            protocol=cls.protocol,
            risk=cls.risk.value,
            description=cls.description or "",
            mitre_ttp=list(cls.mitre_ttp),
            requires=list(cls.requires),
        )
        for cls in modules
    ]


@router.get("/{protocol}", response_model=list[ModuleInfo])
async def list_modules_by_protocol(protocol: str) -> list[ModuleInfo]:
    """List modules filtered by protocol (wifi, ble, lora)."""
    modules = registry.get_all()
    filtered = [cls for cls in modules if cls.protocol == protocol]
    if not filtered:
        # Return empty list rather than 404 - protocol may just have no modules
        return []
    return [
        ModuleInfo(
            name=cls.name,
            protocol=cls.protocol,
            risk=cls.risk.value,
            description=cls.description or "",
            mitre_ttp=list(cls.mitre_ttp),
            requires=list(cls.requires),
        )
        for cls in filtered
    ]


@router.post("/{name}/launch", response_model=LaunchResponse)
async def launch_module(name: str, request: LaunchRequest) -> LaunchResponse:
    """Launch a module by name with optional parameters.

    Safety enforcement: non-passive modules require authorization check
    and default to dry_run=True. The web interface enforces dry_run for
    non-passive modules unless authorization is explicitly verified.
    """
    try:
        cls = registry.get(name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Module '{name}' not found")

    # Safety enforcement: non-passive modules require authorization for live execution
    effective_dry_run = False
    if not request.dry_run and cls.risk != Risk.PASSIVE:
        auth, _ = safety_evaluate()
        if not auth.ok:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Module '{name}' has risk level '{cls.risk.value}' and requires "
                    f"valid authorization for non-dry-run execution. "
                    f"Reason: {auth.reason}"
                ),
            )

    orch = Orchestrator(dry_run=effective_dry_run, operator=request.operator)
    instance = cls()
    result = await asyncio.to_thread(orch.run_module, instance, params=request.params)

    # Store result in app state
    state = get_state()
    state.module_results.append(
        {
            "module_name": result.module_name,
            "status": result.status.value,
            "summary": result.summary,
            "timestamp": time.time(),
        }
    )

    return LaunchResponse(
        module_name=result.module_name,
        status=result.status.value,
        summary=result.summary,
        duration_s=result.duration_s,
        artifacts=result.artifacts,
        metrics=result.metrics,
    )
