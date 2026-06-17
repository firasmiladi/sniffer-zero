"""Base classes shared by every recon and exploit module.

Every action in `sniffer-rt` -- passive scan or active attack -- is an
``AttackModule``. Modules expose a uniform lifecycle so they can be chained by
the orchestrator and rendered uniformly in reports and dashboards.

    precheck(ctx) -> bool      # safety + capability gate
    run(ctx)      -> AttackResult
    cleanup(ctx)  -> None      # always invoked, even on failure

Modules must be **pure declarations of intent**: they never bypass the safety
layer (`srt.core.safety`).
"""

from __future__ import annotations

import abc
import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)


class Risk(str, enum.Enum):
    PASSIVE = "passive"
    ACTIVE_LAB = "active-lab"
    DESTRUCTIVE_LAB = "destructive-lab"
    FORBIDDEN = "forbidden"


class Status(str, enum.Enum):
    OK = "ok"
    FAIL = "fail"
    ABORTED = "aborted"
    REFUSED = "refused"


@dataclass
class ModuleContext:
    """Runtime context passed to every module.

    Built by the orchestrator from the global config + scenario step.
    """

    session_id: uuid.UUID
    operator: str
    params: dict[str, Any] = field(default_factory=dict)
    workdir: str = "data/captures"
    dry_run: bool = False
    # Safety-resolved view (filled by `safety.evaluate`)
    authorization_ok: bool = False
    authorized_bands_mhz: list[str] = field(default_factory=list)
    whitelist: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class AttackResult:
    """Structured outcome of a module run. Persisted to ``module_results``."""

    module_name: str
    protocol: str
    risk: Risk
    status: Status
    started_at: float
    ended_at: float
    summary: str = ""
    mitre_ttp: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_s(self) -> float:
        return max(0.0, self.ended_at - self.started_at)


class AttackModule(abc.ABC):
    """Abstract base for recon and exploit modules.

    Subclasses MUST set ``name``, ``protocol``, ``risk`` and override ``run``.
    """

    # --- declarative metadata -------------------------------------------------
    name: str = ""
    protocol: str = ""           # "wifi" | "ble" | "lora"
    risk: Risk = Risk.PASSIVE
    mitre_ttp: list[str] = []
    cve: list[str] = []
    requires: list[str] = []     # capabilities, e.g. ["hackrf", "monitor-mode-nic"]
    description: str = ""

    # --- lifecycle ------------------------------------------------------------
    def precheck(self, ctx: ModuleContext) -> bool:
        """Default safety gate. Override to add capability checks.

        Refuses if:
          * risk is FORBIDDEN
          * risk > PASSIVE and ``ctx.authorization_ok`` is False
        """
        if self.risk is Risk.FORBIDDEN:
            log.error("module.refused.forbidden", module=self.name)
            return False
        if self.risk is not Risk.PASSIVE and not ctx.authorization_ok:
            log.error(
                "module.refused.unauthorized",
                module=self.name,
                risk=self.risk.value,
            )
            return False
        return True

    @abc.abstractmethod
    def run(self, ctx: ModuleContext) -> AttackResult:
        """Execute the module. Must always return an ``AttackResult``."""

    def cleanup(self, ctx: ModuleContext) -> None:
        """Release resources. Default no-op. Always called by the orchestrator."""
        return None

    # --- helpers --------------------------------------------------------------
    def _result(
        self,
        status: Status,
        started_at: float,
        summary: str = "",
        artifacts: list[dict[str, Any]] | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> AttackResult:
        return AttackResult(
            module_name=self.name,
            protocol=self.protocol,
            risk=self.risk,
            status=status,
            started_at=started_at,
            ended_at=time.time(),
            summary=summary,
            mitre_ttp=list(self.mitre_ttp),
            cve=list(self.cve),
            artifacts=artifacts or [],
            metrics=metrics or {},
        )

    def refused(self, started_at: float, reason: str) -> AttackResult:
        return self._result(Status.REFUSED, started_at, summary=f"refused: {reason}")
