"""Run modules and scenarios end-to-end."""

from __future__ import annotations

import getpass
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml

from srt.core import db, safety
from srt.core.module import AttackModule, AttackResult, ModuleContext, Status
from srt.core.registry import get as registry_get

log = structlog.get_logger(__name__)


@dataclass
class ScenarioStep:
    module: str
    params: dict[str, Any]
    id: str | None = None


@dataclass
class ScenarioOptions:
    """Options parsed from the scenario YAML 'options:' block."""

    bail_on_fail: bool = True
    dry_run: bool = False
    report_format: list[str] = field(default_factory=lambda: ["json", "markdown"])
    loop: bool = False
    loop_delay_s: float = 60.0


@dataclass
class Scenario:
    name: str
    description: str
    steps: list[ScenarioStep]
    operator: str | None = None
    variables: dict[str, str] = field(default_factory=dict)
    options: ScenarioOptions = field(default_factory=ScenarioOptions)

    @classmethod
    def load(cls, path: Path) -> Scenario:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

        # Parse variables block
        variables: dict[str, str] = {}
        raw_vars = data.get("variables", {})
        if isinstance(raw_vars, dict):
            variables = {str(k): str(v) for k, v in raw_vars.items()}

        # Parse options block
        raw_opts = data.get("options", {}) or {}
        options = ScenarioOptions(
            bail_on_fail=bool(raw_opts.get("bail_on_fail", True)),
            dry_run=bool(raw_opts.get("dry_run", False)),
            report_format=list(raw_opts.get("report_format", ["json", "markdown"])),
            loop=bool(raw_opts.get("loop", False)),
            loop_delay_s=float(raw_opts.get("loop_delay_s", 60.0)),
        )

        return cls(
            name=str(data.get("name", path.stem)),
            description=str(data.get("description", "")),
            operator=data.get("operator"),
            variables=variables,
            options=options,
            steps=[
                ScenarioStep(
                    module=str(s["module"]),
                    params=dict(s.get("params", {})),
                    id=s.get("id"),
                )
                for s in (data.get("steps") or [])
            ],
        )


# --------------------------------------------------------------------------- #
# Variable resolution                                                         #
# --------------------------------------------------------------------------- #

_VAR_PATTERN = re.compile(r"\{\{(.+?)\}\}")


def _resolve_dotted(path: str, context: dict[str, Any]) -> str:
    """Resolve a dotted path like 'step_id.artifacts[0].field' into context."""
    parts = path.strip()
    # Split on dots, but handle array indexing
    tokens = re.split(r"\.", parts)
    current: Any = context
    for token in tokens:
        # Check for array indexing: key[N]
        m = re.match(r"^(\w+)\[(\d+)\]$", token)
        if m:
            key, idx = m.group(1), int(m.group(2))
            if isinstance(current, dict) and key in current:
                current = current[key]
                if isinstance(current, (list, tuple)) and idx < len(current):
                    current = current[idx]
                else:
                    return "{{" + path + "}}"
            else:
                return "{{" + path + "}}"
        else:
            if isinstance(current, dict) and token in current:
                current = current[token]
            else:
                return "{{" + path + "}}"
    return str(current) if not isinstance(current, (dict, list)) else str(current)


def _resolve_variables(
    params: dict[str, Any],
    variables: dict[str, str],
    cli_vars: dict[str, str],
    context: dict[str, Any],
) -> dict[str, Any]:
    """Resolve {{var_name}} patterns in step params.

    Resolution order:
      1. cli_vars (highest priority)
      2. scenario variables
      3. context (previous step artifacts via step_id)
    """
    resolved: dict[str, Any] = {}
    for key, value in params.items():
        if isinstance(value, str):
            resolved[key] = _VAR_PATTERN.sub(
                lambda m: _resolve_single(m.group(1), variables, cli_vars, context),
                value,
            )
        else:
            resolved[key] = value
    return resolved


def _resolve_single(
    var_name: str,
    variables: dict[str, str],
    cli_vars: dict[str, str],
    context: dict[str, Any],
) -> str:
    """Resolve a single variable name."""
    name = var_name.strip()
    # CLI vars take priority
    if name in cli_vars:
        return cli_vars[name]
    # Scenario variables
    if name in variables:
        return variables[name]
    # Context (step chaining) - try dotted path resolution
    if "." in name or "[" in name:
        return _resolve_dotted(name, context)
    # Simple context lookup
    if name in context:
        val = context[name]
        return str(val) if not isinstance(val, (dict, list)) else str(val)
    # Unresolved - leave as-is
    return "{{" + var_name + "}}"


# --------------------------------------------------------------------------- #
# Orchestrator                                                                #
# --------------------------------------------------------------------------- #


class Orchestrator:
    def __init__(self, *, dry_run: bool = False, operator: str | None = None) -> None:
        self.dry_run = dry_run
        self.operator = operator or getpass.getuser()

    # --- single module --------------------------------------------------------
    def run_module(
        self, module: AttackModule, params: dict[str, Any] | None = None,
        session_id: uuid.UUID | None = None,
    ) -> AttackResult:
        auth, whitelist = safety.evaluate()
        ctx = ModuleContext(
            session_id=session_id or uuid.uuid4(),
            operator=self.operator,
            params=params or {},
            dry_run=self.dry_run,
            authorization_ok=auth.ok,
            authorized_bands_mhz=list(auth.authorized_bands_mhz),
            whitelist=whitelist,
        )
        started = time.time()
        if not module.precheck(ctx):
            result = module.refused(started, "precheck failed")
        else:
            try:
                if self.dry_run:
                    result = module._result(  # noqa: SLF001 - intentional
                        Status.OK, started, summary="dry-run: skipped"
                    )
                else:
                    result = module.run(ctx)
            except Exception as exc:  # noqa: BLE001 - log + structured fail
                log.exception("module.exception", module=module.name)
                result = module._result(  # noqa: SLF001 - intentional
                    Status.FAIL, started, summary=f"exception: {exc}"
                )
            finally:
                try:
                    module.cleanup(ctx)
                except Exception as exc:  # pragma: no cover - defensive
                    log.warning("module.cleanup.failed", module=module.name, error=str(exc))

        db.write_result(ctx.session_id, result)
        return result

    # --- scenario -------------------------------------------------------------
    def run_scenario(
        self,
        scenario: Scenario,
        cli_vars: dict[str, str] | None = None,
    ) -> list[AttackResult]:
        """Run all steps in a scenario with variable resolution and step chaining.

        Args:
            scenario: Parsed scenario object.
            cli_vars: Optional dict of CLI --var overrides (key=value).

        Returns:
            List of AttackResult from executed steps.
        """
        cli_vars = cli_vars or {}
        operator = scenario.operator or self.operator
        session_id = db.start_session(operator=operator, scenario=scenario.name)
        log.info(
            "orchestrator.scenario.start",
            name=scenario.name,
            steps=len(scenario.steps),
            session_id=str(session_id),
        )

        # Merge dry_run from scenario options
        original_dry_run = self.dry_run
        if scenario.options.dry_run:
            self.dry_run = True
        bail_on_fail = scenario.options.bail_on_fail

        results: list[AttackResult] = []
        context: dict[str, Any] = {}

        def _execute_steps() -> None:
            for i, step in enumerate(scenario.steps, start=1):
                # Resolve variables in params
                resolved_params = _resolve_variables(
                    step.params, scenario.variables, cli_vars, context
                )
                cls = registry_get(step.module)
                log.info("orchestrator.step", index=i, module=step.module, id=step.id)
                result = self.run_module(
                    cls(), params=resolved_params, session_id=session_id
                )
                results.append(result)

                # Store result in context for step chaining
                if step.id:
                    context[step.id] = {
                        "status": result.status.value,
                        "summary": result.summary,
                        "artifacts": result.artifacts,
                        "metrics": result.metrics,
                        "module_name": result.module_name,
                        "protocol": result.protocol,
                    }

                if result.status in {Status.FAIL, Status.REFUSED, Status.ABORTED}:
                    if bail_on_fail:
                        log.warning(
                            "orchestrator.step.bailout",
                            module=step.module,
                            status=result.status.value,
                        )
                        break
                    else:
                        log.warning(
                            "orchestrator.step.continuing",
                            module=step.module,
                            status=result.status.value,
                        )

        try:
            if scenario.options.loop:
                log.info(
                    "orchestrator.loop.start",
                    delay_s=scenario.options.loop_delay_s,
                )
                try:
                    while True:
                        _execute_steps()
                        time.sleep(scenario.options.loop_delay_s)
                        # Reset for next iteration (keep context for chaining)
                except KeyboardInterrupt:
                    log.info("orchestrator.loop.interrupted")
            else:
                _execute_steps()
        finally:
            self.dry_run = original_dry_run

        db.end_session(session_id, notes=f"{len(results)} module(s) ran")
        return results
