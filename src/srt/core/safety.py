"""Safety / authorization layer.

Loads:
  * the authorization metadata embedded in ``docs/legal-scope.md`` (YAML
    block) or, if missing, ``authorization/authorization.yaml``;
  * the operator-managed whitelist of target identifiers
    (``safety/whitelist.yaml``).

Used by the orchestrator to populate ``ModuleContext`` before any module runs.
The kill-switch env var ``SRT_KILLSWITCH=1`` short-circuits to "not authorized".
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml

log = structlog.get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_AUTH_FILES = [
    REPO_ROOT / "authorization" / "authorization.yaml",
    REPO_ROOT / "docs" / "legal-scope.md",
]
DEFAULT_WHITELIST = REPO_ROOT / "safety" / "whitelist.yaml"


@dataclass
class Authorization:
    ok: bool = False
    client: str = ""
    scope: str = ""
    start_date: str = ""
    end_date: str = ""
    signed_by: str = ""
    signed_doc_sha256: str = ""
    authorized_bands_mhz: list[str] = field(default_factory=list)
    authorized_tx_bands_mhz: list[str] = field(default_factory=list)
    shielded_environment: bool = False
    reason: str = ""


def _extract_yaml_block(text: str) -> dict[str, Any] | None:
    """Extract the first ```yaml fenced block from a markdown file."""
    match = re.search(r"```yaml\s*(.+?)```", text, re.DOTALL)
    if not match:
        return None
    try:
        return yaml.safe_load(match.group(1))
    except yaml.YAMLError as exc:  # pragma: no cover - defensive
        log.warning("safety.yaml_parse_error", error=str(exc))
        return None


def load_authorization(path: Path | None = None) -> Authorization:
    """Load and validate the authorization block. Never raises."""
    if os.environ.get("SRT_KILLSWITCH") == "1":
        return Authorization(ok=False, reason="kill-switch active (SRT_KILLSWITCH=1)")

    candidates = [path] if path else DEFAULT_AUTH_FILES
    for candidate in candidates:
        if not candidate or not candidate.exists():
            continue
        try:
            text = candidate.read_text(encoding="utf-8")
        except OSError:
            continue

        if candidate.suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(text) or {}
        else:
            data = _extract_yaml_block(text) or {}

        block = data.get("authorization")
        if not block:
            continue

        # Heuristic: scaffold-default placeholders ("<...>") are not valid auth.
        signed_by = str(block.get("signed_by", ""))
        if not signed_by or signed_by.startswith("<"):
            return Authorization(
                ok=False,
                reason=f"authorization placeholder unfilled in {candidate.name}",
            )
        return Authorization(
            ok=True,
            client=str(block.get("client", "")),
            scope=str(block.get("scope", "")),
            start_date=str(block.get("start_date", "")),
            end_date=str(block.get("end_date", "")),
            signed_by=signed_by,
            signed_doc_sha256=str(block.get("signed_doc_sha256", "")),
            authorized_bands_mhz=list(block.get("authorized_bands_mhz", []) or []),
            authorized_tx_bands_mhz=list(block.get("authorized_tx_bands_mhz", []) or []),
            shielded_environment=bool(block.get("shielded_environment", False)),
        )

    return Authorization(ok=False, reason="no authorization file found")


def load_whitelist(path: Path | None = None) -> dict[str, list[str]]:
    target = path or DEFAULT_WHITELIST
    if not target.exists():
        return {}
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:  # pragma: no cover - defensive
        log.warning("safety.whitelist_parse_error", error=str(exc))
        return {}
    return {k: list(v or []) for k, v in (data.get("whitelist") or {}).items()}


def evaluate() -> tuple[Authorization, dict[str, list[str]]]:
    auth = load_authorization()
    whitelist = load_whitelist()
    log.info(
        "safety.evaluated",
        authorized=auth.ok,
        reason=auth.reason,
        bands=len(auth.authorized_bands_mhz),
        whitelist_kinds=list(whitelist),
    )
    return auth, whitelist
