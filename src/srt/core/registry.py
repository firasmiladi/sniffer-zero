"""Lightweight module registry.

Modules are registered via the ``@register`` decorator and looked up by their
canonical name (``"wifi.deauth"``, ``"lora.recon"``, ...). The registry keeps a
single source of truth so the CLI, orchestrator and reporter can introspect
metadata without importing every module by hand.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterable

import structlog

from srt.core.module import AttackModule

log = structlog.get_logger(__name__)

_MODULES: dict[str, type[AttackModule]] = {}


def register(cls: type[AttackModule]) -> type[AttackModule]:
    if not cls.name:
        raise ValueError(f"{cls.__name__} must define `name`")
    if cls.name in _MODULES:
        raise ValueError(f"duplicate module name: {cls.name}")
    _MODULES[cls.name] = cls
    return cls


def get(name: str) -> type[AttackModule]:
    return _MODULES[name]


def get_all() -> list[type[AttackModule]]:
    """Return all registered modules sorted by name."""
    return sorted(_MODULES.values(), key=lambda c: c.name)


# Backward-compatible alias
list_all = get_all


def autodiscover(packages: Iterable[str] = ("srt.recon", "srt.exploit", "srt.analysis")) -> None:
    """Import every submodule under the given packages so decorators run."""
    for pkg_name in packages:
        try:
            pkg = importlib.import_module(pkg_name)
        except ModuleNotFoundError:
            continue
        if not hasattr(pkg, "__path__"):
            continue
        for mod in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
            try:
                importlib.import_module(mod.name)
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("registry.import_failed", module=mod.name, error=str(exc))
