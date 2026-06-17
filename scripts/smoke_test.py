#!/usr/bin/env python3
"""Integration smoke test for sniffer-rt.

Validates project structure, syntax, and configuration without requiring
external services or hardware. Intended for CI and pre-demo sanity checks.

Usage:
    python scripts/smoke_test.py
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

# Resolve project root
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# Add src to path for import checks
sys.path.insert(0, str(SRC))

results: list[tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    results.append((name, passed, detail))
    status = "PASS" if passed else "FAIL"
    msg = f"  [{status}] {name}"
    if detail:
        msg += f" -- {detail}"
    print(msg)


def test_python_syntax() -> None:
    """Verify all Python source files parse without syntax errors."""
    errors: list[str] = []
    py_files = list(SRC.rglob("*.py"))
    for f in py_files:
        try:
            ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        except SyntaxError as e:
            errors.append(f"{f.relative_to(ROOT)}: {e}")
    check(
        "Python syntax (all src/*.py)",
        len(errors) == 0,
        f"{len(py_files)} files OK" if not errors else "; ".join(errors[:3]),
    )


def test_scenario_yaml() -> None:
    """Verify all scenario YAML files parse correctly."""
    try:
        import yaml
    except ImportError:
        check("Scenario YAML parsing", False, "pyyaml not installed")
        return

    scenario_dir = ROOT / "scenarios"
    if not scenario_dir.exists():
        check("Scenario YAML parsing", False, "scenarios/ directory missing")
        return

    errors: list[str] = []
    yaml_files = list(scenario_dir.glob("*.yaml")) + list(scenario_dir.glob("*.yml"))
    for f in yaml_files:
        try:
            yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            errors.append(f"{f.name}: {e}")
    check(
        "Scenario YAML parsing",
        len(errors) == 0 and len(yaml_files) > 0,
        f"{len(yaml_files)} files OK" if not errors else "; ".join(errors[:3]),
    )


def test_grafana_json() -> None:
    """Verify all Grafana dashboard JSON files are valid JSON."""
    dashboard_dir = ROOT / "infra" / "grafana" / "provisioning" / "dashboards" / "json"
    if not dashboard_dir.exists():
        check("Grafana dashboard JSON", False, "dashboard dir missing")
        return

    errors: list[str] = []
    json_files = list(dashboard_dir.glob("*.json"))
    for f in json_files:
        try:
            json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"{f.name}: {e}")
    check(
        "Grafana dashboard JSON",
        len(errors) == 0 and len(json_files) > 0,
        f"{len(json_files)} files OK" if not errors else "; ".join(errors[:3]),
    )


def test_sql_init_files() -> None:
    """Verify all SQL init files exist and are non-empty."""
    sql_dir = ROOT / "infra" / "timescaledb" / "init"
    expected = [
        "01_schema.sql",
        "02_aggregates.sql",
        "03_retention.sql",
        "04_views.sql",
        "05_correlation.sql",
    ]
    missing: list[str] = []
    empty: list[str] = []
    for name in expected:
        path = sql_dir / name
        if not path.exists():
            missing.append(name)
        elif path.stat().st_size == 0:
            empty.append(name)
    issues = missing + empty
    check(
        "SQL init files",
        len(issues) == 0,
        f"{len(expected)} files OK" if not issues else f"missing={missing}, empty={empty}",
    )


def test_registry_import() -> None:
    """Verify module registry can be imported."""
    try:
        from srt.core.registry import autodiscover  # noqa: F401
        check("Registry import", True, "srt.core.registry importable")
    except ImportError as e:
        check("Registry import", False, str(e))


def test_pyproject_entry_points() -> None:
    """Verify pyproject.toml has all expected entry points."""
    pyproject = ROOT / "pyproject.toml"
    if not pyproject.exists():
        check("pyproject.toml entry points", False, "file missing")
        return
    content = pyproject.read_text(encoding="utf-8")
    has_srt = 'srt = "srt.cli.main:cli"' in content
    check(
        "pyproject.toml entry points",
        has_srt,
        "srt CLI entry point found" if has_srt else "srt entry point missing",
    )


def test_authorization_structure() -> None:
    """Verify authorization.yaml has valid structure."""
    try:
        import yaml
    except ImportError:
        check("authorization.yaml structure", False, "pyyaml not installed")
        return

    auth_path = ROOT / "authorization" / "authorization.yaml"
    if not auth_path.exists():
        check("authorization.yaml structure", False, "file missing")
        return

    data = yaml.safe_load(auth_path.read_text(encoding="utf-8"))
    valid = (
        isinstance(data, dict)
        and "authorization" in data
        and "scope" in data["authorization"]
        and "start_date" in data["authorization"]
    )
    check("authorization.yaml structure", valid)


def test_whitelist_entries() -> None:
    """Verify whitelist.yaml has entries."""
    try:
        import yaml
    except ImportError:
        check("whitelist.yaml entries", False, "pyyaml not installed")
        return

    wl_path = ROOT / "safety" / "whitelist.yaml"
    if not wl_path.exists():
        check("whitelist.yaml entries", False, "file missing")
        return

    data = yaml.safe_load(wl_path.read_text(encoding="utf-8"))
    has_entries = (
        isinstance(data, dict)
        and "whitelist" in data
        and len(data["whitelist"]) > 0
    )
    check(
        "whitelist.yaml entries",
        has_entries,
        f"{len(data.get('whitelist', {}))} categories" if has_entries else "empty",
    )


def test_module_count() -> None:
    """Count total modules expected (should be 22+)."""
    module_dirs = [
        SRC / "srt" / "recon",
        SRC / "srt" / "exploit",
    ]
    py_files: list[Path] = []
    for d in module_dirs:
        if d.exists():
            py_files.extend(
                f for f in d.rglob("*.py")
                if f.name != "__init__.py"
            )
    count = len(py_files)
    check(
        "Module count (22+ expected)",
        count >= 22,
        f"{count} module files found",
    )


def test_template_files() -> None:
    """Verify all template files exist."""
    templates_dir = ROOT / "templates"
    expected = ["report.html", "report.css"]
    missing = [n for n in expected if not (templates_dir / n).exists()]
    check(
        "Template files",
        len(missing) == 0,
        f"{len(expected)} templates OK" if not missing else f"missing: {missing}",
    )


def test_systemd_units() -> None:
    """Verify all systemd units have correct sections."""
    systemd_dir = ROOT / "deploy" / "systemd"
    if not systemd_dir.exists():
        check("systemd units", False, "deploy/systemd/ missing")
        return

    unit_files = list(systemd_dir.glob("*.service"))
    errors: list[str] = []
    required_sections = ["[Unit]", "[Service]", "[Install]"]
    for f in unit_files:
        content = f.read_text(encoding="utf-8")
        for section in required_sections:
            if section not in content:
                errors.append(f"{f.name} missing {section}")
    check(
        "systemd units",
        len(errors) == 0 and len(unit_files) > 0,
        f"{len(unit_files)} units OK" if not errors else "; ".join(errors[:3]),
    )


def main() -> int:
    print("=" * 60)
    print("  sniffer-rt Integration Smoke Test")
    print("=" * 60)
    print()

    test_python_syntax()
    test_scenario_yaml()
    test_grafana_json()
    test_sql_init_files()
    test_registry_import()
    test_pyproject_entry_points()
    test_authorization_structure()
    test_whitelist_entries()
    test_module_count()
    test_template_files()
    test_systemd_units()

    print()
    print("-" * 60)
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"  Summary: {passed}/{total} tests passed")
    print("-" * 60)

    if passed == total:
        print("  All tests PASSED.")
        return 0
    else:
        failed = [name for name, ok, _ in results if not ok]
        print(f"  FAILED: {', '.join(failed)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
