#!/usr/bin/env python3
"""Generate MITRE ATT&CK coverage matrix from registered modules.

Outputs:
  - Markdown table to stdout
  - Navigator layer JSON to reports/mitre_navigator_layer.json

Usage:
    python scripts/generate_mitre_matrix.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure src is importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from srt.core import mitre  # noqa: E402
from srt.core.registry import autodiscover, list_all  # noqa: E402


def main() -> None:
    # Discover all modules
    autodiscover()
    modules = list_all()

    # Build coverage matrix
    coverage = mitre.build_coverage_matrix()

    # Print markdown table
    print("# MITRE ATT&CK Coverage Matrix")
    print()
    print("| Technique ID | Name | Tactic | Covered By |")
    print("|---|---|---|---|")

    for tid in sorted(coverage.keys()):
        info = mitre.TECHNIQUE_DB.get(tid, {})
        name = info.get("name", tid)
        tactic = info.get("tactic", "Unknown")
        covered_by = ", ".join(coverage[tid])
        print(f"| {tid} | {name} | {tactic} | {covered_by} |")

    print()

    # Generate Navigator layer JSON
    output_dir = ROOT / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "mitre_navigator_layer.json"
    mitre.generate_navigator_layer_json(coverage, output_path)

    # Summary
    technique_count = len(coverage)
    module_count = len(modules)
    print(f"Summary: {technique_count} techniques covered by {module_count} modules")
    print(f"Navigator layer written to: {output_path}")


if __name__ == "__main__":
    main()
