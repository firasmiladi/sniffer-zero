"""Render scenario / module results into JSON, Markdown, and PDF reports.

PDF rendering requires the optional ``[report]`` extras:
    pip install ".[report]"

which provides ``weasyprint`` and ``jinja2``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from srt.core.module import AttackResult

log = structlog.get_logger(__name__)

REPORT_DIR = Path("reports/out")
TEMPLATE_DIR = Path("templates")


def _ensure_dir() -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    return REPORT_DIR


def write_json(results: Iterable[AttackResult], name: str) -> Path:
    out = _ensure_dir() / f"{_stamp()}-{name}.json"
    payload = [_serialize(r) for r in results]
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return out


def write_markdown(results: list[AttackResult], name: str) -> Path:
    out = _ensure_dir() / f"{_stamp()}-{name}.md"
    out.write_text(_render_md(name, results), encoding="utf-8")
    return out


def write_pdf(
    results: list[AttackResult],
    name: str,
    session_meta: dict[str, Any] | None = None,
) -> Path | None:
    """Generate a PDF report using Jinja2 + WeasyPrint.

    Args:
        results: list of AttackResult from the scenario run.
        name: report name (used in filename).
        session_meta: optional dict with operator, scenario, session_id, etc.

    Returns:
        Path to generated PDF, or None if weasyprint is unavailable.
    """
    try:
        from jinja2 import Environment, FileSystemLoader
    except ImportError:
        log.warning("reporter.pdf.jinja2_missing", hint="pip install jinja2")
        return None

    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except ImportError:
        log.warning(
            "reporter.pdf.weasyprint_missing",
            hint='pip install ".[report]" for PDF support',
        )
        return None

    mitre_map = build_mitre_map(results)
    generated_at = datetime.now(timezone.utc).isoformat()

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html")
    html = template.render(
        results=results,
        session_meta=session_meta or {},
        mitre_map=mitre_map,
        generated_at=generated_at,
        name=name,
    )

    output_path = _ensure_dir() / f"{_stamp()}-{name}.pdf"
    HTML(string=html).write_pdf(str(output_path))
    log.info("reporter.pdf.written", path=str(output_path))
    return output_path


# --------------------------------------------------------------------------- #
# MITRE ATT&CK aggregation                                                   #
# --------------------------------------------------------------------------- #


def build_mitre_map(results: list[AttackResult]) -> dict[str, list[str]]:
    """Aggregate MITRE TTP IDs from results into {technique_id: [module_names]}.

    Args:
        results: list of AttackResult objects.

    Returns:
        Dict mapping technique IDs to lists of module names that tested them.
    """
    mitre_map: dict[str, list[str]] = {}
    for r in results:
        for ttp in r.mitre_ttp:
            mitre_map.setdefault(ttp, []).append(r.module_name)
    return mitre_map


def generate_mitre_navigator_layer(results: list[AttackResult], name: str) -> Path:
    """Write an ATT&CK Navigator JSON layer file from results.

    Args:
        results: list of AttackResult objects.
        name: layer name used in filename.

    Returns:
        Path to the generated Navigator layer JSON file.
    """
    mitre_map = build_mitre_map(results)
    techniques: list[dict[str, Any]] = []
    for tid, modules in mitre_map.items():
        techniques.append({
            "techniqueID": tid,
            "score": len(modules),
            "color": _navigator_color(len(modules)),
            "comment": f"Tested by: {', '.join(modules)}",
        })

    layer = {
        "version": "4.5",
        "name": f"sniffer-rt - {name}",
        "domain": "enterprise-attack",
        "description": f"ATT&CK coverage from session: {name}",
        "techniques": techniques,
    }

    output_path = _ensure_dir() / f"{_stamp()}-{name}-navigator.json"
    output_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    log.info("reporter.navigator_layer.written", path=str(output_path))
    return output_path


# --------------------------------------------------------------------------- #
# helpers                                                                     #
# --------------------------------------------------------------------------- #

def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _serialize(result: AttackResult) -> dict:
    data = asdict(result)
    data["risk"] = result.risk.value
    data["status"] = result.status.value
    return data


def _navigator_color(score: int) -> str:
    """Color for Navigator layer based on coverage count."""
    if score >= 3:
        return "#31a354"
    if score >= 2:
        return "#addd8e"
    return "#f7fcb1"


def _render_md(name: str, results: list[AttackResult]) -> str:
    lines: list[str] = []
    lines.append(f"# {name}")
    lines.append("")
    lines.append(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")

    # Simple summary table
    lines.append("| Module | Status | Résumé |")
    lines.append("|--------|--------|--------|")
    for r in results:
        lines.append(f"| {r.module_name} | {r.status.value} | {r.summary} |")
    lines.append("")

    # Details per module - SIMPLE
    for r in results:
        lines.append(f"---")
        lines.append(f"## {r.module_name}")
        lines.append("")
        lines.append(f"**Status:** {r.status.value}  ")
        lines.append(f"**Durée:** {r.duration_s:.1f}s  ")
        if r.mitre_ttp:
            lines.append(f"**MITRE:** {', '.join(r.mitre_ttp)}  ")
        if r.cve:
            lines.append(f"**CVE:** {', '.join(r.cve)}  ")
        lines.append("")
        lines.append(r.summary)
        lines.append("")

        # Artifacts rendered as readable tables
        for a in r.artifacts:
            atype = a.get("type", "")
            data = a.get("data")
            if not data:
                continue

            if atype == "ap_list" and isinstance(data, list):
                lines.append("### APs détectés")
                lines.append("| BSSID | SSID | Channel | Encryption |")
                lines.append("|-------|------|---------|-----------|")
                for ap in data:
                    lines.append(
                        f"| {ap.get('bssid','')} | {ap.get('ssid','')} "
                        f"| {ap.get('channel','')} | {ap.get('encryption','')} |"
                    )
                lines.append("")

            elif atype == "ap_security_reports" and isinstance(data, list):
                lines.append("### Évaluation sécurité")
                lines.append("| SSID | Encryption | Grade | Problèmes |")
                lines.append("|------|-----------|-------|-----------|")
                for ap in data:
                    issues = ", ".join(ap.get("issues", [])) or "—"
                    lines.append(
                        f"| {ap.get('ssid','')} | {ap.get('encryption','')} "
                        f"| {ap.get('grade','')} | {issues} |"
                    )
                lines.append("")

            elif atype == "distance_estimates" and isinstance(data, list):
                lines.append("### Distances estimées")
                lines.append("| Source | RSSI moyen | Distance | Samples |")
                lines.append("|--------|-----------|----------|---------|")
                for d in data:
                    lines.append(
                        f"| {d.get('source','')} | {d.get('avg_rssi','')} dBm "
                        f"| {d.get('estimated_distance_m','')} m | {d.get('samples','')} |"
                    )
                lines.append("")

            elif atype == "device_fingerprints" and isinstance(data, dict):
                lines.append("### Devices identifiés")
                lines.append("| MAC | Type | Fingerprint | Random |")
                lines.append("|-----|------|------------|--------|")
                for mac, info in data.items():
                    lines.append(
                        f"| {mac} | {info.get('device_type','')} "
                        f"| {info.get('fingerprint','')} | {info.get('is_random_mac','')} |"
                    )
                lines.append("")

            elif atype == "pnl_map" and isinstance(data, dict):
                lines.append("### PNL (réseaux cherchés par les devices)")
                for mac, ssids in data.items():
                    lines.append(f"- {mac}: {', '.join(ssids)}")
                lines.append("")

            elif atype == "frame_type_stats" and isinstance(data, dict):
                lines.append("### Types de frames")
                lines.append("| Type | Count |")
                lines.append("|------|-------|")
                for ftype, count in data.items():
                    lines.append(f"| {ftype} | {count} |")
                lines.append("")

            elif atype == "beacon_jitter_analysis" and isinstance(data, list):
                if data:
                    lines.append("### Analyse jitter beacons")
                    lines.append("| BSSID | Interval moy | Jitter ratio | Alerte |")
                    lines.append("|-------|-------------|-------------|--------|")
                    for b in data:
                        alert = b.get("alert", "—")
                        lines.append(
                            f"| {b.get('bssid','')} | {b.get('avg_interval_ms',0):.0f} ms "
                            f"| {b.get('jitter_ratio',0):.3f} | {alert} |"
                        )
                    lines.append("")

            elif atype == "probe_timing_profiles" and isinstance(data, list):
                if data:
                    lines.append("### Profils timing probes")
                    lines.append("| Client | Probes | Interval moy | Durée |")
                    lines.append("|--------|--------|-------------|-------|")
                    for p in data:
                        lines.append(
                            f"| {p.get('client_mac','')} | {p.get('probe_count','')} "
                            f"| {p.get('avg_interval_s',0):.2f}s | {p.get('duration_s',0):.1f}s |"
                        )
                    lines.append("")

            elif atype == "grade_distribution" and isinstance(data, dict):
                grades = " / ".join(f"{k}={v}" for k, v in data.items() if v > 0)
                if grades:
                    lines.append(f"**Grades:** {grades}")
                    lines.append("")

            elif atype == "channel_congestion" and isinstance(data, dict):
                lines.append("### Congestion canaux")
                lines.append("| Canal | Frames | % |")
                lines.append("|-------|--------|---|")
                for ch, info in data.items():
                    lines.append(
                        f"| {ch} | {info.get('frame_count','')} | {info.get('percentage','')}% |"
                    )
                lines.append("")

    lines.append("")
    return "\n".join(lines)
