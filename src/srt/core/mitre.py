"""MITRE ATT&CK utilities for sniffer-rt.

Provides technique database, coverage matrix from registered modules,
ATT&CK Navigator layer JSON export, and mitigation recommendations.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)


# --------------------------------------------------------------------------- #
# Technique database                                                          #
# --------------------------------------------------------------------------- #

TECHNIQUE_DB: dict[str, dict[str, str]] = {
    "T1040": {
        "name": "Network Sniffing",
        "tactic": "Collection",
        "description": (
            "Adversaries may sniff network traffic to capture information about an environment."
        ),
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
    },
    "T1110.002": {
        "name": "Password Cracking",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use password cracking to attempt to recover usable credentials."
        ),
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": (
            "Adversaries may perform denial of service attacks to degrade or block availability."
        ),
    },
    "T1499.004": {
        "name": "Application or System Exploitation",
        "tactic": "Impact",
        "description": (
            "Adversaries may exploit software vulnerabilities to cause denial of service."
        ),
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to position themselves between two or more"
            " networked devices."
        ),
    },
    "T1565": {
        "name": "Data Manipulation",
        "tactic": "Impact",
        "description": "Adversaries may insert, delete, or manipulate data to influence outcomes.",
    },
    "T1565.002": {
        "name": "Transmitted Data Manipulation",
        "tactic": "Impact",
        "description": "Adversaries may alter data en route to storage or other systems.",
    },
    "T1592": {
        "name": "Gather Victim Network Information",
        "tactic": "Reconnaissance",
        "description": "Adversaries may gather information about the victim's networks.",
    },
}

# --------------------------------------------------------------------------- #
# Mitigation recommendations per technique                                    #
# --------------------------------------------------------------------------- #

_RECOMMENDATIONS: dict[str, str] = {
    "T1040": (
        "Use encrypted protocols (WPA3, TLS); segment networks;"
        " monitor for promiscuous-mode NICs."
    ),
    "T1110": "Enforce account lockout policies; use multi-factor authentication; use WPA3-SAE.",
    "T1110.002": "Use WPA3-SAE + 12+ character passphrase; avoid dictionary words; rotate keys.",
    "T1499": "Enable 802.11w Protected Management Frames (PMF); deploy wireless IDS.",
    "T1499.004": "Enable 802.11w PMF; apply vendor patches; deploy rate-limiting.",
    "T1557": "Enable mutual authentication; use WPA3; deploy WIDS for rogue AP detection.",
    "T1565": "Implement integrity verification (MIC checks); use authenticated encryption.",
    "T1565.002": "Use end-to-end encryption; enable LoRaWAN frame counters; deploy MIC validation.",
    "T1592": (
        "Minimize broadcast traffic; use MAC randomization;"
        " hide SSIDs in sensitive deployments."
    ),
}


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #


def build_coverage_matrix() -> dict[str, list[str]]:
    """Map technique IDs to module names that test them.

    Returns:
        {technique_id: [module_name, ...]}
    """
    from srt.core.registry import list_all

    coverage: dict[str, list[str]] = {}
    for cls in list_all():
        for ttp in cls.mitre_ttp:
            coverage.setdefault(ttp, []).append(cls.name)
    return coverage


def generate_navigator_layer_json(
    coverage: dict[str, list[str]], output_path: Path
) -> Path:
    """Create an ATT&CK Navigator-compatible JSON layer file.

    Args:
        coverage: mapping of technique_id -> list of module names.
        output_path: file path for the output JSON.

    Returns:
        The resolved output path.
    """
    techniques: list[dict[str, Any]] = []
    for tid, modules in coverage.items():
        info = TECHNIQUE_DB.get(tid, {})
        techniques.append({
            "techniqueID": tid,
            "score": len(modules),
            "color": _score_color(len(modules)),
            "comment": f"Tested by: {', '.join(modules)}",
            "tactic": info.get("tactic", ""),
        })

    layer = {
        "version": "4.5",
        "name": "sniffer-rt Coverage",
        "domain": "enterprise-attack",
        "description": "ATT&CK techniques tested by sniffer-rt modules",
        "techniques": techniques,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    log.info("mitre.navigator_layer.written", path=str(output_path))
    return output_path


def build_recommendations(tested_techniques: list[str]) -> list[dict[str, str]]:
    """Generate mitigation recommendations for tested techniques.

    Args:
        tested_techniques: list of technique IDs that were tested.

    Returns:
        List of dicts with keys: technique_id, name, tactic, recommendation.
    """
    recs: list[dict[str, str]] = []
    for tid in tested_techniques:
        info = TECHNIQUE_DB.get(tid, {})
        recommendation = _RECOMMENDATIONS.get(tid, "Refer to MITRE ATT&CK for mitigations.")
        recs.append({
            "technique_id": tid,
            "name": info.get("name", tid),
            "tactic": info.get("tactic", "Unknown"),
            "recommendation": recommendation,
        })
    return recs


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _score_color(score: int) -> str:
    """Return a color hex for Navigator layer based on coverage score."""
    if score >= 3:
        return "#31a354"  # green - well covered
    if score >= 2:
        return "#addd8e"  # light green
    return "#f7fcb1"      # yellow - minimal coverage
