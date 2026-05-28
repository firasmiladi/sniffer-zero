"""WiFi security assessment engine.

Grades each AP from A to F based on encryption strength, PMF support,
WPS status, and cipher configuration. Detects misconfigurations and
identifies downgrade attack surfaces.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)

# Security grading criteria:
# A = WPA3 (SAE) + PMF required
# B = WPA2-CCMP + PMF capable
# C = WPA2-CCMP, no PMF
# D = WPA2-TKIP (or mixed TKIP/CCMP)
# E = WPA or WEP
# F = OPEN (no encryption)

GRADE_DESCRIPTIONS: dict[str, str] = {
    "A": "WPA3/SAE with mandatory PMF - excellent security",
    "B": "WPA2-CCMP with PMF capable - good security",
    "C": "WPA2-CCMP without PMF - acceptable but upgradeable",
    "D": "WPA2 with TKIP - weak, upgrade recommended",
    "E": "Legacy WPA/WEP - critically weak, must upgrade",
    "F": "OPEN network - no encryption",
}


def _grade_ap(encryption: str, pmf_capable: bool, pmf_required: bool,
              wps_enabled: bool, ciphers: list[str], akms: list[str]) -> dict[str, Any]:
    """Grade an AP and return assessment details."""
    grade = "F"
    issues: list[str] = []

    if encryption == "OPEN" or not encryption:
        grade = "F"
        issues.append("No encryption - all traffic visible")
    elif encryption in ("WEP", "WPA"):
        grade = "E"
        issues.append(f"{encryption} is cryptographically broken")
    elif encryption in ("WPA2", "WPA2/WPA3"):
        has_tkip = "TKIP" in ciphers
        has_ccmp = any(c in ciphers for c in ["CCMP-128", "CCMP-256", "GCMP-128", "GCMP-256"])
        has_sae = "SAE" in akms

        if has_sae and pmf_required:
            grade = "A"
        elif has_sae or (has_ccmp and pmf_required):
            grade = "A"
        elif has_ccmp and pmf_capable:
            grade = "B"
        elif has_ccmp and not pmf_capable:
            grade = "C"
            issues.append("PMF not supported - vulnerable to deauth attacks")
        elif has_tkip:
            grade = "D"
            issues.append("TKIP cipher is deprecated and weak")
        else:
            grade = "C"
    elif encryption == "WPA3":
        if pmf_required:
            grade = "A"
        else:
            grade = "A"
            issues.append("WPA3 should enforce PMF")

    # Additional checks
    if wps_enabled:
        issues.append("WPS enabled - vulnerable to Pixie Dust/brute-force")
        if grade in ("A", "B"):
            grade = "C"  # Downgrade for WPS

    if "TKIP" in ciphers and any(c for c in ciphers if c != "TKIP"):
        issues.append("TKIP fallback enabled - allows cipher downgrade")

    if not pmf_capable and grade in ("A", "B"):
        grade = "C"

    return {
        "grade": grade,
        "grade_description": GRADE_DESCRIPTIONS.get(grade, ""),
        "encryption": encryption,
        "pmf_capable": pmf_capable,
        "pmf_required": pmf_required,
        "wps_enabled": wps_enabled,
        "ciphers": ciphers,
        "akms": akms,
        "issues": issues,
    }


@register
class WiFiSecurityAssessor(AttackModule):
    """WiFi AP security grading engine.

    Grades access points A-F based on encryption, PMF, WPS, and cipher
    strength. Detects WPS misconfigurations, no PMF, TKIP fallback, weak
    ciphers, and generates per-AP security report cards.
    """

    name = "wifi.security_assessor"
    protocol = "wifi"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1592.002", "T1590"]
    requires = []
    description = (
        "Grade WiFi APs A-F: assess encryption, PMF, WPS, cipher strength, "
        "detect misconfigurations and downgrade attack surfaces."
    )

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary="[DRY-RUN] wifi.security_assessor would grade APs",
            )

        ap_reports: list[dict[str, Any]] = []

        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT ON (src) src, fields
                    FROM headers
                    WHERE session_id = %s AND protocol = 'wifi'
                      AND fields->>'frame_type' = 'beacon'
                    ORDER BY src, ts DESC
                    """,
                    (str(ctx.session_id),),
                )
                for row in cur.fetchall():
                    bssid, fields = row
                    if isinstance(fields, str):
                        import json
                        try:
                            fields = json.loads(fields)
                        except (ValueError, TypeError):
                            fields = {}
                    if not isinstance(fields, dict):
                        fields = {}

                    encryption = fields.get("encryption", "OPEN")
                    pmf_capable = fields.get("pmf_capable", False)
                    pmf_required = fields.get("pmf_required", False)
                    wps_enabled = fields.get("wps_enabled", False)
                    ciphers = fields.get("ciphers", [])
                    akms = fields.get("akms", [])
                    ssid = fields.get("ssid", "")

                    assessment = _grade_ap(
                        encryption, pmf_capable, pmf_required,
                        wps_enabled, ciphers, akms,
                    )
                    assessment["bssid"] = bssid
                    assessment["ssid"] = ssid
                    ap_reports.append(assessment)

        except Exception as exc:
            log.warning("wifi.security_assessor.db_error", error=str(exc))
            return self._result(
                Status.FAIL, started, summary=f"DB query error: {exc}"
            )

        # Grade distribution
        grade_dist: dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0, "F": 0}
        for report in ap_reports:
            g = report.get("grade", "F")
            grade_dist[g] = grade_dist.get(g, 0) + 1

        total_issues = sum(len(r.get("issues", [])) for r in ap_reports)

        summary = (
            f"Assessed {len(ap_reports)} APs: "
            f"A={grade_dist['A']} B={grade_dist['B']} C={grade_dist['C']} "
            f"D={grade_dist['D']} E={grade_dist['E']} F={grade_dist['F']}, "
            f"{total_issues} total issues found"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "ap_security_reports", "data": ap_reports},
                {"type": "grade_distribution", "data": grade_dist},
            ],
            metrics={
                "ap_count": len(ap_reports),
                "grade_distribution": grade_dist,
                "total_issues": total_issues,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
