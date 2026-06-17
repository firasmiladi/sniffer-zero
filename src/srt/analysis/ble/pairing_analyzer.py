"""BLE pairing method analysis engine.

Detects pairing methods from IO capabilities, identifies Just Works and
passkey weaknesses, checks BLE version for legacy pairing vulnerabilities
(crackle), assesses pairing entropy and estimates crack time.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)

# BLE Pairing methods and their security properties
PAIRING_METHODS: dict[str, dict[str, Any]] = {
    "just_works": {
        "name": "Just Works",
        "mitm_protected": False,
        "entropy_bits": 0,
        "description": "No user interaction, no MITM protection",
        "risk": "critical",
    },
    "passkey_entry": {
        "name": "Passkey Entry",
        "mitm_protected": True,
        "entropy_bits": 20,  # 6-digit passkey = ~20 bits
        "description": "6-digit passkey, brute-forceable in practice",
        "risk": "medium",
    },
    "numeric_comparison": {
        "name": "Numeric Comparison",
        "mitm_protected": True,
        "entropy_bits": 20,
        "description": "6-digit display comparison, good MITM protection",
        "risk": "low",
    },
    "oob": {
        "name": "Out of Band",
        "mitm_protected": True,
        "entropy_bits": 128,
        "description": "External channel (NFC, etc.), strong security",
        "risk": "low",
    },
}

# IO Capability to pairing method mapping
# Initiator IO -> Responder IO -> Method
IO_CAPABILITIES: dict[str, str] = {
    "no_input_no_output": "DisplayOnly",
    "display_only": "DisplayOnly",
    "display_yes_no": "DisplayYesNo",
    "keyboard_only": "KeyboardOnly",
    "keyboard_display": "KeyboardDisplay",
}

# BLE version vulnerability info
BLE_VERSION_RISKS: dict[str, dict[str, Any]] = {
    "4.0": {"crackle_vulnerable": True, "legacy_pairing": True, "sc_support": False},
    "4.1": {"crackle_vulnerable": True, "legacy_pairing": True, "sc_support": False},
    "4.2": {"crackle_vulnerable": False, "legacy_pairing": True, "sc_support": True},
    "5.0": {"crackle_vulnerable": False, "legacy_pairing": True, "sc_support": True},
    "5.1": {"crackle_vulnerable": False, "legacy_pairing": True, "sc_support": True},
    "5.2": {"crackle_vulnerable": False, "legacy_pairing": True, "sc_support": True},
    "5.3": {"crackle_vulnerable": False, "legacy_pairing": True, "sc_support": True},
}


def _determine_pairing_method(
    initiator_io: str, responder_io: str
) -> str:
    """Determine pairing method from IO capabilities of both devices."""
    # Simplified SMP pairing method selection logic
    no_io = {"no_input_no_output", "display_only"}

    if initiator_io in no_io and responder_io in no_io:
        return "just_works"
    if "keyboard" in initiator_io or "keyboard" in responder_io:
        if "display" in initiator_io or "display" in responder_io:
            return "passkey_entry"
        return "passkey_entry"
    if "display_yes_no" in (initiator_io, responder_io):
        return "numeric_comparison"
    return "just_works"


def _estimate_crack_time(method: str, ble_version: str) -> dict[str, Any]:
    """Estimate time to crack pairing based on method and version."""
    if method == "just_works":
        return {
            "method": "passive_eavesdrop",
            "time_seconds": 0,
            "description": "No key exchange protection, instant compromise",
        }
    elif method == "passkey_entry":
        # 6-digit passkey: 1M possibilities, ~1000 guesses/sec over-the-air
        return {
            "method": "brute_force_passkey",
            "time_seconds": 1000,
            "keyspace": 1_000_000,
            "description": "6-digit passkey brute-force (~17 minutes at 1K/s)",
        }
    elif method == "numeric_comparison":
        return {
            "method": "none_practical",
            "time_seconds": -1,
            "description": "Requires active MITM during pairing ceremony",
        }

    # Legacy pairing with crackle
    version_info = BLE_VERSION_RISKS.get(ble_version, {})
    if version_info.get("crackle_vulnerable"):
        return {
            "method": "crackle_attack",
            "time_seconds": 1,
            "description": "crackle tool recovers STK from captured pairing (BLE <= 4.1)",
        }

    return {
        "method": "unknown",
        "time_seconds": -1,
        "description": "No known practical attack",
    }


@register
class BlePairingAnalyzer(AttackModule):
    """BLE pairing method analysis and vulnerability assessment.

    Detects pairing methods from IO capabilities, identifies Just Works/
    passkey weaknesses, checks BLE version for legacy pairing vulnerabilities
    (crackle), and estimates crack time.
    """

    name = "ble.pairing_analyzer"
    protocol = "ble"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1557", "T1040"]
    requires = []
    description = (
        "BLE pairing analysis: detect method from IO capabilities, identify "
        "Just Works/passkey weaknesses, check for crackle vulnerability."
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
                summary="[DRY-RUN] ble.pairing_analyzer would analyze pairing methods",
            )

        device_analyses: list[dict[str, Any]] = []

        try:
            with db.connect() as conn, conn.cursor() as cur:
                # Query BLE device data from headers
                cur.execute(
                    """
                    SELECT DISTINCT ON (src) src, fields
                    FROM headers
                    WHERE session_id = %s AND protocol = 'ble'
                    ORDER BY src, ts DESC
                    """,
                    (str(ctx.session_id),),
                )
                for row in cur.fetchall():
                    device_mac, fields = row
                    if isinstance(fields, str):
                        import json
                        try:
                            fields = json.loads(fields)
                        except (ValueError, TypeError):
                            fields = {}
                    if not isinstance(fields, dict):
                        fields = {}

                    ble_version = fields.get("ble_version", "4.0")
                    io_capability = fields.get("io_capability", "no_input_no_output")
                    sc_supported = fields.get("secure_connections", False)

                    # Determine likely pairing method
                    pairing_method = _determine_pairing_method(
                        io_capability, "no_input_no_output"  # assume minimal responder
                    )
                    method_info = PAIRING_METHODS.get(pairing_method, PAIRING_METHODS["just_works"])
                    version_risks = BLE_VERSION_RISKS.get(ble_version, BLE_VERSION_RISKS["4.0"])
                    crack_estimate = _estimate_crack_time(pairing_method, ble_version)

                    issues: list[str] = []
                    if not method_info["mitm_protected"]:
                        issues.append("No MITM protection (Just Works pairing)")
                    if version_risks.get("crackle_vulnerable"):
                        issues.append(f"BLE {ble_version} vulnerable to crackle attack")
                    if not sc_supported and not version_risks.get("sc_support"):
                        issues.append("Secure Connections not supported")
                    if pairing_method == "passkey_entry":
                        issues.append("Passkey entry brute-forceable (20-bit entropy)")

                    device_analyses.append({
                        "device_mac": device_mac,
                        "ble_version": ble_version,
                        "io_capability": io_capability,
                        "pairing_method": method_info["name"],
                        "mitm_protected": method_info["mitm_protected"],
                        "entropy_bits": method_info["entropy_bits"],
                        "secure_connections": sc_supported,
                        "crackle_vulnerable": version_risks.get("crackle_vulnerable", False),
                        "crack_estimate": crack_estimate,
                        "risk_level": method_info["risk"],
                        "issues": issues,
                    })

        except Exception as exc:
            log.warning("ble.pairing_analyzer.db_error", error=str(exc))
            return self._result(
                Status.FAIL, started, summary=f"DB query error: {exc}"
            )

        # Risk distribution
        risk_dist: dict[str, int] = {"critical": 0, "medium": 0, "low": 0}
        for analysis in device_analyses:
            risk = analysis.get("risk_level", "critical")
            risk_dist[risk] = risk_dist.get(risk, 0) + 1

        crackle_count = sum(1 for a in device_analyses if a.get("crackle_vulnerable"))

        summary = (
            f"Pairing analysis: {len(device_analyses)} devices, "
            f"critical={risk_dist['critical']} medium={risk_dist['medium']} "
            f"low={risk_dist['low']}, {crackle_count} crackle-vulnerable"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "pairing_analyses", "data": device_analyses},
                {"type": "risk_distribution", "data": risk_dist},
            ],
            metrics={
                "devices_analyzed": len(device_analyses),
                "risk_distribution": risk_dist,
                "crackle_vulnerable": crackle_count,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
