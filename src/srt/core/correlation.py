"""Cross-protocol correlation engine for sniffer-rt.

Provides functions to find the same physical device across WiFi, BLE,
and LoRaWAN protocols by matching OUI prefixes, timing proximity,
and signal strength patterns.
"""

from __future__ import annotations

from typing import Any

import structlog

from srt.core import db

log = structlog.get_logger(__name__)


def _oui_match(mac1: str, mac2: str) -> bool:
    """Compare first 8 characters (OUI portion: AA:BB:CC) of two MAC addresses."""
    if not mac1 or not mac2:
        return False
    return mac1[:8].upper() == mac2[:8].upper()


def find_same_device_across_protocols(time_window_s: float = 5.0) -> list[dict[str, Any]]:
    """Query DB for OUI matches across protocols within a time window.

    Returns:
        List of dicts with keys: wifi_mac, ble_mac, lora_devaddr,
        confidence_score, evidence.
    """
    results: list[dict[str, Any]] = []
    try:
        with db.connect() as conn, conn.cursor() as cur:
            # WiFi <-> BLE correlation
            cur.execute(
                """
                SELECT DISTINCT
                    w.src AS wifi_mac,
                    b.src AS ble_mac,
                    w.fields->>'ssid' AS wifi_ssid,
                    b.fields->>'name' AS ble_name,
                    AVG(ABS(EXTRACT(EPOCH FROM w.ts - b.ts))) AS avg_time_delta
                FROM headers w
                JOIN headers b
                    ON SUBSTRING(w.src, 1, 8) = SUBSTRING(b.src, 1, 8)
                    AND ABS(EXTRACT(EPOCH FROM w.ts - b.ts)) < %s
                WHERE w.protocol = 'wifi' AND b.protocol = 'ble'
                GROUP BY w.src, b.src, w.fields->>'ssid', b.fields->>'name'
                """,
                (time_window_s,),
            )
            for row in cur.fetchall():
                wifi_mac, ble_mac, wifi_ssid, ble_name, avg_delta = row
                confidence = max(0.0, 1.0 - (avg_delta / time_window_s))
                results.append({
                    "wifi_mac": wifi_mac,
                    "ble_mac": ble_mac,
                    "lora_devaddr": None,
                    "confidence_score": round(confidence, 3),
                    "evidence": {
                        "match_type": "oui_timing",
                        "avg_time_delta_s": round(avg_delta, 2),
                        "wifi_ssid": wifi_ssid,
                        "ble_name": ble_name,
                    },
                })

            # WiFi/BLE <-> LoRa correlation (by timing only, LoRa uses DevAddr)
            cur.execute(
                """
                SELECT DISTINCT
                    h.src AS mac,
                    h.protocol AS mac_protocol,
                    l.src AS lora_devaddr,
                    AVG(ABS(EXTRACT(EPOCH FROM h.ts - l.ts))) AS avg_time_delta
                FROM headers h
                JOIN headers l
                    ON ABS(EXTRACT(EPOCH FROM h.ts - l.ts)) < %s
                WHERE h.protocol IN ('wifi', 'ble')
                  AND l.protocol = 'lora'
                  AND h.src IS NOT NULL
                  AND l.src IS NOT NULL
                GROUP BY h.src, h.protocol, l.src
                """,
                (time_window_s,),
            )
            for row in cur.fetchall():
                mac, mac_protocol, lora_devaddr, avg_delta = row
                confidence = max(0.0, 0.6 - (avg_delta / time_window_s) * 0.6)
                entry: dict[str, Any] = {
                    "wifi_mac": mac if mac_protocol == "wifi" else None,
                    "ble_mac": mac if mac_protocol == "ble" else None,
                    "lora_devaddr": lora_devaddr,
                    "confidence_score": round(confidence, 3),
                    "evidence": {
                        "match_type": "timing_only",
                        "avg_time_delta_s": round(avg_delta, 2),
                    },
                }
                results.append(entry)

    except Exception as exc:
        log.warning("correlation.find_same_device.failed", error=str(exc))

    return results


def build_device_graph() -> dict[str, Any]:
    """Create adjacency list of device relationships.

    Relationships are based on: same OUI, same timing window, co-location.

    Returns:
        {nodes: [{id, protocol, mac, name}],
         edges: [{source, target, relationship, confidence}]}
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()

    try:
        with db.connect() as conn, conn.cursor() as cur:
            # Get all unique devices
            cur.execute(
                """
                SELECT DISTINCT protocol, src,
                       fields->>'ssid' AS ssid,
                       fields->>'name' AS name
                FROM headers
                WHERE src IS NOT NULL
                """
            )
            for row in cur.fetchall():
                protocol, src, ssid, name = row
                node_id = f"{protocol}:{src}"
                if node_id not in seen_nodes:
                    seen_nodes.add(node_id)
                    nodes.append({
                        "id": node_id,
                        "protocol": protocol,
                        "mac": src,
                        "name": name or ssid or src,
                    })

            # Find OUI-based edges
            cur.execute(
                """
                SELECT DISTINCT a.protocol, a.src, b.protocol, b.src
                FROM headers a
                JOIN headers b
                    ON SUBSTRING(a.src, 1, 8) = SUBSTRING(b.src, 1, 8)
                    AND a.protocol < b.protocol
                WHERE a.src IS NOT NULL AND b.src IS NOT NULL
                """
            )
            for row in cur.fetchall():
                proto_a, src_a, proto_b, src_b = row
                edges.append({
                    "source": f"{proto_a}:{src_a}",
                    "target": f"{proto_b}:{src_b}",
                    "relationship": "same_oui",
                    "confidence": 0.8,
                })

            # Find timing-based edges
            cur.execute(
                """
                SELECT DISTINCT a.protocol, a.src, b.protocol, b.src,
                       AVG(ABS(EXTRACT(EPOCH FROM a.ts - b.ts))) AS avg_delta
                FROM headers a
                JOIN headers b
                    ON ABS(EXTRACT(EPOCH FROM a.ts - b.ts)) < 5
                    AND a.protocol <> b.protocol
                    AND a.protocol < b.protocol
                WHERE a.src IS NOT NULL AND b.src IS NOT NULL
                GROUP BY a.protocol, a.src, b.protocol, b.src
                HAVING AVG(ABS(EXTRACT(EPOCH FROM a.ts - b.ts))) < 2
                """
            )
            for row in cur.fetchall():
                proto_a, src_a, proto_b, src_b, avg_delta = row
                edge_key = (f"{proto_a}:{src_a}", f"{proto_b}:{src_b}")
                # Only add if not already present as OUI edge
                existing = {(e["source"], e["target"]) for e in edges}
                if edge_key not in existing:
                    edges.append({
                        "source": edge_key[0],
                        "target": edge_key[1],
                        "relationship": "timing_correlation",
                        "confidence": round(max(0.0, 1.0 - avg_delta / 5.0), 2),
                    })

    except Exception as exc:
        log.warning("correlation.build_device_graph.failed", error=str(exc))

    return {"nodes": nodes, "edges": edges}


def generate_correlation_report(session_id: str) -> dict[str, Any]:
    """Run all correlation queries for a session and produce a structured report.

    Args:
        session_id: UUID string of the session to analyze.

    Returns:
        Structured report with cross-protocol findings.
    """
    report: dict[str, Any] = {
        "session_id": session_id,
        "cross_protocol_devices": [],
        "device_graph": {"nodes": [], "edges": []},
        "summary": {
            "total_correlated_devices": 0,
            "protocols_observed": [],
            "high_confidence_matches": 0,
        },
    }

    try:
        # Get cross-protocol matches
        devices = find_same_device_across_protocols(time_window_s=5.0)
        report["cross_protocol_devices"] = devices
        report["summary"]["total_correlated_devices"] = len(devices)
        report["summary"]["high_confidence_matches"] = sum(
            1 for d in devices if d["confidence_score"] > 0.7
        )

        # Build device graph
        graph = build_device_graph()
        report["device_graph"] = graph

        # Get protocol list from session
        with db.connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT protocol FROM headers WHERE session_id = %s",
                (session_id,),
            )
            report["summary"]["protocols_observed"] = [
                row[0] for row in cur.fetchall()
            ]

    except Exception as exc:
        log.warning("correlation.generate_report.failed", error=str(exc))

    return report
