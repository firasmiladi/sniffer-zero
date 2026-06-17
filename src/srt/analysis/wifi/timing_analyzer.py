"""WiFi timing analysis engine.

Beacon interval measurement and jitter detection (rogue AP indicator),
deauth flood detection, client probe timing profiling. Reads from
the DB headers table for the current session.
"""

from __future__ import annotations

import bisect
import time
from typing import Any

import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)

# Rogue AP threshold: if actual beacon interval deviates >5% from declared
BEACON_JITTER_THRESHOLD = 0.05

# Deauth flood: more than this many deauths per BSSID in a time window
DEAUTH_FLOOD_THRESHOLD = 10
DEAUTH_WINDOW_SECONDS = 5.0


@register
class WiFiTimingAnalyzer(AttackModule):
    """Beacon timing jitter analysis and deauth flood detection.

    Reads captured frame data from the DB headers table for the current
    session and analyzes timing patterns to detect rogue APs and
    denial-of-service attacks.
    """

    name = "wifi.timing_analyzer"
    protocol = "wifi"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1557.004", "T1498"]
    requires = []
    description = (
        "Beacon interval jitter analysis (rogue AP detection), deauth flood "
        "detection, and client probe timing profiling from session data."
    )

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def _analyze_beacon_jitter(
        self, beacons: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Detect beacon interval anomalies per BSSID."""
        # Group beacons by BSSID
        bssid_beacons: dict[str, list[float]] = {}
        for b in beacons:
            bssid = b.get("src", "")
            ts = b.get("ts")
            if bssid and ts is not None:
                bssid_beacons.setdefault(bssid, []).append(float(ts))

        anomalies: list[dict[str, Any]] = []
        for bssid, timestamps in bssid_beacons.items():
            if len(timestamps) < 3:
                continue
            timestamps.sort()
            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]
            if not intervals:
                continue

            avg_interval = sum(intervals) / len(intervals)
            if avg_interval == 0:
                continue

            # Standard beacon interval is ~102.4ms (100 TU)
            declared_interval_s = 0.1024
            deviation = abs(avg_interval - declared_interval_s) / declared_interval_s

            max_jitter = max(abs(i - avg_interval) for i in intervals)
            jitter_ratio = max_jitter / avg_interval if avg_interval > 0 else 0

            entry: dict[str, Any] = {
                "bssid": bssid,
                "avg_interval_ms": round(avg_interval * 1000, 2),
                "max_jitter_ms": round(max_jitter * 1000, 2),
                "jitter_ratio": round(jitter_ratio, 4),
                "beacon_count": len(timestamps),
                "deviation_from_declared": round(deviation, 4),
            }

            if jitter_ratio > BEACON_JITTER_THRESHOLD:
                entry["alert"] = "possible_rogue_ap"
                entry["reason"] = (
                    f"Jitter ratio {jitter_ratio:.4f} exceeds "
                    f"threshold {BEACON_JITTER_THRESHOLD}"
                )

            anomalies.append(entry)

        return anomalies

    def _detect_deauth_floods(
        self, deauths: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Detect deauth flooding per BSSID using bisect for O(n log n)."""
        # Group deauths by BSSID with timestamps
        bssid_deauths: dict[str, list[float]] = {}
        for d in deauths:
            bssid = d.get("src", "")
            ts = d.get("ts")
            if bssid and ts is not None:
                bssid_deauths.setdefault(bssid, []).append(float(ts))

        floods: list[dict[str, Any]] = []
        for bssid, timestamps in bssid_deauths.items():
            timestamps.sort()
            # Sliding window detection using bisect_right for O(n log n)
            max_count_in_window = 0
            for i, t in enumerate(timestamps):
                window_end = t + DEAUTH_WINDOW_SECONDS
                # bisect_right finds the insertion point for window_end,
                # which equals the count of elements <= window_end from index i
                j = bisect.bisect_right(timestamps, window_end)
                count = j - i
                max_count_in_window = max(max_count_in_window, count)

            if max_count_in_window >= DEAUTH_FLOOD_THRESHOLD:
                floods.append({
                    "bssid": bssid,
                    "max_deauths_in_window": max_count_in_window,
                    "window_seconds": DEAUTH_WINDOW_SECONDS,
                    "total_deauths": len(timestamps),
                    "alert": "deauth_flood_detected",
                })

        return floods

    def _profile_probe_timing(
        self, probes: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Profile client probe request timing patterns."""
        client_probes: dict[str, list[float]] = {}
        for p in probes:
            client = p.get("src", "")
            ts = p.get("ts")
            if client and ts is not None:
                client_probes.setdefault(client, []).append(float(ts))

        profiles: list[dict[str, Any]] = []
        for client, timestamps in client_probes.items():
            if len(timestamps) < 2:
                continue
            timestamps.sort()
            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]
            avg_interval = sum(intervals) / len(intervals) if intervals else 0

            profiles.append({
                "client_mac": client,
                "probe_count": len(timestamps),
                "avg_interval_s": round(avg_interval, 3),
                "min_interval_s": round(min(intervals), 3) if intervals else 0,
                "max_interval_s": round(max(intervals), 3) if intervals else 0,
                "duration_s": round(timestamps[-1] - timestamps[0], 1),
            })

        return profiles

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary="[DRY-RUN] wifi.timing_analyzer would analyze timing data",
            )

        beacons: list[dict[str, Any]] = []
        deauths: list[dict[str, Any]] = []
        probes: list[dict[str, Any]] = []

        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT ts, src, dst, fields
                    FROM headers
                    WHERE session_id = %s AND protocol = 'wifi'
                    ORDER BY ts
                    """,
                    (str(ctx.session_id),),
                )
                for row in cur.fetchall():
                    ts, src, dst, fields = row
                    frame_type = ""
                    if isinstance(fields, dict):
                        frame_type = fields.get("frame_type", "")
                    elif isinstance(fields, str):
                        import json
                        try:
                            fields = json.loads(fields)
                            frame_type = fields.get("frame_type", "")
                        except (ValueError, TypeError):
                            pass

                    record = {"ts": ts, "src": src, "dst": dst, "fields": fields}
                    if frame_type == "beacon":
                        beacons.append(record)
                    elif frame_type == "deauth":
                        deauths.append(record)
                    elif frame_type == "probe_request":
                        probes.append(record)
        except Exception as exc:
            log.warning("wifi.timing_analyzer.db_query_failed", error=str(exc))
            return self._result(
                Status.FAIL,
                started,
                summary=f"DB query failed: {exc}",
            )

        beacon_analysis = self._analyze_beacon_jitter(beacons)
        flood_alerts = self._detect_deauth_floods(deauths)
        probe_profiles = self._profile_probe_timing(probes)

        rogue_count = sum(1 for a in beacon_analysis if "alert" in a)
        flood_count = len(flood_alerts)

        summary = (
            f"Timing analysis: {len(beacons)} beacons ({rogue_count} suspicious), "
            f"{len(deauths)} deauths ({flood_count} floods), "
            f"{len(probes)} probes from {len(probe_profiles)} clients"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "beacon_jitter_analysis", "data": beacon_analysis},
                {"type": "deauth_flood_alerts", "data": flood_alerts},
                {"type": "probe_timing_profiles", "data": probe_profiles},
            ],
            metrics={
                "beacon_count": len(beacons),
                "rogue_ap_suspects": rogue_count,
                "deauth_count": len(deauths),
                "flood_alerts": flood_count,
                "probe_count": len(probes),
                "clients_profiled": len(probe_profiles),
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
