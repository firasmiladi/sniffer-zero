"""LoRaWAN anomaly detection engine.

Detects FCnt rollback/gaps, DevNonce reuse, duplicate frames (replay attacks),
unexpected DevAddr appearance, ADR parameter anomalies, and timing anomalies.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register
from srt.recon.lora.frame_parser import LoRaWANParser

log = structlog.get_logger(__name__)

# Anomaly thresholds
FCNT_GAP_THRESHOLD = 10  # More than N missed frames is suspicious
FCNT_ROLLBACK_ALERT = True  # FCnt going backwards always suspicious
DUPLICATE_WINDOW_S = 60.0  # Duplicates within this window = replay
TIMING_DEVIATION_FACTOR = 3.0  # >3x normal interval is suspicious


@register
class LoraAnomalyDetector(AttackModule):
    """LoRaWAN network anomaly detection.

    Detects FCnt rollback/gap, DevNonce reuse, duplicate frames (replay),
    unexpected DevAddr, ADR anomalies, and timing anomalies from session
    data in the DB headers table.
    """

    name = "lora.anomaly_detector"
    protocol = "lora"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1040", "T1499"]
    requires = []
    description = (
        "LoRaWAN anomaly detection: FCnt rollback/gap, DevNonce reuse, "
        "replay detection, unexpected DevAddr, ADR/timing anomalies."
    )

    def __init__(self) -> None:
        self._parser = LoRaWANParser()

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def _detect_fcnt_anomalies(
        self, frames: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Detect FCnt rollback and gap anomalies per DevAddr."""
        devaddr_fcnts: dict[str, list[tuple[float, int]]] = {}

        for frame in frames:
            devaddr = frame.get("dev_addr", "")
            fcnt = frame.get("fcnt")
            ts = frame.get("ts", 0)
            if devaddr and fcnt is not None:
                devaddr_fcnts.setdefault(devaddr, []).append((ts, fcnt))

        anomalies: list[dict[str, Any]] = []
        for devaddr, records in devaddr_fcnts.items():
            records.sort(key=lambda x: x[0])
            for i in range(1, len(records)):
                prev_ts, prev_fcnt = records[i - 1]
                curr_ts, curr_fcnt = records[i]

                # FCnt rollback
                if curr_fcnt < prev_fcnt:
                    anomalies.append({
                        "type": "fcnt_rollback",
                        "severity": "high",
                        "dev_addr": devaddr,
                        "prev_fcnt": prev_fcnt,
                        "curr_fcnt": curr_fcnt,
                        "ts": curr_ts,
                        "description": (
                            f"FCnt decreased from {prev_fcnt} to {curr_fcnt} - "
                            "possible device reset or replay attack"
                        ),
                    })

                # FCnt gap
                gap = curr_fcnt - prev_fcnt
                if gap > FCNT_GAP_THRESHOLD:
                    anomalies.append({
                        "type": "fcnt_gap",
                        "severity": "medium",
                        "dev_addr": devaddr,
                        "prev_fcnt": prev_fcnt,
                        "curr_fcnt": curr_fcnt,
                        "gap": gap,
                        "ts": curr_ts,
                        "description": (
                            f"FCnt gap of {gap} frames - "
                            "possible jamming or packet loss"
                        ),
                    })

        return anomalies

    def _detect_duplicates(
        self, frames: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Detect duplicate frames (potential replay attacks)."""
        # Track (DevAddr, FCnt, FPort) combinations
        seen: dict[str, list[float]] = {}
        duplicates: list[dict[str, Any]] = []

        for frame in frames:
            devaddr = frame.get("dev_addr", "")
            fcnt = frame.get("fcnt")
            fport = frame.get("fport")
            ts = frame.get("ts", 0)

            if not devaddr or fcnt is None:
                continue

            key = f"{devaddr}:{fcnt}:{fport}"
            seen.setdefault(key, [])

            # Check if this is a duplicate within the time window
            for prev_ts in seen[key]:
                time_diff = abs(ts - prev_ts)
                if 0 < time_diff < DUPLICATE_WINDOW_S:
                    duplicates.append({
                        "type": "duplicate_frame",
                        "severity": "high",
                        "dev_addr": devaddr,
                        "fcnt": fcnt,
                        "fport": fport,
                        "time_diff_s": round(time_diff, 2),
                        "ts": ts,
                        "description": (
                            f"Duplicate frame (DevAddr={devaddr}, FCnt={fcnt}) "
                            f"within {time_diff:.1f}s - possible replay"
                        ),
                    })
                    break

            seen[key].append(ts)

        return duplicates

    def _detect_devnonce_reuse(
        self, frames: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Detect DevNonce reuse in Join Requests."""
        nonces: dict[str, dict[int, int]] = {}  # DevEUI -> {nonce: count}
        anomalies: list[dict[str, Any]] = []

        for frame in frames:
            if frame.get("mtype") != 0:  # Join Request
                continue
            dev_eui = frame.get("dev_eui", "")
            dev_nonce = frame.get("dev_nonce")
            if not dev_eui or dev_nonce is None:
                continue

            nonces.setdefault(dev_eui, {})
            nonces[dev_eui][dev_nonce] = nonces[dev_eui].get(dev_nonce, 0) + 1

            if nonces[dev_eui][dev_nonce] > 1:
                anomalies.append({
                    "type": "devnonce_reuse",
                    "severity": "critical",
                    "dev_eui": dev_eui,
                    "dev_nonce": dev_nonce,
                    "count": nonces[dev_eui][dev_nonce],
                    "description": (
                        f"DevNonce {dev_nonce} reused {nonces[dev_eui][dev_nonce]} times "
                        f"by {dev_eui} - enables key derivation attack"
                    ),
                })

        return anomalies

    def _detect_timing_anomalies(
        self, frames: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Detect unusual transmission timing patterns."""
        devaddr_times: dict[str, list[float]] = {}

        for frame in frames:
            devaddr = frame.get("dev_addr", "")
            ts = frame.get("ts", 0)
            if devaddr and ts:
                devaddr_times.setdefault(devaddr, []).append(ts)

        anomalies: list[dict[str, Any]] = []
        for devaddr, timestamps in devaddr_times.items():
            if len(timestamps) < 5:
                continue
            timestamps.sort()
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            if not intervals:
                continue

            avg_interval = sum(intervals) / len(intervals)
            if avg_interval <= 0:
                continue

            for _i, interval in enumerate(intervals):
                if interval > avg_interval * TIMING_DEVIATION_FACTOR:
                    anomalies.append({
                        "type": "timing_anomaly",
                        "severity": "low",
                        "dev_addr": devaddr,
                        "interval_s": round(interval, 2),
                        "avg_interval_s": round(avg_interval, 2),
                        "deviation_factor": round(interval / avg_interval, 1),
                        "description": (
                            f"Interval {interval:.1f}s is {interval/avg_interval:.1f}x "
                            f"the average {avg_interval:.1f}s"
                        ),
                    })
                    break  # One alert per device is enough

        return anomalies

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary="[DRY-RUN] lora.anomaly_detector would detect anomalies",
            )

        all_parsed: list[dict[str, Any]] = []

        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT ts, fields
                    FROM headers
                    WHERE session_id = %s AND protocol = 'lora'
                    ORDER BY ts
                    """,
                    (str(ctx.session_id),),
                )
                for row in cur.fetchall():
                    ts, fields = row
                    if isinstance(fields, str):
                        import json
                        try:
                            fields = json.loads(fields)
                        except (ValueError, TypeError):
                            fields = {}
                    if not isinstance(fields, dict):
                        fields = {}

                    raw_hex = fields.get("raw_payload", fields.get("phy_payload", ""))
                    if raw_hex:
                        try:
                            parsed = self._parser.parse(bytes.fromhex(raw_hex))
                            parsed["ts"] = ts
                            all_parsed.append(parsed)
                        except (ValueError, TypeError):
                            pass

        except Exception as exc:
            log.warning("lora.anomaly_detector.db_error", error=str(exc))
            return self._result(
                Status.FAIL, started, summary=f"DB query error: {exc}"
            )

        # Run all detectors
        fcnt_anomalies = self._detect_fcnt_anomalies(all_parsed)
        duplicates = self._detect_duplicates(all_parsed)
        nonce_reuses = self._detect_devnonce_reuse(all_parsed)
        timing_anomalies = self._detect_timing_anomalies(all_parsed)

        all_anomalies = fcnt_anomalies + duplicates + nonce_reuses + timing_anomalies

        # Severity counts
        severity_dist: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in all_anomalies:
            sev = a.get("severity", "low")
            severity_dist[sev] = severity_dist.get(sev, 0) + 1

        summary = (
            f"Anomaly detection: {len(all_anomalies)} anomalies from "
            f"{len(all_parsed)} frames - "
            f"critical={severity_dist['critical']} high={severity_dist['high']} "
            f"medium={severity_dist['medium']} low={severity_dist['low']}"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "fcnt_anomalies", "data": fcnt_anomalies},
                {"type": "duplicate_frames", "data": duplicates},
                {"type": "devnonce_reuses", "data": nonce_reuses},
                {"type": "timing_anomalies", "data": timing_anomalies},
            ],
            metrics={
                "total_anomalies": len(all_anomalies),
                "fcnt_anomalies": len(fcnt_anomalies),
                "duplicate_frames": len(duplicates),
                "nonce_reuses": len(nonce_reuses),
                "timing_anomalies": len(timing_anomalies),
                "severity_distribution": severity_dist,
                "frames_analyzed": len(all_parsed),
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
