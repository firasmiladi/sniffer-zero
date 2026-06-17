"""LoRaWAN traffic profiling engine.

Uplink interval measurement, payload pattern analysis, duty cycle
compliance checking, and SF/BW/CR usage patterns.
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

# EU868 duty cycle limits
EU868_DUTY_CYCLE: dict[str, float] = {
    "g_868_0_868_6": 0.01,   # 1% duty cycle (sub-band g)
    "g1_868_7_869_2": 0.001,  # 0.1%
    "g2_869_4_869_65": 0.10,  # 10%
    "g3_869_7_870_0": 0.01,   # 1%
}

# Standard time-on-air estimates (ms) per SF for 125 kHz BW, CR 4/5
TOA_ESTIMATES_MS: dict[int, dict[int, float]] = {
    # SF -> {payload_bytes -> approx ToA in ms}
    7: {10: 41.2, 20: 56.6, 50: 102.7},
    8: {10: 72.2, 20: 102.9, 50: 185.3},
    9: {10: 144.4, 20: 185.3, 50: 329.7},
    10: {10: 247.8, 20: 329.7, 50: 617.5},
    11: {10: 495.6, 20: 659.5, 50: 1151.0},
    12: {10: 991.2, 20: 1318.9, 50: 2301.9},
}


def _estimate_toa_ms(sf: int, payload_size: int) -> float:
    """Estimate time-on-air in milliseconds."""
    sf_table = TOA_ESTIMATES_MS.get(sf, TOA_ESTIMATES_MS[12])
    # Interpolate based on payload size
    if payload_size <= 10:
        return sf_table[10]
    elif payload_size <= 20:
        ratio = (payload_size - 10) / 10.0
        return sf_table[10] + ratio * (sf_table[20] - sf_table[10])
    elif payload_size <= 50:
        ratio = (payload_size - 20) / 30.0
        return sf_table[20] + ratio * (sf_table[50] - sf_table[20])
    else:
        # Extrapolate linearly
        per_byte = (sf_table[50] - sf_table[20]) / 30.0
        return sf_table[50] + (payload_size - 50) * per_byte


@register
class LoraTrafficProfiler(AttackModule):
    """LoRaWAN traffic pattern profiler.

    Measures uplink intervals, analyzes payload patterns, checks duty
    cycle compliance, and profiles SF/BW/CR usage patterns across devices.
    """

    name = "lora.traffic_profiler"
    protocol = "lora"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1040"]
    requires = []
    description = (
        "LoRaWAN traffic profiling: uplink intervals, payload patterns, "
        "duty cycle compliance, SF/BW/CR usage analysis."
    )

    def __init__(self) -> None:
        self._parser = LoRaWANParser()

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def _profile_intervals(
        self, frames: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        """Measure uplink intervals per device."""
        devaddr_times: dict[str, list[float]] = {}

        for frame in frames:
            devaddr = frame.get("dev_addr", "")
            ts = frame.get("ts", 0)
            direction = frame.get("direction", 0)
            if devaddr and ts and direction == 0:  # Uplinks only
                devaddr_times.setdefault(devaddr, []).append(ts)

        profiles: dict[str, dict[str, Any]] = {}
        for devaddr, timestamps in devaddr_times.items():
            if len(timestamps) < 2:
                profiles[devaddr] = {
                    "uplink_count": len(timestamps),
                    "avg_interval_s": None,
                }
                continue

            timestamps.sort()
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            avg_interval = sum(intervals) / len(intervals) if intervals else 0

            profiles[devaddr] = {
                "uplink_count": len(timestamps),
                "avg_interval_s": round(avg_interval, 2),
                "min_interval_s": round(min(intervals), 2) if intervals else 0,
                "max_interval_s": round(max(intervals), 2) if intervals else 0,
                "total_duration_s": round(timestamps[-1] - timestamps[0], 1),
            }

        return profiles

    def _analyze_payload_patterns(
        self, frames: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        """Analyze payload size and content patterns per device."""
        devaddr_payloads: dict[str, list[dict[str, Any]]] = {}

        for frame in frames:
            devaddr = frame.get("dev_addr", "")
            frm_len = frame.get("frm_payload_len", 0)
            fport = frame.get("fport")
            if devaddr:
                devaddr_payloads.setdefault(devaddr, []).append({
                    "size": frm_len,
                    "fport": fport,
                })

        patterns: dict[str, dict[str, Any]] = {}
        for devaddr, payloads in devaddr_payloads.items():
            sizes = [p["size"] for p in payloads if p["size"]]
            fports = [p["fport"] for p in payloads if p["fport"] is not None]

            # FPort distribution
            fport_dist: dict[int, int] = {}
            for fp in fports:
                fport_dist[fp] = fport_dist.get(fp, 0) + 1

            patterns[devaddr] = {
                "frame_count": len(payloads),
                "avg_payload_size": round(sum(sizes) / len(sizes), 1) if sizes else 0,
                "min_payload_size": min(sizes) if sizes else 0,
                "max_payload_size": max(sizes) if sizes else 0,
                "constant_size": len(set(sizes)) == 1 if sizes else False,
                "fport_distribution": fport_dist,
            }

        return patterns

    def _check_duty_cycle(
        self, frames: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Check duty cycle compliance per device."""
        devaddr_airtime: dict[str, dict[str, Any]] = {}

        for frame in frames:
            devaddr = frame.get("dev_addr", "")
            ts = frame.get("ts", 0)
            direction = frame.get("direction", 0)
            if not devaddr or direction != 0:  # Only check uplinks
                continue

            frm_len = frame.get("frm_payload_len", 0)
            sf = frame.get("sf", 12)

            toa_ms = _estimate_toa_ms(sf, frm_len)

            devaddr_airtime.setdefault(devaddr, {
                "total_toa_ms": 0.0,
                "first_ts": ts,
                "last_ts": ts,
                "frame_count": 0,
            })
            devaddr_airtime[devaddr]["total_toa_ms"] += toa_ms
            devaddr_airtime[devaddr]["last_ts"] = ts
            devaddr_airtime[devaddr]["frame_count"] += 1

        violations: list[dict[str, Any]] = []
        for devaddr, info in devaddr_airtime.items():
            duration_s = info["last_ts"] - info["first_ts"]
            if duration_s <= 0:
                continue

            duty_cycle = (info["total_toa_ms"] / 1000.0) / duration_s
            max_allowed = 0.01  # 1% default EU868

            if duty_cycle > max_allowed:
                violations.append({
                    "dev_addr": devaddr,
                    "duty_cycle_pct": round(duty_cycle * 100, 4),
                    "max_allowed_pct": max_allowed * 100,
                    "total_airtime_ms": round(info["total_toa_ms"], 1),
                    "observation_s": round(duration_s, 1),
                    "frame_count": info["frame_count"],
                    "violation": True,
                })

        return violations

    def _profile_sf_usage(
        self, frames: list[dict[str, Any]]
    ) -> dict[str, int]:
        """Profile spreading factor usage distribution."""
        sf_counts: dict[str, int] = {}
        for frame in frames:
            sf = frame.get("sf")
            if sf is not None:
                key = f"SF{sf}"
                sf_counts[key] = sf_counts.get(key, 0) + 1
        return sf_counts

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary="[DRY-RUN] lora.traffic_profiler would profile traffic",
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
                            parsed["sf"] = fields.get("sf")
                            all_parsed.append(parsed)
                        except (ValueError, TypeError):
                            pass

        except Exception as exc:
            log.warning("lora.traffic_profiler.db_error", error=str(exc))
            return self._result(
                Status.FAIL, started, summary=f"DB query error: {exc}"
            )

        interval_profiles = self._profile_intervals(all_parsed)
        payload_patterns = self._analyze_payload_patterns(all_parsed)
        duty_violations = self._check_duty_cycle(all_parsed)
        sf_usage = self._profile_sf_usage(all_parsed)

        devices_count = len(interval_profiles)
        violation_count = len(duty_violations)

        summary = (
            f"Traffic profile: {len(all_parsed)} frames from {devices_count} devices, "
            f"{violation_count} duty cycle violations, "
            f"SF distribution: {sf_usage}"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "interval_profiles", "data": interval_profiles},
                {"type": "payload_patterns", "data": payload_patterns},
                {"type": "duty_cycle_violations", "data": duty_violations},
                {"type": "sf_usage", "data": sf_usage},
            ],
            metrics={
                "frames_analyzed": len(all_parsed),
                "devices_profiled": devices_count,
                "duty_cycle_violations": violation_count,
                "sf_distribution": sf_usage,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
