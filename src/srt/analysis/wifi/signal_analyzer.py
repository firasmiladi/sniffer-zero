"""WiFi signal analysis engine.

RSSI-based distance estimation using free-space path loss model,
channel congestion mapping, and signal trending over time from DB data.
"""

from __future__ import annotations

import math
import time
from typing import Any

import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)

# Free-space path loss reference values
# FSPL(d) = 20*log10(d) + 20*log10(f) + 20*log10(4*pi/c)
# For 2.4 GHz: FSPL(1m) ~ -40 dBm (typical TX power 20 dBm)
REFERENCE_RSSI_1M = -40  # dBm at 1 meter
PATH_LOSS_EXPONENT = 2.7  # Indoor environment (2 = free space, 2.7-3.5 indoor)

# Channel definitions
CHANNELS_2G: dict[int, int] = {
    1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432, 6: 2437,
    7: 2442, 8: 2447, 9: 2452, 10: 2457, 11: 2462, 12: 2467, 13: 2472,
}

CHANNELS_5G: dict[int, int] = {
    36: 5180, 40: 5200, 44: 5220, 48: 5240, 52: 5260, 56: 5280,
    60: 5300, 64: 5320, 100: 5500, 104: 5520, 108: 5540, 112: 5560,
    116: 5580, 120: 5600, 124: 5620, 128: 5640, 132: 5660, 136: 5680,
    140: 5700, 144: 5720, 149: 5745, 153: 5765, 157: 5785, 161: 5805, 165: 5825,
}


def _estimate_distance_m(rssi_dbm: int, tx_power_dbm: int = 20,
                         path_loss_exp: float = PATH_LOSS_EXPONENT) -> float:
    """Estimate distance in meters from RSSI using log-distance path loss model.

    d = 10 ^ ((tx_power - rssi - reference_loss) / (10 * n))
    """
    if rssi_dbm >= tx_power_dbm:
        return 0.1  # Very close

    # Reference loss at 1m for 2.4 GHz
    reference_loss = 40.0  # dB at 1 meter for 2.4 GHz
    exponent = (tx_power_dbm - rssi_dbm - reference_loss) / (10.0 * path_loss_exp)
    distance = math.pow(10, exponent)
    return round(max(0.1, distance), 2)


@register
class WiFiSignalAnalyzer(AttackModule):
    """WiFi signal strength and channel analysis engine.

    RSSI-based distance estimation using free-space path loss model,
    channel congestion measurement (frame count per channel), and
    signal quality trending from DB data.
    """

    name = "wifi.signal_analyzer"
    protocol = "wifi"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1592"]
    requires = []
    description = (
        "Signal analysis: RSSI distance estimation, channel congestion "
        "mapping, signal trending over time."
    )

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def _analyze_channel_congestion(
        self, frames: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Compute frame count per channel for congestion mapping."""
        channel_counts: dict[int, int] = {}
        for frame in frames:
            ch = frame.get("channel")
            if ch is not None:
                channel_counts[ch] = channel_counts.get(ch, 0) + 1

        total = sum(channel_counts.values())
        congestion: dict[str, Any] = {}
        for ch, count in sorted(channel_counts.items()):
            pct = (count / total * 100) if total > 0 else 0
            band = "2.4GHz" if ch <= 14 else "5GHz"
            congestion[str(ch)] = {
                "frame_count": count,
                "percentage": round(pct, 1),
                "band": band,
            }

        return congestion

    def _compute_signal_trends(
        self, frames: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        """Group RSSI readings by source over time for trending."""
        src_readings: dict[str, list[dict[str, Any]]] = {}
        for frame in frames:
            src = frame.get("src", "")
            rssi = frame.get("rssi_dbm")
            ts = frame.get("ts")
            if src and rssi is not None and ts is not None:
                src_readings.setdefault(src, []).append({
                    "ts": ts, "rssi": rssi,
                })

        # Compute per-source statistics
        trends: dict[str, list[dict[str, Any]]] = {}
        for src, readings in src_readings.items():
            if len(readings) < 2:
                continue
            rssi_values = [r["rssi"] for r in readings]
            avg_rssi = sum(rssi_values) / len(rssi_values)
            min_rssi = min(rssi_values)
            max_rssi = max(rssi_values)
            distance = _estimate_distance_m(int(avg_rssi))

            trends[src] = [{
                "avg_rssi": round(avg_rssi, 1),
                "min_rssi": min_rssi,
                "max_rssi": max_rssi,
                "sample_count": len(readings),
                "estimated_distance_m": distance,
            }]

        return trends

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary="[DRY-RUN] wifi.signal_analyzer would analyze signals",
            )

        frames: list[dict[str, Any]] = []

        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT ts, src, channel, rssi_dbm, fields
                    FROM headers
                    WHERE session_id = %s AND protocol = 'wifi'
                    ORDER BY ts
                    """,
                    (str(ctx.session_id),),
                )
                for row in cur.fetchall():
                    ts, src, channel, rssi_dbm, fields = row
                    frames.append({
                        "ts": ts,
                        "src": src,
                        "channel": channel,
                        "rssi_dbm": rssi_dbm,
                        "fields": fields,
                    })
        except Exception as exc:
            log.warning("wifi.signal_analyzer.db_error", error=str(exc))
            return self._result(
                Status.FAIL, started, summary=f"DB query error: {exc}"
            )

        congestion = self._analyze_channel_congestion(frames)
        trends = self._compute_signal_trends(frames)

        # Distance estimates for all sources with RSSI
        distance_estimates: list[dict[str, Any]] = []
        for src, trend_data in trends.items():
            if trend_data:
                entry = trend_data[0]
                distance_estimates.append({
                    "source": src,
                    "avg_rssi": entry["avg_rssi"],
                    "estimated_distance_m": entry["estimated_distance_m"],
                    "samples": entry["sample_count"],
                })

        summary = (
            f"Signal analysis: {len(frames)} frames, "
            f"{len(congestion)} channels active, "
            f"{len(distance_estimates)} sources with distance estimates"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "channel_congestion", "data": congestion},
                {"type": "distance_estimates", "data": distance_estimates},
                {"type": "signal_trends", "data": trends},
            ],
            metrics={
                "total_frames": len(frames),
                "active_channels": len(congestion),
                "sources_tracked": len(distance_estimates),
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
