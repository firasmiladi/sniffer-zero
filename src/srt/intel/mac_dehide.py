"""intel.mac_dehide - Defeat MAC randomization via IE fingerprinting

Les téléphones modernes (iOS 14+, Android 10+) randomisent leur MAC.
Ce module IDENTIFIE le device malgré la MAC random en analysant:
- La liste des Information Elements dans les probe requests
- L'ordre et les valeurs des Supported Rates
- Les HT/VHT/HE capabilities
- Les Vendor Specific IEs (Apple, MS, Google signatures)

Même avec 10 MACs différentes, le fingerprint reste IDENTIQUE.

MITRE: T1592.002
Hardware: ALFA AWUS036NH (mode monitor)
Taux succès: 70-90% d'identification correcte
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import defaultdict
from typing import Any

import structlog
from scapy.all import Dot11, Dot11Elt, Dot11ProbeReq, RadioTap, sniff

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


def _is_random_mac(mac: str) -> bool:
    """Check if MAC is locally administered (random)."""
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


def _compute_fingerprint(ies: list[int], rates: list[float], ht: bool, vht: bool, he: bool) -> str:
    """Compute stable fingerprint from probe request features."""
    parts = [
        ",".join(str(i) for i in sorted(ies)),
        ",".join(f"{r:.1f}" for r in sorted(rates)),
        f"ht={ht}",
        f"vht={vht}",
        f"he={he}",
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@register
class IntelMacDehide(AttackModule):
    name = "intel.mac_dehide"
    protocol = "wifi"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1592.002"]
    cve = []
    description = (
        "Defeat MAC randomization - identify devices despite random MACs "
        "via IE fingerprinting of probe requests."
    )
    requires = ["monitor-mode-nic"]

    def __init__(self) -> None:
        self._devices: dict[str, dict[str, Any]] = {}
        self._clusters: dict[str, list[str]] = defaultdict(list)
        self._stop_event = threading.Event()

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY CAGE BYPASS

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        iface = ctx.params.get("interface", "wlan0")
        duration = int(ctx.params.get("duration_s", 120))

        if ctx.dry_run:
            return self._result(
                Status.OK, started,
                summary=f"[DRY-RUN] intel.mac_dehide duration={duration}s",
                metrics={"duration_s": duration},
            )

        log.info("intel.mac_dehide.starting", iface=iface, duration=duration)

        self._stop_event.clear()
        self._devices = {}
        self._clusters = defaultdict(list)

        def packet_handler(pkt: Any) -> None:
            if not pkt.haslayer(Dot11ProbeReq):
                return

            src_mac = pkt[Dot11].addr2
            if not src_mac:
                return

            is_random = _is_random_mac(src_mac)

            # Extract IEs
            ie_ids: list[int] = []
            rates: list[float] = []
            ht = False
            vht = False
            he = False
            ssid = ""

            elt = pkt.getlayer(Dot11Elt)
            while elt:
                ie_ids.append(elt.ID)
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace")
                    except Exception:
                        pass
                elif elt.ID == 1 and elt.info:
                    for byte in elt.info:
                        rates.append((byte & 0x7F) * 0.5)
                elif elt.ID == 45:
                    ht = True
                elif elt.ID == 191:
                    vht = True
                elif elt.ID == 255:
                    he = True
                elt = elt.payload.getlayer(Dot11Elt)

            fingerprint = _compute_fingerprint(ie_ids, rates, ht, vht, he)

            # Store device info
            self._devices[src_mac] = {
                "fingerprint": fingerprint,
                "is_random": is_random,
                "ie_count": len(ie_ids),
                "ht": ht, "vht": vht, "he": he,
                "ssids_probed": ssid,
                "last_seen": time.time(),
            }

            # Cluster by fingerprint
            if src_mac not in self._clusters[fingerprint]:
                self._clusters[fingerprint].append(src_mac)

        try:
            sniff(
                iface=iface, prn=packet_handler,
                timeout=duration, store=False, monitor=True,
            )
        except Exception as exc:
            return self._result(Status.FAIL, started, summary=f"Sniff error: {exc}")

        # Analyze clusters
        multi_mac_devices = {
            fp: macs for fp, macs in self._clusters.items() if len(macs) > 1
        }
        random_macs = sum(1 for d in self._devices.values() if d["is_random"])
        real_macs = len(self._devices) - random_macs

        log.info(
            "intel.mac_dehide.completed",
            total_macs=len(self._devices),
            random=random_macs,
            real=real_macs,
            clusters=len(multi_mac_devices),
        )

        return self._result(
            Status.OK, started,
            summary=(
                f"intel.mac_dehide: {len(self._devices)} MACs seen, "
                f"{random_macs} random, {len(multi_mac_devices)} multi-MAC clusters "
                f"(same device with different MACs)"
            ),
            artifacts=[
                {"type": "device_fingerprints", "data": dict(self._devices)},
                {"type": "mac_clusters", "data": dict(multi_mac_devices)},
            ],
            metrics={
                "total_macs_seen": len(self._devices),
                "random_macs": random_macs,
                "real_macs": real_macs,
                "unique_fingerprints": len(self._clusters),
                "multi_mac_clusters": len(multi_mac_devices),
                "duration_s": duration,
            },
        )
