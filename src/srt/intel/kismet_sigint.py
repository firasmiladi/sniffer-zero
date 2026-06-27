"""intel.kismet_sigint - 24/7 WiFi/Bluetooth SIGINT surveillance via Kismet

Surveillance passive continue de l'environnement RF.
Détecte TOUT appareil WiFi/BT qui entre dans le rayon.
Alerte si nouveau device apparaît.
Web UI sur http://localhost:2501

MITRE: T1040, T1592
Hardware: ALFA AWUS036NH (mode monitor)
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
class IntelKismetSigint(AttackModule):
    name = "intel.kismet_sigint"
    protocol = "wifi"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1040", "T1592"]
    cve = []
    description = (
        "24/7 multi-protocol SIGINT via Kismet - "
        "detect all WiFi/BT devices, log activity, alert on new devices."
    )
    requires = ["monitor-mode-nic"]

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY CAGE BYPASS

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        iface = ctx.params.get("interface", "wlan0")
        duration = int(ctx.params.get("duration_s", 600))
        log_dir = ctx.params.get("log_dir", ctx.workdir)

        if ctx.dry_run:
            return self._result(
                Status.OK, started,
                summary=f"[DRY-RUN] intel.kismet_sigint duration={duration}s",
                metrics={"duration_s": duration},
            )

        log.info("intel.kismet_sigint.starting", iface=iface, duration=duration)

        cmd = [
            "kismet",
            "-c", iface,
            "--no-ncurses",
            "--log-prefix", f"{log_dir}/kismet",
        ]

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            time.sleep(duration)
            proc.terminate()
            try:
                stdout, _ = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout = ""
        except FileNotFoundError:
            return self._result(
                Status.FAIL, started,
                summary="kismet not found. Run: sudo apt install kismet",
            )
        except Exception as exc:
            return self._result(Status.FAIL, started, summary=f"Kismet error: {exc}")

        elapsed = time.time() - started

        return self._result(
            Status.OK, started,
            summary=f"intel.kismet_sigint: surveillance ran {elapsed:.0f}s on {iface}",
            metrics={
                "interface": iface,
                "duration_s": duration,
                "actual_duration_s": round(elapsed, 1),
                "log_dir": log_dir,
                "web_ui": "http://localhost:2501",
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        subprocess.run(["pkill", "-f", "kismet"], capture_output=True)
