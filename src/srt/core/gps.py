"""GPS integration module using gpsd daemon.

Connects to the gpsd JSON stream over TCP to obtain position fixes
for timestamping and geo-tagging captured RF headers.
"""

from __future__ import annotations

import json
import socket
import time

import structlog

logger = structlog.get_logger(__name__)


class GPSClient:
    """Client for gpsd (GPS daemon) JSON protocol."""

    def __init__(self, host: str = "127.0.0.1", port: int = 2947) -> None:
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
        self._buffer: str = ""
        self._last_fix: dict = {}

    def connect(self) -> None:
        """Open TCP connection to gpsd and enable JSON watch mode."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(5.0)
        self._sock.connect((self.host, self.port))
        # Enable JSON streaming
        watch_cmd = '?WATCH={"enable":true,"json":true}\n'
        self._sock.sendall(watch_cmd.encode())
        logger.info("gps.connected", host=self.host, port=self.port)

    def _read_line(self) -> str | None:
        """Read a single newline-terminated JSON line from gpsd."""
        if self._sock is None:
            return None
        while "\n" not in self._buffer:
            try:
                data = self._sock.recv(4096)
                if not data:
                    return None
                self._buffer += data.decode("utf-8", errors="replace")
            except TimeoutError:
                return None
        line, self._buffer = self._buffer.split("\n", 1)
        return line.strip()

    def get_position(self) -> dict:
        """Read from gpsd and return the latest TPV (Time-Position-Velocity) fix.

        Returns:
            Dictionary with keys: lat, lon, alt, time, speed, fix_mode, satellites.
            Values may be None if no fix is available.
        """
        result: dict = {
            "lat": None,
            "lon": None,
            "alt": None,
            "time": None,
            "speed": None,
            "fix_mode": 0,
            "satellites": 0,
        }

        # Try to read up to 10 messages to find a TPV report
        for _ in range(10):
            line = self._read_line()
            if line is None:
                break
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            if msg.get("class") == "TPV":
                result["lat"] = msg.get("lat")
                result["lon"] = msg.get("lon")
                result["alt"] = msg.get("alt")
                result["time"] = msg.get("time")
                result["speed"] = msg.get("speed")
                result["fix_mode"] = msg.get("mode", 0)
                self._last_fix = result.copy()
                logger.debug(
                    "gps.tpv",
                    lat=result["lat"],
                    lon=result["lon"],
                    fix_mode=result["fix_mode"],
                )
                return result

            if msg.get("class") == "SKY":
                result["satellites"] = len(msg.get("satellites", []))

        # Return cached fix if no new data
        if self._last_fix:
            return self._last_fix
        return result

    def close(self) -> None:
        """Close the gpsd connection."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            logger.info("gps.disconnected")


def stamp_header(fields: dict) -> dict:
    """Add GPS position fields to an existing header dictionary.

    Creates a short-lived GPS connection to get the current fix
    and merges gps_lat, gps_lon, gps_time into the provided fields.

    Args:
        fields: Existing header fields dictionary.

    Returns:
        The fields dictionary with GPS data added.
    """
    client = GPSClient()
    try:
        client.connect()
        time.sleep(0.5)  # Allow gpsd to send initial data
        pos = client.get_position()
        fields["gps_lat"] = pos.get("lat")
        fields["gps_lon"] = pos.get("lon")
        fields["gps_time"] = pos.get("time")
    except (OSError, ConnectionRefusedError) as exc:
        logger.warning("gps.stamp_failed", error=str(exc))
        fields["gps_lat"] = None
        fields["gps_lon"] = None
        fields["gps_time"] = None
    finally:
        client.close()
    return fields


def get_gps_time() -> str:
    """Return current GPS time as an ISO 8601 string.

    Falls back to empty string if GPS is unavailable.
    """
    client = GPSClient()
    try:
        client.connect()
        time.sleep(0.5)
        pos = client.get_position()
        return pos.get("time") or ""
    except (OSError, ConnectionRefusedError) as exc:
        logger.warning("gps.time_failed", error=str(exc))
        return ""
    finally:
        client.close()
