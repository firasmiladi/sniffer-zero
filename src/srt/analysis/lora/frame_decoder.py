"""LoRaWAN frame decoder engine.

Extends the existing LoRaWANParser with MAC command parsing, FCtrl flags
decode, FOpts vs FPort=0 differentiation, and LoRaWAN 1.0 vs 1.1 detection.
"""

from __future__ import annotations

import struct
import time
from typing import Any

import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register
from srt.recon.lora.frame_parser import LoRaWANParser

log = structlog.get_logger(__name__)

# MAC Command CIDs (Class A)
MAC_COMMANDS_UP: dict[int, dict[str, Any]] = {
    0x01: {"name": "ResetInd", "len": 1, "version": "1.1"},
    0x02: {"name": "LinkCheckReq", "len": 0, "version": "1.0"},
    0x03: {"name": "LinkADRAns", "len": 1, "version": "1.0"},
    0x04: {"name": "DutyCycleAns", "len": 0, "version": "1.0"},
    0x05: {"name": "RXParamSetupAns", "len": 1, "version": "1.0"},
    0x06: {"name": "DevStatusAns", "len": 2, "version": "1.0"},
    0x07: {"name": "NewChannelAns", "len": 1, "version": "1.0"},
    0x08: {"name": "RXTimingSetupAns", "len": 0, "version": "1.0"},
    0x09: {"name": "TXParamSetupAns", "len": 0, "version": "1.0"},
    0x0A: {"name": "DlChannelAns", "len": 1, "version": "1.0"},
    0x0B: {"name": "RekeyInd", "len": 1, "version": "1.1"},
    0x0C: {"name": "ADRParamSetupAns", "len": 0, "version": "1.1"},
    0x0D: {"name": "DeviceTimeReq", "len": 0, "version": "1.0.3"},
    0x0F: {"name": "RejoinParamSetupAns", "len": 1, "version": "1.1"},
}

MAC_COMMANDS_DOWN: dict[int, dict[str, Any]] = {
    0x01: {"name": "ResetConf", "len": 1, "version": "1.1"},
    0x02: {"name": "LinkCheckAns", "len": 2, "version": "1.0"},
    0x03: {"name": "LinkADRReq", "len": 4, "version": "1.0"},
    0x04: {"name": "DutyCycleReq", "len": 1, "version": "1.0"},
    0x05: {"name": "RXParamSetupReq", "len": 4, "version": "1.0"},
    0x06: {"name": "DevStatusReq", "len": 0, "version": "1.0"},
    0x07: {"name": "NewChannelReq", "len": 5, "version": "1.0"},
    0x08: {"name": "RXTimingSetupReq", "len": 1, "version": "1.0"},
    0x09: {"name": "TXParamSetupReq", "len": 1, "version": "1.0"},
    0x0A: {"name": "DlChannelReq", "len": 4, "version": "1.0"},
    0x0B: {"name": "RekeyConf", "len": 1, "version": "1.1"},
    0x0C: {"name": "ADRParamSetupReq", "len": 1, "version": "1.1"},
    0x0D: {"name": "DeviceTimeAns", "len": 5, "version": "1.0.3"},
    0x0E: {"name": "ForceRejoinReq", "len": 2, "version": "1.1"},
    0x0F: {"name": "RejoinParamSetupReq", "len": 1, "version": "1.1"},
}


def _parse_mac_commands(data: bytes, is_uplink: bool) -> list[dict[str, Any]]:
    """Parse MAC commands from FOpts or FRMPayload (FPort=0)."""
    commands: list[dict[str, Any]] = []
    cmd_table = MAC_COMMANDS_UP if is_uplink else MAC_COMMANDS_DOWN
    offset = 0

    while offset < len(data):
        cid = data[offset]
        offset += 1
        cmd_info = cmd_table.get(cid)

        if cmd_info is None:
            commands.append({
                "cid": cid,
                "name": f"Unknown_0x{cid:02X}",
                "raw": data[offset:].hex(),
            })
            break  # Cannot parse further without knowing length

        cmd_len = cmd_info["len"]
        payload = data[offset:offset + cmd_len] if cmd_len > 0 else b""
        offset += cmd_len

        cmd_entry: dict[str, Any] = {
            "cid": cid,
            "name": cmd_info["name"],
            "version": cmd_info["version"],
            "payload_hex": payload.hex(),
        }

        # Decode specific commands
        if cmd_info["name"] == "LinkCheckAns" and len(payload) >= 2:
            cmd_entry["margin_db"] = payload[0]
            cmd_entry["gateway_count"] = payload[1]
        elif cmd_info["name"] == "LinkADRReq" and len(payload) >= 4:
            dr_txpow = payload[0]
            cmd_entry["data_rate"] = (dr_txpow >> 4) & 0x0F
            cmd_entry["tx_power"] = dr_txpow & 0x0F
            ch_mask = struct.unpack_from("<H", payload, 1)[0]
            cmd_entry["channel_mask"] = f"{ch_mask:016b}"
            redundancy = payload[3]
            cmd_entry["nb_trans"] = redundancy & 0x0F
            cmd_entry["ch_mask_ctrl"] = (redundancy >> 4) & 0x07
        elif cmd_info["name"] == "DutyCycleReq" and len(payload) >= 1:
            cmd_entry["max_duty_cycle"] = payload[0] & 0x0F
        elif cmd_info["name"] == "RXParamSetupReq" and len(payload) >= 4:
            dl_settings = payload[0]
            cmd_entry["rx1_dr_offset"] = (dl_settings >> 4) & 0x07
            cmd_entry["rx2_data_rate"] = dl_settings & 0x0F
            freq = struct.unpack_from("<I", payload[1:4] + b"\x00", 0)[0] & 0x00FFFFFF
            cmd_entry["rx2_frequency_hz"] = freq * 100
        elif cmd_info["name"] == "NewChannelReq" and len(payload) >= 5:
            cmd_entry["channel_index"] = payload[0]
            freq = struct.unpack_from("<I", payload[1:4] + b"\x00", 0)[0] & 0x00FFFFFF
            cmd_entry["frequency_hz"] = freq * 100
            dr_range = payload[4]
            cmd_entry["min_dr"] = dr_range & 0x0F
            cmd_entry["max_dr"] = (dr_range >> 4) & 0x0F
        elif cmd_info["name"] == "RXTimingSetupReq" and len(payload) >= 1:
            cmd_entry["rx1_delay_s"] = payload[0] & 0x0F
        elif cmd_info["name"] == "DevStatusAns" and len(payload) >= 2:
            cmd_entry["battery"] = payload[0]
            margin = payload[1] & 0x3F
            if margin & 0x20:
                margin = margin - 64  # sign extend
            cmd_entry["margin_db"] = margin

        commands.append(cmd_entry)

    return commands


def _detect_lorawan_version(parsed: dict[str, Any], mac_cmds: list[dict[str, Any]]) -> str:
    """Detect LoRaWAN version from frame features and MAC commands."""
    # Check for 1.1-specific MAC commands
    for cmd in mac_cmds:
        if cmd.get("version") == "1.1":
            return "1.1"

    # Join Request with longer DevNonce might indicate 1.1
    if parsed.get("mtype") == 0:
        # In 1.1, DevNonce is a counter; in 1.0 it's random
        # We cannot definitively determine from a single frame
        pass

    return "1.0"


@register
class LoraFrameDecoder(AttackModule):
    """Complete LoRaWAN PHYPayload decoder with MAC command parsing.

    Extends the existing LoRaWANParser with MAC command parsing (all CIDs),
    FCtrl flags decode, FOpts vs FPort=0 differentiation, and LoRaWAN
    1.0 vs 1.1 version detection.
    """

    name = "lora.frame_decoder"
    protocol = "lora"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1040"]
    requires = []
    description = (
        "Complete LoRaWAN frame decoder: PHYPayload parsing, MAC command "
        "decode (all CIDs), FCtrl flags, LoRaWAN 1.0/1.1 detection."
    )

    def __init__(self) -> None:
        self._parser = LoRaWANParser()

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def _decode_frame(self, raw_hex: str) -> dict[str, Any]:
        """Decode a complete LoRaWAN frame with MAC commands."""
        try:
            raw_bytes = bytes.fromhex(raw_hex)
        except (ValueError, TypeError):
            return {"error": "invalid_hex"}

        parsed = self._parser.parse(raw_bytes)
        if "error" in parsed:
            return parsed

        # Parse MAC commands from FOpts
        mac_commands: list[dict[str, Any]] = []
        fopts_hex = parsed.get("fopts_hex", "")
        if fopts_hex:
            try:
                fopts_data = bytes.fromhex(fopts_hex)
                is_uplink = parsed.get("direction", 0) == 0
                mac_commands = _parse_mac_commands(fopts_data, is_uplink)
                parsed["mac_commands_fopts"] = mac_commands
            except (ValueError, TypeError):
                pass

        # Parse MAC commands from FRMPayload if FPort == 0
        if parsed.get("fport") == 0:
            frm_hex = parsed.get("frm_payload_hex", "")
            if frm_hex:
                try:
                    frm_data = bytes.fromhex(frm_hex)
                    is_uplink = parsed.get("direction", 0) == 0
                    frm_cmds = _parse_mac_commands(frm_data, is_uplink)
                    parsed["mac_commands_payload"] = frm_cmds
                    mac_commands.extend(frm_cmds)
                except (ValueError, TypeError):
                    pass

        # Detect LoRaWAN version
        parsed["lorawan_version"] = _detect_lorawan_version(parsed, mac_commands)
        parsed["all_mac_commands"] = mac_commands

        return parsed

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary="[DRY-RUN] lora.frame_decoder would decode LoRaWAN frames",
            )

        decoded_frames: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT ts, src, fields
                    FROM headers
                    WHERE session_id = %s AND protocol = 'lora'
                    ORDER BY ts
                    """,
                    (str(ctx.session_id),),
                )
                for row in cur.fetchall():
                    ts, src, fields = row
                    if isinstance(fields, str):
                        import json
                        try:
                            fields = json.loads(fields)
                        except (ValueError, TypeError):
                            fields = {}
                    if not isinstance(fields, dict):
                        fields = {}

                    raw_hex = fields.get("raw_payload", fields.get("phy_payload", ""))
                    if not raw_hex:
                        continue

                    result = self._decode_frame(raw_hex)
                    result["ts"] = ts
                    result["src"] = src

                    if "error" in result:
                        errors.append(result)
                    else:
                        decoded_frames.append(result)

        except Exception as exc:
            log.warning("lora.frame_decoder.db_error", error=str(exc))
            return self._result(
                Status.FAIL, started, summary=f"DB query error: {exc}"
            )

        # Statistics
        mtype_dist: dict[str, int] = {}
        mac_cmd_count = 0
        v11_count = 0
        for frame in decoded_frames:
            mtype_str = frame.get("mtype_str", "Unknown")
            mtype_dist[mtype_str] = mtype_dist.get(mtype_str, 0) + 1
            mac_cmd_count += len(frame.get("all_mac_commands", []))
            if frame.get("lorawan_version") == "1.1":
                v11_count += 1

        summary = (
            f"Decoded {len(decoded_frames)} frames ({len(errors)} errors), "
            f"{mac_cmd_count} MAC commands, "
            f"{v11_count} LoRaWAN 1.1 frames detected"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "decoded_frames", "data": decoded_frames[:100]},
                {"type": "mtype_distribution", "data": mtype_dist},
                {"type": "decode_errors", "data": errors[:20]},
            ],
            metrics={
                "frames_decoded": len(decoded_frames),
                "decode_errors": len(errors),
                "mac_commands": mac_cmd_count,
                "mtype_distribution": mtype_dist,
                "lorawan_v11_frames": v11_count,
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
