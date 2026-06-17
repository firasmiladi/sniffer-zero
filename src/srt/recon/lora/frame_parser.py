"""LoRaWAN PHYPayload frame parser.

Pure-Python implementation -- no scapy-lorawan dependency required.
Parses raw LoRaWAN PHYPayload bytes into structured dictionaries with
MHDR, MACPayload (FHDR + FPort + FRMPayload), and MIC fields.

Supports:
  - Join Request (MType 0)
  - Join Accept  (MType 1)
  - Unconfirmed Data Up/Down (MType 2/3)
  - Confirmed Data Up/Down (MType 4/5)
"""

from __future__ import annotations

import struct
from typing import Any

# ---------------------------------------------------------------------------
# EU868 channel plan constants
# ---------------------------------------------------------------------------

CHANNELS: dict[int, int] = {
    0: 868_100_000,
    1: 868_300_000,
    2: 868_500_000,
    3: 867_100_000,
    4: 867_300_000,
    5: 867_500_000,
    6: 867_700_000,
    7: 867_900_000,
}

EU868_BEACON_FREQ = 869_525_000
EU868_RX2_FREQ = 869_525_000

# Spreading factors
SF_RANGE = list(range(7, 13))  # SF7 .. SF12

# MType mapping (bits 7-5 of MHDR)
MTYPE_MAP: dict[int, str] = {
    0: "JoinRequest",
    1: "JoinAccept",
    2: "UnconfDataUp",
    3: "UnconfDataDown",
    4: "ConfDataUp",
    5: "ConfDataDown",
    6: "RFU",
    7: "Proprietary",
}

# Major version (bits 1-0 of MHDR)
MAJOR_MAP: dict[int, str] = {
    0: "LoRaWAN_R1",
    1: "RFU",
    2: "RFU",
    3: "RFU",
}


class LoRaWANParser:
    """Stateless LoRaWAN PHYPayload parser."""

    def parse(self, raw_bytes: bytes) -> dict[str, Any]:
        """Parse a raw LoRaWAN PHYPayload.

        Returns a dict with at minimum:
          - mhdr: int (raw byte)
          - mtype: int (0-7)
          - mtype_str: human-readable MType string
          - major: int
          - major_str: major version string
          - mic: bytes (last 4 bytes)

        Additional fields depend on MType.
        """
        if len(raw_bytes) < 5:
            return {"error": "payload_too_short", "raw_hex": raw_bytes.hex()}

        mhdr = raw_bytes[0]
        mtype = (mhdr >> 5) & 0x07
        major = mhdr & 0x03

        result: dict[str, Any] = {
            "mhdr": mhdr,
            "mtype": mtype,
            "mtype_str": MTYPE_MAP.get(mtype, "Unknown"),
            "major": major,
            "major_str": MAJOR_MAP.get(major, "Unknown"),
        }

        if mtype == 0:
            self._parse_join_request(raw_bytes, result)
        elif mtype == 1:
            self._parse_join_accept(raw_bytes, result)
        elif mtype in (2, 3, 4, 5):
            self._parse_data_frame(raw_bytes, mtype, result)
        else:
            result["mic"] = raw_bytes[-4:].hex()
            result["payload_hex"] = raw_bytes[1:-4].hex()

        return result

    def _parse_join_request(self, raw: bytes, result: dict[str, Any]) -> None:
        """Parse Join Request: AppEUI(8) + DevEUI(8) + DevNonce(2) + MIC(4) = 23 bytes total."""
        if len(raw) < 23:
            result["error"] = "join_request_too_short"
            return

        # AppEUI: 8 bytes, little-endian
        app_eui = raw[1:9][::-1]
        # DevEUI: 8 bytes, little-endian
        dev_eui = raw[9:17][::-1]
        # DevNonce: 2 bytes, little-endian
        dev_nonce = struct.unpack_from("<H", raw, 17)[0]
        # MIC: last 4 bytes
        mic = raw[19:23]

        result["app_eui"] = app_eui.hex()
        result["dev_eui"] = dev_eui.hex()
        result["dev_nonce"] = dev_nonce
        result["mic"] = mic.hex()

    def _parse_join_accept(self, raw: bytes, result: dict[str, Any]) -> None:
        """Parse Join Accept (encrypted payload, minimal extraction).

        Join Accept is AES-encrypted with AppKey; we can only extract MIC
        position and note that decryption requires AppKey.
        """
        # Minimum: MHDR(1) + encrypted(12 or 28) = 13 or 29 bytes
        if len(raw) < 13:
            result["error"] = "join_accept_too_short"
            return

        # The entire payload after MHDR is encrypted; MIC is inside the ciphertext
        result["encrypted_payload_hex"] = raw[1:].hex()
        result["encrypted_len"] = len(raw) - 1
        result["note"] = "join_accept_encrypted_with_appkey"

    def _parse_data_frame(self, raw: bytes, mtype: int, result: dict[str, Any]) -> None:
        """Parse Data frame (MType 2-5): FHDR + FPort + FRMPayload + MIC."""
        # Minimum: MHDR(1) + DevAddr(4) + FCtrl(1) + FCnt(2) + MIC(4) = 12 bytes
        if len(raw) < 12:
            result["error"] = "data_frame_too_short"
            return

        # MIC is always the last 4 bytes
        mic = raw[-4:]
        mac_payload = raw[1:-4]

        # DevAddr: 4 bytes, little-endian
        dev_addr = struct.unpack_from("<I", mac_payload, 0)[0]
        # FCtrl: 1 byte
        fctrl = mac_payload[4]
        # FCnt: 2 bytes, little-endian
        fcnt = struct.unpack_from("<H", mac_payload, 5)[0]

        # FCtrl bit fields
        adr = bool(fctrl & 0x80)
        ack = bool(fctrl & 0x20)
        fpending = bool(fctrl & 0x10) if mtype in (3, 5) else False
        class_b = bool(fctrl & 0x10) if mtype in (2, 4) else False
        fopts_len = fctrl & 0x0F

        result["dev_addr"] = f"{dev_addr:08X}"
        result["fctrl"] = fctrl
        result["fcnt"] = fcnt
        result["adr"] = adr
        result["ack"] = ack
        result["fpending"] = fpending
        result["class_b"] = class_b
        result["fopts_len"] = fopts_len
        result["mic"] = mic.hex()

        # Direction: 0 = uplink, 1 = downlink
        direction = 0 if mtype in (2, 4) else 1
        result["direction"] = direction

        # FOpts (MAC commands in header)
        offset = 7  # after DevAddr(4) + FCtrl(1) + FCnt(2)
        fopts = b""
        if fopts_len > 0:
            fopts = mac_payload[offset:offset + fopts_len]
            result["fopts_hex"] = fopts.hex()
        offset += fopts_len

        # FPort and FRMPayload (if remaining bytes after FOpts)
        remaining = mac_payload[offset:]
        if len(remaining) > 0:
            fport = remaining[0]
            result["fport"] = fport
            frm_payload = remaining[1:]
            if frm_payload:
                result["frm_payload_hex"] = frm_payload.hex()
                result["frm_payload_len"] = len(frm_payload)
        else:
            result["fport"] = None
            result["frm_payload_hex"] = ""
            result["frm_payload_len"] = 0

    @staticmethod
    def compute_mic_b0_block(
        direction: int,
        devaddr: int,
        fcnt: int,
        payload_len: int,
    ) -> bytes:
        """Compute the B0 block used for MIC calculation (AES-CMAC).

        Per LoRaWAN 1.0.x specification section 4.4:
          B0 = 0x49 | 0x00000000 | Dir | DevAddr(LE) | FCntUp/Down(LE,4) | 0x00 | len

        Args:
            direction: 0 for uplink, 1 for downlink
            devaddr: 32-bit device address
            fcnt: frame counter (full 32-bit)
            payload_len: length of msg (MHDR | FHDR | FPort | FRMPayload)

        Returns:
            16-byte B0 block for AES-CMAC input
        """
        b0 = struct.pack(
            "<BIBIHBB",
            0x49,           # fixed prefix
            0x00000000,     # 4 zero bytes (conf_fcnt in 1.1, zero in 1.0)
            direction,      # Dir: 0=up, 1=down
            devaddr,        # DevAddr little-endian
            fcnt,           # FCnt little-endian (32-bit)
            0x00,           # padding
            payload_len,    # len(msg)
        )
        return b0

    @staticmethod
    def freq_to_channel(freq_hz: int) -> int | None:
        """Map a frequency in Hz to an EU868 channel index."""
        for ch, f in CHANNELS.items():
            if f == freq_hz:
                return ch
        return None

    @staticmethod
    def channel_to_freq(channel: int) -> int | None:
        """Map an EU868 channel index to frequency in Hz."""
        return CHANNELS.get(channel)
