"""Tests for srt.recon.lora.frame_parser.LoRaWANParser."""

from __future__ import annotations

import struct

from srt.recon.lora.frame_parser import LoRaWANParser


def _build_join_request() -> bytes:
    """Build a valid 23-byte Join Request (mtype=0).

    Structure: MHDR(1) + AppEUI(8) + DevEUI(8) + DevNonce(2) + MIC(4) = 23
    """
    mhdr = 0x00  # mtype=0, major=0
    app_eui = bytes.fromhex("0102030405060708")  # little-endian in frame
    dev_eui = bytes.fromhex("1112131415161718")
    dev_nonce = struct.pack("<H", 0xABCD)
    mic = b"\xDE\xAD\xBE\xEF"
    return bytes([mhdr]) + app_eui + dev_eui + dev_nonce + mic


def _build_data_uplink() -> bytes:
    """Build a valid unconfirmed data uplink frame (mtype=2).

    Structure: MHDR(1) + DevAddr(4) + FCtrl(1) + FCnt(2) + FPort(1) + Payload(4) + MIC(4) = 17
    """
    mhdr = 0x40  # mtype=2 (bits 7-5 = 010), major=0
    dev_addr = struct.pack("<I", 0x01020304)
    fctrl = 0x80  # ADR=1, others=0, FOptsLen=0
    fcnt = struct.pack("<H", 42)
    fport = bytes([1])
    frm_payload = b"\xAA\xBB\xCC\xDD"
    mic = b"\x11\x22\x33\x44"
    return bytes([mhdr]) + dev_addr + bytes([fctrl]) + fcnt + fport + frm_payload + mic


class TestLoRaWANParser:
    def setup_method(self):
        self.parser = LoRaWANParser()

    def test_parse_join_request(self):
        raw = _build_join_request()
        result = self.parser.parse(raw)

        assert result["mtype"] == 0
        assert result["mtype_str"] == "JoinRequest"
        # AppEUI is reversed (little-endian -> big-endian for display)
        assert "app_eui" in result
        assert "dev_eui" in result
        assert result["dev_nonce"] == 0xABCD
        assert result["mic"] == "deadbeef"

    def test_parse_data_uplink(self):
        raw = _build_data_uplink()
        result = self.parser.parse(raw)

        assert result["mtype"] == 2
        assert result["mtype_str"] == "UnconfDataUp"
        assert result["dev_addr"] == "01020304"
        assert result["fcnt"] == 42
        assert result["fport"] == 1
        assert result["adr"] is True
        assert result["direction"] == 0  # uplink

    def test_parse_too_short(self):
        raw = b"\x00\x01\x02"  # Only 3 bytes
        result = self.parser.parse(raw)

        assert result.get("error") == "payload_too_short"

    def test_freq_to_channel(self):
        assert LoRaWANParser.freq_to_channel(868_100_000) == 0
        assert LoRaWANParser.freq_to_channel(868_300_000) == 1
        assert LoRaWANParser.freq_to_channel(868_500_000) == 2
        assert LoRaWANParser.freq_to_channel(999_999_999) is None

    def test_channel_to_freq(self):
        assert LoRaWANParser.channel_to_freq(0) == 868_100_000
        assert LoRaWANParser.channel_to_freq(1) == 868_300_000
        assert LoRaWANParser.channel_to_freq(99) is None

    def test_compute_mic_b0_block(self):
        b0 = LoRaWANParser.compute_mic_b0_block(
            direction=0,
            devaddr=0x01020304,
            fcnt=42,
            payload_len=16,
        )
        # The struct format <BIBIHBB gives 14 bytes (packed)
        assert len(b0) == struct.calcsize("<BIBIHBB")
        assert b0[0] == 0x49  # fixed prefix

    def test_parse_join_accept(self):
        """Join accept is encrypted, but we should get encrypted_payload_hex."""
        # MHDR(1) + encrypted(12) = 13 bytes minimum
        mhdr = 0x20  # mtype=1 (JoinAccept)
        raw = bytes([mhdr]) + b"\x01" * 12
        result = self.parser.parse(raw)
        assert result["mtype"] == 1
        assert result["mtype_str"] == "JoinAccept"
        assert "encrypted_payload_hex" in result

    def test_parse_data_downlink(self):
        """Test data downlink frame (mtype=3)."""
        mhdr = 0x60  # mtype=3 (UnconfDataDown), major=0
        dev_addr = struct.pack("<I", 0xAABBCCDD)
        fctrl = 0x10  # FPending=1 for downlink
        fcnt = struct.pack("<H", 99)
        fport = bytes([2])
        payload = b"\xFF" * 4
        mic = b"\x01\x02\x03\x04"
        raw = bytes([mhdr]) + dev_addr + bytes([fctrl]) + fcnt + fport + payload + mic
        result = self.parser.parse(raw)
        assert result["mtype"] == 3
        assert result["direction"] == 1  # downlink
        assert result["fpending"] is True
        assert result["fcnt"] == 99
        assert result["fport"] == 2

    def test_parse_data_frame_with_fopts(self):
        """Test data frame with FOpts (MAC commands in header)."""
        mhdr = 0x40  # mtype=2 (UnconfDataUp), major=0
        dev_addr = struct.pack("<I", 0x11223344)
        fopts_len = 3
        fctrl = 0x00 | fopts_len  # FOptsLen=3
        fcnt = struct.pack("<H", 5)
        fopts = b"\x02\x03\x04"  # 3 bytes of FOpts
        mic = b"\xAA\xBB\xCC\xDD"
        raw = bytes([mhdr]) + dev_addr + bytes([fctrl]) + fcnt + fopts + mic
        result = self.parser.parse(raw)
        assert result["fopts_len"] == 3
        assert result["fopts_hex"] == "020304"

    def test_parse_proprietary_frame(self):
        """Test proprietary frame (mtype=7)."""
        mhdr = 0xE0  # mtype=7 (Proprietary), major=0
        payload = b"\x01\x02\x03\x04\x05"
        mic = b"\xAA\xBB\xCC\xDD"
        raw = bytes([mhdr]) + payload + mic
        result = self.parser.parse(raw)
        assert result["mtype"] == 7
        assert result["mtype_str"] == "Proprietary"
        assert "payload_hex" in result
