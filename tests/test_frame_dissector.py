"""Tests for srt.analysis.wifi.frame_dissector parsing functions."""

from __future__ import annotations

from srt.analysis.wifi.frame_dissector import (
    _parse_ht_capabilities,
    _parse_rsn_ie,
    _parse_vht_capabilities,
)


class TestParseRsnIe:
    def test_wpa2_ccmp_psk(self):
        """Test RSN IE with WPA2 CCMP-128 + PSK AKM."""
        # RSN IE structure:
        # Version(2) + GroupCipher(4) + PairwiseCount(2) + PairwiseCipher(4)
        # + AKMCount(2) + AKM(4) + RSNCap(2)
        data = bytearray()
        data += b"\x01\x00"  # Version 1
        data += b"\x00\x0f\xac\x04"  # Group cipher: CCMP-128
        data += b"\x01\x00"  # Pairwise count: 1
        data += b"\x00\x0f\xac\x04"  # Pairwise: CCMP-128
        data += b"\x01\x00"  # AKM count: 1
        data += b"\x00\x0f\xac\x02"  # AKM: PSK
        data += b"\x80\x00"  # RSN Capabilities: PMF capable (bit 7)
        data = bytes(data)

        result = _parse_rsn_ie(data)
        assert result["version"] == 1
        assert result["group_cipher"] == "CCMP-128"
        assert result["pairwise_ciphers"] == ["CCMP-128"]
        assert result["akm_suites"] == ["PSK"]
        assert result["pmf_capable"] is True
        assert result["pmf_required"] is False

    def test_wpa3_sae_pmf_required(self):
        """Test RSN IE with SAE AKM and PMF required."""
        data = bytearray()
        data += b"\x01\x00"  # Version 1
        data += b"\x00\x0f\xac\x04"  # Group cipher: CCMP-128
        data += b"\x01\x00"  # Pairwise count: 1
        data += b"\x00\x0f\xac\x04"  # Pairwise: CCMP-128
        data += b"\x01\x00"  # AKM count: 1
        data += b"\x00\x0f\xac\x08"  # AKM: SAE
        data += b"\xc0\x00"  # RSN Cap: PMF capable (0x80) + PMF required (0x40)
        data = bytes(data)

        result = _parse_rsn_ie(data)
        assert "SAE" in result["akm_suites"]
        assert result["pmf_capable"] is True
        assert result["pmf_required"] is True

    def test_empty_data(self):
        result = _parse_rsn_ie(b"\x01")
        assert "raw_hex" in result


class TestParseHtCapabilities:
    def test_known_ht_bytes(self):
        """Test HT Capabilities with known values: 40 MHz, short GI 20 MHz."""
        # Capability info: channel_width_40mhz (bit 1) + short_gi_20 (bit 5)
        cap_info = 0x0002 | 0x0020  # 40 MHz + short GI 20
        data = cap_info.to_bytes(2, "little") + b"\x00" * 24  # pad to typical length

        result = _parse_ht_capabilities(data)
        assert result["channel_width_40mhz"] is True
        assert result["short_gi_20mhz"] is True
        assert result["ldpc_coding"] is False

    def test_ldpc_and_stbc(self):
        """Test LDPC coding and TX STBC."""
        cap_info = 0x0001 | 0x0080  # LDPC + TX STBC
        data = cap_info.to_bytes(2, "little") + b"\x00" * 24

        result = _parse_ht_capabilities(data)
        assert result["ldpc_coding"] is True
        assert result["tx_stbc"] is True

    def test_empty_data(self):
        result = _parse_ht_capabilities(b"\x00")
        assert result == {}


class TestParseVhtCapabilities:
    def test_known_vht_bytes(self):
        """Test VHT Capabilities with short GI 80 MHz."""
        # bit 5 = short_gi_80mhz
        cap_info = 0x00000020
        data = cap_info.to_bytes(4, "little") + b"\x00" * 8

        result = _parse_vht_capabilities(data)
        assert result["short_gi_80mhz"] is True
        assert result["short_gi_160mhz"] is False

    def test_beamformer_capable(self):
        """Test SU beamformer capability (bit 11)."""
        cap_info = 0x00000800
        data = cap_info.to_bytes(4, "little") + b"\x00" * 8

        result = _parse_vht_capabilities(data)
        assert result["su_beamformer"] is True
        assert result["su_beamformee"] is False

    def test_empty_data(self):
        result = _parse_vht_capabilities(b"\x00\x01\x02")
        assert result == {}
