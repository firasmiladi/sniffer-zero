"""Tests for srt.analysis.wifi.security_assessor._grade_ap."""

from __future__ import annotations

from srt.analysis.wifi.security_assessor import _grade_ap


class TestGradeAP:
    def test_open_network_grade_f(self):
        result = _grade_ap(
            encryption="OPEN",
            pmf_capable=False,
            pmf_required=False,
            wps_enabled=False,
            ciphers=[],
            akms=[],
        )
        assert result["grade"] == "F"

    def test_wep_grade_e(self):
        result = _grade_ap(
            encryption="WEP",
            pmf_capable=False,
            pmf_required=False,
            wps_enabled=False,
            ciphers=[],
            akms=[],
        )
        assert result["grade"] == "E"

    def test_wpa2_ccmp_pmf_capable_grade_b(self):
        result = _grade_ap(
            encryption="WPA2",
            pmf_capable=True,
            pmf_required=False,
            wps_enabled=False,
            ciphers=["CCMP-128"],
            akms=["PSK"],
        )
        assert result["grade"] == "B"

    def test_wpa3_sae_pmf_required_grade_a(self):
        result = _grade_ap(
            encryption="WPA2",
            pmf_capable=True,
            pmf_required=True,
            wps_enabled=False,
            ciphers=["CCMP-128"],
            akms=["SAE"],
        )
        assert result["grade"] == "A"

    def test_wps_enabled_downgrades(self):
        result = _grade_ap(
            encryption="WPA2",
            pmf_capable=True,
            pmf_required=True,
            wps_enabled=True,
            ciphers=["CCMP-128"],
            akms=["SAE"],
        )
        assert result["grade"] == "C"

    def test_tkip_cipher_grade_d(self):
        result = _grade_ap(
            encryption="WPA2",
            pmf_capable=False,
            pmf_required=False,
            wps_enabled=False,
            ciphers=["TKIP"],
            akms=["PSK"],
        )
        assert result["grade"] == "D"

    def test_wpa_legacy_grade_e(self):
        result = _grade_ap(
            encryption="WPA",
            pmf_capable=False,
            pmf_required=False,
            wps_enabled=False,
            ciphers=["TKIP"],
            akms=["PSK"],
        )
        assert result["grade"] == "E"

    def test_wpa3_pmf_required_grade_a(self):
        result = _grade_ap(
            encryption="WPA3",
            pmf_capable=True,
            pmf_required=True,
            wps_enabled=False,
            ciphers=["GCMP-256"],
            akms=["SAE"],
        )
        assert result["grade"] == "A"
