"""Tests for srt.analysis.wifi.probe_fingerprinter."""

from __future__ import annotations

from srt.analysis.wifi.probe_fingerprinter import _compute_fingerprint, _is_random_mac


class TestComputeFingerprint:
    def test_deterministic(self):
        """Same inputs produce the same hash."""
        ie_ids = [1, 45, 50, 127, 191]
        rates = [6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0]
        fp1 = _compute_fingerprint(ie_ids, rates, True, True, False)
        fp2 = _compute_fingerprint(ie_ids, rates, True, True, False)
        assert fp1 == fp2
        assert len(fp1) == 16  # sha256 truncated to 16 hex chars

    def test_different_inputs_different_hash(self):
        """Different inputs produce different hashes."""
        fp1 = _compute_fingerprint([1, 45, 50], [6.0, 12.0], True, False, False)
        fp2 = _compute_fingerprint([1, 45, 191], [6.0, 24.0], True, True, False)
        assert fp1 != fp2

    def test_order_independent(self):
        """IE IDs and rates are sorted internally, so order should not matter."""
        fp1 = _compute_fingerprint([50, 1, 45], [12.0, 6.0], True, False, False)
        fp2 = _compute_fingerprint([1, 45, 50], [6.0, 12.0], True, False, False)
        assert fp1 == fp2

    def test_he_capability_changes_hash(self):
        """HE (Wi-Fi 6) flag changes the fingerprint."""
        fp1 = _compute_fingerprint([1, 45], [6.0], True, True, False)
        fp2 = _compute_fingerprint([1, 45], [6.0], True, True, True)
        assert fp1 != fp2


class TestIsRandomMac:
    def test_locally_administered_mac(self):
        """MAC with bit 1 of first byte set (0x02) is random."""
        assert _is_random_mac("02:11:22:33:44:55") is True
        assert _is_random_mac("06:AA:BB:CC:DD:EE") is True
        assert _is_random_mac("0A:00:00:00:00:01") is True

    def test_global_mac(self):
        """MAC with bit 1 of first byte clear is global (not random)."""
        assert _is_random_mac("00:11:22:33:44:55") is False
        assert _is_random_mac("AC:DE:48:00:11:22") is False

    def test_empty_mac(self):
        assert _is_random_mac("") is False
        assert _is_random_mac("x") is False

    def test_dash_separated_mac(self):
        """Also works with dash separator."""
        assert _is_random_mac("02-11-22-33-44-55") is True
        assert _is_random_mac("00-11-22-33-44-55") is False
