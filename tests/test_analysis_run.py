"""Tests for analysis module run() methods with mocked DB data."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from unittest.mock import MagicMock

from srt.core.module import ModuleContext, Status


def _make_ctx(dry_run: bool = False) -> ModuleContext:
    return ModuleContext(
        session_id=uuid.uuid4(),
        operator="pytest",
        params={},
        dry_run=dry_run,
        authorization_ok=True,
        authorized_bands_mhz=["868", "2400"],
        whitelist={},
    )


class TestSecurityAssessorRun:
    """Test WiFiSecurityAssessor.run() with mocked DB results."""

    def test_run_with_beacon_data(self, monkeypatch):
        from srt.analysis.wifi.security_assessor import WiFiSecurityAssessor

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ("AA:BB:CC:DD:EE:FF", {
                "encryption": "WPA2",
                "pmf_capable": True,
                "pmf_required": False,
                "wps_enabled": False,
                "ciphers": ["CCMP-128"],
                "akms": ["PSK"],
                "ssid": "TestNet",
            }),
            ("11:22:33:44:55:66", {
                "encryption": "OPEN",
                "pmf_capable": False,
                "pmf_required": False,
                "wps_enabled": False,
                "ciphers": [],
                "akms": [],
                "ssid": "FreeWiFi",
            }),
        ]
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        @contextmanager
        def fake_connect():
            yield mock_conn

        monkeypatch.setattr("srt.core.db.connect", fake_connect)

        assessor = WiFiSecurityAssessor()
        ctx = _make_ctx(dry_run=False)
        result = assessor.run(ctx)

        assert result.status == Status.OK
        assert "2 APs" in result.summary
        assert result.metrics["ap_count"] == 2

    def test_run_dry_run(self):
        from srt.analysis.wifi.security_assessor import WiFiSecurityAssessor

        assessor = WiFiSecurityAssessor()
        ctx = _make_ctx(dry_run=True)
        result = assessor.run(ctx)
        assert result.status == Status.OK
        assert "DRY-RUN" in result.summary

    def test_run_db_error(self, monkeypatch):
        from srt.analysis.wifi.security_assessor import WiFiSecurityAssessor

        @contextmanager
        def failing_connect():
            raise Exception("connection refused")
            yield  # type: ignore[misc]

        monkeypatch.setattr("srt.core.db.connect", failing_connect)

        assessor = WiFiSecurityAssessor()
        ctx = _make_ctx(dry_run=False)
        result = assessor.run(ctx)
        assert result.status == Status.FAIL


class TestAnomalyDetectorRun:
    """Test LoraAnomalyDetector.run() with mocked DB data."""

    def test_run_with_frame_data(self, monkeypatch):
        # Build sample hex payloads (valid data uplink frames)
        import struct

        from srt.analysis.lora.anomaly_detector import LoraAnomalyDetector

        def _make_frame_hex(dev_addr_int, fcnt):
            mhdr = 0x40  # mtype=2
            dev_addr = struct.pack("<I", dev_addr_int)
            fctrl = 0x00
            fcnt_bytes = struct.pack("<H", fcnt)
            fport = bytes([1])
            payload = b"\xAA\xBB"
            mic = b"\x11\x22\x33\x44"
            raw = bytes([mhdr]) + dev_addr + bytes([fctrl]) + fcnt_bytes + fport + payload + mic
            return raw.hex()

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            (1000.0, {"raw_payload": _make_frame_hex(0x01020304, 10)}),
            (1010.0, {"raw_payload": _make_frame_hex(0x01020304, 11)}),
            (1020.0, {"raw_payload": _make_frame_hex(0x01020304, 12)}),
            (1030.0, {"raw_payload": _make_frame_hex(0x01020304, 5)}),  # rollback
        ]
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        @contextmanager
        def fake_connect():
            yield mock_conn

        monkeypatch.setattr("srt.core.db.connect", fake_connect)

        detector = LoraAnomalyDetector()
        ctx = _make_ctx(dry_run=False)
        result = detector.run(ctx)

        assert result.status == Status.OK
        assert result.metrics["total_anomalies"] > 0
        assert result.metrics["frames_analyzed"] == 4

    def test_run_dry_run(self):
        from srt.analysis.lora.anomaly_detector import LoraAnomalyDetector

        detector = LoraAnomalyDetector()
        ctx = _make_ctx(dry_run=True)
        result = detector.run(ctx)
        assert result.status == Status.OK
        assert "DRY-RUN" in result.summary


class TestProbeFingerprinterRun:
    """Test WiFiProbeFingerprinter.run() with mocked DB data."""

    def test_run_with_probe_data(self, monkeypatch):
        from srt.analysis.wifi.probe_fingerprinter import WiFiProbeFingerprinter

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ("02:AA:BB:CC:DD:EE", {
                "ie_ids": [1, 45, 50, 127],
                "rates_mbps": [6.0, 12.0, 24.0],
                "ht_present": True,
                "vht_present": False,
                "he_present": False,
                "ssid": "HomeNet",
                "frame_type": "probe_request",
            }),
            ("00:11:22:33:44:55", {
                "ie_ids": [1, 45, 191, 127],
                "rates_mbps": [6.0, 12.0, 24.0, 54.0],
                "ht_present": True,
                "vht_present": True,
                "he_present": False,
                "ssid": "OfficeNet",
                "frame_type": "probe_request",
            }),
        ]
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        @contextmanager
        def fake_connect():
            yield mock_conn

        monkeypatch.setattr("srt.core.db.connect", fake_connect)

        fp = WiFiProbeFingerprinter()
        ctx = _make_ctx(dry_run=False)
        result = fp.run(ctx)

        assert result.status == Status.OK
        assert result.metrics["total_devices"] == 2
        assert result.metrics["random_mac_count"] == 1  # 02:... is random

    def test_run_dry_run(self):
        from srt.analysis.wifi.probe_fingerprinter import WiFiProbeFingerprinter

        fp = WiFiProbeFingerprinter()
        ctx = _make_ctx(dry_run=True)
        result = fp.run(ctx)
        assert result.status == Status.OK
        assert "DRY-RUN" in result.summary
