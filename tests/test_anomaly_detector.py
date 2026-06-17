"""Tests for srt.analysis.lora.anomaly_detector detection methods."""

from __future__ import annotations

from srt.analysis.lora.anomaly_detector import LoraAnomalyDetector


class TestFcntAnomalies:
    def setup_method(self):
        self.detector = LoraAnomalyDetector()

    def test_fcnt_rollback_detected(self):
        frames = [
            {"dev_addr": "01020304", "fcnt": 100, "ts": 1000.0},
            {"dev_addr": "01020304", "fcnt": 50, "ts": 1010.0},  # rollback
        ]
        anomalies = self.detector._detect_fcnt_anomalies(frames)
        assert len(anomalies) == 1
        assert anomalies[0]["type"] == "fcnt_rollback"
        assert anomalies[0]["severity"] == "high"
        assert anomalies[0]["prev_fcnt"] == 100
        assert anomalies[0]["curr_fcnt"] == 50

    def test_fcnt_gap_detected(self):
        frames = [
            {"dev_addr": "01020304", "fcnt": 10, "ts": 1000.0},
            {"dev_addr": "01020304", "fcnt": 25, "ts": 1010.0},  # gap of 15 > threshold 10
        ]
        anomalies = self.detector._detect_fcnt_anomalies(frames)
        assert len(anomalies) == 1
        assert anomalies[0]["type"] == "fcnt_gap"
        assert anomalies[0]["gap"] == 15

    def test_normal_fcnt_no_anomaly(self):
        frames = [
            {"dev_addr": "01020304", "fcnt": 10, "ts": 1000.0},
            {"dev_addr": "01020304", "fcnt": 11, "ts": 1010.0},
            {"dev_addr": "01020304", "fcnt": 12, "ts": 1020.0},
        ]
        anomalies = self.detector._detect_fcnt_anomalies(frames)
        assert len(anomalies) == 0


class TestDuplicates:
    def setup_method(self):
        self.detector = LoraAnomalyDetector()

    def test_duplicate_within_window(self):
        frames = [
            {"dev_addr": "01020304", "fcnt": 10, "fport": 1, "ts": 1000.0},
            {"dev_addr": "01020304", "fcnt": 10, "fport": 1, "ts": 1030.0},  # same within 60s
        ]
        duplicates = self.detector._detect_duplicates(frames)
        assert len(duplicates) == 1
        assert duplicates[0]["type"] == "duplicate_frame"
        assert duplicates[0]["severity"] == "high"

    def test_no_duplicate_outside_window(self):
        frames = [
            {"dev_addr": "01020304", "fcnt": 10, "fport": 1, "ts": 1000.0},
            {"dev_addr": "01020304", "fcnt": 10, "fport": 1, "ts": 1100.0},  # >60s apart
        ]
        duplicates = self.detector._detect_duplicates(frames)
        assert len(duplicates) == 0

    def test_different_devaddr_no_duplicate(self):
        frames = [
            {"dev_addr": "01020304", "fcnt": 10, "fport": 1, "ts": 1000.0},
            {"dev_addr": "AABBCCDD", "fcnt": 10, "fport": 1, "ts": 1010.0},
        ]
        duplicates = self.detector._detect_duplicates(frames)
        assert len(duplicates) == 0


class TestDevnonceReuse:
    def setup_method(self):
        self.detector = LoraAnomalyDetector()

    def test_devnonce_reuse_detected(self):
        frames = [
            {"mtype": 0, "dev_eui": "0011223344556677", "dev_nonce": 1234, "ts": 1000.0},
            {"mtype": 0, "dev_eui": "0011223344556677", "dev_nonce": 1234, "ts": 1010.0},
        ]
        anomalies = self.detector._detect_devnonce_reuse(frames)
        assert len(anomalies) == 1
        assert anomalies[0]["type"] == "devnonce_reuse"
        assert anomalies[0]["severity"] == "critical"
        assert anomalies[0]["count"] == 2

    def test_unique_nonces_no_anomaly(self):
        frames = [
            {"mtype": 0, "dev_eui": "0011223344556677", "dev_nonce": 1234, "ts": 1000.0},
            {"mtype": 0, "dev_eui": "0011223344556677", "dev_nonce": 5678, "ts": 1010.0},
        ]
        anomalies = self.detector._detect_devnonce_reuse(frames)
        assert len(anomalies) == 0

    def test_non_join_request_ignored(self):
        frames = [
            {"mtype": 2, "dev_eui": "0011223344556677", "dev_nonce": 1234, "ts": 1000.0},
            {"mtype": 2, "dev_eui": "0011223344556677", "dev_nonce": 1234, "ts": 1010.0},
        ]
        anomalies = self.detector._detect_devnonce_reuse(frames)
        assert len(anomalies) == 0


class TestTimingAnomalies:
    def setup_method(self):
        self.detector = LoraAnomalyDetector()

    def test_timing_outlier_detected(self):
        # 5 frames with regular 10s intervals, then one with a 100s gap
        # Intervals: [10, 10, 10, 10, 100], avg = 28, 100/28 = 3.57x > 3.0
        frames = [
            {"dev_addr": "01020304", "ts": 1000.0},
            {"dev_addr": "01020304", "ts": 1010.0},
            {"dev_addr": "01020304", "ts": 1020.0},
            {"dev_addr": "01020304", "ts": 1030.0},
            {"dev_addr": "01020304", "ts": 1040.0},
            {"dev_addr": "01020304", "ts": 1140.0},  # 100s gap
        ]
        anomalies = self.detector._detect_timing_anomalies(frames)
        assert len(anomalies) == 1
        assert anomalies[0]["type"] == "timing_anomaly"
        assert anomalies[0]["severity"] == "low"

    def test_regular_timing_no_anomaly(self):
        # All intervals are uniform 10s
        frames = [
            {"dev_addr": "01020304", "ts": 1000.0},
            {"dev_addr": "01020304", "ts": 1010.0},
            {"dev_addr": "01020304", "ts": 1020.0},
            {"dev_addr": "01020304", "ts": 1030.0},
            {"dev_addr": "01020304", "ts": 1040.0},
        ]
        anomalies = self.detector._detect_timing_anomalies(frames)
        assert len(anomalies) == 0

    def test_too_few_frames_skipped(self):
        frames = [
            {"dev_addr": "01020304", "ts": 1000.0},
            {"dev_addr": "01020304", "ts": 1010.0},
        ]
        anomalies = self.detector._detect_timing_anomalies(frames)
        assert len(anomalies) == 0
