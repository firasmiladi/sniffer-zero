"""Tests for HackRF sweep integration.

Tests the hackrf_sweep wrapper, spectrum_sweep attack module,
and the spectrum API endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from srt.gnuradio.hackrf_sweep import (
    HackRFSweep,
    SweepBin,
    SweepResult,
    parse_sweep_line,
    _classify_band,
)
from srt.web.app import create_app
from srt.web.state import reset_state


# --------------------------------------------------------------------------- #
# Fixtures                                                                      #
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _reset():
    """Reset app state between tests."""
    reset_state()
    from srt.web.api.spectrum import reset_spectrum_state
    reset_spectrum_state()
    yield
    reset_state()
    reset_spectrum_state()


@pytest.fixture
def client():
    """FastAPI test client."""
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def sample_csv_output():
    """Sample hackrf_sweep CSV output for testing."""
    return (
        "2026-06-12, 05:21:34.081576, 2400000000, 2405000000, 1000000.00, 20, "
        "-74.48, -66.84, -61.85, -58.96, -59.67\n"
        "2026-06-12, 05:21:34.081576, 2405000000, 2410000000, 1000000.00, 20, "
        "-72.11, -65.23, -60.10, -57.44, -58.02\n"
        "2026-06-12, 05:21:34.081576, 2410000000, 2415000000, 1000000.00, 20, "
        "-45.32, -42.15, -40.88, -43.56, -48.21\n"
    )


# --------------------------------------------------------------------------- #
# Test parse_sweep_line                                                         #
# --------------------------------------------------------------------------- #


class TestParseSweepLine:
    """Tests for CSV line parsing."""

    def test_parse_valid_line(self):
        line = "2026-06-12, 05:21:34.081576, 2400000000, 2405000000, 1000000.00, 20, -74.48, -66.84, -61.85"
        bins = parse_sweep_line(line)
        assert bins is not None
        assert len(bins) == 3
        assert bins[0].freq_hz == 2400000000.0
        assert bins[0].power_db == -74.48
        assert bins[1].freq_hz == 2401000000.0
        assert bins[1].power_db == -66.84
        assert bins[2].freq_hz == 2402000000.0
        assert bins[2].power_db == -61.85

    def test_parse_timestamp(self):
        line = "2026-06-12, 05:21:34.081576, 2400000000, 2405000000, 1000000.00, 20, -74.48"
        bins = parse_sweep_line(line)
        assert bins is not None
        assert bins[0].timestamp.year == 2026
        assert bins[0].timestamp.month == 6
        assert bins[0].timestamp.day == 12
        assert bins[0].timestamp.hour == 5
        assert bins[0].timestamp.minute == 21

    def test_parse_empty_line(self):
        assert parse_sweep_line("") is None
        assert parse_sweep_line("   ") is None

    def test_parse_comment_line(self):
        assert parse_sweep_line("# This is a comment") is None

    def test_parse_invalid_line(self):
        assert parse_sweep_line("not,enough,fields") is None

    def test_parse_line_with_many_bins(self):
        # 10 power values
        powers = ", ".join([f"-{60+i}.0" for i in range(10)])
        line = f"2026-06-12, 10:00:00.000000, 2400000000, 2410000000, 1000000.00, 20, {powers}"
        bins = parse_sweep_line(line)
        assert bins is not None
        assert len(bins) == 10
        # Check frequencies are sequential
        for i in range(1, len(bins)):
            assert bins[i].freq_hz > bins[i - 1].freq_hz


# --------------------------------------------------------------------------- #
# Test _classify_band                                                          #
# --------------------------------------------------------------------------- #


class TestClassifyBand:
    """Tests for band classification."""

    def test_classify_433(self):
        assert _classify_band(433.5) == "ISM_433MHz"

    def test_classify_868(self):
        assert _classify_band(868.0) == "ISM_868MHz"

    def test_classify_915(self):
        assert _classify_band(915.0) == "ISM_915MHz"

    def test_classify_2400(self):
        assert _classify_band(2450.0) == "ISM_2.4GHz"

    def test_classify_5200(self):
        assert _classify_band(5200.0) == "U-NII-1_5.2GHz"

    def test_classify_other(self):
        result = _classify_band(1000.0)
        assert "Other" in result


# --------------------------------------------------------------------------- #
# Test SweepResult                                                             #
# --------------------------------------------------------------------------- #


class TestSweepResult:
    """Tests for SweepResult dataclass."""

    def test_empty_result(self):
        result = SweepResult(
            timestamp=datetime.now(),
            freq_start_hz=2400e6,
            freq_end_hz=2500e6,
            bin_width_hz=1e6,
        )
        assert result.num_bins == 0
        assert result.peak_power_db == -120.0
        assert result.avg_power_db == -120.0
        assert result.noise_floor_db == -120.0

    def test_result_with_bins(self):
        now = datetime.now()
        bins = [
            SweepBin(freq_hz=2400e6, power_db=-80.0, timestamp=now),
            SweepBin(freq_hz=2401e6, power_db=-50.0, timestamp=now),
            SweepBin(freq_hz=2402e6, power_db=-70.0, timestamp=now),
        ]
        result = SweepResult(
            timestamp=now,
            freq_start_hz=2400e6,
            freq_end_hz=2403e6,
            bin_width_hz=1e6,
            bins=bins,
            duration_s=1.5,
        )
        assert result.num_bins == 3
        assert result.peak_power_db == -50.0
        assert result.freq_start_mhz == 2400.0
        assert result.freq_end_mhz == 2403.0

    def test_to_dict(self):
        now = datetime.now()
        bins = [
            SweepBin(freq_hz=2400e6, power_db=-75.0, timestamp=now),
            SweepBin(freq_hz=2401e6, power_db=-60.0, timestamp=now),
        ]
        result = SweepResult(
            timestamp=now,
            freq_start_hz=2400e6,
            freq_end_hz=2402e6,
            bin_width_hz=1e6,
            bins=bins,
            duration_s=0.8,
        )
        d = result.to_dict()
        assert "frequencies_mhz" in d
        assert "powers_db" in d
        assert len(d["frequencies_mhz"]) == 2
        assert len(d["powers_db"]) == 2
        assert d["peak_power_db"] == -60.0
        assert d["freq_start_mhz"] == 2400.0
        assert d["freq_end_mhz"] == 2402.0
        assert d["num_bins"] == 2

    def test_band_summary(self):
        now = datetime.now()
        bins = [
            SweepBin(freq_hz=2400e6, power_db=-75.0, timestamp=now),
            SweepBin(freq_hz=2410e6, power_db=-60.0, timestamp=now),
            SweepBin(freq_hz=2450e6, power_db=-50.0, timestamp=now),
        ]
        result = SweepResult(
            timestamp=now,
            freq_start_hz=2400e6,
            freq_end_hz=2500e6,
            bin_width_hz=1e6,
            bins=bins,
        )
        summary = result.get_band_summary()
        assert "ISM_2.4GHz" in summary
        assert summary["ISM_2.4GHz"]["peak_power_db"] == -50.0


# --------------------------------------------------------------------------- #
# Test HackRFSweep class                                                       #
# --------------------------------------------------------------------------- #


class TestHackRFSweep:
    """Tests for the HackRFSweep wrapper."""

    def test_build_command_single(self):
        sweep = HackRFSweep(
            freq_start_mhz=2400,
            freq_end_mhz=2500,
            bin_width_hz=1000000,
            lna_gain=32,
            vga_gain=20,
        )
        cmd = sweep._build_command(single=True)
        assert "hackrf_sweep" in cmd
        assert "-f" in cmd
        assert "2400:2500" in cmd
        assert "-w" in cmd
        assert "1000000" in cmd
        assert "-l" in cmd
        assert "32" in cmd
        assert "-g" in cmd
        assert "20" in cmd
        assert "-1" in cmd

    def test_build_command_continuous(self):
        sweep = HackRFSweep(freq_start_mhz=863, freq_end_mhz=870)
        cmd = sweep._build_command(single=False)
        assert "-1" not in cmd
        assert "863:870" in cmd

    def test_simulated_sweep(self):
        """When hardware is not available, simulated data is returned."""
        sweep = HackRFSweep(freq_start_mhz=2400, freq_end_mhz=2500)
        # Force unavailable
        with patch("shutil.which", return_value=None):
            result = sweep.single_sweep()

        assert result is not None
        assert result.num_bins > 0
        assert result.freq_start_mhz <= 2400
        assert result.freq_end_mhz >= 2499

    def test_parse_output(self, sample_csv_output):
        """Test parsing multi-line output."""
        sweep = HackRFSweep(freq_start_mhz=2400, freq_end_mhz=2415)
        result = sweep._parse_output(sample_csv_output, duration=1.0)
        assert result.num_bins == 15  # 3 lines x 5 bins each
        assert result.duration_s == 1.0

    def test_latest_result_property(self):
        sweep = HackRFSweep()
        assert sweep.latest_result is None


# --------------------------------------------------------------------------- #
# Test SpectrumSweep module                                                    #
# --------------------------------------------------------------------------- #


class TestSpectrumSweepModule:
    """Tests for the spectrum.sweep attack module."""

    def test_module_registered(self):
        """Verify the module is discoverable via registry."""
        from srt.core import registry

        registry.autodiscover()
        modules = {m.name: m for m in registry.get_all()}
        assert "spectrum.sweep" in modules

    def test_module_metadata(self):
        from srt.core import registry

        registry.autodiscover()
        mod_cls = registry.get("spectrum.sweep")
        assert mod_cls.protocol == "spectrum"
        assert mod_cls.risk.value == "passive"
        assert "hackrf" in mod_cls.requires

    def test_module_dry_run(self):
        from srt.core.module import ModuleContext
        from srt.recon.spectrum_sweep import SpectrumSweep

        module = SpectrumSweep()
        ctx = ModuleContext(
            session_id=uuid.uuid4(),
            operator="test",
            params={
                "freq_start_mhz": 2400,
                "freq_end_mhz": 2500,
                "bin_width_hz": 1000000,
            },
            dry_run=True,
        )

        result = module.run(ctx)
        assert result.status.value == "ok"
        assert "DRY RUN" in result.summary
        assert result.metrics["freq_start_mhz"] == 2400

    def test_module_single_sweep(self):
        from srt.core.module import ModuleContext
        from srt.recon.spectrum_sweep import SpectrumSweep

        module = SpectrumSweep()
        ctx = ModuleContext(
            session_id=uuid.uuid4(),
            operator="test",
            params={
                "freq_start_mhz": 2400,
                "freq_end_mhz": 2500,
                "bin_width_hz": 1000000,
                "duration_s": 0,
                "lna_gain": 32,
                "vga_gain": 20,
            },
            dry_run=False,
        )

        with patch("shutil.which", return_value=None):
            result = module.run(ctx)

        assert result.status.value == "ok"
        assert result.metrics["sweep_passes"] == 1
        assert result.metrics["total_bins"] > 0
        assert "signals_detected" in result.metrics

    def test_module_precheck_valid(self):
        from srt.core.module import ModuleContext
        from srt.recon.spectrum_sweep import SpectrumSweep

        module = SpectrumSweep()
        ctx = ModuleContext(
            session_id=uuid.uuid4(),
            operator="test",
            params={"freq_start_mhz": 2400, "freq_end_mhz": 2500},
        )
        assert module.precheck(ctx) is True

    def test_module_precheck_invalid_range(self):
        from srt.core.module import ModuleContext
        from srt.recon.spectrum_sweep import SpectrumSweep

        module = SpectrumSweep()
        ctx = ModuleContext(
            session_id=uuid.uuid4(),
            operator="test",
            params={"freq_start_mhz": 2500, "freq_end_mhz": 2400},
        )
        assert module.precheck(ctx) is False

    def test_module_precheck_out_of_range(self):
        from srt.core.module import ModuleContext
        from srt.recon.spectrum_sweep import SpectrumSweep

        module = SpectrumSweep()
        ctx = ModuleContext(
            session_id=uuid.uuid4(),
            operator="test",
            params={"freq_start_mhz": 0, "freq_end_mhz": 7000},
        )
        assert module.precheck(ctx) is False


# --------------------------------------------------------------------------- #
# Test Spectrum API endpoints                                                  #
# --------------------------------------------------------------------------- #


class TestSpectrumAPI:
    """Tests for /api/spectrum/* endpoints."""

    def test_get_live_no_data(self, client):
        resp = client.get("/api/spectrum/live")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "no_data"

    def test_post_sweep(self, client):
        """Trigger a sweep and verify response structure."""
        resp = client.post(
            "/api/spectrum/sweep",
            params={"freq_start_mhz": 2400, "freq_end_mhz": 2500},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "frequencies_mhz" in data
        assert "powers_db" in data
        assert len(data["frequencies_mhz"]) > 0
        assert len(data["powers_db"]) > 0
        assert data["freq_start_mhz"] <= 2400
        assert data["freq_end_mhz"] >= 2499

    def test_get_live_after_sweep(self, client):
        """After a sweep, GET /api/spectrum/live returns data."""
        # First trigger a sweep
        client.post(
            "/api/spectrum/sweep",
            params={"freq_start_mhz": 2400, "freq_end_mhz": 2500},
        )
        # Now check live endpoint
        resp = client.get("/api/spectrum/live")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert len(data["frequencies_mhz"]) > 0

    def test_get_bands_no_data(self, client):
        resp = client.get("/api/spectrum/bands")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "no_data"

    def test_get_bands_after_sweep(self, client):
        """After a sweep, GET /api/spectrum/bands returns band data."""
        client.post(
            "/api/spectrum/sweep",
            params={"freq_start_mhz": 2400, "freq_end_mhz": 2500},
        )
        resp = client.get("/api/spectrum/bands")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "bands" in data
        assert "ISM_2.4GHz" in data["bands"]

    def test_get_history(self, client):
        resp = client.get("/api/spectrum/history")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "sweeps" in data

    def test_sweep_invalid_range(self, client):
        resp = client.post(
            "/api/spectrum/sweep",
            params={"freq_start_mhz": 3000, "freq_end_mhz": 2000},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "error" in data

    def test_spectrum_in_health_check(self, client):
        """Health check still works with spectrum router added."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
