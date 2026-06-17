"""Tests for srt.cli.main using click.testing.CliRunner."""

from __future__ import annotations

from textwrap import dedent
from unittest.mock import patch

from click.testing import CliRunner

from srt.cli.main import cli


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_help(self):
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "sniffer-rt" in result.output

    def test_info_command(self):
        result = self.runner.invoke(cli, ["info"])
        assert result.exit_code == 0
        assert "sniffer-rt" in result.output

    def test_list_command(self):
        result = self.runner.invoke(cli, ["list"])
        assert result.exit_code == 0
        assert "Modules" in result.output

    def test_list_with_protocol_filter(self):
        result = self.runner.invoke(cli, ["list", "--protocol", "wifi"])
        assert result.exit_code == 0

    def test_list_with_risk_filter(self):
        result = self.runner.invoke(cli, ["list", "--risk", "passive"])
        assert result.exit_code == 0

    def test_selftest_fails_no_hardware(self):
        result = self.runner.invoke(cli, ["selftest"])
        # Should fail because no SDR and no DB
        assert result.exit_code == 1

    def test_run_dry_run(self):
        result = self.runner.invoke(
            cli, ["run", "wifi.security_assessor", "--dry-run"]
        )
        assert result.exit_code == 0

    def test_run_unknown_module(self):
        result = self.runner.invoke(cli, ["run", "nonexistent.module"])
        assert result.exit_code != 0

    def test_run_with_params(self):
        result = self.runner.invoke(
            cli,
            ["run", "wifi.security_assessor", "--dry-run", "-p", "timeout=30"],
        )
        assert result.exit_code == 0

    def test_run_bad_param_format(self):
        result = self.runner.invoke(
            cli,
            ["run", "wifi.security_assessor", "--dry-run", "-p", "badparam"],
        )
        assert result.exit_code != 0

    def test_scenario_command(self, tmp_path):
        scenario_yaml = dedent("""\
            name: test-scenario
            description: test
            steps:
              - module: lora.anomaly_detector
                params: {}
        """)
        p = tmp_path / "test.yaml"
        p.write_text(scenario_yaml)

        with patch("srt.core.reporter.REPORT_DIR", tmp_path / "reports"):
            result = self.runner.invoke(
                cli, ["scenario", str(p), "--dry-run"]
            )
            assert result.exit_code == 0
            assert "wrote" in result.output

    def test_scenario_with_var(self, tmp_path):
        scenario_yaml = dedent("""\
            name: var-test
            description: test variables
            variables:
              target: default_target
            steps:
              - module: lora.anomaly_detector
                params:
                  target: "{{target}}"
        """)
        p = tmp_path / "test.yaml"
        p.write_text(scenario_yaml)

        with patch("srt.core.reporter.REPORT_DIR", tmp_path / "reports"):
            result = self.runner.invoke(
                cli, ["scenario", str(p), "--dry-run", "--var", "target=override"]
            )
            assert result.exit_code == 0

    def test_report_no_results(self):
        result = self.runner.invoke(
            cli, ["report", "--session-id", "fake-uuid-1234"]
        )
        assert result.exit_code == 1
        assert "No results" in result.output

    def test_verbose_flag(self):
        result = self.runner.invoke(cli, ["-v", "info"])
        assert result.exit_code == 0
