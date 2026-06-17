"""Tests for srt.core.orchestrator variable resolution and Scenario loading."""

from __future__ import annotations

from textwrap import dedent

from srt.core.module import Status
from srt.core.orchestrator import (
    Orchestrator,
    Scenario,
    ScenarioOptions,
    ScenarioStep,
    _resolve_dotted,
    _resolve_variables,
)


class TestResolveVariables:
    def test_simple_substitution(self):
        params = {"target": "{{device_addr}}"}
        variables = {"device_addr": "01020304"}
        result = _resolve_variables(params, variables, {}, {})
        assert result["target"] == "01020304"

    def test_cli_vars_priority(self):
        params = {"target": "{{device_addr}}"}
        variables = {"device_addr": "from_scenario"}
        cli_vars = {"device_addr": "from_cli"}
        result = _resolve_variables(params, variables, cli_vars, {})
        assert result["target"] == "from_cli"

    def test_unresolved_variable_remains(self):
        params = {"target": "{{unknown_var}}"}
        result = _resolve_variables(params, {}, {}, {})
        assert result["target"] == "{{unknown_var}}"

    def test_non_string_values_pass_through(self):
        params = {"count": 42, "enabled": True}
        result = _resolve_variables(params, {}, {}, {})
        assert result["count"] == 42
        assert result["enabled"] is True

    def test_multiple_vars_in_one_string(self):
        params = {"cmd": "{{proto}}-{{target}}"}
        variables = {"proto": "lora", "target": "device1"}
        result = _resolve_variables(params, variables, {}, {})
        assert result["cmd"] == "lora-device1"

    def test_context_resolution(self):
        params = {"target": "{{step1.status}}"}
        context = {"step1": {"status": "ok"}}
        result = _resolve_variables(params, {}, {}, context)
        assert result["target"] == "ok"


class TestResolveDotted:
    def test_simple_dotted_path(self):
        context = {"step1": {"status": "ok", "summary": "done"}}
        result = _resolve_dotted("step1.status", context)
        assert result == "ok"

    def test_array_index(self):
        context = {"step1": {"artifacts": ["file1.pcap", "file2.pcap"]}}
        result = _resolve_dotted("step1.artifacts[0]", context)
        assert result == "file1.pcap"

    def test_missing_key_returns_template(self):
        context = {"step1": {"status": "ok"}}
        result = _resolve_dotted("step1.missing_key", context)
        assert result == "{{step1.missing_key}}"

    def test_nested_dict(self):
        context = {"step1": {"metrics": {"count": 5}}}
        result = _resolve_dotted("step1.metrics.count", context)
        assert result == "5"

    def test_out_of_range_index(self):
        context = {"step1": {"artifacts": ["a"]}}
        result = _resolve_dotted("step1.artifacts[5]", context)
        assert result == "{{step1.artifacts[5]}}"


class TestScenarioLoad:
    def test_load_from_yaml(self, tmp_path):
        scenario_yaml = dedent("""\
            name: test-scenario
            description: A test scenario
            operator: tester
            variables:
              target: "01020304"
              channel: "0"
            options:
              bail_on_fail: true
              dry_run: false
              report_format:
                - json
                - markdown
            steps:
              - module: lora.anomaly_detector
                id: step1
                params:
                  target: "{{target}}"
        """)
        p = tmp_path / "test.yaml"
        p.write_text(scenario_yaml)

        scenario = Scenario.load(p)
        assert scenario.name == "test-scenario"
        assert scenario.description == "A test scenario"
        assert scenario.operator == "tester"
        assert scenario.variables["target"] == "01020304"
        assert len(scenario.steps) == 1
        assert scenario.steps[0].module == "lora.anomaly_detector"
        assert scenario.steps[0].id == "step1"

    def test_scenario_options_defaults(self):
        opts = ScenarioOptions()
        assert opts.bail_on_fail is True
        assert opts.dry_run is False
        assert opts.report_format == ["json", "markdown"]
        assert opts.loop is False
        assert opts.loop_delay_s == 60.0

    def test_load_empty_yaml(self, tmp_path):
        p = tmp_path / "empty.yaml"
        p.write_text("")
        scenario = Scenario.load(p)
        assert scenario.name == "empty"
        assert scenario.steps == []


class TestOrchestrator:
    def test_run_module_dry_run(self):
        from srt.analysis.lora.anomaly_detector import LoraAnomalyDetector

        orch = Orchestrator(dry_run=True, operator="tester")
        result = orch.run_module(LoraAnomalyDetector(), params={})
        assert result.status == Status.OK
        assert "dry-run" in result.summary

    def test_run_module_precheck_fails(self):
        from srt.exploit.wifi.deauth import WifiDeauth

        orch = Orchestrator(dry_run=False, operator="tester")
        # WifiDeauth has risk=ACTIVE_LAB, so without auth it should be refused
        result = orch.run_module(WifiDeauth(), params={})
        assert result.status == Status.REFUSED

    def test_run_scenario_dry_run(self, tmp_path):
        scenario = Scenario(
            name="test",
            description="test scenario",
            steps=[
                ScenarioStep(module="lora.anomaly_detector", params={}, id="step1"),
            ],
            variables={},
            options=ScenarioOptions(dry_run=True),
        )
        orch = Orchestrator(dry_run=True, operator="tester")
        results = orch.run_scenario(scenario)
        assert len(results) == 1
        assert results[0].status == Status.OK
