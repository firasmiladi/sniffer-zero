"""Tests for srt.core.reporter JSON, Markdown, and MITRE map output."""

from __future__ import annotations

import json
import time
from unittest.mock import patch

from srt.core.module import AttackResult, Risk, Status
from srt.core.reporter import build_mitre_map, write_json, write_markdown


def _make_result(name: str = "test.module", ttp: list[str] | None = None) -> AttackResult:
    return AttackResult(
        module_name=name,
        protocol="test",
        risk=Risk.PASSIVE,
        status=Status.OK,
        started_at=time.time() - 1,
        ended_at=time.time(),
        summary="test summary",
        mitre_ttp=ttp or ["T1040"],
        cve=[],
        artifacts=[{"type": "test", "data": "value"}],
        metrics={"count": 1},
    )


class TestWriteJson:
    def test_creates_json_file(self, tmp_path):
        with patch("srt.core.reporter.REPORT_DIR", tmp_path):
            results = [_make_result()]
            path = write_json(results, "test-report")
            assert path.exists()
            assert path.suffix == ".json"

            content = json.loads(path.read_text())
            assert isinstance(content, list)
            assert len(content) == 1
            assert content[0]["module_name"] == "test.module"
            assert content[0]["status"] == "ok"


class TestWriteMarkdown:
    def test_creates_markdown_file(self, tmp_path):
        with patch("srt.core.reporter.REPORT_DIR", tmp_path):
            results = [_make_result()]
            path = write_markdown(results, "test-report")
            assert path.exists()
            assert path.suffix == ".md"

            content = path.read_text()
            assert "# Report: test-report" in content
            assert "| Module |" in content
            assert "`test.module`" in content


class TestBuildMitreMap:
    def test_aggregates_ttps(self):
        results = [
            _make_result("mod.a", ttp=["T1040", "T1592"]),
            _make_result("mod.b", ttp=["T1040", "T1499"]),
        ]
        mitre_map = build_mitre_map(results)
        assert "T1040" in mitre_map
        assert len(mitre_map["T1040"]) == 2
        assert "mod.a" in mitre_map["T1040"]
        assert "mod.b" in mitre_map["T1040"]
        assert "T1499" in mitre_map
        assert mitre_map["T1499"] == ["mod.b"]

    def test_empty_results(self):
        mitre_map = build_mitre_map([])
        assert mitre_map == {}


class TestGenerateNavigatorLayer:
    def test_creates_navigator_json(self, tmp_path):
        from srt.core.reporter import generate_mitre_navigator_layer

        with patch("srt.core.reporter.REPORT_DIR", tmp_path):
            results = [
                _make_result("mod.a", ttp=["T1040", "T1592"]),
                _make_result("mod.b", ttp=["T1040"]),
            ]
            path = generate_mitre_navigator_layer(results, "test-nav")
            assert path.exists()
            assert path.suffix == ".json"
            content = json.loads(path.read_text())
            assert content["domain"] == "enterprise-attack"
            assert len(content["techniques"]) == 2
