"""Tests for srt.core.module.AttackModule precheck logic."""

from __future__ import annotations

import time
import uuid

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status


class DummyModule(AttackModule):
    """Minimal concrete module for testing."""

    name = "test.dummy"
    protocol = "test"
    risk = Risk.PASSIVE

    def run(self, ctx: ModuleContext) -> AttackResult:
        return self._result(Status.OK, time.time(), summary="dummy run")


class ForbiddenModule(AttackModule):
    name = "test.forbidden"
    protocol = "test"
    risk = Risk.FORBIDDEN

    def run(self, ctx: ModuleContext) -> AttackResult:
        return self._result(Status.OK, time.time(), summary="should not run")


class ActiveLabModule(AttackModule):
    name = "test.active_lab"
    protocol = "test"
    risk = Risk.ACTIVE_LAB

    def run(self, ctx: ModuleContext) -> AttackResult:
        return self._result(Status.OK, time.time(), summary="active lab")


def _make_ctx(authorization_ok: bool = True) -> ModuleContext:
    return ModuleContext(
        session_id=uuid.uuid4(),
        operator="pytest",
        params={},
        dry_run=False,
        authorization_ok=authorization_ok,
    )


class TestPrecheck:
    def test_forbidden_always_false(self):
        mod = ForbiddenModule()
        ctx = _make_ctx(authorization_ok=True)
        assert mod.precheck(ctx) is False

    def test_passive_always_true(self):
        mod = DummyModule()
        ctx = _make_ctx(authorization_ok=False)
        assert mod.precheck(ctx) is True

    def test_active_lab_requires_authorization(self):
        mod = ActiveLabModule()
        ctx_no_auth = _make_ctx(authorization_ok=False)
        assert mod.precheck(ctx_no_auth) is False

        ctx_with_auth = _make_ctx(authorization_ok=True)
        assert mod.precheck(ctx_with_auth) is True


class TestResultHelper:
    def test_result_builds_correctly(self):
        mod = DummyModule()
        started = time.time()
        result = mod._result(
            Status.OK,
            started,
            summary="test summary",
            artifacts=[{"type": "test", "data": "value"}],
            metrics={"count": 1},
        )
        assert isinstance(result, AttackResult)
        assert result.module_name == "test.dummy"
        assert result.protocol == "test"
        assert result.status == Status.OK
        assert result.summary == "test summary"
        assert len(result.artifacts) == 1
        assert result.metrics["count"] == 1
        assert result.duration_s >= 0

    def test_refused_helper(self):
        mod = DummyModule()
        started = time.time()
        result = mod.refused(started, "not allowed")
        assert result.status == Status.REFUSED
        assert "not allowed" in result.summary
