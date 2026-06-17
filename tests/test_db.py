"""Tests for srt.core.db with mocked connections."""

from __future__ import annotations

import time
import uuid

from srt.core.db import (
    dsn,
    end_session,
    insert_header,
    query_session_results,
    start_session,
    write_result,
)
from srt.core.module import AttackResult, Risk, Status


class TestDsn:
    def test_default_dsn(self, monkeypatch):
        monkeypatch.delenv("SRT_DB_DSN", raising=False)
        result = dsn()
        assert "postgresql://" in result
        assert "srt" in result

    def test_custom_dsn(self, monkeypatch):
        monkeypatch.setenv("SRT_DB_DSN", "postgresql://custom:5432/testdb")
        result = dsn()
        assert result == "postgresql://custom:5432/testdb"


class TestPing:
    def test_ping_returns_false_when_mocked(self):
        # The conftest patches srt.core.db.ping to return False
        # Import via module to use the patched version
        import srt.core.db
        assert srt.core.db.ping() is False


class TestStartSession:
    def test_start_session_returns_uuid(self):
        sid = start_session(operator="tester", scenario="test")
        assert isinstance(sid, uuid.UUID)


class TestEndSession:
    def test_end_session_no_error(self):
        # Should not raise
        end_session(uuid.uuid4(), notes="test complete")


class TestInsertHeader:
    def test_insert_header_no_error(self):
        # Should not raise (mocked)
        insert_header(
            ts=time.time(),
            session_id=uuid.uuid4(),
            protocol="wifi",
            src="AA:BB:CC:DD:EE:FF",
            dst="FF:FF:FF:FF:FF:FF",
            channel=6,
            freq_hz=2437000000,
            rssi_dbm=-50,
            fields={"frame_type": "beacon"},
        )


class TestWriteResult:
    def test_write_result_no_error(self):
        result = AttackResult(
            module_name="test.module",
            protocol="test",
            risk=Risk.PASSIVE,
            status=Status.OK,
            started_at=time.time() - 1,
            ended_at=time.time(),
            summary="test",
        )
        write_result(uuid.uuid4(), result)


class TestQuerySessionResults:
    def test_returns_empty_on_error(self):
        # With mocked db.connect, the cursor mock won't have proper data
        results = query_session_results("some-uuid")
        # Should not raise, returns empty or data depending on mock
        assert isinstance(results, list)
