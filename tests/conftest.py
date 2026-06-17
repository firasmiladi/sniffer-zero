"""Shared fixtures for sniffer-rt test suite."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

from srt.core.module import ModuleContext


@pytest.fixture(autouse=True)
def _mock_db(monkeypatch):
    """Patch db.connect to return a mock context manager (no real DB)."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

    @contextmanager
    def fake_connect():
        yield mock_conn

    monkeypatch.setattr("srt.core.db.connect", fake_connect)
    monkeypatch.setattr("srt.core.db.ping", lambda: False)
    monkeypatch.setattr("srt.core.db.write_result", lambda *a, **kw: None)
    monkeypatch.setattr("srt.core.db.start_session", lambda *a, **kw: uuid.uuid4())
    monkeypatch.setattr("srt.core.db.end_session", lambda *a, **kw: None)


@pytest.fixture(autouse=True)
def _mock_sdr(monkeypatch):
    """Patch sdr.probe to return empty list (no hardware)."""
    monkeypatch.setattr("srt.core.sdr.probe", lambda: [])


@pytest.fixture()
def module_ctx():
    """A sample ModuleContext with dry_run=True."""
    return ModuleContext(
        session_id=uuid.uuid4(),
        operator="pytest",
        params={},
        dry_run=True,
        authorization_ok=True,
        authorized_bands_mhz=["868"],
        whitelist={},
    )


@pytest.fixture(scope="session", autouse=True)
def _autodiscover():
    """Run autodiscover once per session so all modules are registered."""
    from srt.core.registry import autodiscover

    autodiscover()
