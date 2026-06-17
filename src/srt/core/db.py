"""Tiny TimescaleDB / Postgres helper.

We deliberately keep this dependency-light: psycopg3 + a few ``execute``
helpers. Modules call ``db.insert_header(...)``, ``db.write_result(...)``,
``db.start_session(...)``.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any

import psycopg
import structlog

from srt.core.module import AttackResult

log = structlog.get_logger(__name__)


def dsn() -> str:
    return os.environ.get(
        "SRT_DB_DSN",
        "postgresql://srt:srt_dev_password@127.0.0.1:5432/srt",
    )


@contextmanager
def connect() -> Iterator[psycopg.Connection]:
    conn = psycopg.connect(dsn(), autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


def ping() -> bool:
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1;")
            cur.fetchone()
        return True
    except Exception as exc:  # pragma: no cover - depends on infra availability
        log.warning("db.ping.failed", error=str(exc))
        return False


def start_session(operator: str, scenario: str | None = None,
                  auth_doc_sha: str | None = None) -> uuid.UUID:
    sid = uuid.uuid4()
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sessions (id, operator, scenario, auth_doc_sha)
                VALUES (%s, %s, %s, %s)
                """,
                (str(sid), operator, scenario, auth_doc_sha),
            )
    except Exception as exc:
        log.warning("db.start_session.failed", error=str(exc))
    return sid


def end_session(session_id: uuid.UUID, notes: str = "") -> None:
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET ended_at = NOW(), notes = %s WHERE id = %s",
                (notes, str(session_id)),
            )
    except Exception as exc:
        log.warning("db.end_session.failed", error=str(exc))


def insert_header(
    *,
    ts: float,
    session_id: uuid.UUID | None,
    protocol: str,
    src: str | None = None,
    dst: str | None = None,
    channel: int | None = None,
    freq_hz: int | None = None,
    rssi_dbm: int | None = None,
    snr_db: float | None = None,
    fields: dict[str, Any] | None = None,
) -> None:
    """Insert one normalized header record. Never raises."""
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO headers
                  (ts, session_id, protocol, src, dst, channel, freq_hz,
                   rssi_dbm, snr_db, fields)
                VALUES
                  (to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    ts,
                    str(session_id) if session_id else None,
                    protocol,
                    src,
                    dst,
                    channel,
                    freq_hz,
                    rssi_dbm,
                    snr_db,
                    json.dumps(fields or {}),
                ),
            )
    except Exception as exc:
        log.debug("db.insert_header.failed", error=str(exc))


def query_session_results(session_id: str) -> list[dict[str, Any]]:
    """Query all module_results for a given session ID.

    Returns a list of dicts with keys matching AttackResult fields.
    Returns empty list on failure or no results.
    """
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT module_name, protocol, risk, status,
                       EXTRACT(EPOCH FROM started_at) AS started_at,
                       EXTRACT(EPOCH FROM ended_at) AS ended_at,
                       summary, mitre_ttp, cve, artifacts, metrics
                FROM module_results
                WHERE session_id = %s
                ORDER BY started_at
                """,
                (session_id,),
            )
            columns = [desc[0] for desc in cur.description]
            rows: list[dict[str, Any]] = []
            for row in cur.fetchall():
                record = dict(zip(columns, row, strict=False))
                # Parse JSON fields if they are strings
                if isinstance(record.get("artifacts"), str):
                    record["artifacts"] = json.loads(record["artifacts"])
                if isinstance(record.get("metrics"), str):
                    record["metrics"] = json.loads(record["metrics"])
                rows.append(record)
            return rows
    except Exception as exc:
        log.warning("db.query_session_results.failed", error=str(exc))
        return []


def write_result(session_id: uuid.UUID, result: AttackResult) -> None:
    payload = asdict(result)
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO module_results
                  (session_id, module_name, protocol, risk,
                   started_at, ended_at, status,
                   mitre_ttp, cve, summary, artifacts, metrics)
                VALUES
                  (%s, %s, %s, %s,
                   to_timestamp(%s), to_timestamp(%s), %s,
                   %s, %s, %s, %s::jsonb, %s::jsonb)
                """,
                (
                    str(session_id),
                    result.module_name,
                    result.protocol,
                    result.risk.value,
                    result.started_at,
                    result.ended_at,
                    result.status.value,
                    result.mitre_ttp,
                    result.cve,
                    result.summary,
                    json.dumps(payload["artifacts"]),
                    json.dumps(payload["metrics"]),
                ),
            )
    except Exception as exc:
        log.warning("db.write_result.failed", module=result.module_name, error=str(exc))
