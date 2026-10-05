"""Tests for the HTTP ingestion front door: auth + tolerant batch parsing.

The front door delivers to the real pipeline now (classify → assembler), so
acceptance is verified by the rows that land in SQLite (session rows for
recordings, pending connections for start lines, API-request rows for audit
lines) rather than by a raw enqueue counter. The DB is read from the test thread via a separate sqlite3
connection (WAL allows concurrent readers), avoiding the app's event loop.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from fastapi.testclient import TestClient

from gatorcast.config import Settings
from gatorcast.main import create_app
from tests.samples import sample_lines

TOKEN = "secret-ingest-token"


def _settings(tmp_path: Path) -> Settings:
    """Settings with syslog disabled and a known ingest token."""
    return Settings(data_dir=tmp_path, syslog_tcp_port=0, ingest_token=TOKEN)


# Sample fixture: line 0 is a recording chunk (conn A), line 1 an
# "Authenticated connection" start (conn B), line 2 a legacy API audit on conn A.
CONN_B = "22f2002a-9a49-45ca-b365-616dc9cfd203"


def _scalar(db_path: Path, sql: str, params: tuple = ()) -> object:
    """Run a single-value query via an independent reader connection."""
    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(sql, params).fetchone()
        return row[0] if row is not None else None
    finally:
        conn.close()


def _count_sessions(db_path: Path) -> int:
    """Count rows in the sessions table via an independent reader connection."""
    return int(_scalar(db_path, "SELECT COUNT(*) FROM sessions"))


def _wait_for(
    db_path: Path, sql: str, expected: int, params: tuple = (), timeout: float = 3.0
) -> int:
    """Poll a ``COUNT(*)`` query until it reaches at least ``expected``."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if int(_scalar(db_path, sql, params)) >= expected:
                break
        except sqlite3.OperationalError:
            pass  # db not yet created / momentarily locked
        time.sleep(0.02)
    return int(_scalar(db_path, sql, params))


def _wait_for_sessions(db_path: Path, expected: int, timeout: float = 3.0) -> int:
    """Poll the sessions table until it has at least ``expected`` rows."""
    return _wait_for(db_path, "SELECT COUNT(*) FROM sessions", expected, timeout=timeout)


def _wait_for_pending_b(db_path: Path) -> None:
    """Wait until the start line's connection B is stored as a pending connection."""
    sql = "SELECT COUNT(*) FROM connections WHERE conn_id = ?"
    assert _wait_for(db_path, sql, 1, params=(CONN_B,)) == 1
    state = _scalar(
        db_path, "SELECT state FROM connections WHERE conn_id = ?", (CONN_B,)
    )
    assert state == "pending"


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


def test_auth_required(tmp_path: Path) -> None:
    """Missing or wrong bearer token is rejected with 401."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        assert client.post("/ingest", content="{}").status_code == 401
        assert (
            client.post(
                "/ingest", content="{}", headers={"Authorization": "Bearer wrong"}
            ).status_code
            == 401
        )


def _assert_sample_batch_processed(db_path: Path) -> None:
    """Assert the full three-line sample batch landed as designed.

    The recording chunk (conn A) becomes the only session row; the start line
    (conn B) becomes a hidden pending connection with no session row; the API
    audit line is stored as API activity metadata on conn A. The consumer drains
    in order, so waiting for the audit row (last line) means all three are done.
    """
    assert _wait_for(db_path, "SELECT COUNT(*) FROM api_requests", 1) == 1
    assert _count_sessions(db_path) == 1
    _wait_for_pending_b(db_path)
    assert (
        _scalar(db_path, "SELECT COUNT(*) FROM sessions WHERE conn_id = ?", (CONN_B,))
        == 0
    )


def test_ndjson_accepted_and_processed(tmp_path: Path) -> None:
    """A valid NDJSON batch returns 204 and every line reaches the pipeline.

    The sample has a recording chunk (conn A), a session-start (conn B), and one
    API-audit line (conn A). Only the chunk creates a session row: the start is a
    pending connection, and the audit line is stored as API activity metadata.
    """
    settings = _settings(tmp_path)
    app = create_app(settings)
    lines = sample_lines()
    with TestClient(app) as client:
        resp = client.post(
            "/ingest",
            content="\n".join(lines),
            headers={**_auth(), "Content-Type": "application/x-ndjson"},
        )
        assert resp.status_code == 204
        _assert_sample_batch_processed(settings.db_path)


def test_json_array_accepted(tmp_path: Path) -> None:
    """An application/json array of objects is processed like the NDJSON batch."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    objs = [json.loads(line) for line in sample_lines()]
    with TestClient(app) as client:
        resp = client.post(
            "/ingest",
            content=json.dumps(objs),
            headers={**_auth(), "Content-Type": "application/json"},
        )
        assert resp.status_code == 204
        _assert_sample_batch_processed(settings.db_path)


def test_single_json_object_accepted(tmp_path: Path) -> None:
    """A single application/json recording chunk creates one provisional row."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    with TestClient(app) as client:
        resp = client.post(
            "/ingest",
            content=sample_lines()[0],
            headers={**_auth(), "Content-Type": "application/json"},
        )
        assert resp.status_code == 204
        assert _wait_for_sessions(settings.db_path, 1) == 1


def test_bad_line_does_not_fail_batch(tmp_path: Path) -> None:
    """A junk line is dropped; the valid chunk in the same batch still lands."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    body = "\n".join(["this is not json", sample_lines()[0], "{ also broken"])
    with TestClient(app) as client:
        resp = client.post(
            "/ingest",
            content=body,
            headers={**_auth(), "Content-Type": "text/plain"},
        )
        assert resp.status_code == 204
        assert _wait_for_sessions(settings.db_path, 1) == 1


# --- collector-envelope unwrap via application/json path -------------------


def test_json_collector_wrapped_object_unwrapped(tmp_path: Path) -> None:
    """A Docker collector envelope as a single application/json body is unwrapped.

    The body is ``{"log": "<json recording chunk>", "stream": "stdout"}``.  The
    HTTP path must call ``unwrap_collector`` on each parsed dict, so the inner
    gateway.audit chunk reaches the pipeline and creates a session row.
    """
    settings = _settings(tmp_path)
    app = create_app(settings)
    recording_chunk = sample_lines()[0]  # gateway.audit with asciicast
    wrapper = json.dumps({"log": recording_chunk, "stream": "stdout"})
    with TestClient(app) as client:
        resp = client.post(
            "/ingest",
            content=wrapper,
            headers={**_auth(), "Content-Type": "application/json"},
        )
        assert resp.status_code == 204
        assert _wait_for_sessions(settings.db_path, 1) == 1


def test_json_collector_wrapped_array_unwrapped(tmp_path: Path) -> None:
    """A JSON array of Docker-wrapped objects is unwrapped item-by-item."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    # Wrap both the recording chunk and the session-start line.
    wrappers = [
        {"log": sample_lines()[0], "stream": "stdout"},
        {"log": sample_lines()[1], "stream": "stdout"},
    ]
    with TestClient(app) as client:
        resp = client.post(
            "/ingest",
            content=json.dumps(wrappers),
            headers={**_auth(), "Content-Type": "application/json"},
        )
        assert resp.status_code == 204
        # Both reach the pipeline: the session-start becomes a pending connection
        # (no session row) and the recording chunk the only session row.
        _wait_for_pending_b(settings.db_path)
        assert _wait_for_sessions(settings.db_path, 1) == 1


def test_json_plain_object_still_works_alongside_collector(tmp_path: Path) -> None:
    """Plain (unwrapped) JSON objects in an array still reach the pipeline."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    # Mix: one plain object, one collector-wrapped object.
    objs = [
        json.loads(sample_lines()[0]),          # plain recording chunk
        {"log": sample_lines()[1], "stream": "stdout"},  # wrapped session-start
    ]
    with TestClient(app) as client:
        resp = client.post(
            "/ingest",
            content=json.dumps(objs),
            headers={**_auth(), "Content-Type": "application/json"},
        )
        assert resp.status_code == 204
        # Plain chunk → session row; wrapped start → pending connection.
        _wait_for_pending_b(settings.db_path)
        assert _wait_for_sessions(settings.db_path, 1) == 1
