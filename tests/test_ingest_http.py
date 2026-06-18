"""Tests for the HTTP ingestion front door: auth + tolerant batch parsing.

The front door delivers to the real pipeline now (classify → assembler), so
acceptance is verified by the session rows that land in SQLite rather than by a
raw enqueue counter. The DB is read from the test thread via a separate sqlite3
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


def _count_sessions(db_path: Path) -> int:
    """Count rows in the sessions table via an independent reader connection."""
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    finally:
        conn.close()


def _wait_for_sessions(db_path: Path, expected: int, timeout: float = 3.0) -> int:
    """Poll the sessions table until it has at least ``expected`` rows."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if _count_sessions(db_path) >= expected:
                break
        except sqlite3.OperationalError:
            pass  # db not yet created / momentarily locked
        time.sleep(0.02)
    return _count_sessions(db_path)


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


def test_ndjson_accepted_and_processed(tmp_path: Path) -> None:
    """A valid NDJSON batch returns 204; the two recordable lines become rows.

    The sample has a recording chunk (conn A), a session-start (conn B), and one
    API-audit noise line that classify drops — so two session rows are expected.
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
        assert _wait_for_sessions(settings.db_path, 2) == 2


def test_json_array_accepted(tmp_path: Path) -> None:
    """An application/json array of objects is processed (two session rows)."""
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
        assert _wait_for_sessions(settings.db_path, 2) == 2


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
        # Both the recording chunk and the session-start produce session rows.
        assert _wait_for_sessions(settings.db_path, 2) == 2


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
        assert _wait_for_sessions(settings.db_path, 2) == 2
