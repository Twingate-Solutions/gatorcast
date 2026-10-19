"""Session 13 review fixes: ``rejected`` and ``normalize_error`` drop reasons, the intake loop's
yield interval, and the periodic ``ingest.syslog`` summary on a long-lived connection.

Shares its helpers and the ``intake_log`` fixture with ``test_intake_counts``.
"""

from __future__ import annotations

import asyncio
import io
import json
import time
from pathlib import Path

import pytest

import gatorcast.ingest.http as http_module
import gatorcast.ingest.syslog_tcp as syslog_module
from gatorcast.ingest.syslog_tcp import SyslogTCPServer
from gatorcast.models import SessionStart
from tests.test_intake_counts import (  # noqa: F401  (intake_log is a fixture)
    CONN,
    _auth,
    _client,
    _events,
    _noise_line,
    _octet,
    _send,
    _start_line,
    _wait_for_event,
    intake_log,
)

CONN_2 = "aaaaaaaa-0000-4000-8000-0000000000c2"


# --------------------------------------------------------------------------- rejected


def test_rejected_counts_malformed_known_events_and_noise_stays_separate(tmp_path: Path) -> None:
    """A recognised event type ``classify`` refuses is ``rejected`` (no logger breakdown)."""
    lines = [
        # recording logger + string asciicast with a bad conn_id / seq
        json.dumps({"logger": "session_recording", "conn_id": "a/b", "asciicast": "x",
                    "asciicast_sequence_num": 1}),
        json.dumps({"logger": "gateway.audit", "conn_id": CONN, "asciicast": "x",
                    "asciicast_sequence_num": "one"}),
        # audit logger + API message but unusable fields
        json.dumps({"logger": "audit", "message": "API request completed", "conn_id": CONN}),
        # start logger + start message, no conn_id
        json.dumps({"logger": "system", "message": "Authenticated connection"}),
        # a null or non-string asciicast is not a recognised chunk (only a string is): noise,
        # under its logger
        json.dumps({"logger": "session_recording", "message": "x", "asciicast": None}),
        json.dumps({"logger": "session_recording", "conn_id": CONN, "asciicast": 5,
                    "asciicast_sequence_num": 1}),
    ]
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest",
            content="\n".join(lines),
            headers={**_auth(), "Content-Type": "application/x-ndjson"},
        )
    assert resp.status_code == 200
    assert resp.json() == {
        "accepted": 0,
        "dropped": 6,
        "accepted_by_kind": {},
        "dropped_by_reason": {"noise": 2, "rejected": 4},
        "noise_by_logger": {"session_recording": 2},
    }


def test_request_line_with_a_rejected_method_is_rejected_not_noise(tmp_path: Path) -> None:
    """The method gate drops a request line: counted ``rejected``, no logger bucket."""
    line = json.dumps(
        {
            "logger": "audit",
            "message": "API request completed",
            "conn_id": CONN,
            "request_id": "11111111-1111-4111-8111-111111111199",
            "requested_at": "2026-10-01T10:00:01.200Z",
            "method": "BAD METHOD",
            "url": "/x",
        }
    )
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest", content=line, headers={**_auth(), "Content-Type": "text/plain"}
        )
    assert resp.json()["dropped_by_reason"] == {"rejected": 1}
    assert resp.json()["noise_by_logger"] == {}


# --------------------------------------------------------------------------- normalize_error


def test_normalize_error_is_counted_per_line_and_the_batch_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, intake_log: io.StringIO
) -> None:
    """``normalize`` raising on one NDJSON line is a counted ``normalize_error``, type-only log."""
    real = http_module.normalize

    def flaky(line: str) -> object:
        if "EXPLODE_NORMALIZE" in line:
            raise RuntimeError("SENTINEL_NORMALIZE_TEXT_31")
        return real(line)

    monkeypatch.setattr(http_module, "normalize", flaky)
    lines = [_start_line(), "x EXPLODE_NORMALIZE x", "junk", _noise_line("system")]
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest",
            content="\n".join(lines),
            headers={**_auth(), "Content-Type": "application/x-ndjson"},
        )
    assert resp.status_code == 200
    assert resp.json() == {
        "accepted": 1,
        "dropped": 3,
        "accepted_by_kind": {"SessionStart": 1},
        "dropped_by_reason": {"noise": 1, "normalize_error": 1, "not_json": 1},
        "noise_by_logger": {"system": 1},
    }
    errors = [e for e in _events(intake_log) if e["event"] == "pipeline.error"]
    assert [(e["stage"], e["error"]) for e in errors] == [("normalize", "RuntimeError")]
    assert "SENTINEL_NORMALIZE_TEXT_31" not in intake_log.getvalue()
    assert "EXPLODE_NORMALIZE" not in intake_log.getvalue()


def test_normalize_error_on_the_application_json_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, intake_log: io.StringIO
) -> None:
    """``unwrap_collector`` raising on one JSON item is a counted ``normalize_error``."""
    real = http_module.unwrap_collector

    def flaky(obj: dict) -> object:
        if obj.get("boom"):
            raise ValueError("SENTINEL_UNWRAP_TEXT_44")
        return real(obj)

    monkeypatch.setattr(http_module, "unwrap_collector", flaky)
    payload = [{"boom": True, "logger": "system"}, json.loads(_start_line())]
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest",
            content=json.dumps(payload),
            headers={**_auth(), "Content-Type": "application/json"},
        )
    assert resp.json()["accepted"] == 1
    assert resp.json()["dropped_by_reason"] == {"normalize_error": 1}
    assert "SENTINEL_UNWRAP_TEXT_44" not in intake_log.getvalue()
    errors = [e for e in _events(intake_log) if e["event"] == "pipeline.error"]
    assert [(e["stage"], e["error"]) for e in errors] == [("normalize", "ValueError")]


def test_large_batch_crossing_the_yield_interval_is_fully_counted(tmp_path: Path) -> None:
    """600 inputs (the loop yields every 256) are all counted, in both body shapes."""
    lines = [_noise_line("system")] * 300 + ["not json"] * 300
    objs = [json.loads(_noise_line("audit"))] * 600
    with _client(tmp_path) as client:
        nd = client.post(
            "/ingest",
            content="\n".join(lines),
            headers={**_auth(), "Content-Type": "application/x-ndjson"},
        )
        js = client.post(
            "/ingest",
            content=json.dumps(objs),
            headers={**_auth(), "Content-Type": "application/json"},
        )
    assert nd.json()["dropped_by_reason"] == {"noise": 300, "not_json": 300}
    assert js.json()["dropped_by_reason"] == {"noise": 600}
    assert js.json()["noise_by_logger"] == {"audit": 600}


@pytest.mark.asyncio
async def test_syslog_normalize_error_is_counted_and_the_connection_continues(
    monkeypatch: pytest.MonkeyPatch, intake_log: io.StringIO
) -> None:
    """``normalize`` raising on one syslog message is a counted ``normalize_error``."""
    real = syslog_module.normalize

    def flaky(message: str) -> object:
        if "EXPLODE_NORMALIZE" in message:
            raise RuntimeError("SENTINEL_SYSLOG_NORMALIZE_8")
        return real(message)

    monkeypatch.setattr(syslog_module, "normalize", flaky)
    queue: asyncio.Queue = asyncio.Queue()
    server = SyslogTCPServer(host="127.0.0.1", port=0, queue=queue)
    await server.start()
    try:
        await _send(server.port, _octet("EXPLODE_NORMALIZE") + _octet(_start_line()))
        logged = await _wait_for_event(intake_log, "ingest.syslog")
    finally:
        await server.stop()
    assert logged[0]["accepted"] == 1
    assert logged[0]["dropped_by_reason"] == {"normalize_error": 1}
    assert isinstance(queue.get_nowait(), SessionStart)
    assert "SENTINEL_SYSLOG_NORMALIZE_8" not in intake_log.getvalue()


# --------------------------------------------------------------------------- periodic syslog summary


async def _wait_for_count(
    buffer: io.StringIO, name: str, count: int, timeout: float = 3.0
) -> list[dict]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = [e for e in _events(buffer) if e["event"] == name]
        if len(found) >= count:
            return found
        await asyncio.sleep(0.02)
    return [e for e in _events(buffer) if e["event"] == name]


@pytest.mark.asyncio
async def test_syslog_summary_is_logged_every_n_messages_on_an_open_connection(
    monkeypatch: pytest.MonkeyPatch, intake_log: io.StringIO
) -> None:
    """With the threshold at 2, an open connection logs after messages 2 and 4; close logs the rest."""
    monkeypatch.setattr(syslog_module, "SUMMARY_EVERY_MESSAGES", 2)
    monkeypatch.setattr(syslog_module, "SUMMARY_EVERY_SECONDS", 3600.0)
    queue: asyncio.Queue = asyncio.Queue()
    server = SyslogTCPServer(host="127.0.0.1", port=0, queue=queue)
    await server.start()
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        for line in (_start_line(), "junk", _noise_line("audit"), _noise_line("system")):
            writer.write(_octet(line))
        await writer.drain()
        mid = await _wait_for_count(intake_log, "ingest.syslog", 2)
        assert len(mid) == 2, "no periodic summary before the connection closed"
        writer.write(_octet(_start_line().replace(CONN, CONN_2)))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        final = await _wait_for_count(intake_log, "ingest.syslog", 3)
    finally:
        await server.stop()
    assert [e["accepted"] + e["dropped"] for e in final] == [2, 2, 1]
    assert final[0]["accepted"] == 1 and final[0]["dropped_by_reason"] == {"not_json": 1}
    assert final[1]["noise_by_logger"] == {"audit": 1, "system": 1}
    assert final[2]["accepted_by_kind"] == {"SessionStart": 1}


@pytest.mark.asyncio
async def test_syslog_summary_is_logged_after_the_time_threshold(
    monkeypatch: pytest.MonkeyPatch, intake_log: io.StringIO
) -> None:
    """With the time threshold at 0, every message flushes its own summary while open."""
    monkeypatch.setattr(syslog_module, "SUMMARY_EVERY_MESSAGES", 10_000)
    monkeypatch.setattr(syslog_module, "SUMMARY_EVERY_SECONDS", 0.0)
    queue: asyncio.Queue = asyncio.Queue()
    server = SyslogTCPServer(host="127.0.0.1", port=0, queue=queue)
    await server.start()
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        for line in (_start_line(), _noise_line("system"), "junk"):
            writer.write(_octet(line))
            await writer.drain()
        logged = await _wait_for_count(intake_log, "ingest.syslog", 3)
        assert len(logged) == 3, "time threshold did not flush while the connection was open"
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.1)
        after = [e for e in _events(intake_log) if e["event"] == "ingest.syslog"]
    finally:
        await server.stop()
    assert [e["accepted"] + e["dropped"] for e in after] == [1, 1, 1]  # close adds nothing empty
