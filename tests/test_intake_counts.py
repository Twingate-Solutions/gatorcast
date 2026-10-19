"""Session 13: intake counts for ``POST /ingest`` and the syslog TCP front door.

Every non-blank input ends in exactly one outcome (accepted by event kind, or dropped as
``not_json`` / ``noise`` / ``classify_error``), noise is bucketed by a fixed logger label, and
no attacker-controlled text reaches the response or the logs.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import time
from pathlib import Path

import pytest
import structlog
from fastapi.testclient import TestClient

import gatorcast.ingest.counts as counts_module
import gatorcast.ingest.http as http_module
import gatorcast.ingest.syslog_tcp as syslog_module
from gatorcast.config import Settings
from gatorcast.ingest.counts import (
    KNOWN_LOGGERS,
    LOGGER_MISSING,
    LOGGER_OTHER,
    IntakeCounts,
    logger_bucket,
)
from gatorcast.ingest.syslog_tcp import SyslogTCPServer
from gatorcast.main import create_app
from gatorcast.models import ApiRequest, RecordingChunk, SessionStart
from tests.samples import ga_recording_lines, sample_lines

TOKEN = "counts-ingest-token"
RESPONSE_KEYS = {"accepted", "dropped", "accepted_by_kind", "dropped_by_reason", "noise_by_logger"}
CONN = "aaaaaaaa-0000-4000-8000-0000000000c1"
HOSTILE_SCRIPT = "<script>alert('SENTINEL_HOSTILE_LOGGER_1')</script>"
HOSTILE_LONG = "SENTINEL_LONG_LOGGER_" + "x" * 5000


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(data_dir=tmp_path, syslog_tcp_port=0, ingest_token=TOKEN)
    return TestClient(create_app(settings))


def _start_line() -> str:
    return json.dumps(
        {
            "logger": "system",
            "message": "Authenticated connection",
            "conn_id": CONN,
            "user": {"username": "u@example.com", "id": "uid"},
            "resource_type": "KUBERNETES",
            "resource_address": "k8s.example",
        }
    )


def _noise_line(logger: object) -> str:
    return json.dumps({"logger": logger, "message": "some operational line"})


@pytest.fixture
def intake_log(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    """Capture the intake modules' loggers (all levels) as JSON lines."""
    buffer = io.StringIO()

    def make() -> object:
        return structlog.wrap_logger(
            structlog.PrintLogger(file=buffer),
            processors=[structlog.processors.add_log_level, structlog.processors.JSONRenderer()],
            wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
        )

    for module in (http_module, counts_module, syslog_module):
        monkeypatch.setattr(module, "log", make())
    return buffer


def _events(buffer: io.StringIO) -> list[dict]:
    return [json.loads(ln) for ln in buffer.getvalue().splitlines() if ln.strip()]


# --------------------------------------------------------------------------- IntakeCounts unit


def test_empty_counts_render_all_five_keys() -> None:
    """A fresh ``IntakeCounts`` renders zero totals and three empty maps."""
    assert IntakeCounts().as_dict() == {
        "accepted": 0,
        "dropped": 0,
        "accepted_by_kind": {},
        "dropped_by_reason": {},
        "noise_by_logger": {},
    }


def test_triage_counts_each_accepted_event_kind() -> None:
    """``accepted_by_kind`` is keyed by the event type name classify returned."""
    counts = IntakeCounts()
    objs = [json.loads(line) for line in ga_recording_lines()]
    events = [counts.triage(o) for o in objs]
    kinds = sorted(type(e).__name__ for e in events if e is not None)
    assert kinds == sorted(
        ["SessionStart"] * 2 + ["RecordingChunk"] * 5 + ["ApiRequest"]
    )
    assert counts.accepted_by_kind == {"SessionStart": 2, "RecordingChunk": 5, "ApiRequest": 1}
    assert counts.accepted == 8
    # Dropped: "Starting SSH proxy" (system) and the two ssh audit events (audit).
    assert counts.dropped_by_reason == {"noise": 3}
    assert counts.noise_by_logger == {"system": 1, "audit": 2}


@pytest.mark.parametrize("logger", sorted(KNOWN_LOGGERS))
def test_noise_is_bucketed_under_each_known_logger_name(logger: str) -> None:
    """An unrecognised line of each known logger is counted under that logger's name."""
    counts = IntakeCounts()
    assert counts.triage(json.loads(_noise_line(logger))) is None
    assert counts.dropped_by_reason == {"noise": 1}
    assert counts.noise_by_logger == {logger: 1}


@pytest.mark.parametrize(
    "obj",
    [
        {"message": "no logger key"},
        {"logger": None},
        {"logger": 5},
        {"logger": True},
    ],
    ids=repr,
)
def test_absent_or_non_string_logger_is_bucketed_as_missing(obj: dict) -> None:
    """A noise line with no usable ``logger`` string counts under ``missing``."""
    counts = IntakeCounts()
    assert counts.triage(obj) is None
    assert counts.noise_by_logger == {LOGGER_MISSING: 1}
    assert logger_bucket(obj) == "missing"


@pytest.mark.parametrize("logger", [["system"], {"a": "b"}], ids=repr)
def test_unhashable_logger_value_is_missing_noise_not_a_classify_error(logger: object) -> None:
    """A list/dict ``logger`` is attacker-shaped noise: ``missing``, not ``classify_error``."""
    counts = IntakeCounts()
    assert counts.triage({"logger": logger, "message": "x"}) is None
    assert counts.dropped_by_reason == {"noise": 1}
    assert counts.noise_by_logger == {LOGGER_MISSING: 1}


@pytest.mark.parametrize("value", [HOSTILE_SCRIPT, HOSTILE_LONG, " system", "System", "audit\n"])
def test_unknown_logger_string_is_bucketed_as_other_and_never_echoed(value: str) -> None:
    """Any other logger string collapses to ``other``; its text appears in no key."""
    counts = IntakeCounts()
    counts.triage({"logger": value, "message": "x"})
    assert counts.noise_by_logger == {LOGGER_OTHER: 1}
    assert value not in json.dumps(counts.as_dict())


def test_malformed_recognised_event_counts_as_rejected_not_noise() -> None:
    """A recording chunk with a bad conn_id is a recognised type ``classify`` rejected: ``rejected``.

    It is not added to ``noise_by_logger`` (that breakdown is for unrecognised lines only).
    """
    counts = IntakeCounts()
    obj = {
        "logger": "session_recording",
        "conn_id": "../../etc/passwd",
        "asciicast": "x",
        "asciicast_sequence_num": 1,
    }
    assert counts.triage(obj) is None
    assert counts.dropped_by_reason == {"rejected": 1}
    assert counts.noise_by_logger == {}


def test_classify_error_is_isolated_counted_and_logged_by_type_only(
    monkeypatch: pytest.MonkeyPatch, intake_log: io.StringIO
) -> None:
    """A raising ``classify`` counts as ``classify_error``; the next object is still processed."""

    def boom(obj: dict) -> object:
        if obj.get("boom"):
            raise ValueError("SENTINEL_EXCEPTION_TEXT_77")
        return real(obj)

    real = counts_module.classify
    monkeypatch.setattr(counts_module, "classify", boom)
    counts = IntakeCounts()
    assert counts.triage({"boom": True, "logger": HOSTILE_SCRIPT}) is None
    assert isinstance(counts.triage(json.loads(_start_line())), SessionStart)
    assert counts.dropped_by_reason == {"classify_error": 1}
    assert counts.noise_by_logger == {}  # a classify error is not noise
    assert counts.accepted_by_kind == {"SessionStart": 1}
    events = _events(intake_log)
    assert len(events) == 1
    assert events[0]["event"] == "pipeline.error"
    assert events[0]["level"] == "warning"
    assert events[0]["stage"] == "classify"
    assert events[0]["error"] == "ValueError"
    assert "SENTINEL_EXCEPTION_TEXT_77" not in intake_log.getvalue()
    assert HOSTILE_SCRIPT not in intake_log.getvalue()


def test_drop_not_json_ignores_non_positive_counts() -> None:
    """Zero or negative ``drop_not_json`` counts nothing."""
    counts = IntakeCounts()
    counts.drop_not_json(0)
    counts.drop_not_json(-3)
    counts.drop_not_json(2)
    assert counts.dropped_by_reason == {"not_json": 2}


# --------------------------------------------------------------------------- POST /ingest


def test_ingest_returns_200_json_with_all_keys_for_an_empty_body(tmp_path: Path) -> None:
    """An empty body is a valid batch with nothing in it: 200, zero counts, all keys present."""
    with _client(tmp_path) as client:
        resp = client.post("/ingest", content="", headers=_auth())
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json() == {
        "accepted": 0,
        "dropped": 0,
        "accepted_by_kind": {},
        "dropped_by_reason": {},
        "noise_by_logger": {},
    }


def test_ingest_blank_lines_are_not_counted(tmp_path: Path) -> None:
    """Blank and whitespace-only lines are skipped, not dropped."""
    body = "\n\n   \n" + _start_line() + "\n\r\n\t\n"
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest", content=body, headers={**_auth(), "Content-Type": "application/x-ndjson"}
        )
    assert resp.json()["accepted"] == 1
    assert resp.json()["dropped"] == 0


def test_ingest_batch_with_every_outcome_reports_each(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One batch holding an accepted line of each kind, plus one drop of each reason."""
    real = counts_module.classify

    def maybe_boom(obj: dict) -> object:
        if obj.get("boom"):
            raise RuntimeError("never shown")
        return real(obj)

    monkeypatch.setattr(counts_module, "classify", maybe_boom)
    ga = ga_recording_lines()
    lines = [
        ga[1],  # SessionStart (SSH, system)
        ga[3],  # RecordingChunk
        ga[10],  # ApiRequest (audit)
        "this is not json",  # not_json
        "{ also broken",  # not_json
        _noise_line("system"),  # noise
        _noise_line("audit"),
        _noise_line("audit"),
        _noise_line("gateway"),
        _noise_line("gateway.audit"),
        _noise_line("session_recording"),
        json.dumps({"message": "no logger"}),  # noise: missing
        json.dumps({"logger": "kubelet", "message": "x"}),  # noise: other
        json.dumps({"boom": True}),  # classify_error
    ]
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest",
            content="\n".join(lines),
            headers={**_auth(), "Content-Type": "application/x-ndjson"},
        )
    assert resp.status_code == 200
    assert resp.json() == {
        "accepted": 3,
        "dropped": 11,
        "accepted_by_kind": {"ApiRequest": 1, "RecordingChunk": 1, "SessionStart": 1},
        "dropped_by_reason": {"classify_error": 1, "noise": 8, "not_json": 2},
        "noise_by_logger": {
            "audit": 2,
            "gateway": 1,
            "gateway.audit": 1,
            "missing": 1,
            "other": 1,
            "session_recording": 1,
            "system": 1,
        },
    }
    body = resp.json()
    assert list(body["dropped_by_reason"]) == sorted(body["dropped_by_reason"])  # sorted keys
    assert list(body["noise_by_logger"]) == sorted(body["noise_by_logger"])


def test_ingest_counts_match_the_log_line(tmp_path: Path, intake_log: io.StringIO) -> None:
    """One ``ingest.http`` info line per batch carries the same fields as the response."""
    lines = [_start_line(), "junk", _noise_line("system")]
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest",
            content="\n".join(lines),
            headers={**_auth(), "Content-Type": "application/x-ndjson"},
        )
    logged = [e for e in _events(intake_log) if e["event"] == "ingest.http"]
    assert len(logged) == 1
    assert logged[0]["level"] == "info"
    assert {k: v for k, v in logged[0].items() if k in RESPONSE_KEYS} == resp.json()


def test_ingest_hostile_logger_values_are_bucketed_other_and_never_echoed(
    tmp_path: Path, intake_log: io.StringIO
) -> None:
    """``<script>`` and a 5 KB logger name appear in neither the response nor any log line."""
    lines = [_noise_line(HOSTILE_SCRIPT), _noise_line(HOSTILE_LONG), _noise_line("system")]
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest",
            content="\n".join(lines),
            headers={**_auth(), "Content-Type": "application/x-ndjson"},
        )
    assert resp.json()["noise_by_logger"] == {"other": 2, "system": 1}
    assert resp.json()["dropped_by_reason"] == {"noise": 3}
    for forbidden in ("SENTINEL_HOSTILE_LOGGER_1", "SENTINEL_LONG_LOGGER_", "<script>"):
        assert forbidden not in resp.text
        assert forbidden not in intake_log.getvalue()
    assert intake_log.getvalue().strip(), "log capture recorded nothing (vacuous)"


def test_ingest_classify_error_does_not_fail_the_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, intake_log: io.StringIO
) -> None:
    """A classify exception is a counted drop; the other lines still land and the status is 200."""
    real = counts_module.classify

    def boom(obj: dict) -> object:
        if obj.get("conn_id") == CONN:
            raise ValueError("SENTINEL_CLASSIFY_BOOM_5")
        return real(obj)

    monkeypatch.setattr(counts_module, "classify", boom)
    ga = ga_recording_lines()
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest",
            content="\n".join([_start_line(), ga[1]]),
            headers={**_auth(), "Content-Type": "application/x-ndjson"},
        )
    assert resp.status_code == 200
    assert resp.json()["accepted"] == 1
    assert resp.json()["dropped_by_reason"] == {"classify_error": 1}
    errors = [e for e in _events(intake_log) if e["event"] == "pipeline.error"]
    assert [(e["stage"], e["error"]) for e in errors] == [("classify", "ValueError")]
    assert "SENTINEL_CLASSIFY_BOOM_5" not in intake_log.getvalue()


def test_ingest_application_json_array_counts_non_objects_as_not_json(tmp_path: Path) -> None:
    """In a JSON array, non-object items count as ``not_json`` and objects are classified."""
    payload = [json.loads(_start_line()), 5, "str", None, json.loads(_noise_line("audit"))]
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest",
            content=json.dumps(payload),
            headers={**_auth(), "Content-Type": "application/json"},
        )
    assert resp.json() == {
        "accepted": 1,
        "dropped": 4,
        "accepted_by_kind": {"SessionStart": 1},
        "dropped_by_reason": {"noise": 1, "not_json": 3},
        "noise_by_logger": {"audit": 1},
    }


@pytest.mark.parametrize("body", ["{not json", "42", '"just a string"', "null"])
def test_ingest_application_json_invalid_body_counts_one_not_json(
    tmp_path: Path, body: str
) -> None:
    """An unparseable or non-object/array ``application/json`` body is one ``not_json`` drop."""
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest", content=body, headers={**_auth(), "Content-Type": "application/json"}
        )
    assert resp.status_code == 200
    assert resp.json()["accepted"] == 0
    assert resp.json()["dropped_by_reason"] == {"not_json": 1}


def test_ingest_collector_wrapper_without_json_inside_is_not_json(tmp_path: Path) -> None:
    """A Docker ``{"log": ...}`` wrapper whose inner text is not JSON is one ``not_json`` drop."""
    payload = [{"log": "plain text, not json", "stream": "stderr"}, {"log": _start_line()}]
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest",
            content=json.dumps(payload),
            headers={**_auth(), "Content-Type": "application/json"},
        )
    assert resp.json()["accepted"] == 1
    assert resp.json()["dropped_by_reason"] == {"not_json": 1}


def test_ingest_auth_failure_stays_401_with_no_counts(tmp_path: Path) -> None:
    """Auth failures keep their 401; the body is not a counts document."""
    with _client(tmp_path) as client:
        resp = client.post("/ingest", content=_start_line(), headers={"Authorization": "Bearer no"})
        missing = client.post("/ingest", content=_start_line())
    assert resp.status_code == 401 and missing.status_code == 401
    assert "accepted" not in resp.text


def test_ingest_preview_batch_counts_unchanged_by_the_new_semantics(tmp_path: Path) -> None:
    """The three real preview sample lines are three accepted events, nothing dropped."""
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest",
            content="\n".join(sample_lines()),
            headers={**_auth(), "Content-Type": "application/x-ndjson"},
        )
    assert resp.json()["accepted"] == 3 and resp.json()["dropped"] == 0


def test_ingest_mixed_preview_and_ga_batch_accepts_both(tmp_path: Path) -> None:
    """A preview chunk and the GA fixture lines in one batch are all classified."""
    lines = [*sample_lines(), *ga_recording_lines()]
    with _client(tmp_path) as client:
        resp = client.post(
            "/ingest",
            content="\n".join(lines),
            headers={**_auth(), "Content-Type": "application/x-ndjson"},
        )
    body = resp.json()
    assert body["accepted"] == 3 + 8
    assert body["dropped_by_reason"] == {"noise": 3}
    assert body["accepted_by_kind"] == {"ApiRequest": 2, "RecordingChunk": 6, "SessionStart": 3}


# --------------------------------------------------------------------------- syslog TCP


async def _send(port: int, payload: bytes) -> None:
    """Connect, write ``payload``, close, and let the server see the EOF."""
    _, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def _wait_for_event(buffer: io.StringIO, name: str, timeout: float = 3.0) -> list[dict]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = [e for e in _events(buffer) if e["event"] == name]
        if found:
            return found
        await asyncio.sleep(0.02)
    return []


def _octet(line: str) -> bytes:
    raw = line.encode("utf-8")
    return f"{len(raw)} ".encode() + raw


@pytest.mark.asyncio
async def test_syslog_logs_one_ingest_line_with_counts_at_disconnect(
    intake_log: io.StringIO,
) -> None:
    """One ``ingest.syslog`` line, at disconnect, with the same fields as the HTTP response."""
    queue: asyncio.Queue = asyncio.Queue()
    server = SyslogTCPServer(host="127.0.0.1", port=0, queue=queue)
    await server.start()
    try:
        ga = ga_recording_lines()
        payload = b"".join(
            [
                _octet(ga[1]),
                _octet(ga[3]),
                _octet(ga[10]),
                _octet("not json at all"),
                _octet(_noise_line("system")),
                _octet(_noise_line(HOSTILE_SCRIPT)),
                (_noise_line("audit") + "\n").encode(),  # newline-framed in the same stream
            ]
        )
        await _send(server.port, payload)
        logged = await _wait_for_event(intake_log, "ingest.syslog")
    finally:
        await server.stop()
    assert len(logged) == 1
    event = logged[0]
    assert event["level"] == "info"
    assert event["peer"]
    assert {k: v for k, v in event.items() if k in RESPONSE_KEYS} == {
        "accepted": 3,
        "dropped": 4,
        "accepted_by_kind": {"ApiRequest": 1, "RecordingChunk": 1, "SessionStart": 1},
        "dropped_by_reason": {"noise": 3, "not_json": 1},
        "noise_by_logger": {"audit": 1, "other": 1, "system": 1},
    }
    assert "SENTINEL_HOSTILE_LOGGER_1" not in intake_log.getvalue()
    assert "<script>" not in intake_log.getvalue()
    kinds = []
    while not queue.empty():
        kinds.append(type(queue.get_nowait()))
    assert kinds == [SessionStart, RecordingChunk, ApiRequest]


@pytest.mark.asyncio
async def test_syslog_connection_with_nothing_countable_logs_no_summary(
    intake_log: io.StringIO,
) -> None:
    """A connection that sends only blank lines (or nothing) logs no ``ingest.syslog`` line."""
    queue: asyncio.Queue = asyncio.Queue()
    server = SyslogTCPServer(host="127.0.0.1", port=0, queue=queue)
    await server.start()
    try:
        await _send(server.port, b"")
        await _send(server.port, b"\n\r\n   \n")
        # A third connection that does count proves the capture is live and ordered after.
        await _send(server.port, _octet(_start_line()))
        logged = await _wait_for_event(intake_log, "ingest.syslog")
    finally:
        await server.stop()
    assert len(logged) == 1
    assert logged[0]["accepted"] == 1


@pytest.mark.asyncio
async def test_syslog_classify_error_does_not_end_the_connection(
    monkeypatch: pytest.MonkeyPatch, intake_log: io.StringIO
) -> None:
    """A classify exception on one line is counted; the lines after it on the connection land."""
    real = counts_module.classify

    def boom(obj: dict) -> object:
        if obj.get("boom"):
            raise KeyError("SENTINEL_SYSLOG_BOOM_9")
        return real(obj)

    monkeypatch.setattr(counts_module, "classify", boom)
    queue: asyncio.Queue = asyncio.Queue()
    server = SyslogTCPServer(host="127.0.0.1", port=0, queue=queue)
    await server.start()
    try:
        await _send(
            server.port,
            _octet(json.dumps({"boom": True})) + _octet(_start_line()),
        )
        logged = await _wait_for_event(intake_log, "ingest.syslog")
    finally:
        await server.stop()
    assert logged[0]["accepted"] == 1
    assert logged[0]["dropped_by_reason"] == {"classify_error": 1}
    assert isinstance(queue.get_nowait(), SessionStart)
    assert "SENTINEL_SYSLOG_BOOM_9" not in intake_log.getvalue()
    errors = [e for e in _events(intake_log) if e["event"] == "pipeline.error"]
    assert [(e["stage"], e["error"]) for e in errors] == [("classify", "KeyError")]


@pytest.mark.parametrize("logger", ["audit", "gateway.audit", "system", "gateway"])
@pytest.mark.parametrize("message", [["x"], {"a": 1}], ids=repr)
def test_unhashable_message_value_is_noise_not_a_classify_error(logger: str, message: object) -> None:
    """A list/dict ``message`` on a known logger is ordinary noise under that logger."""
    counts = IntakeCounts()
    assert counts.triage({"logger": logger, "message": message}) is None
    assert counts.dropped_by_reason == {"noise": 1}
    assert counts.noise_by_logger == {logger: 1}
