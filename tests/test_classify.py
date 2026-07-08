"""Tests for pipeline.classify: the two-stage recording filter and event shaping."""

from __future__ import annotations

import json

from gatorcast.models import RecordingChunk, SessionEnd, SessionStart
from gatorcast.pipeline.classify import classify
from tests.samples import sample_lines


def test_recording_chunk_from_real_sample() -> None:
    """A gateway.audit line with an asciicast becomes a RecordingChunk."""
    obj = json.loads(sample_lines()[0])
    event = classify(obj)
    assert isinstance(event, RecordingChunk)
    assert event.conn_id == "9114cb20-7e00-4bfd-b50b-aa6f7440127a"
    assert event.seq == 0
    assert event.username == "grady@twingate.com"
    assert event.asciicast.startswith('{"version":2')


def test_session_start_from_real_sample() -> None:
    """A gateway 'Authenticated connection' line becomes a SessionStart."""
    obj = json.loads(sample_lines()[1])
    event = classify(obj)
    assert isinstance(event, SessionStart)
    assert event.conn_id == "22f2002a-9a49-45ca-b365-616dc9cfd203"
    assert event.resource_address == "kubernetes.default.svc.cluster.local"
    assert event.username == "grady@twingate.com"


def test_api_audit_noise_is_dropped() -> None:
    """A gateway.audit line WITHOUT an asciicast (API audit) is dropped."""
    obj = json.loads(sample_lines()[2])
    assert obj["logger"] == "gateway.audit"  # logger alone is not enough
    assert classify(obj) is None


def test_gateway_audit_without_asciicast_dropped() -> None:
    """The two-stage filter requires the asciicast field, not just the logger."""
    assert classify({"logger": "gateway.audit", "conn_id": "abc"}) is None
    assert classify({"logger": "gateway.audit", "conn_id": "abc", "asciicast": None}) is None


def test_chunk_requires_integer_seq() -> None:
    """A chunk missing or with a non-integer ordering key is dropped."""
    base = {"logger": "gateway.audit", "conn_id": "abc", "asciicast": "x"}
    assert classify(base) is None
    assert classify({**base, "asciicast_sequence_num": "0"}) is None
    assert classify({**base, "asciicast_sequence_num": True}) is None
    assert isinstance(classify({**base, "asciicast_sequence_num": 3}), RecordingChunk)


def test_final_flush_marks_chunk_is_final() -> None:
    """The Gateway's final flush ('session finished') sets is_final on the chunk."""
    base = {
        "logger": "gateway.audit",
        "conn_id": "abc",
        "asciicast": "x",
        "asciicast_sequence_num": 5,
    }
    ongoing = classify({**base, "message": "session recording"})
    assert isinstance(ongoing, RecordingChunk) and ongoing.is_final is False

    final = classify({**base, "message": "session finished"})
    assert isinstance(final, RecordingChunk) and final.is_final is True

    # A chunk with no message field is treated as non-final.
    assert classify(base).is_final is False


def test_unsafe_conn_id_is_rejected() -> None:
    """A conn_id that could escape the casts directory is dropped (no path traversal)."""
    obj = {
        "logger": "gateway.audit",
        "conn_id": "../../etc/passwd",
        "asciicast": "x",
        "asciicast_sequence_num": 0,
    }
    assert classify(obj) is None
    assert classify({**obj, "conn_id": "a/b"}) is None
    assert classify({**obj, "conn_id": ""}) is None


def test_close_event_hook() -> None:
    """A candidate close message produces a SessionEnd (idle timeout still primary)."""
    event = classify(
        {"logger": "gateway", "message": "Connection closed", "conn_id": "abc"}
    )
    assert isinstance(event, SessionEnd)
    assert event.conn_id == "abc"


def test_unknown_logger_dropped() -> None:
    """Anything else is operational noise and is dropped."""
    assert classify({"logger": "gateway", "message": "something else"}) is None
    assert classify({"logger": "other"}) is None
    assert classify({}) is None
