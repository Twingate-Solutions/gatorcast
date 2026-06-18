"""Tests for ingest.normalize: plain JSON, syslog-wrapped, collector-wrapped, junk."""

from __future__ import annotations

import json

from tests.samples import sample_lines

from gatorcast.ingest.normalize import normalize, unwrap_collector


def test_plain_json_lines_parse() -> None:
    """Each real sample line parses to a dict preserving its fields."""
    for line in sample_lines():
        obj = normalize(line)
        assert isinstance(obj, dict)
        assert obj["logger"].startswith("gateway")

    recording = normalize(sample_lines()[0])
    assert recording is not None
    assert recording["conn_id"] == "9114cb20-7e00-4bfd-b50b-aa6f7440127a"
    assert recording["asciicast_sequence_num"] == 0
    assert recording["user"]["username"] == "grady@twingate.com"


def test_syslog_envelope_stripped() -> None:
    """An RFC 5424 <PRI> header before the JSON payload is stripped off."""
    payload = sample_lines()[1]
    wrapped = f"<134>1 2026-06-17T21:16:35.986Z gw-host gateway - - - {payload}"
    obj = normalize(wrapped)
    assert isinstance(obj, dict)
    assert obj["message"] == "Authenticated connection"
    assert obj["resource_address"] == "kubernetes.default.svc.cluster.local"


def test_bsd_syslog_envelope_stripped() -> None:
    """A BSD-style ``<PRI>TS HOST TAG:`` header is also stripped."""
    payload = sample_lines()[0]
    wrapped = f"<134>Jun 17 21:01:39 gw-host gateway[1]: {payload}"
    obj = normalize(wrapped)
    assert isinstance(obj, dict)
    assert obj["conn_id"] == "9114cb20-7e00-4bfd-b50b-aa6f7440127a"


def test_collector_envelope_unwrapped() -> None:
    """A Docker-style ``{"log": "...", "stream": ...}`` wrapper is unwrapped."""
    payload = sample_lines()[1]
    wrapped = json.dumps({"log": payload + "\n", "stream": "stdout", "time": "x"})
    obj = normalize(wrapped)
    assert isinstance(obj, dict)
    assert obj["logger"] == "gateway"
    assert obj["resource_address"] == "kubernetes.default.svc.cluster.local"


def test_junk_and_empty_dropped() -> None:
    """Unparseable, empty, and non-object lines all return None."""
    assert normalize("not json at all") is None
    assert normalize("") is None
    assert normalize("   ") is None
    assert normalize("[1, 2, 3]") is None  # valid JSON, but not an object
    assert normalize("12345") is None


# --- unwrap_collector unit tests --------------------------------------------


def test_unwrap_collector_strips_docker_wrapper() -> None:
    """A Docker-style {"log": "<json>", "stream": ...} wrapper is unwrapped."""
    payload = sample_lines()[1]  # session-start line (has "logger" field)
    wrapper = {"log": payload + "\n", "stream": "stdout", "time": "2026-06-17T00:00:00Z"}
    result = unwrap_collector(wrapper)
    assert isinstance(result, dict)
    assert result.get("logger") == "gateway"
    assert result.get("resource_address") == "kubernetes.default.svc.cluster.local"


def test_unwrap_collector_passthrough_plain_object() -> None:
    """An object that already has a 'logger' field is returned unchanged."""
    obj = json.loads(sample_lines()[0])
    assert "logger" in obj
    result = unwrap_collector(obj)
    assert result is obj  # same object, not a copy


def test_unwrap_collector_wraps_recording_chunk() -> None:
    """A wrapper around a gateway.audit recording chunk unwraps to that chunk."""
    payload = sample_lines()[0]  # recording chunk
    wrapper = {"log": payload, "stream": "stderr"}
    result = unwrap_collector(wrapper)
    assert isinstance(result, dict)
    assert result.get("logger") == "gateway.audit"
    assert "asciicast" in result
    assert result.get("conn_id") == "9114cb20-7e00-4bfd-b50b-aa6f7440127a"


def test_unwrap_collector_returns_none_for_non_object_inner() -> None:
    """A wrapper whose 'log' value does not reduce to a JSON object returns None."""
    # "log" is a plain string, not JSON
    wrapper = {"log": "this is not json", "stream": "stdout"}
    result = unwrap_collector(wrapper)
    assert result is None


def test_unwrap_collector_returns_none_for_array_inner() -> None:
    """A wrapper whose 'log' parses to a JSON array (not an object) returns None."""
    wrapper = {"log": json.dumps([1, 2, 3]), "stream": "stdout"}
    result = unwrap_collector(wrapper)
    assert result is None
