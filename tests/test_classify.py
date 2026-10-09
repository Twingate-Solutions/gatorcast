"""Tests for pipeline.classify: the two-stage recording filter and event shaping."""

from __future__ import annotations

import json
import re

import pytest
from pydantic import ValidationError

from gatorcast.models import RESOURCE_TYPE_INVALID, ApiRequest, RecordingChunk, SessionEnd, SessionStart
from gatorcast.pipeline.classify import (
    _allowlisted_headers,
    _norm_ts,
    _store_url,
    _synth_request_id,
    classify,
)
from tests.samples import FIXTURES, sample_lines

_KUBECTL_FIXTURE = FIXTURES / "kubectl_audit_lines.ndjson"
_CONN_A = "aaaaaaaa-0000-4000-8000-000000000001"
_CONN_B = "aaaaaaaa-0000-4000-8000-000000000002"
_CONN_C = "aaaaaaaa-0000-4000-8000-000000000003"
_EXEC_REQ = "22222222-2222-4222-8222-222222222222"


def _kubectl_objs() -> list[dict]:
    """The synthetic kubectl fixture lines, parsed (index == 0-based line number)."""
    text = _KUBECTL_FIXTURE.read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _api_line(**overrides: object) -> dict:
    """A minimal valid API-request audit line, with overrides applied."""
    obj: dict = {
        "logger": "gateway.audit",
        "message": "API request completed",
        "ts": "2026-10-01T10:00:00.500Z",
        "requested_at": "2026-10-01T10:00:00.400Z",
        "request_id": "req-1",
        "conn_id": "conn-1",
        "method": "GET",
        "url": "/api/v1/pods",
        "user": {"id": "uid-1", "username": "u@example.com"},
    }
    obj.update(overrides)
    return obj


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


def test_api_audit_without_asciicast_is_api_request() -> None:
    """A gateway.audit API line WITHOUT an asciicast is an ApiRequest, never a chunk."""
    obj = json.loads(sample_lines()[2])
    assert obj["logger"] == "gateway.audit"
    assert obj.get("asciicast") is None
    event = classify(obj)
    assert isinstance(event, ApiRequest)
    assert not isinstance(event, RecordingChunk)
    assert event.conn_id == "9114cb20-7e00-4bfd-b50b-aa6f7440127a"
    assert event.method == "GET"
    assert event.url == "/api/v1/pods"  # legacy "path" spelling accepted
    assert event.username == "grady@twingate.com"
    assert event.outcome == "completed"
    assert event.requested_at == "2026-06-17T21:02:10.001Z"  # falls back to ts
    assert event.request_id.startswith("h:")  # sample carries no request_id


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


# --- ApiRequest classification (Session 9, spec §4 / §13) ---


def test_fixture_line_types() -> None:
    """Every fixture line lands in the expected event class (sweep over the file)."""
    events = [classify(o) for o in _kubectl_objs()]
    assert all(e is not None for e in events)
    assert sum(isinstance(e, SessionStart) for e in events) == 3
    assert sum(isinstance(e, RecordingChunk) for e in events) == 2
    assert sum(isinstance(e, ApiRequest) for e in events) == 8


def test_api_request_from_url_line() -> None:
    """A modern line (url + requested_at + request_id) maps field by field."""
    event = classify(_kubectl_objs()[3])
    assert isinstance(event, ApiRequest)
    assert event.conn_id == _CONN_A
    assert event.request_id == "11111111-1111-4111-8111-111111111111"
    assert event.requested_at == "2026-10-01T10:00:01.200Z"
    assert event.user_id == "VXNlcjox"
    assert event.username == "user@example.com"
    assert event.method == "GET"
    assert event.url == "/api?timeout=32s"
    assert event.status_code == 200
    assert event.outcome == "completed"
    assert event.kubectl_command == "kubectl exec"
    assert event.kubectl_session == "5e55e55e-0000-4000-8000-000000000001"
    assert event.user_agent == "kubectl/v1.33.0 (linux/amd64) kubernetes/abcdef0"


def test_legacy_path_line_without_request_id() -> None:
    """A legacy line using ``path`` and no request_id is accepted with a synthetic id."""
    event = classify(_kubectl_objs()[12])
    assert isinstance(event, ApiRequest)
    assert event.url == "/api/v1/namespaces"
    assert event.request_id.startswith("h:")
    assert event.requested_at == "2026-10-01T10:06:00.000Z"


def test_url_preferred_over_path() -> None:
    """When both spellings are present, ``url`` wins."""
    event = classify(_api_line(url="/from-url", path="/from-path"))
    assert isinstance(event, ApiRequest)
    assert event.url == "/from-url"


def test_event_is_frozen() -> None:
    """ApiRequest is immutable."""
    event = classify(_api_line())
    assert isinstance(event, ApiRequest)
    with pytest.raises(ValidationError):
        event.method = "POST"


def test_headers_case_insensitive_first_list_element() -> None:
    """Allowlisted headers match any key case and take the first list element."""
    line = _api_line(
        request={
            "headers": {
                "user-agent": ["ua-1", "ua-2"],
                "KUBECTL-COMMAND": ["kubectl get", "ignored"],
                "Kubectl-Session": ["sess-1"],
            }
        }
    )
    event = classify(line)
    assert isinstance(event, ApiRequest)
    assert event.user_agent == "ua-1"
    assert event.kubectl_command == "kubectl get"
    assert event.kubectl_session == "sess-1"


def test_headers_plain_string_values_accepted() -> None:
    """A bare string header value is accepted defensively."""
    event = classify(_api_line(request={"headers": {"User-Agent": "plain-ua"}}))
    assert isinstance(event, ApiRequest)
    assert event.user_agent == "plain-ua"
    assert event.kubectl_command is None
    assert event.kubectl_session is None


def test_allowlisted_headers_helper_only_returns_allowlist() -> None:
    """The helper never surfaces Authorization, cookies, or any other header."""
    picked = _allowlisted_headers(
        {
            "Authorization": ["Bearer GC_SENTINEL_TOKEN"],
            "Cookie": ["session=GC_SENTINEL_TOKEN"],
            "Accept": ["application/json"],
            "User-Agent": ["kubectl/v1"],
            "Kubectl-Command": ["kubectl get"],
        }
    )
    assert picked == {"user-agent": "kubectl/v1", "kubectl-command": "kubectl get"}
    assert "GC_SENTINEL_TOKEN" not in json.dumps(picked)


@pytest.mark.parametrize("headers", [None, "x", ["a"], 7, {}])
def test_allowlisted_headers_tolerates_garbage(headers: object) -> None:
    """Non-dict / empty headers yield an empty result, not an exception."""
    assert _allowlisted_headers(headers) == {}


def test_allowlisted_headers_skips_empty_and_odd_values() -> None:
    """Empty lists, empty strings, non-string values and non-string keys are skipped."""
    picked = _allowlisted_headers(
        {"User-Agent": [], "Kubectl-Command": "", "Kubectl-Session": [123], 5: ["x"]}
    )
    assert picked == {}


def test_header_value_capped_at_256_chars() -> None:
    """Header values are truncated to 256 characters."""
    picked = _allowlisted_headers({"User-Agent": ["a" * 1000]})
    assert picked["user-agent"] == "a" * 256


def test_model_carries_no_sensitive_data() -> None:
    """Authorization / cookie / response-header / remote_addr data never reach the model."""
    seen = 0
    for obj in _kubectl_objs():
        event = classify(obj)
        if not isinstance(event, ApiRequest):
            continue
        seen += 1
        dumped = event.model_dump_json()
        for needle in (
            "GC_SENTINEL_TOKEN",
            "Bearer",
            "Authorization",
            "Cookie",
            "session=",
            "no-cache",
            "application/json",
            "10.0.0.5",
            "GC_SENTINEL_PANIC",
        ):
            assert needle not in dumped, needle
    assert seen == 8
    assert set(ApiRequest.model_fields) == {
        "conn_id",
        "request_id",
        "requested_at",
        "user_id",
        "username",
        "method",
        "url",
        "status_code",
        "outcome",
        "kubectl_command",
        "kubectl_session",
        "user_agent",
        "url_web",
    }


# --- _store_url ---


def test_exec_url_keeps_only_allowlisted_query_keys() -> None:
    """The fixture exec URL loses ``command`` (and its secret) but keeps the flags."""
    event = classify(_kubectl_objs()[8])
    assert isinstance(event, ApiRequest)
    assert event.request_id == _EXEC_REQ
    assert event.status_code == 101
    assert event.url == (
        "/api/v1/namespaces/default/pods/web-1/exec"
        "?container=nginx&stdin=true&stdout=true&tty=true"
    )
    assert "command" not in event.url
    assert "GC_SENTINEL_CMD" not in event.model_dump_json()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # exec / attach: only the allowlist survives, in original order
        (
            "/api/v1/namespaces/d/pods/p/exec?stderr=true&command=ls&container=c&tty=false&x=1",
            "/api/v1/namespaces/d/pods/p/exec?stderr=true&container=c&tty=false",
        ),
        (
            "/api/v1/namespaces/d/pods/p/attach?command=secret&stdin=true",
            "/api/v1/namespaces/d/pods/p/attach?stdin=true",
        ),
        # nothing allowlisted left -> bare path, no trailing '?'
        (
            "/api/v1/namespaces/d/pods/p/exec?command=sh&command=-c",
            "/api/v1/namespaces/d/pods/p/exec",
        ),
        # an empty container name fails validation and is dropped (not kept blank)
        (
            "/api/v1/namespaces/d/pods/p/exec?container=&command=x",
            "/api/v1/namespaces/d/pods/p/exec",
        ),
        # no query at all
        ("/api/v1/namespaces/d/pods/p/exec", "/api/v1/namespaces/d/pods/p/exec"),
        # selector-style queries on ordinary URLs survive the allowlist
        (
            "/api/v1/namespaces/default/pods?labelSelector=app%3Dweb&limit=500",
            "/api/v1/namespaces/default/pods?labelSelector=app%3Dweb&limit=500",
        ),
        ("/api?timeout=32s", "/api?timeout=32s"),
        # exec as a non-final path segment is not the exec subresource: command dropped
        (
            "/api/v1/namespaces/d/pods/p/exec/extra?command=x",
            "/api/v1/namespaces/d/pods/p/exec/extra",
        ),
        # portforward goes through the allowlist like everything else
        (
            "/api/v1/namespaces/d/pods/p/portforward?ports=80",
            "/api/v1/namespaces/d/pods/p/portforward",
        ),
        # exec-only keys are not allowed on non-exec URLs
        (
            "/api/v1/namespaces/d/pods/p/log?container=c&follow=true&tailLines=10",
            "/api/v1/namespaces/d/pods/p/log?follow=true&tailLines=10",
        ),
    ],
)
def test_store_url(raw: str, expected: str) -> None:
    """_store_url applies the query-key allowlist (plus exec/attach extras) to every URL."""
    assert _store_url(raw) == expected


# --- F1: query allowlist on every URL, proxy truncation ---

_GENERAL_KEYS = [
    "labelSelector",
    "fieldSelector",
    "limit",
    "continue",
    "watch",
    "timeout",
    "timeoutSeconds",
    "resourceVersion",
    "resourceVersionMatch",
    "allowWatchBookmarks",
    "propagationPolicy",
    "gracePeriodSeconds",
    "dryRun",
    "fieldManager",
    "fieldValidation",
    "force",
    "follow",
    "tailLines",
    "sinceSeconds",
    "previous",
    "timestamps",
    "pretty",
    "orphanDependents",
]


@pytest.mark.parametrize("key", _GENERAL_KEYS)
def test_store_url_general_allowlist_keys_survive(key: str) -> None:
    """Every allowlisted general key is stored on an ordinary URL."""
    assert _store_url(f"/api/v1/pods?{key}=x") == f"/api/v1/pods?{key}=x"


@pytest.mark.parametrize(
    "raw",
    [
        "/api/v1/pods?auth_token=GC_SECRET",
        "/api/v1/pods?command=GC_SECRET",
        "/api/v1/pods?ports=GC_SECRET",
        "/api/v1/pods?container=GC_SECRET",  # exec-only key on a non-exec URL
        "/api/v1/pods?LabelSelector=GC_SECRET",  # keys are case-sensitive
        "/api/v1/pods?limit=1&password=GC_SECRET&follow=true",
    ],
)
def test_store_url_drops_non_allowlisted_keys_entirely(raw: str) -> None:
    """A non-allowlisted key is dropped with its value; no empty ``key=`` is kept."""
    stored = _store_url(raw)
    assert "GC_SECRET" not in stored
    for dropped in ("auth_token", "command", "ports", "container", "password", "LabelSelector"):
        assert dropped not in stored


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # F1 probe: node proxy exec keeps only the exec prefix; path tail and query dropped
        (
            "/api/v1/nodes/n1/proxy/exec/ns/p/c?command=cat&command=/etc/token",
            "/api/v1/nodes/n1/proxy/exec",
        ),
        ("/api/v1/nodes/n1/proxy/run/ns/p/c?cmd=x", "/api/v1/nodes/n1/proxy/run"),
        ("/api/v1/nodes/n1/proxy/attach/ns/p/c", "/api/v1/nodes/n1/proxy/attach"),
        # F1 probe: service proxy with a secret in the query
        (
            "/api/v1/namespaces/mon/services/grafana:3000/proxy/api/x?auth_token=SECRET",
            "/api/v1/namespaces/mon/services/grafana:3000/proxy",
        ),
        # F1 probe: pod proxy
        (
            "/api/v1/namespaces/d/pods/p:8080/proxy/admin?password=SECRET",
            "/api/v1/namespaces/d/pods/p:8080/proxy",
        ),
        # F1 probe as literally written (no namespace prefix)
        ("/pods/p:8080/proxy/admin?password=SECRET", "/pods/p:8080/proxy"),
        # bare proxy segment: query still dropped, even allowlisted keys
        ("/api/v1/nodes/n1/proxy?limit=5", "/api/v1/nodes/n1/proxy"),
        ("/api/v1/nodes/n1/proxy/", "/api/v1/nodes/n1/proxy"),
        # other node-proxy subresources are truncated after proxy
        ("/api/v1/nodes/n1/proxy/metrics?x=1", "/api/v1/nodes/n1/proxy"),
        # proxy segment is case-insensitive (fail closed)
        ("/api/v1/nodes/n1/Proxy/Exec/ns/p/c?command=x", "/api/v1/nodes/n1/Proxy/Exec"),
        # first proxy segment wins; a nested node proxy is behind it
        (
            "/api/v1/namespaces/d/services/s/proxy/api/v1/nodes/n1/proxy/exec/x",
            "/api/v1/namespaces/d/services/s/proxy",
        ),
        # exec after a non-node proxy is not kept
        ("/api/v1/namespaces/d/pods/p/proxy/exec/x", "/api/v1/namespaces/d/pods/p/proxy"),
        # "proxy" only as part of a longer segment is not a proxy segment
        ("/api/v1/namespaces/d/pods/proxyish?limit=1", "/api/v1/namespaces/d/pods/proxyish?limit=1"),
    ],
)
def test_store_url_proxy_truncation(raw: str, expected: str) -> None:
    """A ``proxy`` segment keeps the path up to it and drops the rest and the query."""
    assert _store_url(raw) == expected


def test_store_url_proxy_end_to_end_via_classify() -> None:
    """classify() stores the truncated proxy URL; the secret never reaches the model."""
    event = classify(
        _api_line(url="/api/v1/namespaces/mon/services/grafana:3000/proxy/api/x?auth_token=SECRET")
    )
    assert isinstance(event, ApiRequest)
    assert event.url == "/api/v1/namespaces/mon/services/grafana:3000/proxy"
    assert "SECRET" not in event.model_dump_json()


# --- F2: path normalization variants ---

_EXEC_BASE = "/api/v1/namespaces/d/pods/p"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # every F2 probe, with a realistic prefix: command=SECRET never survives
        (f"{_EXEC_BASE}/%65xec?command=SECRET", f"{_EXEC_BASE}/exec"),
        (f"{_EXEC_BASE}/exec/?command=SECRET", f"{_EXEC_BASE}/exec"),
        (f"{_EXEC_BASE}//exec?command=SECRET", f"{_EXEC_BASE}/exec"),
        (f"{_EXEC_BASE}/EXEC?command=SECRET", f"{_EXEC_BASE}/EXEC"),
        (f"{_EXEC_BASE}/exec%3Fcommand=SECRET", f"{_EXEC_BASE}/exec"),
        (f"{_EXEC_BASE}/exec#x?command=SECRET", f"{_EXEC_BASE}/exec"),
        # the probes exactly as written in the finding (no prefix)
        ("/pods/p/%65xec?command=SECRET", "/pods/p/exec"),
        ("/pods/p/exec/?command=SECRET", "/pods/p/exec"),
        ("/pods/p//exec?command=SECRET", "/pods/p/exec"),
        ("/pods/p/EXEC?command=SECRET", "/pods/p/EXEC"),
        ("/pods/p/exec%3Fcommand=SECRET", "/pods/p/exec"),
        ("/pods/p/exec#x?command=SECRET", "/pods/p/exec"),
        # allowlisted flags still survive on a normalized exec path, case-insensitively
        (f"{_EXEC_BASE}/%65xec/?stdin=true&command=SECRET", f"{_EXEC_BASE}/exec?stdin=true"),
        (f"{_EXEC_BASE}/EXEC?tty=1&command=SECRET", f"{_EXEC_BASE}/EXEC?tty=1"),
        # double encoding: path unquoted once, residual % -> whole query dropped
        (f"{_EXEC_BASE}/%2565xec?stdin=true&command=SECRET", f"{_EXEC_BASE}/%65xec"),
        # encoded fragment / slash
        (f"{_EXEC_BASE}/exec%23x?command=SECRET", f"{_EXEC_BASE}/exec"),
        (f"{_EXEC_BASE.replace('/pods/p', '/pods%2Fp')}/exec?command=SECRET", f"{_EXEC_BASE}/exec"),
        # the root path is never stripped to empty
        ("/", "/"),
        ("//", "/"),
        ("/?limit=1", "/?limit=1"),
        # a trailing slash and repeated slashes are normalized on ordinary URLs too
        ("/api/v1//namespaces/d/pods/?limit=5", "/api/v1/namespaces/d/pods?limit=5"),
        # fragment dropped
        ("/api/v1/pods?limit=5#frag", "/api/v1/pods?limit=5"),
        ("/api/v1/pods#frag", "/api/v1/pods"),
    ],
)
def test_store_url_normalizes_path_variants(raw: str, expected: str) -> None:
    """Encoded, repeated-slash, case, fragment and trailing-slash variants cannot leak ``command``."""
    stored = _store_url(raw)
    assert stored == expected
    assert "command" not in stored
    assert "SECRET" not in stored


def test_store_url_fail_closed_on_residual_percent_drops_query() -> None:
    """Double-encoded paths drop the query even for allowlisted keys."""
    assert _store_url("/api/v1/pods%252Fx?limit=5") == "/api/v1/pods%2Fx"
    assert _store_url("/api/v1/pods%3Fx?limit=5") == "/api/v1/pods"


# --- F3: allowlisted exec parameter values are validated ---


@pytest.mark.parametrize(
    "raw",
    [
        f"{_EXEC_BASE}/exec?stdin=true;command=SECRET",
        f"{_EXEC_BASE}/exec?stdout=yes",
        f"{_EXEC_BASE}/exec?stderr=TRUE",
        f"{_EXEC_BASE}/exec?tty=",
        f"{_EXEC_BASE}/exec?tty=2",
        f"{_EXEC_BASE}/exec?container=",
        f"{_EXEC_BASE}/exec?container=Bad_Name",
        f"{_EXEC_BASE}/exec?container=-lead",
        f"{_EXEC_BASE}/exec?container=trail-",
        f"{_EXEC_BASE}/exec?container=c;command=SECRET",
        f"{_EXEC_BASE}/exec?container=c%0A",
        f"{_EXEC_BASE}/exec?container={'a' * 64}",
        f"{_EXEC_BASE}/attach?stdin=true%3Bcommand%3DSECRET",
    ],
)
def test_store_url_invalid_exec_values_are_dropped(raw: str) -> None:
    """Exec flag / container values that fail validation are dropped, key and all."""
    assert _store_url(raw) == raw.partition("?")[0]


@pytest.mark.parametrize("value", ["true", "false", "1", "0"])
@pytest.mark.parametrize("key", ["stdin", "stdout", "stderr", "tty"])
def test_store_url_valid_exec_flags_kept(key: str, value: str) -> None:
    """The four flags accept exactly true/false/1/0."""
    assert _store_url(f"{_EXEC_BASE}/exec?{key}={value}") == f"{_EXEC_BASE}/exec?{key}={value}"


@pytest.mark.parametrize("name", ["c", "nginx", "my-container-1", "a" * 63, "0abc"])
def test_store_url_valid_container_kept(name: str) -> None:
    """DNS-label-style container names are kept."""
    assert _store_url(f"{_EXEC_BASE}/exec?container={name}") == (
        f"{_EXEC_BASE}/exec?container={name}"
    )


@pytest.mark.parametrize(
    "raw",
    [
        "/api/v1/pods?labelSelector=a;command=SECRET",
        "/api/v1/pods?labelSelector=a%3Bb",
        "/api/v1/pods?labelSelector=a%00b",
        "/api/v1/pods?labelSelector=a%0Ab",
        "/api/v1/pods?labelSelector=a%1Fb",
        "/api/v1/pods?labelSelector=a%7Fb",
        f"/api/v1/pods?labelSelector={'a' * 257}",
    ],
)
def test_store_url_general_value_validation_drops(raw: str) -> None:
    """General allowlisted values with ``;``, a control character, or >256 chars are dropped."""
    assert _store_url(raw) == "/api/v1/pods"


def test_store_url_general_value_at_cap_is_kept() -> None:
    """A 256-character value is within the cap."""
    value = "a" * 256
    assert _store_url(f"/api/v1/pods?labelSelector={value}") == (
        f"/api/v1/pods?labelSelector={value}"
    )


def test_store_url_exec_allows_general_keys_too() -> None:
    """The exec allowlist is additive: general keys still pass on exec URLs."""
    assert _store_url(f"{_EXEC_BASE}/exec?timeout=5s&stdin=true&command=x") == (
        f"{_EXEC_BASE}/exec?timeout=5s&stdin=true"
    )


def test_non_exec_query_kept_end_to_end() -> None:
    """labelSelector / timeout / limit survive classification on ordinary requests."""
    objs = _kubectl_objs()
    pods = classify(objs[5])
    discovery = classify(objs[3])
    assert isinstance(pods, ApiRequest) and isinstance(discovery, ApiRequest)
    assert pods.url == "/api/v1/namespaces/default/pods?labelSelector=app%3Dweb&limit=500"
    assert discovery.url == "/api?timeout=32s"


def test_url_capped_at_4096_chars() -> None:
    """An oversized URL is truncated to 4096 characters."""
    event = classify(_api_line(url="/" + "a" * 6000))
    assert isinstance(event, ApiRequest)
    assert len(event.url) == 4096


# --- status / outcome ---


def test_502_completed_keeps_status() -> None:
    """A non-2xx outcome still says 'completed' and keeps its status code."""
    event = classify(_kubectl_objs()[9])
    assert isinstance(event, ApiRequest)
    assert event.status_code == 502
    assert event.outcome == "completed"


def test_failed_message_has_no_status_and_no_panic() -> None:
    """'API request failed' -> outcome 'failed', status None, panic text never read."""
    obj = _kubectl_objs()[11]
    assert obj["message"] == "API request failed"
    assert "GC_SENTINEL_PANIC" in obj["panic"]
    event = classify(obj)
    assert isinstance(event, ApiRequest)
    assert event.outcome == "failed"
    assert event.status_code is None
    assert event.method == "GET"
    assert event.url == "/api/v1/nodes"
    dumped = event.model_dump_json()
    assert "GC_SENTINEL_PANIC" not in dumped
    assert "panic" not in dumped


def test_failed_message_ignores_status_even_if_response_present() -> None:
    """A failed line never reads response.status_code."""
    event = classify(_api_line(message="API request failed", response={"status_code": 500}))
    assert isinstance(event, ApiRequest)
    assert event.outcome == "failed"
    assert event.status_code is None


@pytest.mark.parametrize("status", [99, 600, "200", 200.0, True, None])
def test_invalid_status_becomes_none(status: object) -> None:
    """Out-of-range or non-int statuses are stored as None."""
    event = classify(_api_line(response={"status_code": status}))
    assert isinstance(event, ApiRequest)
    assert event.status_code is None


def test_missing_response_is_status_none() -> None:
    """No response object at all is tolerated."""
    obj = _api_line()
    obj.pop("response", None)
    event = classify(obj)
    assert isinstance(event, ApiRequest)
    assert event.status_code is None


# --- requested_at normalization ---


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-10-01T10:00:01.200Z", "2026-10-01T10:00:01.200Z"),
        ("2026-10-01T10:05:01.123456789Z", "2026-10-01T10:05:01.123Z"),  # truncated
        ("2026-10-01T10:05:01Z", "2026-10-01T10:05:01.000Z"),  # ms padded
        ("2026-10-01T12:00:00.5+02:00", "2026-10-01T10:00:00.500Z"),  # converted to UTC
        ("2026-10-01T10:00:00.250", "2026-10-01T10:00:00.250Z"),  # naive taken as UTC
        ("2026-10-01T23:30:00-05:00", "2026-10-02T04:30:00.000Z"),  # day rollover
    ],
)
def test_norm_ts(raw: str, expected: str) -> None:
    """_norm_ts always yields ``YYYY-MM-DDTHH:MM:SS.mmmZ`` in UTC."""
    assert _norm_ts(raw) == expected


@pytest.mark.parametrize("raw", [None, 123, "", "not a time", ["2026-10-01T00:00:00Z"]])
def test_norm_ts_rejects_garbage(raw: object) -> None:
    """Non-strings and unparseable strings give None."""
    assert _norm_ts(raw) is None


@pytest.mark.parametrize(
    "raw",
    [
        "0001-01-01T00:00:00+01:00",  # UTC conversion underflows
        "9999-12-31T23:59:59-01:00",  # UTC conversion overflows
    ],
)
def test_norm_ts_out_of_range_is_none_not_overflow(raw: str) -> None:
    """F6: a timestamp whose UTC conversion overflows returns None instead of raising."""
    assert _norm_ts(raw) is None


@pytest.mark.parametrize(
    "ts", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"]
)
def test_out_of_range_timestamp_line_is_dropped(ts: str) -> None:
    """F6: classify() drops the line (no exception) when requested_at overflows."""
    assert classify(_api_line(requested_at=ts)) is None
    assert classify(_api_line(requested_at=None, ts=ts)) is None


# --- F4: validation regexes are full matches, not '$' matches ---


@pytest.mark.parametrize("bad", ["abc\n", "abc\r\n", "\nabc", "abc\x00", "a b", "../x", ""])
def test_conn_id_must_fully_match(bad: str) -> None:
    """F4: a conn_id with a trailing newline (or any stray char) is rejected on every path."""
    chunk = {
        "logger": "gateway.audit",
        "conn_id": bad,
        "asciicast": "x",
        "asciicast_sequence_num": 0,
    }
    assert classify(chunk) is None
    assert classify(_api_line(conn_id=bad)) is None
    assert (
        classify(
            {"logger": "gateway", "message": "Authenticated connection", "conn_id": bad}
        )
        is None
    )
    assert classify({"logger": "gateway", "message": "Connection closed", "conn_id": bad}) is None
    for etype in ("session_start", "recording_chunk", "session_end"):
        assert (
            classify({"type": etype, "conn_id": bad, "seq": 0, "events": "[1,\"o\",\"x\"]\n"})
            is None
        )


def test_conn_id_without_trailing_newline_still_accepted() -> None:
    """F4: the same conn_id minus the newline is still valid (behaviour otherwise unchanged)."""
    chunk = {
        "logger": "gateway.audit",
        "conn_id": "abc",
        "asciicast": "x",
        "asciicast_sequence_num": 0,
    }
    assert isinstance(classify(chunk), RecordingChunk)
    assert isinstance(classify(_api_line(conn_id="abc")), ApiRequest)


@pytest.mark.parametrize("bad", ["abc\n", "abc\r\n", "x\x00"])
def test_request_id_must_fully_match(bad: str) -> None:
    """F4: an unsafe request_id is never stored; an API line falls back to a synthesized id."""
    event = classify(_api_line(request_id=bad))
    assert isinstance(event, ApiRequest)
    assert event.request_id.startswith("h:")
    chunk = classify(
        {
            "logger": "gateway.audit",
            "conn_id": "abc",
            "asciicast": "x",
            "asciicast_sequence_num": 0,
            "request_id": bad,
        }
    )
    assert isinstance(chunk, RecordingChunk)
    assert chunk.request_id is None


@pytest.mark.parametrize(
    "bad", ["DELETE\n", "GET\n", "GET ", "", "A" * 25, "1GET", "-GET", "_GET", "G ET", "GE\x00T"]
)
def test_http_method_must_fully_match(bad: str) -> None:
    """F4: a method with a trailing newline (or any char outside the gate) is dropped."""
    assert classify(_api_line(method=bad)) is None


@pytest.mark.parametrize(
    "method",
    ["get", "Get", "GE", "G", "ABCDEFGHIJK", "TOOLONGMETHOD", "MKWORKSPACE", "delete", "M-SEARCH", "A" * 24],
)
def test_widened_method_gate_accepts_and_stores_method_as_received(method: str) -> None:
    """WEBAPP_SPEC 5.6: lowercase, short and 11-24 character methods now produce a row, unchanged."""
    event = classify(_api_line(method=method))
    assert isinstance(event, ApiRequest)
    assert event.method == method


def test_http_method_valid_accepted() -> None:
    """F4: well-formed methods are unaffected."""
    event = classify(_api_line(method="DELETE"))
    assert isinstance(event, ApiRequest)
    assert event.method == "DELETE"


def test_requested_at_normalized_in_event() -> None:
    """The 9-digit-fraction fixture timestamp is normalized on the model."""
    event = classify(_kubectl_objs()[9])
    assert isinstance(event, ApiRequest)
    assert event.requested_at == "2026-10-01T10:05:01.123Z"


def test_requested_at_falls_back_to_ts() -> None:
    """Without ``requested_at`` the line's ``ts`` is used."""
    obj = _api_line()
    obj.pop("requested_at")
    event = classify(obj)
    assert isinstance(event, ApiRequest)
    assert event.requested_at == "2026-10-01T10:00:00.500Z"


# --- request_id: Gateway id vs synthetic ---


def test_missing_request_id_gets_deterministic_synthetic_id() -> None:
    """The same line classified twice yields the same ``h:`` id (redelivery dedup)."""
    obj = _api_line()
    obj.pop("request_id")
    first, second = classify(obj), classify(dict(obj))
    assert isinstance(first, ApiRequest) and isinstance(second, ApiRequest)
    assert first.request_id == second.request_id
    assert first.request_id.startswith("h:")
    assert len(first.request_id) == len("h:") + 32
    assert all(c in "0123456789abcdef" for c in first.request_id[2:])
    assert first.request_id == _synth_request_id(
        "conn-1", "2026-10-01T10:00:00.400Z", "GET", "/api/v1/pods"
    )


def test_synthetic_id_varies_with_each_input() -> None:
    """conn_id, time, method and URL each change the synthetic id."""
    base = ("c", "2026-10-01T10:00:00.000Z", "GET", "/x")
    ids = {
        _synth_request_id(*base),
        _synth_request_id("d", *base[1:]),
        _synth_request_id(base[0], "2026-10-01T10:00:00.001Z", *base[2:]),
        _synth_request_id(*base[:2], "POST", base[3]),
        _synth_request_id(*base[:3], "/y"),
    }
    assert len(ids) == 5


def test_synthetic_id_field_boundaries_do_not_collide() -> None:
    """The NUL separator keeps ('ab','c') distinct from ('a','bc')."""
    assert _synth_request_id("ab", "c", "GET", "/x") != _synth_request_id("a", "bc", "GET", "/x")


@pytest.mark.parametrize("bad", ["../x", "a/b", "", "x" * 200, 12345])
def test_unsafe_request_id_is_replaced_by_synthetic(bad: object) -> None:
    """A request_id that is not a safe token is not trusted; a synthetic id is used."""
    event = classify(_api_line(request_id=bad))
    assert isinstance(event, ApiRequest)
    assert event.request_id.startswith("h:")


def test_gateway_request_id_is_kept_verbatim() -> None:
    """A safe Gateway request_id is used as-is."""
    event = classify(_api_line(request_id="11111111-1111-4111-8111-111111111111"))
    assert isinstance(event, ApiRequest)
    assert event.request_id == "11111111-1111-4111-8111-111111111111"


# --- drops ---


@pytest.mark.parametrize("conn_id", ["../../etc/passwd", "a/b", "", None, 5, "x" * 129])
def test_api_bad_conn_id_dropped(conn_id: object) -> None:
    """An unsafe or non-string conn_id drops the API line."""
    assert classify(_api_line(conn_id=conn_id)) is None


def test_api_missing_conn_id_dropped() -> None:
    """An absent conn_id key drops the API line."""
    obj = _api_line()
    obj.pop("conn_id")
    assert classify(obj) is None


@pytest.mark.parametrize(
    "method", ["G ET", "", None, 5, "A" * 25, "1GET", "-GET", "GET\n", "GE\tT", ["GET"]]
)
def test_api_bad_method_dropped(method: object) -> None:
    """A method with a space/control char, over 24 chars, leading digit, or non-string drops the line."""
    assert classify(_api_line(method=method)) is None


def test_api_missing_method_dropped() -> None:
    """An absent method drops the line."""
    obj = _api_line()
    obj.pop("method")
    assert classify(obj) is None


@pytest.mark.parametrize("url", ["api/v1/pods", "http://x/api", "", None, 7, ["/a"]])
def test_api_bad_url_dropped(url: object) -> None:
    """A URL that is not a string starting with '/' drops the line."""
    assert classify(_api_line(url=url)) is None


def test_api_missing_url_and_path_dropped() -> None:
    """With neither ``url`` nor ``path`` the line is dropped."""
    obj = _api_line()
    obj.pop("url")
    assert classify(obj) is None


def test_api_bad_time_dropped() -> None:
    """With no parseable requested_at / ts the line is dropped."""
    assert classify(_api_line(requested_at="garbage", ts="also garbage")) is None
    obj = _api_line()
    obj.pop("requested_at")
    obj.pop("ts")
    assert classify(obj) is None


@pytest.mark.parametrize(
    "message", ["API request started", "session recording", "", None, "Something"]
)
def test_other_gateway_audit_messages_dropped(message: object) -> None:
    """gateway.audit lines with any other message and no asciicast are noise."""
    assert classify(_api_line(message=message)) is None


def test_api_message_on_other_logger_dropped() -> None:
    """The API message is only honored on the gateway.audit logger."""
    assert classify(_api_line(logger="gateway")) is None
    assert classify(_api_line(logger="other")) is None


def test_api_line_with_asciicast_is_still_a_chunk() -> None:
    """Any line carrying an asciicast string stays a RecordingChunk (branch 1 wins)."""
    event = classify(_api_line(asciicast="x", asciicast_sequence_num=0))
    assert isinstance(event, RecordingChunk)


def test_api_identity_missing_user_is_none() -> None:
    """No ``user`` object leaves both identity fields None (line is still kept)."""
    obj = _api_line()
    obj.pop("user")
    event = classify(obj)
    assert isinstance(event, ApiRequest)
    assert event.user_id is None and event.username is None


# --- RecordingChunk.request_id / SessionStart.user_id ---


def test_k8s_chunk_carries_request_id() -> None:
    """Exec chunk lines expose their request_id for linking to the API audit line."""
    objs = _kubectl_objs()
    for idx, seq in ((6, 0), (7, 1)):
        event = classify(objs[idx])
        assert isinstance(event, RecordingChunk)
        assert event.conn_id == _CONN_B
        assert event.seq == seq
        assert event.request_id == _EXEC_REQ
    final = classify(objs[7])
    assert isinstance(final, RecordingChunk) and final.is_final is True


def test_ssh_chunk_has_no_request_id() -> None:
    """A chunk from the real SSH-style sample has request_id None."""
    event = classify(json.loads(sample_lines()[0]))
    assert isinstance(event, RecordingChunk)
    assert event.request_id is None


@pytest.mark.parametrize("bad", ["../x", "a b", "", 5])
def test_chunk_unsafe_request_id_is_none(bad: object) -> None:
    """A chunk's request_id must pass the safe-token check, else it falls back to None."""
    event = classify(
        {
            "logger": "gateway.audit",
            "conn_id": "abc",
            "asciicast": "x",
            "asciicast_sequence_num": 0,
            "request_id": bad,
        }
    )
    assert isinstance(event, RecordingChunk)
    assert event.request_id is None


def test_session_start_carries_user_id() -> None:
    """The legacy 'Authenticated connection' branch sets SessionStart.user_id."""
    event = classify(_kubectl_objs()[0])
    assert isinstance(event, SessionStart)
    assert event.user_id == "VXNlcjox"
    assert event.resource_address == "k8s.example.internal"
    assert event.username == "user@example.com"
    sample = classify(json.loads(sample_lines()[1]))
    assert isinstance(sample, SessionStart)
    assert sample.user_id == "VXNlcjoxMzk2NDA="


def test_session_start_without_user_id() -> None:
    """A start line with no user.id leaves user_id None."""
    event = classify(
        {
            "logger": "gateway",
            "message": "Authenticated connection",
            "conn_id": "abc",
            "user": {"username": "u@example.com"},
        }
    )
    assert isinstance(event, SessionStart)
    assert event.user_id is None


def test_envelope_session_start_has_no_user_id() -> None:
    """Envelope session_start records are unchanged: user_id stays None."""
    event = classify({"type": "session_start", "conn_id": "abc", "sso_user": "u@example.com"})
    assert isinstance(event, SessionStart)
    assert event.user_id is None
    assert event.username == "u@example.com"


# --- Session 11 (web apps): resource_type, url_web, method gate, header tolerance, identity ---

from tests.samples import (  # noqa: E402
    WEBAPP_GWOPS_CASES,
    WEBAPP_GWOPS_SENTINELS,
    WEBAPP_HEADER_VARIANTS,
    WEBAPP_NEVER_STORED_SENTINELS,
    WEBAPP_PATH_TOKENS,
    WEBAPP_WORKED_EXAMPLES,
    check_webapp_fixture_index,
    webapp_lines,
    webapp_request_line,
    webapp_start_line,
)

_WEB_IDENTITY = "PLACEHOLDER-KEY-ID-1"


def _start_line(**overrides: object) -> dict:
    """A minimal valid ``Authenticated connection`` line, with overrides applied."""
    obj: dict = {
        "logger": "gateway",
        "message": "Authenticated connection",
        "conn_id": "conn-1",
        "ts": "2026-10-01T10:00:00.000Z",
        "user": {"id": "uid-1", "username": "u@example.com"},
        "resource_address": "portal.example.test",
    }
    obj.update(overrides)
    return obj


def _web_event(request_key: str) -> ApiRequest:
    """Classify the fixture request line registered under ``request_key``."""
    event = classify(json.loads(webapp_request_line(request_key)))
    assert isinstance(event, ApiRequest), request_key
    return event


def test_webapp_fixture_index_matches_the_fixture_files() -> None:
    """The registries in tests/samples.py agree with webapp_lines.ndjson and the interim file."""
    check_webapp_fixture_index()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("kubernetes", "KUBERNETES"),
        ("KUBERNETES", "KUBERNETES"),
        ("Kubernetes", "KUBERNETES"),
        ("  kubernetes  ", "KUBERNETES"),
        ("WEB_APP", "WEB_APP"),
        ("web_app", "WEB_APP"),
        ("SSH", "SSH"),
        ("ssh", "SSH"),
        ("DATABASE", "DATABASE"),
        ("A" + "B" * 31, "A" + "B" * 31),  # 32 characters: the upper bound
        ("A" + "B" * 32, RESOURCE_TYPE_INVALID),  # 33 characters
        ("WEB APP", RESOURCE_TYPE_INVALID),
        ("WEB-APP", RESOURCE_TYPE_INVALID),
        ("1ST", RESOURCE_TYPE_INVALID),
        ("_X", RESOURCE_TYPE_INVALID),
        ("", RESOURCE_TYPE_INVALID),
        ("   ", RESOURCE_TYPE_INVALID),
        ("WEB_APP\n", "WEB_APP"),  # strip() removes the newline before validation
        ("WEB\nAPP", RESOURCE_TYPE_INVALID),
        (123, RESOURCE_TYPE_INVALID),
        (None, None),
        (["SSH"], RESOURCE_TYPE_INVALID),
        (True, RESOURCE_TYPE_INVALID),
    ],
)
def test_start_resource_type_is_normalized(raw: object, expected: str | None) -> None:
    """WEBAPP_SPEC 4.1: strip + upper-case, keep ``[A-Z][A-Z0-9_]{0,31}``; null is None, anything else the marker."""
    event = classify(_start_line(resource_type=raw))
    assert isinstance(event, SessionStart)
    assert event.resource_type == expected
    assert event.conn_id == "conn-1"  # an unusable type never changes the rest of the line
    assert event.resource_address == "portal.example.test"


def test_start_without_resource_type_key_has_none() -> None:
    """A start line with no ``resource_type`` key (old fork, other senders) yields None."""
    event = classify(_start_line())
    assert isinstance(event, SessionStart)
    assert event.resource_type is None
    assert event.gwops is None


def test_kubectl_fixture_start_lines_normalize_to_uppercase_kubernetes() -> None:
    """The existing fixture's start lines normalize to ``KUBERNETES``."""
    types = {
        classify(obj).resource_type
        for obj in _kubectl_objs()
        if obj.get("message") == "Authenticated connection"
    }
    assert types == {"KUBERNETES"}


@pytest.mark.parametrize("case", WEBAPP_GWOPS_CASES, ids=lambda c: c.key)
def test_web_fixture_start_lines_carry_the_expected_normalized_resource_type(case) -> None:
    """Every synthetic start line in the web fixture normalizes to the type samples.py documents."""
    event = classify(json.loads(webapp_start_line(case.key)))
    assert isinstance(event, SessionStart)
    assert event.resource_type == case.resource_type
    assert event.username == _WEB_IDENTITY
    assert event.resource_address  # every start line names its target


@pytest.mark.parametrize(
    ("key", "raw", "stored"), WEBAPP_WORKED_EXAMPLES, ids=[row[0] for row in WEBAPP_WORKED_EXAMPLES]
)
def test_api_request_url_web_is_the_web_policy_form(key: str, raw: str, stored: str) -> None:
    """``url_web`` is the WEBAPP_SPEC 5.7 stored form; ``url`` stays the Kubernetes form."""
    event = _web_event(key)
    assert event.url_web == stored
    assert event.url == _store_url(raw)[:4096]


def test_url_web_masks_query_values_while_url_drops_them() -> None:
    """A secret query value is masked in ``url_web`` and absent from ``url``; neither holds it whole."""
    event = _web_event("hy_query_login")
    dumped = event.model_dump_json()
    for sentinel in WEBAPP_NEVER_STORED_SENTINELS:
        assert sentinel not in dumped
    assert "token=" in event.url_web  # key kept, value masked
    assert re.search(r"token=.{0,2}….{0,2}\(\d+\)$", event.url_web)  # masked, length appended


def test_url_web_keeps_path_tokens_unmasked() -> None:
    """WEBAPP_SPEC 5.3 withdrawn: a path token is stored in full in ``url_web``."""
    event = _web_event("hy_path_reset")
    assert any(token in event.url_web for token in WEBAPP_PATH_TOKENS)


def test_url_web_is_capped_after_masking() -> None:
    """A very long URL is capped at 4096 characters and its query sentinel does not survive."""
    event = _web_event("hy_long_url")
    assert len(event.url_web) <= 4096
    assert len(event.url) <= 4096
    for sentinel in WEBAPP_NEVER_STORED_SENTINELS:
        assert sentinel not in event.model_dump_json()


def test_url_web_is_required_for_hand_built_models() -> None:
    """``url_web`` has no default: a hand-built ApiRequest must say which URL form it carries."""
    with pytest.raises(ValidationError) as exc:
        ApiRequest(
            conn_id="c", request_id="r", requested_at="2026-10-01T10:00:00.000Z", method="GET", url="/x"
        )
    assert [e["loc"] for e in exc.value.errors()] == [("url_web",)]
    assert exc.value.errors()[0]["type"] == "missing"
    built = ApiRequest(
        conn_id="c", request_id="r", requested_at="2026-10-01T10:00:00.000Z", method="GET", url="/x", url_web="/x"
    )
    assert built.url_web == "/x"


@pytest.mark.parametrize(
    ("key", "method"),
    [
        ("hy_method_lower_delete", "delete"),
        ("hy_method_mkworkspace", "MKWORKSPACE"),
        ("cap_method_propfind", "PROPFIND"),
        ("cap_delete_items_42", "DELETE"),
    ],
)
def test_web_fixture_lowercase_and_long_methods_produce_rows(key: str, method: str) -> None:
    """``delete`` and ``MKWORKSPACE`` classify, with the method stored as received."""
    assert _web_event(key).method == method


@pytest.mark.parametrize("key", ["bm_space", "bm_too_long", "bm_digit_first", "bm_empty"])
def test_web_fixture_methods_the_gate_still_rejects_are_dropped(key: str) -> None:
    """Fixture requests with a space, 25 characters, a leading digit or no method return None."""
    assert classify(json.loads(webapp_request_line(key))) is None


@pytest.mark.parametrize(
    "key",
    [
        "ht_ua_missing",
        "ht_ua_empty_list",
        "ht_ua_int_first",
        "ht_ua_int_value",
        "ht_ua_empty_string",
        "ht_no_request_key",
        "ht_headers_not_dict",
    ],
)
def test_unusable_allowlisted_header_is_absent_and_line_still_classified(key: str) -> None:
    """WEBAPP_SPEC 5.5: missing, empty, wrong-type or non-dict headers store User-Agent as None."""
    event = _web_event(key)
    assert event.user_agent is None
    assert event.kubectl_command is None
    assert event.kubectl_session is None
    assert event.url_web  # the row is intact


@pytest.mark.parametrize("key", ["ht_ua_placeholder", "ht_ua_plain_string"])
def test_usable_allowlisted_header_is_kept(key: str) -> None:
    """A placeholder string or a plain non-empty string is stored as is."""
    event = _web_event(key)
    assert isinstance(event.user_agent, str) and event.user_agent


@pytest.mark.parametrize("key", ["k8s_ht_no_kubectl_headers", "k8s_ht_empty_lists"])
def test_absent_kubectl_headers_leave_command_and_session_none(key: str) -> None:
    """Kubernetes lines without usable Kubectl-* headers are still classified, with NULL columns."""
    event = _web_event(key)
    assert event.kubectl_command is None
    assert event.kubectl_session is None
    assert event.method and event.url


@pytest.mark.parametrize("group", sorted(WEBAPP_HEADER_VARIANTS))
def test_credential_header_variants_classify_to_identical_events(group: str) -> None:
    """Values present, placeholdered and names removed give the same event (ids and time aside)."""
    variants = WEBAPP_HEADER_VARIANTS[group]
    dumps = []
    for form in ("present", "placeholder", "removed"):
        event = _web_event(variants[form])
        dumps.append(event.model_dump(exclude={"conn_id", "request_id", "requested_at"}))
    assert dumps[0] == dumps[1] == dumps[2]
    assert dumps[0]["user_agent"]


@pytest.mark.parametrize("key", ["cap_spoofed_identity", "spoof_four_spellings"])
def test_spoofed_identity_headers_never_change_the_identity(key: str) -> None:
    """X-Twingate-User / X_twingate_user (any spelling) are never read: identity is user.username."""
    event = _web_event(key)
    assert event.username == _WEB_IDENTITY
    assert event.user_id == _WEB_IDENTITY
    dumped = event.model_dump_json()
    for sentinel in WEBAPP_NEVER_STORED_SENTINELS:
        assert sentinel not in dumped


def test_spoofed_identity_header_does_not_override_a_distinct_username() -> None:
    """With a username that differs from the spoofed value, the envelope user still wins."""
    obj = _api_line(
        request={
            "headers": {
                "X-Twingate-User": ["mallory"],
                "X_twingate_user": ["mallory"],
                "User-Agent": ["ua"],
            }
        }
    )
    event = classify(obj)
    assert isinstance(event, ApiRequest)
    assert event.username == "u@example.com"
    assert event.user_id == "uid-1"
    assert "mallory" not in event.model_dump_json()


def test_failed_web_line_keeps_outcome_and_drops_panic() -> None:
    """An ``API request failed`` web line is outcome=failed with no status and no panic text."""
    event = _web_event("hy_failed_panic")
    assert event.outcome == "failed"
    assert event.status_code is None
    for sentinel in WEBAPP_NEVER_STORED_SENTINELS:
        assert sentinel not in event.model_dump_json()


def test_no_never_stored_sentinel_reaches_any_classified_web_fixture_event() -> None:
    """Across every fixture line no credential, spoof, query, panic or gwops sentinel survives."""
    classified = 0
    for line in webapp_lines():
        event = classify(json.loads(line))
        if event is None:
            continue
        classified += 1
        dumped = event.model_dump_json()
        for sentinel in WEBAPP_NEVER_STORED_SENTINELS:
            if isinstance(event, SessionStart) and sentinel in WEBAPP_GWOPS_SENTINELS:
                continue  # a valid exact gwops object's app is accepted and stored by design
            assert sentinel not in dumped, sentinel
    assert classified > 200


# --- Session 11 T12: the gwops object on WEB_APP start lines (WEBAPP_SPEC 3.3, 12.2) ---

import io  # noqa: E402
import logging  # noqa: E402

import structlog  # noqa: E402

from gatorcast.models import GwopsWebApp  # noqa: E402
from gatorcast.pipeline import classify as classify_module  # noqa: E402
from tests.samples import WEBAPP_CONNS  # noqa: E402

_GWOPS_FIELDS = {
    "match", "gateway_id", "app", "managed",
    "downstream_tls", "downstream_port", "upstream_tls", "upstream_port",
}
_ACCEPTED = [c for c in WEBAPP_GWOPS_CASES if c.outcome == "accepted"]
_APP_IGNORED = [c for c in WEBAPP_GWOPS_CASES if c.outcome == "accepted_app_ignored"]
_REJECTED = [c for c in WEBAPP_GWOPS_CASES if c.outcome == "rejected"]
_NOT_READ = [c for c in WEBAPP_GWOPS_CASES if c.outcome == "not_read"]
_ABSENT = [c for c in WEBAPP_GWOPS_CASES if c.outcome == "absent"]
_REJECT_REASONS = {
    "gwops_not_object", "gwops_bad_schema", "gwops_bad_match", "gwops_bad_gateway_id",
    "gwops_bad_managed", "gwops_bad_mode", "gwops_bad_port",
}


class _GwopsLog:
    """JSON-lines capture of the classifier's logger (all levels)."""

    def __init__(self) -> None:
        self.buffer = io.StringIO()

    def events(self) -> list[dict]:
        """Every event logged so far, parsed."""
        return [json.loads(ln) for ln in self.buffer.getvalue().splitlines() if ln.strip()]

    def gwops_events(self) -> list[dict]:
        """Only the ``classify.gwops_*`` events."""
        return [e for e in self.events() if str(e["event"]).startswith("classify.gwops_")]


@pytest.fixture
def cls_log(monkeypatch: pytest.MonkeyPatch) -> _GwopsLog:
    """Swap the classifier's module logger for one rendering JSON lines to a buffer.

    structlog caches loggers on first use, so its own capture is unreliable across a
    suite; replacing the module logger is how ``test_secret_hygiene`` does it.
    """
    capture = _GwopsLog()
    logger = structlog.wrap_logger(
        structlog.PrintLogger(file=capture.buffer),
        processors=[structlog.processors.add_log_level, structlog.processors.JSONRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
    )
    monkeypatch.setattr(classify_module, "log", logger)
    return capture


def _gwops_start(key: str) -> dict:
    """The parsed ``Authenticated connection`` line of fixture connection ``key``."""
    return json.loads(webapp_start_line(key))


def _web_start(**gwops_overrides: object) -> dict:
    """A WEB_APP start line whose valid exact ``gwops`` object has ``gwops_overrides`` applied.

    A value of ``...`` removes the key.
    """
    gwops: dict = {
        "schema": 1, "gateway_id": "R2F0ZXdheToxMjk0", "match": "exact", "app": "unit-app",
        "managed": True, "downstream_tls": "tls13", "downstream_port": 443,
        "upstream_tls": "verify_full", "upstream_port": 8443,
    }
    for key, value in gwops_overrides.items():
        if value is ...:
            gwops.pop(key, None)
        else:
            gwops[key] = value
    return _start_line(resource_type="WEB_APP", gwops=gwops)


def _only_warning(log: _GwopsLog) -> dict:
    """The single ``classify.gwops_*`` event, which must carry exactly ``reason`` and ``conn_id``."""
    events = log.gwops_events()
    assert len(events) == 1, events
    event = events[0]
    assert set(event) == {"event", "level", "reason", "conn_id"}, event
    assert event["level"] == "warning"
    return event


def test_gwops_case_table_covers_every_outcome_and_all_reject_reasons() -> None:
    """The fixture table drives the tests below: 62 cases, every reason code present."""
    assert len(WEBAPP_GWOPS_CASES) == 62
    assert {c.reason for c in _REJECTED} == _REJECT_REASONS
    assert {c.reason for c in _APP_IGNORED} == {"gwops_bad_app"}
    assert all(c.expected is not None for c in _ACCEPTED + _APP_IGNORED)
    assert len(_ACCEPTED) + len(_APP_IGNORED) + len(_REJECTED) + len(_NOT_READ) + len(_ABSENT) == 62


@pytest.mark.parametrize("case", _ACCEPTED, ids=lambda c: c.key)
def test_gwops_accepted_variant_parses_to_the_expected_model_and_logs_nothing(case, cls_log) -> None:
    """A valid object yields the frozen model with exactly the documented fields; no warning."""
    event = classify(_gwops_start(case.key))
    assert isinstance(event, SessionStart)
    assert isinstance(event.gwops, GwopsWebApp)
    assert event.gwops.model_dump() == case.expected
    assert event.resource_type == "WEB_APP"
    assert cls_log.gwops_events() == []


@pytest.mark.parametrize("case", _APP_IGNORED, ids=lambda c: c.key)
def test_gwops_bad_app_is_dropped_with_one_field_ignored_warning_and_the_rest_accepted(
    case, cls_log
) -> None:
    """A bad ``app`` becomes None, everything else is kept, and one warning names only the reason."""
    event = classify(_gwops_start(case.key))
    assert isinstance(event, SessionStart)
    assert event.gwops is not None and event.gwops.app is None
    assert event.gwops.model_dump() == case.expected
    warning = _only_warning(cls_log)
    assert warning["event"] == "classify.gwops_field_ignored"
    assert warning["reason"] == case.reason == "gwops_bad_app"
    assert warning["conn_id"] == WEBAPP_CONNS[case.key].conn_id


@pytest.mark.parametrize("case", _REJECTED, ids=lambda c: c.key)
def test_gwops_rejected_variant_yields_none_with_one_warning_naming_only_the_reason(
    case, cls_log
) -> None:
    """Each invalid object is dropped whole: gwops None, exact reason code, reason + conn_id only."""
    event = classify(_gwops_start(case.key))
    assert isinstance(event, SessionStart)
    assert event.gwops is None
    warning = _only_warning(cls_log)
    assert warning["event"] == "classify.gwops_rejected"
    assert warning["reason"] == case.reason
    assert warning["conn_id"] == WEBAPP_CONNS[case.key].conn_id
    assert len(cls_log.events()) == 1  # nothing else was logged for the line


@pytest.mark.parametrize("case", _REJECTED, ids=lambda c: c.key)
def test_gwops_rejected_start_classifies_identically_to_the_same_line_without_the_object(
    case, cls_log
) -> None:
    """A rejected object never changes any other field of the SessionStart."""
    obj = _gwops_start(case.key)
    stripped = {k: v for k, v in obj.items() if k != "gwops"}
    with_object = classify(obj)
    assert len(cls_log.gwops_events()) == 1
    without_object = classify(stripped)
    assert len(cls_log.gwops_events()) == 1  # the stripped line logged nothing
    assert with_object == without_object
    assert with_object is not None and with_object.gwops is None


@pytest.mark.parametrize("case", _ACCEPTED + _APP_IGNORED, ids=lambda c: c.key)
def test_gwops_object_changes_only_the_gwops_field_of_the_start_event(case, cls_log) -> None:
    """Identity, address, time and type come from the line, never from the object."""
    obj = _gwops_start(case.key)
    stripped = {k: v for k, v in obj.items() if k != "gwops"}
    with_object = classify(obj)
    without_object = classify(stripped)
    assert with_object is not None and without_object is not None
    assert with_object.model_dump(exclude={"gwops"}) == without_object.model_dump(exclude={"gwops"})
    assert without_object.gwops is None


@pytest.mark.parametrize("case", _NOT_READ, ids=lambda c: c.key)
def test_gwops_object_on_a_non_web_app_start_is_ignored_without_any_gwops_log(case, cls_log) -> None:
    """KUBERNETES, SSH, other, junk and missing types: the object is never read and never logged.

    An unusable ``resource_type`` (junk string, integer) yields the ``invalid`` marker, which is not
    ``WEB_APP``, so the object is still not read. The only log line is the ``resource_type`` warning.
    """
    obj = _gwops_start(case.key)
    assert "gwops" in obj  # the fixture really carries one
    event = classify(obj)
    assert isinstance(event, SessionStart)
    assert event.gwops is None
    assert event.resource_type == case.resource_type
    assert cls_log.gwops_events() == []
    if case.resource_type == RESOURCE_TYPE_INVALID:
        assert [e["event"] for e in cls_log.events()] == ["classify.resource_type_rejected"]
    else:
        assert cls_log.events() == []


@pytest.mark.parametrize("case", _ABSENT, ids=lambda c: c.key)
def test_gwops_absent_object_yields_none_and_logs_nothing(case, cls_log) -> None:
    """A WEB_APP start with no ``gwops`` key is the designed non-gwops path: silent."""
    obj = _gwops_start(case.key)
    assert "gwops" not in obj
    event = classify(obj)
    assert isinstance(event, SessionStart)
    assert event.gwops is None and event.resource_type == "WEB_APP"
    assert cls_log.events() == []


@pytest.mark.parametrize("resource_type", ["KUBERNETES", "kubernetes", "SSH", "DATABASE", "WEB APP", 123, None])
@pytest.mark.parametrize("raw", ["SENTINEL_GWOPS_UNIT_STR", ["x"], 7, None, {"schema": 2}, {}])
def test_gwops_of_any_shape_on_a_non_web_app_line_is_never_read_or_logged(
    resource_type: object, raw: object, cls_log
) -> None:
    """Even a malformed object on a non-WEB_APP line produces no gwops warning.

    ``"WEB APP"`` and ``123`` are unusable types (the ``invalid`` marker): they log the one
    ``resource_type`` warning and never read the object.
    """
    event = classify(_start_line(resource_type=resource_type, gwops=raw))
    assert isinstance(event, SessionStart)
    assert event.gwops is None
    assert cls_log.gwops_events() == []
    unusable = resource_type in ("WEB APP", 123)
    if unusable:
        assert event.resource_type == RESOURCE_TYPE_INVALID
    assert [e["event"] for e in cls_log.events()] == (["classify.resource_type_rejected"] if unusable else [])


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (123, "not_a_string"),
        (True, "not_a_string"),
        (["SSH"], "not_a_string"),
        ("", "bad_value"),
        ("   ", "bad_value"),
        ("WEB APP", "bad_value"),
        ("1ST", "bad_value"),
        ("A" + "B" * 32, "bad_value"),
        ("SENTINEL-RT-VALUE", "bad_value"),
    ],
)
def test_unusable_resource_type_logs_one_warning_with_reason_and_conn_id_only(
    raw: object, reason: str, cls_log
) -> None:
    """E: present-but-unusable becomes the marker; one warning carries the reason and conn_id, never the value."""
    event = classify(_start_line(resource_type=raw))
    assert isinstance(event, SessionStart)
    assert event.resource_type == RESOURCE_TYPE_INVALID == "invalid"
    events = cls_log.events()
    assert len(events) == 1, events
    assert set(events[0]) == {"event", "level", "reason", "conn_id"}
    assert events[0]["event"] == "classify.resource_type_rejected"
    assert events[0]["level"] == "warning"
    assert events[0]["reason"] == reason
    assert events[0]["conn_id"] == "conn-1"
    assert "SENTINEL-RT-VALUE" not in cls_log.buffer.getvalue()


@pytest.mark.parametrize("raw", ["SSH", "kubernetes", "WEB_APP", None])
def test_usable_or_null_resource_type_logs_no_resource_type_warning(raw: object, cls_log) -> None:
    """A usable type, and JSON null, never log ``resource_type_rejected``."""
    classify(_start_line(resource_type=raw))
    assert cls_log.events() == []


def test_missing_resource_type_key_logs_nothing_and_is_none(cls_log) -> None:
    """An absent key is None (Kubernetes policy downstream), not the marker, and is silent."""
    event = classify(_start_line())
    assert isinstance(event, SessionStart) and event.resource_type is None
    assert cls_log.events() == []


def test_invalid_resource_type_never_reads_the_gwops_object_even_if_it_looks_valid(cls_log) -> None:
    """The gwops object is read only when the type normalizes to WEB_APP; the marker is not WEB_APP.

    Pinned current behaviour: ``classify`` compares the normalized type to ``"WEB_APP"``, so a
    ``WEB APP`` / integer type with a perfectly valid object yields ``gwops=None`` and no gwops log.
    """
    for raw in ("WEB APP", 123, "WEB-APP"):
        obj = _web_start()
        obj["resource_type"] = raw
        event = classify(obj)
        assert isinstance(event, SessionStart)
        assert event.resource_type == RESOURCE_TYPE_INVALID
        assert event.gwops is None
    assert cls_log.gwops_events() == []


def test_gwops_key_is_not_read_when_resource_type_key_is_missing(cls_log) -> None:
    """No ``resource_type`` key at all: the object is ignored and nothing is logged."""
    event = classify(_start_line(gwops="SENTINEL_GWOPS_UNIT_STR"))
    assert isinstance(event, SessionStart)
    assert event.resource_type is None and event.gwops is None
    assert cls_log.events() == []


@pytest.mark.parametrize("resource_type", ["WEB_APP", "web_app", "  Web_App  "])
def test_gwops_is_read_for_every_spelling_that_normalizes_to_web_app(resource_type: str, cls_log) -> None:
    """The check runs on the normalized type, so lowercase and padded spellings are read."""
    obj = _web_start()
    obj["resource_type"] = resource_type
    event = classify(obj)
    assert isinstance(event, SessionStart)
    assert event.resource_type == "WEB_APP"
    assert event.gwops is not None and event.gwops.app == "unit-app"
    assert cls_log.events() == []


# --- ordering of the checks: the first failure is the only one reported ---


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"schema": 2, "match": "bogus"}, "gwops_bad_schema"),
        ({"match": "bogus", "gateway_id": "has space"}, "gwops_bad_match"),
        ({"gateway_id": "has space", "managed": "yes"}, "gwops_bad_gateway_id"),
        ({"managed": "yes", "downstream_tls": "tls12"}, "gwops_bad_managed"),
        ({"downstream_tls": "tls12", "upstream_port": 0}, "gwops_bad_mode"),
        ({"upstream_tls": "bogus", "downstream_port": "443"}, "gwops_bad_mode"),
        ({"upstream_port": 0, "app": ""}, "gwops_bad_port"),
    ],
    ids=["schema-first", "match-second", "gateway_id-third", "managed-fourth", "mode-fifth-down",
         "mode-fifth-up", "port-sixth-beats-app"],
)
def test_gwops_checks_run_in_order_and_log_only_the_first_failure(
    overrides: dict, reason: str, cls_log
) -> None:
    """An object failing several checks logs exactly one warning, for the earliest one."""
    event = classify(_web_start(**overrides))
    assert isinstance(event, SessionStart)
    assert event.gwops is None
    warning = _only_warning(cls_log)
    assert warning["event"] == "classify.gwops_rejected"
    assert warning["reason"] == reason


def test_gwops_rejection_beats_a_bad_app_so_no_field_ignored_warning_is_added(cls_log) -> None:
    """A rejected object logs the rejection only, never also ``gwops_field_ignored``."""
    classify(_web_start(downstream_port=70000, app="\x00"))
    assert [e["event"] for e in cls_log.gwops_events()] == ["classify.gwops_rejected"]


@pytest.mark.parametrize("match", ["none", "ambiguous"])
def test_gwops_none_and_ambiguous_read_only_match_and_gateway_id(match: str, cls_log) -> None:
    """Fields the spec does not read for none/ambiguous cannot reject the object or reach the model."""
    obj = _web_start(match=match, managed="not-a-bool", downstream_tls="tls12", upstream_port=0, app=5)
    event = classify(obj)
    assert isinstance(event, SessionStart) and event.gwops is not None
    assert event.gwops.model_dump() == {
        "match": match, "gateway_id": "R2F0ZXdheToxMjk0", "app": None, "managed": None,
        "downstream_tls": None, "downstream_port": None, "upstream_tls": None, "upstream_port": None,
    }
    assert cls_log.gwops_events() == []


@pytest.mark.parametrize("match", ["none", "ambiguous"])
def test_gwops_gateway_id_is_still_required_and_validated_for_none_and_ambiguous(match: str, cls_log) -> None:
    """Checks 3 and 4 apply to every match value."""
    classify(_web_start(match=match, gateway_id=...))
    classify(_web_start(match=match, gateway_id="bad id"))
    classify(_web_start(match=match, gateway_id=5))
    events = cls_log.gwops_events()
    assert [e["reason"] for e in events] == ["gwops_bad_gateway_id"] * 3


@pytest.mark.parametrize("match", ["exact", "none", "ambiguous"])
def test_gwops_gateway_id_null_is_accepted_for_every_match(match: str, cls_log) -> None:
    """``gateway_id: null`` (gwops Mode B before its first reconcile) is valid; a missing key is not."""
    event = classify(_web_start(match=match, gateway_id=None))
    assert isinstance(event, SessionStart) and event.gwops is not None
    assert event.gwops.match == match and event.gwops.gateway_id is None
    assert cls_log.gwops_events() == []


@pytest.mark.parametrize("port", [1, 80, 65535])
def test_gwops_port_bounds_are_inclusive(port: int, cls_log) -> None:
    """1 and 65535 are valid ports for both sides."""
    event = classify(_web_start(downstream_port=port, upstream_port=port))
    assert isinstance(event, SessionStart) and event.gwops is not None
    assert (event.gwops.downstream_port, event.gwops.upstream_port) == (port, port)
    assert cls_log.gwops_events() == []


@pytest.mark.parametrize("port", [0, -1, 65536, True, 443.0, "443", None])
def test_gwops_port_outside_1_to_65535_or_not_an_int_is_rejected(port: object, cls_log) -> None:
    """Zero, negative, too large, bool, float, string and null ports reject the object."""
    event = classify(_web_start(upstream_port=port))
    assert isinstance(event, SessionStart) and event.gwops is None
    assert _only_warning(cls_log)["reason"] == "gwops_bad_port"


@pytest.mark.parametrize("app", ["a", "x" * 200, "Legacy Wiki (prod)", "café – wiki", "日本"])
def test_gwops_app_free_text_within_200_code_points_is_accepted(app: str, cls_log) -> None:
    """Spaces, parentheses and non-ASCII letters are fine; the limit counts code points."""
    event = classify(_web_start(app=app))
    assert isinstance(event, SessionStart) and event.gwops is not None
    assert event.gwops.app == app
    assert cls_log.gwops_events() == []


@pytest.mark.parametrize(
    "app",
    ["x" * 201, "", "tab\there", "nul\x00", "bidi‮", "zwj‍", "ls ", "ps ", 5, ["a"], None],
    ids=["201", "empty", "tab", "nul", "rlo", "zwj", "line-sep", "para-sep", "int", "list", "null"],
)
def test_gwops_app_that_fails_check_10_is_ignored_with_the_rest_kept(app: object, cls_log) -> None:
    """Over-long, empty, control, format, separator or non-string app: app None, one warning."""
    event = classify(_web_start(app=app))
    assert isinstance(event, SessionStart) and event.gwops is not None
    assert event.gwops.app is None
    assert event.gwops.managed is True and event.gwops.upstream_port == 8443
    warning = _only_warning(cls_log)
    assert (warning["event"], warning["reason"]) == ("classify.gwops_field_ignored", "gwops_bad_app")


def test_gwops_unknown_keys_are_never_read_and_never_reach_the_model(cls_log) -> None:
    """An unknown key (even one named like a secret) neither rejects the object nor survives."""
    obj = _web_start(request_headers={"Authorization": ["Bearer SENTINEL_GWOPS_UNIT"]}, extra="SENTINEL_X")
    event = classify(obj)
    assert isinstance(event, SessionStart) and event.gwops is not None
    assert set(event.gwops.model_dump()) == _GWOPS_FIELDS
    assert "SENTINEL_" not in event.model_dump_json()
    assert cls_log.events() == []


def test_gwops_model_is_frozen_and_has_exactly_the_documented_fields() -> None:
    """The parsed object is immutable and carries nothing beyond the eight stored fields."""
    event = classify(_web_start())
    assert isinstance(event, SessionStart) and event.gwops is not None
    assert set(type(event.gwops).model_fields) == _GWOPS_FIELDS
    with pytest.raises(ValidationError):
        event.gwops.app = "changed"  # type: ignore[misc]


def test_gwops_warning_never_carries_a_value_or_a_key_name(cls_log) -> None:
    """The log line for a rejection holds neither the offending value nor any gwops key name."""
    classify(_web_start(upstream_tls="SENTINEL_GWOPS_UNIT_MODE"))
    text = cls_log.buffer.getvalue()
    assert "SENTINEL_GWOPS_UNIT_MODE" not in text
    for key in ("upstream_tls", "downstream_tls", "gateway_id", "unit-app"):
        assert key not in text
    assert _only_warning(cls_log)["reason"] == "gwops_bad_mode"


def test_gwops_rejected_line_still_yields_the_full_start_event(cls_log) -> None:
    """A rejected object leaves identity, address, type and time on the event intact."""
    obj = _web_start(schema=9)
    event = classify(obj)
    assert isinstance(event, SessionStart)
    assert event.conn_id == "conn-1"
    assert event.username == "u@example.com" and event.user_id == "uid-1"
    assert event.resource_address == "portal.example.test"
    assert event.resource_type == "WEB_APP"
    assert event.gwops is None


# --- Session 12 fix loop: gwops app categories (Cs / Co / Cn) and lone-surrogate cleaning ---

import unicodedata  # noqa: E402

_FFFD = "�"
_SUR = "\ud800"  # what a JSON ``\ud800`` escape decodes to


@pytest.mark.parametrize(
    ("app", "category"),
    [
        (_SUR, "Cs"),
        ("ok" + _SUR + "ok", "Cs"),
        ("\udfff", "Cs"),
        ("", "Co"),
        ("prepost", "Co"),
        ("\U000f0000", "Co"),
        ("͸", "Cn"),
        ("name\U000e0080", "Cn"),
    ],
    ids=["lone-high", "embedded-lone-high", "lone-low", "private-use", "private-use-embedded",
         "supplementary-private-use", "unassigned", "unassigned-supplementary"],
)
def test_gwops_app_with_surrogate_private_use_or_unassigned_is_ignored_and_the_start_is_kept(
    app: str, category: str, cls_log
) -> None:
    """C: check 10 refuses Cs, Co and Cn too: ``app`` becomes None, one warning, the line is accepted."""
    assert category in {unicodedata.category(ch) for ch in app}  # the case really has that category
    event = classify(_web_start(app=app))
    assert isinstance(event, SessionStart) and event.gwops is not None
    assert event.gwops.app is None
    assert event.gwops.match == "exact" and event.gwops.managed is True
    assert event.gwops.downstream_port == 443 and event.gwops.upstream_port == 8443
    assert event.resource_address == "portal.example.test" and event.username == "u@example.com"
    warning = _only_warning(cls_log)
    assert (warning["event"], warning["reason"]) == ("classify.gwops_field_ignored", "gwops_bad_app")
    assert "\\ud800" not in cls_log.buffer.getvalue()  # nothing of the value is logged


def _surrogate_start() -> dict:
    """A ``WEB_APP`` start line with a lone surrogate in every free-text string."""
    return _start_line(
        ts="2026-10-01T10:00:00.000Z" + _SUR,
        user={"id": "uid" + _SUR, "username": "user" + _SUR},
        resource_address="host" + _SUR,
        resource_type="WEB_APP",
    )


def _surrogate_api() -> dict:
    """An API line with a lone surrogate in identity, URL and the three allowlisted headers."""
    return _api_line(
        url="/a" + _SUR + "b?limit=1" + _SUR,
        user={"id": "uid" + _SUR, "username": "user" + _SUR},
        request={"headers": {
            "User-Agent": ["ua" + _SUR], "Kubectl-Command": ["cmd" + _SUR], "Kubectl-Session": ["ses" + _SUR],
        }},
    )


def _surrogate_chunk() -> dict:
    """A recording chunk with a lone surrogate in the username, ``ts`` and asciicast text."""
    return {
        "logger": "gateway.audit", "conn_id": "conn-1", "asciicast_sequence_num": 0,
        "ts": "2026-10-01T10:00:00.000Z" + _SUR, "user": {"username": "rec" + _SUR},
        "asciicast": '{"version":2}\n[0.1,"o","x' + _SUR + 'y"]\n',
    }


def _no_surrogates(*values: object) -> bool:
    """True when no string in ``values`` holds a code point in U+D800..U+DFFF."""
    return not any(
        isinstance(v, str) and any(0xD800 <= ord(ch) <= 0xDFFF for ch in v) for v in values
    )


def test_lone_surrogates_in_a_start_line_become_fffd_and_the_line_is_not_dropped() -> None:
    """C: username, user.id, resource_address and ts are cleaned, not rejected."""
    event = classify(_surrogate_start())
    assert isinstance(event, SessionStart)
    assert event.username == "user" + _FFFD
    assert event.user_id == "uid" + _FFFD
    assert event.resource_address == "host" + _FFFD
    assert event.ts == "2026-10-01T10:00:00.000Z" + _FFFD
    assert event.resource_type == "WEB_APP"
    event.model_dump_json().encode("utf-8")  # encodable: this is what the stores need


def test_lone_surrogates_in_an_api_line_become_fffd_and_the_line_is_not_dropped() -> None:
    """C: username, user.id, url (and url_web), User-Agent, Kubectl-Command and Kubectl-Session."""
    event = classify(_surrogate_api())
    assert isinstance(event, ApiRequest)
    assert event.username == "user" + _FFFD and event.user_id == "uid" + _FFFD
    assert event.url == "/a" + _FFFD + "b?limit=1%EF%BF%BD"  # the query is re-encoded, so U+FFFD is percent-encoded
    assert event.url_web.startswith("/a" + _FFFD + "b")
    assert event.user_agent == "ua" + _FFFD
    assert event.kubectl_command == "cmd" + _FFFD
    assert event.kubectl_session == "ses" + _FFFD
    assert _no_surrogates(*event.model_dump().values())
    event.model_dump_json().encode("utf-8")


def test_lone_surrogates_in_a_recording_chunk_become_fffd_and_the_line_is_not_dropped() -> None:
    """C: username, ``ts`` and the asciicast text are cleaned; the chunk keeps its place in the sequence."""
    event = classify(_surrogate_chunk())
    assert isinstance(event, RecordingChunk)
    assert event.username == "rec" + _FFFD
    assert event.ts == "2026-10-01T10:00:00.000Z" + _FFFD
    assert event.asciicast == '{"version":2}\n[0.1,"o","x' + _FFFD + 'y"]\n'
    assert event.seq == 0
    event.model_dump_json().encode("utf-8")


def test_lone_surrogate_in_the_gwops_app_of_a_surrogate_start_is_dropped_not_replaced(cls_log) -> None:
    """A surrogate in ``app`` is refused (check 10), not turned into U+FFFD: the name becomes None."""
    obj = _surrogate_start()
    obj["gwops"] = _web_start(app="a" + _SUR)["gwops"]
    event = classify(obj)
    assert isinstance(event, SessionStart) and event.gwops is not None
    assert event.gwops.app is None
    assert event.username == "user" + _FFFD  # the rest of the line is cleaned and kept
