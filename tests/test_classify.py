"""Tests for pipeline.classify: the two-stage recording filter and event shaping."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from gatorcast.models import ApiRequest, RecordingChunk, SessionEnd, SessionStart
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


@pytest.mark.parametrize("bad", ["DELETE\n", "GET\n", "get", "GE", "TOOLONGMETHOD", "GET ", ""])
def test_http_method_must_fully_match(bad: str) -> None:
    """F4: a method with a trailing newline is dropped like any other malformed method."""
    assert classify(_api_line(method=bad)) is None


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


@pytest.mark.parametrize("method", ["get", "Get", "GE", "ABCDEFGHIJK", "G ET", "", None, 5])
def test_api_bad_method_dropped(method: object) -> None:
    """A lowercase, too short/long, or non-string method drops the line."""
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
