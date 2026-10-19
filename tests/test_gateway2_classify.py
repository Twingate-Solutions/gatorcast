"""Session 13: ``classify`` accepts Gateway 2.0.0 (GA) lines alongside the preview ones.

Covers both GA fixtures copied from the gwops repo, the per-line logger-generation rules,
``ssh.channel.id`` validation (``RecordingChunk.stream``), and the guarantee that no other
``ssh`` field is stored or logged.
"""

from __future__ import annotations

import io
import json
import logging

import pytest
import structlog

from gatorcast.models import ApiRequest, RecordingChunk, SessionEnd, SessionStart
from gatorcast.pipeline import classify as classify_module
from gatorcast.pipeline.classify import classify
from tests.samples import (
    GA_CHANNEL_ID,
    GA_EXEC_REQUEST_ID,
    GA_K8S_CONN,
    GA_SSH_CONN,
    ga_recording_objects,
    ga_webapp_json_objects,
)

CONN = "aaaaaaaa-0000-4000-8000-000000000020"
HEADER = '{"version":2,"width":120,"height":40,"timestamp":1792000000,"user":"ubuntu"}'
CAST = HEADER + '\n[0.01,"o","$ "]'


def _chunk(logger: str = "session_recording", **overrides: object) -> dict:
    """A GA-shaped SSH recording chunk line; ``...`` as an override removes the key."""
    obj: dict = {
        "logger": logger,
        "message": "session recording",
        "ts": "2026-10-15T09:00:00.000Z",
        "user": {"id": "VXNlcjox", "username": "user@example.com", "groups": ["g"]},
        "conn_id": CONN,
        "ssh": {
            "id": "a1b2c3d4",
            "username": "ubuntu",
            "client_version": "SSH-2.0-OpenSSH_9.6",
            "server_version": "SSH-2.0-OpenSSH_9.6",
            "channel": {"id": 0, "type": "session", "source": "client", "target": "upstream"},
        },
        "asciicast": CAST,
        "asciicast_sequence_num": 1,
    }
    for key, value in overrides.items():
        if value is ...:
            obj.pop(key, None)
        else:
            obj[key] = value
    return obj


def _with_channel(channel_id: object) -> dict:
    """A chunk whose ``ssh.channel.id`` is ``channel_id``."""
    obj = _chunk()
    obj["ssh"]["channel"]["id"] = channel_id
    return obj


# --------------------------------------------------------------------------- GA recording fixture


def test_ga_recording_fixture_every_line_classifies_as_expected() -> None:
    """Each of the 11 lines yields the documented event type, or ``None`` for the dropped ones."""
    objs = ga_recording_objects()
    assert len(objs) == 11
    kinds = [type(classify(o)).__name__ for o in objs]
    assert kinds == [
        "NoneType",  # 0 system "Starting SSH proxy" (service line)
        "SessionStart",  # 1 system Authenticated connection (SSH)
        "NoneType",  # 2 audit "SSH connection established"
        "RecordingChunk",  # 3 session_recording seq 1
        "RecordingChunk",  # 4 seq 2
        "RecordingChunk",  # 5 session finished, seq 3
        "NoneType",  # 6 audit "SSH connection closed"
        "SessionStart",  # 7 system Authenticated connection (KUBERNETES)
        "RecordingChunk",  # 8 k8s exec chunk seq 1
        "RecordingChunk",  # 9 k8s exec session finished seq 2
        "ApiRequest",  # 10 audit API request completed (the 101 line)
    ]


def test_ga_ssh_chunks_are_ordered_seq_1_to_3_and_final_only_on_the_last() -> None:
    """SSH chunks carry seq 1, 2, 3 under the SSH connection id; only seq 3 is final."""
    events = [classify(o) for o in ga_recording_objects()[3:6]]
    assert all(isinstance(e, RecordingChunk) for e in events)
    assert [e.seq for e in events] == [1, 2, 3]
    assert {e.conn_id for e in events} == {GA_SSH_CONN}
    assert [e.is_final for e in events] == [False, False, True]
    assert {e.username for e in events} == {"placeholder-user"}
    assert all(e.request_id is None for e in events)


def test_ga_fixture_ssh_channel_id_is_a_uuid_string_and_becomes_the_stream() -> None:
    """The gwops fixture's ``ssh.channel.id`` is a UUID string; ``stream`` is that string."""
    objs = ga_recording_objects()[3:6]
    for obj in objs:
        assert obj["ssh"]["channel"]["id"] == GA_CHANNEL_ID
    events = [classify(o) for o in objs]
    assert [e.stream for e in events] == [GA_CHANNEL_ID] * 3
    assert all(isinstance(e.stream, str) for e in events)


def test_ga_k8s_exec_chunks_carry_request_id_and_no_stream() -> None:
    """Kubernetes exec chunks on the new logger have ``request_id`` and ``stream None``."""
    first, last = (classify(o) for o in ga_recording_objects()[8:10])
    for event in (first, last):
        assert isinstance(event, RecordingChunk)
        assert event.conn_id == GA_K8S_CONN
        assert event.request_id == GA_EXEC_REQUEST_ID
        assert event.stream is None
    assert (first.seq, first.is_final) == (1, False)
    assert (last.seq, last.is_final) == (2, True)


def test_ga_system_start_lines_carry_resource_type_and_address() -> None:
    """``system`` ``Authenticated connection`` lines become ``SessionStart`` with the type."""
    objs = ga_recording_objects()
    ssh, k8s = classify(objs[1]), classify(objs[7])
    assert isinstance(ssh, SessionStart) and isinstance(k8s, SessionStart)
    assert (ssh.conn_id, ssh.resource_type) == (GA_SSH_CONN, "SSH")
    assert ssh.resource_address == "ssh-target.example.test:22"
    assert (k8s.conn_id, k8s.resource_type) == (GA_K8S_CONN, "KUBERNETES")
    assert k8s.resource_address == "kubernetes.default.svc.cluster.local"
    assert ssh.username == "placeholder-user"


def test_ga_audit_api_line_becomes_api_request_without_caller() -> None:
    """The exec's 101 line on the ``audit`` logger (no ``caller``) classifies as ``ApiRequest``."""
    obj = ga_recording_objects()[10]
    assert "caller" not in obj
    event = classify(obj)
    assert isinstance(event, ApiRequest)
    assert event.request_id == GA_EXEC_REQUEST_ID
    assert event.conn_id == GA_K8S_CONN
    assert event.status_code == 101
    assert event.method == "POST"


def test_ga_ssh_audit_service_and_proxy_error_lines_are_dropped() -> None:
    """SSH connection events and ``system`` service lines match no branch."""
    objs = ga_recording_objects()
    assert classify(objs[0]) is None  # Starting SSH proxy
    assert classify(objs[2]) is None  # SSH connection established
    assert classify(objs[6]) is None  # SSH connection closed
    proxy_error = {
        "logger": "system",
        "message": "http: proxy error: tls: failed to verify certificate: x509: ...",
        "caller": "httputil/reverseproxy.go",
    }
    assert classify(proxy_error) is None


def test_ssh_connection_closed_is_not_a_close_signal() -> None:
    """The GA ``audit`` ``SSH connection closed`` line (same conn id) does not become ``SessionEnd``."""
    event = classify(ga_recording_objects()[6])
    assert event is None
    assert not isinstance(event, SessionEnd)


# --------------------------------------------------------------------------- GA web-app fixture


def test_ga_webapp_fixture_classification_totals() -> None:
    """58 WEB_APP starts, 55 API requests, and every other ``system`` line is noise."""
    objs = ga_webapp_json_objects()
    events = [classify(o) for o in objs]
    starts = [e for e in events if isinstance(e, SessionStart)]
    apis = [e for e in events if isinstance(e, ApiRequest)]
    noise = [o for o, e in zip(objs, events) if e is None]
    assert len(starts) == 58 and {s.resource_type for s in starts} == {"WEB_APP"}
    assert len({s.conn_id for s in starts}) == 58
    assert all(s.gwops is None for s in starts)  # this capture predates the gwops object
    assert len(apis) == 55 and len({a.request_id for a in apis}) == 55
    assert len(starts) + len(apis) + len(noise) == len(objs)
    assert {o["logger"] for o in noise} == {"system"}
    assert not any(isinstance(e, (RecordingChunk, SessionEnd)) for e in events)


def test_ga_webapp_api_lines_join_to_a_start_line() -> None:
    """Every API request's ``conn_id`` has a start line in the same file."""
    events = [classify(o) for o in ga_webapp_json_objects()]
    start_ids = {e.conn_id for e in events if isinstance(e, SessionStart)}
    api_ids = {e.conn_id for e in events if isinstance(e, ApiRequest)}
    assert api_ids <= start_ids


# --------------------------------------------------------------------------- logger generations


@pytest.mark.parametrize("logger", ["gateway.audit", "session_recording"])
def test_both_recording_logger_names_classify_identically(logger: str) -> None:
    """The preview and GA recording logger names yield the same event."""
    event = classify(_chunk(logger=logger))
    assert isinstance(event, RecordingChunk)
    assert (event.conn_id, event.seq, event.asciicast) == (CONN, 1, CAST)
    assert event.is_final is False


@pytest.mark.parametrize("logger", ["gateway.audit", "session_recording"])
def test_session_finished_is_final_on_both_generations(logger: str) -> None:
    """``session finished`` ends the recording on the preview and the GA logger."""
    assert classify(_chunk(logger=logger, message="session finished")).is_final is True
    assert classify(_chunk(logger=logger, message="session recording")).is_final is False


def test_gateway_audit_ssh_chunk_also_reads_the_channel_id() -> None:
    """Logger generation and ``ssh.channel.id`` are independent: a preview name with ``ssh`` works."""
    assert classify(_with_channel(7) | {"logger": "gateway.audit"}).stream == "7"


def test_audit_logger_line_with_asciicast_is_never_a_recording_chunk() -> None:
    """An ``audit`` line is never a chunk, even when it carries ``asciicast``."""
    assert classify(_chunk(logger="audit")) is None
    assert classify(_chunk(logger="system")) is None
    assert classify(_chunk(logger="gateway")) is None


def _api_obj(logger: str) -> dict:
    return {
        "logger": logger,
        "message": "API request completed",
        "request_id": "11111111-1111-4111-8111-111111111113",
        "requested_at": "2026-10-01T10:00:01.200Z",
        "method": "GET",
        "url": "/api/v1/pods",
        "conn_id": CONN,
        "user": {"username": "u@example.com"},
        "response": {"status_code": 200},
    }


@pytest.mark.parametrize("logger", ["gateway.audit", "audit"])
def test_api_request_classifies_on_both_audit_loggers(logger: str) -> None:
    """The preview and GA audit logger names both yield an ``ApiRequest``."""
    event = classify(_api_obj(logger))
    assert isinstance(event, ApiRequest)
    assert event.status_code == 200


@pytest.mark.parametrize("logger", ["session_recording", "system", "gateway"])
def test_api_request_message_on_a_non_audit_logger_is_noise(logger: str) -> None:
    """Only the audit loggers carry API requests."""
    assert classify(_api_obj(logger)) is None


@pytest.mark.parametrize("logger", ["gateway", "system"])
def test_start_line_classifies_on_both_start_loggers(logger: str) -> None:
    """``Authenticated connection`` is accepted on ``gateway`` and ``system``."""
    obj = {
        "logger": logger,
        "message": "Authenticated connection",
        "conn_id": CONN,
        "user": {"username": "u@example.com", "id": "uid"},
        "resource_type": "SSH",
        "resource_address": "host:22",
    }
    event = classify(obj)
    assert isinstance(event, SessionStart)
    assert event.resource_address == "host:22"


@pytest.mark.parametrize("logger", ["gateway.audit", "audit", "session_recording"])
def test_start_line_on_a_non_start_logger_is_noise(logger: str) -> None:
    """The start message on a recording or audit logger is not a start."""
    obj = {"logger": logger, "message": "Authenticated connection", "conn_id": CONN}
    assert classify(obj) is None


@pytest.mark.parametrize("logger", ["gateway", "system"])
@pytest.mark.parametrize("message", ["Connection closed", "Closed connection"])
def test_close_messages_on_both_start_loggers_end_the_session(logger: str, message: str) -> None:
    """The defensive close hook works on either generation's logger."""
    event = classify({"logger": logger, "message": message, "conn_id": CONN})
    assert isinstance(event, SessionEnd)
    assert event.conn_id == CONN


def test_mixed_generation_lines_in_one_pass_produce_matching_events() -> None:
    """Preview and GA lines for the same roles produce events of the same type."""
    preview = [_chunk(logger="gateway.audit"), _api_obj("gateway.audit")]
    ga = [_chunk(logger="session_recording"), _api_obj("audit")]
    assert [type(classify(o)) for o in preview] == [type(classify(o)) for o in ga]


# --------------------------------------------------------------------------- ssh.channel.id


_UUID = "00000000-0000-4000-8000-000000000001"


@pytest.mark.parametrize(
    ("channel_id", "expected"),
    [
        (0, "0"),
        (1, "1"),
        (17, "17"),
        (2**31 - 1, str(2**31 - 1)),
        (_UUID, _UUID),
        ("abc", "abc"),
        ("a.b_c-1", "a.b_c-1"),
        ("0", "0"),
        ("x" * 128, "x" * 128),
        (True, None),
        (False, None),
        (-1, None),
        (2**31, None),
        (2**63, None),
        (1.0, None),
        (0.0, None),
        ("", None),
        (" ", None),
        ("a b", None),
        (" abc", None),
        ("a/b", None),
        ("../x", None),
        ("x" * 129, None),
        ("a" + chr(10), None),
        (chr(10), None),
        ("café", None),
        (None, None),
        ([0], None),
        ({"id": 0}, None),
    ],
    ids=lambda v: repr(v)[:30],
)
def test_ssh_channel_id_validation(channel_id: object, expected: str | None) -> None:
    """``stream`` is a safe-token string; a non-bool int 0..2**31-1 is normalized to its decimal string."""
    event = classify(_with_channel(channel_id))
    assert isinstance(event, RecordingChunk)
    assert event.stream == expected


@pytest.mark.parametrize("channel_id", ["..", ".", "-", "_.-"])
def test_dot_only_channel_id_is_rejected(channel_id: str) -> None:
    """A dot-only channel id is not a usable stream."""
    assert classify(_with_channel(channel_id)).stream is None


def test_an_int_channel_id_and_its_decimal_string_are_the_same_stream() -> None:
    """Ints are normalized, so ``7`` and ``"7"`` key the same recording."""
    assert classify(_with_channel(7)).stream == classify(_with_channel("7")).stream == "7"


def test_ssh_channel_id_missing_key_gives_none() -> None:
    """A channel object with no ``id`` key gives ``stream None``."""
    obj = _chunk()
    del obj["ssh"]["channel"]["id"]
    assert classify(obj).stream is None


@pytest.mark.parametrize(
    "ssh", [None, "x", 5, [], [{"channel": {"id": 1}}], {"channel": None}, {"channel": "x"}, {}],
    ids=repr,
)
def test_malformed_ssh_object_gives_no_stream_and_still_classifies(ssh: object) -> None:
    """A missing or malformed ``ssh`` object never drops the chunk; ``stream`` is None."""
    obj = _chunk()
    obj["ssh"] = ssh
    event = classify(obj)
    assert isinstance(event, RecordingChunk)
    assert event.stream is None


def test_chunk_without_ssh_object_has_no_stream() -> None:
    """Kubernetes and preview chunks carry no ``ssh`` object."""
    event = classify(_chunk(ssh=...))
    assert isinstance(event, RecordingChunk)
    assert event.stream is None


# --------------------------------------------------------------------------- nothing else from ssh


SENT_USER = "SENTINEL_SSH_USERNAME_9f3a1c7e"
SENT_CLIENT = "SENTINEL_SSH_CLIENTVER_4b2d8e61"
SENT_SERVER = "SENTINEL_SSH_SERVERVER_77c0ab12"
SENT_ID = "SENTINEL_SSH_ID_e19d05f3"
SENT_TYPE = "SENTINEL_SSH_CHANNELTYPE_3a6b9c20"
SENT_EXTRA = "SENTINEL_SSH_EXTRA_c4d1f7a8"


@pytest.fixture
def cls_log(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    """Swap the classifier's module logger for a JSON-lines buffer capturing all levels."""
    buffer = io.StringIO()
    monkeypatch.setattr(
        classify_module,
        "log",
        structlog.wrap_logger(
            structlog.PrintLogger(file=buffer),
            processors=[structlog.processors.add_log_level, structlog.processors.JSONRenderer()],
            wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
        ),
    )
    return buffer


def _sentinel_chunk(channel_id: object) -> dict:
    obj = _with_channel(channel_id)
    obj["ssh"].update(
        username=SENT_USER,
        client_version=SENT_CLIENT,
        server_version=SENT_SERVER,
        id=SENT_ID,
        extra=SENT_EXTRA,
    )
    obj["ssh"]["channel"]["type"] = SENT_TYPE
    return obj


@pytest.mark.parametrize("channel_id", [0, 3, "not-an-int", -5, True])
def test_no_ssh_field_other_than_channel_id_reaches_the_event_or_logs(
    cls_log: io.StringIO, channel_id: object
) -> None:
    """Sentinels in every other ``ssh`` field are in neither the event nor the classifier's logs."""
    obj = _sentinel_chunk(channel_id)
    event = classify(obj)
    assert isinstance(event, RecordingChunk)
    dumped = event.model_dump_json() + repr(event)
    for sentinel in (SENT_USER, SENT_CLIENT, SENT_SERVER, SENT_ID, SENT_TYPE, SENT_EXTRA):
        assert sentinel not in dumped
        assert sentinel not in cls_log.getvalue()
    # Identity stays the envelope user, never ssh.username.
    assert event.username == "user@example.com"


def test_dropped_ssh_audit_line_logs_nothing_of_its_ssh_object(cls_log: io.StringIO) -> None:
    """An SSH ``audit`` event carrying sentinels is dropped and its content is not logged."""
    obj = {
        "logger": "audit",
        "message": "SSH connection established",
        "conn_id": CONN,
        "user": {"username": "u@example.com"},
        "ssh": {"id": SENT_ID, "username": SENT_USER, "client_version": SENT_CLIENT},
    }
    assert classify(obj) is None
    for sentinel in (SENT_ID, SENT_USER, SENT_CLIENT):
        assert sentinel not in cls_log.getvalue()


def test_recording_chunk_model_has_no_ssh_fields_beyond_stream() -> None:
    """The event model exposes ``stream`` and no other ssh-derived attribute."""
    fields = set(RecordingChunk.model_fields)
    assert "stream" in fields
    assert not {f for f in fields if f.startswith("ssh")}
    assert json.loads(classify(_sentinel_chunk(2)).model_dump_json()).keys() == fields
