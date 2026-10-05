"""Tests for the envelope wire format (fork recording sink) in pipeline.classify.

Sample records are verbatim from the fork's ``claudedocs/envelope-wire-spec.md``
(build ``dev-integration-e29ed20``) — byte-representative of what the sink POSTs
to ``/ingest`` as NDJSON. The envelope branch must be strictly additive: legacy
log-line classification is regression-tested at the bottom.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import aiosqlite

from gatorcast.db import init_db
from gatorcast.models import RecordingChunk, SessionEnd, SessionStart
from gatorcast.pipeline.assembler import Assembler
from gatorcast.pipeline.classify import classify
from gatorcast.store.activity import ActivityStore
from gatorcast.store.casts import CastStore
from gatorcast.store.sessions import SessionRepository

CONN = "7eea6b1c-d4e3-4cbf-a8e4-3d529d6f0d14"

# One full SSH session, start → chunks → end (spec §1, verbatim).
SESSION_LINES = [
    '{"schema_version":"2","type":"session_start","conn_id":"7eea6b1c-d4e3-4cbf-a8e4-3d529d6f0d14","shell_user":"bcameron-twingate-com","started_at":"2026-07-13T21:08:43.442Z"}',
    '{"schema_version":"2","type":"recording_chunk","conn_id":"7eea6b1c-d4e3-4cbf-a8e4-3d529d6f0d14","seq":1,"final":false,"header":{"version":2,"width":210,"height":52,"timestamp":1784149723},"events":"[0.454071, \\"o\\", \\"Welcome to Ubuntu 25.10 (GNU/Linux 6.17.0-14-generic x86_64)\\\\r\\\\n\\"]\\n","bytes":84,"encoding":"utf-8"}',
    '{"schema_version":"2","type":"recording_chunk","conn_id":"7eea6b1c-d4e3-4cbf-a8e4-3d529d6f0d14","seq":2,"final":false,"events":"[0.454339, \\"o\\", \\"Last login: Sun Jul 13 21:05:11 2026 from 10.0.0.1\\\\r\\\\n\\"]\\n","bytes":74,"encoding":"utf-8"}',
    '{"schema_version":"2","type":"recording_chunk","conn_id":"7eea6b1c-d4e3-4cbf-a8e4-3d529d6f0d14","seq":3,"final":false,"events":"[1.102938, \\"o\\", \\"bcameron-twingate-com@lxc-ssh-1:~$ \\ufffd\\"]\\n","bytes":58,"encoding":"utf-8"}',
    '{"schema_version":"2","type":"recording_chunk","conn_id":"7eea6b1c-d4e3-4cbf-a8e4-3d529d6f0d14","seq":4,"final":false,"events":"[4.220119, \\"o\\", \\"ls -la\\\\r\\\\n\\"]\\n[4.391208, \\"o\\", \\"total 28\\\\r\\\\ndrwxr-x--- 4 bcameron-twingate-com ...\\\\r\\\\n\\"]\\n","bytes":104,"encoding":"utf-8"}',
    '{"schema_version":"2","type":"session_end","conn_id":"7eea6b1c-d4e3-4cbf-a8e4-3d529d6f0d14","final_seq":4,"total_chunks":4,"total_bytes":320,"duration_seconds":137.061,"sha256":"feb7161d0c5ba1613e75e18f7f021357cdabf2020b17cf7f85676bdd144cd6b2"}',
]

# K8s-path session_start with richer meta (spec §1, verbatim).
K8S_START_LINE = '{"schema_version":"2","type":"session_start","conn_id":"0d63a763-5b78-4b04-9c8e-2f4e9be0a111","sso_user":"bcameron@twingate.com","groups":["SSH Admins","twingate:authenticated"],"resource":{"address":"10.0.0.40","id":"UmVzb3VyY2U6MTIzNDU2"},"authz":{"device_id":"RGV2aWNlOjc3Nzc3"},"started_at":"2026-07-13T21:08:43.442Z"}'


def _obj(line: str) -> dict:
    return json.loads(line)


# --- session_start ----------------------------------------------------------


def test_ssh_start_maps_shell_user_but_not_identity() -> None:
    """SSH-path start (no sso_user in current builds): identity stays None."""
    event = classify(_obj(SESSION_LINES[0]))
    assert isinstance(event, SessionStart)
    assert event.conn_id == CONN
    assert event.username is None  # never map shell_user to identity (rule 4)
    assert event.shell_user == "bcameron-twingate-com"
    assert event.resource_address is None
    assert event.ts == "2026-07-13T21:08:43.442Z"


def test_k8s_start_maps_sso_user_and_resource() -> None:
    """K8s-path start: username ← sso_user, system ← resource.address."""
    event = classify(_obj(K8S_START_LINE))
    assert isinstance(event, SessionStart)
    assert event.username == "bcameron@twingate.com"
    assert event.resource_address == "10.0.0.40"
    assert event.shell_user is None


# --- recording_chunk --------------------------------------------------------


def test_chunk_with_header_synthesizes_header_line_plus_events() -> None:
    """Seq 1 carries the header object: chunk text = header line + events."""
    event = classify(_obj(SESSION_LINES[1]))
    assert isinstance(event, RecordingChunk)
    assert event.conn_id == CONN
    assert event.seq == 1
    assert event.is_final is False
    lines = event.asciicast.splitlines()
    header = json.loads(lines[0])
    assert header == {"version": 2, "width": 210, "height": 52, "timestamp": 1784149723}
    assert json.loads(lines[1])[1] == "o"


def test_chunk_without_header_is_events_only() -> None:
    """Later seqs carry no header: chunk text is the events string verbatim."""
    obj = _obj(SESSION_LINES[2])
    event = classify(obj)
    assert isinstance(event, RecordingChunk)
    assert event.seq == 2
    assert event.asciicast == obj["events"]


def test_chunk_final_flag_is_advisory_but_honored() -> None:
    """final:true marks is_final; absent/false does not."""
    obj = _obj(SESSION_LINES[2])
    assert classify(obj).is_final is False
    del obj["final"]
    assert classify(obj).is_final is False  # omitempty: tolerate absence
    obj["final"] = True
    assert classify(obj).is_final is True


def test_chunk_requires_integer_seq() -> None:
    """A chunk with a missing or non-integer seq cannot be ordered — drop."""
    obj = _obj(SESSION_LINES[2])
    del obj["seq"]
    assert classify(obj) is None
    assert classify({**obj, "seq": "2"}) is None
    assert classify({**obj, "seq": True}) is None


def test_chunk_requires_events_string() -> None:
    """A chunk with missing or non-string events carries nothing usable — drop."""
    obj = _obj(SESSION_LINES[2])
    del obj["events"]
    assert classify(obj) is None
    assert classify({**obj, "events": ["not", "a", "string"]}) is None


def test_chunk_base64_encoding_is_decoded() -> None:
    """The reserved base64 mode decodes to the events text."""
    events = '[0.1, "o", "hi"]\n'
    obj = _obj(SESSION_LINES[2])
    obj["events"] = base64.b64encode(events.encode()).decode()
    obj["encoding"] = "base64"
    event = classify(obj)
    assert isinstance(event, RecordingChunk)
    assert event.asciicast == events


def test_chunk_invalid_base64_is_dropped() -> None:
    obj = _obj(SESSION_LINES[2])
    obj["encoding"] = "base64"
    obj["events"] = "!!not base64!!"
    assert classify(obj) is None


def test_chunk_unknown_encoding_stores_raw() -> None:
    """An unknown future encoding stores the raw string rather than lose data."""
    obj = _obj(SESSION_LINES[2])
    obj["encoding"] = "zstd"
    event = classify(obj)
    assert isinstance(event, RecordingChunk)
    assert event.asciicast == obj["events"]


# --- session_end ------------------------------------------------------------


def test_session_end_is_terminal_finalize() -> None:
    """A session_end record maps to SessionEnd (control-only, no chunk synth)."""
    event = classify(_obj(SESSION_LINES[5]))
    assert isinstance(event, SessionEnd)
    assert event.conn_id == CONN


# --- safety & regression ------------------------------------------------------


def test_envelope_unsafe_conn_id_is_rejected() -> None:
    """The conn_id choke point applies to envelope records too."""
    for line in (SESSION_LINES[0], SESSION_LINES[1], SESSION_LINES[5]):
        obj = _obj(line)
        obj["conn_id"] = "../../etc/passwd"
        assert classify(obj) is None


def test_unknown_envelope_type_is_dropped() -> None:
    assert classify({"schema_version": "2", "type": "heartbeat", "conn_id": "abc"}) is None


def test_envelope_lines_survive_normalize() -> None:
    """The HTTP NDJSON front door runs normalize() first — envelope records have
    no "logger" and no "log" wrapper key, so they must pass through unchanged."""
    from gatorcast.ingest.normalize import normalize

    for line in SESSION_LINES + [K8S_START_LINE]:
        assert normalize(line) == json.loads(line)


def test_legacy_line_with_type_field_is_not_diverted() -> None:
    """A legacy line (has "logger") always takes the legacy path, even if some
    future build adds a coincidental "type" field."""
    obj = {
        "logger": "gateway.audit",
        "type": "recording_chunk",  # would be an envelope discriminator otherwise
        "conn_id": "abc",
        "asciicast": '{"version":2,"width":80,"height":24}',
        "asciicast_sequence_num": 0,
    }
    event = classify(obj)
    assert isinstance(event, RecordingChunk)
    assert event.seq == 0  # legacy field, not envelope "seq"


# --- end to end: spec session through the assembler --------------------------


async def _make(tmp_path: Path) -> tuple[Assembler, aiosqlite.Connection]:
    db = await init_db(tmp_path / "gatorcast.db")
    asm = Assembler(
        repo=SessionRepository(db),
        casts=CastStore(tmp_path / "casts"),
        idle_timeout_seconds=120,
        clock=lambda: 0.0,
        activity=ActivityStore(db),
    )
    return asm, db


async def test_full_envelope_session_assembles_and_seals(tmp_path: Path) -> None:
    """The spec's verbatim session yields one complete, playable recording."""
    asm, db = await _make(tmp_path)
    for line in SESSION_LINES:
        event = classify(json.loads(line))
        assert event is not None, "no spec line may be dropped"
        await asm.handle(event)

    cur = await db.execute("SELECT * FROM sessions WHERE conn_id = ?", (CONN,))
    row = await cur.fetchone()
    await cur.close()
    assert row is not None
    assert row["status"] == "complete"
    assert row["chunk_count"] == 4
    assert row["shell_user"] == "bcameron-twingate-com"
    assert row["username"] is None
    assert row["width"] == 210 and row["height"] == 52

    cast = Path(row["cast_path"]).read_text(encoding="utf-8")
    lines = [line for line in cast.splitlines() if line.strip()]
    # Header exactly once, then all five event tuples in seq order.
    assert json.loads(lines[0])["version"] == 2
    assert sum(1 for line in lines if line.lstrip().startswith("{")) == 1
    events = [json.loads(line) for line in lines[1:]]
    assert len(events) == 5
    assert [event[0] for event in events] == sorted(event[0] for event in events)
    assert events[0][2].startswith("Welcome to Ubuntu")

    await db.close()
