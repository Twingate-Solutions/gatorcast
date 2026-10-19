"""Per-SSH-channel recordings (Session 13 T3, final semantics).

* ``classify`` keeps ``ssh.channel.id`` as a string ``stream`` (tested in ``test_gateway2_classify``).
* The FIRST stream to record on a connection claims ``conn_id`` as its session id (persisted in
  ``sessions.stream``); the same stream later maps to ``conn_id`` again; any other stream gets the
  derived id ``session_id_for(conn_id, stream)`` with ``parent_conn_id`` set. No stream keeps
  ``conn_id`` and never sets ``stream``.
* ``handle`` finalizes on ``is_final`` only for ``STORED`` / ``REDELIVERED`` chunks and only its own
  session; ``SessionEnd`` seals every session of the connection.
* Redelivery against a baseline (re-adopted or reopened buffer, or a reopenably sealed session) is
  an offset-and-block check; a covered chunk against a sealed cast leaves the file byte-identical.
"""

from __future__ import annotations

import io
import json
import logging
import uuid
from pathlib import Path

import aiosqlite
import pytest
import structlog

import gatorcast.pipeline.assembler as assembler_module
from gatorcast.models import RecordingChunk, SessionEnd, SessionStart
from gatorcast.pipeline.assembler import (
    Assembler,
    ChunkOutcome,
    _STREAM_NAMESPACE,
    session_id_for,
)
from gatorcast.pipeline.retention import RetentionPurger
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import SessionRepository
from tests.test_assembler import (
    CHUNK_1,
    CHUNK_2,
    FULL_DOC,
    HEADER,
    FakeClock,
    _age_connection,
    _boot,
    _conn,
    _make,
    _row,
    _start,
)

CONN = "aaaaaaaa-0000-4000-8000-0000000000d1"
OTHER_CONN = "aaaaaaaa-0000-4000-8000-0000000000d2"
CH_A = "00000000-0000-4000-8000-0000000000a1"
CH_B = "00000000-0000-4000-8000-0000000000b2"
CH_C = "00000000-0000-4000-8000-0000000000c3"
# Pinned: the namespace is FIXED FOR EVER, so these literals must never change.
DERIVED_B = "a3b30121-6447-59b8-b6ec-89b83b99d0e8"  # session_id_for(CONN, CH_B)


# --------------------------------------------------------------------------- helpers


def _chunk(
    stream: str | None,
    seq: int,
    tag: str,
    offset: float,
    *,
    final: bool = False,
    conn: str = CONN,
) -> RecordingChunk:
    """A self-contained chunk: the header plus one event ``[offset, "o", tag]``."""
    return RecordingChunk(
        conn_id=conn,
        seq=seq,
        asciicast=HEADER + json.dumps([offset, "o", tag]) + "\n",
        stream=stream,
        is_final=final,
        username="chunk-user@example.com",
        ts="2026-10-15T09:00:00.000Z",
    )


def _tags(cast_text: str) -> list[str]:
    """The output text of every event of a cast, in order."""
    return [json.loads(ln)[2] for ln in cast_text.split("\n") if ln.startswith("[")]


def _headers(cast_text: str) -> int:
    return sum(1 for ln in cast_text.split("\n") if ln.startswith("{"))


def _cast(tmp_path: Path, session_id: str) -> str:
    """Plaintext ``.cast`` (only valid for unsealed-or-unencrypted sessions)."""
    return (tmp_path / "casts" / f"{session_id}.cast").read_text(encoding="utf-8")


def _cast_path(tmp_path: Path, session_id: str) -> Path:
    return tmp_path / "casts" / f"{session_id}.cast"


@pytest.fixture
def asm_log(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    """The assembler's logger swapped for a JSON-lines buffer capturing every level."""
    buffer = io.StringIO()
    monkeypatch.setattr(
        assembler_module,
        "log",
        structlog.wrap_logger(
            structlog.PrintLogger(file=buffer),
            processors=[structlog.processors.add_log_level, structlog.processors.JSONRenderer()],
            wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
        ),
    )
    return buffer


def _events(buffer: io.StringIO, name: str | None = None) -> list[dict]:
    events = [json.loads(ln) for ln in buffer.getvalue().splitlines() if ln.strip()]
    return [e for e in events if name is None or e["event"] == name]


# --------------------------------------------------------------------------- session_id_for


def test_session_id_for_no_stream_is_the_connection_id() -> None:
    assert session_id_for(CONN, None) == CONN


def test_session_id_for_is_the_pinned_uuid5_of_connection_and_stream() -> None:
    """The derived id is ``uuid5(namespace, "<conn>/ssh-channel/<stream>")``; the value is pinned."""
    assert session_id_for(CONN, CH_B) == DERIVED_B
    assert DERIVED_B == str(uuid.uuid5(_STREAM_NAMESPACE, f"{CONN}/ssh-channel/{CH_B}"))
    assert str(_STREAM_NAMESPACE) == "c3f1a7e2-5b0d-4e6a-9a48-7d2e1f8b6c35"
    assert session_id_for(CONN, "7") == "57de39fa-7988-56e7-ae8a-4ae50a88bfb4"


def test_session_id_for_is_stable_distinct_and_a_plain_uuid() -> None:
    ids = {session_id_for(CONN, s) for s in (CH_A, CH_B, CH_C, "0", "1")}
    assert len(ids) == 5
    assert session_id_for(CONN, CH_A) == session_id_for(CONN, CH_A)
    assert session_id_for(CONN, CH_A) != session_id_for(OTHER_CONN, CH_A)
    for sid in ids:
        assert str(uuid.UUID(sid)) == sid
        assert sid != CONN
    # "0" is not special: only None keeps the connection id.
    assert session_id_for(CONN, "0") != CONN


# --------------------------------------------------------------------------- two interleaved channels


@pytest.mark.asyncio
async def test_two_interleaved_channels_make_two_sessions_first_keeps_conn_id(tmp_path: Path) -> None:
    """Channel A claims ``conn_id``; B is derived; content is unmixed; each final seals only itself."""
    asm, db = await _make(tmp_path)
    await asm.handle(_start(CONN))
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))
    await asm.handle(_chunk(CH_B, 1, "B1", 1.5))
    await asm.handle(_chunk(CH_A, 2, "A2", 2.0))
    await asm.handle(_chunk(CH_B, 2, "B2", 2.5))
    assert asm.active_count == 2
    assert asm.seq_conflict_count == 0  # same seq numbers on two channels never collide

    await asm.handle(_chunk(CH_A, 3, "A3", 3.0, final=True))
    primary = await _row(db, CONN)
    derived = await _row(db, DERIVED_B)
    assert (primary["status"], primary["sealed_terminal"]) == ("complete", 1)
    assert derived["status"] == "provisional"  # A's final did not seal B
    assert asm.active_count == 1

    await asm.handle(_chunk(CH_B, 3, "B3", 3.5, final=True))
    derived = await _row(db, DERIVED_B)
    assert (derived["status"], derived["sealed_terminal"]) == ("complete", 1)
    assert asm.active_count == 0

    assert _tags(_cast(tmp_path, CONN)) == ["A1", "A2", "A3"]
    assert _tags(_cast(tmp_path, DERIVED_B)) == ["B1", "B2", "B3"]
    assert _headers(_cast(tmp_path, CONN)) == _headers(_cast(tmp_path, DERIVED_B)) == 1

    assert (primary["parent_conn_id"], primary["stream"]) == (None, CH_A)
    assert (derived["parent_conn_id"], derived["stream"]) == (CONN, CH_B)
    for row in (primary, derived):  # identity and address come from the connection
        assert row["username"] == "user@example.com"
        assert row["resource_address"] == "k8s.example.internal"
        assert row["chunk_count"] == 3
    conn = await _conn(db, CONN)
    assert conn["state"] == "recording"
    cur = await db.execute("SELECT COUNT(*) FROM sessions")
    assert (await cur.fetchone())[0] == 2
    await db.close()


@pytest.mark.asyncio
async def test_a_derived_channels_final_leaves_the_first_channel_recording(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await asm.handle(_start(CONN))
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))
    await asm.handle(_chunk(CH_B, 1, "B1", 1.5, final=True))
    assert (await _row(db, DERIVED_B))["status"] == "complete"
    assert (await _row(db, CONN))["status"] == "provisional"
    assert asm.active_count == 1
    await asm.handle(_chunk(CH_A, 2, "A2", 2.0))  # still accepted
    assert _tags(_cast(tmp_path, CONN)) == ["A1", "A2"]
    await db.close()


@pytest.mark.asyncio
async def test_session_end_seals_every_channel_of_the_connection_only(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await asm.handle(_start(CONN))
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))
    await asm.handle(_chunk(CH_B, 1, "B1", 1.5))
    await asm.handle(_chunk(CH_C, 1, "C1", 1.7))
    await asm.handle(_chunk(None, 1, "O1", 1.0, conn=OTHER_CONN))
    assert asm.active_count == 4
    await asm.handle(SessionEnd(conn_id=CONN))
    for sid in (CONN, DERIVED_B, session_id_for(CONN, CH_C)):
        row = await _row(db, sid)
        assert (row["status"], row["sealed_terminal"]) == ("complete", 1), sid
    assert (await _row(db, OTHER_CONN))["status"] == "provisional"
    assert asm.active_count == 1
    await db.close()


@pytest.mark.asyncio
async def test_session_end_for_a_connection_with_one_recording_seals_it(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "conn-end"
    await asm.handle(SessionStart(conn_id=cid, resource_address="host", username="u@x"))
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=CHUNK_1))
    await asm.handle(RecordingChunk(conn_id=cid, seq=2, asciicast=CHUNK_2))
    await asm.handle(SessionEnd(conn_id=cid))
    row = await _row(db, cid)
    assert (row["status"], row["sealed_terminal"], row["stream"]) == ("complete", 1, None)
    assert _cast(tmp_path, cid) == FULL_DOC
    await db.close()


@pytest.mark.asyncio
async def test_session_end_for_an_unknown_connection_is_a_noop(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await asm.handle(RecordingChunk(conn_id="keep-open", seq=1, asciicast=HEADER))
    await asm.handle(SessionEnd(conn_id="someone-else"))
    assert asm.active_count == 1
    assert (await _row(db, "keep-open"))["status"] == "provisional"
    await db.close()


# --------------------------------------------------------------------------- stream-less chunks


@pytest.mark.asyncio
async def test_streamless_chunks_keep_conn_id_and_never_set_stream(tmp_path: Path) -> None:
    """Kubernetes and preview chunks (no ``ssh`` object) behave exactly as before Session 13."""
    asm, db = await _make(tmp_path)
    for seq in (1, 2):
        result = await asm._on_chunk(_chunk(None, seq, f"K{seq}", float(seq)))
        assert result.outcome is ChunkOutcome.STORED and result.session_id == CONN
    row = await _row(db, CONN)
    assert (row["stream"], row["parent_conn_id"]) == (None, None)
    await db.close()


@pytest.mark.asyncio
async def test_a_streamed_chunk_on_a_streamless_recording_gets_a_derived_session(
    tmp_path: Path,
) -> None:
    """A stream-less recording already holds ``conn_id``; a chunk with a stream cannot claim it."""
    asm, db = await _make(tmp_path)
    await asm.handle(_chunk(None, 1, "K1", 1.0))
    result = await asm._on_chunk(_chunk(CH_A, 1, "A1", 1.0))
    assert result.session_id == session_id_for(CONN, CH_A) != CONN
    assert _tags(_cast(tmp_path, CONN)) == ["K1"]
    derived = await _row(db, result.session_id)
    assert (derived["parent_conn_id"], derived["stream"]) == (CONN, CH_A)
    await db.close()


@pytest.mark.asyncio
async def test_a_sealed_error_row_with_a_cast_is_not_claimable(tmp_path: Path) -> None:
    """A stream-less recording sealed as ``error`` (no header) keeps its cast; the stream goes derived."""
    asm, db = await _make(tmp_path)
    headerless = RecordingChunk(
        conn_id=CONN, seq=1, asciicast='[1.0,"o","x"]\n', is_final=True, stream=None
    )
    await asm.handle(headerless)
    row = await _row(db, CONN)
    assert row["status"] == "error" and row["cast_path"] is not None
    before = _cast_path(tmp_path, CONN).read_bytes()
    result = await asm._on_chunk(_chunk(CH_A, 1, "A1", 1.0))
    assert result.session_id == session_id_for(CONN, CH_A)
    assert _cast_path(tmp_path, CONN).read_bytes() == before
    await db.close()


# --------------------------------------------------------------------------- claims persist


@pytest.mark.asyncio
async def test_stream_claims_survive_a_restart_of_in_progress_recordings(tmp_path: Path) -> None:
    asm, db, _ = await _boot(tmp_path, encrypted=False)
    await asm.handle(_start(CONN))
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))
    await asm.handle(_chunk(CH_B, 1, "B1", 1.5))
    await db.close()

    asm, db, _ = await _boot(tmp_path, encrypted=False)  # fresh process: sweep re-adopts both
    assert asm.active_count == 2
    assert asm._buffers[CONN].stream == CH_A and asm._buffers[CONN].parent_conn_id is None
    assert asm._buffers[DERIVED_B].stream == CH_B and asm._buffers[DERIVED_B].parent_conn_id == CONN
    b2 = await asm._on_chunk(_chunk(CH_B, 2, "B2", 2.5))
    a2 = await asm._on_chunk(_chunk(CH_A, 2, "A2", 2.0))
    assert (b2.outcome, b2.session_id) == (ChunkOutcome.STORED, DERIVED_B)
    assert (a2.outcome, a2.session_id) == (ChunkOutcome.STORED, CONN)
    await asm.handle(_chunk(CH_A, 3, "A3", 3.0, final=True))
    await asm.handle(_chunk(CH_B, 3, "B3", 3.5, final=True))
    assert _tags(_cast(tmp_path, CONN)) == ["A1", "A2", "A3"]
    assert _tags(_cast(tmp_path, DERIVED_B)) == ["B1", "B2", "B3"]
    row = await _row(db, DERIVED_B)
    assert (row["parent_conn_id"], row["stream"], row["status"]) == (CONN, CH_B, "complete")
    await db.close()


@pytest.mark.asyncio
async def test_a_sealed_claim_still_blocks_a_second_stream_after_restart(tmp_path: Path) -> None:
    """The claim is read from ``sessions.stream`` (no buffer, no cache): B must not take ``conn_id``."""
    clock = FakeClock()
    asm, db, _ = await _boot(tmp_path, encrypted=False, clock=clock, max_idle=100)
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))
    clock.advance(500)
    await asm.finalize_idle()  # A sealed reopenably
    assert (await _row(db, CONN))["sealed_terminal"] == 0
    sealed_bytes = _cast_path(tmp_path, CONN).read_bytes()
    await db.close()

    asm, db, _ = await _boot(tmp_path, encrypted=False)
    result = await asm._on_chunk(_chunk(CH_B, 1, "B1", 1.2))
    assert result.session_id == DERIVED_B
    assert _cast_path(tmp_path, CONN).read_bytes() == sealed_bytes  # A's recording untouched
    assert (await _row(db, CONN))["stream"] == CH_A
    await asm.handle(_chunk(CH_A, 2, "A2", 2.0))  # a later chunk of A reopens its own session
    assert _tags(_cast(tmp_path, CONN)) == ["A1", "A2"]
    await db.close()


@pytest.mark.asyncio
async def test_stream_id_collision_drops_the_chunk_with_a_warning(
    tmp_path: Path, asm_log: io.StringIO
) -> None:
    """A derived id already owned by a different stream is never mixed into: dropped, warned."""
    asm, db = await _make(tmp_path)
    await asm.handle(_start(CONN))
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))
    await SessionRepository(db).upsert_start(
        DERIVED_B, "squatter", None, None, parent_conn_id=CONN, stream="someone-else"
    )
    result = await asm._on_chunk(_chunk(CH_B, 1, "B1", 1.5))
    assert result.outcome is ChunkOutcome.IGNORED and result.session_id is None
    assert asm.active_count == 1  # nothing buffered for the colliding stream
    assert not _cast_path(tmp_path, DERIVED_B).exists()
    warnings = _events(asm_log, "assembler.stream_id_collision")
    assert len(warnings) == 1 and warnings[0]["level"] == "warning"
    assert set(warnings[0]) == {"event", "level", "conn_id"}
    assert warnings[0]["conn_id"] == DERIVED_B
    # Even as a final flush it seals nothing.
    await asm.handle(_chunk(CH_B, 2, "B2", 2.5, final=True))
    assert asm.active_count == 1
    assert (await _row(db, CONN))["status"] == "provisional"
    await db.close()


# --------------------------------------------------------------------------- outcomes and finals


@pytest.mark.asyncio
async def test_conflicting_final_chunk_does_not_seal(
    tmp_path: Path, asm_log: io.StringIO
) -> None:
    asm, db = await _make(tmp_path)
    await asm.handle(_chunk(CH_A, 1, "FIRST", 1.0))
    conflicting = _chunk(CH_A, 1, "SECOND", 1.0, final=True)
    result = await asm._on_chunk(conflicting)
    assert result.outcome is ChunkOutcome.CONFLICT and result.session_id == CONN
    await asm.handle(conflicting)  # through handle: still no seal
    assert asm.active_count == 1
    assert (await _row(db, CONN))["status"] == "provisional"
    assert asm.seq_conflict_count == 2
    assert _tags(_cast(tmp_path, CONN)) == ["FIRST"]
    conflicts = _events(asm_log, "assembler.seq_conflict")
    assert len(conflicts) == 2
    assert all(set(e) == {"event", "level", "conn_id", "seq", "kept_length", "dropped_length"} for e in conflicts)
    assert "FIRST" not in asm_log.getvalue() and "SECOND" not in asm_log.getvalue()
    await asm.handle(_chunk(CH_A, 2, "REAL-FINAL", 2.0, final=True))  # a genuine final still seals
    assert (await _row(db, CONN))["status"] == "complete"
    await db.close()


@pytest.mark.asyncio
async def test_identical_redelivery_of_a_final_chunk_still_seals(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))
    result = await asm._on_chunk(_chunk(CH_A, 1, "A1", 1.0, final=True))
    assert result.outcome is ChunkOutcome.REDELIVERED
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0, final=True))
    assert (await _row(db, CONN))["status"] == "complete"
    assert asm.active_count == 0 and asm.seq_redelivered_count == 2
    await db.close()


@pytest.mark.asyncio
async def test_a_chunk_for_a_terminally_sealed_session_is_ignored(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0, final=True))
    before = _cast_path(tmp_path, CONN).read_bytes()
    result = await asm._on_chunk(_chunk(CH_A, 2, "LATE", 9.0))
    assert result.outcome is ChunkOutcome.IGNORED and result.session_id == CONN
    assert _cast_path(tmp_path, CONN).read_bytes() == before
    await db.close()


# --------------------------------------------------------------------------- redelivery vs a baseline


@pytest.mark.asyncio
async def test_redelivery_after_restart_is_a_noop_and_new_data_is_stored(tmp_path: Path) -> None:
    asm, db, _ = await _boot(tmp_path, encrypted=False)
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))
    await asm.handle(_chunk(CH_A, 2, "A2", 2.0))
    before = _cast(tmp_path, CONN)
    await db.close()

    asm, db, _ = await _boot(tmp_path, encrypted=False)
    for seq, tag, offset in ((1, "A1", 1.0), (2, "A2", 2.0)):
        result = await asm._on_chunk(_chunk(CH_A, seq, tag, offset))
        assert result.outcome is ChunkOutcome.REDELIVERED, tag
    assert asm.seq_redelivered_count == 2
    assert _cast(tmp_path, CONN) == before  # no duplicate events
    assert (await _row(db, CONN))["chunk_count"] == 2

    new = await asm._on_chunk(_chunk(CH_A, 3, "A3", 3.0))  # greater offset: new data
    assert new.outcome is ChunkOutcome.STORED
    # Same offset range but text the baseline does not hold: not a redelivery.
    other = await asm._on_chunk(_chunk(CH_A, 4, "DIFFERENT", 0.5))
    assert other.outcome is ChunkOutcome.STORED
    assert _tags(_cast(tmp_path, CONN)) == ["A1", "A2", "A3", "DIFFERENT"]  # by seq, after the baseline
    await db.close()


@pytest.mark.asyncio
async def test_a_multi_event_chunk_inside_the_baseline_is_a_redelivery(tmp_path: Path) -> None:
    """A chunk with several events is covered when its joined event block is in the baseline."""
    asm, db, _ = await _boot(tmp_path, encrypted=False)
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))
    await asm.handle(_chunk(CH_A, 2, "A2", 2.0))
    await db.close()
    asm, db, _ = await _boot(tmp_path, encrypted=False)
    both = RecordingChunk(
        conn_id=CONN,
        seq=7,
        asciicast=HEADER + json.dumps([1.0, "o", "A1"]) + "\n" + json.dumps([2.0, "o", "A2"]) + "\n",
        stream=CH_A,
    )
    assert (await asm._on_chunk(both)).outcome is ChunkOutcome.REDELIVERED
    # Out of order (A2 then A1) is not a line-aligned block of the baseline.
    swapped = RecordingChunk(
        conn_id=CONN,
        seq=8,
        asciicast=HEADER + json.dumps([2.0, "o", "A2"]) + "\n" + json.dumps([1.0, "o", "A1"]) + "\n",
        stream=CH_A,
    )
    assert (await asm._on_chunk(swapped)).outcome is ChunkOutcome.STORED
    await db.close()


@pytest.mark.parametrize("restart", [False, True], ids=["same-process", "after-restart"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "encrypted"])
@pytest.mark.asyncio
async def test_redelivery_to_a_reopenably_sealed_session_leaves_it_sealed_and_untouched(
    tmp_path: Path, encrypted: bool, restart: bool
) -> None:
    clock = FakeClock()
    asm, db, casts = await _boot(tmp_path, encrypted=encrypted, clock=clock, max_idle=100)
    await asm.handle(_start(CONN))
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))
    await asm.handle(_chunk(CH_A, 2, "A2", 2.0))
    clock.advance(500)
    await asm.finalize_idle()  # idle backstop: sealed, reopenable
    row = await _row(db, CONN)
    assert (row["status"], row["sealed_terminal"]) == ("complete", 0)
    sealed_bytes = _cast_path(tmp_path, CONN).read_bytes()
    if encrypted:
        assert b'"A1"' not in sealed_bytes  # really ciphertext at rest
    if restart:
        await db.close()
        asm, db, casts = await _boot(tmp_path, encrypted=encrypted, clock=FakeClock(), max_idle=100)

    result = await asm._on_chunk(_chunk(CH_A, 2, "A2", 2.0))
    assert result.outcome is ChunkOutcome.REDELIVERED and result.session_id == CONN
    assert _cast_path(tmp_path, CONN).read_bytes() == sealed_bytes  # byte-identical, still encrypted
    row = await _row(db, CONN)
    assert (row["status"], row["sealed_terminal"]) == ("complete", 0)
    assert asm.active_count == 0
    assert asm.seq_redelivered_count == 1

    # A chunk with new data reopens, extends and re-seals, each event once.
    stored = await asm._on_chunk(_chunk(CH_A, 3, "A3", 3.0))
    assert stored.outcome is ChunkOutcome.STORED
    assert (await _row(db, CONN))["status"] == "provisional"
    await asm.handle(_chunk(CH_A, 4, "A4", 4.0, final=True))
    row = await _row(db, CONN)
    assert (row["status"], row["sealed_terminal"]) == ("complete", 1)
    assert _tags(await casts.read_cast(CONN)) == ["A1", "A2", "A3", "A4"]
    await db.close()


# --------------------------------------------------------------------------- start lines and expiry


@pytest.mark.asyncio
async def test_a_late_start_line_after_one_channel_sealed_still_annotates_the_connection(
    tmp_path: Path, asm_log: io.StringIO
) -> None:
    asm, db = await _make(tmp_path)
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))  # chunks beat the start line
    await asm.handle(_chunk(CH_B, 1, "B1", 1.5))
    await asm.handle(_chunk(CH_A, 2, "A2", 2.0, final=True))  # A sealed, B still recording
    await asm.handle(_start(CONN, "late.example"))
    conn = await _conn(db, CONN)
    assert conn["resource_address"] == "late.example"
    assert (await _row(db, DERIVED_B))["resource_address"] == "late.example"
    assert asm._buffers[DERIVED_B].resource_address == "late.example"
    assert _events(asm_log, "assembler.ignore_sealed") == []

    await asm.handle(_chunk(CH_B, 2, "B2", 2.5, final=True))  # now every session is sealed
    await asm.handle(_start(CONN, "much-later.example"))
    assert (await _conn(db, CONN))["resource_address"] == "late.example"  # ignored
    ignored = [e for e in _events(asm_log, "assembler.ignore_sealed") if e.get("phase") == "start"]
    assert len(ignored) == 1
    await db.close()


async def _force_pending_and_aged(db: aiosqlite.Connection, conn_id: str) -> None:
    await db.execute("UPDATE connections SET state = 'pending' WHERE conn_id = ?", (conn_id,))
    await db.commit()
    await _age_connection(db, conn_id)


@pytest.mark.asyncio
async def test_pending_expiry_skips_a_connection_with_buffered_channels(tmp_path: Path) -> None:
    clock = FakeClock()
    asm, db = await _make(tmp_path, clock=clock, max_idle=3600)
    await asm.handle(_start(CONN))
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0))
    await asm.handle(_chunk(CH_B, 1, "B1", 1.5))
    await _force_pending_and_aged(db, CONN)
    await asm.finalize_idle()  # buffers are not idle; the pending connection is past the backstop
    for sid in (CONN, DERIVED_B):
        assert (await _row(db, sid))["status"] == "provisional", sid
    assert (await _conn(db, CONN))["state"] == "recording"
    await db.close()


@pytest.mark.asyncio
async def test_pending_expiry_skips_a_connection_whose_only_session_is_sealed(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await asm.handle(_start(CONN))
    await asm.handle(_chunk(CH_A, 1, "A1", 1.0, final=True))
    await _force_pending_and_aged(db, CONN)
    await asm.finalize_idle()
    row = await _row(db, CONN)
    assert (row["status"], row["sealed_terminal"]) == ("complete", 1)  # not turned into 'error'
    assert (await _conn(db, CONN))["state"] == "recording"
    await db.close()


@pytest.mark.asyncio
async def test_first_stream_claims_a_backstop_error_row_without_deleting_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock()
    asm, db = await _make(tmp_path, clock=clock, max_idle=3600)
    await asm.handle(_start(CONN))
    await _age_connection(db, CONN)
    await asm.finalize_idle()  # pending past the backstop: a visible start-only 'error' row
    placeholder = await _row(db, CONN)
    assert (placeholder["status"], placeholder["stream"], placeholder["cast_path"]) == (
        "error", None, None,
    )

    async def must_not_be_called(conn_id: str) -> bool:
        raise AssertionError("_promote must not delete the start-only error row")

    monkeypatch.setattr(asm._repo, "delete_start_only_error", must_not_be_called)
    result = await asm._on_chunk(_chunk(CH_A, 1, "A1", 1.0))
    assert (result.outcome, result.session_id) == (ChunkOutcome.STORED, CONN)
    row = await _row(db, CONN)
    assert row["status"] == "provisional"  # reverted through revert_error_to_provisional
    assert (row["stream"], row["parent_conn_id"]) == (CH_A, None)
    assert row["resource_address"] == "k8s.example.internal"
    # The second stream is derived as usual.
    assert (await asm._on_chunk(_chunk(CH_B, 1, "B1", 1.5))).session_id == DERIVED_B
    await db.close()


# --------------------------------------------------------------------------- store round trip


@pytest.mark.asyncio
async def test_channel_columns_round_trip_and_first_non_null_wins(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    repo = SessionRepository(db)
    await repo.upsert_start("s1", "u", "addr", None, parent_conn_id="parent-1", stream="0")
    row = await repo.get("s1")
    assert (row.parent_conn_id, row.stream) == ("parent-1", "0")  # "0" stays a string
    await repo.upsert_start("s1", "u", "addr", None, parent_conn_id="parent-2", stream="9")
    await repo.upsert_start("s1", "u", "addr", None)
    await repo.add_chunk_meta(
        conn_id="s1", username="u", started_at=None, request_id=None,
        parent_conn_id="parent-3", stream="8",
    )
    row = await repo.get("s1")
    assert (row.parent_conn_id, row.stream) == ("parent-1", "0")  # never overwritten, never cleared
    await repo.upsert_start("plain", "u", "addr", None)
    plain = await repo.get("plain")
    assert (plain.parent_conn_id, plain.stream) == (None, None)
    cur = await db.execute("SELECT typeof(stream) FROM sessions WHERE conn_id = 's1'")
    assert (await cur.fetchone())[0] == "text"
    await db.close()


# --------------------------------------------------------------------------- retention


@pytest.mark.asyncio
async def test_retention_purges_derived_sessions_with_their_cast_sidecar_and_findings(
    tmp_path: Path,
) -> None:
    from gatorcast.db import init_db
    from gatorcast.store.activity import ActivityStore

    db = await init_db(tmp_path / "gatorcast.db")
    repo = SessionRepository(db)
    casts = CastStore(tmp_path / "casts")
    search = SearchStore(db, casts)
    asm = Assembler(
        repo=repo, casts=casts, idle_timeout_seconds=120, clock=lambda: 0.0,
        activity=ActivityStore(db), search=search,
    )
    other_derived = session_id_for(OTHER_CONN, CH_B)
    for conn in (CONN, OTHER_CONN):
        await asm.handle(_start(conn))
        await asm.handle(_chunk(CH_A, 1, "rm -rf /etc", 1.0, conn=conn))
        await asm.handle(_chunk(CH_B, 1, "rm -rf /etc", 1.5, conn=conn))
    await asm.handle(SessionEnd(conn_id=CONN))
    await asm.handle(SessionEnd(conn_id=OTHER_CONN))
    for sid in (CONN, DERIVED_B, OTHER_CONN, other_derived):
        assert _cast_path(tmp_path, sid).exists() and casts.has_sidecar(sid), sid
        assert await search.list_findings(sid), sid
    await db.execute(
        "UPDATE sessions SET started_at = '2000-01-01T00:00:00Z' WHERE conn_id IN (?, ?)",
        (CONN, DERIVED_B),
    )
    await db.execute(
        "UPDATE sessions SET started_at = '2099-12-31T00:00:00Z' WHERE conn_id IN (?, ?)",
        (OTHER_CONN, other_derived),
    )
    await db.commit()

    await RetentionPurger(
        repo=repo, casts=casts, retention_days=1, retention_max_gb=0, search=search
    ).run()

    for sid in (CONN, DERIVED_B):  # the old connection's two channels are both gone
        assert await repo.get(sid) is None, sid
        assert not _cast_path(tmp_path, sid).exists()
        assert not casts.has_sidecar(sid)
        assert await search.list_findings(sid) == []
    for sid in (OTHER_CONN, other_derived):  # the recent connection's are untouched
        assert await repo.get(sid) is not None, sid
        assert _cast_path(tmp_path, sid).exists() and casts.has_sidecar(sid)
    await db.close()

