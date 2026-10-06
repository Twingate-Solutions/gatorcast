"""Tests for pipeline.assembler: parsing, reassembly, finalize, idle, sweep, and the
connection lifecycle (pending → recording / api / error, kubectl activity spec §6)."""

from __future__ import annotations

import base64
import io
import json
import logging
from pathlib import Path

import aiosqlite
import pytest
import structlog

import gatorcast.pipeline.assembler as assembler_module
from gatorcast.crypto import Cryptor

from gatorcast.db import init_db
from gatorcast.models import ApiRequest, RecordingChunk, SessionEnd, SessionStart
from gatorcast.pipeline.assembler import (
    Assembler,
    parse_asciicast,
    reassemble_asciicast,
)
from gatorcast.store.activity import ActivityStore
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import SessionRepository
from tests.samples import sample_lines

# Real Gateway chunking (confirmed against internal/sessionrecorder): each flush
# re-emits the header, then only the events recorded since the previous flush.
# Events are always whole lines — the recorder marshals one [t,"o",data] tuple per
# line and never splits mid-tuple.
HEADER = '{"version":2,"width":80,"height":24,"timestamp":1700000000,"user":"ubuntu"}\n'
CHUNK_1 = HEADER + '[0.0,"o","a"]\n[1.5,"o","b"]\n'
CHUNK_2 = HEADER + '[3.25,"o","c"]\n'  # header repeats; only new events follow
# What Gatorcast must store after reassembly: the header once, all events in order.
FULL_DOC = HEADER + '[0.0,"o","a"]\n[1.5,"o","b"]\n[3.25,"o","c"]\n'


def _nonblank(text: str) -> list[str]:
    """Return the stripped, non-blank lines of a document (order preserved)."""
    return [line.strip() for line in text.splitlines() if line.strip()]


class FakeClock:
    """A controllable monotonic clock for idle-timeout tests."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


async def _make(
    tmp_path: Path, idle: int = 120, clock=None, max_idle: int = 3600
) -> tuple[Assembler, aiosqlite.Connection]:
    """Build an assembler backed by a fresh schema-initialized DB."""
    db = await init_db(tmp_path / "gatorcast.db")
    repo = SessionRepository(db)
    casts = CastStore(tmp_path / "casts")
    asm = Assembler(
        repo=repo,
        casts=casts,
        idle_timeout_seconds=idle,
        session_max_idle_seconds=max_idle,
        clock=clock or (lambda: 0.0),
        activity=ActivityStore(db),
    )
    return asm, db


async def _make_with_search(
    tmp_path: Path, idle: int = 120, detection_enabled: bool = True
) -> tuple[Assembler, SessionRepository, CastStore, SearchStore, aiosqlite.Connection]:
    """Build an assembler wired with a real SearchStore for scan-hook tests."""
    db = await init_db(tmp_path / "gatorcast.db")
    repo = SessionRepository(db)
    casts = CastStore(tmp_path / "casts")
    search = SearchStore(db, casts)
    asm = Assembler(
        repo=repo,
        casts=casts,
        idle_timeout_seconds=idle,
        clock=lambda: 0.0,
        activity=ActivityStore(db),
        search=search,
        detection_enabled=detection_enabled,
    )
    return asm, repo, casts, search, db


# A minimal valid asciicast whose output contains a dangerous command for detection.
SCAN_CAST = (
    '{"version":2,"width":80,"height":24,"timestamp":1700000000}\n'
    '[0.5,"o","rm -rf /etc\\r\\n"]\n'
)


async def _row(db: aiosqlite.Connection, conn_id: str) -> aiosqlite.Row | None:
    cur = await db.execute("SELECT * FROM sessions WHERE conn_id = ?", (conn_id,))
    row = await cur.fetchone()
    await cur.close()
    return row


async def _conn(db: aiosqlite.Connection, conn_id: str) -> aiosqlite.Row | None:
    """Fetch one ``connections`` row (hidden per-connection lifecycle state)."""
    cur = await db.execute("SELECT * FROM connections WHERE conn_id = ?", (conn_id,))
    row = await cur.fetchone()
    await cur.close()
    return row


async def _count(db: aiosqlite.Connection, sql: str, params: tuple = ()) -> int:
    """Run a ``COUNT(*)`` query and return the number."""
    cur = await db.execute(sql, params)
    row = await cur.fetchone()
    await cur.close()
    return int(row[0])


async def _age_connection(db: aiosqlite.Connection, conn_id: str) -> None:
    """Backdate a connection's ``last_seen_at`` past any backstop window.

    The pending backstop ages connections on SQLite wall-clock time (so it
    survives restarts), not on the assembler's injectable monotonic clock.
    """
    await db.execute(
        "UPDATE connections SET last_seen_at = '2000-01-01 00:00:00' WHERE conn_id = ?",
        (conn_id,),
    )
    await db.commit()


def _api(
    conn_id: str,
    request_id: str,
    *,
    method: str = "GET",
    url: str = "/api/v1/namespaces/default/pods",
) -> ApiRequest:
    """Build an allowlisted API audit event (as ``classify`` would emit it)."""
    return ApiRequest(
        conn_id=conn_id,
        request_id=request_id,
        requested_at="2026-10-01T10:00:01.200Z",
        user_id="VXNlcjox",
        username="user@example.com",
        method=method,
        url=url,
        status_code=200,
        kubectl_command="kubectl get",
        kubectl_session="5e55e55e-0000-4000-8000-000000000001",
        user_agent="kubectl/v1.33.0 (linux/amd64)",
    )


def _start(conn_id: str, address: str = "k8s.example.internal") -> SessionStart:
    """Build an ``Authenticated connection`` event."""
    return SessionStart(
        conn_id=conn_id,
        resource_address=address,
        username="user@example.com",
        user_id="VXNlcjox",
        ts="2026-10-01T10:00:00.100Z",
    )


# --- parse_asciicast --------------------------------------------------------


def test_parse_valid_document() -> None:
    meta = parse_asciicast(FULL_DOC)
    assert meta.ok
    assert meta.width == 80
    assert meta.height == 24
    assert meta.shell_user == "ubuntu"
    assert meta.event_count == 3
    assert meta.duration_seconds == 3.25
    assert meta.started_at is not None and meta.started_at.endswith("Z")


def test_parse_missing_header_marks_error() -> None:
    meta = parse_asciicast('[0.0,"o","a"]\n')
    assert not meta.ok
    assert meta.error is not None


def test_parse_empty_marks_error() -> None:
    assert parse_asciicast("").ok is False


def test_parse_tolerates_trailing_partial_line() -> None:
    meta = parse_asciicast(HEADER + '[0.0,"o","a"]\n[1.5,"o","b')
    assert meta.ok
    assert meta.event_count == 1  # the partial trailing tuple is skipped


# --- reassembly -------------------------------------------------------------


def test_reassemble_dedups_repeated_header() -> None:
    """Multiple Gateway chunks (each header+events) rebuild to one clean document."""
    doc = reassemble_asciicast([CHUNK_1, CHUNK_2])
    assert doc == FULL_DOC
    # Exactly one header line survives; all three events are kept in order.
    meta = parse_asciicast(doc)
    assert meta.ok
    assert meta.event_count == 3
    assert meta.duration_seconds == 3.25
    assert doc.count('"version":2') == 1


def test_reassemble_single_chunk_is_stable() -> None:
    """A single chunk round-trips to an equivalent document (one header + events)."""
    assert reassemble_asciicast([CHUNK_1]) == HEADER + '[0.0,"o","a"]\n[1.5,"o","b"]\n'


def test_reassemble_tolerates_boundary_garbage_and_blank_lines() -> None:
    """Blank lines and a non-JSON boundary fragment are skipped, not corrupting output."""
    noisy = HEADER + '[0.0,"o","a"]\n\n(not json)\n[1.0,"o","b"]\n'
    doc = reassemble_asciicast([noisy])
    meta = parse_asciicast(doc)
    assert meta.ok and meta.event_count == 2


def test_reassemble_no_header_returns_events_only() -> None:
    """With no header anywhere, events are kept (caller will mark the row error)."""
    doc = reassemble_asciicast(['[0.0,"o","x"]\n'])
    assert not parse_asciicast(doc).ok  # header missing → error, but raw kept
    assert '[0.0,"o","x"]' in doc


@pytest.mark.asyncio
async def test_real_sample_reassembles(tmp_path: Path) -> None:
    """The real recording chunk finalizes to a valid, metadata-bearing .cast."""
    asm, db = await _make(tmp_path)
    obj = json.loads(sample_lines()[0])
    conn_id = obj["conn_id"]
    await asm.handle(
        RecordingChunk(conn_id=conn_id, seq=0, asciicast=obj["asciicast"])
    )
    await asm.finalize(conn_id)

    cast = (tmp_path / "casts" / f"{conn_id}.cast").read_text(encoding="utf-8")
    # Reassembly is line-based: the stored cast has the same non-blank lines as the
    # source chunk (a single chunk is already one header + its events).
    assert _nonblank(cast) == _nonblank(obj["asciicast"])
    row = await _row(db, conn_id)
    assert row["status"] == "complete"
    assert row["width"] == 111
    assert row["height"] == 56
    assert row["shell_user"] == "ubuntu"
    assert row["chunk_count"] == 1
    await db.close()


@pytest.mark.asyncio
async def test_multi_chunk_in_order(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "conn-multi"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=CHUNK_2))
    await asm.finalize(cid)
    assert (tmp_path / "casts" / f"{cid}.cast").read_text(encoding="utf-8") == FULL_DOC
    row = await _row(db, cid)
    assert row["status"] == "complete" and row["chunk_count"] == 2
    await db.close()


@pytest.mark.asyncio
async def test_out_of_order_seq_reassembles_correctly(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "conn-ooo"
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=CHUNK_2))
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))
    await asm.finalize(cid)
    assert (tmp_path / "casts" / f"{cid}.cast").read_text(encoding="utf-8") == FULL_DOC
    await db.close()


@pytest.mark.asyncio
async def test_duplicate_seq_last_write_wins(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "conn-dup"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=HEADER))
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast='[0.0,"o","WRONG"]\n'))
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast='[0.0,"o","right"]\n'))
    await asm.finalize(cid)
    cast = (tmp_path / "casts" / f"{cid}.cast").read_text(encoding="utf-8")
    assert "right" in cast and "WRONG" not in cast
    row = await _row(db, cid)
    assert row["chunk_count"] == 2  # two distinct seqs
    await db.close()


@pytest.mark.asyncio
async def test_interleaved_two_connections_separate(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await asm.handle(SessionStart(conn_id="A", resource_address="host-a", username="u@x"))
    await asm.handle(RecordingChunk(conn_id="A", seq=0, asciicast=CHUNK_1))
    await asm.handle(SessionStart(conn_id="B", resource_address="host-b", username="u@x"))
    await asm.handle(RecordingChunk(conn_id="B", seq=0, asciicast=HEADER))
    await asm.handle(RecordingChunk(conn_id="A", seq=1, asciicast=CHUNK_2))
    await asm.finalize("A")
    await asm.finalize("B")

    assert (tmp_path / "casts" / "A.cast").read_text(encoding="utf-8") == FULL_DOC
    assert (tmp_path / "casts" / "B.cast").read_text(encoding="utf-8") == HEADER
    row_a = await _row(db, "A")
    row_b = await _row(db, "B")
    assert row_a["resource_address"] == "host-a"
    assert row_b["resource_address"] == "host-b"
    await db.close()


# --- finalize lifecycle -----------------------------------------------------


@pytest.mark.asyncio
async def test_final_chunk_finalizes_immediately(tmp_path: Path) -> None:
    """The Gateway's 'session finished' flush (is_final) finalizes without any wait."""
    asm, db = await _make(tmp_path)
    cid = "conn-final"
    await asm.handle(
        RecordingChunk(conn_id=cid, seq=0, asciicast=FULL_DOC, is_final=True)
    )
    # No clock advance, no idle sweep: the end signal finalized it.
    assert asm.active_count == 0
    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert row["duration_seconds"] == 3.25
    await db.close()


@pytest.mark.asyncio
async def test_idle_does_not_cut_short_active_recording(tmp_path: Path) -> None:
    """A recording that goes quiet past idle_timeout keeps buffering (not finalized)."""
    clock = FakeClock()
    asm, db = await _make(tmp_path, idle=120, clock=clock, max_idle=3600)
    cid = "conn-active"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))

    clock.advance(300)  # long pause, well past idle_timeout but under max_idle
    await asm.finalize_idle()
    assert asm.active_count == 1, "an active recording must not be finalized by idle"
    assert (await _row(db, cid))["status"] == "provisional"
    await db.close()


@pytest.mark.asyncio
async def test_pause_then_resume_recombines_under_conn_id(tmp_path: Path) -> None:
    """The core requirement: chunks split by a long pause recombine into ONE session.

    A chunk arrives, the session goes silent past the idle timeout (an interactive
    pause), then more chunks + the final flush arrive under the same conn_id. The
    result is a single complete recording containing ALL events — nothing lost.
    """
    clock = FakeClock()
    asm, db = await _make(tmp_path, idle=120, clock=clock, max_idle=3600)
    cid = "conn-pause"

    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))
    clock.advance(600)  # user steps away for 10 minutes; no output flushes
    await asm.finalize_idle()  # must NOT finalize/lock the session
    assert (await _row(db, cid))["status"] == "provisional"

    # User resumes; the Gateway sends the next chunk and then the final flush.
    await asm.handle(
        RecordingChunk(conn_id=cid, seq=1, asciicast=CHUNK_2, is_final=True)
    )
    assert asm.active_count == 0
    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert row["chunk_count"] == 2
    # All three events across both chunks survived the pause.
    cast = (tmp_path / "casts" / f"{cid}.cast").read_text(encoding="utf-8")
    assert cast == FULL_DOC
    assert parse_asciicast(cast).event_count == 3
    await db.close()


@pytest.mark.asyncio
async def test_hard_idle_backstop_finalizes_abandoned_recording(tmp_path: Path) -> None:
    """If 'session finished' never arrives (Gateway crash), the hard backstop finalizes."""
    clock = FakeClock()
    asm, db = await _make(tmp_path, idle=120, clock=clock, max_idle=1800)
    cid = "conn-crash"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))

    clock.advance(1700)  # past idle, under max_idle → still buffering
    await asm.finalize_idle()
    assert (await _row(db, cid))["status"] == "provisional"

    clock.advance(200)  # now past max_idle → backstop finalizes what we have
    await asm.finalize_idle()
    assert asm.active_count == 0
    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert row["chunk_count"] == 1
    await db.close()


# --- file-first: durability, live detection, reopen, encryption ------------


@pytest.mark.asyncio
async def test_append_persists_plaintext_before_seal(tmp_path: Path) -> None:
    """Durability: each append writes the plaintext .cast to disk immediately."""
    asm, db = await _make(tmp_path)
    cid = "conn-persist"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))
    # No finalize yet: the file already exists with the current content, and the
    # row is provisional with derived metadata mirrored on.
    cast_path = tmp_path / "casts" / f"{cid}.cast"
    assert cast_path.is_file()
    assert parse_asciicast(cast_path.read_text(encoding="utf-8")).event_count == 2
    row = await _row(db, cid)
    assert row["status"] == "provisional"
    assert row["width"] == 80 and row["size_bytes"] > 0
    await db.close()


@pytest.mark.asyncio
async def test_live_detection_before_seal(tmp_path: Path) -> None:
    """Detection runs live on append: findings exist before the session is sealed."""
    asm, repo, casts, search, db = await _make_with_search(tmp_path)
    cid = "conn-live"
    # A non-final chunk carrying a dangerous command.
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=SCAN_CAST))

    # Still in progress, but the finding is already recorded (live scan).
    row = await _row(db, cid)
    assert row["status"] == "provisional"
    findings = await search.list_findings(cid)
    assert any(f.rule_id == "recursive-delete" for f in findings)
    # The search sidecar is NOT written until seal.
    assert casts.has_sidecar(cid) is False
    await db.close()


@pytest.mark.asyncio
async def test_reopen_after_backstop_seal_recombines(tmp_path: Path) -> None:
    """A backstop-sealed session that resumes reopens and recombines all events."""
    clock = FakeClock()
    asm, db = await _make(tmp_path, idle=120, clock=clock, max_idle=1800)
    cid = "conn-reopen"

    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))
    clock.advance(1801)  # silent past the backstop
    await asm.finalize_idle()
    assert (await _row(db, cid))["status"] == "complete"  # reopenably sealed

    # A late chunk (with the final flush) resumes it: reopen → append → re-seal.
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=CHUNK_2, is_final=True))
    row = await _row(db, cid)
    assert row["status"] == "complete"
    cast = (tmp_path / "casts" / f"{cid}.cast").read_text(encoding="utf-8")
    assert parse_asciicast(cast).event_count == 3  # nothing lost across the seal
    await db.close()


def _key() -> str:
    """A deterministic base64-encoded 32-byte key for encryption tests."""
    return base64.b64encode(b"k" * 32).decode()


@pytest.mark.asyncio
async def test_encryption_plaintext_while_in_progress_then_sealed(tmp_path: Path) -> None:
    """In-progress .cast is plaintext on disk; sealing encrypts it (round-trips)."""
    db = await init_db(tmp_path / "gatorcast.db")
    repo = SessionRepository(db)
    casts = CastStore(tmp_path / "casts", cryptor=Cryptor(_key()))
    asm = Assembler(
        repo=repo,
        casts=casts,
        idle_timeout_seconds=120,
        clock=lambda: 0.0,
        activity=ActivityStore(db),
    )
    cid = "conn-enc"

    # In progress: the on-disk file is PLAINTEXT even though encryption is enabled.
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))
    raw = (tmp_path / "casts" / f"{cid}.cast").read_bytes()
    assert raw.startswith(b'{"version":2'), "in-progress file must be plaintext"

    # Seal via the final flush: the file is now encrypted, and decrypts back cleanly.
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=CHUNK_2, is_final=True))
    sealed = (tmp_path / "casts" / f"{cid}.cast").read_bytes()
    assert not sealed.startswith(b'{"version":2'), "sealed file must be encrypted"
    assert await casts.read_cast(cid) == FULL_DOC
    assert (await _row(db, cid))["status"] == "complete"
    await db.close()


@pytest.mark.asyncio
async def test_idle_does_not_error_chunkless_start(tmp_path: Path) -> None:
    """A started-but-not-yet-recorded session must survive the idle sweep.

    Regression: the Gateway emits "Authenticated connection" at session start but
    ships the asciicast recording only at session end. A long-running session (or
    one whose recording is delayed past the idle window) therefore has a buffer
    with ZERO chunks when the idle sweep fires. It must NOT be finalized as
    ``error`` and must NOT be marked finalized — otherwise the real recording that
    arrives later is discarded and the row is stuck at ``error``.

    A start creates only a hidden pending connection (no session row) until the
    first chunk promotes it.
    """
    clock = FakeClock()
    asm, db = await _make(tmp_path, idle=120, clock=clock)
    cid = "conn-late-record"

    # Session start arrives; no recording chunks yet → pending connection, no row.
    await asm.handle(
        SessionStart(conn_id=cid, resource_address="10.0.0.30", username="u@x")
    )
    assert await _row(db, cid) is None
    assert (await _conn(db, cid))["state"] == "pending"

    # Idle window elapses with zero chunks (under the backstop). The sweep must
    # leave it pending, not error it.
    clock.advance(121)
    await asm.finalize_idle()
    assert await _row(db, cid) is None, "chunkless start must not be errored by idle sweep"
    assert (await _conn(db, cid))["state"] == "pending"
    assert (tmp_path / "casts" / f"{cid}.cast").exists() is False, "no .cast for a chunkless session"

    # The real recording finally ships (with its final flush). It must be accepted
    # (conn_id was never locked) and recombine under the same conn_id.
    await asm.handle(
        RecordingChunk(conn_id=cid, seq=0, asciicast=FULL_DOC, is_final=True)
    )
    row = await _row(db, cid)
    assert row["status"] == "complete", "late-arriving recording must still finalize to complete"
    assert row["resource_address"] == "10.0.0.30"  # identity from the start event preserved
    await db.close()


@pytest.mark.asyncio
async def test_chunkless_session_errors_at_backstop_then_recovers(tmp_path: Path) -> None:
    """A session that starts but never records is marked error at the backstop.

    This is the "unparseable data / broken shipper" case: the start event created a
    pending connection but no valid chunk (and no API audit) ever arrived. Below the
    backstop it stays pending with no row (a quiet session may just not have flushed
    yet); past the backstop it becomes a visible ``error`` row. A genuinely-late
    chunk still recovers it.
    """
    clock = FakeClock()
    asm, db = await _make(tmp_path, idle=120, clock=clock, max_idle=1800)
    cid = "conn-norecord"
    await asm.handle(
        SessionStart(conn_id=cid, resource_address="10.0.0.30", username="u@x")
    )

    clock.advance(600)  # under the backstop → still pending, no visible row
    await asm.finalize_idle()
    assert await _row(db, cid) is None
    assert (await _conn(db, cid))["state"] == "pending"

    # Past the backstop (aged on SQLite wall-clock last_seen_at) → visible error row.
    await _age_connection(db, cid)
    await asm.finalize_idle()
    assert asm.active_count == 0
    row = await _row(db, cid)
    assert row["status"] == "error"
    assert row["resource_address"] == "10.0.0.30"
    assert row["username"] == "u@x"
    assert (await _conn(db, cid))["state"] == "error"

    # A genuinely-late chunk recovers it: error → provisional → complete.
    await asm.handle(
        RecordingChunk(conn_id=cid, seq=0, asciicast=FULL_DOC, is_final=True)
    )
    row = await _row(db, cid)
    assert row["status"] == "complete", "late chunk must recover an errored empty session"
    assert row["resource_address"] == "10.0.0.30"  # start-event identity preserved
    assert (await _conn(db, cid))["state"] == "recording"
    await db.close()


@pytest.mark.asyncio
async def test_partial_session_still_finalizes(tmp_path: Path) -> None:
    """An interrupted session (no close event) still produces a playable .cast."""
    asm, db = await _make(tmp_path)
    cid = "conn-partial"
    await asm.handle(SessionStart(conn_id=cid, resource_address="host", username="u@x"))
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))  # no final flush
    await asm.finalize(cid)
    row = await _row(db, cid)
    # CHUNK_1 has a valid header, so it is complete and playable despite being partial.
    assert row["status"] == "complete"
    assert (tmp_path / "casts" / f"{cid}.cast").exists()
    await db.close()


@pytest.mark.asyncio
async def test_headerless_session_marked_error_but_kept(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "conn-bad"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast='[0.0,"o","x"]\n'))
    await asm.finalize(cid)
    row = await _row(db, cid)
    assert row["status"] == "error"
    assert (tmp_path / "casts" / f"{cid}.cast").exists()  # raw kept for inspection
    await db.close()


@pytest.mark.asyncio
async def test_finalize_is_idempotent(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "conn-idem"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=HEADER))
    await asm.finalize(cid)
    await asm.finalize(cid)  # second call: buffer gone → no-op
    assert (await _row(db, cid))["status"] == "complete"
    await db.close()


@pytest.mark.asyncio
async def test_session_end_event_finalizes(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "conn-end"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=HEADER))
    await asm.handle(SessionEnd(conn_id=cid))
    assert asm.active_count == 0
    assert (await _row(db, cid))["status"] == "complete"
    await db.close()


# --- startup sweep ----------------------------------------------------------


@pytest.mark.asyncio
async def test_sweep_deletes_stale_empty_provisional(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path, idle=120)
    await db.execute(
        "INSERT INTO sessions (conn_id, status, created_at) "
        "VALUES ('stale', 'provisional', '2000-01-01 00:00:00')"
    )
    await db.commit()
    await asm.sweep_startup()
    assert await _row(db, "stale") is None  # swept
    await db.close()


@pytest.mark.asyncio
async def test_sweep_readopts_provisional_with_cast_on_disk(tmp_path: Path) -> None:
    """Restart: a provisional row + on-disk plaintext .cast is re-adopted as active.

    File-first durability: instead of sealing on boot, the recording is re-adopted
    in-progress (baseline from disk) so continuation chunks keep appending. It seals
    normally afterward (here, on a terminal 'session finished' chunk) with ALL events.
    """
    asm, db = await _make(tmp_path, idle=120)
    cid = "recovered"
    (tmp_path / "casts").mkdir(exist_ok=True)
    (tmp_path / "casts" / f"{cid}.cast").write_text(CHUNK_1, encoding="utf-8")
    await db.execute(
        "INSERT INTO sessions (conn_id, status, created_at) "
        "VALUES (?, 'provisional', '2000-01-01 00:00:00')",
        (cid,),
    )
    await db.commit()
    await asm.sweep_startup()

    # Re-adopted, not sealed: still provisional and buffering in memory.
    assert asm.active_count == 1
    assert (await _row(db, cid))["status"] == "provisional"

    # A continuation chunk (with the final flush) recombines with the recovered
    # baseline and seals to complete with every event.
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=CHUNK_2, is_final=True))
    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert row["width"] == 80
    cast = (tmp_path / "casts" / f"{cid}.cast").read_text(encoding="utf-8")
    assert parse_asciicast(cast).event_count == 3  # baseline's 2 + continuation's 1
    await db.close()


@pytest.mark.asyncio
async def test_sweep_leaves_recent_provisional(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path, idle=120)
    await db.execute(
        "INSERT INTO sessions (conn_id, status, created_at) "
        "VALUES ('fresh', 'provisional', datetime('now'))"
    )
    await db.commit()
    await asm.sweep_startup()
    assert (await _row(db, "fresh"))["status"] == "provisional"
    await db.close()


# --- provisional → complete transition (via repository) ---------------------


@pytest.mark.asyncio
async def test_pending_to_provisional_to_complete_transition(tmp_path: Path) -> None:
    """SessionStart creates a pending connection; the first chunk promotes it to a
    provisional row carrying the start's identity; finalize completes it."""
    asm, db = await _make(tmp_path)
    cid = "conn-trans"
    await asm.handle(
        SessionStart(conn_id=cid, resource_address="srv.example.com", username="alice@x")
    )
    assert await _row(db, cid) is None
    assert (await _conn(db, cid))["state"] == "pending"

    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=HEADER))
    row = await _row(db, cid)
    assert row["status"] == "provisional"
    assert row["resource_address"] == "srv.example.com"
    assert row["username"] == "alice@x"

    await asm.finalize(cid)
    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert row["resource_address"] == "srv.example.com"  # preserved through finalize
    await db.close()


@pytest.mark.asyncio
async def test_complete_row_not_clobbered_by_upsert(tmp_path: Path) -> None:
    """A complete row is never overwritten by a subsequent upsert_start call."""
    asm, db = await _make(tmp_path)
    cid = "conn-guard"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=HEADER))
    await asm.finalize(cid)
    row = await _row(db, cid)
    assert row["status"] == "complete"

    # Simulate a redelivery: another start event for the same conn_id.
    await asm.handle(
        SessionStart(conn_id=cid, resource_address="other", username="late@x")
    )
    row = await _row(db, cid)
    # The complete row must not be touched by the provisional guard.
    assert row["status"] == "complete"
    await db.close()


# --- late-chunk / post-finalize regression (HIGH bug fix) ------------------


@pytest.mark.asyncio
async def test_late_chunk_after_finalize_is_ignored(tmp_path: Path) -> None:
    """A RecordingChunk arriving after finalize must not overwrite the .cast file.

    Regression for the HIGH finding: without the ``_finalized`` guard a late
    redelivery re-creates a buffer, the idle sweep fires, and writes a truncated
    .cast over the good one. This test fails if the guard is removed.
    """
    clock = FakeClock()
    asm, db = await _make(tmp_path, idle=10, clock=clock)
    cid = "conn-late"

    # Normal happy path: two chunks → finalize → complete.
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=CHUNK_2))
    await asm.finalize(cid)

    cast_path = tmp_path / "casts" / f"{cid}.cast"
    original_content = cast_path.read_text(encoding="utf-8")
    assert original_content == FULL_DOC
    assert (await _row(db, cid))["status"] == "complete"
    assert asm.active_count == 0

    # Late/redelivered chunk arrives AFTER finalize.
    await asm.handle(RecordingChunk(conn_id=cid, seq=2, asciicast='[99.0,"o","LATE"]\n'))

    # The guard must have ignored the late chunk: no new buffer created.
    assert asm.active_count == 0, "late chunk must not re-create a buffer"

    # Even if idle sweep fires, the .cast file is unchanged.
    clock.advance(30)
    await asm.finalize_idle()
    assert asm.active_count == 0
    assert cast_path.read_text(encoding="utf-8") == original_content, (
        "idle sweep must not overwrite the finalized .cast file"
    )

    # Row stays complete, not reverted to provisional.
    assert (await _row(db, cid))["status"] == "complete"
    await db.close()


@pytest.mark.asyncio
async def test_late_start_after_finalize_is_ignored(tmp_path: Path) -> None:
    """A SessionStart arriving after finalize must not re-create a buffer."""
    clock = FakeClock()
    asm, db = await _make(tmp_path, idle=10, clock=clock)
    cid = "conn-late-start"

    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=HEADER))
    await asm.finalize(cid)

    cast_path = tmp_path / "casts" / f"{cid}.cast"
    original_content = cast_path.read_text(encoding="utf-8")

    # Simulate a late SessionStart redelivery.
    await asm.handle(SessionStart(conn_id=cid, resource_address="late-host", username="u@x"))

    assert asm.active_count == 0, "late SessionStart must not re-create a buffer"

    clock.advance(30)
    await asm.finalize_idle()
    assert cast_path.read_text(encoding="utf-8") == original_content
    assert (await _row(db, cid))["status"] == "complete"
    await db.close()


# --- post-finalize scan hook (Task 6) --------------------------------------


@pytest.mark.asyncio
async def test_finalize_indexes_and_detects(tmp_path: Path) -> None:
    """Finalize writes the sidecar and records detection findings + risk summary."""
    asm, repo, casts, search, db = await _make_with_search(tmp_path)
    cid = "c1"
    await asm.handle(
        RecordingChunk(
            conn_id=cid,
            seq=0,
            asciicast=SCAN_CAST,
            username="u@x",
            ts="2026-06-01T00:00:00Z",
        )
    )
    await asm.finalize(cid)

    # Sidecar indexed with the ANSI-stripped plaintext.
    assert casts.has_sidecar(cid) is True
    assert "rm -rf /etc" in await casts.read_sidecar(cid)

    # Detection ran and stored the recursive-delete finding.
    findings = await search.list_findings(cid)
    assert any(f.rule_id == "recursive-delete" for f in findings)

    # Denormalized risk summary mirrored onto the session row.
    row = await repo.get(cid)
    assert row is not None
    assert row.finding_count >= 1
    assert row.max_severity is not None
    await db.close()


@pytest.mark.asyncio
async def test_refinalize_no_duplicate_findings(tmp_path: Path) -> None:
    """Re-running the scan replaces findings (delete-then-insert), no duplicates."""
    asm, repo, casts, search, db = await _make_with_search(tmp_path)
    cid = "c2"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=SCAN_CAST))
    await asm.finalize(cid)

    first = await search.list_findings(cid)
    assert len(first) >= 1

    # Drive the scan path again directly with the same content.
    await asm._run_scan(cid, SCAN_CAST, write_sidecar=True)

    second = await search.list_findings(cid)
    assert len(second) == len(first)
    await db.close()


@pytest.mark.asyncio
async def test_scan_failure_does_not_break_finalize(tmp_path: Path) -> None:
    """A scan failure is swallowed: the session still completes and keeps its .cast."""
    asm, repo, casts, search, db = await _make_with_search(tmp_path)
    cid = "c3"

    async def _boom(conn_id: str, findings: list) -> None:
        raise RuntimeError("scan exploded")

    # Inject a failing replace_findings on the wired search store.
    search.replace_findings = _boom  # type: ignore[method-assign]

    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=SCAN_CAST))
    await asm.finalize(cid)

    # Finalize completed despite the scan error.
    row = await repo.get(cid)
    assert row is not None
    assert row.status == "complete"
    assert (tmp_path / "casts" / f"{cid}.cast").exists()
    await db.close()


@pytest.mark.asyncio
async def test_no_search_means_no_scan(tmp_path: Path) -> None:
    """Without a search store, finalize behaves as before and writes no sidecar."""
    asm, db = await _make(tmp_path)  # built WITHOUT a search store
    cid = "c4"
    casts = asm._casts  # the assembler's own cast store
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=SCAN_CAST))
    await asm.finalize(cid)

    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert casts.has_sidecar(cid) is False
    await db.close()


# --- connection lifecycle: pending / recording / api / error (spec §6) -------

K8S_ADDR = "k8s.example.internal"
REQ_EXEC = "11111111-1111-4111-8111-111111111111"


@pytest.mark.asyncio
async def test_start_creates_pending_connection_only(tmp_path: Path) -> None:
    """An Authenticated connection writes a pending connection and no session row."""
    asm, db = await _make(tmp_path)
    cid = "conn-pending"
    await asm.handle(_start(cid))

    assert await _row(db, cid) is None
    assert await _count(db, "SELECT COUNT(*) FROM sessions") == 0
    assert asm.active_count == 0  # no in-memory buffer for a bare start
    conn = await _conn(db, cid)
    assert conn["state"] == "pending"
    assert conn["has_api"] == 0
    assert conn["resource_address"] == K8S_ADDR
    assert conn["username"] == "user@example.com"
    assert conn["user_id"] == "VXNlcjox"
    assert conn["started_at"] == "2026-10-01T10:00:00.100Z"
    await db.close()


@pytest.mark.asyncio
async def test_first_chunk_promotes_and_records_request_id(tmp_path: Path) -> None:
    """The first k8s chunk promotes the pending connection with the start line's
    identity and cluster, and its request_id lands on the session row (first wins)."""
    asm, db = await _make(tmp_path)
    cid = "conn-exec"
    await asm.handle(_start(cid))

    # k8s chunk lines carry request_id but no resource_address and no headers.
    await asm.handle(
        RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1, request_id=REQ_EXEC)
    )
    row = await _row(db, cid)
    assert row["status"] == "provisional"
    assert row["resource_address"] == K8S_ADDR
    assert row["username"] == "user@example.com"
    assert row["started_at"] == "2026-10-01T10:00:00.100Z"
    assert row["request_id"] == REQ_EXEC
    assert (await _conn(db, cid))["state"] == "recording"

    # A later chunk with a different request_id never overwrites the first.
    await asm.handle(
        RecordingChunk(
            conn_id=cid,
            seq=1,
            asciicast=CHUNK_2,
            request_id="22222222-2222-4222-8222-222222222222",
            is_final=True,
        )
    )
    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert row["request_id"] == REQ_EXEC
    await db.close()


@pytest.mark.asyncio
async def test_ssh_chunk_leaves_request_id_null(tmp_path: Path) -> None:
    """SSH recordings carry no request_id: the column stays NULL, behaviour unchanged."""
    asm, db = await _make(tmp_path)
    cid = "conn-ssh"
    await asm.handle(_start(cid, address="10.0.0.30"))
    await asm.handle(
        RecordingChunk(conn_id=cid, seq=0, asciicast=FULL_DOC, is_final=True)
    )
    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert row["resource_address"] == "10.0.0.30"
    assert row["request_id"] is None
    assert (tmp_path / "casts" / f"{cid}.cast").read_text(encoding="utf-8") == FULL_DOC
    await db.close()


@pytest.mark.asyncio
async def test_chunk_without_start_inserts_recording_connection(tmp_path: Path) -> None:
    """A chunk-first connection is marked recording, so a late start line never
    leaves it pending (and the backstop can never error a live recording)."""
    asm, db = await _make(tmp_path)
    cid = "conn-chunk-first"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))
    assert (await _conn(db, cid))["state"] == "recording"

    # The start line arrives late: identity/cluster land, state stays recording.
    await asm.handle(_start(cid))
    conn = await _conn(db, cid)
    assert conn["state"] == "recording"
    assert conn["resource_address"] == K8S_ADDR
    assert (await _row(db, cid))["resource_address"] == K8S_ADDR

    await _age_connection(db, cid)
    await asm.finalize_idle()
    assert (await _row(db, cid))["status"] == "provisional"  # still recording
    await db.close()


@pytest.mark.asyncio
async def test_api_only_connection_never_creates_session(tmp_path: Path) -> None:
    """An audit line marks the connection api; it never gets a row, even after the
    backstop window, and the request is stored with the start line's cluster."""
    asm, db = await _make(tmp_path)
    cid = "conn-api"
    await asm.handle(_start(cid))
    await asm.handle(_api(cid, "req-get-1"))

    assert await _row(db, cid) is None
    conn = await _conn(db, cid)
    assert conn["state"] == "api"
    assert conn["has_api"] == 1
    assert (
        await _count(db, "SELECT COUNT(*) FROM api_requests WHERE conn_id = ?", (cid,))
        == 1
    )
    cur = await db.execute(
        "SELECT resource_address, user_key FROM api_requests WHERE request_id = ?",
        ("req-get-1",),
    )
    req = await cur.fetchone()
    await cur.close()
    assert req["resource_address"] == K8S_ADDR
    assert req["user_key"] == "VXNlcjox"

    # The pending backstop ignores api connections: still no visible row.
    await _age_connection(db, cid)
    await asm.finalize_idle()
    assert await _row(db, cid) is None
    assert (await _conn(db, cid))["state"] == "api"
    await db.close()


@pytest.mark.asyncio
async def test_pending_backstop_creates_visible_error_row(tmp_path: Path) -> None:
    """A connection with neither chunks nor audits becomes a visible error row."""
    asm, db = await _make(tmp_path, max_idle=1800)
    cid = "conn-neither"
    await asm.handle(_start(cid, address="10.0.0.31"))

    # Not yet past the backstop: nothing happens.
    await asm.finalize_idle()
    assert await _row(db, cid) is None

    await _age_connection(db, cid)
    await asm.finalize_idle()
    row = await _row(db, cid)
    assert row is not None
    assert row["status"] == "error"
    assert row["resource_address"] == "10.0.0.31"
    assert row["username"] == "user@example.com"
    assert row["started_at"] == "2026-10-01T10:00:00.100Z"
    assert (await _conn(db, cid))["state"] == "error"

    # A second sweep is a no-op (already expired).
    await asm.finalize_idle()
    assert await _count(db, "SELECT COUNT(*) FROM sessions") == 1
    await db.close()


@pytest.mark.asyncio
async def test_pending_connection_survives_restart(tmp_path: Path) -> None:
    """Pending connections live in SQLite: a new Assembler over the same DB still
    sees and expires them."""
    asm, db = await _make(tmp_path)
    cid = "conn-restart"
    await asm.handle(_start(cid))

    # "Restart": a fresh assembler (empty in-memory state) over the same database.
    asm2 = Assembler(
        repo=SessionRepository(db),
        casts=CastStore(tmp_path / "casts"),
        idle_timeout_seconds=120,
        clock=lambda: 0.0,
        activity=ActivityStore(db),
    )
    await asm2.sweep_startup()
    assert await _row(db, cid) is None
    assert (await _conn(db, cid))["state"] == "pending"

    await _age_connection(db, cid)
    await asm2.finalize_idle()
    assert (await _row(db, cid))["status"] == "error"
    await db.close()


@pytest.mark.asyncio
async def test_late_audit_on_error_deletes_row_and_marks_api(tmp_path: Path) -> None:
    """A late audit (e.g. a long watch) on an expired connection removes the
    phantom start-only error row and marks the connection api."""
    asm, db = await _make(tmp_path)
    cid = "conn-watch"
    await asm.handle(_start(cid))
    await _age_connection(db, cid)
    await asm.finalize_idle()
    assert (await _row(db, cid))["status"] == "error"

    await asm.handle(_api(cid, "req-watch-1"))
    assert await _row(db, cid) is None
    conn = await _conn(db, cid)
    assert conn["state"] == "api"
    assert conn["has_api"] == 1
    await db.close()


@pytest.mark.asyncio
async def test_api_then_chunk_promotes_to_recording(tmp_path: Path) -> None:
    """An api connection that later records is promoted; has_api stays set."""
    asm, db = await _make(tmp_path)
    cid = "conn-api-rec"
    await asm.handle(_start(cid))
    await asm.handle(_api(cid, "req-pre-1"))
    assert (await _conn(db, cid))["state"] == "api"

    await asm.handle(
        RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1, request_id=REQ_EXEC)
    )
    conn = await _conn(db, cid)
    assert conn["state"] == "recording"
    assert conn["has_api"] == 1
    row = await _row(db, cid)
    assert row["status"] == "provisional"
    assert row["resource_address"] == K8S_ADDR
    assert row["request_id"] == REQ_EXEC
    await db.close()


@pytest.mark.asyncio
async def test_exec_audit_on_recording_connection_keeps_recording(tmp_path: Path) -> None:
    """The exec's status-101 audit line (same request_id, arriving at exec end)
    sets has_api but leaves the recording connection and its row intact."""
    asm, db = await _make(tmp_path)
    cid = "conn-exec-b"
    await asm.handle(_start(cid))
    await asm.handle(
        RecordingChunk(
            conn_id=cid, seq=0, asciicast=FULL_DOC, request_id=REQ_EXEC, is_final=True
        )
    )
    await asm.handle(
        _api(
            cid,
            REQ_EXEC,
            url="/api/v1/namespaces/default/pods/web-1/exec?container=nginx&stdin=true",
        )
    )
    conn = await _conn(db, cid)
    assert conn["state"] == "recording"
    assert conn["has_api"] == 1
    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert row["request_id"] == REQ_EXEC
    # The audit line is linked to the recording through request_id.
    links = await ActivityStore(db).recordings_for_requests([REQ_EXEC])
    assert links == {REQ_EXEC: cid}
    # The exec rule fired once on the request.
    assert (
        await _count(
            db,
            "SELECT COUNT(*) FROM api_findings "
            "WHERE request_id = ? AND rule_id = 'kube-exec'",
            (REQ_EXEC,),
        )
        == 1
    )
    await db.close()


@pytest.mark.asyncio
async def test_redelivered_audit_line_is_not_duplicated(tmp_path: Path) -> None:
    """At-least-once redelivery: the same request_id yields one row and one set of
    findings."""
    asm, db = await _make(tmp_path)
    cid = "conn-dedup"
    await asm.handle(_start(cid))
    delete = _api(
        cid, "req-del-1", method="DELETE", url="/api/v1/namespaces/default/pods/web-1"
    )
    await asm.handle(delete)
    await asm.handle(delete)  # redelivered
    await asm.handle(delete)  # and again

    assert await _count(db, "SELECT COUNT(*) FROM api_requests") == 1
    assert (
        await _count(
            db, "SELECT COUNT(*) FROM api_findings WHERE request_id = ?", ("req-del-1",)
        )
        == 1
    )
    assert (
        await _count(db, "SELECT COUNT(*) FROM api_findings WHERE rule_id = 'kube-delete'")
        == 1
    )
    assert (await _conn(db, cid))["state"] == "api"
    await db.close()


@pytest.mark.asyncio
async def test_audit_before_start_is_backfilled(tmp_path: Path) -> None:
    """An audit line arriving before its start line creates a minimal api
    connection; the start line then backfills the request's cluster."""
    asm, db = await _make(tmp_path)
    cid = "conn-audit-first"
    await asm.handle(_api(cid, "req-early-1"))
    conn = await _conn(db, cid)
    assert conn["state"] == "api"
    assert conn["resource_address"] is None

    await asm.handle(_start(cid))
    conn = await _conn(db, cid)
    assert conn["state"] == "api"  # the start line never demotes it to pending
    assert conn["resource_address"] == K8S_ADDR
    cur = await db.execute(
        "SELECT resource_address FROM api_requests WHERE request_id = ?",
        ("req-early-1",),
    )
    req = await cur.fetchone()
    await cur.close()
    assert req["resource_address"] == K8S_ADDR
    assert await _row(db, cid) is None
    await db.close()


@pytest.mark.asyncio
async def test_detection_disabled_skips_api_findings(tmp_path: Path) -> None:
    """DETECTION_ENABLED=false stores the request but runs no API rules."""
    asm, repo, casts, search, db = await _make_with_search(
        tmp_path, detection_enabled=False
    )
    cid = "conn-nodetect"
    await asm.handle(_start(cid))
    await asm.handle(
        _api(cid, "req-nd-1", method="DELETE", url="/api/v1/namespaces/default/pods/x")
    )
    assert await _count(db, "SELECT COUNT(*) FROM api_requests") == 1
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    await db.close()


@pytest.mark.asyncio
async def test_api_findings_survive_failure_between_request_and_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Security P1: request + findings are one transaction. A failure after the
    request insert rolls the request back too, so the redelivered line is not a
    dedup hit and stores the request *with* its findings."""
    asm, db = await _make(tmp_path)
    cid = "conn-atomic"
    await asm.handle(_start(cid))
    delete = _api(cid, "req-atomic-1", method="DELETE", url="/api/v1/namespaces/default/pods/web-1")

    async def boom(request_id: str, findings) -> None:
        raise RuntimeError("simulated crash between the request and its findings")

    monkeypatch.setattr(asm._activity, "_insert_finding_rows", boom)
    with pytest.raises(RuntimeError):
        await asm.handle(delete)
    assert await _count(db, "SELECT COUNT(*) FROM api_requests") == 0
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    assert (await _conn(db, cid))["state"] == "pending"  # no state change either

    monkeypatch.undo()
    await asm.handle(delete)  # at-least-once redelivery
    assert await _count(db, "SELECT COUNT(*) FROM api_requests") == 1
    assert (
        await _count(
            db,
            "SELECT COUNT(*) FROM api_findings WHERE request_id = ? AND rule_id = 'kube-delete'",
            ("req-atomic-1",),
        )
        == 1
    )
    assert (await _conn(db, cid))["state"] == "api"

    await asm.handle(delete)  # a further redelivery still duplicates nothing
    assert await _count(db, "SELECT COUNT(*) FROM api_requests") == 1
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 1
    await db.close()


@pytest.mark.asyncio
async def test_api_detection_error_still_stores_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If detect_api raises, the request is still stored (without findings) and the
    connection still advances; the failure is logged by exception type only."""
    import gatorcast.pipeline.assembler as assembler_module

    def broken_detect(method: str, url: str):
        raise ValueError("rule engine failure")

    warnings: list[tuple[str, dict]] = []

    class _Log:
        def warning(self, event: str, **kw) -> None:
            warnings.append((event, kw))

        def __getattr__(self, name: str):
            return lambda *a, **k: None

    monkeypatch.setattr(assembler_module, "detect_api", broken_detect)
    monkeypatch.setattr(assembler_module, "log", _Log())
    asm, db = await _make(tmp_path)
    cid = "conn-detect-err"
    await asm.handle(_start(cid))
    await asm.handle(
        _api(cid, "req-de-1", method="DELETE", url="/api/v1/namespaces/default/pods/x")
    )

    assert await _count(db, "SELECT COUNT(*) FROM api_requests") == 1
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    assert (await _conn(db, cid))["state"] == "api"
    assert warnings == [
        ("assembler.api_detect_error", {"conn_id": cid, "error": "ValueError"})
    ]
    await db.close()


# --- Session 10 T11: a late chunk never replaces a sealed recording ------------
#
# The seal mode is persisted on the session row (``sealed_terminal``), so after a
# restart or a ``_sealed`` cache eviction the row decides: ignore (terminal or
# legacy NULL), reopen (reopenable), adopt (provisional with a file), or promote
# (no recording yet). Each scenario runs with encryption off and on.

SENTINEL = "GC_SENTINEL_LATE_CHUNK"
LATE_EVENT = f'[9.0,"o","{SENTINEL}"]'
LATE_CHUNK = HEADER + LATE_EVENT + "\n"


@pytest.fixture(params=[False, True], ids=["plaintext", "encrypted"])
def encrypted(request: pytest.FixtureRequest) -> bool:
    """Run a T11 scenario once without and once with ``.cast`` encryption."""
    return bool(request.param)


@pytest.fixture
def asm_log(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    """Swap the assembler's logger for one rendering JSON lines (all levels) to a buffer.

    structlog caches loggers on first use, so its test capture is unreliable across
    a suite; replacing the module logger is how ``test_secret_hygiene`` does it.
    """
    buffer = io.StringIO()
    logger = structlog.wrap_logger(
        structlog.PrintLogger(file=buffer),
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
    )
    monkeypatch.setattr(assembler_module, "log", logger)
    return buffer


def _log_events(buffer: io.StringIO) -> list[dict]:
    """Parse the captured assembler log lines."""
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


def _assert_no_sentinel(buffer: io.StringIO) -> None:
    """The capture is live, and no chunk content reached any log line."""
    text = buffer.getvalue()
    assert text.strip(), "log capture recorded nothing (vacuous check)"
    assert SENTINEL not in text, "chunk content leaked into the logs"


async def _boot(
    tmp_path: Path,
    *,
    encrypted: bool,
    clock=None,
    max_idle: int = 3600,
) -> tuple[Assembler, aiosqlite.Connection, CastStore]:
    """(Re)start the service: same DB + casts dir, fresh Assembler, startup sweep.

    Calling this twice on one ``tmp_path`` (after closing the first DB) simulates a
    restart: every in-memory map, including ``_sealed``, starts empty.
    """
    casts_dir = tmp_path / "casts"
    db = await init_db(tmp_path / "gatorcast.db", casts_dir)
    casts = CastStore(casts_dir, cryptor=Cryptor(_key()) if encrypted else None)
    asm = Assembler(
        repo=SessionRepository(db),
        casts=casts,
        idle_timeout_seconds=120,
        session_max_idle_seconds=max_idle,
        clock=clock or (lambda: 0.0),
        activity=ActivityStore(db),
    )
    await asm.sweep_startup()
    return asm, db, casts


def _cast_bytes(tmp_path: Path, conn_id: str) -> bytes:
    """Raw on-disk bytes of a ``.cast`` (ciphertext when sealed under encryption)."""
    return (tmp_path / "casts" / f"{conn_id}.cast").read_bytes()


async def _seal_state(db: aiosqlite.Connection, conn_id: str) -> dict:
    """The row fields a late chunk must not change on a sealed session."""
    row = await _row(db, conn_id)
    assert row is not None
    return {
        k: row[k]
        for k in (
            "status",
            "size_bytes",
            "chunk_count",
            "ended_at",
            "cast_path",
            "sealed_terminal",
        )
    }


@pytest.mark.asyncio
async def test_t11_restart_terminal_seal_ignores_late_chunks(
    tmp_path: Path, encrypted: bool, asm_log: io.StringIO
) -> None:
    """Terminal seal → restart → redelivered and new-seq chunks are ignored."""
    cid = "conn-t11-terminal"
    asm, db, _ = await _boot(tmp_path, encrypted=encrypted)
    await asm.handle(_start(cid))
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=CHUNK_2, is_final=True))
    before = _cast_bytes(tmp_path, cid)
    state = await _seal_state(db, cid)
    assert state["status"] == "complete"
    assert state["sealed_terminal"] == 1
    await db.close()

    asm, db, casts = await _boot(tmp_path, encrypted=encrypted)  # restart
    # (i) a redelivered chunk with an existing seq (the final flush, redelivered)
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=LATE_CHUNK, is_final=True))
    # (ii) a chunk with a new seq
    await asm.handle(RecordingChunk(conn_id=cid, seq=2, asciicast=LATE_CHUNK))

    assert _cast_bytes(tmp_path, cid) == before, "sealed .cast must be byte-identical"
    assert await _seal_state(db, cid) == state, "sealed row must be unchanged"
    assert asm._ignored_finalized == 2
    assert asm.active_count == 0
    assert await casts.read_cast(cid) == FULL_DOC  # still decrypts to the original
    events = _log_events(asm_log)
    assert {
        "event": "assembler.ignore_sealed",
        "phase": "chunk",
        "source": "db",
        "level": "debug",
    } in events
    _assert_no_sentinel(asm_log)
    await db.close()


@pytest.mark.asyncio
async def test_t11_restart_reopenable_seal_reopens_and_appends(
    tmp_path: Path, encrypted: bool, asm_log: io.StringIO
) -> None:
    """Backstop seal → restart → a new chunk reopens it and appends after the original."""
    cid = "conn-t11-reopen"
    clock = FakeClock()
    asm, db, casts = await _boot(tmp_path, encrypted=encrypted, clock=clock, max_idle=1800)
    await asm.handle(_start(cid))
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=CHUNK_2))
    clock.advance(1801)
    await asm.finalize_idle()
    state = await _seal_state(db, cid)
    assert state["status"] == "complete"
    assert state["sealed_terminal"] == 0
    assert await casts.read_cast(cid) == FULL_DOC
    await db.close()

    asm, db, casts = await _boot(
        tmp_path, encrypted=encrypted, clock=FakeClock(), max_idle=1800
    )
    await asm.handle(RecordingChunk(conn_id=cid, seq=2, asciicast=LATE_CHUNK))

    row = await _row(db, cid)
    assert row["status"] == "provisional"
    assert row["sealed_terminal"] is None  # cleared by reopen
    in_progress = _cast_bytes(tmp_path, cid).decode("utf-8")  # plaintext while open
    assert _nonblank(in_progress) == _nonblank(FULL_DOC) + [LATE_EVENT]

    # A final flush re-seals it terminally (encrypted when encryption is on).
    await asm.handle(
        RecordingChunk(
            conn_id=cid, seq=3, asciicast=HEADER + '[10.0,"o","end"]\n', is_final=True
        )
    )
    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert row["sealed_terminal"] == 1
    sealed = _cast_bytes(tmp_path, cid)
    assert sealed.startswith(b'{"version":2') is (not encrypted)
    final = await casts.read_cast(cid)
    assert _nonblank(final) == _nonblank(FULL_DOC) + [LATE_EVENT, '[10.0,"o","end"]']
    reopens = [e for e in _log_events(asm_log) if e["event"] == "assembler.reopen"]
    assert reopens == [
        {"event": "assembler.reopen", "conn_id": cid, "source": "db", "level": "info"}
    ]
    _assert_no_sentinel(asm_log)
    await db.close()


@pytest.mark.asyncio
async def test_t11_eviction_without_restart_ignores_late_chunk(
    tmp_path: Path,
    encrypted: bool,
    asm_log: io.StringIO,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After ``_sealed`` is cleared at ``_FINALIZED_MAX``, the row still blocks a late chunk."""
    monkeypatch.setattr(assembler_module, "_FINALIZED_MAX", 2)
    asm, db, casts = await _boot(tmp_path, encrypted=encrypted)
    cids = ["conn-evict-a", "conn-evict-b", "conn-evict-c"]
    for cid in cids:
        await asm.handle(
            RecordingChunk(conn_id=cid, seq=0, asciicast=FULL_DOC, is_final=True)
        )
    assert cids[0] not in asm._sealed, "the first seal must have been evicted"
    before = _cast_bytes(tmp_path, cids[0])
    state = await _seal_state(db, cids[0])

    await asm.handle(RecordingChunk(conn_id=cids[0], seq=1, asciicast=LATE_CHUNK))

    assert _cast_bytes(tmp_path, cids[0]) == before
    assert await _seal_state(db, cids[0]) == state
    assert asm._ignored_finalized == 1
    assert asm.active_count == 0
    assert await casts.read_cast(cids[0]) == FULL_DOC
    _assert_no_sentinel(asm_log)
    await db.close()


@pytest.mark.asyncio
async def test_t11_failed_connection_still_recovers_after_restart(
    tmp_path: Path, encrypted: bool, asm_log: io.StringIO
) -> None:
    """A pending connection expired to ``error`` (no cast) recovers on a later chunk."""
    cid = "conn-t11-failed"
    asm, db, _ = await _boot(tmp_path, encrypted=encrypted)
    await asm.handle(_start(cid))
    await _age_connection(db, cid)
    await asm.finalize_idle()
    row = await _row(db, cid)
    assert row["status"] == "error"
    assert row["cast_path"] is None
    await db.close()

    asm, db, _ = await _boot(tmp_path, encrypted=encrypted)
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=LATE_CHUNK))

    row = await _row(db, cid)
    assert row["status"] == "provisional"
    assert row["resource_address"] == "k8s.example.internal"  # start-line identity kept
    written = _cast_bytes(tmp_path, cid).decode("utf-8")
    assert _nonblank(written) == _nonblank(LATE_CHUNK)
    assert (await _conn(db, cid))["state"] == "recording"
    assert "assembler.promote" in [e["event"] for e in _log_events(asm_log)]
    _assert_no_sentinel(asm_log)
    await db.close()


@pytest.mark.asyncio
async def test_t11_legacy_null_flag_is_treated_as_terminal(
    tmp_path: Path, encrypted: bool, asm_log: io.StringIO
) -> None:
    """A sealed row from before the column existed (NULL) ignores a late chunk."""
    cid = "conn-t11-legacy"
    clock = FakeClock()
    asm, db, _ = await _boot(tmp_path, encrypted=encrypted, clock=clock, max_idle=1800)
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=FULL_DOC))
    clock.advance(1801)
    await asm.finalize_idle()  # sealed reopenably ...
    # ... but as if written before T11, when no seal mode was recorded.
    await db.execute(
        "UPDATE sessions SET sealed_terminal = NULL WHERE conn_id = ?", (cid,)
    )
    await db.commit()
    before = _cast_bytes(tmp_path, cid)
    state = await _seal_state(db, cid)
    await db.close()

    asm, db, _ = await _boot(tmp_path, encrypted=encrypted)
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=LATE_CHUNK))

    assert _cast_bytes(tmp_path, cid) == before
    assert await _seal_state(db, cid) == state
    assert asm._ignored_finalized == 1
    assert asm._sealed[cid] is False  # re-cached as terminal
    _assert_no_sentinel(asm_log)
    await db.close()


@pytest.mark.asyncio
async def test_t11_sealed_error_row_reopens(
    tmp_path: Path, encrypted: bool, asm_log: io.StringIO
) -> None:
    """A backstop-sealed ``error`` row (no header, cast set) reopens on a late chunk."""
    cid = "conn-t11-error"
    clock = FakeClock()
    asm, db, _ = await _boot(tmp_path, encrypted=encrypted, clock=clock, max_idle=1800)
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast='[0.0,"o","x"]\n'))
    clock.advance(1801)
    await asm.finalize_idle()
    row = await _row(db, cid)
    assert row["status"] == "error"
    assert row["cast_path"] is not None
    assert row["sealed_terminal"] == 0
    await db.close()

    asm, db, casts = await _boot(
        tmp_path, encrypted=encrypted, clock=FakeClock(), max_idle=1800
    )
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=LATE_CHUNK))
    row = await _row(db, cid)
    assert row["status"] == "provisional", "repo.reopen must accept a sealed error row"
    assert row["sealed_terminal"] is None
    assert row["chunk_count"] == 1  # update_progress no longer skips the row

    # The late chunk carried a header, so the re-seal is a valid recording.
    await asm.handle(RecordingChunk(conn_id=cid, seq=2, asciicast=HEADER, is_final=True))
    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert row["sealed_terminal"] == 1
    assert parse_asciicast(await casts.read_cast(cid)).event_count == 2
    _assert_no_sentinel(asm_log)
    await db.close()


@pytest.mark.asyncio
async def test_t11_orphan_cast_without_row_is_never_overwritten(
    tmp_path: Path, encrypted: bool, asm_log: io.StringIO
) -> None:
    """No session row but a non-empty ``.cast`` on disk: the chunk is ignored."""
    cid = "conn-t11-orphan"
    asm, db, _ = await _boot(tmp_path, encrypted=encrypted)
    orphan = tmp_path / "casts" / f"{cid}.cast"
    orphan.write_bytes(b"orphaned recording bytes\n")

    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=LATE_CHUNK))

    assert orphan.read_bytes() == b"orphaned recording bytes\n"
    assert await _row(db, cid) is None
    assert asm.active_count == 0
    events = _log_events(asm_log)
    assert {
        "event": "assembler.orphan_cast_skip",
        "conn_id": cid,
        "level": "warning",
    } in events
    _assert_no_sentinel(asm_log)
    await db.close()


@pytest.mark.asyncio
async def test_t11_sealed_row_with_missing_cast_writes_nothing(
    tmp_path: Path, encrypted: bool, asm_log: io.StringIO
) -> None:
    """A sealed row whose ``.cast`` is gone: the chunk is ignored and no file appears."""
    cid = "conn-t11-missing"
    clock = FakeClock()
    asm, db, _ = await _boot(tmp_path, encrypted=encrypted, clock=clock, max_idle=1800)
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=FULL_DOC))
    clock.advance(1801)
    await asm.finalize_idle()  # reopenable: the most permissive seal mode
    state = await _seal_state(db, cid)
    (tmp_path / "casts" / f"{cid}.cast").unlink()
    await db.close()

    asm, db, _ = await _boot(tmp_path, encrypted=encrypted)
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=LATE_CHUNK))

    assert not (tmp_path / "casts" / f"{cid}.cast").exists()
    assert await _seal_state(db, cid) == state
    events = _log_events(asm_log)
    assert {
        "event": "assembler.sealed_cast_missing",
        "conn_id": cid,
        "level": "warning",
    } in events
    _assert_no_sentinel(asm_log)
    await db.close()


@pytest.mark.asyncio
async def test_t11_provisional_row_with_cast_is_adopted_on_buffer_miss(
    tmp_path: Path, encrypted: bool, asm_log: io.StringIO
) -> None:
    """A provisional row with a plaintext ``.cast`` but no buffer is adopted, not replaced."""
    cid = "conn-t11-adopt"
    asm, db, _ = await _boot(tmp_path, encrypted=encrypted)
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1))
    asm._buffers.clear()  # lose the buffer without sealing

    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=LATE_CHUNK))

    text = _cast_bytes(tmp_path, cid).decode("utf-8")
    assert _nonblank(text) == _nonblank(CHUNK_1) + [LATE_EVENT]
    assert (await _row(db, cid))["status"] == "provisional"
    assert "assembler.adopt" in [e["event"] for e in _log_events(asm_log)]
    _assert_no_sentinel(asm_log)
    await db.close()


@pytest.mark.asyncio
async def test_t11_seal_persists_mode(tmp_path: Path) -> None:
    """Every seal writes ``sealed_terminal``: 1 on the final flush, 0 on the backstop."""
    clock = FakeClock()
    asm, db = await _make(tmp_path, clock=clock, max_idle=1800)
    await asm.handle(
        RecordingChunk(conn_id="term", seq=0, asciicast=FULL_DOC, is_final=True)
    )
    await asm.handle(RecordingChunk(conn_id="idle", seq=0, asciicast=FULL_DOC))
    clock.advance(1801)
    await asm.finalize_idle()
    assert (await _row(db, "term"))["sealed_terminal"] == 1
    assert (await _row(db, "idle"))["sealed_terminal"] == 0
    await db.close()
