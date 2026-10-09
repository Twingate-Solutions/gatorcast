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
        url_web=url,
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

    def broken_detect(method: str, url: str, rules=None, *, resource_type=None):
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


# --- Session 11 (web apps): WEBAPP_SPEC 4.4 policy table, backfill, redelivery, empty lifecycle ---
#
# gwops/TLS snapshot behaviour is covered by T12; these tests only compare connection rows
# wholesale where "unchanged state" is required.

from tests.samples import (  # noqa: E402
    WEBAPP_CONNS,
    WEBAPP_EMPTY_CONN_KEYS,
    WEBAPP_GWOPS_SENTINELS,
    WEBAPP_NEVER_STORED_SENTINELS,
    WEBAPP_SPOOF_SENTINELS,
    webapp_batch,
    webapp_lines,
    webapp_lines_for,
    webapp_redelivery,
)
from gatorcast.pipeline.classify import classify  # noqa: E402

WEB_ADDR = "wiki.corp.internal"
WEB_QUERY_SENTINEL = "SENTINEL_QUERY_UNIT_0123456789abcdef"
WEB_USER = "PLACEHOLDER-KEY-ID-1"


def _typed_start(conn_id: str, resource_type: str | None, address: str = WEB_ADDR) -> SessionStart:
    """A start line with an explicit normalized ``resource_type``."""
    return SessionStart(
        conn_id=conn_id,
        resource_address=address,
        username="user@example.com",
        user_id="VXNlcjox",
        ts="2026-10-01T10:00:00.100Z",
        resource_type=resource_type,
    )


def _web_api(
    conn_id: str,
    request_id: str,
    *,
    method: str = "GET",
    path: str = "/report",
    raw_query: str = f"month={WEB_QUERY_SENTINEL}",
    masked_query: str = "month=SE…ef(36)",
    at: str = "2026-10-01T10:00:01.200Z",
    k8s_query: str = "",
) -> ApiRequest:
    """An ApiRequest as classify would emit it for a web-looking URL.

    ``url`` is the Kubernetes form (query keys outside the allowlist dropped; ``k8s_query`` is
    what survived, if anything), ``url_web`` the web form (query value masked). The raw sentinel
    never appears in either.
    """
    return ApiRequest(
        conn_id=conn_id,
        request_id=request_id,
        requested_at=at,
        user_id="VXNlcjox",
        username="user@example.com",
        method=method,
        url=f"{path}?{k8s_query}" if k8s_query else path,
        url_web=f"{path}?{masked_query}" if masked_query else path,
        status_code=200,
        kubectl_command="kubectl get",
        kubectl_session="5e55e55e-0000-4000-8000-000000000001",
        user_agent="Mozilla/5.0 (test)",
    )


async def _feed(asm: Assembler, lines: list[str]) -> None:
    """Classify NDJSON fixture lines and hand each resulting event to the assembler, in order."""
    for line in lines:
        event = classify(json.loads(line))
        if event is not None:
            await asm.handle(event)


async def _req_rows(db: aiosqlite.Connection, where: str = "1=1", params: tuple = ()) -> list[aiosqlite.Row]:
    cur = await db.execute(f"SELECT * FROM api_requests WHERE {where} ORDER BY requested_at, request_id", params)  # noqa: S608
    rows = await cur.fetchall()
    await cur.close()
    return list(rows)


async def _kinds(db: aiosqlite.Connection, conn_id: str) -> dict[str, str]:
    """request_id -> api_kind for one connection."""
    return {r["request_id"]: r["api_kind"] for r in await _req_rows(db, "conn_id = ?", (conn_id,))}


async def _finding_rules(db: aiosqlite.Connection, request_id: str) -> list[str]:
    cur = await db.execute("SELECT rule_id FROM api_findings WHERE request_id = ? ORDER BY id", (request_id,))
    rules = [r[0] for r in await cur.fetchall()]
    await cur.close()
    return rules


async def _db_text(db: aiosqlite.Connection) -> str:
    """Every value of every table as one string (for sentinel greps)."""
    cur = await db.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
    tables = [r[0] for r in await cur.fetchall()]
    await cur.close()
    parts: list[str] = []
    for table in tables:
        cur = await db.execute(f"SELECT * FROM {table}")  # noqa: S608 - names come from sqlite_master
        parts.extend(" ".join(str(v) for v in row) for row in await cur.fetchall())
        await cur.close()
    return "\n".join(parts)


async def _conn_state(db: aiosqlite.Connection, conn_id: str) -> dict:
    """A connection row as a dict without the bump-on-every-touch ``last_seen_at``."""
    row = dict(await _conn(db, conn_id))
    row.pop("last_seen_at")
    return row


# --- policy table, one test per row ---


@pytest.mark.asyncio
async def test_policy_kubernetes_connection_stores_kubectl_form_and_runs_rules(tmp_path: Path) -> None:
    """Row 1: KUBERNETES -> kubectl, Kubernetes URL, three headers, rules, TLS NULL."""
    asm, db = await _make(tmp_path)
    cid = "pol-k8s"
    await asm.handle(_typed_start(cid, "KUBERNETES", K8S_ADDR))
    await asm.handle(
        _web_api(cid, "r1", method="DELETE", path="/api/v1/namespaces/default/pods/x",
                 raw_query="x=1", masked_query="x=…(1)")
    )
    row = (await _req_rows(db))[0]
    assert row["api_kind"] == "kubectl"
    assert row["url"] == "/api/v1/namespaces/default/pods/x"  # Kubernetes form, not url_web
    assert row["kubectl_command"] == "kubectl get"
    assert row["kubectl_session"] == "5e55e55e-0000-4000-8000-000000000001"
    assert row["user_agent"] == "Mozilla/5.0 (test)"
    assert row["downstream_tls"] is None and row["upstream_tls"] is None
    assert row["resource_address"] == K8S_ADDR
    assert await _finding_rules(db, "r1") == ["kube-delete"]
    assert (await _conn(db, cid))["state"] == "api"
    await db.close()


@pytest.mark.asyncio
async def test_policy_processed_start_without_resource_type_is_kubectl(tmp_path: Path) -> None:
    """Row 2: a start line that was processed (started_at set) but carries no type stays kubectl."""
    asm, db = await _make(tmp_path)
    cid = "pol-untyped"
    await asm.handle(_typed_start(cid, None, K8S_ADDR))
    await asm.handle(_api(cid, "r1", method="DELETE", url="/api/v1/namespaces/default/pods/x"))
    row = (await _req_rows(db))[0]
    assert row["api_kind"] == "kubectl"
    assert row["kubectl_command"] == "kubectl get"
    assert await _finding_rules(db, "r1") == ["kube-delete"]  # None is treated as Kubernetes
    await db.close()


@pytest.mark.asyncio
async def test_policy_web_app_connection_stores_web_form_without_rules_or_kubectl_headers(
    tmp_path: Path,
) -> None:
    """Row 3: WEB_APP -> web, url_web, User-Agent only, no findings, even for kube-looking requests."""
    asm, db = await _make(tmp_path)
    cid = "pol-web"
    await asm.handle(_typed_start(cid, "WEB_APP"))
    await asm.handle(_web_api(cid, "r1", method="DELETE", path="/api/v1/namespaces/default/pods/x"))
    row = (await _req_rows(db))[0]
    assert row["api_kind"] == "web"
    assert row["url"] == "/api/v1/namespaces/default/pods/x?month=SE…ef(36)"
    assert row["kubectl_command"] is None and row["kubectl_session"] is None
    assert row["user_agent"] == "Mozilla/5.0 (test)"
    assert row["resource_address"] == WEB_ADDR
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    conn = await _conn(db, cid)
    assert (conn["state"], conn["has_api"]) == ("api", 1)
    assert await _row(db, cid) is None  # a web connection never gets a sessions row
    await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("resource_type", ["SSH", "DATABASE"])
async def test_policy_any_other_non_null_type_is_stored_as_web(tmp_path: Path, resource_type: str) -> None:
    """Row 3 covers every non-null type that is not KUBERNETES."""
    asm, db = await _make(tmp_path)
    cid = "pol-other"
    await asm.handle(_typed_start(cid, resource_type))
    await asm.handle(_web_api(cid, "r1", method="DELETE", path="/items/42"))
    row = (await _req_rows(db))[0]
    assert row["api_kind"] == "web"
    assert row["kubectl_command"] is None
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    await db.close()


@pytest.mark.asyncio
async def test_policy_request_with_no_connection_row_fails_closed(tmp_path: Path) -> None:
    """Row 4 (none): provisional kubectl, Kubernetes URL form with masked values, three headers, rules.

    The stored URL is ``store_provisional_url(event.url)``: the Kubernetes form (``url_web`` is not
    used) with the web value masking on what survived the key allowlist.
    """
    asm, db = await _make(tmp_path)
    cid = "pol-none"
    await asm.handle(
        _web_api(cid, "r1", method="DELETE", path="/api/v1/namespaces/default/pods/x", k8s_query="limit=500")
    )
    row = (await _req_rows(db))[0]
    assert row["api_kind"] == "kubectl"
    assert row["url"] == "/api/v1/namespaces/default/pods/x?limit=…(3)"  # allowlisted key, masked value
    assert "month=" not in row["url"]  # the web-form query (url_web) is not used
    assert WEB_QUERY_SENTINEL not in row["url"]
    assert row["kubectl_command"] == "kubectl get"
    assert row["kubectl_session"] == "5e55e55e-0000-4000-8000-000000000001"
    assert row["resource_address"] is None
    assert row["downstream_tls"] is None and row["upstream_tls"] is None
    assert await _finding_rules(db, "r1") == ["kube-delete"]
    conn = await _conn(db, cid)
    assert (conn["state"], conn["has_api"]) == ("api", 1)
    assert conn["started_at"] is None and conn["resource_type"] is None  # the minimal row
    await db.close()


@pytest.mark.asyncio
async def test_policy_every_request_before_the_start_line_fails_closed_not_just_the_first(
    tmp_path: Path,
) -> None:
    """Row 4 (minimal row): the second and later early requests meet the minimal row set_state
    inserted for the first, and are stored under the same fail-closed policy."""
    asm, db = await _make(tmp_path)
    cid = "pol-multi"
    for i in range(4):
        await asm.handle(
            _web_api(cid, f"r{i}", path=f"/page/{i}", at=f"2026-10-01T10:00:0{i}.000Z")
        )
    rows = await _req_rows(db)
    assert [r["api_kind"] for r in rows] == ["kubectl"] * 4
    for i, row in enumerate(rows):
        assert row["url"] == f"/page/{i}"  # Kubernetes form: the non-allowlisted query is dropped
        assert row["kubectl_command"] == "kubectl get"  # provisional rows keep the kubectl headers
    assert WEB_QUERY_SENTINEL not in await _db_text(db)
    await db.close()


@pytest.mark.asyncio
async def test_policy_second_early_request_still_runs_rules_on_the_event_path(tmp_path: Path) -> None:
    """The fail-closed branch keeps the Kubernetes rules for the minimal row too."""
    asm, db = await _make(tmp_path)
    cid = "pol-multi-rules"
    await asm.handle(_web_api(cid, "r1", path="/api/v1/namespaces"))
    await asm.handle(_web_api(cid, "r2", method="DELETE", path="/api/v1/namespaces/default/pods/x"))
    assert await _finding_rules(db, "r1") == []
    assert await _finding_rules(db, "r2") == ["kube-delete"]
    await db.close()


@pytest.mark.asyncio
async def test_early_requests_then_web_start_convert_all_of_them_and_remove_findings(
    tmp_path: Path,
) -> None:
    """A later WEB_APP start line converts every early request to web, drops their kube-api
    findings and clears the kubectl headers; later requests are web from the start.

    The provisional URL form is final: the early rows keep it (no query), while a request stored
    after the start line gets the web form with its masked query.
    """
    asm, db = await _make(tmp_path)
    cid = "pol-convert"
    await asm.handle(_web_api(cid, "r1", method="DELETE", path="/items/42", at="2026-10-01T10:00:01.000Z"))
    await asm.handle(_web_api(cid, "r2", method="DELETE", path="/items/43", at="2026-10-01T10:00:02.000Z"))
    await asm.handle(_web_api(cid, "r3", path="/home", at="2026-10-01T10:00:03.000Z"))
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 2  # provisional kube-delete x2
    assert set((await _kinds(db, cid)).values()) == {"kubectl"}

    await asm.handle(_typed_start(cid, "WEB_APP"))
    await asm.handle(_web_api(cid, "r4", path="/later", at="2026-10-01T10:00:04.000Z"))

    assert await _kinds(db, cid) == {"r1": "web", "r2": "web", "r3": "web", "r4": "web"}
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    urls = {r["request_id"]: r["url"] for r in await _req_rows(db)}
    assert urls == {
        "r1": "/items/42",  # provisional form is final: not re-derived from url_web
        "r2": "/items/43",
        "r3": "/home",
        "r4": "/later?month=SE…ef(36)",  # after the start line: the web form
    }
    for row in await _req_rows(db):
        assert row["kubectl_command"] is None and row["kubectl_session"] is None
        assert row["resource_address"] == WEB_ADDR
    assert WEB_QUERY_SENTINEL not in await _db_text(db)
    assert await _row(db, cid) is None
    await db.close()


@pytest.mark.asyncio
async def test_early_requests_then_kubernetes_start_stay_kubectl_with_masked_query(tmp_path: Path) -> None:
    """A KUBERNETES start line after early requests leaves them kubectl, findings kept; their
    URLs keep the provisional form (allowlisted keys, masked values): the recorded fidelity loss."""
    asm, db = await _make(tmp_path)
    cid = "pol-late-k8s"
    await asm.handle(
        _web_api(cid, "r1", method="DELETE", path="/api/v1/namespaces/default/pods/x", k8s_query="limit=500")
    )
    await asm.handle(_web_api(cid, "r2", path="/api/v1/namespaces"))
    await asm.handle(_typed_start(cid, "KUBERNETES", K8S_ADDR))
    assert await _kinds(db, cid) == {"r1": "kubectl", "r2": "kubectl"}
    assert await _finding_rules(db, "r1") == ["kube-delete"]
    urls = {r["request_id"]: r["url"] for r in await _req_rows(db)}
    assert urls == {"r1": "/api/v1/namespaces/default/pods/x?limit=…(3)", "r2": "/api/v1/namespaces"}
    for row in await _req_rows(db):
        assert "month=" not in row["url"]
        assert row["kubectl_command"] == "kubectl get"
        assert row["resource_address"] == K8S_ADDR
    await db.close()


@pytest.mark.asyncio
async def test_lost_start_line_leaves_a_provisional_kubectl_row_with_the_kubernetes_form_url(
    tmp_path: Path,
) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for("no_start"))
    row = (await _req_rows(db))[0]
    assert row["api_kind"] == "kubectl"
    assert row["url"] == "/orphan"  # ``q`` is not on the Kubernetes allowlist: dropped, not masked
    assert "SENTINEL_QUERY_ORPHAN_1b15bb3e" not in row["url"]
    assert "SENTINEL_QUERY_ORPHAN_1b15bb3e" not in await _db_text(db)
    await db.close()


@pytest.mark.asyncio
async def test_fixture_late_web_start_converts_both_early_requests(tmp_path: Path) -> None:
    """Fixture late_start_web: GET and DELETE arrive before the WEB_APP start line."""
    asm, db = await _make(tmp_path)
    lines = webapp_lines_for("late_start_web")
    assert json.loads(lines[-1])["message"] == "Authenticated connection"  # the start line is last
    await _feed(asm, lines[:-1])
    assert set((await _kinds(db, "c0ffee00-0000-4000-8000-000000000077")).values()) == {"kubectl"}
    assert await _finding_rules(db, "5eed0000-0000-4000-8000-000000000128") == ["kube-delete"]
    assert "SENTINEL_QUERY_LATEWEB_9108c263" not in await _db_text(db)  # masked before the start line

    await _feed(asm, lines[-1:])
    assert set((await _kinds(db, "c0ffee00-0000-4000-8000-000000000077")).values()) == {"web"}
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    assert "SENTINEL_QUERY_LATEWEB_9108c263" not in await _db_text(db)
    await db.close()


@pytest.mark.asyncio
async def test_fixture_late_kubernetes_start_keeps_the_request_kubectl(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for("late_start_k8s"))
    kinds = await _kinds(db, "c0ffee00-0000-4000-8000-000000000078")
    assert set(kinds.values()) == {"kubectl"}
    text = await _db_text(db)
    assert "SENTINEL_QUERY_LATEK8S_16f36460" not in text
    await db.close()


@pytest.mark.asyncio
async def test_fixture_kubernetes_connection_keeps_kubectl_policy_and_findings(tmp_path: Path) -> None:
    """Uppercase KUBERNETES (as the real gateway emits): kubectl rows, rules, non-allowlisted keys dropped."""
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for("k8s_upper"))
    cid = "c0ffee00-0000-4000-8000-000000000011"
    assert set((await _kinds(db, cid)).values()) == {"kubectl"}
    assert await _finding_rules(db, "5eed0000-0000-4000-8000-000000000062") == ["kube-delete"]
    assert "kube-secrets" in await _finding_rules(db, "5eed0000-0000-4000-8000-000000000063")
    assert "SENTINEL_QUERY_K8SDROP_216629bb" not in await _db_text(db)
    assert (await _conn(db, cid))["resource_type"] == "KUBERNETES"
    await db.close()


@pytest.mark.asyncio
async def test_fixture_web_connection_with_kubernetes_look_alike_requests_gets_no_findings(
    tmp_path: Path,
) -> None:
    """Nothing in web_rule_lookalikes (DELETE, /secrets, eviction, node PATCH, exec, proxy exec)
    fires a Kubernetes rule once the connection is a WEB_APP."""
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for("web_rule_lookalikes"))
    kinds = await _kinds(db, "c0ffee00-0000-4000-8000-000000000004")
    assert len(kinds) == 10 and set(kinds.values()) == {"web"}
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    assert "SENTINEL_QUERY_EXECCMD_4e5706eb" not in await _db_text(db)
    await db.close()


@pytest.mark.asyncio
async def test_detection_disabled_is_irrelevant_for_web_rows_and_still_stores_them(tmp_path: Path) -> None:
    asm, repo, casts, search, db = await _make_with_search(tmp_path, detection_enabled=False)
    await asm.handle(_typed_start("web", "WEB_APP"))
    await asm.handle(_web_api("web", "r1", method="DELETE", path="/items/42"))
    assert await _kinds(db, "web") == {"r1": "web"}
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    await db.close()


# --- identity ---


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["cap_spoofed_identity", "spoof_variants"])
async def test_spoofed_identity_headers_never_change_the_stored_identity(tmp_path: Path, key: str) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for(key))
    rows = await _req_rows(db)
    assert rows, key
    for row in rows:
        assert row["username"] == WEB_USER
        assert row["user_id"] == WEB_USER
        assert row["user_key"] == WEB_USER
    conn = await _conn(db, WEBAPP_CONNS[key].conn_id)
    assert conn["username"] == WEB_USER
    text = await _db_text(db)
    for sentinel in WEBAPP_SPOOF_SENTINELS:
        assert sentinel not in text
    await db.close()


# --- redelivery (at-least-once) ---


@pytest.mark.asyncio
async def test_redelivered_web_batch_leaves_one_row_per_request_and_unchanged_state(tmp_path: Path) -> None:
    """A byte-identical replay of start + requests changes no row, no finding and no connection state."""
    asm, db = await _make(tmp_path)
    redelivery = webapp_redelivery()
    cid = WEBAPP_CONNS["redeliver"].conn_id
    await _feed(asm, redelivery.originals)
    before_conn = await _conn_state(db, cid)
    before_rows = [tuple(r) for r in await _req_rows(db)]
    assert len(before_rows) == 2 and before_conn["state"] == "api"

    for _ in range(2):
        await _feed(asm, redelivery.replay)

    assert [tuple(r) for r in await _req_rows(db)] == before_rows
    assert await _conn_state(db, cid) == before_conn
    assert await _count(db, "SELECT COUNT(*) FROM api_requests WHERE conn_id = ?", (cid,)) == 2
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    assert await _row(db, cid) is None
    await db.close()


@pytest.mark.asyncio
async def test_repeated_start_lines_with_different_or_no_objects_leave_the_connection_unchanged(
    tmp_path: Path,
) -> None:
    """A later start line for the same conn_id (a different gwops object, then none) changes no
    connection column other than last_seen_at, and converts nothing again."""
    asm, db = await _make(tmp_path)
    redelivery = webapp_redelivery()
    cid = WEBAPP_CONNS["redeliver"].conn_id
    await _feed(asm, redelivery.originals)
    before_conn = await _conn_state(db, cid)
    before_rows = [tuple(r) for r in await _req_rows(db)]

    await _feed(asm, [redelivery.conflicting_start])
    assert await _conn_state(db, cid) == before_conn
    await _feed(asm, [redelivery.no_object_start])
    assert await _conn_state(db, cid) == before_conn
    assert [tuple(r) for r in await _req_rows(db)] == before_rows
    await db.close()


@pytest.mark.asyncio
async def test_repeated_start_with_an_object_does_not_change_a_connection_first_seen_without_one(
    tmp_path: Path,
) -> None:
    asm, db = await _make(tmp_path)
    first_start, request, repeated_start = webapp_redelivery().noobj_then_obj
    cid = WEBAPP_CONNS["redeliver_noobj_then_obj"].conn_id
    await _feed(asm, [first_start, request])
    before_conn = await _conn_state(db, cid)
    before_rows = [tuple(r) for r in await _req_rows(db)]

    await _feed(asm, [repeated_start])

    assert await _conn_state(db, cid) == before_conn
    assert [tuple(r) for r in await _req_rows(db)] == before_rows
    await db.close()


@pytest.mark.asyncio
async def test_redelivered_kubernetes_batch_duplicates_neither_requests_nor_findings(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    lines = webapp_lines_for("k8s_upper")
    await _feed(asm, lines)
    requests = await _count(db, "SELECT COUNT(*) FROM api_requests")
    findings = await _count(db, "SELECT COUNT(*) FROM api_findings")
    cid = WEBAPP_CONNS["k8s_upper"].conn_id
    before_conn = await _conn_state(db, cid)
    assert requests == 4 and findings >= 2

    await _feed(asm, lines)
    await _feed(asm, lines)

    assert await _count(db, "SELECT COUNT(*) FROM api_requests") == requests
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == findings
    assert await _conn_state(db, cid) == before_conn
    await db.close()


@pytest.mark.asyncio
async def test_redelivered_early_requests_after_conversion_do_not_resurrect_findings(tmp_path: Path) -> None:
    """Early requests, the WEB_APP start line, then the early requests redelivered: still web,
    still no findings, still one row each."""
    asm, db = await _make(tmp_path)
    early = [_web_api("rd", "r1", method="DELETE", path="/items/1"), _web_api("rd", "r2", path="/home")]
    for event in early:
        await asm.handle(event)
    await asm.handle(_typed_start("rd", "WEB_APP"))
    assert await _kinds(db, "rd") == {"r1": "web", "r2": "web"}

    for event in early:
        await asm.handle(event)

    assert await _kinds(db, "rd") == {"r1": "web", "r2": "web"}
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    await db.close()


# --- lifecycle: empty WEB_APP connections ---


@pytest.mark.asyncio
@pytest.mark.parametrize("key", WEBAPP_EMPTY_CONN_KEYS["WEB_APP"])
async def test_idle_web_app_connection_expires_to_empty_with_no_session_row(tmp_path: Path, key: str) -> None:
    """A WEB_APP connection that delivers nothing (or whose every request was dropped by the
    method gate) becomes the hidden `empty` state, never an error session."""
    asm, db = await _make(tmp_path, max_idle=1800)
    cid = WEBAPP_CONNS[key].conn_id
    await _feed(asm, webapp_lines_for(key))
    assert (await _conn(db, cid))["state"] == "pending"
    assert await _count(db, "SELECT COUNT(*) FROM api_requests") == 0

    await asm.finalize_idle()  # not yet idle
    assert (await _conn(db, cid))["state"] == "pending"

    await _age_connection(db, cid)
    await asm.finalize_idle()
    assert (await _conn(db, cid))["state"] == "empty"
    assert await _row(db, cid) is None
    assert await _count(db, "SELECT COUNT(*) FROM sessions") == 0

    await asm.finalize_idle()  # idempotent
    assert (await _conn(db, cid))["state"] == "empty"
    assert await _count(db, "SELECT COUNT(*) FROM sessions") == 0
    await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("key", "resource_type"),
    [(k, t) for t in ("SSH", "KUBERNETES") for k in WEBAPP_EMPTY_CONN_KEYS[t]],
)
async def test_idle_ssh_and_kubernetes_connections_still_become_visible_errors(
    tmp_path: Path, key: str, resource_type: str
) -> None:
    asm, db = await _make(tmp_path, max_idle=1800)
    cid = WEBAPP_CONNS[key].conn_id
    await _feed(asm, webapp_lines_for(key))
    await _age_connection(db, cid)
    await asm.finalize_idle()
    row = await _row(db, cid)
    assert row is not None and row["status"] == "error"
    assert row["resource_type"] == resource_type
    assert (await _conn(db, cid))["state"] == "error"
    await db.close()


@pytest.mark.asyncio
async def test_one_sweep_hides_web_and_surfaces_ssh_and_kubernetes(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path, max_idle=1800)
    keys = ("cap_empty_a", "cap_empty_b", "ssh_upper", "k8s_empty")
    await _feed(asm, webapp_batch(*keys))
    for key in keys:
        await _age_connection(db, WEBAPP_CONNS[key].conn_id)
    await asm.finalize_idle()
    states = {k: (await _conn(db, WEBAPP_CONNS[k].conn_id))["state"] for k in keys}
    assert states == {"cap_empty_a": "empty", "cap_empty_b": "empty", "ssh_upper": "error", "k8s_empty": "error"}
    cur = await db.execute("SELECT conn_id FROM sessions ORDER BY conn_id")
    assert [r[0] for r in await cur.fetchall()] == sorted(
        WEBAPP_CONNS[k].conn_id for k in ("ssh_upper", "k8s_empty")
    )
    await db.close()


@pytest.mark.asyncio
async def test_a_request_after_empty_moves_the_connection_to_api_without_a_session(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path, max_idle=1800)
    cid = WEBAPP_CONNS["cap_empty_a"].conn_id
    await _feed(asm, webapp_lines_for("cap_empty_a"))
    await _age_connection(db, cid)
    await asm.finalize_idle()
    assert (await _conn(db, cid))["state"] == "empty"

    await asm.handle(_web_api(cid, "late-1", path="/long-idle-keepalive"))

    conn = await _conn(db, cid)
    assert (conn["state"], conn["has_api"]) == ("api", 1)
    assert await _kinds(db, cid) == {"late-1": "web"}
    assert await _row(db, cid) is None
    await _age_connection(db, cid)
    await asm.finalize_idle()  # api connections are never expired
    assert (await _conn(db, cid))["state"] == "api"
    assert await _count(db, "SELECT COUNT(*) FROM sessions") == 0
    await db.close()


@pytest.mark.asyncio
async def test_web_app_connection_with_requests_never_expires_and_never_gets_a_session(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path, max_idle=1800)
    await _feed(asm, webapp_lines_for("hygiene_requests"))
    cid = WEBAPP_CONNS["hygiene_requests"].conn_id
    await _age_connection(db, cid)
    await asm.finalize_idle()
    assert (await _conn(db, cid))["state"] == "api"
    assert await _count(db, "SELECT COUNT(*) FROM sessions") == 0
    await db.close()


@pytest.mark.asyncio
async def test_connection_restart_still_expires_a_pending_web_app_connection_to_empty(tmp_path: Path) -> None:
    """Pending state lives in SQLite: a fresh Assembler over the same DB still hides an idle web app."""
    asm, db = await _make(tmp_path)
    cid = WEBAPP_CONNS["cap_empty_b"].conn_id
    await _feed(asm, webapp_lines_for("cap_empty_b"))
    asm2 = Assembler(
        repo=SessionRepository(db),
        casts=CastStore(tmp_path / "casts"),
        idle_timeout_seconds=120,
        clock=lambda: 0.0,
        activity=ActivityStore(db),
    )
    await asm2.sweep_startup()
    await _age_connection(db, cid)
    await asm2.finalize_idle()
    assert (await _conn(db, cid))["state"] == "empty"
    assert await _row(db, cid) is None
    await db.close()


# --- resource_type reaches the session row ---


@pytest.mark.asyncio
async def test_promoted_recording_session_carries_the_connection_resource_type(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "ssh-rec"
    await asm.handle(_typed_start(cid, "SSH", "10.0.0.5"))
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1, username="user@example.com"))
    row = await _row(db, cid)
    assert row is not None and row["resource_type"] == "SSH"
    assert (await _conn(db, cid))["state"] == "recording"
    await db.close()


# --- whole-fixture ingestion ---


@pytest.mark.asyncio
async def test_whole_web_fixture_never_creates_a_session_or_leaks_a_never_stored_sentinel(
    tmp_path: Path,
) -> None:
    """Every fixture line through classify + assembler in file order: web traffic stays out of
    `sessions`, and no credential, spoof, query-value or panic sentinel reaches any table."""
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines())

    assert await _count(db, "SELECT COUNT(*) FROM sessions") == 0
    assert await _count(db, "SELECT COUNT(*) FROM api_requests WHERE api_kind = 'web'") > 100
    # Only the deliberately provisional connections remain kubectl among the non-Kubernetes ones.
    text = await _db_text(db)
    for sentinel in WEBAPP_NEVER_STORED_SENTINELS:
        if sentinel in WEBAPP_GWOPS_SENTINELS:
            continue  # accepted gwops apps are stored by design; covered by the T12 tests
        assert sentinel not in text, sentinel
    await db.close()


@pytest.mark.asyncio
async def test_each_request_id_in_the_whole_fixture_is_stored_at_most_once(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines())
    cur = await db.execute("SELECT request_id, COUNT(*) FROM api_requests GROUP BY request_id HAVING COUNT(*) > 1")
    assert await cur.fetchall() == []
    await db.close()


@pytest.mark.asyncio
async def test_fixture_methods_the_gate_accepts_are_stored_as_received(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for("hygiene_requests"))
    methods = {r["method"] for r in await _req_rows(db)}
    assert {"delete", "MKWORKSPACE", "Propfind", "GET", "POST"} <= methods
    await db.close()


# --- stored forms: worked examples and header variants (WEBAPP_SPEC 5.5, 5.7) ---


@pytest.mark.asyncio
async def test_every_worked_example_is_stored_exactly_as_listed(tmp_path: Path) -> None:
    """The WEBAPP_SPEC 5.7 table, end to end through classify, the assembler and SQLite."""
    from tests.samples import WEBAPP_REQUESTS, WEBAPP_WORKED_EXAMPLES

    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for("worked_examples"))
    stored = {r["request_id"]: r["url"] for r in await _req_rows(db)}
    for key, _raw, expected in WEBAPP_WORKED_EXAMPLES:
        assert stored[WEBAPP_REQUESTS[key].request_id] == expected, key
    assert len(stored) == len(WEBAPP_WORKED_EXAMPLES)
    assert set((await _kinds(db, WEBAPP_CONNS["worked_examples"].conn_id)).values()) == {"web"}
    await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("group", ["login", "orders"])
async def test_credential_header_variants_store_identical_rows(tmp_path: Path, group: str) -> None:
    """Values present, placeholdered and names removed give the same stored row (ids and time aside),
    and no credential sentinel is stored for any of them."""
    from tests.samples import WEBAPP_HEADER_VARIANTS, WEBAPP_HEADER_SENTINELS, WEBAPP_REQUESTS

    asm, db = await _make(tmp_path)
    variants = WEBAPP_HEADER_VARIANTS[group]
    for form in ("present", "placeholder", "removed"):
        await _feed(asm, webapp_lines_for(WEBAPP_REQUESTS[variants[form]].conn))

    rows = []
    for form in ("present", "placeholder", "removed"):
        row = dict((await _req_rows(db, "request_id = ?", (WEBAPP_REQUESTS[variants[form]].request_id,)))[0])
        for volatile in ("request_id", "conn_id", "requested_at", "created_at"):
            row.pop(volatile)
        rows.append(row)
    assert rows[0] == rows[1] == rows[2]
    assert rows[0]["api_kind"] == "web" and rows[0]["user_agent"]
    text = await _db_text(db)
    for sentinel in WEBAPP_HEADER_SENTINELS:
        assert sentinel not in text
    await db.close()


@pytest.mark.asyncio
async def test_unusable_allowlisted_headers_never_drop_a_row_or_fail_the_batch(tmp_path: Path) -> None:
    from tests.samples import WEBAPP_REQUESTS

    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for("hdr_tolerance"))
    rows = {r["request_id"]: r for r in await _req_rows(db)}
    for key in (
        "ht_ua_missing", "ht_ua_empty_list", "ht_ua_int_first", "ht_ua_int_value",
        "ht_ua_empty_string", "ht_no_request_key", "ht_headers_not_dict",
    ):
        assert rows[WEBAPP_REQUESTS[key].request_id]["user_agent"] is None, key
    for key in ("ht_ua_placeholder", "ht_ua_plain_string"):
        assert rows[WEBAPP_REQUESTS[key].request_id]["user_agent"], key
    assert len(rows) == 9
    await db.close()


@pytest.mark.asyncio
async def test_kubernetes_requests_without_kubectl_headers_are_stored_with_null_columns(
    tmp_path: Path,
) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for("k8s_hdr_tolerance"))
    rows = await _req_rows(db)
    assert len(rows) == 2
    assert all(r["api_kind"] == "kubectl" for r in rows)
    assert all(r["kubectl_command"] is None and r["kubectl_session"] is None for r in rows)
    await db.close()


@pytest.mark.asyncio
async def test_a_web_request_stores_only_the_user_agent_header(tmp_path: Path) -> None:
    """Credential and extra headers on a web line are never read, so nothing but the
    User-Agent (and no kubectl header) can be stored."""
    from tests.samples import WEBAPP_REQUESTS

    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for("hygiene_requests"))
    row = (await _req_rows(db, "request_id = ?", (WEBAPP_REQUESTS["hy_credential_headers"].request_id,)))[0]
    assert row["api_kind"] == "web"
    assert row["kubectl_command"] is None and row["kubectl_session"] is None
    assert row["user_agent"] is None or len(row["user_agent"]) <= 256
    await db.close()


# --- Session 11 T12: gwops/TLS snapshot through classify + assembler (WEBAPP_SPEC 3.3, 4.4, 4.5) ---

from gatorcast.models import GwopsWebApp  # noqa: E402
from tests.samples import WEBAPP_GWOPS_CASES, WEBAPP_REQUESTS  # noqa: E402

SNAP_COLS = (
    "gwops_match", "gwops_gateway_id", "gwops_app", "gwops_managed",
    "downstream_tls", "downstream_port", "upstream_tls", "upstream_port",
)
NO_SNAPSHOT = dict.fromkeys(SNAP_COLS)
GW_ID = "R2F0ZXdheToxMjk0"

_GW_EXACT = [c for c in WEBAPP_GWOPS_CASES if c.outcome == "accepted" and c.expected["match"] == "exact"]
_GW_NO_APP_MATCH = [
    c for c in WEBAPP_GWOPS_CASES if c.outcome == "accepted" and c.expected["match"] != "exact"
]
_GW_APP_IGNORED = [c for c in WEBAPP_GWOPS_CASES if c.outcome == "accepted_app_ignored"]
_GW_NO_SNAPSHOT = [c for c in WEBAPP_GWOPS_CASES if c.outcome in ("rejected", "absent")]
_GW_NOT_READ = [c for c in WEBAPP_GWOPS_CASES if c.outcome == "not_read"]


def _columns_for(expected: dict | None) -> dict:
    """The eight stored column values for a parsed object (WEBAPP_SPEC 3.3 "What is stored")."""
    if expected is None:
        return dict(NO_SNAPSHOT)
    cols = {**NO_SNAPSHOT, "gwops_match": expected["match"], "gwops_gateway_id": expected["gateway_id"]}
    if expected["match"] == "exact":
        cols.update(
            gwops_app=expected["app"],
            gwops_managed=int(expected["managed"]),
            downstream_tls=expected["downstream_tls"],
            downstream_port=expected["downstream_port"],
            upstream_tls=expected["upstream_tls"],
            upstream_port=expected["upstream_port"],
        )
    return cols


def _modes_for(expected: dict | None) -> tuple[str | None, str | None]:
    """The (downstream, upstream) modes a request on that connection must carry."""
    if expected is None or expected["match"] != "exact":
        return (None, None)
    return (expected["downstream_tls"], expected["upstream_tls"])


async def _snapshot(db: aiosqlite.Connection, conn_id: str) -> dict:
    """The eight raw snapshot columns of one connection."""
    row = await _conn(db, conn_id)
    assert row is not None, conn_id
    return {col: row[col] for col in SNAP_COLS}


async def _request_tls(db: aiosqlite.Connection, conn_id: str) -> dict[str, tuple[str | None, str | None]]:
    """request_id -> (downstream_tls, upstream_tls) for every request of one connection."""
    return {
        r["request_id"]: (r["downstream_tls"], r["upstream_tls"])
        for r in await _req_rows(db, "conn_id = ?", (conn_id,))
    }


def _gw_start(conn_id: str, gwops: GwopsWebApp | None, resource_type: str | None = "WEB_APP") -> SessionStart:
    """A start line event carrying an already-validated ``gwops`` object."""
    return _typed_start(conn_id, resource_type).model_copy(update={"gwops": gwops})


def _gw_exact(**overrides: object) -> GwopsWebApp:
    """A valid exact object: tls13 downstream, verify_full upstream."""
    fields: dict = {
        "match": "exact", "gateway_id": GW_ID, "app": "unit-app", "managed": True,
        "downstream_tls": "tls13", "downstream_port": 443,
        "upstream_tls": "verify_full", "upstream_port": 8443,
    }
    fields.update(overrides)
    return GwopsWebApp(**fields)


_GW_EXACT_COLUMNS = {
    "gwops_match": "exact", "gwops_gateway_id": GW_ID, "gwops_app": "unit-app", "gwops_managed": 1,
    "downstream_tls": "tls13", "downstream_port": 443, "upstream_tls": "verify_full", "upstream_port": 8443,
}


# --- valid exact object: all eight columns, both modes on every request ---


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _GW_EXACT, ids=lambda c: c.key)
async def test_exact_gwops_stores_all_eight_columns_and_the_request_carries_both_modes(
    tmp_path: Path, case
) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for(case.key))
    cid = WEBAPP_CONNS[case.key].conn_id

    assert await _snapshot(db, cid) == _columns_for(case.expected)
    assert (await _conn(db, cid))["resource_type"] == "WEB_APP"
    tls = await _request_tls(db, cid)
    assert len(tls) == 1
    assert list(tls.values()) == [(case.expected["downstream_tls"], case.expected["upstream_tls"])]
    assert set((await _kinds(db, cid)).values()) == {"web"}
    await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _GW_APP_IGNORED, ids=lambda c: c.key)
async def test_bad_app_is_stored_null_with_the_other_seven_columns_and_both_modes(
    tmp_path: Path, case
) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for(case.key))
    cid = WEBAPP_CONNS[case.key].conn_id

    snapshot = await _snapshot(db, cid)
    assert snapshot["gwops_app"] is None
    assert snapshot == _columns_for(case.expected)
    assert all(snapshot[c] is not None for c in SNAP_COLS if c != "gwops_app")
    assert list((await _request_tls(db, cid)).values()) == [("tls13", "verify_full")]
    text = await _db_text(db)
    assert not any(s in text for s in WEBAPP_GWOPS_SENTINELS)  # no gwops sentinel was stored
    await db.close()


@pytest.mark.asyncio
async def test_exact_gwops_with_gateway_id_null_stores_the_rest(tmp_path: Path) -> None:
    """gwops Mode B before its first reconcile: gateway id NULL, everything else stored."""
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for("gw_gateway_id_null"))
    cid = WEBAPP_CONNS["gw_gateway_id_null"].conn_id
    snapshot = await _snapshot(db, cid)
    assert snapshot["gwops_gateway_id"] is None
    assert snapshot["gwops_match"] == "exact" and snapshot["gwops_app"] == "mode-b-app"
    assert list((await _request_tls(db, cid)).values()) == [("tls13", "verify_full")]
    await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("key", "modes"),
    [
        ("gw_exact_upstream_none", ("none", "none")),
        ("gw_exact_upstream_verify_ca", ("tls13", "verify_ca")),
        ("gw_exact_upstream_verify_full", ("tls13", "verify_full")),
        ("gw_exact_upstream_insecure", ("tls13", "insecure")),
        ("gw_exact_downstream_tls13", ("tls13", "verify_full")),
        ("gw_exact_downstream_none", ("none", "none")),
    ],
)
async def test_each_mode_combination_reaches_the_connection_and_its_request(
    tmp_path: Path, key: str, modes: tuple[str, str]
) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for(key))
    cid = WEBAPP_CONNS[key].conn_id
    conn = await _conn(db, cid)
    assert (conn["downstream_tls"], conn["upstream_tls"]) == modes
    assert list((await _request_tls(db, cid)).values()) == [modes]
    await db.close()


@pytest.mark.asyncio
async def test_every_request_on_a_connection_carries_the_same_two_modes(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "multi"
    await asm.handle(_gw_start(cid, _gw_exact(downstream_tls="none", upstream_tls="verify_ca")))
    for i in range(4):
        await asm.handle(_web_api(cid, f"r{i}", path=f"/p/{i}", at=f"2026-10-01T10:00:0{i}.000Z"))
    assert await _request_tls(db, cid) == {f"r{i}": ("none", "verify_ca") for i in range(4)}
    assert await _snapshot(db, cid) == {
        **_GW_EXACT_COLUMNS, "downstream_tls": "none", "upstream_tls": "verify_ca",
    }
    await db.close()


@pytest.mark.asyncio
async def test_detection_disabled_still_stores_the_snapshot_and_request_modes(tmp_path: Path) -> None:
    asm, _repo, _casts, _search, db = await _make_with_search(tmp_path, detection_enabled=False)
    await asm.handle(_gw_start("c1", _gw_exact()))
    await asm.handle(_web_api("c1", "r1"))
    assert await _snapshot(db, "c1") == _GW_EXACT_COLUMNS
    assert await _request_tls(db, "c1") == {"r1": ("tls13", "verify_full")}
    await db.close()


# --- none / ambiguous: only match and gateway id, TLS unknown ---


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _GW_NO_APP_MATCH, ids=lambda c: c.key)
async def test_none_and_ambiguous_store_only_match_and_gateway_id_and_requests_have_no_modes(
    tmp_path: Path, case
) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for(case.key))
    cid = WEBAPP_CONNS[case.key].conn_id

    snapshot = await _snapshot(db, cid)
    assert snapshot == _columns_for(case.expected)
    assert snapshot["gwops_match"] in ("none", "ambiguous")
    assert snapshot["gwops_gateway_id"] == GW_ID
    assert all(snapshot[c] is None for c in SNAP_COLS if c not in ("gwops_match", "gwops_gateway_id"))
    assert list((await _request_tls(db, cid)).values()) == [(None, None)]
    assert set((await _kinds(db, cid)).values()) == {"web"}
    text = await _db_text(db)
    assert "SENTINEL_GWOPS_NONE_APP_20846bf9" not in text  # app fields on a none object are never read
    assert "SENTINEL_GWOPS_UNKNOWN_SCALAR_d3df20d3" not in text
    await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("match", ["none", "ambiguous"])
async def test_hand_built_none_object_with_stray_fields_still_stores_only_two_columns(
    tmp_path: Path, match: str
) -> None:
    """Belt and braces below the classifier: the store maps by match, not by what the model holds."""
    asm, db = await _make(tmp_path)
    stray = GwopsWebApp(**{**_gw_exact().model_dump(), "match": match})
    await asm.handle(_gw_start("c1", stray))
    await asm.handle(_web_api("c1", "r1"))
    assert await _snapshot(db, "c1") == {**NO_SNAPSHOT, "gwops_match": match, "gwops_gateway_id": GW_ID}
    assert await _request_tls(db, "c1") == {"r1": (None, None)}
    await db.close()


# --- no valid object: rejected or absent leaves TLS unknown, the connection otherwise normal ---


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _GW_NO_SNAPSHOT, ids=lambda c: c.key)
async def test_absent_or_rejected_object_stores_a_null_snapshot_and_a_normal_web_connection(
    tmp_path: Path, case
) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for(case.key))
    cid = WEBAPP_CONNS[case.key].conn_id

    assert await _snapshot(db, cid) == NO_SNAPSHOT
    conn = await _conn(db, cid)
    assert conn["resource_type"] == "WEB_APP" and conn["state"] == "api" and conn["has_api"] == 1
    assert conn["username"] == WEB_USER and conn["resource_address"]
    assert list((await _request_tls(db, cid)).values()) == [(None, None)]
    assert set((await _kinds(db, cid)).values()) == {"web"}
    await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", [c for c in _GW_NO_SNAPSHOT if c.outcome == "rejected"], ids=lambda c: c.key)
async def test_a_rejected_object_leaves_the_connection_exactly_as_the_line_without_it(
    tmp_path: Path, case
) -> None:
    """Stored connection and request equal those of the same line with the key removed."""
    import copy

    lines = webapp_lines_for(case.key)
    stripped = copy.deepcopy(json.loads(lines[0]))
    stripped.pop("gwops")
    stripped["conn_id"] = "c0ffee00-0000-4000-8000-0000000000ff"
    request = json.loads(lines[1])
    request["conn_id"] = stripped["conn_id"]
    request["request_id"] = "5eed0000-0000-4000-8000-0000000000ff"

    asm, db = await _make(tmp_path)
    await _feed(asm, lines)
    await _feed(asm, [json.dumps(stripped), json.dumps(request)])

    cid = WEBAPP_CONNS[case.key].conn_id
    a, b = dict(await _conn(db, cid)), dict(await _conn(db, stripped["conn_id"]))
    for volatile in ("conn_id", "created_at", "last_seen_at"):
        a.pop(volatile), b.pop(volatile)
    assert a == b
    ra = dict((await _req_rows(db, "conn_id = ?", (cid,)))[0])
    rb = dict((await _req_rows(db, "conn_id = ?", (stripped["conn_id"],)))[0])
    for volatile in ("conn_id", "request_id", "created_at"):
        ra.pop(volatile), rb.pop(volatile)
    assert ra == rb
    await db.close()


# --- an object on a start line that is not WEB_APP is ignored ---


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _GW_NOT_READ, ids=lambda c: c.key)
async def test_gwops_on_a_non_web_app_start_line_stores_nothing_and_requests_have_no_modes(
    tmp_path: Path, case
) -> None:
    asm, db = await _make(tmp_path)
    lines = webapp_lines_for(case.key)
    assert "gwops" in json.loads(lines[0])
    await _feed(asm, lines)
    cid = WEBAPP_CONNS[case.key].conn_id

    assert await _snapshot(db, cid) == NO_SNAPSHOT
    assert (await _conn(db, cid))["resource_type"] == case.resource_type
    for tls in (await _request_tls(db, cid)).values():
        assert tls == (None, None)
    text = await _db_text(db)
    assert not any(s in text for s in WEBAPP_GWOPS_SENTINELS)  # no gwops sentinel was stored
    await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["gw_on_kubernetes_upper", "gw_on_kubernetes_lower"])
async def test_gwops_on_a_kubernetes_line_leaves_its_request_kubectl_with_null_modes(
    tmp_path: Path, key: str
) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for(key))
    cid = WEBAPP_CONNS[key].conn_id
    conn = await _conn(db, cid)
    assert conn["resource_type"] == "KUBERNETES"
    assert await _snapshot(db, cid) == NO_SNAPSHOT
    rows = await _req_rows(db, "conn_id = ?", (cid,))
    assert len(rows) == 1
    assert rows[0]["api_kind"] == "kubectl"
    assert (rows[0]["downstream_tls"], rows[0]["upstream_tls"]) == (None, None)
    await db.close()


@pytest.mark.asyncio
async def test_gwops_on_an_ssh_line_is_ignored_and_a_later_request_has_no_modes(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines_for("gw_on_ssh_upper"))
    cid = WEBAPP_CONNS["gw_on_ssh_upper"].conn_id
    assert await _snapshot(db, cid) == NO_SNAPSHOT
    assert (await _conn(db, cid))["resource_type"] == "SSH"

    await asm.handle(_web_api(cid, "ssh-r1"))

    assert await _snapshot(db, cid) == NO_SNAPSHOT
    assert await _request_tls(db, cid) == {"ssh-r1": (None, None)}
    await db.close()


@pytest.mark.asyncio
async def test_an_object_cannot_be_smuggled_onto_a_kubernetes_connection_by_a_later_web_start(
    tmp_path: Path,
) -> None:
    """Processed KUBERNETES start with no object, then a WEB_APP start with one: the snapshot stays NULL."""
    asm, db = await _make(tmp_path)
    await asm.handle(_gw_start("c1", None, "KUBERNETES"))
    await asm.handle(_gw_start("c1", _gw_exact(), "WEB_APP"))
    assert await _snapshot(db, "c1") == NO_SNAPSHOT
    await db.close()


# --- requests that beat their start line (WEBAPP_SPEC 4.4 backfill) ---


@pytest.mark.asyncio
async def test_fixture_early_requests_get_both_modes_when_the_exact_start_line_arrives(tmp_path: Path) -> None:
    """late_start_web: GET and DELETE arrive first (kubectl, no modes); the start converts both."""
    asm, db = await _make(tmp_path)
    lines = webapp_lines_for("late_start_web")
    cid = WEBAPP_CONNS["late_start_web"].conn_id

    await _feed(asm, lines[:-1])
    assert set((await _kinds(db, cid)).values()) == {"kubectl"}
    assert set((await _request_tls(db, cid)).values()) == {(None, None)}
    assert await _snapshot(db, cid) == NO_SNAPSHOT

    await _feed(asm, lines[-1:])

    assert set((await _kinds(db, cid)).values()) == {"web"}
    assert len(await _request_tls(db, cid)) == 2
    assert set((await _request_tls(db, cid)).values()) == {("tls13", "verify_full")}
    assert await _snapshot(db, cid) == {
        **_GW_EXACT_COLUMNS, "gwops_app": "verifier-a", "upstream_port": 443,
    }
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    await db.close()


@pytest.mark.asyncio
async def test_a_request_after_the_backfill_carries_the_same_modes_as_the_converted_ones(
    tmp_path: Path,
) -> None:
    asm, db = await _make(tmp_path)
    cid = "late"
    await asm.handle(_web_api(cid, "early-1", at="2026-10-01T10:00:01.000Z"))
    await asm.handle(_web_api(cid, "early-2", at="2026-10-01T10:00:02.000Z"))
    await asm.handle(_gw_start(cid, _gw_exact(upstream_tls="insecure")))
    await asm.handle(_web_api(cid, "after", at="2026-10-01T10:00:03.000Z"))
    assert await _request_tls(db, cid) == {
        "early-1": ("tls13", "insecure"), "early-2": ("tls13", "insecure"), "after": ("tls13", "insecure"),
    }
    assert set((await _kinds(db, cid)).values()) == {"web"}
    await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "gwops",
    [None, GwopsWebApp(match="none", gateway_id=GW_ID), GwopsWebApp(match="ambiguous", gateway_id=None)],
    ids=["no-object", "none", "ambiguous"],
)
async def test_backfilled_requests_have_no_modes_when_the_start_has_no_exact_object(
    tmp_path: Path, gwops: GwopsWebApp | None
) -> None:
    asm, db = await _make(tmp_path)
    cid = "late"
    await asm.handle(_web_api(cid, "early-1", at="2026-10-01T10:00:01.000Z"))
    await asm.handle(_web_api(cid, "early-2", at="2026-10-01T10:00:02.000Z"))
    await asm.handle(_gw_start(cid, gwops))
    assert await _request_tls(db, cid) == {"early-1": (None, None), "early-2": (None, None)}
    assert set((await _kinds(db, cid)).values()) == {"web"}
    await db.close()


@pytest.mark.asyncio
async def test_early_requests_then_a_kubernetes_start_keep_null_modes_and_stay_kubectl(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "late-k8s"
    await asm.handle(_web_api(cid, "early-1"))
    await asm.handle(_gw_start(cid, None, "KUBERNETES"))
    assert await _request_tls(db, cid) == {"early-1": (None, None)}
    assert set((await _kinds(db, cid)).values()) == {"kubectl"}
    assert await _snapshot(db, cid) == NO_SNAPSHOT
    await db.close()


# --- redelivery: first processing fixes the snapshot, request TLS never moves ---


_REDELIVER_COLUMNS = {
    "gwops_match": "exact", "gwops_gateway_id": GW_ID, "gwops_app": "redeliver-app", "gwops_managed": 1,
    "downstream_tls": "tls13", "downstream_port": 443, "upstream_tls": "verify_full", "upstream_port": 443,
}
_REDELIVER_TLS = {
    "5eed0000-0000-4000-8000-000000000131": ("tls13", "verify_full"),
    "5eed0000-0000-4000-8000-000000000132": ("tls13", "verify_full"),
}


@pytest.mark.asyncio
async def test_redelivered_batch_keeps_the_first_snapshot_and_the_request_modes(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    redelivery = webapp_redelivery()
    cid = WEBAPP_CONNS["redeliver"].conn_id

    await _feed(asm, redelivery.originals)
    assert await _snapshot(db, cid) == _REDELIVER_COLUMNS
    assert await _request_tls(db, cid) == _REDELIVER_TLS

    for _ in range(3):
        await _feed(asm, redelivery.replay)

    assert await _snapshot(db, cid) == _REDELIVER_COLUMNS
    assert await _request_tls(db, cid) == _REDELIVER_TLS
    await db.close()


@pytest.mark.asyncio
async def test_a_conflicting_object_on_a_repeated_start_changes_neither_snapshot_nor_request_modes(
    tmp_path: Path,
) -> None:
    asm, db = await _make(tmp_path)
    redelivery = webapp_redelivery()
    cid = WEBAPP_CONNS["redeliver"].conn_id
    await _feed(asm, redelivery.originals)

    await _feed(asm, [redelivery.conflicting_start])

    assert await _snapshot(db, cid) == _REDELIVER_COLUMNS
    assert await _request_tls(db, cid) == _REDELIVER_TLS
    assert "SENTINEL_GWOPS_CONFLICT_APP_59ec7daf" not in await _db_text(db)
    await db.close()


@pytest.mark.asyncio
async def test_a_repeated_start_without_an_object_does_not_clear_the_snapshot(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    redelivery = webapp_redelivery()
    cid = WEBAPP_CONNS["redeliver"].conn_id
    await _feed(asm, redelivery.originals)

    await _feed(asm, [redelivery.no_object_start])

    assert await _snapshot(db, cid) == _REDELIVER_COLUMNS
    assert await _request_tls(db, cid) == _REDELIVER_TLS
    await db.close()


@pytest.mark.asyncio
async def test_the_whole_redelivery_sequence_in_fixture_order_ends_with_the_first_snapshot(
    tmp_path: Path,
) -> None:
    """originals, replay, conflicting start, no-object start; then the replay once more."""
    asm, db = await _make(tmp_path)
    r = webapp_redelivery()
    cid = WEBAPP_CONNS["redeliver"].conn_id
    await _feed(asm, r.originals + r.replay + [r.conflicting_start, r.no_object_start] + r.replay)
    assert await _snapshot(db, cid) == _REDELIVER_COLUMNS
    assert await _request_tls(db, cid) == _REDELIVER_TLS
    assert len(await _req_rows(db, "conn_id = ?", (cid,))) == 2
    await db.close()


@pytest.mark.asyncio
async def test_a_new_request_after_a_conflicting_start_carries_the_first_snapshots_modes(
    tmp_path: Path,
) -> None:
    """The conflicting object says none/insecure; a request first seen afterwards still gets tls13/verify_full."""
    asm, db = await _make(tmp_path)
    r = webapp_redelivery()
    cid = WEBAPP_CONNS["redeliver"].conn_id
    await _feed(asm, r.originals)
    await _feed(asm, [r.conflicting_start])

    await asm.handle(_web_api(cid, "after-conflict"))

    assert (await _request_tls(db, cid))["after-conflict"] == ("tls13", "verify_full")
    await db.close()


@pytest.mark.asyncio
async def test_the_snapshot_survives_a_restart_and_a_redelivered_conflicting_start(tmp_path: Path) -> None:
    """State is in SQLite: a fresh Assembler over the same database still treats the start as a repeat."""
    asm, db = await _make(tmp_path)
    r = webapp_redelivery()
    cid = WEBAPP_CONNS["redeliver"].conn_id
    await _feed(asm, r.originals)

    asm2 = Assembler(
        repo=SessionRepository(db),
        casts=CastStore(tmp_path / "casts"),
        idle_timeout_seconds=120,
        clock=lambda: 0.0,
        activity=ActivityStore(db),
    )
    await asm2.sweep_startup()
    await _feed(asm2, [r.conflicting_start, r.no_object_start])
    await _feed(asm2, r.replay)

    assert await _snapshot(db, cid) == _REDELIVER_COLUMNS
    assert await _request_tls(db, cid) == _REDELIVER_TLS
    await db.close()


@pytest.mark.asyncio
async def test_a_connection_first_seen_without_an_object_stays_null_when_a_repeat_has_one(
    tmp_path: Path,
) -> None:
    """redeliver_noobj_then_obj: [start without object, request, start with object] -> TLS unknown."""
    asm, db = await _make(tmp_path)
    first_start, request, repeated_start = webapp_redelivery().noobj_then_obj
    cid = WEBAPP_CONNS["redeliver_noobj_then_obj"].conn_id

    await _feed(asm, [first_start, request])
    assert await _snapshot(db, cid) == NO_SNAPSHOT
    assert list((await _request_tls(db, cid)).values()) == [(None, None)]

    await _feed(asm, [repeated_start])
    await _feed(asm, [first_start, request, repeated_start])

    assert await _snapshot(db, cid) == NO_SNAPSHOT
    assert list((await _request_tls(db, cid)).values()) == [(None, None)]
    assert "SENTINEL_GWOPS_RETROFILL_APP_8982deb0" not in await _db_text(db)
    await db.close()


@pytest.mark.asyncio
async def test_a_new_request_after_the_repeated_start_still_has_null_modes(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    first_start, request, repeated_start = webapp_redelivery().noobj_then_obj
    cid = WEBAPP_CONNS["redeliver_noobj_then_obj"].conn_id
    await _feed(asm, [first_start, request, repeated_start])

    await asm.handle(_web_api(cid, "later"))

    assert (await _request_tls(db, cid))["later"] == (None, None)
    assert await _snapshot(db, cid) == NO_SNAPSHOT
    await db.close()


@pytest.mark.asyncio
async def test_a_null_snapshot_created_by_a_rejected_first_object_is_not_filled_by_a_valid_repeat(
    tmp_path: Path,
) -> None:
    """The first processing logged a rejection and stored NULL; a valid copy later changes nothing."""
    asm, db = await _make(tmp_path)
    cid = WEBAPP_CONNS["gw_rej_schema_2"].conn_id
    rejected_start, request = webapp_lines_for("gw_rej_schema_2")
    valid = json.loads(rejected_start)
    valid["gwops"] = json.loads(webapp_lines_for("gw_exact_upstream_verify_ca")[0])["gwops"]

    await _feed(asm, [rejected_start, request])
    await _feed(asm, [json.dumps(valid)])

    assert await _snapshot(db, cid) == NO_SNAPSHOT
    assert list((await _request_tls(db, cid)).values()) == [(None, None)]
    await db.close()


@pytest.mark.asyncio
async def test_redelivered_early_requests_after_conversion_keep_their_modes(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "rd-early"
    early = [_web_api(cid, "r1", method="DELETE", path="/items/1"), _web_api(cid, "r2", path="/home")]
    for event in early:
        await asm.handle(event)
    await asm.handle(_gw_start(cid, _gw_exact()))
    expected = {"r1": ("tls13", "verify_full"), "r2": ("tls13", "verify_full")}
    assert await _request_tls(db, cid) == expected

    for event in early:  # redelivered after conversion: deduplicated, not re-stored as kubectl
        await asm.handle(event)
    await asm.handle(_gw_start(cid, _gw_exact(upstream_tls="none")))  # repeat with a different object

    assert await _request_tls(db, cid) == expected
    assert set((await _kinds(db, cid)).values()) == {"web"}
    assert await _snapshot(db, cid) == _GW_EXACT_COLUMNS
    await db.close()


# --- lifecycle is unaffected by the snapshot ---


@pytest.mark.asyncio
async def test_a_web_connection_with_a_snapshot_still_expires_to_empty_without_requests(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path, max_idle=1800)
    cid = "idle-web"
    await asm.handle(_gw_start(cid, _gw_exact()))
    await _age_connection(db, cid)
    await asm.finalize_idle()
    conn = await _conn(db, cid)
    assert conn["state"] == "empty"
    assert await _row(db, cid) is None
    assert await _snapshot(db, cid) == _GW_EXACT_COLUMNS
    await db.close()


@pytest.mark.asyncio
async def test_a_request_after_empty_still_carries_the_snapshot_modes(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path, max_idle=1800)
    cid = "idle-then-active"
    await asm.handle(_gw_start(cid, _gw_exact()))
    await _age_connection(db, cid)
    await asm.finalize_idle()
    assert (await _conn(db, cid))["state"] == "empty"

    await asm.handle(_web_api(cid, "late-1"))

    assert (await _conn(db, cid))["state"] == "api"
    assert await _request_tls(db, cid) == {"late-1": ("tls13", "verify_full")}
    await db.close()


# --- whole-fixture invariants ---


@pytest.mark.asyncio
async def test_whole_fixture_snapshots_are_all_or_nothing_and_requests_mirror_their_connection(
    tmp_path: Path,
) -> None:
    """Across every fixture line: each connection's snapshot is a valid unit, kubectl rows have no
    modes, and every web request's modes equal its connection's stored modes."""
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines())

    cur = await db.execute("SELECT * FROM connections")
    conns = {r["conn_id"]: r for r in await cur.fetchall()}
    await cur.close()
    seen = {"exact": 0, "none": 0, "ambiguous": 0, "null": 0}
    for row in conns.values():
        snap = {c: row[c] for c in SNAP_COLS}
        match = snap["gwops_match"]
        if match is None:
            assert all(v is None for v in snap.values()), row["conn_id"]
            seen["null"] += 1
        elif match == "exact":
            assert all(snap[c] is not None for c in SNAP_COLS if c not in ("gwops_gateway_id", "gwops_app"))
            assert row["resource_type"] == "WEB_APP"
            seen["exact"] += 1
        else:
            assert match in ("none", "ambiguous")
            assert all(snap[c] is None for c in SNAP_COLS if c not in ("gwops_match", "gwops_gateway_id"))
            assert row["resource_type"] == "WEB_APP"
            seen[match] += 1
    assert min(seen.values()) > 0, seen  # the fixture exercises every shape

    for req in await _req_rows(db):
        conn = conns[req["conn_id"]]
        if req["api_kind"] == "kubectl":
            assert (req["downstream_tls"], req["upstream_tls"]) == (None, None), req["request_id"]
        else:
            assert (req["downstream_tls"], req["upstream_tls"]) == (
                conn["downstream_tls"], conn["upstream_tls"],
            ), req["request_id"]
    await db.close()


@pytest.mark.asyncio
async def test_whole_fixture_connections_match_the_expected_columns_for_every_gwops_case(
    tmp_path: Path,
) -> None:
    """One pass over the whole fixture, then every gw_* case checked against WEBAPP_GWOPS_CASES."""
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines())
    for case in WEBAPP_GWOPS_CASES:
        cid = WEBAPP_CONNS[case.key].conn_id
        expected = case.expected if case.outcome in ("accepted", "accepted_app_ignored") else None
        assert await _snapshot(db, cid) == _columns_for(expected), case.key
        for tls in (await _request_tls(db, cid)).values():
            assert tls == _modes_for(expected), case.key
    await db.close()


@pytest.mark.asyncio
async def test_no_web_app_manifest_tables_exist_after_ingesting_the_fixture(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    await _feed(asm, webapp_lines())
    cur = await db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    names = {r[0] for r in await cur.fetchall()}
    await cur.close()
    assert not {n for n in names if n.startswith("web_app")}
    await db.close()


# --- Session 12 fix loop: first-write-wins type (A), provisional URL form (B), invalid type (E) ---

from gatorcast.models import RESOURCE_TYPE_INVALID  # noqa: E402

KUBE_DELETE_PATH = "/api/v1/namespaces/default/pods/x"


async def _kube_rows_with_finding(asm: Assembler, cid: str) -> None:
    """KUBERNETES start, then a DELETE that trips ``kube-delete`` (with the kubectl headers)."""
    await asm.handle(_typed_start(cid, "KUBERNETES", K8S_ADDR))
    await asm.handle(_web_api(cid, "k1", method="DELETE", path=KUBE_DELETE_PATH, at="2026-10-01T10:00:01.000Z"))


@pytest.mark.asyncio
async def test_forged_web_start_on_a_kubernetes_connection_changes_nothing(tmp_path: Path) -> None:
    """A: KUBERNETES start + kubectl rows with a finding, then a forged WEB_APP start for the same
    conn_id: type, api_kind, kubectl headers and findings are unchanged, and the next request is
    still kubectl with findings (detection cannot be switched off by a forged line)."""
    asm, db = await _make(tmp_path)
    cid = "forged-web"
    await _kube_rows_with_finding(asm, cid)
    assert await _finding_rules(db, "k1") == ["kube-delete"]

    await asm.handle(_typed_start(cid, "WEB_APP", WEB_ADDR))

    assert (await _conn(db, cid))["resource_type"] == "KUBERNETES"
    assert await _snapshot(db, cid) == NO_SNAPSHOT
    row = (await _req_rows(db))[0]
    assert (row["api_kind"], row["kubectl_command"]) == ("kubectl", "kubectl get")
    assert await _finding_rules(db, "k1") == ["kube-delete"]

    await asm.handle(_web_api(cid, "k2", method="DELETE", path=KUBE_DELETE_PATH, at="2026-10-01T10:00:02.000Z"))
    assert await _kinds(db, cid) == {"k1": "kubectl", "k2": "kubectl"}
    assert await _finding_rules(db, "k2") == ["kube-delete"]
    await db.close()


@pytest.mark.asyncio
async def test_forged_kubernetes_start_on_a_web_connection_changes_nothing(tmp_path: Path) -> None:
    """A (reverse): WEB_APP start, then a forged KUBERNETES start: still WEB_APP, still web rows,
    no rules, snapshot untouched, and the next request is web with the snapshot's modes."""
    asm, db = await _make(tmp_path)
    cid = "forged-k8s"
    await asm.handle(_gw_start(cid, _gw_exact()))
    await asm.handle(_web_api(cid, "w1", method="DELETE", path=KUBE_DELETE_PATH, at="2026-10-01T10:00:01.000Z"))
    before = await _snapshot(db, cid)
    assert before["gwops_match"] == "exact"

    await asm.handle(_typed_start(cid, "KUBERNETES", K8S_ADDR))

    assert (await _conn(db, cid))["resource_type"] == "WEB_APP"
    assert await _snapshot(db, cid) == before
    await asm.handle(_web_api(cid, "w2", method="DELETE", path=KUBE_DELETE_PATH, at="2026-10-01T10:00:02.000Z"))
    assert await _kinds(db, cid) == {"w1": "web", "w2": "web"}
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    assert set((await _request_tls(db, cid)).values()) == {("tls13", "verify_full")}
    await db.close()


@pytest.mark.asyncio
async def test_pre_upgrade_processed_start_with_null_type_is_not_retyped_by_a_web_start(tmp_path: Path) -> None:
    """A: a processed start line with no type (pre-upgrade) keeps NULL (Kubernetes policy). A later
    WEB_APP start neither types it, nor snapshots, nor backfills; requests stay kubectl with rules."""
    asm, db = await _make(tmp_path)
    cid = "legacy-null"
    await asm.handle(_typed_start(cid, None, K8S_ADDR))
    await asm.handle(_web_api(cid, "k1", method="DELETE", path=KUBE_DELETE_PATH, at="2026-10-01T10:00:01.000Z"))

    await asm.handle(_gw_start(cid, _gw_exact()))

    conn = await _conn(db, cid)
    assert conn["resource_type"] is None
    assert await _snapshot(db, cid) == NO_SNAPSHOT
    assert (await _kinds(db, cid)) == {"k1": "kubectl"}
    assert await _finding_rules(db, "k1") == ["kube-delete"]  # no backfill: findings stay

    await asm.handle(_web_api(cid, "k2", method="DELETE", path=KUBE_DELETE_PATH, at="2026-10-01T10:00:02.000Z"))
    assert await _kinds(db, cid) == {"k1": "kubectl", "k2": "kubectl"}
    assert await _finding_rules(db, "k2") == ["kube-delete"]
    await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("start_type", ["KUBERNETES", "WEB_APP", "SSH"])
async def test_minimal_row_then_typed_start_takes_the_start_type(tmp_path: Path, start_type: str) -> None:
    """A: a request that beat its start line leaves the minimal row; the first start types it."""
    asm, db = await _make(tmp_path)
    cid = f"minimal-{start_type.lower()}"
    await asm.handle(_web_api(cid, "r1", method="DELETE", path=KUBE_DELETE_PATH))
    minimal = await _conn(db, cid)
    assert minimal["started_at"] is None and minimal["resource_type"] is None

    await asm.handle(_typed_start(cid, start_type, K8S_ADDR))

    assert (await _conn(db, cid))["resource_type"] == start_type
    expected_kind = "kubectl" if start_type == "KUBERNETES" else "web"
    assert await _kinds(db, cid) == {"r1": expected_kind}
    assert await _finding_rules(db, "r1") == (["kube-delete"] if start_type == "KUBERNETES" else [])
    await db.close()


@pytest.mark.asyncio
async def test_chunk_first_then_ssh_start_sets_the_session_resource_type(tmp_path: Path) -> None:
    """A recording chunk that beat its start line gets ``sessions.resource_type == "SSH"`` from the start."""
    asm, db = await _make(tmp_path)
    cid = "chunk-then-ssh"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1, username="user@example.com"))
    assert (await _row(db, cid))["resource_type"] is None  # nothing known yet

    await asm.handle(_typed_start(cid, "SSH", "10.0.0.5"))

    assert (await _row(db, cid))["resource_type"] == "SSH"
    assert (await _conn(db, cid))["resource_type"] == "SSH"
    await db.close()


@pytest.mark.asyncio
async def test_session_resource_type_follows_the_connections_stored_type_not_a_later_start(
    tmp_path: Path,
) -> None:
    """A: with a recording in progress, a forged start with another type changes neither row."""
    asm, db = await _make(tmp_path)
    cid = "session-follows"
    await asm.handle(_typed_start(cid, "SSH", "10.0.0.5"))
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1, username="user@example.com"))
    assert (await _row(db, cid))["resource_type"] == "SSH"

    await asm.handle(_typed_start(cid, "KUBERNETES", K8S_ADDR))
    await asm.handle(_typed_start(cid, "WEB_APP", WEB_ADDR))

    assert (await _row(db, cid))["resource_type"] == "SSH"
    assert (await _conn(db, cid))["resource_type"] == "SSH"
    await db.close()


@pytest.mark.asyncio
async def test_invalid_resource_type_is_web_policy_with_no_rules_and_is_not_copied_to_sessions(
    tmp_path: Path,
) -> None:
    """E: the ``invalid`` marker is non-Kubernetes (web form, no rules) and never reaches ``sessions``."""
    asm, db = await _make(tmp_path)
    cid = "invalid-type"
    await asm.handle(_typed_start(cid, RESOURCE_TYPE_INVALID, K8S_ADDR))
    await asm.handle(_web_api(cid, "r1", method="DELETE", path=KUBE_DELETE_PATH, at="2026-10-01T10:00:01.000Z"))
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=CHUNK_1, username="user@example.com"))

    assert (await _conn(db, cid))["resource_type"] == "invalid"  # stored on the connection
    assert await _kinds(db, cid) == {"r1": "web"}
    row = (await _req_rows(db))[0]
    assert row["url"] == f"{KUBE_DELETE_PATH}?month=SE…ef(36)"  # url_web
    assert row["kubectl_command"] is None
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    assert (await _row(db, cid))["resource_type"] is None  # never copied to sessions
    await db.close()


@pytest.mark.asyncio
async def test_invalid_resource_type_pending_connection_expires_to_an_error_row_without_a_type(
    tmp_path: Path,
) -> None:
    """E: an idle ``invalid`` connection is a visible error (only WEB_APP is hidden), with no type shown."""
    asm, db = await _make(tmp_path, max_idle=1800)
    cid = "invalid-idle"
    await asm.handle(_typed_start(cid, RESOURCE_TYPE_INVALID, K8S_ADDR))
    await _age_connection(db, cid)
    await asm.finalize_idle()
    row = await _row(db, cid)
    assert row is not None and row["status"] == "error"
    assert row["resource_type"] is None
    await db.close()


@pytest.mark.asyncio
async def test_web_pending_hidden_debug_log_carries_a_count_and_no_values(
    tmp_path: Path, asm_log: io.StringIO
) -> None:
    """Hidden (``empty``) WEB_APP expiries log one debug line with the count only."""
    asm, db = await _make(tmp_path, max_idle=1800)
    cids = ("hidden-conn-aaa", "hidden-conn-bbb")
    for cid in cids:
        await asm.handle(_typed_start(cid, "WEB_APP", "sentinel-host.corp.example"))
        await _age_connection(db, cid)

    await asm.finalize_idle()

    events = [e for e in _log_events(asm_log) if e["event"] == "assembler.web_pending_hidden"]
    assert events == [{"event": "assembler.web_pending_hidden", "level": "debug", "count": 2}]
    text = asm_log.getvalue()
    assert "sentinel-host" not in text
    assert not any(cid in text for cid in cids)
    for cid in cids:
        assert (await _conn(db, cid))["state"] == "empty"
    await db.close()


# --- B: hygiene for requests that beat (or never meet) their start line ---

HYGIENE_CMD = "QJxCMDsentinelValue7f3aKZ"
HYGIENE_PROXY = "QJxPROXYsentinelPath9c1dKZ"
HYGIENE_QUERY = "QJxQUERYsentinelValue4b2eKZ"
HYGIENE_FRAGMENTS = ("QJ", "KZ", "sentinel")
EXEC_PATH = "/api/v1/namespaces/x/pods/y/exec"


def _raw_api_line(conn_id: str, request_id: str, url: str, at: str) -> dict:
    """A raw ``gateway.audit`` line (as the Gateway emits it) for ``classify``."""
    return {
        "logger": "gateway.audit",
        "message": "API request completed",
        "ts": at,
        "requested_at": at,
        "request_id": request_id,
        "conn_id": conn_id,
        "method": "GET",
        "url": url,
        "user": {"id": "VXNlcjox", "username": "user@example.com"},
        "request": {
            "headers": {
                "User-Agent": ["kubectl/v1.33.0"],
                "Kubectl-Command": ["kubectl exec"],
                "Kubectl-Session": ["5e55e55e-0000-4000-8000-000000000001"],
            }
        },
        "response": {"status_code": 101},
    }


def _hygiene_urls() -> list[str]:
    """An exec URL carrying ``command=`` and a service-proxy URL carrying a path token and a query."""
    return [
        f"{EXEC_PATH}?command={HYGIENE_CMD}&stdin=true",
        f"/api/v1/namespaces/x/services/s/proxy/{HYGIENE_PROXY}?a={HYGIENE_QUERY}",
    ]


async def _feed_hygiene_requests(asm: Assembler, cid: str) -> None:
    """Classify and handle the two hygiene URLs on ``cid`` (the start line is not sent)."""
    for i, url in enumerate(_hygiene_urls()):
        event = classify(_raw_api_line(cid, f"hy-{cid}-{i}", url, f"2026-10-01T10:00:0{i + 1}.000Z"))
        assert isinstance(event, ApiRequest)
        await asm.handle(event)


@pytest.mark.asyncio
@pytest.mark.parametrize("start_type", [None, "KUBERNETES", "WEB_APP"], ids=["no-start", "late-k8s", "late-web"])
async def test_requests_before_the_start_line_store_no_command_or_proxy_value(
    tmp_path: Path, start_type: str | None
) -> None:
    """B: exec ``command=`` and proxy path/query values never reach the DB for a provisional row,
    not whole and not as a prefix/suffix fragment, whether the start line never comes, or comes
    as KUBERNETES or WEB_APP. The provisional URL is final in every case."""
    asm, db = await _make(tmp_path)
    cid = f"hygiene-{start_type or 'none'}".lower()
    await _feed_hygiene_requests(asm, cid)
    if start_type is not None:
        await asm.handle(_typed_start(cid, start_type, WEB_ADDR))

    text = await _db_text(db)
    for needle in (HYGIENE_CMD, HYGIENE_PROXY, HYGIENE_QUERY, *HYGIENE_FRAGMENTS):
        assert needle not in text, needle
    urls = [r["url"] for r in await _req_rows(db)]
    assert urls == [f"{EXEC_PATH}?stdin=t…(4)", "/api/v1/namespaces/x/services/s/proxy"]
    expected_kind = "web" if start_type == "WEB_APP" else "kubectl"
    assert set((await _kinds(db, cid)).values()) == {expected_kind}
    row = (await _req_rows(db))[0]
    if expected_kind == "kubectl":
        assert row["kubectl_command"] == "kubectl exec"  # provisional rows keep the kubectl headers
    else:
        assert row["kubectl_command"] is None  # converted: headers cleared
    await db.close()


# --- Session 12 fix loop: gwops app categories are stored as NULL with the start line kept (C) ---


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "app", ["\ud800", "xy", "͸"], ids=["surrogate-Cs", "private-use-Co", "unassigned-Cn"]
)
async def test_start_line_with_a_refused_gwops_app_is_stored_with_a_null_app(tmp_path: Path, app: str) -> None:
    """C: a gwops ``app`` in Cs/Co/Cn is refused, but the start line is accepted and stored."""
    asm, db = await _make(tmp_path)
    cid = "c0ffee00-0000-4000-8000-00000000c0c0"
    line = {
        "logger": "gateway", "message": "Authenticated connection", "conn_id": cid,
        "ts": "2026-10-01T10:00:00.100Z", "user": {"id": "uid", "username": "user@example.com"},
        "resource_address": WEB_ADDR, "resource_type": "WEB_APP",
        "gwops": {
            "schema": 1, "gateway_id": GW_ID, "match": "exact", "app": app, "managed": True,
            "downstream_tls": "tls13", "downstream_port": 443, "upstream_tls": "verify_full",
            "upstream_port": 8443,
        },
    }
    event = classify(line)
    assert isinstance(event, SessionStart)
    await asm.handle(event)

    conn = await _conn(db, cid)
    assert conn is not None and conn["state"] == "pending"
    assert conn["resource_address"] == WEB_ADDR
    snap = await _snapshot(db, cid)
    assert snap["gwops_match"] == "exact" and snap["gwops_app"] is None
    assert (snap["downstream_tls"], snap["upstream_tls"]) == ("tls13", "verify_full")
    await db.close()


# --- Known production bug (Session 12 review): parse_asciicast splits on str.splitlines() ---


@pytest.mark.parametrize("raw", ["\u0085", " ", " "], ids=["NEL", "LS", "PS"])
def test_parse_asciicast_counts_an_event_that_holds_a_raw_unicode_line_separator(raw: str) -> None:
    """An event whose output contains one raw separator is still ONE event (offset 2.0)."""
    doc = reassemble_asciicast([HEADER + json.dumps([2.0, "o", f"a{raw}b"], ensure_ascii=False) + "\n"])
    meta = parse_asciicast(doc)
    assert (meta.event_count, meta.duration_seconds) == (1, 2.0)


# --- M: retention keeps a connection that a stored request still references ---


@pytest.mark.asyncio
async def test_purge_keeps_an_old_connection_with_a_recent_request_and_the_next_request_is_still_web(
    tmp_path: Path,
) -> None:
    """M: old created/last-seen clocks do not purge a connection with a recent request, so its type
    and gwops snapshot survive and the next request is stored as web with the snapshot's modes
    (not as a provisional kubectl row with rules)."""
    asm, db = await _make(tmp_path)
    cid = "purge-keep"
    await asm.handle(_gw_start(cid, _gw_exact()))
    await asm.handle(_web_api(cid, "r1", method="DELETE", path="/items/1", at="2026-10-07T10:00:01.000Z"))
    await db.execute(
        "UPDATE connections SET created_at = '2000-01-01 00:00:00', last_seen_at = '2000-01-01 00:00:00' "
        "WHERE conn_id = ?",
        (cid,),
    )
    await db.execute("UPDATE api_requests SET created_at = datetime('now')")
    await db.commit()
    snapshot_before = await _snapshot(db, cid)

    purged = await asm._activity.purge_before("2026-10-05T00:00:00Z")

    assert purged == (0, 0)
    conn = await _conn(db, cid)
    assert conn is not None and conn["resource_type"] == "WEB_APP"
    assert await _snapshot(db, cid) == snapshot_before
    await asm.handle(_web_api(cid, "r2", method="DELETE", path="/items/2", at="2026-10-07T10:00:02.000Z"))
    assert await _kinds(db, cid) == {"r1": "web", "r2": "web"}
    assert await _request_tls(db, cid) == {"r1": ("tls13", "verify_full"), "r2": ("tls13", "verify_full")}
    assert await _count(db, "SELECT COUNT(*) FROM api_findings") == 0
    await db.close()


@pytest.mark.asyncio
async def test_purge_removes_the_connection_once_nothing_references_it_and_its_clocks_are_old(
    tmp_path: Path,
) -> None:
    """M: with no request left and both clocks old, the connection (and its snapshot) goes."""
    asm, db = await _make(tmp_path)
    cid = "purge-gone"
    await asm.handle(_gw_start(cid, _gw_exact()))
    await db.execute(
        "UPDATE connections SET created_at = '2000-01-01 00:00:00', last_seen_at = '2000-01-01 00:00:00'"
    )
    await db.commit()
    assert await asm._activity.purge_before("2026-10-05T00:00:00Z") == (0, 1)
    assert await _conn(db, cid) is None
    await db.close()
