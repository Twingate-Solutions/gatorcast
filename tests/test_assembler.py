"""Tests for pipeline.assembler: parsing, reassembly, finalize, idle, sweep."""

from __future__ import annotations

import json
from pathlib import Path

import aiosqlite
import pytest

from gatorcast.db import init_db
from gatorcast.models import RecordingChunk, SessionEnd, SessionStart
from gatorcast.pipeline.assembler import Assembler, parse_asciicast
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import SessionRepository
from tests.samples import sample_lines

# A small asciicast v2 document, split mid-tuple across two fragments to exercise
# the "concatenate ALL fragments first, then parse" rule (CLAUDE.md rule 3).
HEADER = '{"version":2,"width":80,"height":24,"timestamp":1700000000,"user":"ubuntu"}\n'
FRAG_A = HEADER + '[0.0,"o","a"]\n[1.5,"o'
FRAG_B = '","b"]\n[3.25,"o","c"]\n'
FULL_DOC = FRAG_A + FRAG_B


class FakeClock:
    """A controllable monotonic clock for idle-timeout tests."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


async def _make(
    tmp_path: Path, idle: int = 120, clock=None
) -> tuple[Assembler, aiosqlite.Connection]:
    """Build an assembler backed by a fresh schema-initialized DB."""
    db = await init_db(tmp_path / "gatorcast.db")
    repo = SessionRepository(db)
    casts = CastStore(tmp_path / "casts")
    asm = Assembler(
        repo=repo,
        casts=casts,
        idle_timeout_seconds=idle,
        clock=clock or (lambda: 0.0),
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
    assert cast == obj["asciicast"]
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
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=FRAG_A))
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=FRAG_B))
    await asm.finalize(cid)
    assert (tmp_path / "casts" / f"{cid}.cast").read_text(encoding="utf-8") == FULL_DOC
    row = await _row(db, cid)
    assert row["status"] == "complete" and row["chunk_count"] == 2
    await db.close()


@pytest.mark.asyncio
async def test_out_of_order_seq_reassembles_correctly(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path)
    cid = "conn-ooo"
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=FRAG_B))
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=FRAG_A))
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
    await asm.handle(RecordingChunk(conn_id="A", seq=0, asciicast=FRAG_A))
    await asm.handle(SessionStart(conn_id="B", resource_address="host-b", username="u@x"))
    await asm.handle(RecordingChunk(conn_id="B", seq=0, asciicast=HEADER))
    await asm.handle(RecordingChunk(conn_id="A", seq=1, asciicast=FRAG_B))
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
async def test_idle_finalize(tmp_path: Path) -> None:
    clock = FakeClock()
    asm, db = await _make(tmp_path, idle=120, clock=clock)
    cid = "conn-idle"
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=HEADER))

    clock.advance(60)
    await asm.finalize_idle()
    assert asm.active_count == 1  # not silent long enough yet
    assert (await _row(db, cid))["status"] == "provisional"

    clock.advance(61)  # now past the 120s idle window
    await asm.finalize_idle()
    assert asm.active_count == 0
    assert (await _row(db, cid))["status"] == "complete"
    await db.close()


@pytest.mark.asyncio
async def test_partial_session_still_finalizes(tmp_path: Path) -> None:
    """An interrupted session (no close event) still produces a playable .cast."""
    asm, db = await _make(tmp_path)
    cid = "conn-partial"
    await asm.handle(SessionStart(conn_id=cid, resource_address="host", username="u@x"))
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=FRAG_A))  # mid-tuple
    await asm.finalize(cid)
    row = await _row(db, cid)
    # FRAG_A has a valid header, so it is complete and playable despite truncation.
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
async def test_sweep_recovers_provisional_with_cast_on_disk(tmp_path: Path) -> None:
    asm, db = await _make(tmp_path, idle=120)
    cid = "recovered"
    (tmp_path / "casts").mkdir(exist_ok=True)
    (tmp_path / "casts" / f"{cid}.cast").write_text(FULL_DOC, encoding="utf-8")
    await db.execute(
        "INSERT INTO sessions (conn_id, status, created_at) "
        "VALUES (?, 'provisional', '2000-01-01 00:00:00')",
        (cid,),
    )
    await db.commit()
    await asm.sweep_startup()
    row = await _row(db, cid)
    assert row["status"] == "complete"
    assert row["width"] == 80
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
async def test_provisional_to_complete_transition(tmp_path: Path) -> None:
    """SessionStart creates a provisional row; finalize transitions it to complete."""
    asm, db = await _make(tmp_path)
    cid = "conn-trans"
    await asm.handle(
        SessionStart(conn_id=cid, resource_address="srv.example.com", username="alice@x")
    )
    row = await _row(db, cid)
    assert row["status"] == "provisional"
    assert row["resource_address"] == "srv.example.com"
    assert row["username"] == "alice@x"

    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=HEADER))
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

    # Normal happy path: two fragments → finalize → complete.
    await asm.handle(RecordingChunk(conn_id=cid, seq=0, asciicast=FRAG_A))
    await asm.handle(RecordingChunk(conn_id=cid, seq=1, asciicast=FRAG_B))
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
    await asm._post_finalize_scan(cid, SCAN_CAST)

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
