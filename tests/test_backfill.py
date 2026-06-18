"""Tests for pipeline.backfill: index + detect existing finalized sessions.

Covers:
  - a finalized session lacking a sidecar is indexed + detected (processed == 1)
  - the sidecar is written, findings are stored, and the session summary is updated
  - a second run is a no-op (idempotent; the sidecar now exists)
  - provisional sessions are never processed
  - a candidate whose .cast file is missing is skipped without raising
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gatorcast.db import init_db
from gatorcast.pipeline.backfill import run_backfill
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import SessionRepository

# Minimal asciicast whose single output event contains a flagged command.
_CAST = '{"version":2,"width":80,"height":24,"timestamp":1700000000}\n[0.5,"o","rm -rf /etc\\r\\n"]\n'


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db(tmp_path: Path):
    conn = await init_db(tmp_path / "gatorcast.db")
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db):
    return SessionRepository(db)


@pytest.fixture
def cast_store(tmp_path: Path) -> CastStore:
    return CastStore(tmp_path / "casts")


@pytest.fixture
def search_store(db, cast_store: CastStore) -> SearchStore:
    return SearchStore(db, cast_store)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _finalize_complete(
    repo: SessionRepository, cast_store: CastStore, conn_id: str, cast_text: str
) -> None:
    """Seed a complete session row + its .cast file (but NOT a sidecar)."""
    await repo.upsert_start(
        conn_id,
        username="alice",
        resource_address="host-1",
        started_at="2026-01-01T00:00:00Z",
    )
    path, size = await cast_store.write_cast(conn_id, cast_text)
    await repo.finalize(
        conn_id,
        username="alice",
        shell_user="ubuntu",
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:00:01Z",
        duration_seconds=0.5,
        width=80,
        height=24,
        chunk_count=1,
        size_bytes=size,
        cast_path=str(path),
        status="complete",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_backfill_indexes_and_detects(
    repo: SessionRepository, cast_store: CastStore, search_store: SearchStore
) -> None:
    """A finalized session with no sidecar is indexed + detected on backfill."""
    conn_id = "sess-1"
    await _finalize_complete(repo, cast_store, conn_id, _CAST)
    assert not cast_store.has_sidecar(conn_id)

    processed = await run_backfill(repo, cast_store, search_store)

    assert processed == 1
    assert cast_store.has_sidecar(conn_id)

    findings = await search_store.list_findings(conn_id)
    assert any(f.rule_id == "recursive-delete" for f in findings)

    session = await repo.get(conn_id)
    assert session is not None
    assert session.finding_count >= 1
    assert session.max_severity is not None


async def test_backfill_is_idempotent(
    repo: SessionRepository, cast_store: CastStore, search_store: SearchStore
) -> None:
    """A second run processes nothing because the sidecar already exists."""
    conn_id = "sess-2"
    await _finalize_complete(repo, cast_store, conn_id, _CAST)

    first = await run_backfill(repo, cast_store, search_store)
    assert first == 1

    second = await run_backfill(repo, cast_store, search_store)
    assert second == 0


async def test_backfill_skips_provisional(
    repo: SessionRepository, cast_store: CastStore, search_store: SearchStore
) -> None:
    """Provisional sessions are not eligible for backfill (only complete/error)."""
    conn_id = "prov-1"
    await repo.upsert_start(
        conn_id,
        username="bob",
        resource_address="host-2",
        started_at="2026-01-01T00:00:00Z",
    )
    await cast_store.write_cast(conn_id, _CAST)

    processed = await run_backfill(repo, cast_store, search_store)

    assert processed == 0
    assert not cast_store.has_sidecar(conn_id)


async def test_backfill_skips_missing_cast(
    repo: SessionRepository, cast_store: CastStore, search_store: SearchStore
) -> None:
    """A finalized candidate whose .cast file is gone is skipped without raising."""
    conn_id = "gone-1"
    # Finalize a row that points at a cast file we then never wrote (simulate loss).
    await repo.upsert_start(
        conn_id,
        username="carol",
        resource_address="host-3",
        started_at="2026-01-01T00:00:00Z",
    )
    await repo.finalize(
        conn_id,
        username="carol",
        shell_user="ubuntu",
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:00:01Z",
        duration_seconds=0.5,
        width=80,
        height=24,
        chunk_count=1,
        size_bytes=0,
        cast_path=str(cast_store.path_for(conn_id)),
        status="complete",
    )
    assert not cast_store.path_for(conn_id).exists()

    processed = await run_backfill(repo, cast_store, search_store)  # must not raise

    assert processed == 0
    assert not cast_store.has_sidecar(conn_id)
