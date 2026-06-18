"""Tests for pipeline.retention: age-based and size-based purge.

Covers:
  - purge by age (RETENTION_DAYS): old rows + .cast files removed
  - NULL started_at rows are never age-purged (age is unknown)
  - purge by size (RETENTION_MAX_GB): oldest complete sessions removed until under cap
  - only complete rows are eligible for size-based purge
  - row + file deletion together
  - tolerate already-missing .cast file
  - disabled policies (0 values) are no-ops
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gatorcast.db import init_db
from gatorcast.pipeline.detect import Finding
from gatorcast.pipeline.retention import RetentionPurger
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import SessionRepository

_1_GB = 1024 * 1024 * 1024


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
def casts_dir(tmp_path: Path) -> Path:
    d = tmp_path / "casts"
    d.mkdir()
    return d


@pytest.fixture
def cast_store(casts_dir: Path) -> CastStore:
    return CastStore(casts_dir)


@pytest.fixture
def search_store(db, cast_store: CastStore) -> SearchStore:
    return SearchStore(db, cast_store)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _insert(
    db,
    conn_id: str,
    status: str = "complete",
    started_at: str | None = None,
    size_bytes: int = 0,
    cast_path: str | None = None,
) -> None:
    """Insert a session row for testing."""
    await db.execute(
        """
        INSERT INTO sessions
            (conn_id, status, started_at, size_bytes, cast_path, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        """,
        (conn_id, status, started_at, size_bytes, cast_path),
    )
    await db.commit()


async def _count(db, conn_id: str) -> int:
    cur = await db.execute("SELECT COUNT(*) FROM sessions WHERE conn_id = ?", (conn_id,))
    row = await cur.fetchone()
    await cur.close()
    return row[0]


# ---------------------------------------------------------------------------
# Age-based purge
# ---------------------------------------------------------------------------


async def test_purge_by_age_removes_old_rows(
    repo: SessionRepository, cast_store: CastStore, casts_dir: Path, db
) -> None:
    """Sessions older than RETENTION_DAYS are deleted along with their .cast files."""
    cast_path = str(casts_dir / "old.cast")
    (casts_dir / "old.cast").write_text("old content", encoding="utf-8")
    await _insert(db, "old", started_at="2000-01-01T00:00:00Z", cast_path=cast_path)

    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=1, retention_max_gb=0
    )
    await purger.run()

    assert await _count(db, "old") == 0
    assert not (casts_dir / "old.cast").exists()


async def test_purge_by_age_keeps_recent_rows(
    repo: SessionRepository, cast_store: CastStore, db
) -> None:
    """Sessions newer than the cutoff are not deleted."""
    await _insert(db, "recent", started_at="2099-12-31T00:00:00Z")
    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=1, retention_max_gb=0
    )
    await purger.run()
    assert await _count(db, "recent") == 1


async def test_purge_by_age_skips_null_started_at(
    repo: SessionRepository, cast_store: CastStore, db
) -> None:
    """Rows with NULL started_at are never age-purged (age is unknown)."""
    await _insert(db, "no-ts", started_at=None, status="complete")
    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=1, retention_max_gb=0
    )
    await purger.run()
    assert await _count(db, "no-ts") == 1


async def test_purge_by_age_disabled_when_zero(
    repo: SessionRepository, cast_store: CastStore, db
) -> None:
    """retention_days=0 means keep forever — no rows are deleted."""
    await _insert(db, "ancient", started_at="2000-01-01T00:00:00Z")
    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=0, retention_max_gb=0
    )
    await purger.run()
    assert await _count(db, "ancient") == 1


async def test_purge_by_age_tolerates_missing_cast_file(
    repo: SessionRepository, cast_store: CastStore, casts_dir: Path, db
) -> None:
    """Age purge succeeds even when the .cast file is already gone."""
    missing_path = str(casts_dir / "gone.cast")
    # Do NOT create the file.
    await _insert(
        db, "gone", started_at="2000-01-01T00:00:00Z", cast_path=missing_path
    )
    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=1, retention_max_gb=0
    )
    await purger.run()  # must not raise
    assert await _count(db, "gone") == 0


async def test_purge_by_age_null_cast_path_ok(
    repo: SessionRepository, cast_store: CastStore, db
) -> None:
    """Age purge handles rows that have no cast_path (never finalized)."""
    await _insert(db, "no-path", started_at="2000-01-01T00:00:00Z", cast_path=None)
    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=1, retention_max_gb=0
    )
    await purger.run()
    assert await _count(db, "no-path") == 0


# ---------------------------------------------------------------------------
# Size-based purge
# ---------------------------------------------------------------------------


async def test_purge_by_size_removes_oldest_complete(
    repo: SessionRepository, cast_store: CastStore, casts_dir: Path, db
) -> None:
    """Over-cap purge removes oldest-first complete sessions until under the cap."""
    # Each fake cast file is 100 bytes.
    for name, started in [
        ("old-a", "2026-01-01T00:00:00Z"),
        ("old-b", "2026-02-01T00:00:00Z"),
        ("new-c", "2026-06-01T00:00:00Z"),
    ]:
        path = casts_dir / f"{name}.cast"
        path.write_bytes(b"x" * 100)
        await _insert(
            db,
            name,
            status="complete",
            started_at=started,
            size_bytes=100,
            cast_path=str(path),
        )

    # Cap at 150 bytes (300 total → need to delete at least 150 bytes worth).
    # Oldest sessions (old-a, old-b) are the candidates; only old-a should be
    # enough to drop total to 200 which is still over; both old-a+old-b bring
    # total to 100 which is under 150.
    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=0,
        retention_max_gb=150 / _1_GB,
    )
    await purger.run()

    # old-a and old-b should be gone (total was 300; needed to reach ≤ 150)
    assert await _count(db, "old-a") == 0
    assert await _count(db, "old-b") == 0
    assert await _count(db, "new-c") == 1
    assert not (casts_dir / "old-a.cast").exists()
    assert not (casts_dir / "old-b.cast").exists()
    assert (casts_dir / "new-c.cast").exists()


async def test_purge_by_size_skips_provisional(
    repo: SessionRepository, cast_store: CastStore, casts_dir: Path, db
) -> None:
    """Size purge only considers complete sessions; provisional rows are untouched."""
    path = casts_dir / "prov.cast"
    path.write_bytes(b"x" * 1000)
    await _insert(
        db,
        "prov",
        status="provisional",
        started_at="2026-01-01T00:00:00Z",
        size_bytes=1000,
        cast_path=str(path),
    )
    # Cap is well below the 1000 bytes recorded, but the row is provisional.
    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=0,
        retention_max_gb=1 / _1_GB,  # 1 byte cap
    )
    await purger.run()
    assert await _count(db, "prov") == 1


async def test_purge_by_size_noop_when_under_cap(
    repo: SessionRepository, cast_store: CastStore, casts_dir: Path, db
) -> None:
    """No deletion occurs when total size is already within the cap."""
    path = casts_dir / "small.cast"
    path.write_bytes(b"x" * 50)
    await _insert(
        db, "small", status="complete", size_bytes=50, cast_path=str(path)
    )
    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=0,
        retention_max_gb=1.0,  # 1 GB cap — 50 bytes is way under
    )
    await purger.run()
    assert await _count(db, "small") == 1


async def test_purge_by_size_disabled_when_zero(
    repo: SessionRepository, cast_store: CastStore, casts_dir: Path, db
) -> None:
    """retention_max_gb=0 disables size-based purge."""
    path = casts_dir / "big.cast"
    path.write_bytes(b"x" * 1000)
    await _insert(
        db, "big", status="complete", size_bytes=1000, cast_path=str(path)
    )
    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=0, retention_max_gb=0
    )
    await purger.run()
    assert await _count(db, "big") == 1


async def test_purge_by_size_tolerates_missing_cast_file(
    repo: SessionRepository, cast_store: CastStore, casts_dir: Path, db
) -> None:
    """Size purge removes the row and skips the missing .cast file without error."""
    missing_path = str(casts_dir / "gone2.cast")
    # File does not exist.
    await _insert(
        db,
        "gone2",
        status="complete",
        started_at="2026-01-01T00:00:00Z",
        size_bytes=500,
        cast_path=missing_path,
    )
    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=0,
        retention_max_gb=1 / _1_GB,  # 1 byte cap to force deletion
    )
    await purger.run()  # must not raise
    assert await _count(db, "gone2") == 0


# ---------------------------------------------------------------------------
# Combined age + size in one run
# ---------------------------------------------------------------------------


async def test_both_policies_run_together(
    repo: SessionRepository, cast_store: CastStore, casts_dir: Path, db
) -> None:
    """Both age and size policies execute in a single run() call."""
    # Age victim: very old.
    old_path = casts_dir / "age-victim.cast"
    old_path.write_bytes(b"x" * 10)
    await _insert(
        db,
        "age-victim",
        status="complete",
        started_at="2000-01-01T00:00:00Z",
        size_bytes=10,
        cast_path=str(old_path),
    )
    # Size victim: large, but recent.
    size_path = casts_dir / "size-victim.cast"
    size_path.write_bytes(b"x" * 900)
    await _insert(
        db,
        "size-victim",
        status="complete",
        started_at="2026-01-01T00:00:00Z",
        size_bytes=900,
        cast_path=str(size_path),
    )
    # Survivor: recent and small.
    survivor_path = casts_dir / "survivor.cast"
    survivor_path.write_bytes(b"x" * 10)
    await _insert(
        db,
        "survivor",
        status="complete",
        started_at="2099-12-31T00:00:00Z",
        size_bytes=10,
        cast_path=str(survivor_path),
    )

    # Age cap = 1 day (removes age-victim); size cap = 50 bytes (after age purge,
    # size-victim at 900 bytes triggers size purge).
    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=1,
        retention_max_gb=50 / _1_GB,
    )
    await purger.run()

    assert await _count(db, "age-victim") == 0
    assert await _count(db, "size-victim") == 0
    assert await _count(db, "survivor") == 1


# ---------------------------------------------------------------------------
# Sidecar + findings purge (Task 7)
# ---------------------------------------------------------------------------


async def test_purge_also_removes_sidecar_and_findings(
    repo: SessionRepository,
    cast_store: CastStore,
    search_store: SearchStore,
    casts_dir: Path,
    db,
) -> None:
    """Age purge removes row + .cast + sidecar + findings as one operation."""
    conn_id = "withextras"
    path, _ = await cast_store.write_cast(conn_id, "cast content")
    await cast_store.write_sidecar(conn_id, "sidecar plaintext")
    await search_store.replace_findings(
        conn_id,
        [
            Finding(
                rule_id="recursive-delete",
                category="dangerous-command",
                severity="high",
                label="Recursive delete (rm -rf)",
                offset_seconds=0.5,
            )
        ],
    )
    await _insert(
        db,
        conn_id,
        status="complete",
        started_at="2000-01-01T00:00:00Z",
        cast_path=str(path),
    )

    # Sanity: everything exists before the purge.
    assert cast_store.path_for(conn_id).exists()
    assert cast_store.has_sidecar(conn_id)
    assert len(await search_store.list_findings(conn_id)) == 1

    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=1,
        retention_max_gb=0,
        search=search_store,
    )
    await purger.run()

    assert await _count(db, conn_id) == 0
    assert not cast_store.path_for(conn_id).exists()
    assert not cast_store.has_sidecar(conn_id)
    assert await search_store.list_findings(conn_id) == []


async def test_purge_without_search_still_removes_sidecar(
    repo: SessionRepository,
    cast_store: CastStore,
    casts_dir: Path,
    db,
) -> None:
    """A purger built WITHOUT a SearchStore still deletes row + file + sidecar."""
    conn_id = "nosearch"
    path, _ = await cast_store.write_cast(conn_id, "cast content")
    await cast_store.write_sidecar(conn_id, "sidecar plaintext")
    await _insert(
        db,
        conn_id,
        status="complete",
        started_at="2000-01-01T00:00:00Z",
        cast_path=str(path),
    )

    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=1, retention_max_gb=0
    )
    await purger.run()  # must not raise

    assert await _count(db, conn_id) == 0
    assert not cast_store.path_for(conn_id).exists()
    assert not cast_store.has_sidecar(conn_id)
