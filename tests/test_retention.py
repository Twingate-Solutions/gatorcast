"""Tests for pipeline.retention: age-based and size-based purge.

Covers:
  - purge by age (RETENTION_DAYS): old rows + .cast files removed
  - NULL started_at rows are never age-purged (age is unknown)
  - purge by size (RETENTION_MAX_GB): oldest complete sessions removed until under cap
  - only complete rows are eligible for size-based purge
  - row + file deletion together
  - tolerate already-missing .cast file
  - disabled policies (0 values) are no-ops
  - kubectl activity (spec §11/§13): the age purge also removes api_requests,
    api_findings and connections with the same RETENTION_DAYS cutoff; the size
    purge leaves them; counters are logged; no new retention setting exists
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from gatorcast.config import Settings
from gatorcast.db import init_db
from gatorcast.pipeline import retention as retention_module
from gatorcast.pipeline.detect import Finding
from gatorcast.pipeline.retention import RetentionPurger
from gatorcast.store.activity import ActivityStore
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


@pytest.fixture
def activity_store(db) -> ActivityStore:
    return ActivityStore(db)


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


# ---------------------------------------------------------------------------
# kubectl activity retention (spec §11 / §13)
# ---------------------------------------------------------------------------

_RETENTION_DAYS = 10


def _days_ago(days: float) -> datetime:
    """Return an aware UTC datetime ``days`` before now."""
    return datetime.now(tz=UTC) - timedelta(days=days)


def _requested_at(dt: datetime) -> str:
    """Format as the stored ``api_requests.requested_at`` (``…T…:….mmmZ``)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _sqlite_now_format(dt: datetime) -> str:
    """Format as SQLite ``datetime('now')`` (``connections.created_at``)."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _session_ts(dt: datetime) -> str:
    """Format as a session ``started_at`` (second precision, ``Z``)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


async def _insert_request(db, request_id: str, conn_id: str, requested_at: str) -> None:
    """Insert one ``api_requests`` row with allowlisted-shape metadata."""
    await db.execute(
        """
        INSERT INTO api_requests (
            request_id, conn_id, resource_address, user_key, username,
            requested_at, method, url, status_code, outcome
        )
        VALUES (?, ?, 'cluster.example', 'u1', 'alice', ?, 'GET',
                '/api/v1/namespaces/default/secrets', 200, 'completed')
        """,
        (request_id, conn_id, requested_at),
    )
    await db.commit()


async def _insert_api_finding(db, request_id: str) -> None:
    """Insert one ``api_findings`` row for ``request_id``."""
    await db.execute(
        """
        INSERT INTO api_findings (request_id, rule_id, category, severity, label)
        VALUES (?, 'kube-secrets', 'kube-api', 'high', 'Secret access')
        """,
        (request_id,),
    )
    await db.commit()


async def _insert_connection(db, conn_id: str, created_at: str, state: str = "api") -> None:
    """Insert one ``connections`` row with an explicit ``created_at``."""
    await db.execute(
        """
        INSERT INTO connections (
            conn_id, username, resource_address, state, has_api,
            created_at, last_seen_at
        )
        VALUES (?, 'alice', 'cluster.example', ?, 1, ?, ?)
        """,
        (conn_id, state, created_at, created_at),
    )
    await db.commit()


async def _table_count(db, table: str, column: str, value: str) -> int:
    """Count rows in ``table`` where ``column = value`` (test-only identifiers)."""
    cur = await db.execute(f"SELECT COUNT(*) FROM {table} WHERE {column} = ?", (value,))
    row = await cur.fetchone()
    await cur.close()
    return row[0]


async def _seed_activity(db) -> None:
    """Seed one old (11 days) and one new (9 days) request/finding/connection.

    With ``RETENTION_DAYS = 10`` the ``old-*`` rows fall before the cutoff and the
    ``new-*`` rows after it.
    """
    old, new = _days_ago(_RETENTION_DAYS + 1), _days_ago(_RETENTION_DAYS - 1)
    await _insert_connection(db, "old-conn", _sqlite_now_format(old))
    await _insert_connection(db, "new-conn", _sqlite_now_format(new))
    await _insert_request(db, "old-req", "old-conn", _requested_at(old))
    await _insert_request(db, "new-req", "new-conn", _requested_at(new))
    await _insert_api_finding(db, "old-req")
    await _insert_api_finding(db, "new-req")


class _LogRecorder:
    """Stand-in for the module's structlog logger; records ``info`` calls."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def info(self, event: str, **kwargs: Any) -> None:
        self.events.append((event, kwargs))


@pytest.fixture
def log_recorder(monkeypatch: pytest.MonkeyPatch) -> _LogRecorder:
    recorder = _LogRecorder()
    monkeypatch.setattr(retention_module, "log", recorder)
    return recorder


async def test_age_purge_removes_old_api_rows_findings_and_connections(
    repo: SessionRepository,
    cast_store: CastStore,
    activity_store: ActivityStore,
    db,
) -> None:
    """Rows older than RETENTION_DAYS go; newer ones stay (requests, findings, conns)."""
    await _seed_activity(db)

    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=_RETENTION_DAYS,
        retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()

    assert await _table_count(db, "api_requests", "request_id", "old-req") == 0
    assert await _table_count(db, "api_findings", "request_id", "old-req") == 0
    assert await _table_count(db, "connections", "conn_id", "old-conn") == 0

    assert await _table_count(db, "api_requests", "request_id", "new-req") == 1
    assert await _table_count(db, "api_findings", "request_id", "new-req") == 1
    assert await _table_count(db, "connections", "conn_id", "new-conn") == 1


async def test_age_purge_uses_same_cutoff_for_sessions_and_activity(
    repo: SessionRepository,
    cast_store: CastStore,
    activity_store: ActivityStore,
    db,
) -> None:
    """Sessions and API activity on each side of the cutoff are treated alike."""
    await _seed_activity(db)
    await _insert(db, "old-sess", started_at=_session_ts(_days_ago(_RETENTION_DAYS + 1)))
    await _insert(db, "new-sess", started_at=_session_ts(_days_ago(_RETENTION_DAYS - 1)))

    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=_RETENTION_DAYS,
        retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()

    assert await _count(db, "old-sess") == 0
    assert await _table_count(db, "api_requests", "request_id", "old-req") == 0
    assert await _table_count(db, "connections", "conn_id", "old-conn") == 0
    assert await _count(db, "new-sess") == 1
    assert await _table_count(db, "api_requests", "request_id", "new-req") == 1
    assert await _table_count(db, "connections", "conn_id", "new-conn") == 1


async def test_age_purge_activity_disabled_when_zero(
    repo: SessionRepository,
    cast_store: CastStore,
    activity_store: ActivityStore,
    db,
) -> None:
    """RETENTION_DAYS=0 keeps API rows, findings, and connections forever."""
    await _seed_activity(db)
    await _insert_connection(db, "ancient-conn", "2000-01-01 00:00:00")
    await _insert_request(db, "ancient-req", "ancient-conn", "2000-01-01T00:00:00.000Z")

    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=0,
        retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()

    assert await _table_count(db, "api_requests", "request_id", "ancient-req") == 1
    assert await _table_count(db, "api_requests", "request_id", "old-req") == 1
    assert await _table_count(db, "api_findings", "request_id", "old-req") == 1
    assert await _table_count(db, "connections", "conn_id", "ancient-conn") == 1


async def test_size_purge_leaves_api_rows_and_connections(
    repo: SessionRepository,
    cast_store: CastStore,
    activity_store: ActivityStore,
    casts_dir: Path,
    db,
) -> None:
    """RETENTION_MAX_GB counts .cast bytes only and never deletes activity rows."""
    await _seed_activity(db)
    path = casts_dir / "big.cast"
    path.write_bytes(b"x" * 1000)
    await _insert(
        db,
        "big",
        status="complete",
        started_at="2026-01-01T00:00:00Z",
        size_bytes=1000,
        cast_path=str(path),
    )

    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=0,
        retention_max_gb=1 / _1_GB,  # 1 byte cap
        activity=activity_store,
    )
    await purger.run()

    assert await _count(db, "big") == 0  # the size policy still ran
    for req in ("old-req", "new-req"):
        assert await _table_count(db, "api_requests", "request_id", req) == 1
        assert await _table_count(db, "api_findings", "request_id", req) == 1
    for conn in ("old-conn", "new-conn"):
        assert await _table_count(db, "connections", "conn_id", conn) == 1


async def test_purger_without_activity_store_leaves_api_rows(
    repo: SessionRepository, cast_store: CastStore, db
) -> None:
    """A purger built without an ActivityStore purges sessions only (back-compat)."""
    await _seed_activity(db)
    await _insert(db, "old-sess", started_at="2000-01-01T00:00:00Z")

    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=_RETENTION_DAYS, retention_max_gb=0
    )
    await purger.run()

    assert await _count(db, "old-sess") == 0
    assert await _table_count(db, "api_requests", "request_id", "old-req") == 1
    assert await _table_count(db, "connections", "conn_id", "old-conn") == 1


async def test_purge_logs_activity_counters(
    repo: SessionRepository,
    cast_store: CastStore,
    activity_store: ActivityStore,
    log_recorder: _LogRecorder,
    db,
) -> None:
    """run() logs purged_api_requests and purged_connections (counters only)."""
    await _seed_activity(db)
    await _insert(db, "old-sess", started_at="2000-01-01T00:00:00Z")

    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=_RETENTION_DAYS,
        retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()

    assert log_recorder.events == [
        (
            "retention.purge",
            {
                "purged_age": 1,
                "purged_size": 0,
                "purged_api_requests": 1,
                "purged_connections": 1,
            },
        )
    ]


async def test_purge_logs_when_only_activity_purged(
    repo: SessionRepository,
    cast_store: CastStore,
    activity_store: ActivityStore,
    log_recorder: _LogRecorder,
    db,
) -> None:
    """A run that deletes only API rows (no sessions) still logs its counters."""
    await _seed_activity(db)

    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=_RETENTION_DAYS,
        retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()

    assert len(log_recorder.events) == 1
    event, fields = log_recorder.events[0]
    assert event == "retention.purge"
    assert fields["purged_age"] == 0
    assert fields["purged_api_requests"] == 1
    assert fields["purged_connections"] == 1
    # Counters only: every logged value is an int, never a URL or identifier.
    assert all(isinstance(v, int) for v in fields.values())


async def test_purge_logs_nothing_when_nothing_purged(
    repo: SessionRepository,
    cast_store: CastStore,
    activity_store: ActivityStore,
    log_recorder: _LogRecorder,
    db,
) -> None:
    """A no-op run (only rows newer than the cutoff) emits no summary line."""
    fresh = _days_ago(1)
    await _insert_connection(db, "fresh-conn", _sqlite_now_format(fresh))
    await _insert_request(db, "fresh-req", "fresh-conn", _requested_at(fresh))

    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=_RETENTION_DAYS,
        retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()

    assert log_recorder.events == []


def test_no_new_retention_setting() -> None:
    """API retention reuses RETENTION_DAYS: no new setting, no new purger knob."""
    retention_fields = {
        name for name in Settings.model_fields if "retention" in name or "purge" in name
    }
    assert retention_fields == {"retention_days", "retention_max_gb"}

    params = set(inspect.signature(RetentionPurger.__init__).parameters) - {"self"}
    assert params == {
        "repo",
        "casts",
        "retention_days",
        "retention_max_gb",
        "search",
        "activity",
    }


async def test_session_age_purge_unchanged_with_activity_store(
    repo: SessionRepository,
    cast_store: CastStore,
    activity_store: ActivityStore,
    casts_dir: Path,
    db,
) -> None:
    """Supplying an ActivityStore does not change session purge semantics."""
    old_path = casts_dir / "old.cast"
    old_path.write_text("old content", encoding="utf-8")
    await _insert(db, "old", started_at="2000-01-01T00:00:00Z", cast_path=str(old_path))
    await _insert(db, "recent", started_at="2099-12-31T00:00:00Z")
    await _insert(db, "no-ts", started_at=None)

    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=1,
        retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()

    assert await _count(db, "old") == 0
    assert not old_path.exists()
    assert await _count(db, "recent") == 1
    assert await _count(db, "no-ts") == 1


async def test_age_purge_removes_future_dated_api_row_by_created_at(
    repo: SessionRepository,
    cast_store: CastStore,
    activity_store: ActivityStore,
    db,
) -> None:
    """Security F5: a request the Gateway dated 9999 is still purged once its
    server-assigned created_at is past the cutoff (findings go with it)."""
    await _insert_request(db, "future-req", "future-conn", "9999-01-01T00:00:00.000Z")
    await _insert_api_finding(db, "future-req")
    await db.execute(
        "UPDATE api_requests SET created_at = ? WHERE request_id = ?",
        (_sqlite_now_format(_days_ago(_RETENTION_DAYS + 1)), "future-req"),
    )
    # A future-dated row inserted recently is not yet due.
    await _insert_request(db, "future-fresh", "future-conn", "9999-01-01T00:00:00.000Z")
    await db.commit()

    purger = RetentionPurger(
        repo=repo,
        casts=cast_store,
        retention_days=_RETENTION_DAYS,
        retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()

    assert await _table_count(db, "api_requests", "request_id", "future-req") == 0
    assert await _table_count(db, "api_findings", "request_id", "future-req") == 0
    assert await _table_count(db, "api_requests", "request_id", "future-fresh") == 1


# ---------------------------------------------------------------------------
# Session 11: web rows and their connections age out like every other activity row
# (WEBAPP_SPEC 9). The gwops/TLS columns are written as raw values here: the snapshot
# logic itself is covered elsewhere.
# ---------------------------------------------------------------------------


async def _insert_web_connection(db, conn_id: str, created_at: str, state: str = "api") -> None:
    """A WEB_APP connection carrying a populated gwops/TLS snapshot."""
    await db.execute(
        """
        INSERT INTO connections (
            conn_id, username, resource_address, state, has_api, created_at, last_seen_at,
            resource_type, gwops_match, gwops_gateway_id, gwops_app, gwops_managed,
            downstream_tls, downstream_port, upstream_tls, upstream_port
        )
        VALUES (?, 'alice', 'wiki.corp.internal', ?, 1, ?, ?, 'WEB_APP', 'exact',
                'R2F0ZXdheToxMjk0', 'Legacy Wiki', 0, 'none', 80, 'none', 8080)
        """,
        (conn_id, state, created_at, created_at),
    )
    await db.commit()


async def _insert_web_request(db, request_id: str, conn_id: str, requested_at: str) -> None:
    """A web ``api_requests`` row with its denormalized configured modes."""
    await db.execute(
        """
        INSERT INTO api_requests (
            request_id, conn_id, resource_address, user_key, username, requested_at,
            method, url, status_code, outcome, api_kind, downstream_tls, upstream_tls
        )
        VALUES (?, ?, 'wiki.corp.internal', 'u1', 'alice', ?, 'GET', '/reports?month=…(2)',
                200, 'completed', 'web', 'none', 'none')
        """,
        (request_id, conn_id, requested_at),
    )
    await db.commit()


async def _seed_web_activity(db) -> None:
    """One old (11 days) and one new (9 days) web connection with a request each."""
    old, new = _days_ago(_RETENTION_DAYS + 1), _days_ago(_RETENTION_DAYS - 1)
    await _insert_web_connection(db, "old-web-conn", _sqlite_now_format(old))
    await _insert_web_connection(db, "new-web-conn", _sqlite_now_format(new))
    await _insert_web_request(db, "old-web-req", "old-web-conn", _requested_at(old))
    await _insert_web_request(db, "new-web-req", "new-web-conn", _requested_at(new))


async def test_age_purge_removes_old_web_rows_and_their_connections(
    repo: SessionRepository, cast_store: CastStore, activity_store: ActivityStore, db
) -> None:
    await _seed_web_activity(db)
    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=_RETENTION_DAYS, retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()

    assert await _table_count(db, "api_requests", "request_id", "old-web-req") == 0
    assert await _table_count(db, "connections", "conn_id", "old-web-conn") == 0
    assert await _table_count(db, "api_requests", "request_id", "new-web-req") == 1
    assert await _table_count(db, "connections", "conn_id", "new-web-conn") == 1
    # The surviving connection keeps its snapshot untouched.
    cur = await db.execute(
        "SELECT resource_type, gwops_match, gwops_app, downstream_tls, upstream_port "
        "FROM connections WHERE conn_id = 'new-web-conn'"
    )
    assert tuple(await cur.fetchone()) == ("WEB_APP", "exact", "Legacy Wiki", "none", 8080)


async def test_age_purge_removes_old_empty_web_connections(
    repo: SessionRepository, cast_store: CastStore, activity_store: ActivityStore, db
) -> None:
    """A hidden `empty` WEB_APP connection has no requests and no session: age still purges it."""
    old, new = _days_ago(_RETENTION_DAYS + 1), _days_ago(_RETENTION_DAYS - 1)
    await _insert_web_connection(db, "old-empty", _sqlite_now_format(old), state="empty")
    await _insert_web_connection(db, "new-empty", _sqlite_now_format(new), state="empty")
    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=_RETENTION_DAYS, retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()
    assert await _table_count(db, "connections", "conn_id", "old-empty") == 0
    assert await _table_count(db, "connections", "conn_id", "new-empty") == 1


async def test_age_purge_leaves_kubectl_and_web_rows_on_the_same_side_of_the_cutoff_alike(
    repo: SessionRepository, cast_store: CastStore, activity_store: ActivityStore, db
) -> None:
    await _seed_activity(db)
    await _seed_web_activity(db)
    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=_RETENTION_DAYS, retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()

    cur = await db.execute("SELECT request_id, api_kind FROM api_requests ORDER BY request_id")
    assert [tuple(r) for r in await cur.fetchall()] == [("new-req", "kubectl"), ("new-web-req", "web")]
    cur = await db.execute("SELECT conn_id FROM connections ORDER BY conn_id")
    assert [r[0] for r in await cur.fetchall()] == ["new-conn", "new-web-conn"]
    assert await _table_count(db, "api_findings", "request_id", "old-req") == 0
    assert await _table_count(db, "api_findings", "request_id", "new-req") == 1


async def test_age_purge_removes_a_future_dated_web_row_by_its_server_insert_time(
    repo: SessionRepository, cast_store: CastStore, activity_store: ActivityStore, db
) -> None:
    """The created_at bound that stops a forged future requested_at pinning a kubectl row applies to web rows."""
    old = _days_ago(_RETENTION_DAYS + 1)
    await _insert_web_connection(db, "forged-conn", _sqlite_now_format(old))
    await _insert_web_request(db, "forged-web-req", "forged-conn", "9999-01-01T00:00:00.000Z")
    await db.execute(
        "UPDATE api_requests SET created_at = ? WHERE request_id = 'forged-web-req'",
        (_sqlite_now_format(old),),
    )
    await db.commit()
    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=_RETENTION_DAYS, retention_max_gb=0,
        activity=activity_store,
    )
    await purger.run()
    assert await _table_count(db, "api_requests", "request_id", "forged-web-req") == 0


async def test_size_purge_leaves_web_rows_and_connections(
    repo: SessionRepository, cast_store: CastStore, activity_store: ActivityStore, db
) -> None:
    """Size-based purge only trims recordings: web rows and their connections stay."""
    await _seed_web_activity(db)
    purger = RetentionPurger(
        repo=repo, casts=cast_store, retention_days=0, retention_max_gb=0.000001,
        activity=activity_store,
    )
    await purger.run()
    assert await _table_count(db, "api_requests", "request_id", "old-web-req") == 1
    assert await _table_count(db, "connections", "conn_id", "old-web-conn") == 1
