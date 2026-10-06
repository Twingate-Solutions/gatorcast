"""Schema/migration tests: Session 8 findings, Session 9 tables + v1 migration,
Session 10 indexes, SQL fragments, and the ``gc_is_discovery`` SQL function."""

import sqlite3

import aiosqlite
import pytest

from gatorcast.db import (
    CMD_KEY_SQL,
    FAILED_SQL,
    SCHEMA_VERSION,
    SESSION_AT_SQL,
    cmd_key,
    connect,
    init_db,
    session_at,
)
from gatorcast.pipeline.activity import is_discovery


@pytest.mark.asyncio
async def test_new_table_and_columns(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        cur = await db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
        names = {r["name"] for r in await cur.fetchall()}
        assert "findings" in names
        assert "session_text" not in names  # sidecar model: no FTS5 table
        cols = {
            r["name"]
            for r in await (await db.execute("PRAGMA table_info(sessions)")).fetchall()
        }
        assert {"finding_count", "max_severity"} <= cols
        # findings is writable with the expected shape
        await db.execute(
            "INSERT INTO findings (conn_id, rule_id, category, severity, label, offset_seconds) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("c1", "recursive-delete", "dangerous-command", "high", "Recursive delete (rm -rf)", 1.5),
        )
        await db.commit()
        cur = await db.execute("SELECT conn_id, rule_id FROM findings WHERE conn_id = ?", ("c1",))
        row = await cur.fetchone()
        assert row["rule_id"] == "recursive-delete"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_migration_adds_columns_to_existing_db(tmp_path):
    # Simulate a pre-Session-8 DB: a sessions table without the new columns.
    path = tmp_path / "old.db"
    conn = await aiosqlite.connect(path)
    await conn.execute("CREATE TABLE sessions (conn_id TEXT PRIMARY KEY, status TEXT)")
    await conn.commit()
    await conn.close()
    db = await init_db(path)  # must add columns idempotently, not crash
    try:
        cols = {
            r[1]
            for r in await (await db.execute("PRAGMA table_info(sessions)")).fetchall()
        }
        assert {"finding_count", "max_severity"} <= cols
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_init_db_is_idempotent(tmp_path):
    path = tmp_path / "gatorcast.db"
    db = await init_db(path)
    await db.close()
    db = await init_db(path)  # second call must not raise (IF NOT EXISTS + guarded ALTER)
    try:
        cols = {
            r[1]
            for r in await (await db.execute("PRAGMA table_info(sessions)")).fetchall()
        }
        assert {"finding_count", "max_severity"} <= cols
    finally:
        await db.close()


# --- Session 9: connections / api_requests / api_findings, sessions.request_id ---

_LEGACY_SESSIONS_DDL = """
CREATE TABLE sessions (
    conn_id          TEXT PRIMARY KEY,
    username         TEXT,
    resource_address TEXT,
    shell_user       TEXT,
    started_at       TEXT,
    ended_at         TEXT,
    duration_seconds REAL,
    width            INTEGER,
    height           INTEGER,
    chunk_count      INTEGER DEFAULT 0,
    size_bytes       INTEGER DEFAULT 0,
    cast_path        TEXT,
    status           TEXT DEFAULT 'provisional',
    created_at       TEXT DEFAULT (datetime('now')),
    updated_at       TEXT DEFAULT (datetime('now'))
)
"""

_EXPECTED_INDEXES = {
    # findings (pre-existing)
    "idx_findings_conn",
    "idx_findings_category",
    "idx_findings_severity",
    # connections
    "idx_connections_state_seen",
    "idx_connections_created",
    # api_requests
    "idx_api_req_sys_time",
    "idx_api_req_sys_user_time",
    "idx_api_req_conn",
    "idx_api_req_session",
    "idx_api_req_time",
    # api_requests, Session 10 (spec §7.1)
    "idx_api_req_cmd",
    "idx_api_req_user_time",
    "idx_api_req_userid_time",
    # api_findings
    "idx_api_findings_request",
    "idx_api_findings_severity",
    # sessions
    "idx_sessions_resource",
    "idx_sessions_started",
    "idx_sessions_status",
    "idx_sessions_request",
    "idx_sessions_at",  # Session 10 (spec §7.1)
}


async def _names(db, kind: str) -> set[str]:
    """Names of all sqlite_master objects of ``kind`` ('table' or 'index')."""
    cur = await db.execute("SELECT name FROM sqlite_master WHERE type = ?", (kind,))
    return {r[0] for r in await cur.fetchall()}


async def _user_version(db) -> int:
    cur = await db.execute("PRAGMA user_version")
    row = await cur.fetchone()
    return int(row[0])


async def _make_legacy_db(path, rows: list[tuple]) -> None:
    """Create a pre-Session-9 DB (user_version 0, no request_id column) with ``rows``.

    Each row is ``(conn_id, username, resource_address, started_at, status,
    chunk_count, size_bytes, cast_path, created_at)``.
    """
    conn = await aiosqlite.connect(path)
    try:
        await conn.execute(_LEGACY_SESSIONS_DDL)
        await conn.executemany(
            "INSERT INTO sessions (conn_id, username, resource_address, started_at, status, "
            "chunk_count, size_bytes, cast_path, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            rows,
        )
        await conn.commit()
    finally:
        await conn.close()


async def _ids(db, table: str) -> set[str]:
    cur = await db.execute(f"SELECT conn_id FROM {table}")  # noqa: S608 - fixed literals
    return {r[0] for r in await cur.fetchall()}


@pytest.mark.asyncio
async def test_session9_tables_and_columns_exist(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        tables = await _names(db, "table")
        assert {"connections", "api_requests", "api_findings"} <= tables

        async def cols(table: str) -> set[str]:
            cur = await db.execute(f"PRAGMA table_info({table})")  # noqa: S608 - fixed literals
            return {r[1] for r in await cur.fetchall()}

        assert await cols("connections") == {
            "conn_id", "user_id", "username", "resource_address", "started_at",
            "state", "has_api", "created_at", "last_seen_at",
        }
        assert await cols("api_requests") == {
            "request_id", "conn_id", "resource_address", "user_key", "user_id",
            "username", "requested_at", "method", "url", "status_code", "outcome",
            "kubectl_command", "kubectl_session", "user_agent", "created_at",
        }
        assert await cols("api_findings") == {
            "id", "request_id", "rule_id", "category", "severity", "label", "created_at",
        }
        assert "request_id" in await cols("sessions")
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_all_20_indexes_exist(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        cur = await db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'"
        )
        indexes = {r[0] for r in await cur.fetchall()}
        assert indexes == _EXPECTED_INDEXES
        assert len(indexes) == 20
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_composite_indexes_cover_expected_columns(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        async def index_cols(name: str) -> list[str]:
            cur = await db.execute(f"PRAGMA index_info({name})")  # noqa: S608 - fixed literals
            return [r[2] for r in sorted(await cur.fetchall(), key=lambda r: r[0])]

        assert await index_cols("idx_api_req_sys_time") == ["resource_address", "requested_at"]
        assert await index_cols("idx_api_req_sys_user_time") == [
            "resource_address", "user_key", "requested_at",
        ]
        assert await index_cols("idx_connections_state_seen") == ["state", "last_seen_at"]
        assert await index_cols("idx_sessions_request") == ["request_id"]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_connections_defaults(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        await db.execute("INSERT INTO connections (conn_id) VALUES ('c1')")
        await db.commit()
        cur = await db.execute("SELECT * FROM connections WHERE conn_id = 'c1'")
        row = await cur.fetchone()
        assert row["state"] == "pending"
        assert row["has_api"] == 0
        assert row["created_at"] is not None
        assert row["last_seen_at"] is not None
        assert row["user_id"] is None and row["resource_address"] is None
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_api_requests_primary_key_dedups_and_defaults(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        sql = (
            "INSERT INTO api_requests (request_id, conn_id, requested_at, method, url) "
            "VALUES (?, 'c1', '2026-10-01T10:00:00.000Z', 'GET', '/api')"
        )
        await db.execute(sql, ("r1",))
        await db.commit()
        with pytest.raises(sqlite3.IntegrityError):
            await db.execute(sql, ("r1",))
        await db.rollback()
        # INSERT OR IGNORE is the dedup path the store uses: rowcount tells new vs duplicate
        cur = await db.execute(sql.replace("INSERT INTO", "INSERT OR IGNORE INTO"), ("r1",))
        assert cur.rowcount == 0
        cur = await db.execute(sql.replace("INSERT INTO", "INSERT OR IGNORE INTO"), ("r2",))
        assert cur.rowcount == 1
        await db.commit()
        cur = await db.execute("SELECT outcome FROM api_requests WHERE request_id = 'r1'")
        assert (await cur.fetchone())["outcome"] == "completed"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_api_requests_not_null_columns_enforced(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        for missing_sql in (
            # no conn_id
            "INSERT INTO api_requests (request_id, requested_at, method, url) "
            "VALUES ('r', 't', 'GET', '/')",
            # no requested_at
            "INSERT INTO api_requests (request_id, conn_id, method, url) "
            "VALUES ('r', 'c', 'GET', '/')",
            # no method
            "INSERT INTO api_requests (request_id, conn_id, requested_at, url) "
            "VALUES ('r', 'c', 't', '/')",
            # no url
            "INSERT INTO api_requests (request_id, conn_id, requested_at, method) "
            "VALUES ('r', 'c', 't', 'GET')",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                await db.execute(missing_sql)
            await db.rollback()
    finally:
        await db.close()


async def _seed_request_with_findings(db, request_id: str, n_findings: int) -> None:
    await db.execute(
        "INSERT INTO api_requests (request_id, conn_id, requested_at, method, url) "
        "VALUES (?, 'c1', '2026-10-01T10:00:00.000Z', 'DELETE', '/api/v1/pods/p')",
        (request_id,),
    )
    for i in range(n_findings):
        await db.execute(
            "INSERT INTO api_findings (request_id, rule_id, category, severity, label) "
            "VALUES (?, ?, 'kube-api', 'high', 'x')",
            (request_id, f"rule-{i}"),
        )
    await db.commit()


@pytest.mark.asyncio
async def test_api_findings_cascade_on_request_delete(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        await _seed_request_with_findings(db, "r1", 2)
        await _seed_request_with_findings(db, "r2", 1)

        await db.execute("DELETE FROM api_requests WHERE request_id = 'r1'")
        await db.commit()

        cur = await db.execute("SELECT request_id, COUNT(*) AS n FROM api_findings GROUP BY request_id")
        remaining = {r["request_id"]: r["n"] for r in await cur.fetchall()}
        assert remaining == {"r2": 1}  # r1's findings gone, r2's untouched
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_api_findings_cascade_on_bulk_purge(tmp_path):
    """A retention-style ``DELETE ... WHERE requested_at < ?`` cascades to findings."""
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        await _seed_request_with_findings(db, "old", 2)
        await db.execute(
            "UPDATE api_requests SET requested_at = '2020-01-01T00:00:00.000Z' WHERE request_id = 'old'"
        )
        await _seed_request_with_findings(db, "new", 1)
        await db.execute("DELETE FROM api_requests WHERE requested_at < '2025-01-01'")
        await db.commit()
        cur = await db.execute("SELECT DISTINCT request_id FROM api_findings")
        assert {r[0] for r in await cur.fetchall()} == {"new"}
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_api_findings_require_existing_request(tmp_path):
    """The FK is enforced: a finding cannot reference a request that does not exist."""
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            await db.execute(
                "INSERT INTO api_findings (request_id, rule_id, category, severity, label) "
                "VALUES ('ghost', 'kube-delete', 'kube-api', 'high', 'x')"
            )
    finally:
        await db.rollback()
        await db.close()


@pytest.mark.asyncio
async def test_fresh_db_sets_user_version_1(tmp_path):
    path = tmp_path / "gatorcast.db"
    db = await init_db(path)
    try:
        assert await _user_version(db) == 1
    finally:
        await db.close()
    # persisted on disk, not just on the live connection
    db = await init_db(path)
    try:
        assert await _user_version(db) == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_upgrade_adds_request_id_column_and_index(tmp_path):
    """A pre-Session-9 sessions table gains request_id (NULL) and its index."""
    path = tmp_path / "old.db"
    await _make_legacy_db(
        path,
        [("keep", "u", "h", "2026-01-01T00:00:00Z", "complete", 3, 100, "/data/keep.cast", "2026-01-01 00:00:00")],
    )
    db = await init_db(path)
    try:
        cur = await db.execute("PRAGMA table_info(sessions)")
        assert "request_id" in {r[1] for r in await cur.fetchall()}
        cur = await db.execute("SELECT request_id FROM sessions WHERE conn_id = 'keep'")
        assert (await cur.fetchone())["request_id"] is None
        assert "idx_sessions_request" in await _names(db, "index")
    finally:
        await db.close()


# --- Session 10 T11: sessions.sealed_terminal ----------------------------------


async def _session_cols(db) -> set[str]:
    cur = await db.execute("PRAGMA table_info(sessions)")
    return {r[1] for r in await cur.fetchall()}


@pytest.mark.asyncio
async def test_fresh_db_has_sealed_terminal_column(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        assert "sealed_terminal" in await _session_cols(db)
        assert await _user_version(db) == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_upgrade_adds_sealed_terminal_without_version_bump(tmp_path):
    """A legacy sessions table gains sealed_terminal (NULL on old rows); a second
    init_db is a no-op; user_version stays 1."""
    path = tmp_path / "old.db"
    await _make_legacy_db(
        path,
        [("sealed", "u", "h", "2026-01-01T00:00:00Z", "complete", 3, 100, "/data/sealed.cast", "2026-01-01 00:00:00")],
    )
    db = await init_db(path)
    try:
        assert "sealed_terminal" in await _session_cols(db)
        cur = await db.execute("SELECT sealed_terminal FROM sessions WHERE conn_id = 'sealed'")
        assert (await cur.fetchone())["sealed_terminal"] is None  # legacy: unknown mode
        assert await _user_version(db) == 1
    finally:
        await db.close()

    db = await init_db(path)  # second boot: guarded ALTER must not re-run or raise
    try:
        cur = await db.execute("PRAGMA table_info(sessions)")
        names = [r[1] for r in await cur.fetchall()]
        assert names.count("sealed_terminal") == 1
        assert await _user_version(db) == 1
    finally:
        await db.close()
    assert SCHEMA_VERSION == 1


# --- one-time migration: start-only sessions rows -> connections (spec §11) ---

# (conn_id, username, resource_address, started_at, status, chunk_count, size_bytes, cast_path, created_at)
_MOVED_PROVISIONAL = (
    "start-prov", "alice@example.com", "k8s.example.internal",
    "2026-09-01T10:00:00Z", "provisional", 0, 0, None, "2026-09-01 10:00:01",
)
_MOVED_ERROR = (
    "start-err", "bob@example.com", "ssh.example.internal",
    "2026-09-02T11:00:00Z", "error", 0, 0, None, "2026-09-02 11:00:01",
)
_MOVED_NULL_COUNTS = (
    "start-null", "carol@example.com", "k8s.example.internal",
    "2026-09-03T12:00:00Z", "provisional", None, None, None, "2026-09-03 12:00:01",
)
_KEPT_ROWS = [
    # recording in progress: has chunks + a cast file
    ("rec-prov", "u1", "h1", "2026-09-04T00:00:00Z", "provisional", 2, 512, "/data/casts/rec-prov.cast", "2026-09-04 00:00:00"),
    # sealed recording
    ("rec-done", "u2", "h2", "2026-09-05T00:00:00Z", "complete", 5, 4096, "/data/casts/rec-done.cast", "2026-09-05 00:00:00"),
    # errored but data-bearing (chunks + file)
    ("rec-err", "u3", "h3", "2026-09-06T00:00:00Z", "error", 1, 64, "/data/casts/rec-err.cast", "2026-09-06 00:00:00"),
    # each single data signal is enough to keep a row
    ("only-chunks", "u4", "h4", "2026-09-07T00:00:00Z", "provisional", 1, 0, None, "2026-09-07 00:00:00"),
    ("only-castpath", "u5", "h5", "2026-09-08T00:00:00Z", "provisional", 0, 0, "/data/casts/only-castpath.cast", "2026-09-08 00:00:00"),
    ("only-size", "u6", "h6", "2026-09-09T00:00:00Z", "error", 0, 10, None, "2026-09-09 00:00:00"),
    # empty but already complete: not a start-only row (status gate)
    ("empty-complete", "u7", "h7", "2026-09-10T00:00:00Z", "complete", 0, 0, None, "2026-09-10 00:00:00"),
]


@pytest.mark.asyncio
async def test_migration_moves_start_only_rows(tmp_path):
    path = tmp_path / "old.db"
    await _make_legacy_db(path, [_MOVED_PROVISIONAL, _MOVED_ERROR, _MOVED_NULL_COUNTS, *_KEPT_ROWS])

    db = await init_db(path)
    try:
        assert await _ids(db, "connections") == {"start-prov", "start-err", "start-null"}
        assert await _ids(db, "sessions") == {r[0] for r in _KEPT_ROWS}
        assert await _user_version(db) == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_migration_preserves_fields_and_marks_error(tmp_path):
    path = tmp_path / "old.db"
    await _make_legacy_db(path, [_MOVED_PROVISIONAL, _MOVED_ERROR])

    db = await init_db(path)
    try:
        cur = await db.execute("SELECT * FROM connections ORDER BY conn_id")
        rows = {r["conn_id"]: r for r in await cur.fetchall()}
        prov = rows["start-prov"]
        assert prov["username"] == "alice@example.com"
        assert prov["resource_address"] == "k8s.example.internal"
        assert prov["started_at"] == "2026-09-01T10:00:00Z"
        assert prov["created_at"] == "2026-09-01 10:00:01"
        assert prov["state"] == "error"  # even though it was 'provisional'
        assert prov["has_api"] == 0
        assert prov["last_seen_at"] is not None
        assert prov["user_id"] is None  # sessions never stored it

        err = rows["start-err"]
        assert err["state"] == "error"
        assert err["username"] == "bob@example.com"
        assert err["resource_address"] == "ssh.example.internal"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_migration_leaves_data_bearing_rows_untouched(tmp_path):
    path = tmp_path / "old.db"
    await _make_legacy_db(path, [*_KEPT_ROWS])

    db = await init_db(path)
    try:
        assert await _ids(db, "connections") == set()
        cur = await db.execute(
            "SELECT conn_id, username, status, chunk_count, size_bytes, cast_path "
            "FROM sessions ORDER BY conn_id"
        )
        got = [tuple(r) for r in await cur.fetchall()]
        want = sorted((r[0], r[1], r[4], r[5], r[6], r[7]) for r in _KEPT_ROWS)
        assert got == want
        assert await _user_version(db) == 1  # version still bumped with nothing to move
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_migration_runs_only_once(tmp_path):
    """After v1, a start-only 'error' row (what the pending backstop creates) survives reboot."""
    path = tmp_path / "old.db"
    await _make_legacy_db(path, [_MOVED_ERROR])

    db = await init_db(path)  # migrates: start-err moves to connections
    try:
        assert await _ids(db, "sessions") == set()
        assert await _ids(db, "connections") == {"start-err"}
        # Post-upgrade the backstop deliberately writes start-only visible error rows.
        await db.execute(
            "INSERT INTO sessions (conn_id, username, resource_address, status) "
            "VALUES ('backstop-err', 'dave@example.com', 'h', 'error')"
        )
        await db.commit()
    finally:
        await db.close()

    db = await init_db(path)  # second boot must NOT re-run the migration
    try:
        assert await _ids(db, "sessions") == {"backstop-err"}
        assert await _ids(db, "connections") == {"start-err"}
        assert await _user_version(db) == 1
    finally:
        await db.close()

    db = await init_db(path)  # and a third, for good measure
    try:
        assert await _ids(db, "sessions") == {"backstop-err"}
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_migration_skipped_when_version_already_1(tmp_path):
    """A DB already stamped user_version=1 is never migrated, even if it has start-only rows."""
    path = tmp_path / "stamped.db"
    await _make_legacy_db(path, [_MOVED_PROVISIONAL])
    conn = await aiosqlite.connect(path)
    await conn.execute("PRAGMA user_version = 1")
    await conn.commit()
    await conn.close()

    db = await init_db(path)
    try:
        assert await _ids(db, "sessions") == {"start-prov"}
        assert await _ids(db, "connections") == set()
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_migration_handles_minimal_legacy_sessions_table(tmp_path):
    """A sessions table with only (conn_id, status) migrates: absent columns count as defaults."""
    path = tmp_path / "minimal.db"
    conn = await aiosqlite.connect(path)
    await conn.execute("CREATE TABLE sessions (conn_id TEXT PRIMARY KEY, status TEXT)")
    await conn.executemany(
        "INSERT INTO sessions (conn_id, status) VALUES (?, ?)",
        [("p", "provisional"), ("e", "error"), ("c", "complete")],
    )
    await conn.commit()
    await conn.close()

    db = await init_db(path)
    try:
        assert await _ids(db, "connections") == {"p", "e"}
        assert await _ids(db, "sessions") == {"c"}
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_migration_does_not_touch_findings(tmp_path):
    """Moving a start-only session leaves unrelated findings rows alone."""
    path = tmp_path / "old.db"
    await _make_legacy_db(path, [_MOVED_PROVISIONAL, *_KEPT_ROWS[:1]])
    db = await init_db(path)
    try:
        await db.execute(
            "INSERT INTO findings (conn_id, rule_id, category, severity, label) "
            "VALUES ('rec-prov', 'r', 'c', 'high', 'l')"
        )
        await db.commit()
    finally:
        await db.close()
    db = await init_db(path)
    try:
        cur = await db.execute("SELECT COUNT(*) FROM findings")
        assert (await cur.fetchone())[0] == 1
    finally:
        await db.close()


# --- v1 migration keeps rows whose recording is already on disk (security P2) ---

_CRASHED_PROVISIONAL = (
    # A recording whose plaintext .cast was written just before a crash, between
    # write_plaintext and update_progress: its metadata still looks start-only.
    "crash-prov", "erin@example.com", "ssh.example.internal",
    "2026-09-11T09:00:00Z", "provisional", 0, 0, None, "2026-09-11 09:00:01",
)


@pytest.mark.asyncio
async def test_migration_keeps_start_only_row_with_cast_on_disk(tmp_path):
    """A start-only-looking row with <conn_id>.cast on disk stays in sessions, so
    the secret-grade plaintext file stays under the sweep and retention."""
    path = tmp_path / "old.db"
    casts_dir = tmp_path / "casts"
    casts_dir.mkdir()
    cast_file = casts_dir / "crash-prov.cast"
    cast_file.write_bytes(b'{"version":2,"width":80,"height":24}\n[0.1,"o","x"]\n')
    await _make_legacy_db(path, [_MOVED_PROVISIONAL, _MOVED_ERROR, _CRASHED_PROVISIONAL])

    db = await init_db(path, casts_dir=casts_dir)
    try:
        assert await _ids(db, "sessions") == {"crash-prov"}
        assert await _ids(db, "connections") == {"start-prov", "start-err"}
        assert await _user_version(db) == 1
    finally:
        await db.close()
    assert cast_file.read_bytes().startswith(b'{"version":2')  # file untouched


@pytest.mark.asyncio
async def test_migration_keeps_start_only_row_with_sidecar_on_disk(tmp_path):
    """A <conn_id>.txt.enc sidecar alone is enough to keep the row."""
    path = tmp_path / "old.db"
    casts_dir = tmp_path / "casts"
    casts_dir.mkdir()
    (casts_dir / "crash-prov.txt.enc").write_bytes(b"plaintext sidecar")
    await _make_legacy_db(path, [_MOVED_PROVISIONAL, _CRASHED_PROVISIONAL])

    db = await init_db(path, casts_dir=casts_dir)
    try:
        assert await _ids(db, "sessions") == {"crash-prov"}
        assert await _ids(db, "connections") == {"start-prov"}
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_migration_with_casts_dir_still_moves_rows_without_files(tmp_path):
    """Files for other conn_ids do not keep a row; a missing casts dir is fine."""
    for casts_dir in (tmp_path / "casts", tmp_path / "does-not-exist"):
        path = tmp_path / f"old-{casts_dir.name}.db"
        if casts_dir.name == "casts":
            casts_dir.mkdir()
            (casts_dir / "someone-else.cast").write_bytes(b"x")
        await _make_legacy_db(path, [_MOVED_PROVISIONAL, _MOVED_ERROR, _MOVED_NULL_COUNTS])

        db = await init_db(path, casts_dir=casts_dir)
        try:
            assert await _ids(db, "sessions") == set()
            assert await _ids(db, "connections") == {"start-prov", "start-err", "start-null"}
        finally:
            await db.close()


@pytest.mark.asyncio
async def test_migration_keeps_row_with_unsafe_conn_id_and_never_follows_it(tmp_path):
    """A conn_id that fails the safe-token check is never turned into a path: the
    row is kept (fail-safe) and a file outside casts_dir is not consulted."""
    path = tmp_path / "old.db"
    casts_dir = tmp_path / "casts"
    casts_dir.mkdir()
    outside = tmp_path / "evil.cast"
    outside.write_bytes(b"outside the casts dir")
    unsafe = ("../evil", None, None, None, "provisional", 0, 0, None, "2026-09-12 00:00:00")
    await _make_legacy_db(path, [_MOVED_PROVISIONAL, unsafe])

    db = await init_db(path, casts_dir=casts_dir)
    try:
        assert await _ids(db, "sessions") == {"../evil"}
        assert await _ids(db, "connections") == {"start-prov"}
    finally:
        await db.close()
    assert outside.read_bytes() == b"outside the casts dir"


@pytest.mark.asyncio
async def test_migration_without_casts_dir_skips_file_check(tmp_path):
    """Without casts_dir (tests only) the migration keeps its metadata-only rule."""
    path = tmp_path / "old.db"
    casts_dir = tmp_path / "casts"
    casts_dir.mkdir()
    (casts_dir / "crash-prov.cast").write_bytes(b"x")
    await _make_legacy_db(path, [_CRASHED_PROVISIONAL])

    db = await init_db(path)
    try:
        assert await _ids(db, "sessions") == set()
        assert await _ids(db, "connections") == {"crash-prov"}
    finally:
        await db.close()


# --- Session 10 T1: indexes, SQL fragments, gc_is_discovery (spec §7.1–§7.3) ---

_SESSION10_INDEXES = {"idx_api_req_cmd", "idx_api_req_user_time", "idx_api_req_userid_time", "idx_sessions_at"}

# SQLITE_DETERMINISTIC, as reported in the flags column of PRAGMA function_list.
_SQLITE_DETERMINISTIC = 0x800


async def _index_info(db, name: str) -> list[str | None]:
    """Key columns of index ``name`` in order; ``None`` marks an expression column."""
    cur = await db.execute(f"PRAGMA index_info({name})")  # noqa: S608 - fixed literals
    return [r[2] for r in sorted(await cur.fetchall(), key=lambda r: r[0])]


async def _index_sql(db, name: str) -> str:
    cur = await db.execute("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", (name,))
    return (await cur.fetchone())[0]


async def _plan(db, sql: str, params: tuple = ()) -> str:
    """The ``EXPLAIN QUERY PLAN`` detail lines of ``sql``, joined."""
    cur = await db.execute("EXPLAIN QUERY PLAN " + sql, params)
    return " | ".join(r[3] for r in await cur.fetchall())


async def _schema_snapshot(db) -> set[tuple]:
    cur = await db.execute("SELECT type, name, tbl_name, sql FROM sqlite_master")
    return {tuple(r) for r in await cur.fetchall()}


@pytest.mark.asyncio
async def test_session10_indexes_have_expected_keys(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        assert _SESSION10_INDEXES <= await _names(db, "index")
        assert await _index_info(db, "idx_api_req_cmd") == [None, "requested_at", "request_id"]
        assert await _index_info(db, "idx_api_req_user_time") == ["username", "requested_at", "request_id"]
        assert await _index_info(db, "idx_api_req_userid_time") == ["user_id", "requested_at", "request_id"]
        assert await _index_info(db, "idx_sessions_at") == [None, "conn_id"]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_expression_indexes_are_built_from_the_shared_fragments(tmp_path):
    """The index DDL reproduces the fragments exactly, so cmd_key()/session_at() match."""
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        assert cmd_key() in await _index_sql(db, "idx_api_req_cmd")
        assert session_at() in await _index_sql(db, "idx_sessions_at")
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_second_init_db_is_a_noop(tmp_path):
    """A second boot changes no schema object and leaves user_version at 1 (no bump)."""
    path = tmp_path / "gatorcast.db"
    db = await init_db(path)
    try:
        before = await _schema_snapshot(db)
        assert await _user_version(db) == 1
    finally:
        await db.close()
    db = await init_db(path)
    try:
        assert await _schema_snapshot(db) == before
        assert await _user_version(db) == 1
    finally:
        await db.close()
    assert SCHEMA_VERSION == 1


@pytest.mark.asyncio
async def test_legacy_sessions_without_started_at_skips_idx_sessions_at(tmp_path):
    """idx_sessions_at is guarded on started_at; its absence must not crash init_db."""
    path = tmp_path / "minimal.db"
    conn = await aiosqlite.connect(path)
    await conn.execute("CREATE TABLE sessions (conn_id TEXT PRIMARY KEY, status TEXT)")
    await conn.commit()
    await conn.close()

    db = await init_db(path)
    try:
        indexes = await _names(db, "index")
        assert "idx_sessions_at" not in indexes
        assert "idx_sessions_started" not in indexes
        # indexes on present columns, and the api_requests indexes, are still built
        assert {"idx_sessions_status", "idx_sessions_request"} <= indexes
        assert {"idx_api_req_cmd", "idx_api_req_user_time", "idx_api_req_userid_time"} <= indexes
        assert await _user_version(db) == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_legacy_sessions_with_started_at_gains_idx_sessions_at(tmp_path):
    path = tmp_path / "old.db"
    await _make_legacy_db(path, [_KEPT_ROWS[1]])
    db = await init_db(path)
    try:
        assert "idx_sessions_at" in await _names(db, "index")
        assert await _user_version(db) == 1
    finally:
        await db.close()


def test_fragment_helpers_render_aliases():
    assert cmd_key() == CMD_KEY_SQL.format(a="")
    assert session_at() == SESSION_AT_SQL.format(a="")
    assert cmd_key("q") == CMD_KEY_SQL.format(a="q.")
    assert "q.kubectl_session" in cmd_key("q") and "q.conn_id" in cmd_key("q")
    assert "{a}" not in cmd_key("q")
    assert session_at("s") == (
        "strftime('%Y-%m-%dT%H:%M:%fZ', COALESCE(s.started_at, s.created_at))"
    )


@pytest.mark.parametrize("alias", ["q.x", "q; DROP TABLE sessions", "1q", "q r", "q--"])
def test_fragment_helpers_reject_non_identifier_aliases(alias):
    with pytest.raises(ValueError):
        cmd_key(alias)
    with pytest.raises(ValueError):
        session_at(alias)


async def _insert_api(db, request_id: str, conn_id: str, session: str | None, at: str) -> None:
    await db.execute(
        "INSERT INTO api_requests (request_id, conn_id, kubectl_session, requested_at, method, url) "
        "VALUES (?, ?, ?, ?, 'GET', '/api/v1/pods')",
        (request_id, conn_id, session, at),
    )


@pytest.mark.asyncio
async def test_cmd_key_values_and_index_use(tmp_path):
    """Header when non-empty (s:), else the connection (c:); a c:-shaped header never
    collides with a connection; an aliased query is served by idx_api_req_cmd."""
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        await _insert_api(db, "r-sess", "conn-1", "S1", "2026-10-01T10:00:00.000Z")
        await _insert_api(db, "r-null", "conn-1", None, "2026-10-01T10:00:01.000Z")
        await _insert_api(db, "r-empty", "conn-1", "", "2026-10-01T10:00:02.000Z")
        await _insert_api(db, "r-spoof", "conn-2", "c:conn-1", "2026-10-01T10:00:03.000Z")
        await db.commit()

        cur = await db.execute(f"SELECT request_id, {cmd_key('q')} AS k FROM api_requests q")
        keys = {r["request_id"]: r["k"] for r in await cur.fetchall()}
        assert keys == {
            "r-sess": "s:S1",
            "r-null": "c:conn-1",
            "r-empty": "c:conn-1",
            "r-spoof": "s:c:conn-1",
        }

        sql = (
            f"SELECT q.request_id FROM api_requests q WHERE {cmd_key('q')} = ? "
            "ORDER BY q.requested_at, q.request_id"
        )
        assert "idx_api_req_cmd" in await _plan(db, sql, ("c:conn-1",))
        cur = await db.execute(sql, ("c:conn-1",))
        assert [r[0] for r in await cur.fetchall()] == ["r-null", "r-empty"]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_session_at_normalizes_to_requested_at_format(tmp_path):
    """Every stored started_at shape and the created_at fallback render as
    YYYY-MM-DDTHH:MM:SS.mmmZ, fixing the boundary-second string mis-order."""
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        rows = [
            ("ms", "2026-10-01T10:00:01.250Z", "2026-10-01 10:00:09"),
            ("whole", "2026-10-01T10:00:01Z", "2026-10-01 10:00:09"),
            ("nanos", "2026-10-01T10:00:01.123456789Z", "2026-10-01 10:00:09"),
            ("fallback", None, "2026-10-01 10:00:00"),
        ]
        await db.executemany(
            "INSERT INTO sessions (conn_id, started_at, created_at) VALUES (?, ?, ?)", rows
        )
        await db.commit()

        cur = await db.execute(f"SELECT s.conn_id, {session_at('s')} AS at FROM sessions s")
        got = {r["conn_id"]: r["at"] for r in await cur.fetchall()}
        assert got == {
            "ms": "2026-10-01T10:00:01.250Z",
            "whole": "2026-10-01T10:00:01.000Z",
            "nanos": "2026-10-01T10:00:01.123Z",
            "fallback": "2026-10-01T10:00:00.000Z",
        }

        sql = f"SELECT s.conn_id FROM sessions s ORDER BY {session_at('s')} DESC, s.conn_id DESC"
        assert "idx_sessions_at" in await _plan(db, sql)
        cur = await db.execute(sql)
        # raw strings would sort "…01.250Z" before "…01Z"; the normalized form does not
        assert [r[0] for r in await cur.fetchall()] == ["ms", "nanos", "whole", "fallback"]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_failed_sql_selects_only_failed_connections(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        # (conn_id, status, chunk_count, cast_path)
        rows = [
            ("failed", "error", 0, None),
            ("failed-null-count", "error", None, None),
            ("error-with-chunks", "error", 3, "/data/casts/error-with-chunks.cast"),
            ("error-with-cast", "error", 0, "/data/casts/error-with-cast.cast"),
            ("error-chunks-no-cast", "error", 1, None),
            ("empty-complete", "complete", 0, None),
            ("provisional", "provisional", 0, None),
        ]
        await db.executemany(
            "INSERT INTO sessions (conn_id, status, chunk_count, cast_path) VALUES (?, ?, ?, ?)", rows
        )
        await db.commit()
        cur = await db.execute(f"SELECT s.conn_id FROM sessions s WHERE {FAILED_SQL.format(a='s.')}")
        assert {r[0] for r in await cur.fetchall()} == {"failed", "failed-null-count"}
        cur = await db.execute(f"SELECT conn_id FROM sessions WHERE NOT {FAILED_SQL.format(a='')}")
        assert len(await cur.fetchall()) == len(rows) - 2
    finally:
        await db.close()


# The five spec §12 cases plus extra NULL / non-text shapes: (method, url, expected).
_DISCOVERY_CASES = [
    ("GET", "/api?timeout=32s", 1),
    ("GET", "/apis/apps/v1", 1),
    ("GET", "/api/v1/pods?limit=500", 0),
    ("POST", "/api", 0),
    (None, None, 0),
    (None, "/api", 0),
    ("GET", None, 0),
    (1, "/api", 0),
    ("GET", b"/api", 0),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "url", "expected"), _DISCOVERY_CASES)
async def test_gc_is_discovery_agrees_with_is_discovery(tmp_path, method, url, expected):
    """Registered by connect() itself (not only init_db); never raises; 0 for NULLs."""
    db = await connect(tmp_path / "plain.db")
    try:
        cur = await db.execute("SELECT gc_is_discovery(?, ?)", (method, url))
        got = (await cur.fetchone())[0]
        assert got == expected
        if isinstance(method, str) and isinstance(url, str):
            assert got == int(is_discovery(method, url))
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_gc_is_discovery_is_deterministic_and_works_over_rows(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        cur = await db.execute("PRAGMA function_list")
        flags = [r["flags"] for r in await cur.fetchall() if r["name"] == "gc_is_discovery"]
        assert flags and all(f & _SQLITE_DETERMINISTIC for f in flags)

        await db.execute(
            "INSERT INTO api_requests (request_id, conn_id, requested_at, method, url) VALUES "
            "('d1', 'c', '2026-10-01T10:00:00.000Z', 'GET', '/api?timeout=32s'), "
            "('d2', 'c', '2026-10-01T10:00:01.000Z', 'get', '/openapi/v2'), "
            "('n1', 'c', '2026-10-01T10:00:02.000Z', 'GET', '/api/v1/namespaces/default/pods'), "
            "('n2', 'c', '2026-10-01T10:00:03.000Z', 'DELETE', '/apis/apps/v1')"
        )
        await db.commit()
        cur = await db.execute(
            "SELECT request_id FROM api_requests WHERE gc_is_discovery(method, url) = 1"
        )
        assert {r[0] for r in await cur.fetchall()} == {"d1", "d2"}
    finally:
        await db.close()
