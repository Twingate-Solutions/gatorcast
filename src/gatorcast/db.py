"""SQLite connection management, schema initialization, and migrations.

WAL mode with synchronous=NORMAL for durable, concurrent-friendly metadata.
.cast recording payloads live on the volume, never in the database (CLAUDE.md rule 9).

Tables:
    sessions      — one row per recording (visible in the UI).
    findings      — cast-offset findings from the plaintext sidecar scan.
    connections   — hidden per-``conn_id`` connection state (pending | recording | api | error).
    api_requests  — allowlisted kubectl API-request metadata, deduplicated by ``request_id``.
    api_findings  — rule findings on API requests (cascade-deleted with their request).

Schema evolution:
    * ``CREATE TABLE/INDEX IF NOT EXISTS`` for new tables (idempotent every boot).
    * ``_ensure_columns`` adds columns to a pre-existing ``sessions`` table (idempotent).
    * ``PRAGMA user_version`` gates one-time data migrations that must never re-run.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import aiosqlite

from gatorcast.logging import get_logger
from gatorcast.pipeline.classify import _safe_conn_id

log = get_logger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    conn_id          TEXT PRIMARY KEY,
    username         TEXT,                          -- envelope user.username (identity)
    resource_address TEXT,                          -- target "system"
    shell_user       TEXT,                          -- asciicast header user (secondary)
    started_at       TEXT,                          -- ISO8601 (from start event / header)
    ended_at         TEXT,
    duration_seconds REAL,
    width            INTEGER,
    height           INTEGER,
    chunk_count      INTEGER DEFAULT 0,
    size_bytes       INTEGER DEFAULT 0,
    cast_path        TEXT,
    status           TEXT DEFAULT 'provisional',    -- provisional | complete | error
    finding_count    INTEGER DEFAULT 0,             -- number of sidecar findings for this session
    max_severity     TEXT,                          -- highest finding severity (low | medium | high | critical)
    request_id       TEXT,                          -- k8s exec/attach request_id (NULL for SSH)
    created_at       TEXT DEFAULT (datetime('now')),
    updated_at       TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    conn_id        TEXT NOT NULL,
    rule_id        TEXT NOT NULL,
    category       TEXT NOT NULL,
    severity       TEXT NOT NULL,
    label          TEXT NOT NULL,
    offset_seconds REAL,
    created_at     TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_findings_conn     ON findings(conn_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS connections (
    conn_id          TEXT PRIMARY KEY,
    user_id          TEXT,
    username         TEXT,
    resource_address TEXT,
    started_at       TEXT,                           -- ISO8601 from the start line
    state            TEXT NOT NULL DEFAULT 'pending',-- pending | recording | api | error
    has_api          INTEGER NOT NULL DEFAULT 0,     -- 1 once any audit line arrived
    created_at       TEXT DEFAULT (datetime('now')),
    last_seen_at     TEXT DEFAULT (datetime('now'))  -- drives the pending backstop
);
CREATE INDEX IF NOT EXISTS idx_connections_state_seen ON connections(state, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_connections_created    ON connections(created_at);

CREATE TABLE IF NOT EXISTS api_requests (
    request_id       TEXT PRIMARY KEY,               -- dedup key (at-least-once delivery)
    conn_id          TEXT NOT NULL,
    resource_address TEXT,                           -- cluster, from connections
    user_key         TEXT,                           -- user_id, else username
    user_id          TEXT,
    username         TEXT,
    requested_at     TEXT NOT NULL,                  -- "YYYY-MM-DDTHH:MM:SS.mmmZ"
    method           TEXT NOT NULL,
    url              TEXT NOT NULL,                  -- sanitized by _store_url
    status_code      INTEGER,
    outcome          TEXT NOT NULL DEFAULT 'completed',
    kubectl_command  TEXT,
    kubectl_session  TEXT,
    user_agent       TEXT,
    created_at       TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_api_req_sys_time      ON api_requests(resource_address, requested_at);
CREATE INDEX IF NOT EXISTS idx_api_req_sys_user_time ON api_requests(resource_address, user_key, requested_at);
CREATE INDEX IF NOT EXISTS idx_api_req_conn          ON api_requests(conn_id);
CREATE INDEX IF NOT EXISTS idx_api_req_session       ON api_requests(kubectl_session);
CREATE INDEX IF NOT EXISTS idx_api_req_time          ON api_requests(requested_at);

CREATE TABLE IF NOT EXISTS api_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id  TEXT NOT NULL REFERENCES api_requests(request_id) ON DELETE CASCADE,
    rule_id     TEXT NOT NULL,
    category    TEXT NOT NULL,                       -- 'kube-api'
    severity    TEXT NOT NULL,
    label       TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_api_findings_request  ON api_findings(request_id);
CREATE INDEX IF NOT EXISTS idx_api_findings_severity ON api_findings(severity);
"""

# Columns added to ``sessions`` after its first release. ``CREATE TABLE IF NOT EXISTS``
# never alters an existing table, so each is added with a guarded ``ALTER`` on boot.
SESSION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("finding_count", "ALTER TABLE sessions ADD COLUMN finding_count INTEGER DEFAULT 0"),
    ("max_severity", "ALTER TABLE sessions ADD COLUMN max_severity TEXT"),
    ("request_id", "ALTER TABLE sessions ADD COLUMN request_id TEXT"),
)

# Session indexes are created after _ensure_columns so they can reference columns
# that an upgraded-in-place (pre-Session-8) DB may have been missing. Each index is
# only created when its target column actually exists on the sessions table, so a
# minimal legacy table does not crash index creation.
SESSION_INDEXES: tuple[tuple[str, str], ...] = (
    ("resource_address", "CREATE INDEX IF NOT EXISTS idx_sessions_resource ON sessions(resource_address)"),
    ("started_at", "CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at)"),
    ("status", "CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)"),
    ("request_id", "CREATE INDEX IF NOT EXISTS idx_sessions_request ON sessions(request_id)"),
)

# Current data-migration level stored in ``PRAGMA user_version``.
#   0 → 1: move start-only ``sessions`` rows into ``connections`` (Session 9, spec §11).
SCHEMA_VERSION = 1


async def connect(db_path: Path) -> aiosqlite.Connection:
    """Open an aiosqlite connection with WAL pragmas and row factory set.

    Args:
        db_path: Filesystem path to the SQLite database file.

    Returns:
        An open aiosqlite connection.
    """
    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL;")
    await conn.execute("PRAGMA synchronous=NORMAL;")
    await conn.execute("PRAGMA foreign_keys=ON;")
    await conn.commit()
    return conn


async def _session_columns(conn: aiosqlite.Connection) -> set[str]:
    """Return the set of column names currently present on ``sessions``."""
    cur = await conn.execute("PRAGMA table_info(sessions)")
    existing = {row[1] for row in await cur.fetchall()}
    await cur.close()
    return existing


async def _ensure_columns(conn: aiosqlite.Connection) -> None:
    """Add later-release columns to a pre-existing ``sessions`` table (idempotent).

    ``CREATE TABLE IF NOT EXISTS`` will not alter an existing table, so a DB created
    before these columns existed needs an explicit, guarded ``ALTER``. Covers the
    Session 8 finding columns and the Session 9 ``request_id`` column.
    """
    existing = await _session_columns(conn)
    for col, ddl in SESSION_COLUMNS:
        if col not in existing:
            await conn.execute(ddl)
    await conn.commit()


async def _ensure_session_indexes(conn: aiosqlite.Connection) -> None:
    """Create the sessions indexes, skipping any whose target column is absent.

    A legacy ``sessions`` table may lack columns that an index references; creating
    the index unconditionally would raise. Only build indexes for present columns.
    """
    existing = await _session_columns(conn)
    for col, ddl in SESSION_INDEXES:
        if col in existing:
            await conn.execute(ddl)
    await conn.commit()


async def _get_user_version(conn: aiosqlite.Connection) -> int:
    """Return the database's ``PRAGMA user_version`` (0 for a never-migrated DB)."""
    cur = await conn.execute("PRAGMA user_version")
    row = await cur.fetchone()
    await cur.close()
    return int(row[0]) if row is not None else 0


def _start_only_sql(existing: set[str]) -> tuple[str, str, str]:
    """Build the v1 migration's WHERE clause and the copy column expressions.

    Column names come only from fixed literals in this function, never from input.
    A column absent from a minimal legacy ``sessions`` table is treated as its
    default (0 / NULL), which is what the row would have held had it existed.

    Args:
        existing: Column names present on ``sessions``.

    Returns:
        ``(where, select_exprs, insert_cols)`` for the copy-then-delete statements.
    """
    preds = ["status IN ('provisional', 'error')"]
    if "chunk_count" in existing:
        preds.append("COALESCE(chunk_count, 0) = 0")
    if "cast_path" in existing:
        preds.append("cast_path IS NULL")
    if "size_bytes" in existing:
        preds.append("COALESCE(size_bytes, 0) = 0")
    where = " AND ".join(preds)

    def col(name: str) -> str:
        return name if name in existing else "NULL"

    created = "COALESCE(created_at, datetime('now'))" if "created_at" in existing else "datetime('now')"
    seen_parts = [c for c in ("updated_at", "created_at") if c in existing]
    last_seen = f"COALESCE({', '.join(seen_parts)}, datetime('now'))" if seen_parts else "datetime('now')"

    insert_cols = "conn_id, username, resource_address, started_at, state, has_api, created_at, last_seen_at"
    select_exprs = (
        f"conn_id, {col('username')}, {col('resource_address')}, {col('started_at')}, "
        f"'error', 0, {created}, {last_seen}"
    )
    return where, select_exprs, insert_cols


# On-disk artifacts named for a ``conn_id`` (see ``store/casts.py``): the ``.cast``
# recording — the same name whether plaintext (in progress) or encrypted (sealed) —
# and the plaintext-extraction sidecar.
_CAST_ARTIFACT_SUFFIXES: tuple[str, ...] = (".cast", ".txt.enc")


def _has_cast_artifact(casts_dir: Path, conn_id: str) -> bool:
    """Return True if a recording artifact for ``conn_id`` may exist on disk.

    Fail-safe for the v1 migration: True means "keep the ``sessions`` row" so the
    file stays under the sweep and retention. ``conn_id`` is validated with the
    classifier's safe-token check before any path is built; an unsafe id cannot be
    checked, so it is reported as present (the row is kept, nothing is touched).
    Each candidate path is resolved and must stay inside ``casts_dir``; an entry
    that resolves outside it (e.g. a symlink) is never followed and is likewise
    reported as present.

    Args:
        casts_dir: The ``.cast`` directory on the data volume.
        conn_id: The candidate row's connection id (untrusted).

    Returns:
        True if an artifact exists or cannot be safely ruled out; False otherwise.
    """
    if _safe_conn_id({"conn_id": conn_id}) is None:
        return True
    base = casts_dir.resolve()
    for suffix in _CAST_ARTIFACT_SUFFIXES:
        candidate = casts_dir / f"{conn_id}{suffix}"
        resolved = candidate.resolve()
        if not resolved.is_relative_to(base):
            return True
        if resolved.exists():
            return True
    return False


def _rows_with_cast_artifacts(casts_dir: Path, conn_ids: list[str]) -> set[str]:
    """Return the subset of ``conn_ids`` that have (or may have) an on-disk artifact."""
    return {cid for cid in conn_ids if _has_cast_artifact(casts_dir, cid)}


async def _migrate_v1_start_only_rows(
    conn: aiosqlite.Connection, casts_dir: Path | None = None
) -> int:
    """One-time move of start-only ``sessions`` rows into ``connections`` (spec §11).

    Before Session 9, every ``Authenticated connection`` created a visible
    ``sessions`` row, so API-only kubectl connections showed as ``provisional`` and
    then ``error``. A start-only row is one that never received a recording chunk:
    ``status IN ('provisional','error') AND COALESCE(chunk_count,0) = 0 AND
    cast_path IS NULL AND COALESCE(size_bytes,0) = 0``.

    Those metadata columns lag the file: a crash between ``write_plaintext`` and
    ``update_progress`` leaves a row that looks start-only but whose plaintext
    ``.cast`` is on disk. So when ``casts_dir`` is given, any candidate with a
    ``<conn_id>.cast`` (plaintext or sealed — same name) or ``<conn_id>.txt.enc``
    sidecar on disk is skipped: it stays in ``sessions`` for ``sweep_startup`` to
    re-adopt and retention to purge, instead of becoming an orphaned secret-grade
    file. Candidates whose ``conn_id`` fails the safe-token check are skipped too
    (no path is built from them). Without ``casts_dir`` no file check is made
    (test-only; production always passes it).

    Each remaining row is copied into ``connections`` with ``state = 'error'``
    (keeping ``username``, ``resource_address``, ``started_at``, ``created_at``) and
    then deleted from ``sessions``, in one transaction that also sets
    ``user_version = 1``. Historical SSH transport-failure rows are indistinguishable
    from API-only rows and are moved too (accepted, spec §14 item 5).

    The ``user_version`` guard is mandatory: after Session 9 the pending backstop
    deliberately creates start-only ``error`` rows, which a re-run would delete.

    Args:
        conn: The open database connection.
        casts_dir: The ``.cast`` directory, used to keep rows whose recording is on
            disk. ``None`` skips the file check.

    Returns:
        Number of rows moved (0 when the migration was already applied).
    """
    # BEGIN IMMEDIATE takes the write lock up front, so the version re-check below
    # and the copy/delete/version-bump are atomic against another writer.
    await conn.execute("BEGIN IMMEDIATE")
    try:
        if await _get_user_version(conn) >= 1:
            await conn.rollback()
            return 0

        existing = await _session_columns(conn)
        moved = 0
        if "status" in existing:
            where, select_exprs, insert_cols = _start_only_sql(existing)
            cur = await conn.execute(f"SELECT conn_id FROM sessions WHERE {where}")
            candidates = [row[0] for row in await cur.fetchall()]
            await cur.close()
            kept: set[str] = set()
            if casts_dir is not None and candidates:
                kept = await asyncio.to_thread(
                    _rows_with_cast_artifacts, Path(casts_dir), candidates
                )
            to_move = [(cid,) for cid in candidates if cid not in kept]
            if to_move:
                await conn.executemany(
                    f"INSERT INTO connections ({insert_cols}) "
                    f"SELECT {select_exprs} FROM sessions WHERE conn_id = ? AND {where} "
                    "ON CONFLICT(conn_id) DO NOTHING",
                    to_move,
                )
                cur = await conn.executemany(
                    f"DELETE FROM sessions WHERE conn_id = ? AND {where}", to_move
                )
                moved = max(cur.rowcount, 0)
                await cur.close()
            if kept:
                log.info("db.migration_kept_rows_with_cast", kept=len(kept))
        # PRAGMA cannot take a bound parameter; the value is a fixed literal. Setting
        # user_version inside the transaction makes it roll back with the data move.
        await conn.execute("PRAGMA user_version = 1")
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    return moved


async def _run_migrations(conn: aiosqlite.Connection, casts_dir: Path | None = None) -> None:
    """Apply any pending ``user_version``-gated data migrations, in order.

    Args:
        conn: The open database connection.
        casts_dir: The ``.cast`` directory, passed to migrations that must check
            for recordings on disk. ``None`` skips those checks.
    """
    version = await _get_user_version(conn)
    if version < 1:
        moved = await _migrate_v1_start_only_rows(conn, casts_dir)
        log.info("db.migrated", from_version=version, to_version=1, start_only_rows_moved=moved)


async def init_db(db_path: Path, casts_dir: Path | None = None) -> aiosqlite.Connection:
    """Ensure the data directory exists, open a connection, and create the schema.

    Order: create tables/indexes → add missing ``sessions`` columns → create the
    column-dependent ``sessions`` indexes → run ``user_version``-gated migrations.

    Args:
        db_path: Filesystem path to the SQLite database file.
        casts_dir: The ``.cast`` directory on the data volume. The v1 migration
            uses it to keep any start-only-looking ``sessions`` row whose recording
            is already on disk. Production always passes it; ``None`` (tests only)
            skips the file check.

    Returns:
        An open, schema-initialized aiosqlite connection.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = await connect(db_path)
    await conn.executescript(SCHEMA)
    await conn.commit()
    await _ensure_columns(conn)
    await _ensure_session_indexes(conn)
    await _run_migrations(conn, casts_dir)
    log.info("db.initialized", db_path=str(db_path), user_version=await _get_user_version(conn))
    return conn
