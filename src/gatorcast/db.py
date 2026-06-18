"""SQLite connection management and schema initialization.

WAL mode with synchronous=NORMAL for durable, concurrent-friendly metadata.
.cast recording payloads live on the volume, never in the database (CLAUDE.md rule 9).
"""

from __future__ import annotations

from pathlib import Path

import aiosqlite

from gatorcast.logging import get_logger

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
"""

# Session indexes are created after _ensure_columns so they can reference columns
# that an upgraded-in-place (pre-Session-8) DB may have been missing. Each index is
# only created when its target column actually exists on the sessions table, so a
# minimal legacy table does not crash index creation.
SESSION_INDEXES: tuple[tuple[str, str], ...] = (
    ("resource_address", "CREATE INDEX IF NOT EXISTS idx_sessions_resource ON sessions(resource_address)"),
    ("started_at", "CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at)"),
    ("status", "CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)"),
)


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


async def _ensure_columns(conn: aiosqlite.Connection) -> None:
    """Add Session 8 columns to a pre-existing ``sessions`` table (idempotent).

    ``CREATE TABLE IF NOT EXISTS`` will not alter an existing table, so a DB created
    before these columns existed needs an explicit, guarded ``ALTER``.
    """
    cur = await conn.execute("PRAGMA table_info(sessions)")
    existing = {row[1] for row in await cur.fetchall()}
    await cur.close()
    for col, ddl in (
        ("finding_count", "ALTER TABLE sessions ADD COLUMN finding_count INTEGER DEFAULT 0"),
        ("max_severity", "ALTER TABLE sessions ADD COLUMN max_severity TEXT"),
    ):
        if col not in existing:
            await conn.execute(ddl)
    await conn.commit()


async def _ensure_session_indexes(conn: aiosqlite.Connection) -> None:
    """Create the sessions indexes, skipping any whose target column is absent.

    A legacy ``sessions`` table may lack columns that an index references; creating
    the index unconditionally would raise. Only build indexes for present columns.
    """
    cur = await conn.execute("PRAGMA table_info(sessions)")
    existing = {row[1] for row in await cur.fetchall()}
    await cur.close()
    for col, ddl in SESSION_INDEXES:
        if col in existing:
            await conn.execute(ddl)
    await conn.commit()


async def init_db(db_path: Path) -> aiosqlite.Connection:
    """Ensure the data directory exists, open a connection, and create the schema.

    Args:
        db_path: Filesystem path to the SQLite database file.

    Returns:
        An open, schema-initialized aiosqlite connection.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = await connect(db_path)
    await conn.executescript(SCHEMA)
    await conn.commit()
    await _ensure_columns(conn)
    await _ensure_session_indexes(conn)
    log.info("db.initialized", db_path=str(db_path))
    return conn
