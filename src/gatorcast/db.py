"""SQLite connection management, schema initialization, and migrations.

WAL mode with synchronous=NORMAL for durable, concurrent-friendly metadata.
.cast recording payloads live on the volume, never in the database (CLAUDE.md rule 9).

Tables:
    sessions      — one row per recording (visible in the UI).
    findings      — cast-offset findings from the plaintext sidecar scan.
    connections   — hidden per-``conn_id`` connection state
                    (pending | recording | api | error | empty) plus the Gateway
                    ``resource_type`` and the per-connection gwops/TLS snapshot.
    api_requests  — allowlisted API-request metadata (``api_kind`` ``kubectl`` | ``web``),
                    deduplicated by ``request_id``.
    api_findings  — rule findings on API requests (cascade-deleted with their request).

Schema evolution:
    * ``CREATE TABLE/INDEX IF NOT EXISTS`` for new tables (idempotent every boot).
    * ``_ensure_columns`` adds later-release columns to pre-existing ``sessions``,
      ``connections`` and ``api_requests`` tables from per-table column lists
      (idempotent, PRAGMA-guarded ``ALTER``).
    * Indexes on later-release columns (``API_REQUEST_INDEXES``) are created after the
      ``ALTER``s; superseded indexes (``RETIRED_INDEXES``) are dropped every boot.
    * ``PRAGMA user_version`` gates one-time data migrations that must never re-run.

Shared SQL fragments (``CMD_KEY_SQL``, ``SESSION_AT_SQL``, ``FAILED_SQL``) live here
because the expression indexes must reproduce them exactly; query code renders them
through :func:`cmd_key` / :func:`session_at` (or ``.format(a=...)``) so its
expressions match the indexes. Every connection opened through :func:`connect` has
the deterministic SQL function ``gc_is_discovery(method, url)`` registered.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import aiosqlite

from gatorcast.logging import get_logger
from gatorcast.pipeline.activity import is_discovery
from gatorcast.pipeline.classify import _safe_conn_id

log = get_logger(__name__)

# --- shared SQL fragments (spec §7.1) ----------------------------------------------
# Each fragment has an ``{a}`` placeholder for an optional table-alias prefix ("" or
# "q."). The index DDL below is rendered from the same fragments with ``a=""``, so a
# query that renders them with any alias produces an expression SQLite matches to the
# index (it compares parsed expressions; the table qualifier does not matter).

# Command key of an ``api_requests`` row: the ``Kubectl-Session`` header when
# non-empty, else the connection. Distinct ``s:``/``c:`` tags mirror the tagged tuple
# in ``pipeline.activity._command_key`` so a header value of ``c:<id>`` can never
# collide with a connection fallback; the empty-string test mirrors its truthiness.
CMD_KEY_SQL = (
    "(CASE WHEN COALESCE({a}kubectl_session, '') <> '' "
    "THEN 's:' || {a}kubectl_session ELSE 'c:' || {a}conn_id END)"
)

# Sort/filter instant of a ``sessions`` row, rendered in the exact ``requested_at``
# format ("YYYY-MM-DDTHH:MM:SS.mmmZ") so recordings and kubectl commands compare as
# strings. Normalizes every stored ``started_at`` shape and the ``created_at``
# fallback ("YYYY-MM-DD HH:MM:SS"). Deterministic: no 'now' / 'localtime' / 'utc'.
SESSION_AT_SQL = "strftime('%Y-%m-%dT%H:%M:%fZ', COALESCE({a}started_at, {a}created_at))"

# A failed connection: a visible ``error`` row that never received a chunk or a cast
# (spec §4.2). Same predicate as ``SessionRepository.delete_start_only_error``.
FAILED_SQL = "({a}status = 'error' AND COALESCE({a}chunk_count, 0) = 0 AND {a}cast_path IS NULL)"

# A table alias interpolated into SQL must be a plain identifier (code-supplied only).
_ALIAS_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _alias_prefix(alias: str) -> str:
    """Return ``"<alias>."`` (or ``""`` for no alias) after validating ``alias``.

    Args:
        alias: A table alias, or ``""`` for unqualified column names.

    Returns:
        The column-qualifier prefix to substitute for ``{a}``.

    Raises:
        ValueError: If ``alias`` is not a plain SQL identifier.
    """
    if not alias:
        return ""
    if _ALIAS_RE.fullmatch(alias) is None:
        raise ValueError("SQL alias must be a plain identifier")
    return f"{alias}."


def cmd_key(alias: str = "") -> str:
    """Render :data:`CMD_KEY_SQL` for an optional table alias.

    Args:
        alias: Table alias of ``api_requests`` in the query (``"q"`` renders
            ``q.kubectl_session`` / ``q.conn_id``), or ``""`` for bare columns.

    Returns:
        The command-key SQL expression, matching ``idx_api_req_cmd``.

    Raises:
        ValueError: If ``alias`` is not a plain SQL identifier.
    """
    return CMD_KEY_SQL.format(a=_alias_prefix(alias))


def session_at(alias: str = "") -> str:
    """Render :data:`SESSION_AT_SQL` for an optional table alias.

    Args:
        alias: Table alias of ``sessions`` in the query (``"s"`` renders
            ``s.started_at`` / ``s.created_at``), or ``""`` for bare columns.

    Returns:
        The session-instant SQL expression, matching ``idx_sessions_at``.

    Raises:
        ValueError: If ``alias`` is not a plain SQL identifier.
    """
    return SESSION_AT_SQL.format(a=_alias_prefix(alias))


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
    sealed_terminal  INTEGER,                       -- 1 terminal seal | 0 reopenable seal | NULL unsealed/legacy
    resource_type    TEXT,                          -- Gateway resource type, copied from connections at promote
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
    state            TEXT NOT NULL DEFAULT 'pending',-- pending | recording | api | error | empty
    has_api          INTEGER NOT NULL DEFAULT 0,     -- 1 once any audit line arrived
    created_at       TEXT DEFAULT (datetime('now')),
    last_seen_at     TEXT DEFAULT (datetime('now')), -- drives the pending backstop
    resource_type    TEXT,                           -- normalized start-line value (KUBERNETES, SSH, WEB_APP, ...)
    start_seen       INTEGER NOT NULL DEFAULT 0,     -- 1 once a start line was processed (first-processing marker)
    -- gwops snapshot (WEB_APP start lines only; configured state, never proof; first write wins)
    gwops_match      TEXT,                           -- exact | none | ambiguous | NULL
    gwops_gateway_id TEXT,                           -- opaque Twingate gateway id; NULL in gwops Mode B or when absent
    gwops_app        TEXT,                           -- display only (exact)
    gwops_managed    INTEGER,                        -- 1 | 0 | NULL (exact only)
    downstream_tls   TEXT,                           -- tls13 | none | NULL (unknown)
    downstream_port  INTEGER,                        -- 1-65535 | NULL
    upstream_tls     TEXT,                           -- verify_full | verify_ca | insecure | none | NULL
    upstream_port    INTEGER                         -- 1-65535 | NULL
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
    created_at       TEXT DEFAULT (datetime('now')),
    api_kind         TEXT NOT NULL DEFAULT 'kubectl',-- kubectl | web (storage policy and search kind)
    downstream_tls   TEXT,                           -- configured mode, copied from the connection (web rows)
    upstream_tls     TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_req_conn          ON api_requests(conn_id);
CREATE INDEX IF NOT EXISTS idx_api_req_session       ON api_requests(kubectl_session);

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
""" + f"""
-- Session 10 (spec §7.1). Every column idx_api_req_cmd references existed when
-- Session 9 created the table, so it needs no column guard. It is rendered from
-- CMD_KEY_SQL so query expressions built with cmd_key() match it exactly. The other
-- api_requests scan indexes lead with api_kind (a Session 11 column) and are created
-- by init_db after the ALTERs: see API_REQUEST_INDEXES.
CREATE INDEX IF NOT EXISTS idx_api_req_cmd ON api_requests(
    {CMD_KEY_SQL.format(a="")},
    requested_at, request_id);
"""

# Columns added to ``sessions`` after its first release. ``CREATE TABLE IF NOT EXISTS``
# never alters an existing table, so each is added with a guarded ``ALTER`` on boot.
SESSION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("finding_count", "ALTER TABLE sessions ADD COLUMN finding_count INTEGER DEFAULT 0"),
    ("max_severity", "ALTER TABLE sessions ADD COLUMN max_severity TEXT"),
    ("request_id", "ALTER TABLE sessions ADD COLUMN request_id TEXT"),
    # Session 10 T11: how the row was sealed (1 terminal, 0 reopenable, NULL not
    # sealed / sealed before this column existed — treated as terminal).
    ("sealed_terminal", "ALTER TABLE sessions ADD COLUMN sealed_terminal INTEGER"),
    # Session 11 (spec §4.2): the Gateway resource type, copied from ``connections``
    # when a recording promotes the connection to a session.
    ("resource_type", "ALTER TABLE sessions ADD COLUMN resource_type TEXT"),
)

# Columns added to ``connections`` after Session 9 created it (Session 11, spec §4.2,
# §3.3): the normalized start-line ``resource_type`` and the eight gwops/TLS snapshot
# columns. All nullable: NULL means "unknown" (no object, a rejected object, ``none``
# or ``ambiguous``). No index: the snapshot is read by primary key only.
CONNECTION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("resource_type", "ALTER TABLE connections ADD COLUMN resource_type TEXT"),
    # 1 once an ``Authenticated connection`` line has been processed for the row: the
    # reliable "first processing" marker (a start line may carry neither ``ts`` nor
    # ``resource_type``, so those columns cannot say). Rows from before it existed are
    # recognised by the old minimal-row test (``started_at``/``resource_type`` NULL).
    ("start_seen", "ALTER TABLE connections ADD COLUMN start_seen INTEGER NOT NULL DEFAULT 0"),
    ("gwops_match", "ALTER TABLE connections ADD COLUMN gwops_match TEXT"),
    ("gwops_gateway_id", "ALTER TABLE connections ADD COLUMN gwops_gateway_id TEXT"),
    ("gwops_app", "ALTER TABLE connections ADD COLUMN gwops_app TEXT"),
    ("gwops_managed", "ALTER TABLE connections ADD COLUMN gwops_managed INTEGER"),
    ("downstream_tls", "ALTER TABLE connections ADD COLUMN downstream_tls TEXT"),
    ("downstream_port", "ALTER TABLE connections ADD COLUMN downstream_port INTEGER"),
    ("upstream_tls", "ALTER TABLE connections ADD COLUMN upstream_tls TEXT"),
    ("upstream_port", "ALTER TABLE connections ADD COLUMN upstream_port INTEGER"),
)

# Columns added to ``api_requests`` in Session 11 (spec §4.2). ``api_kind`` is NOT NULL
# with a constant default, which ``ALTER TABLE ADD COLUMN`` accepts and which makes
# every existing row ``kubectl`` with no data migration and no table rewrite.
API_REQUEST_COLUMNS: tuple[tuple[str, str], ...] = (
    (
        "api_kind",
        "ALTER TABLE api_requests ADD COLUMN api_kind TEXT NOT NULL DEFAULT 'kubectl'",
    ),
    ("downstream_tls", "ALTER TABLE api_requests ADD COLUMN downstream_tls TEXT"),
    ("upstream_tls", "ALTER TABLE api_requests ADD COLUMN upstream_tls TEXT"),
)

# Per-table column lists applied by ``_ensure_columns``. Table names are fixed
# literals (never input).
TABLE_COLUMNS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    ("sessions", SESSION_COLUMNS),
    ("connections", CONNECTION_COLUMNS),
    ("api_requests", API_REQUEST_COLUMNS),
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
    # Session 10 keyset index for the unified timeline (spec §7.1), rendered from
    # SESSION_AT_SQL so queries built with session_at() match it.
    (
        "started_at",
        "CREATE INDEX IF NOT EXISTS idx_sessions_at ON sessions("
        f"{SESSION_AT_SQL.format(a='')}, conn_id)",
    ),
)

# api_requests indexes that lead with ``api_kind`` (Session 11, spec §4.2). They
# reference a column that an upgraded database only gains through ``API_REQUEST_COLUMNS``,
# so they are created after ``_ensure_columns`` (never in ``SCHEMA``). ``api_kind``
# is an equality column in every kubectl-source query, so each index is a kind-scoped
# version of the one it replaces and a web-heavy table never makes a kubectl scan
# walk web rows. Each statement is idempotent.
API_REQUEST_INDEXES: tuple[str, ...] = (
    # scan mode without system/user; dashboard request count
    "CREATE INDEX IF NOT EXISTS idx_api_req_kind_time "
    "ON api_requests(api_kind, requested_at, request_id)",
    # user= arm 1 (username)
    "CREATE INDEX IF NOT EXISTS idx_api_req_kind_user_time "
    "ON api_requests(api_kind, username, requested_at, request_id)",
    # user= arm 2 (user_id)
    "CREATE INDEX IF NOT EXISTS idx_api_req_kind_userid_time "
    "ON api_requests(api_kind, user_id, requested_at, request_id)",
    # list_systems (covering), scans with system. ``request_id`` is the trailing tie-break
    # of the scan's ``ORDER BY requested_at DESC, request_id DESC``: with it the planner
    # walks (resource_address = ?, api_kind = ?) in order with no sort and prefers this
    # index to ``idx_api_req_kind_time`` (without it the planner picks the kind-only
    # index and filters the system row by row, and a scan would burn its budget on
    # other systems' rows).
    "CREATE INDEX IF NOT EXISTS idx_api_req_sys_kind_time "
    "ON api_requests(resource_address, api_kind, requested_at, request_id)",
    # activity and visit reads (same reason for the trailing ``request_id``: their
    # ``ORDER BY requested_at, request_id`` over one user's bounded window)
    "CREATE INDEX IF NOT EXISTS idx_api_req_sys_kind_user_time "
    "ON api_requests(resource_address, api_kind, user_key, requested_at, request_id)",
)

# Indexes superseded by ``API_REQUEST_INDEXES`` (same order). They are no longer in
# ``SCHEMA`` and are dropped on every boot after the replacements exist, so an upgraded
# database converges on the same 20 indexes as a fresh one. ``DROP INDEX IF EXISTS`` is
# idempotent.
RETIRED_INDEXES: tuple[str, ...] = (
    "idx_api_req_time",
    "idx_api_req_user_time",
    "idx_api_req_userid_time",
    "idx_api_req_sys_time",
    "idx_api_req_sys_user_time",
)

# Current data-migration level stored in ``PRAGMA user_version``.
#   0 → 1: move start-only ``sessions`` rows into ``connections`` (Session 9, spec §11).
# Session 10's indexes are idempotent DDL with no data migration: no bump (spec §7.3).
SCHEMA_VERSION = 1


def _sql_is_discovery(method: object, url: object) -> int:
    """SQL function ``gc_is_discovery(method, url)``: 1 for a discovery request, else 0.

    Delegates to :func:`gatorcast.pipeline.activity.is_discovery`, the single source
    of truth for the discovery rule. Never raises: a NULL or non-text argument
    yields 0, so a bad row can never abort the query that calls it.

    Args:
        method: The ``api_requests.method`` value (any SQLite type).
        url: The ``api_requests.url`` value (any SQLite type).

    Returns:
        1 if ``(method, url)`` is a discovery request, else 0.
    """
    return int(isinstance(method, str) and isinstance(url, str) and is_discovery(method, url))


async def connect(db_path: Path) -> aiosqlite.Connection:
    """Open an aiosqlite connection with WAL pragmas, row factory, and SQL functions.

    Registers the deterministic SQL function ``gc_is_discovery(method, url)``
    (spec §7.2). It is used only in queries, never in schema, so the database stays
    readable by any SQLite client.

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
    await conn.create_function("gc_is_discovery", 2, _sql_is_discovery, deterministic=True)
    await conn.commit()
    return conn


async def _table_columns(conn: aiosqlite.Connection, table: str) -> set[str]:
    """Return the set of column names currently present on ``table``.

    Uses the ``pragma_table_info`` table-valued function so the table name is a bound
    parameter, not interpolated SQL. An absent table yields an empty set.

    Args:
        conn: The open database connection.
        table: The table name.

    Returns:
        The column names on ``table``.
    """
    cur = await conn.execute("SELECT name FROM pragma_table_info(?)", (table,))
    existing = {row[0] for row in await cur.fetchall()}
    await cur.close()
    return existing


async def _session_columns(conn: aiosqlite.Connection) -> set[str]:
    """Return the set of column names currently present on ``sessions``."""
    return await _table_columns(conn, "sessions")


async def _ensure_columns(conn: aiosqlite.Connection) -> None:
    """Add later-release columns to pre-existing tables (idempotent).

    ``CREATE TABLE IF NOT EXISTS`` will not alter an existing table, so a DB created
    before these columns existed needs an explicit, guarded ``ALTER``. Applies each
    per-table list in :data:`TABLE_COLUMNS`: ``sessions`` (Session 8 finding columns,
    Session 9 ``request_id``, Session 10 ``sealed_terminal``, Session 11
    ``resource_type``), ``connections`` (Session 11 ``resource_type`` and gwops/TLS
    snapshot) and ``api_requests`` (Session 11 ``api_kind`` and TLS modes). No
    ``user_version`` bump. A column is added only if absent, so a second boot, or a
    fresh install whose ``CREATE TABLE`` already has it, issues no ``ALTER``.
    """
    for table, columns in TABLE_COLUMNS:
        existing = await _table_columns(conn, table)
        for col, ddl in columns:
            if col not in existing:
                await conn.execute(ddl)
    await conn.commit()


async def _ensure_api_request_indexes(conn: aiosqlite.Connection) -> None:
    """Create the ``api_kind``-prefixed ``api_requests`` indexes, then drop retired ones.

    Must run after :func:`_ensure_columns`: the new indexes reference ``api_kind``,
    which an upgraded database only has once its ``ALTER`` has run. The replacements
    are built before the superseded indexes are dropped, so a crash between the two
    steps leaves every query with an index, and the next boot finishes the job.
    """
    for ddl in API_REQUEST_INDEXES:
        await conn.execute(ddl)
    for name in RETIRED_INDEXES:
        await conn.execute(f"DROP INDEX IF EXISTS {name}")  # noqa: S608 - fixed literals
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

    Order: create tables/indexes → add missing columns (``sessions``, ``connections``,
    ``api_requests``) → create the column-dependent ``sessions`` indexes → create the
    ``api_kind``-prefixed ``api_requests`` indexes and drop the retired ones → run
    ``user_version``-gated migrations.

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
    await _ensure_api_request_indexes(conn)
    await _run_migrations(conn, casts_dir)
    log.info("db.initialized", db_path=str(db_path), user_version=await _get_user_version(conn))
    return conn
