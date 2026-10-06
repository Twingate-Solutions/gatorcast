"""SQLite repository for session metadata (raw, parameterized SQL — no ORM).

This is the single place that issues SQL against the ``sessions`` table. It serves
two callers:

  * the **assembler**, which upserts provisional rows during buffering and finalizes
    them (from memory or, on crash recovery, from disk), and
  * the **retention job**, which purges by age and by total ``.cast`` size.

All SQL is parameterized. The schema's WAL/durability pragmas are configured at
connection time in ``gatorcast.db``. SQLite's ``datetime('now')`` is used for server-side
timestamps so behavior matches the inline SQL that previously lived in the assembler.

Recording payloads are never modeled or logged here — only metadata (CLAUDE.md
rules 5 and 9).
"""

from __future__ import annotations

import aiosqlite
from pydantic import BaseModel

from gatorcast.db import session_at
from gatorcast.models import Session


class SystemSummary(BaseModel):
    """Aggregate view of one target system (distinct ``resource_address``).

    A system is listed when it has recording sessions, kubectl API requests, or
    both. ``finding_count``/``max_severity`` summarize recording findings only;
    API-request findings are shown on the system's kubectl activity table.

    Timestamps are all in the ``api_requests.requested_at`` format
    (``YYYY-MM-DDTHH:MM:SS.mmmZ``), so they compare as strings:

    * ``last_session_at`` — newest recording start (``SESSION_AT_SQL``: ``started_at``,
      else ``created_at``), or ``None`` with no ``sessions`` rows.
    * ``last_api_at`` — newest ``requested_at``, or ``None`` with no API requests.
    * ``last_seen`` — the larger of the two (kept for existing callers).

    Counts (spec §7.5): ``session_count`` is every ``sessions`` row (recordings and
    failed connections); ``ssh_count`` is SSH recordings that hold recording data
    (chunks, or a ``.cast`` on disk); ``exec_count`` is kubectl exec/attach
    recordings (``request_id`` set).
    """

    resource_address: str | None
    session_count: int
    last_seen: str | None
    finding_count: int = 0
    max_severity: str | None = None
    api_request_count: int = 0
    ssh_count: int = 0
    exec_count: int = 0
    last_session_at: str | None = None
    last_api_at: str | None = None

    @property
    def has_ssh(self) -> bool:
        """True when the system earns the SSH badge (at least one SSH recording)."""
        return self.ssh_count > 0

    @property
    def has_kubernetes(self) -> bool:
        """True when the system earns the Kubernetes badge (exec recordings or API requests)."""
        return self.exec_count > 0 or self.api_request_count > 0


# Maps the SQL severity-rank back to a label (0 / no findings → None).
_RANK_TO_SEVERITY = {4: "critical", 3: "high", 2: "medium", 1: "low"}

# Static CASE expression ranking a session's max_severity; used only to compute a
# per-system highest severity via MAX(). No user input is interpolated.
_SEVERITY_RANK_CASE = (
    "CASE max_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
    "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
)

# Q12 (unified search spec §7.4, §7.5): the systems list. A UNION ALL of a
# per-system aggregate over ``sessions`` (a small table, scanned) and one over
# ``api_requests`` answered by a covering scan of ``idx_api_req_sys_time``
# (``resource_address, requested_at``), folded by the outer GROUP BY. No new index.
# Both timestamps are in the ``requested_at`` format (the sessions side through
# ``SESSION_AT_SQL``), so they compare directly with no per-row ``datetime()``.
# Rows sort by the newer of the two, then by address for a stable order.
#
# ``ssh_count`` requires recording data (chunks, or a ``.cast`` from crash recovery,
# which leaves ``chunk_count`` at 0), so a start-only ``error`` row on a cluster never
# earns an SSH badge. Static SQL only; no value is interpolated.
LIST_SYSTEMS_SQL = f"""
SELECT
    resource_address        AS resource_address,
    SUM(session_count)      AS session_count,
    SUM(ssh_count)          AS ssh_count,
    SUM(exec_count)         AS exec_count,
    SUM(api_request_count)  AS api_request_count,
    MAX(last_session_at)    AS last_session_at,
    MAX(last_api_at)        AS last_api_at,
    SUM(finding_count)      AS finding_count,
    MAX(sev_rank)           AS sev_rank
FROM (
    SELECT
        s.resource_address                                   AS resource_address,
        COUNT(*)                                             AS session_count,
        SUM(s.request_id IS NULL AND (COALESCE(s.chunk_count, 0) > 0
                                      OR s.cast_path IS NOT NULL)) AS ssh_count,
        SUM(s.request_id IS NOT NULL)                        AS exec_count,
        0                                                    AS api_request_count,
        MAX({session_at("s")})                               AS last_session_at,
        NULL                                                 AS last_api_at,
        COALESCE(SUM(s.finding_count), 0)                    AS finding_count,
        MAX({_SEVERITY_RANK_CASE})                           AS sev_rank
    FROM sessions AS s
    GROUP BY s.resource_address
    UNION ALL
    SELECT
        r.resource_address, 0, 0, 0, COUNT(*), NULL, MAX(r.requested_at), 0, 0
    FROM api_requests AS r
    GROUP BY r.resource_address
)
GROUP BY resource_address
ORDER BY MAX(COALESCE(MAX(last_session_at), ''), COALESCE(MAX(last_api_at), '')) DESC,
         resource_address
"""


class PurgedSession(BaseModel):
    """Identifies a deleted session so the caller can remove its ``.cast`` file."""

    conn_id: str
    cast_path: str | None


# Columns selected for a full Session row, in model field order.
_SESSION_COLUMNS = (
    "conn_id, username, resource_address, shell_user, started_at, ended_at, "
    "duration_seconds, width, height, chunk_count, size_bytes, cast_path, status, "
    "finding_count, max_severity, request_id, sealed_terminal"
)


def _row_to_session(row: aiosqlite.Row) -> Session:
    """Map a ``sessions`` table row to the ``Session`` model.

    ``sealed_terminal`` is read only when the row carries that column, so a caller
    selecting its own narrower column list still maps cleanly (it gets ``None``).
    """
    sealed = row["sealed_terminal"] if "sealed_terminal" in row.keys() else None
    return Session(
        conn_id=row["conn_id"],
        username=row["username"],
        resource_address=row["resource_address"],
        shell_user=row["shell_user"],
        started_at=row["started_at"],
        ended_at=row["ended_at"],
        duration_seconds=row["duration_seconds"],
        width=row["width"],
        height=row["height"],
        chunk_count=row["chunk_count"] or 0,
        size_bytes=row["size_bytes"] or 0,
        cast_path=row["cast_path"],
        status=row["status"],
        finding_count=row["finding_count"] or 0,
        max_severity=row["max_severity"],
        request_id=row["request_id"],
        sealed_terminal=None if sealed is None else bool(sealed),
    )


class SessionRepository:
    """Async repository over the ``sessions`` table (raw parameterized SQL)."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        """Initialize the repository.

        Args:
            db: An open aiosqlite connection (WAL, ``aiosqlite.Row`` factory).
        """
        self._db = db

    # --- assembler write path --------------------------------------------------

    async def upsert_start(
        self,
        conn_id: str,
        username: str | None,
        resource_address: str | None,
        started_at: str | None,
    ) -> None:
        """Insert or refresh a provisional row for a buffering session.

        Idempotent and redelivery-safe: an existing provisional row is updated
        (non-null fields win via ``COALESCE``; ``started_at`` keeps its first value);
        a completed row is left untouched by the ``WHERE status = 'provisional'``
        guard. Mirrors the assembler's former ``_upsert_provisional``.

        Args:
            conn_id: The connection id (primary key).
            username: Envelope SSO identity, if known.
            resource_address: Target system address, if known.
            started_at: Session start timestamp (start event / first chunk), if known.
        """
        await self._upsert_provisional(
            conn_id, username, resource_address, started_at, request_id=None
        )

    async def _upsert_provisional(
        self,
        conn_id: str,
        username: str | None,
        resource_address: str | None,
        started_at: str | None,
        *,
        request_id: str | None,
    ) -> None:
        """Shared INSERT-or-refresh of a provisional row (see :meth:`upsert_start`).

        ``request_id`` is first-wins (``COALESCE(sessions.request_id, ?)``): once a
        k8s exec/attach chunk has set it, later chunks never overwrite it.
        """
        await self._db.execute(
            """
            INSERT INTO sessions (
                conn_id, username, resource_address, started_at, request_id, status,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, 'provisional', datetime('now'), datetime('now'))
            ON CONFLICT(conn_id) DO UPDATE SET
                username         = COALESCE(excluded.username, sessions.username),
                resource_address = COALESCE(excluded.resource_address, sessions.resource_address),
                started_at       = COALESCE(sessions.started_at, excluded.started_at),
                request_id       = COALESCE(sessions.request_id, excluded.request_id),
                updated_at       = datetime('now')
            WHERE sessions.status = 'provisional'
            """,
            (conn_id, username, resource_address, started_at, request_id),
        )
        await self._db.commit()

    # add_chunk_meta refreshes the same provisional row a chunk arrives on. It is
    # upsert_start with the chunk's known fields (including the k8s request_id) —
    # kept as a distinct method for caller clarity.
    async def add_chunk_meta(
        self,
        conn_id: str,
        username: str | None,
        started_at: str | None,
        request_id: str | None = None,
    ) -> None:
        """Refresh the provisional row when a recording chunk arrives.

        Equivalent to ``upsert_start`` for the fields a chunk can carry (it has no
        ``resource_address``). Keeps the provisional row's ``updated_at`` current and
        backfills ``username``/``started_at``/``request_id`` if not yet known.

        Args:
            conn_id: The connection id (primary key).
            username: Envelope SSO identity from the chunk, if present.
            started_at: First-seen timestamp for the session, if known.
            request_id: Gateway request UUID from a k8s exec/attach chunk; ``None``
                for SSH. Written with ``COALESCE`` so the first value wins.
        """
        await self._upsert_provisional(
            conn_id, username, None, started_at, request_id=request_id
        )

    async def update_progress(
        self,
        conn_id: str,
        *,
        username: str | None,
        shell_user: str | None,
        started_at: str | None,
        ended_at: str | None,
        duration_seconds: float | None,
        width: int | None,
        height: int | None,
        chunk_count: int,
        size_bytes: int,
        cast_path: str,
        request_id: str | None = None,
    ) -> None:
        """Refresh an in-progress row's derived metadata WITHOUT sealing it.

        Used by the file-first assembler on every append: the plaintext ``.cast`` has
        just grown, so mirror its size/duration/dimensions onto the row while leaving
        ``status = 'provisional'`` (the session is still recording). Guarded to only
        touch provisional rows so it can never revert a sealed row.

        Args:
            conn_id: The connection id (row must already exist).
            username: Envelope identity (backfilled via ``COALESCE``).
            shell_user: asciicast header user (secondary detail).
            started_at: Header-derived start, used only if the row had none.
            ended_at: Timestamp of the latest chunk seen so far.
            duration_seconds: Recording duration so far (max event offset).
            width: Terminal width from the header.
            height: Terminal height from the header.
            chunk_count: Distinct chunks appended so far.
            size_bytes: Current on-disk (plaintext) size.
            cast_path: Path to the ``.cast`` file.
            request_id: Gateway request UUID from a k8s exec/attach chunk; ``None``
                for SSH. Written with ``COALESCE`` so an existing value is kept.
        """
        await self._db.execute(
            """
            UPDATE sessions SET
                username         = COALESCE(?, username),
                shell_user       = ?,
                started_at       = COALESCE(started_at, ?),
                ended_at         = ?,
                duration_seconds = ?,
                width            = ?,
                height           = ?,
                chunk_count      = ?,
                size_bytes       = ?,
                cast_path        = ?,
                request_id       = COALESCE(request_id, ?),
                updated_at       = datetime('now')
            WHERE conn_id = ? AND status = 'provisional'
            """,
            (
                username,
                shell_user,
                started_at,
                ended_at,
                duration_seconds,
                width,
                height,
                chunk_count,
                size_bytes,
                cast_path,
                request_id,
                conn_id,
            ),
        )
        await self._db.commit()

    async def delete_start_only_error(self, conn_id: str) -> bool:
        """Delete a visible ``error`` row that never received a recording chunk.

        Called when a late API audit line arrives for a connection the pending
        backstop had surfaced as ``error`` (e.g. a long ``kubectl get -w``): the
        connection is API-only after all, so its phantom row is removed. Guarded so a
        row that holds any recording data (chunks or a ``.cast`` path) is never
        deleted.

        Args:
            conn_id: The connection id whose start-only error row to delete.

        Returns:
            True if a row was deleted.
        """
        cursor = await self._db.execute(
            "DELETE FROM sessions WHERE conn_id = ? AND status = 'error' "
            "AND COALESCE(chunk_count, 0) = 0 AND cast_path IS NULL",
            (conn_id,),
        )
        deleted = cursor.rowcount == 1
        await cursor.close()
        await self._db.commit()
        return deleted

    async def reopen(self, conn_id: str) -> None:
        """Revert a timeout-sealed row back to ``provisional`` and clear its seal mode.

        Called when a late chunk arrives for a session that was sealed by the idle
        backstop (not by a terminal end signal). Puts the row back in the in-progress
        state so subsequent appends and the eventual re-seal proceed normally, and
        resets ``sealed_terminal`` to ``NULL`` (not sealed).

        Accepts a sealed ``complete`` row and a sealed ``error`` row (unparseable
        header, but ``cast_path`` set) — otherwise a reopened ``error`` row would stay
        ``error`` and ``update_progress`` would silently skip it. A failed connection
        (``error`` with no ``cast_path``) never matches; it recovers through
        :meth:`revert_error_to_provisional` instead.

        Args:
            conn_id: The connection id to reopen.
        """
        await self._db.execute(
            "UPDATE sessions SET status = 'provisional', sealed_terminal = NULL, "
            "updated_at = datetime('now') "
            "WHERE conn_id = ? AND status IN ('complete', 'error') "
            "AND cast_path IS NOT NULL",
            (conn_id,),
        )
        await self._db.commit()

    async def mark_error_if_provisional(self, conn_id: str) -> None:
        """Mark a still-provisional session ``error`` — started but never recorded.

        Called by the idle backstop for a session that authenticated but never
        received a single valid recording chunk within the backstop window (e.g. the
        transport mangled or dropped every chunk). Flipping it to ``error`` stops it
        showing "in progress" forever. Guarded to ``provisional`` so it can never
        overwrite a completed or already-errored row.

        Args:
            conn_id: The connection id to mark errored.
        """
        await self._db.execute(
            "UPDATE sessions SET status = 'error', "
            "ended_at = COALESCE(ended_at, datetime('now')), updated_at = datetime('now') "
            "WHERE conn_id = ? AND status = 'provisional'",
            (conn_id,),
        )
        await self._db.commit()

    async def revert_error_to_provisional(self, conn_id: str) -> None:
        """Revert an ``error`` row to ``provisional`` when late data finally arrives.

        The mirror of :meth:`mark_error_if_provisional`: if a chunk shows up for a
        session that the backstop had given up on, put it back in the in-progress
        state so the recording records and seals normally. Guarded to ``error`` rows.

        Args:
            conn_id: The connection id to recover.
        """
        await self._db.execute(
            "UPDATE sessions SET status = 'provisional', updated_at = datetime('now') "
            "WHERE conn_id = ? AND status = 'error'",
            (conn_id,),
        )
        await self._db.commit()

    async def finalize(
        self,
        conn_id: str,
        *,
        username: str | None,
        shell_user: str | None,
        started_at: str | None,
        ended_at: str | None,
        duration_seconds: float | None,
        width: int | None,
        height: int | None,
        chunk_count: int,
        size_bytes: int,
        cast_path: str,
        status: str,
        sealed_terminal: bool = True,
    ) -> None:
        """Complete a row with derived metadata after reassembly from memory.

        Mirrors the assembler's former ``_finalize_buffer`` UPDATE: the
        ``status != 'complete'`` guard makes finalize idempotent, and
        ``COALESCE(started_at, ?)`` preserves the provisional (start-event) value,
        only falling back to the asciicast header timestamp. The seal mode is
        written in the same ``UPDATE`` so the database, not the assembler's memory,
        decides what a later chunk may do to this row.

        Args:
            conn_id: The connection id to finalize.
            username: Envelope identity (backfilled via ``COALESCE``).
            shell_user: asciicast header user (secondary detail).
            started_at: Header-derived start, used only if the row had none.
            ended_at: Session end timestamp (last chunk ts).
            duration_seconds: Recording duration (max event offset).
            width: Terminal width from the header.
            height: Terminal height from the header.
            chunk_count: Number of distinct fragments reassembled.
            size_bytes: Size of the written ``.cast`` file.
            cast_path: Path to the written ``.cast`` file.
            status: ``"complete"`` (parsed OK) or ``"error"`` (kept but unparsable).
            sealed_terminal: ``True`` for a terminal seal ("session finished" /
                close — a later chunk is ignored), ``False`` for a reopenable seal
                (idle backstop — a later chunk reopens and extends it). Defaults to
                ``True``, the safe choice for callers that do not say.
        """
        await self._db.execute(
            """
            UPDATE sessions SET
                username         = COALESCE(?, username),
                shell_user       = ?,
                started_at       = COALESCE(started_at, ?),
                ended_at         = ?,
                duration_seconds = ?,
                width            = ?,
                height           = ?,
                chunk_count      = ?,
                size_bytes       = ?,
                cast_path        = ?,
                status           = ?,
                sealed_terminal  = ?,
                updated_at       = datetime('now')
            WHERE conn_id = ? AND status != 'complete'
            """,
            (
                username,
                shell_user,
                started_at,
                ended_at,
                duration_seconds,
                width,
                height,
                chunk_count,
                size_bytes,
                cast_path,
                status,
                1 if sealed_terminal else 0,
                conn_id,
            ),
        )
        await self._db.commit()

    async def finalize_from_disk(
        self,
        conn_id: str,
        *,
        shell_user: str | None,
        started_at: str | None,
        duration_seconds: float | None,
        width: int | None,
        height: int | None,
        size_bytes: int,
        cast_path: str,
        status: str,
    ) -> None:
        """Complete a crash-recovered row from its existing ``.cast`` file.

        Mirrors the assembler's former ``_finalize_from_disk``: ``ended_at`` is set
        to ``datetime('now')`` (the real end ts is lost with the in-memory buffer),
        ``chunk_count`` is left at its provisional default (unrecoverable from disk),
        and the same ``status != 'complete'`` idempotency guard applies.

        Args:
            conn_id: The connection id to finalize.
            shell_user: asciicast header user (secondary detail).
            started_at: Header-derived start, used only if the row had none.
            duration_seconds: Recording duration (max event offset).
            width: Terminal width from the header.
            height: Terminal height from the header.
            size_bytes: Size of the on-disk ``.cast`` file.
            cast_path: Path to the ``.cast`` file.
            status: ``"complete"`` or ``"error"``.
        """
        await self._db.execute(
            """
            UPDATE sessions SET
                shell_user       = ?,
                started_at       = COALESCE(started_at, ?),
                ended_at         = datetime('now'),
                duration_seconds = ?,
                width            = ?,
                height           = ?,
                size_bytes       = ?,
                cast_path        = ?,
                status           = ?,
                updated_at       = datetime('now')
            WHERE conn_id = ? AND status != 'complete'
            """,
            (
                shell_user,
                started_at,
                duration_seconds,
                width,
                height,
                size_bytes,
                cast_path,
                status,
                conn_id,
            ),
        )
        await self._db.commit()

    # --- detection summary -----------------------------------------------------

    async def update_finding_summary(
        self, conn_id: str, finding_count: int, max_severity: str | None
    ) -> None:
        """Set the denormalized risk summary on a session row.

        Mirrors the ``findings`` table's per-session aggregate onto the session row
        so listings and dashboards can filter/sort without a join (CLAUDE.md rule 6:
        only the rule-derived count and severity are stored, never matched text).

        Args:
            conn_id: The connection id whose summary to update.
            finding_count: Number of findings recorded for the session.
            max_severity: Highest finding severity, or ``None`` when there are none.
        """
        await self._db.execute(
            "UPDATE sessions SET finding_count = ?, max_severity = ?, updated_at = datetime('now') WHERE conn_id = ?",
            (finding_count, max_severity, conn_id),
        )
        await self._db.commit()

    # --- startup sweep ---------------------------------------------------------

    async def find_provisional(self) -> list[tuple[str, str | None]]:
        """Return ``(conn_id, created_at)`` for every provisional row.

        Used by the assembler's startup sweep to reconcile rows orphaned by a crash.

        Returns:
            A list of ``(conn_id, created_at)`` tuples.
        """
        cursor = await self._db.execute(
            "SELECT conn_id, created_at FROM sessions WHERE status = 'provisional'"
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [(row["conn_id"], row["created_at"]) for row in rows]

    async def find_finalized(self) -> list[tuple[str, str | None]]:
        """Return ``(conn_id, cast_path)`` for every complete/error session.

        Used by the startup backfill to find sessions whose plaintext sidecar +
        findings may not exist yet.

        Returns:
            A list of ``(conn_id, cast_path)`` tuples for finalized sessions.
        """
        cursor = await self._db.execute(
            "SELECT conn_id, cast_path FROM sessions WHERE status IN ('complete', 'error')"
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [(row["conn_id"], row["cast_path"]) for row in rows]

    async def delete_provisional(self, conn_id: str) -> None:
        """Delete a single stale provisional row (startup sweep of empty sessions).

        Guarded by ``status = 'provisional'`` so a concurrently completed row is
        never removed.

        Args:
            conn_id: The connection id to delete.
        """
        await self._db.execute(
            "DELETE FROM sessions WHERE conn_id = ? AND status = 'provisional'",
            (conn_id,),
        )
        await self._db.commit()

    # --- query path (web UI) ---------------------------------------------------

    async def list_systems(self) -> list[SystemSummary]:
        """List distinct target systems with counts, last activity, and risk (Q12).

        The union of systems that have recording sessions and clusters that have
        only kubectl API activity: :data:`LIST_SYSTEMS_SQL`, a ``UNION ALL`` of the
        per-system ``sessions`` aggregate and a ``GROUP BY resource_address`` over
        ``api_requests`` (a covering scan of ``idx_api_req_sys_time``), folded by an
        outer ``GROUP BY``. ``GROUP BY`` keeps the NULL (unknown) bucket as one group.

        ``last_session_at`` is the newest recording start and ``last_api_at`` the
        newest ``requested_at``, both in the ``requested_at`` format;
        ``last_seen`` is the larger of the two. Rows are ordered by that value,
        newest first (ties by address). ``finding_count`` and ``max_severity``
        summarize recording findings only.

        Returns:
            A list of ``SystemSummary`` rows, most-recent activity first.
        """
        cursor = await self._db.execute(LIST_SYSTEMS_SQL)
        rows = await cursor.fetchall()
        await cursor.close()
        summaries: list[SystemSummary] = []
        for row in rows:
            last_session_at = row["last_session_at"]
            last_api_at = row["last_api_at"]
            present = [t for t in (last_session_at, last_api_at) if t]
            summaries.append(
                SystemSummary(
                    resource_address=row["resource_address"],
                    session_count=int(row["session_count"] or 0),
                    ssh_count=int(row["ssh_count"] or 0),
                    exec_count=int(row["exec_count"] or 0),
                    api_request_count=int(row["api_request_count"] or 0),
                    last_session_at=last_session_at,
                    last_api_at=last_api_at,
                    last_seen=max(present) if present else None,
                    finding_count=int(row["finding_count"] or 0),
                    max_severity=_RANK_TO_SEVERITY.get(int(row["sev_rank"] or 0)),
                )
            )
        return summaries

    async def list_sessions(self, resource_address: str | None) -> list[Session]:
        """List sessions for one system, newest first.

        Newest is determined by ``started_at`` (falling back to ``created_at`` when
        a session never recorded a start). Matches ``resource_address`` including the
        ``NULL`` (unknown system) bucket.

        Args:
            resource_address: The target system address (or ``None`` for the unknown
                bucket).

        Returns:
            A list of ``Session`` rows, newest first.
        """
        if resource_address is None:
            cursor = await self._db.execute(
                f"""
                SELECT {_SESSION_COLUMNS}
                FROM sessions
                WHERE resource_address IS NULL
                ORDER BY COALESCE(started_at, created_at) DESC
                """
            )
        else:
            cursor = await self._db.execute(
                f"""
                SELECT {_SESSION_COLUMNS}
                FROM sessions
                WHERE resource_address = ?
                ORDER BY COALESCE(started_at, created_at) DESC
                """,
                (resource_address,),
            )
        rows = await cursor.fetchall()
        await cursor.close()
        return [_row_to_session(row) for row in rows]

    async def get(self, conn_id: str) -> Session | None:
        """Fetch a single session by connection id.

        Args:
            conn_id: The connection id to look up.

        Returns:
            The ``Session`` row, or ``None`` if no such row exists.
        """
        cursor = await self._db.execute(
            f"SELECT {_SESSION_COLUMNS} FROM sessions WHERE conn_id = ?",
            (conn_id,),
        )
        row = await cursor.fetchone()
        await cursor.close()
        return _row_to_session(row) if row is not None else None

    # --- retention purge -------------------------------------------------------

    async def purge_before(self, iso_cutoff: str) -> list[PurgedSession]:
        """Delete sessions whose ``started_at`` is older than ``iso_cutoff``.

        Selects the affected rows first so the caller can remove their ``.cast``
        files, then deletes them in the same transaction. Rows with a NULL
        ``started_at`` are not purged by age (their age is unknown).

        Args:
            iso_cutoff: An ISO8601 cutoff string; rows with ``started_at`` strictly
                less than this are deleted.

        Returns:
            The ``(conn_id, cast_path)`` of each deleted row.
        """
        cursor = await self._db.execute(
            """
            SELECT conn_id, cast_path
            FROM sessions
            WHERE started_at IS NOT NULL AND started_at < ?
            """,
            (iso_cutoff,),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        purged = [
            PurgedSession(conn_id=row["conn_id"], cast_path=row["cast_path"])
            for row in rows
        ]
        if purged:
            await self._db.executemany(
                "DELETE FROM sessions WHERE conn_id = ?",
                [(p.conn_id,) for p in purged],
            )
            await self._db.commit()
        return purged

    async def purge_over_bytes(self, max_bytes: int) -> list[PurgedSession]:
        """Delete oldest complete sessions until total ``size_bytes`` is under a cap.

        Only ``complete`` sessions are eligible (a provisional session is still
        buffering). Deletes oldest-first by ``started_at``/``created_at``. Sizing uses
        the recorded ``size_bytes``; the caller removes the corresponding files.

        Args:
            max_bytes: The total ``.cast`` size cap in bytes. Non-positive disables
                the purge (returns an empty list).

        Returns:
            The ``(conn_id, cast_path)`` of each deleted row.
        """
        if max_bytes <= 0:
            return []

        cursor = await self._db.execute(
            "SELECT COALESCE(SUM(size_bytes), 0) AS total FROM sessions"
        )
        total_row = await cursor.fetchone()
        await cursor.close()
        total = int(total_row["total"]) if total_row is not None else 0
        if total <= max_bytes:
            return []

        # Oldest complete sessions first; trim until under the cap.
        cursor = await self._db.execute(
            """
            SELECT conn_id, cast_path, size_bytes
            FROM sessions
            WHERE status = 'complete'
            ORDER BY COALESCE(started_at, created_at) ASC
            """
        )
        rows = await cursor.fetchall()
        await cursor.close()

        purged: list[PurgedSession] = []
        for row in rows:
            if total <= max_bytes:
                break
            purged.append(
                PurgedSession(conn_id=row["conn_id"], cast_path=row["cast_path"])
            )
            total -= int(row["size_bytes"] or 0)

        if purged:
            await self._db.executemany(
                "DELETE FROM sessions WHERE conn_id = ?",
                [(p.conn_id,) for p in purged],
            )
            await self._db.commit()
        return purged
