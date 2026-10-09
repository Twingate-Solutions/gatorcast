"""Search + findings store: metadata/finding filtering plus scan-on-demand content.

This module owns the ``findings`` table (delete-then-insert reconciliation, ordered
reads) and the composite **search** that powers the UI. Search runs cheapest-first:
a parameterized WHERE over ``sessions`` (plus EXISTS subqueries over ``findings``)
narrows the candidate set, and only then — when a keyword or regex is supplied — are
the encrypted plaintext sidecars read and scanned in Python.

There is deliberately no FTS5 index: recordings are secret-grade (CLAUDE.md rule 5),
so their text is never indexed in SQLite. Content search decrypts sidecars on demand
over a metadata-narrowed set, bounded by ``regex_max_candidates`` (a ReDoS / resource
guard). The Python scan runs off the event loop via ``asyncio.to_thread``.

Security:
  * All SQL is parameterized; filter values are never string-interpolated.
  * Sidecar CONTENT is never logged (CLAUDE.md rule 5). The only counter logged on a
    truncated scan is the number of dropped candidates — never any text.
  * A :class:`FindingRow` carries rule metadata + offset only, never matched text
    (CLAUDE.md rule 6).
"""

from __future__ import annotations

import asyncio
import re

import aiosqlite
from pydantic import BaseModel

from gatorcast.db import cmd_key, session_at
from gatorcast.logging import get_logger
from gatorcast.models import Session
from gatorcast.pipeline.detect import SEVERITY_RANK, Finding
from gatorcast.store.activity import to_requested_at_format
from gatorcast.store.casts import CastStore
from gatorcast.store.sessions import _SESSION_COLUMNS, _row_to_session

log = get_logger(__name__)


class SearchFilters(BaseModel):
    """User-supplied search criteria. All fields optional except paging defaults."""

    username: str | None = None
    resource_address: str | None = None
    status: str | None = None
    started_after: str | None = None
    started_before: str | None = None
    min_duration: float | None = None
    max_duration: float | None = None
    category: str | None = None
    severity: str | None = None
    max_severity: str | None = None
    rule_ids: list[str] = []
    has_findings: bool | None = None
    keyword: str | None = None
    regex: str | None = None
    sort: str = "newest"
    page: int = 1
    page_size: int = 50


class FindingRow(BaseModel):
    """One persisted finding row (rule metadata + offset only, never matched text)."""

    id: int
    conn_id: str
    rule_id: str
    category: str
    severity: str
    label: str
    offset_seconds: float | None = None
    created_at: str | None = None


class SessionWithFindings(BaseModel):
    """A session paired with its findings for a search result item."""

    session: Session
    findings: list[FindingRow] = []


class LabeledCount(BaseModel):
    """A label/count pair for dashboard top-N breakdowns."""

    label: str
    count: int


class SearchResult(BaseModel):
    """A page of search results plus paging metadata."""

    items: list[SessionWithFindings]
    total: int
    page: int
    page_size: int
    truncated: bool = False


class DashboardStats(BaseModel):
    """Aggregate counts for the dashboard view (unified search spec §8.2).

    Session figures are windowed on the recording start (``SESSION_AT_SQL``), the
    same predicate ``/search`` uses, so ``total_sessions`` equals the item count of
    ``type=recordings&window=W``, ``flagged_sessions`` that of
    ``type=recordings&has_findings=true&window=W``, and each ``by_severity`` entry
    that of ``type=recordings&max_severity=S&window=W``.

    The ``api_*`` fields cover kubectl activity:

    * ``api_requests_total`` counts stored **requests** (discovery included),
      windowed on ``api_requests.requested_at``. It is the one figure that is not
      an item count of its linked search.
    * ``api_flagged_commands`` counts kubectl **commands** with at least one API
      finding, each once, windowed on the command's start row — the item count of
      ``type=kubectl&has_findings=true&window=W``.
    * ``api_commands_by_severity`` maps each flagged command's highest finding
      severity to a command count — each entry is the item count of
      ``type=kubectl&max_severity=S&window=W``. A command whose findings all have
      an unknown severity is counted in ``api_flagged_commands`` but in no entry.
    * ``api_flagged_truncated`` is true when more than ``_FLAGGED_CMD_CAP``
      flagged commands were found; the figures are then lower bounds and
      ``api_flagged_commands`` is clamped to the cap (rendered as ``5000+``).

    ``web_requests_total`` counts stored web **requests** (``api_kind = 'web'``),
    windowed on ``api_requests.requested_at`` (WEBAPP_SPEC §8.6). Like
    ``api_requests_total`` it is a request count, while its linked ``type=web``
    search lists connections.
    """

    total_sessions: int
    flagged_sessions: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    top_users: list[LabeledCount]
    top_systems: list[LabeledCount]
    api_requests_total: int = 0
    api_flagged_commands: int = 0
    api_commands_by_severity: dict[str, int] = {}
    api_flagged_truncated: bool = False
    web_requests_total: int = 0


# ``api_kind`` → its SQL literal, for the request totals. Fixed strings only, so the
# kind never reaches SQL from input and each kind's statement text is static.
_API_KIND_LITERALS: dict[str, str] = {"kubectl": "'kubectl'", "web": "'web'"}


# Columns for a FindingRow, in model field order.
_FINDING_COLUMNS = "id, conn_id, rule_id, category, severity, label, offset_seconds, created_at"


def _row_to_finding(row: aiosqlite.Row) -> FindingRow:
    """Map a ``findings`` table row to a :class:`FindingRow`."""
    return FindingRow(
        id=row["id"],
        conn_id=row["conn_id"],
        rule_id=row["rule_id"],
        category=row["category"],
        severity=row["severity"],
        label=row["label"],
        offset_seconds=row["offset_seconds"],
        created_at=row["created_at"],
    )


def _severities_at_or_above(severity: str) -> list[str]:
    """Return the severity strings whose rank is >= the requested severity's rank.

    An unknown severity string yields an empty list (so the caller matches nothing).

    Args:
        severity: The requested severity (e.g. ``"medium"``).

    Returns:
        The list of severities with rank >= the requested rank, or ``[]`` if the
        requested severity is not a known rank.
    """
    floor = SEVERITY_RANK.get(severity)
    if floor is None:
        return []
    return [name for name, rank in SEVERITY_RANK.items() if rank >= floor]


# Static fragment used only for the risk sort; no user input is interpolated.
_RISK_CASE = (
    "CASE max_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
    "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
)

# Static rank of an API finding's severity, for a per-request MAX(). No user input.
_API_FINDING_RANK_CASE = (
    "CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
    "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
)

# Maps a severity rank back to its label (0 / unknown → dropped).
_RANK_TO_SEVERITY = {rank: name for name, rank in SEVERITY_RANK.items()}

# Distinct flagged kubectl commands considered by one dashboard query (spec §6.5,
# same cap as the search's flagged mode). Read at call time so tests can lower it.
_FLAGGED_CMD_CAP = 5000

# "q is a row of the command identified by hit row h" (spec §6.3 SAME_CMD). The
# command key is rendered by db.cmd_key so SQLite matches it to idx_api_req_cmd.
# The unary ``+`` on the two scope columns stops the planner from choosing
# idx_api_req_sys_kind_user_time instead (a range over the user's whole history on
# that cluster); they stay residual filters on the idx_api_req_cmd range. No
# ``api_kind`` term: a command key is single-kind, and adding one flips the probe
# to a full kind scan. Static SQL: no user value is interpolated.
_SAME_CMD_AS_HIT = (
    f"{cmd_key('q')} = h.ck "
    "AND +q.resource_address IS h.resource_address AND +q.user_key IS h.user_key"
)


def flagged_command_stats_sql(*, windowed: bool) -> str:
    """Return the dashboard flagged-command query (spec ``Q10``).

    One row per ``(in_window, max_rank)`` with a command count. Named parameters:
    ``:cap`` (the ``hit`` limit, ``_FLAGGED_CMD_CAP + 1``) and, when ``windowed``,
    ``:cutoff`` (``…SS.mmmZ`` format). ``CROSS JOIN`` fixes SQLite's join order so
    both ``hit`` and the per-command rank are driven as the spec's plan requires
    (``api_findings`` → ``api_requests`` primary key; ``idx_api_req_cmd`` → findings).
    ``hit`` is restricted to ``api_kind = 'kubectl'`` (a command key is single-kind,
    so the per-command probes need no kind term).
    Static SQL: only fixed fragments are interpolated, never a user value.

    Args:
        windowed: Whether to emit the ``:cutoff`` predicates.

    Returns:
        The SQL text.
    """
    hit_where = (
        "WHERE r.api_kind = 'kubectl' AND r.requested_at >= :cutoff"
        if windowed
        else "WHERE r.api_kind = 'kubectl'"
    )
    in_window = "(c.start_at >= :cutoff)" if windowed else "1"
    return f"""
        WITH hit AS (
            SELECT DISTINCT r.resource_address AS resource_address,
                            r.user_key AS user_key,
                            {cmd_key("r")} AS ck
            FROM api_findings f
            CROSS JOIN api_requests r ON r.request_id = f.request_id
            {hit_where}
            LIMIT :cap
        ),
        cmd AS (
            SELECT
                (SELECT q.requested_at FROM api_requests q
                  WHERE {_SAME_CMD_AS_HIT}
                  ORDER BY q.requested_at, q.request_id LIMIT 1) AS start_at,
                (SELECT MAX({_API_FINDING_RANK_CASE})
                   FROM api_requests q
                   CROSS JOIN api_findings f ON f.request_id = q.request_id
                  WHERE {_SAME_CMD_AS_HIT}) AS max_rank
            FROM hit h
        )
        SELECT {in_window} AS in_window, c.max_rank AS max_rank, COUNT(*) AS n
        FROM cmd c
        GROUP BY 1, 2
    """


class SearchStore:
    """Findings persistence plus composite metadata/finding/content search."""

    def __init__(self, db: aiosqlite.Connection, casts: CastStore) -> None:
        """Initialize the search store.

        Args:
            db: An open aiosqlite connection (WAL, ``aiosqlite.Row`` factory).
            casts: The cast store used to read plaintext sidecars on demand.
        """
        self._db = db
        self._casts = casts

    # --- findings persistence --------------------------------------------------

    async def replace_findings(self, conn_id: str, findings: list[Finding]) -> None:
        """Replace all findings for a session (delete-then-insert; idempotent).

        Re-running with the same findings yields the same rows with no duplicates.
        Matched text is never persisted (CLAUDE.md rule 6).

        Args:
            conn_id: The connection id whose findings to replace.
            findings: The findings to store (may be empty to clear).
        """
        await self._db.execute("DELETE FROM findings WHERE conn_id = ?", (conn_id,))
        if findings:
            await self._db.executemany(
                """
                INSERT INTO findings (conn_id, rule_id, category, severity, label, offset_seconds)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        conn_id,
                        f.rule_id,
                        f.category,
                        f.severity,
                        f.label,
                        f.offset_seconds,
                    )
                    for f in findings
                ],
            )
        await self._db.commit()

    async def list_findings(self, conn_id: str) -> list[FindingRow]:
        """List a session's findings, earliest offset first (NULL offsets last).

        Args:
            conn_id: The connection id whose findings to list.

        Returns:
            The findings ordered by ``offset_seconds`` (NULLs last), then ``id``.
        """
        cursor = await self._db.execute(
            f"""
            SELECT {_FINDING_COLUMNS}
            FROM findings
            WHERE conn_id = ?
            ORDER BY offset_seconds IS NULL, offset_seconds, id
            """,
            (conn_id,),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [_row_to_finding(row) for row in rows]

    async def delete_findings(self, conn_id: str) -> None:
        """Delete all findings for a session.

        Args:
            conn_id: The connection id whose findings to delete.
        """
        await self._db.execute("DELETE FROM findings WHERE conn_id = ?", (conn_id,))
        await self._db.commit()

    # --- search ----------------------------------------------------------------

    def _build_where(self, filters: SearchFilters) -> tuple[str, list[object]]:
        """Build the parameterized WHERE clause + params for metadata/finding filters.

        Only clauses for non-None (or non-empty) filters are emitted. Severity is
        expanded to an at-or-above set via :func:`_severities_at_or_above`; an unknown
        severity contributes a clause that matches nothing.

        Args:
            filters: The active search filters.

        Returns:
            A ``(where_sql, params)`` tuple. ``where_sql`` is empty (no leading
            ``WHERE``) when there are no constraints; otherwise it is the conjunction
            of clauses (no leading ``WHERE`` keyword).
        """
        clauses: list[str] = []
        params: list[object] = []

        # 1. Metadata filters on the sessions table.
        if filters.username is not None:
            clauses.append("username = ?")
            params.append(filters.username)
        if filters.resource_address is not None:
            clauses.append("resource_address = ?")
            params.append(filters.resource_address)
        if filters.status is not None:
            clauses.append("status = ?")
            params.append(filters.status)
        if filters.started_after is not None:
            clauses.append("started_at >= ?")
            params.append(filters.started_after)
        if filters.started_before is not None:
            clauses.append("started_at <= ?")
            params.append(filters.started_before)
        if filters.min_duration is not None:
            clauses.append("duration_seconds >= ?")
            params.append(filters.min_duration)
        if filters.max_duration is not None:
            clauses.append("duration_seconds <= ?")
            params.append(filters.max_duration)

        # 2. Finding filters (session column or EXISTS subqueries over findings).
        if filters.has_findings is True:
            clauses.append("finding_count > 0")
        elif filters.has_findings is False:
            clauses.append("finding_count = 0")

        # Exact highest-severity match (drives the dashboard's per-severity drill-down,
        # which counts sessions by their single highest severity). Distinct from the
        # `severity` filter above, which is an at-or-above match over findings.
        if filters.max_severity is not None:
            clauses.append("max_severity = ?")
            params.append(filters.max_severity)

        if filters.category is not None:
            clauses.append(
                "EXISTS (SELECT 1 FROM findings f WHERE f.conn_id = sessions.conn_id AND f.category = ?)"
            )
            params.append(filters.category)

        if filters.rule_ids:
            placeholders = ", ".join("?" for _ in filters.rule_ids)
            clauses.append(
                f"EXISTS (SELECT 1 FROM findings f WHERE f.conn_id = sessions.conn_id AND f.rule_id IN ({placeholders}))"
            )
            params.extend(filters.rule_ids)

        if filters.severity is not None:
            allowed = _severities_at_or_above(filters.severity)
            if not allowed:
                # Unknown severity → match nothing.
                clauses.append("1 = 0")
            else:
                placeholders = ", ".join("?" for _ in allowed)
                clauses.append(
                    f"EXISTS (SELECT 1 FROM findings f WHERE f.conn_id = sessions.conn_id AND f.severity IN ({placeholders}))"
                )
                params.extend(allowed)

        where_sql = " AND ".join(clauses)
        return where_sql, params

    @staticmethod
    def _order_by(sort: str) -> str:
        """Return the ORDER BY fragment for a sort mode (static; no user values).

        Args:
            sort: One of ``"newest"``, ``"duration"``, ``"risk"`` (any other value
                falls back to newest).

        Returns:
            The ORDER BY clause text (without the ``ORDER BY`` keyword).
        """
        match sort:
            case "duration":
                # NULLS LAST emulation, then longest first.
                return "duration_seconds IS NULL, duration_seconds DESC"
            case "risk":
                return f"{_RISK_CASE} DESC, COALESCE(started_at, created_at) DESC"
            case _:
                return "COALESCE(started_at, created_at) DESC"

    async def _candidate_conn_ids(
        self, where_sql: str, params: list[object], order_by: str
    ) -> list[str]:
        """Return ALL matching conn_ids in sort order (no LIMIT). For content scans."""
        where = f"WHERE {where_sql}" if where_sql else ""
        cursor = await self._db.execute(
            f"SELECT conn_id FROM sessions {where} ORDER BY {order_by}",
            tuple(params),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [row["conn_id"] for row in rows]

    async def _count(self, where_sql: str, params: list[object]) -> int:
        """Return COUNT(*) of sessions matching the WHERE clause."""
        where = f"WHERE {where_sql}" if where_sql else ""
        cursor = await self._db.execute(
            f"SELECT COUNT(*) AS n FROM sessions {where}", tuple(params)
        )
        row = await cursor.fetchone()
        await cursor.close()
        return int(row["n"]) if row is not None else 0

    async def _page_conn_ids(
        self,
        where_sql: str,
        params: list[object],
        order_by: str,
        *,
        limit: int,
        offset: int,
    ) -> list[str]:
        """Return one page of matching conn_ids in sort order (LIMIT/OFFSET)."""
        where = f"WHERE {where_sql}" if where_sql else ""
        cursor = await self._db.execute(
            f"SELECT conn_id FROM sessions {where} ORDER BY {order_by} LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [row["conn_id"] for row in rows]

    async def _load_items(self, conn_ids: list[str]) -> list[SessionWithFindings]:
        """Load sessions + findings for an ordered conn_id list, preserving order."""
        items: list[SessionWithFindings] = []
        for conn_id in conn_ids:
            cursor = await self._db.execute(
                f"SELECT {_SESSION_COLUMNS} FROM sessions WHERE conn_id = ?",
                (conn_id,),
            )
            row = await cursor.fetchone()
            await cursor.close()
            if row is None:
                continue
            session = _row_to_session(row)
            findings = await self.list_findings(conn_id)
            items.append(SessionWithFindings(session=session, findings=findings))
        return items

    @staticmethod
    def _scan_matches(
        texts: list[tuple[str, str]],
        keyword: str | None,
        compiled: re.Pattern[str] | None,
    ) -> list[str]:
        """Filter (conn_id, text) pairs by keyword AND/OR regex (runs off-loop).

        A candidate passes only if it satisfies ALL provided content filters. This is
        pure CPU work intended for ``asyncio.to_thread``; it never logs text.

        Args:
            texts: ``(conn_id, sidecar_text)`` pairs to scan, in candidate order.
            keyword: Case-insensitive substring to require, or ``None``.
            compiled: Pre-compiled regex to require, or ``None``.

        Returns:
            The conn_ids that matched, preserving the input order.
        """
        kw = keyword.lower() if keyword is not None else None
        matched: list[str] = []
        for conn_id, text in texts:
            if kw is not None and kw not in text.lower():
                continue
            if compiled is not None and compiled.search(text) is None:
                continue
            matched.append(conn_id)
        return matched

    async def search(
        self, filters: SearchFilters, *, regex_max_candidates: int = 2000
    ) -> SearchResult:
        """Run a composite metadata/finding/content search.

        Execution is cheapest-first: a parameterized WHERE over ``sessions`` (with
        EXISTS subqueries over ``findings``) narrows candidates, then — only when a
        keyword or regex is supplied — the encrypted sidecars for the narrowed set are
        decrypted and scanned in Python (off the event loop). The content scan is
        bounded by ``regex_max_candidates``; exceeding it sets ``truncated`` and logs a
        counter of dropped candidates (never any text, CLAUDE.md rule 5).

        An invalid user regex is treated as a no-match (returns an empty result), never
        a raised error.

        Args:
            filters: The active search filters (including paging and sort).
            regex_max_candidates: Cap on sidecars scanned for a content search.

        Returns:
            A :class:`SearchResult` page with total match count and paging metadata.
        """
        where_sql, params = self._build_where(filters)
        order_by = self._order_by(filters.sort)
        page = max(1, filters.page)
        page_size = max(1, filters.page_size)

        has_content = filters.keyword is not None or filters.regex is not None

        # --- Metadata-only branch: page directly in SQL. --------------------------
        if not has_content:
            total = await self._count(where_sql, params)
            conn_ids = await self._page_conn_ids(
                where_sql,
                params,
                order_by,
                limit=page_size,
                offset=(page - 1) * page_size,
            )
            items = await self._load_items(conn_ids)
            return SearchResult(
                items=items,
                total=total,
                page=page,
                page_size=page_size,
                truncated=False,
            )

        # --- Content-scan branch. -------------------------------------------------
        # Compile the user regex once, guarded; an invalid pattern => empty result.
        compiled: re.Pattern[str] | None = None
        if filters.regex is not None:
            try:
                compiled = re.compile(filters.regex)
            except re.error:
                return SearchResult(
                    items=[], total=0, page=page, page_size=page_size, truncated=False
                )

        candidates = await self._candidate_conn_ids(where_sql, params, order_by)
        truncated = len(candidates) > regex_max_candidates
        if truncated:
            dropped = len(candidates) - regex_max_candidates
            candidates = candidates[:regex_max_candidates]
            # Counter only — never log sidecar content (CLAUDE.md rule 5).
            log.info("search.truncated", dropped=dropped, scanned=len(candidates))

        # Read sidecars (already off-loop in CastStore); skip missing ones silently.
        texts: list[tuple[str, str]] = []
        for conn_id in candidates:
            try:
                text = await self._casts.read_sidecar(conn_id)
            except FileNotFoundError:
                continue
            texts.append((conn_id, text))

        # Run the pure CPU matching off the event loop.
        matched = await asyncio.to_thread(
            self._scan_matches, texts, filters.keyword, compiled
        )

        total = len(matched)
        start = (page - 1) * page_size
        page_ids = matched[start : start + page_size]
        items = await self._load_items(page_ids)
        return SearchResult(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            truncated=truncated,
        )

    # --- dashboard -------------------------------------------------------------

    async def dashboard_stats(self, *, started_after: str | None = None) -> DashboardStats:
        """Compute aggregate counts for the dashboard, optionally time-windowed.

        Every count is defined so it equals the item count of the unified search
        the dashboard links it to (spec §8.2), except the request totals
        ``api_requests_total`` and ``web_requests_total``:

        * Sessions are windowed on ``SESSION_AT_SQL`` (``COALESCE(started_at,
          created_at)`` rendered in the ``requested_at`` format), the predicate
          search's ``window``/``from`` uses. A session with a NULL ``started_at``
          is placed by ``created_at``, and fractional-second starts compare
          correctly at the boundary second.
        * kubectl figures count commands from ``Q10`` (see
          :meth:`_api_command_stats`).

        Args:
            started_after: An ISO 8601 cutoff (any ``fromisoformat`` shape; naive is
                UTC); when supplied, every aggregate counts only sessions whose start
                is at or after it (and findings on those sessions), API requests at
                or after it, and kubectl commands whose start row is at or after it.
                ``None`` means all time. It is normalized with
                :func:`to_requested_at_format`, as search normalizes ``from``.

        Returns:
            A :class:`DashboardStats` with total/flagged session counts, a per-session
            highest-severity breakdown, a per-category finding breakdown, the top 10
            users and systems by session count, the kubectl and web request
            totals, and the flagged-command figures — all within the window.

        Raises:
            ValueError: If ``started_after`` is not parseable ISO 8601.
        """
        cutoff = to_requested_at_format(started_after) if started_after else None
        win = f"{session_at()} >= ?"
        p: tuple[object, ...] = (cutoff,) if cutoff else ()

        def s_and() -> str:
            return f" AND {win}" if cutoff else ""

        def s_where() -> str:
            return f" WHERE {win}" if cutoff else ""

        # total / flagged sessions (every sessions row: ssh + exec + failed)
        cursor = await self._db.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN finding_count > 0 THEN 1 ELSE 0 END) AS flagged "
            f"FROM sessions{s_where()}",
            p,
        )
        row = await cursor.fetchone()
        await cursor.close()
        total_sessions = int(row["total"]) if row is not None else 0
        flagged_sessions = int(row["flagged"] or 0) if row is not None else 0

        # by severity (per-session highest severity; non-null only)
        cursor = await self._db.execute(
            "SELECT max_severity AS sev, COUNT(*) AS n FROM sessions "
            f"WHERE max_severity IS NOT NULL{s_and()} GROUP BY max_severity",
            p,
        )
        sev_rows = await cursor.fetchall()
        await cursor.close()
        by_severity = {r["sev"]: int(r["n"]) for r in sev_rows}

        # by category (per-finding; joined to the session for the time window)
        cat_where = f" WHERE {session_at('s')} >= ?" if cutoff else ""
        cursor = await self._db.execute(
            "SELECT f.category AS cat, COUNT(*) AS n FROM findings f "
            f"JOIN sessions s ON s.conn_id = f.conn_id{cat_where} GROUP BY f.category",
            p,
        )
        cat_rows = await cursor.fetchall()
        await cursor.close()
        by_category = {r["cat"]: int(r["n"]) for r in cat_rows}

        # top users / systems by session count (non-null), desc, top 10
        cursor = await self._db.execute(
            "SELECT username AS label, COUNT(*) AS n FROM sessions "
            f"WHERE username IS NOT NULL{s_and()} GROUP BY username ORDER BY n DESC, username LIMIT 10",
            p,
        )
        user_rows = await cursor.fetchall()
        await cursor.close()
        top_users = [LabeledCount(label=r["label"], count=int(r["n"])) for r in user_rows]

        cursor = await self._db.execute(
            "SELECT resource_address AS label, COUNT(*) AS n FROM sessions "
            f"WHERE resource_address IS NOT NULL{s_and()} GROUP BY resource_address ORDER BY n DESC, resource_address LIMIT 10",
            p,
        )
        sys_rows = await cursor.fetchall()
        await cursor.close()
        top_systems = [LabeledCount(label=r["label"], count=int(r["n"])) for r in sys_rows]

        api_total = await self._api_request_total(cutoff)
        web_total = await self._api_request_total(cutoff, api_kind="web")
        flagged_cmds, cmds_by_severity, truncated = await self._api_command_stats(cutoff)

        return DashboardStats(
            total_sessions=total_sessions,
            flagged_sessions=flagged_sessions,
            by_severity=by_severity,
            by_category=by_category,
            top_users=top_users,
            top_systems=top_systems,
            api_requests_total=api_total,
            api_flagged_commands=flagged_cmds,
            api_commands_by_severity=cmds_by_severity,
            api_flagged_truncated=truncated,
            web_requests_total=web_total,
        )

    async def _api_request_total(self, cutoff: str | None, api_kind: str = "kubectl") -> int:
        """Count stored API requests of one kind for the dashboard.

        Restricted to ``api_kind`` and windowed on ``api_requests.requested_at``
        (``idx_api_req_kind_time``). This is a request count, not a command or
        connection count, so it is not the item count of its linked
        ``type=kubectl`` / ``type=web`` search (spec §8.2 "kubectl API requests";
        WEBAPP_SPEC §8.6 "Web requests"). kubectl discovery requests are included.

        Args:
            cutoff: A cutoff already in the stored ``…SS.mmmZ`` format, or ``None``
                for all time.
            api_kind: ``'kubectl'`` (default) or ``'web'``; mapped to a fixed SQL
                literal.

        Returns:
            The number of stored requests at or after the cutoff.

        Raises:
            KeyError: If ``api_kind`` is not a known kind.
        """
        r_where = f" WHERE api_kind = {_API_KIND_LITERALS[api_kind]}"
        if cutoff:
            r_where += " AND requested_at >= ?"
        p: tuple[object, ...] = (cutoff,) if cutoff else ()
        cursor = await self._db.execute(f"SELECT COUNT(*) AS n FROM api_requests{r_where}", p)
        row = await cursor.fetchone()
        await cursor.close()
        return int(row["n"]) if row is not None else 0

    async def _api_command_stats(
        self, cutoff: str | None
    ) -> tuple[int, dict[str, int], bool]:
        """Count flagged kubectl commands by highest severity (spec ``Q10``).

        ``Q10`` is the search's flagged-mode ``Q5`` without a keyset: commands are
        found from ``api_findings`` (``hit``, at most ``_FLAGGED_CMD_CAP + 1``
        distinct commands), then each command's start row and highest finding rank
        are computed over **all** its rows through ``idx_api_req_cmd``. A command
        is ``(resource_address, user_key, CMD_KEY)`` and is counted once, at its
        max severity, in the window that contains its start row — exactly how
        ``type=kubectl&has_findings=true`` / ``&max_severity=S`` select and window
        commands, so each figure equals the item count of its linked list.

        ``hit`` is driven from ``api_findings``, which holds only rule hits, and
        reaches ``api_requests`` through its primary key, so the cost does not
        grow with the time range (:func:`flagged_command_stats_sql`). The ``hit``
        prefilter ``r.requested_at >= cutoff`` is safe: a command that
        starts in the window has every row at or after its start. Discovery is not
        applied (no API rule fires on a discovery path). Only counts and
        rule-derived severities are read — never a URL or header value.

        Args:
            cutoff: A cutoff already in the stored ``…SS.mmmZ`` format, or ``None``
                for all time.

        Returns:
            ``(flagged_commands, highest severity → command count, truncated)``.
            When truncated, the figures cover only the capped set and
            ``flagged_commands`` is clamped to the cap.
        """
        cap = _FLAGGED_CMD_CAP
        params: dict[str, object] = {"cap": cap + 1}
        if cutoff:
            params["cutoff"] = cutoff

        cursor = await self._db.execute(
            flagged_command_stats_sql(windowed=cutoff is not None), params
        )
        rows = await cursor.fetchall()
        await cursor.close()

        hits = 0
        flagged = 0
        by_severity: dict[str, int] = {}
        for r in rows:
            count = int(r["n"])
            hits += count
            if not r["in_window"]:
                continue
            flagged += count
            label = _RANK_TO_SEVERITY.get(int(r["max_rank"] or 0))
            if label is not None:
                by_severity[label] = by_severity.get(label, 0) + count

        truncated = hits > cap
        if truncated:
            # Counter only; never any request content.
            log.info("dashboard.flagged_commands_truncated", cap=cap)
            flagged = min(flagged, cap)
        return flagged, by_severity, truncated
