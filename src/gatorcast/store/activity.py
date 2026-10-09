"""kubectl activity store: connections, API-request metadata, and API findings.

Raw, parameterized SQL over three tables (see ``gatorcast.db``):

  * ``connections``  — hidden per-``conn_id`` state (``pending | recording | api |
    error | empty``) plus the Gateway ``resource_type``. An ``Authenticated connection`` line creates a *pending* connection
    here instead of a visible ``sessions`` row (spec §6).
  * ``api_requests`` — one row of allowlisted metadata per Gateway API-request audit
    line, deduplicated by ``request_id`` (``INSERT OR IGNORE``) so at-least-once
    redelivery never creates a duplicate request or duplicate findings.
  * ``api_findings`` — rule findings on API requests, cascade-deleted with their
    request.

It also resolves exec/attach recordings for a set of audit ``request_id`` values
(``recordings_for_requests``), reading ``sessions.request_id`` — the only link from
a command to its recording (spec §3: never ``conn_id``).

Security (CLAUDE.md rules 2, 5, 9):
  * Only the fields of :class:`~gatorcast.models.ApiRequest` are stored; that model
    is already allowlisted by the classifier (no ``Authorization``, cookies, other
    headers, response headers, ``remote_addr``, or ``panic``).
  * Nothing here logs. Callers log counters and ``conn_id`` only — never a URL,
    header value, or raw audit line.
  * All user-influenced values (``request_id``, user, bounds) are bound parameters.

Timestamps: ``api_requests.requested_at`` is stored as ``YYYY-MM-DDTHH:MM:SS.mmmZ``
and compared lexicographically, so every time bound passed in is first normalized
to that exact format by :func:`to_requested_at_format`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

import aiosqlite

from gatorcast.models import ApiRequest, GwopsSnapshot, GwopsWebApp
from gatorcast.pipeline.detect import Finding

# Valid ``connections.state`` values (spec §5/§6).
CONNECTION_STATES: frozenset[str] = frozenset({"pending", "recording", "api", "error", "empty"})

# Valid ``api_requests.api_kind`` values (WEBAPP_SPEC §4.2).
API_KINDS: frozenset[str] = frozenset({"kubectl", "web"})

# SQLite's default bound-parameter limit is 999 on older builds; stay well under it.
_IN_CHUNK = 500

# Default row cap for bounded reads; matches the route's ``_ACTIVITY_MAX_ROWS``.
DEFAULT_MAX_ROWS = 20000


# --- row types -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConnectionRow:
    """One ``connections`` row: hidden per-connection lifecycle state."""

    conn_id: str
    user_id: str | None
    username: str | None
    resource_address: str | None
    started_at: str | None
    state: str
    has_api: bool
    created_at: str | None
    last_seen_at: str | None
    resource_type: str | None = None
    start_seen: bool = False
    """True once an ``Authenticated connection`` line has been processed for this row."""
    gwops_match: str | None = None
    """``exact`` | ``none`` | ``ambiguous``, or ``None`` (absent, rejected, not a web app)."""
    gwops_gateway_id: str | None = field(default=None, repr=False)
    gwops_app: str | None = field(default=None, repr=False)
    gwops_managed: bool | None = None
    downstream_tls: str | None = None
    """Configured client-facing TLS mode, or ``None`` (unknown). Copied onto web requests."""
    downstream_port: int | None = None
    upstream_tls: str | None = None
    """Configured app-facing TLS mode, or ``None`` (unknown). Copied onto web requests."""
    upstream_port: int | None = None


@dataclass(frozen=True, slots=True)
class ApiRequestRow:
    """One ``api_requests`` row: allowlisted metadata for a single API request."""

    request_id: str
    conn_id: str
    resource_address: str | None
    user_key: str | None
    user_id: str | None
    username: str | None
    requested_at: str
    method: str
    url: str
    status_code: int | None
    outcome: str
    kubectl_command: str | None
    kubectl_session: str | None
    user_agent: str | None
    created_at: str | None


@dataclass(frozen=True, slots=True)
class ApiFindingRow:
    """One ``api_findings`` row: rule metadata only, never request content."""

    id: int
    request_id: str
    rule_id: str
    category: str
    severity: str
    label: str
    created_at: str | None


@dataclass(frozen=True, slots=True)
class RequestStorage:
    """The storage form chosen for one API request (WEBAPP_SPEC §4.4 policy table).

    The assembler picks the policy from the connection row and passes the result
    here; the store writes exactly these values and applies no policy of its own.
    Every field is already allowlisted/masked by the classifier: ``url`` is
    ``ApiRequest.url`` (Kubernetes form) or ``ApiRequest.url_web`` (web form).

    Attributes:
        api_kind: ``'kubectl'`` or ``'web'`` (stored on ``api_requests.api_kind``).
        url: The URL form to store.
        user_agent: ``User-Agent`` value, or ``None``.
        kubectl_command: ``Kubectl-Command`` value, or ``None`` (always ``None`` for web).
        kubectl_session: ``Kubectl-Session`` value, or ``None`` (always ``None`` for web).
        downstream_tls: Connection's downstream TLS mode copied onto the row (web), or ``None``.
        upstream_tls: Connection's upstream TLS mode copied onto the row (web), or ``None``.
    """

    api_kind: str
    url: str
    user_agent: str | None
    kubectl_command: str | None
    kubectl_session: str | None
    downstream_tls: str | None = None
    upstream_tls: str | None = None

    def __post_init__(self) -> None:
        """Reject an unknown ``api_kind`` before it reaches the database."""
        if self.api_kind not in API_KINDS:
            raise ValueError(f"unknown api_kind: {self.api_kind!r}")

    @classmethod
    def kubectl(cls, req: ApiRequest) -> RequestStorage:
        """Kubernetes-policy form: ``req.url`` and the three allowlisted headers, no TLS."""
        return cls(
            api_kind="kubectl",
            url=req.url,
            user_agent=req.user_agent,
            kubectl_command=req.kubectl_command,
            kubectl_session=req.kubectl_session,
        )


# The eight ``gwops``/TLS snapshot columns on ``connections`` (WEBAPP_SPEC §3.3), in
# the order ``_gwops_values`` produces them and ``GwopsSnapshot`` declares them.
_GWOPS_COLUMNS: tuple[str, ...] = (
    "gwops_match",
    "gwops_gateway_id",
    "gwops_app",
    "gwops_managed",
    "downstream_tls",
    "downstream_port",
    "upstream_tls",
    "upstream_port",
)
_GWOPS_COLUMN_LIST = ", ".join(_GWOPS_COLUMNS)

# "First processing" of a start line (WEBAPP_SPEC §4.4): no start line has yet been
# processed for this ``conn_id``. ``connections.start_seen`` is the marker (set by every
# start line, never by the request path), so a start line that carried neither ``ts`` nor
# ``resource_type`` still counts as processed. The ``started_at``/``resource_type`` NULL
# test is kept for rows written before the marker existed: either column being non-NULL
# marks such a row processed, and a row with none of the three is the minimal one
# ``set_state`` inserts for a request that beat its start line. Every SET expression
# reads the pre-update row, so assigning ``start_seen``/``started_at``/``resource_type``
# in the same statement cannot change this test.
_FIRST_PROCESSING_SQL = (
    "connections.start_seen = 0 AND connections.started_at IS NULL "
    "AND connections.resource_type IS NULL"
)

# First write wins (WEBAPP_SPEC §4.4): the snapshot is taken from the incoming line only
# on the first processing of the start line.
_GWOPS_FIRST_WRITE_SET =",\n                    ".join(
    f"{col} = CASE WHEN {_FIRST_PROCESSING_SQL} THEN excluded.{col} ELSE connections.{col} END"
    for col in _GWOPS_COLUMNS
)

_CONNECTION_COLUMNS = (
    "conn_id, user_id, username, resource_address, started_at, state, has_api, "
    "created_at, last_seen_at, resource_type, start_seen, " + _GWOPS_COLUMN_LIST
)


def _gwops_values(gwops: GwopsWebApp | None) -> tuple[object, ...]:
    """Map a validated ``gwops`` object to the eight snapshot column values.

    ``exact`` yields every field; ``none`` and ``ambiguous`` yield only the match and
    gateway id (any app fields are never stored, even if the model carries them);
    ``None`` yields all NULL.

    Args:
        gwops: The validated object from ``classify``, or ``None``.

    Returns:
        Values in :data:`_GWOPS_COLUMNS` order.
    """
    if gwops is None:
        return (None,) * len(_GWOPS_COLUMNS)
    if gwops.match != "exact":
        return (gwops.match, gwops.gateway_id, None, None, None, None, None, None)
    return (
        gwops.match,
        gwops.gateway_id,
        gwops.app,
        None if gwops.managed is None else int(gwops.managed),
        gwops.downstream_tls,
        gwops.downstream_port,
        gwops.upstream_tls,
        gwops.upstream_port,
    )

# Retention for ``connections`` (WEBAPP_SPEC §9): purge on last activity, not creation.
# ``created_at <= last_seen_at`` always, so the ``created_at`` conjunct costs nothing
# semantically and lets ``idx_connections_created`` bound the scan to old-created rows
# (a MULTI-INDEX OR so a NULL ``created_at`` is still reachable); the remaining
# predicates are evaluated on those rows only. ``idx_api_req_conn`` serves the NOT EXISTS.
_PURGE_CONNECTIONS_SQL = """
DELETE FROM connections
WHERE (created_at < datetime(?1) OR created_at IS NULL)
  AND COALESCE(last_seen_at, created_at) < datetime(?1)
  AND NOT EXISTS (SELECT 1 FROM api_requests r WHERE r.conn_id = connections.conn_id)
"""

_REQUEST_COLUMNS = (
    "request_id, conn_id, resource_address, user_key, user_id, username, "
    "requested_at, method, url, status_code, outcome, kubectl_command, "
    "kubectl_session, user_agent, created_at"
)

_FINDING_COLUMNS = "id, request_id, rule_id, category, severity, label, created_at"


def _row_to_connection(row: aiosqlite.Row) -> ConnectionRow:
    """Map a ``connections`` row to a :class:`ConnectionRow`."""
    return ConnectionRow(
        conn_id=row["conn_id"],
        user_id=row["user_id"],
        username=row["username"],
        resource_address=row["resource_address"],
        started_at=row["started_at"],
        state=row["state"],
        has_api=bool(row["has_api"]),
        created_at=row["created_at"],
        last_seen_at=row["last_seen_at"],
        resource_type=row["resource_type"],
        start_seen=bool(row["start_seen"]),
        gwops_match=row["gwops_match"],
        gwops_gateway_id=row["gwops_gateway_id"],
        gwops_app=row["gwops_app"],
        gwops_managed=None if row["gwops_managed"] is None else bool(row["gwops_managed"]),
        downstream_tls=row["downstream_tls"],
        downstream_port=row["downstream_port"],
        upstream_tls=row["upstream_tls"],
        upstream_port=row["upstream_port"],
    )


def _row_to_gwops_snapshot(row: aiosqlite.Row) -> GwopsSnapshot:
    """Map the eight snapshot columns of a ``connections`` row to a :class:`GwopsSnapshot`."""
    return GwopsSnapshot(
        gwops_match=row["gwops_match"],
        gwops_gateway_id=row["gwops_gateway_id"],
        gwops_app=row["gwops_app"],
        gwops_managed=None if row["gwops_managed"] is None else bool(row["gwops_managed"]),
        downstream_tls=row["downstream_tls"],
        downstream_port=row["downstream_port"],
        upstream_tls=row["upstream_tls"],
        upstream_port=row["upstream_port"],
    )


def _row_to_request(row: aiosqlite.Row) -> ApiRequestRow:
    """Map an ``api_requests`` row to an :class:`ApiRequestRow`."""
    return ApiRequestRow(
        request_id=row["request_id"],
        conn_id=row["conn_id"],
        resource_address=row["resource_address"],
        user_key=row["user_key"],
        user_id=row["user_id"],
        username=row["username"],
        requested_at=row["requested_at"],
        method=row["method"],
        url=row["url"],
        status_code=row["status_code"],
        outcome=row["outcome"],
        kubectl_command=row["kubectl_command"],
        kubectl_session=row["kubectl_session"],
        user_agent=row["user_agent"],
        created_at=row["created_at"],
    )


def _row_to_finding(row: aiosqlite.Row) -> ApiFindingRow:
    """Map an ``api_findings`` row to an :class:`ApiFindingRow`."""
    return ApiFindingRow(
        id=row["id"],
        request_id=row["request_id"],
        rule_id=row["rule_id"],
        category=row["category"],
        severity=row["severity"],
        label=row["label"],
        created_at=row["created_at"],
    )


def to_requested_at_format(value: str | datetime) -> str:
    """Normalize a time bound to the stored ``YYYY-MM-DDTHH:MM:SS.mmmZ`` format.

    ``api_requests.requested_at`` is compared as a string, so a bound in any other
    ISO 8601 shape (``+00:00`` offset, no fraction, microseconds) would compare
    wrongly at the boundary. Naive values are taken as UTC; aware values are
    converted to UTC. Sub-millisecond precision is truncated.

    Args:
        value: An ISO 8601 string (``Z`` or offset suffix accepted) or a datetime.

    Returns:
        The UTC timestamp in the stored millisecond ``Z`` format.

    Raises:
        ValueError: If ``value`` is a string that is not parseable ISO 8601.
    """
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(value.strip())
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    # Explicit zero-padding: ``%Y`` does not pad years below 1000 on glibc, which
    # would break both the lexicographic compare and SQLite's ``datetime()``.
    return (
        f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T"
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}."
        f"{dt.microsecond // 1000:03d}Z"
    )


def _check_api_kind(api_kind: str) -> None:
    """Raise ``ValueError`` unless ``api_kind`` is a known ``api_requests.api_kind``."""
    if api_kind not in API_KINDS:
        raise ValueError(f"unknown api_kind: {api_kind!r}")


def _chunks(values: Sequence[str], size: int = _IN_CHUNK) -> Iterable[Sequence[str]]:
    """Yield consecutive slices of ``values`` of at most ``size`` items."""
    for start in range(0, len(values), size):
        yield values[start : start + size]


def _unique(values: Iterable[str]) -> list[str]:
    """Return ``values`` de-duplicated, preserving first-seen order."""
    return list(dict.fromkeys(values))


class ActivityStore:
    """Async repository over ``connections``, ``api_requests`` and ``api_findings``."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        """Initialize the store.

        Args:
            db: An open aiosqlite connection (WAL, ``aiosqlite.Row`` factory,
                ``foreign_keys=ON`` as set by :func:`gatorcast.db.connect`).
        """
        self._db = db

    # --- connections -----------------------------------------------------------

    async def upsert_connection_start(
        self,
        conn_id: str,
        user_id: str | None,
        username: str | None,
        resource_address: str | None,
        started_at: str | None,
        resource_type: str | None = None,
        gwops: GwopsWebApp | None = None,
    ) -> None:
        """Record an ``Authenticated connection`` line as a pending connection.

        Inserts a ``pending`` row, or refreshes an existing one: identity and
        cluster fields take the incoming non-null value (``COALESCE``),
        ``started_at`` keeps its first value, ``last_seen_at`` is bumped, and
        ``state``/``has_api`` are never changed on conflict (a connection already
        promoted to ``recording``/``api`` stays there).

        ``resource_type`` is **first write wins** (CLAUDE.md rule 2, WEBAPP_SPEC
        §4.4): it is written only on the first processing of the start line (the same
        test as the ``gwops`` snapshot, below), so a repeated or forged start line
        can never retype a connection (for example flip ``KUBERNETES`` to
        ``WEB_APP`` and thereby disable detection) nor fill a NULL one. A
        pre-upgrade connection with a processed start line and no type stays NULL
        (Kubernetes policy).

        **First processing** means no start line has been processed for this
        ``conn_id``: there is no row, or the row is the minimal one ``set_state``
        inserts for a request that beat its start line (``start_seen = 0 AND
        started_at IS NULL AND resource_type IS NULL``). Every call here sets
        ``start_seen = 1``, so a start line with no ``ts`` and no ``resource_type``
        still counts as processed.

        The eight ``gwops``/TLS snapshot columns are written as one unit, only
        on the first processing of the start line (WEBAPP_SPEC §4.4, §4.5; first
        write wins). Any later call keeps the
        stored snapshot, including a NULL one: a repeat can neither rewrite nor
        retroactively fill it. The rule is a ``CASE`` on the existing row inside
        the single ``INSERT … ON CONFLICT`` statement, so there is no
        read-then-write window. ``exact`` stores all eight values; ``none`` and
        ``ambiguous`` store only ``gwops_match`` and ``gwops_gateway_id``; ``None``
        stores NULL in all eight. Nothing here logs a ``gwops`` value.

        Then, in the same transaction (one commit):

          * backfills ``resource_address`` onto any of this connection's API
            requests that arrived before the start line (stored with a NULL cluster);
          * on the **first processing** of the start line only (the same test the
            ``gwops`` snapshot and ``resource_type`` use), and only when the
            ``resource_type`` **stored after the upsert** (not the incoming
            argument) is non-null and not ``KUBERNETES``, runs the web backfill
            (WEBAPP_SPEC §4.4): the connection's earlier ``kubectl`` rows lose their
            ``kube-api`` findings and become ``web`` rows (kubectl headers cleared,
            TLS modes copied from the connection's stored modes, read back after
            the upsert). A repeated start line never backfills.

        The first-processing read and the upsert are separate statements in one
        transaction; the assembler lock (every caller holds it) serializes them.

        Args:
            conn_id: The connection id (primary key).
            user_id: Gateway ``user.id``, if present.
            username: Envelope ``user.username`` (identity), if present.
            resource_address: Target system / cluster, if present.
            started_at: Start-line timestamp, if present.
            resource_type: Normalized Gateway resource type (``KUBERNETES``, ``SSH``,
                ``WEB_APP``, …) from the start line, if present.
            gwops: The validated ``gwops`` object from a ``WEB_APP`` start line, or
                ``None`` (absent, rejected, or not a web app).
        """
        try:
            cursor = await self._db.execute(
                "SELECT start_seen, started_at, resource_type FROM connections "
                "WHERE conn_id = ?",
                (conn_id,),
            )
            existing = await cursor.fetchone()
            await cursor.close()
            first_processing = existing is None or (
                not existing["start_seen"]
                and existing["started_at"] is None
                and existing["resource_type"] is None
            )
            await self._db.execute(
                f"""
                INSERT INTO connections (
                    conn_id, user_id, username, resource_address, started_at,
                    resource_type, state, has_api, created_at, last_seen_at, start_seen,
                    {_GWOPS_COLUMN_LIST}
                )
                VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, datetime('now'), datetime('now'), 1,
                        ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(conn_id) DO UPDATE SET
                    user_id          = COALESCE(excluded.user_id, connections.user_id),
                    username         = COALESCE(excluded.username, connections.username),
                    resource_address = COALESCE(excluded.resource_address, connections.resource_address),
                    started_at       = COALESCE(connections.started_at, excluded.started_at),
                    resource_type    = CASE WHEN {_FIRST_PROCESSING_SQL}
                                       THEN excluded.resource_type
                                       ELSE connections.resource_type END,
                    start_seen       = 1,
                    last_seen_at     = datetime('now'),
                    {_GWOPS_FIRST_WRITE_SET}
                """,
                (
                    conn_id,
                    user_id,
                    username,
                    resource_address,
                    started_at,
                    resource_type,
                    *_gwops_values(gwops),
                ),
            )
            if resource_address is not None:
                await self._db.execute(
                    "UPDATE api_requests SET resource_address = ? "
                    "WHERE conn_id = ? AND resource_address IS NULL",
                    (resource_address, conn_id),
                )
            if first_processing:
                await self._backfill_web_requests(conn_id)
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise

    async def _backfill_web_requests(self, conn_id: str) -> None:
        """Convert a connection's early ``kubectl`` rows to ``web`` (no commit).

        A no-op unless the connection's **stored** ``resource_type`` (read back
        here, after the upsert) is non-null and not ``KUBERNETES``. For requests
        stored before this connection's start line said it is not a Kubernetes
        connection (WEBAPP_SPEC §4.4):

          1. delete their findings (all are ``kube-api`` rule findings);
          2. set ``api_kind = 'web'``, clear ``kubectl_command``/``kubectl_session``
             and bind the connection's stored ``downstream_tls``/``upstream_tls``.

        The modes are read back from the connection row (after the upsert) so a
        repeated start line cannot substitute different values. Their URLs were
        already stored in the provisional form (the stricter of the Kubernetes and
        web policies, ``webmask.store_provisional_url``), so no URL rewrite is
        needed or possible (the raw URL is not kept).

        Args:
            conn_id: The connection whose rows are converted (the row must exist).
        """
        cursor = await self._db.execute(
            "SELECT resource_type, downstream_tls, upstream_tls FROM connections "
            "WHERE conn_id = ?",
            (conn_id,),
        )
        modes = await cursor.fetchone()
        await cursor.close()
        if modes is None or modes["resource_type"] in (None, "KUBERNETES"):
            return
        downstream_tls = modes["downstream_tls"]
        upstream_tls = modes["upstream_tls"]
        await self._db.execute(
            "DELETE FROM api_findings WHERE request_id IN "
            "(SELECT request_id FROM api_requests WHERE conn_id = ? AND api_kind = 'kubectl')",
            (conn_id,),
        )
        await self._db.execute(
            """
            UPDATE api_requests
            SET api_kind = 'web', kubectl_command = NULL, kubectl_session = NULL,
                downstream_tls = ?, upstream_tls = ?
            WHERE conn_id = ? AND api_kind = 'kubectl'
            """,
            (downstream_tls, upstream_tls, conn_id),
        )

    async def get_connection(self, conn_id: str) -> ConnectionRow | None:
        """Fetch one connection by id.

        Args:
            conn_id: The connection id to look up.

        Returns:
            The :class:`ConnectionRow`, or ``None`` if the connection is unknown.
        """
        cursor = await self._db.execute(
            f"SELECT {_CONNECTION_COLUMNS} FROM connections WHERE conn_id = ?",
            (conn_id,),
        )
        row = await cursor.fetchone()
        await cursor.close()
        return _row_to_connection(row) if row is not None else None

    async def gwops_for_connections(self, conn_ids: Iterable[str]) -> dict[str, GwopsSnapshot]:
        """Fetch the ``gwops``/TLS snapshot of each of a set of connections.

        A primary-key lookup over ``connections`` with parameterized ``IN`` lists of
        at most 500 ids per query. Duplicates are ignored.

        Args:
            conn_ids: Connection ids to look up.

        Returns:
            ``conn_id → GwopsSnapshot`` for every id that has a ``connections`` row.
            A connection with no stored object maps to a snapshot whose fields are all
            ``None`` (TLS unknown); an id with no row is absent.
        """
        ids = _unique(conn_ids)
        result: dict[str, GwopsSnapshot] = {}
        for chunk in _chunks(ids):
            placeholders = ", ".join("?" for _ in chunk)
            cursor = await self._db.execute(
                f"SELECT conn_id, {_GWOPS_COLUMN_LIST} FROM connections "
                f"WHERE conn_id IN ({placeholders})",
                tuple(chunk),
            )
            rows = await cursor.fetchall()
            await cursor.close()
            for row in rows:
                result[row["conn_id"]] = _row_to_gwops_snapshot(row)
        return result

    async def set_state(self, conn_id: str, state: str, *, has_api: bool = False) -> None:
        """Set a connection's lifecycle state (upsert).

        Inserts a minimal row (no identity, no cluster) when the start line was
        never seen, e.g. an audit line that arrived first. ``has_api`` is sticky:
        passing ``True`` sets it, passing ``False`` never clears it. ``last_seen_at``
        is bumped.

        Args:
            conn_id: The connection id.
            state: One of ``pending``, ``recording``, ``api``, ``error``, ``empty``.
            has_api: True when an API audit line has arrived on this connection.

        Raises:
            ValueError: If ``state`` is not a known connection state.
        """
        if state not in CONNECTION_STATES:
            raise ValueError(f"unknown connection state: {state!r}")
        await self._db.execute(
            """
            INSERT INTO connections (conn_id, state, has_api, created_at, last_seen_at)
            VALUES (?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(conn_id) DO UPDATE SET
                state        = excluded.state,
                has_api      = MAX(connections.has_api, excluded.has_api),
                last_seen_at = datetime('now')
            """,
            (conn_id, state, 1 if has_api else 0),
        )
        await self._db.commit()

    async def expire_pending(self, max_idle_seconds: int) -> list[ConnectionRow]:
        """Expire pending connections idle longer than the backstop.

        Selects ``state = 'pending' AND last_seen_at < datetime('now', '-N seconds')``
        and flips them in one atomic ``UPDATE … RETURNING``, so a connection touched
        concurrently is never expired by a stale read. A ``WEB_APP`` connection
        becomes ``empty`` (hidden: a browser pre-connect or refused tunnel, WEBAPP_SPEC
        §6); every other connection becomes ``error``. Uses SQLite wall-clock time, so
        it is correct across restarts.

        Args:
            max_idle_seconds: The backstop window (``SESSION_MAX_IDLE_SECONDS``).

        Returns:
            Every expired connection, oldest first, each with its new ``state``
            (``'error'`` or ``'empty'``). The caller surfaces a visible ``error``
            session row only for rows whose ``state == 'error'``.
        """
        modifier = f"-{max(0, int(max_idle_seconds))} seconds"
        cursor = await self._db.execute(
            f"""
            UPDATE connections
            SET state = CASE WHEN resource_type = 'WEB_APP' THEN 'empty' ELSE 'error' END
            WHERE state = 'pending' AND last_seen_at < datetime('now', ?)
            RETURNING {_CONNECTION_COLUMNS}
            """,
            (modifier,),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        await self._db.commit()
        expired = [_row_to_connection(row) for row in rows]
        expired.sort(key=lambda c: (c.last_seen_at or "", c.conn_id))
        return expired

    # --- API requests + findings ------------------------------------------------

    async def insert_request(
        self,
        req: ApiRequest,
        resource_address: str | None,
        *,
        storage: RequestStorage | None = None,
    ) -> bool:
        """Store one API request with no findings, ignoring a redelivered duplicate.

        Equivalent to :meth:`insert_request_with_findings` with an empty findings
        list. ``INSERT OR IGNORE`` keyed on ``request_id``. ``user_key`` is
        ``user_id``, else ``username``. Only the allowlisted :class:`ApiRequest`
        fields are written.

        Args:
            req: The classified, allowlisted API request.
            resource_address: The cluster, from the connection (``None`` until the
                start line is seen; :meth:`upsert_connection_start` backfills it).
            storage: The storage form chosen by the caller (``api_kind``, URL,
                headers, TLS modes). ``None`` stores the Kubernetes form
                (:meth:`RequestStorage.kubectl`).

        Returns:
            True if a new row was inserted; False if ``request_id`` already existed.
        """
        return await self.insert_request_with_findings(
            req, resource_address, (), storage=storage
        )

    async def insert_request_with_findings(
        self,
        req: ApiRequest,
        resource_address: str | None,
        findings: Sequence[Finding],
        *,
        storage: RequestStorage | None = None,
    ) -> bool:
        """Store one API request and its findings atomically (one transaction).

        The request row (``INSERT OR IGNORE`` keyed on ``request_id``) and, only if
        that row is new, its findings are written in a single transaction with a
        single commit. So either both land or neither does:

          * a redelivered line (``request_id`` already stored) inserts nothing — no
            duplicate request, no duplicate findings;
          * if anything fails between the two inserts the whole unit is rolled
            back and the error propagates, so a redelivery of the same line retries
            the request *and* its findings (they can never be lost to a dedup hit).

        Only the allowlisted :class:`ApiRequest` fields and rule metadata are
        written; ``offset_seconds`` is not stored (API findings have none). The
        URL, headers, ``api_kind`` and TLS modes written are the caller-chosen
        ``storage``, never read from ``req`` when ``storage`` is given.

        Args:
            req: The classified, allowlisted API request.
            resource_address: The cluster, from the connection (``None`` until the
                start line is seen; :meth:`upsert_connection_start` backfills it).
            findings: The findings from ``detect_api`` (computed by the caller
                before this call); empty stores the request alone.
            storage: The storage form chosen by the caller per the policy table
                (WEBAPP_SPEC §4.4). ``None`` stores the Kubernetes form
                (:meth:`RequestStorage.kubectl`).

        Returns:
            True if a new request row was inserted (with its findings); False if
            ``request_id`` already existed (nothing written).

        Raises:
            Exception: Any database error, after the transaction is rolled back.
        """
        chosen = storage if storage is not None else RequestStorage.kubectl(req)
        try:
            inserted = await self._insert_request_row(req, resource_address, chosen)
            if inserted:
                await self._insert_finding_rows(req.request_id, findings)
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise
        return inserted

    async def _insert_request_row(
        self,
        req: ApiRequest,
        resource_address: str | None,
        storage: RequestStorage,
    ) -> bool:
        """Execute the ``INSERT OR IGNORE`` for one request (no commit).

        Identity, time, method, status and outcome come from ``req``; ``api_kind``,
        URL, headers and TLS modes come from ``storage``.

        Returns:
            True if a new row was inserted; False if ``request_id`` already existed.
        """
        cursor = await self._db.execute(
            """
            INSERT OR IGNORE INTO api_requests (
                request_id, conn_id, resource_address, user_key, user_id, username,
                requested_at, method, url, status_code, outcome,
                kubectl_command, kubectl_session, user_agent,
                api_kind, downstream_tls, upstream_tls
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                req.request_id,
                req.conn_id,
                resource_address,
                req.user_id or req.username,
                req.user_id,
                req.username,
                req.requested_at,
                req.method,
                storage.url,
                req.status_code,
                req.outcome,
                storage.kubectl_command,
                storage.kubectl_session,
                storage.user_agent,
                storage.api_kind,
                storage.downstream_tls,
                storage.upstream_tls,
            ),
        )
        inserted = cursor.rowcount == 1
        await cursor.close()
        return inserted

    async def _insert_finding_rows(self, request_id: str, findings: Sequence[Finding]) -> None:
        """Execute the ``api_findings`` inserts for one request (no commit).

        Args:
            request_id: The request the findings belong to (must exist).
            findings: The findings to store; empty is a no-op.
        """
        if not findings:
            return
        await self._db.executemany(
            """
            INSERT INTO api_findings (request_id, rule_id, category, severity, label)
            VALUES (?, ?, ?, ?, ?)
            """,
            [(request_id, f.rule_id, f.category, f.severity, f.label) for f in findings],
        )

    async def insert_api_findings(self, request_id: str, findings: Sequence[Finding]) -> None:
        """Store rule findings for an already-stored API request (own transaction).

        The ingest path uses :meth:`insert_request_with_findings` instead, so a
        request and its findings commit together. This stays for direct use (tests,
        seeding). ``offset_seconds`` is not stored (API findings have none). No
        matched text exists to store.

        Args:
            request_id: The request the findings belong to (must exist).
            findings: The findings from ``detect_api``; empty is a no-op.
        """
        if not findings:
            return
        try:
            await self._insert_finding_rows(request_id, findings)
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise

    async def requests_for_system(
        self,
        resource_address: str | None,
        since: str | datetime,
        until: str | datetime,
        limit: int = DEFAULT_MAX_ROWS,
        *,
        api_kind: str = "kubectl",
    ) -> list[ApiRequestRow]:
        """List a system's API requests of one kind in a time window.

        The window is half-open, ``since <= requested_at < until``, so adjacent
        pages (``until`` of one = ``since`` of the next) never repeat a request.
        ``resource_address IS ?`` matches the NULL (unknown cluster) bucket too.
        Ordered ``user_key, requested_at`` as ``group_activity`` requires.

        The query is pinned to ``idx_api_req_sys_kind_time`` (``INDEXED BY``): it
        walks ``(resource_address, api_kind)`` in ``requested_at`` order, and the
        planner would otherwise prefer ``idx_api_req_kind_time`` and scan every row
        of the kind across all systems.

        Args:
            resource_address: The system, or ``None`` for the unknown bucket.
            since: Inclusive lower bound (ISO 8601 string or datetime).
            until: Exclusive upper bound (ISO 8601 string or datetime).
            limit: Maximum rows returned. A result of exactly ``limit`` rows means
                the window may be truncated.
            api_kind: ``'kubectl'`` (default) or ``'web'``.

        Returns:
            The matching :class:`ApiRequestRow` list.

        Raises:
            ValueError: If a string bound is not parseable ISO 8601, or ``api_kind``
                is unknown.
        """
        _check_api_kind(api_kind)
        cursor = await self._db.execute(
            f"""
            SELECT {_REQUEST_COLUMNS}
            FROM api_requests INDEXED BY idx_api_req_sys_kind_time
            WHERE resource_address IS ? AND api_kind = ?
              AND requested_at >= ? AND requested_at < ?
            ORDER BY user_key, requested_at, request_id
            LIMIT ?
            """,
            (
                resource_address,
                api_kind,
                to_requested_at_format(since),
                to_requested_at_format(until),
                max(1, int(limit)),
            ),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [_row_to_request(row) for row in rows]

    async def requests_in_bounds(
        self,
        resource_address: str | None,
        user_key: str | None,
        from_: str | datetime,
        to: str | datetime,
        limit: int = DEFAULT_MAX_ROWS,
        *,
        api_kind: str = "kubectl",
    ) -> list[ApiRequestRow]:
        """List one user's requests of one kind on one system within an activity session's bounds.

        Bounds are inclusive (``from_ <= requested_at <= to``) because they are an
        activity session's own first and last ``requested_at``. ``IS ?`` matches the
        NULL cluster and NULL user buckets. Served by
        ``idx_api_req_sys_kind_user_time`` with no hint and no sort.

        Args:
            resource_address: The system, or ``None`` for the unknown bucket.
            user_key: The ``user_key`` (user id, else username), or ``None``.
            from_: Inclusive lower bound (ISO 8601 string or datetime).
            to: Inclusive upper bound (ISO 8601 string or datetime).
            limit: Maximum rows returned.
            api_kind: ``'kubectl'`` (default) or ``'web'``.

        Returns:
            The matching :class:`ApiRequestRow` list, ordered by ``requested_at``.

        Raises:
            ValueError: If a string bound is not parseable ISO 8601, or ``api_kind``
                is unknown.
        """
        _check_api_kind(api_kind)
        cursor = await self._db.execute(
            f"""
            SELECT {_REQUEST_COLUMNS}
            FROM api_requests
            WHERE resource_address IS ? AND api_kind = ? AND user_key IS ?
              AND requested_at >= ? AND requested_at <= ?
            ORDER BY requested_at, request_id
            LIMIT ?
            """,
            (
                resource_address,
                api_kind,
                user_key,
                to_requested_at_format(from_),
                to_requested_at_format(to),
                max(1, int(limit)),
            ),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [_row_to_request(row) for row in rows]

    async def findings_for_requests(
        self, request_ids: Iterable[str]
    ) -> dict[str, list[ApiFindingRow]]:
        """Fetch the findings for a set of requests, grouped by ``request_id``.

        Queried with ``IN (…)`` in chunks of 500 bound parameters.

        Args:
            request_ids: Request ids to look up (duplicates are ignored).

        Returns:
            ``request_id → findings`` (in insertion order). Requests with no
            findings are absent from the mapping.
        """
        ids = _unique(request_ids)
        result: dict[str, list[ApiFindingRow]] = {}
        for chunk in _chunks(ids):
            placeholders = ", ".join("?" for _ in chunk)
            cursor = await self._db.execute(
                f"SELECT {_FINDING_COLUMNS} FROM api_findings "
                f"WHERE request_id IN ({placeholders}) ORDER BY id",
                tuple(chunk),
            )
            rows = await cursor.fetchall()
            await cursor.close()
            for row in rows:
                finding = _row_to_finding(row)
                result.setdefault(finding.request_id, []).append(finding)
        return result

    async def recordings_for_requests(self, request_ids: Iterable[str]) -> dict[str, str]:
        """Map audit ``request_id`` values to the ``conn_id`` of their recording.

        Reads ``sessions.request_id`` (set from k8s exec/attach chunk lines), which
        equals the exec's status-101 audit line ``request_id``. This is the only
        recording link: one exec run can span two connections, so ``conn_id`` is
        never used to join. Queried in chunks of 500 bound parameters. If more than
        one session carries the same ``request_id``, the earliest-started wins.

        Args:
            request_ids: Audit request ids to resolve (duplicates are ignored).

        Returns:
            ``request_id → recording conn_id`` for every id that has a recording.
        """
        ids = _unique(request_ids)
        result: dict[str, str] = {}
        for chunk in _chunks(ids):
            placeholders = ", ".join("?" for _ in chunk)
            cursor = await self._db.execute(
                f"""
                SELECT request_id, conn_id
                FROM sessions
                WHERE request_id IN ({placeholders})
                ORDER BY COALESCE(started_at, created_at), conn_id
                """,
                tuple(chunk),
            )
            rows = await cursor.fetchall()
            await cursor.close()
            for row in rows:
                result.setdefault(row["request_id"], row["conn_id"])
        return result

    async def known_request_ids(self, request_ids: Iterable[str]) -> set[str]:
        """Return the subset of ``request_ids`` that have an ``api_requests`` row.

        The batched form of Q13 (unified search spec §7.4): an exec recording's
        ``sessions.request_id`` links to its kubectl command only when the exec's
        audit line has been stored. Primary-key probes, in chunks of 500 bound
        parameters.

        Args:
            request_ids: Candidate request ids (duplicates are ignored).

        Returns:
            The ids that exist in ``api_requests``.
        """
        ids = _unique(request_ids)
        found: set[str] = set()
        for chunk in _chunks(ids):
            placeholders = ", ".join("?" for _ in chunk)
            cursor = await self._db.execute(
                f"SELECT request_id FROM api_requests WHERE request_id IN ({placeholders})",
                tuple(chunk),
            )
            rows = await cursor.fetchall()
            await cursor.close()
            found.update(row["request_id"] for row in rows)
        return found

    # --- retention -------------------------------------------------------------

    async def purge_before(self, iso_cutoff: str | datetime) -> tuple[int, int]:
        """Delete API requests and connections older than the retention cutoff.

        An ``api_requests`` row is purged when *either* clock says it is old:
        ``requested_at < cutoff`` (the Gateway's timestamp) OR
        ``datetime(created_at) < datetime(cutoff)`` (the server's own insert time).
        ``requested_at`` is Gateway-supplied, so a row dated in the future (e.g.
        ``9999-01-01T…Z``) would otherwise survive every purge; ``created_at`` is
        always server-assigned and bounds it. The row's ``api_findings`` go with it
        under the same condition — deleted explicitly as well as by the FK cascade,
        so the purge is correct even on a connection without ``foreign_keys=ON``.

        ``connections`` rows are purged on the connection's **last activity**, on
        server time only (:data:`_PURGE_CONNECTIONS_SQL`): a connection goes only
        when ``COALESCE(last_seen_at, created_at)`` is before the cutoff *and* no
        ``api_requests`` row (run after the request purge above, so only requests
        newer than the cutoff remain) still references it. A long keep-alive
        connection with recent requests therefore keeps its row, and its later
        requests keep their cluster and type instead of falling back to the
        provisional path. Both columns are server-assigned (``datetime('now')``),
        never Gateway-supplied (``started_at`` is not consulted), so a forged future
        timestamp cannot pin a connection. ``last_seen_at`` is bumped by every
        start line and every newly stored request.

        One transaction; rolled back on error.

        Args:
            iso_cutoff: The retention cutoff (ISO 8601 string or datetime), the
                same one used for sessions.

        Returns:
            ``(api_requests_deleted, connections_deleted)``.

        Raises:
            ValueError: If ``iso_cutoff`` is a string that is not parseable ISO 8601.
        """
        cutoff = to_requested_at_format(iso_cutoff)
        request_is_old = "requested_at < ? OR datetime(created_at) < datetime(?)"
        try:
            await self._db.execute(
                "DELETE FROM api_findings WHERE request_id IN "
                f"(SELECT request_id FROM api_requests WHERE {request_is_old})",
                (cutoff, cutoff),
            )
            cursor = await self._db.execute(
                f"DELETE FROM api_requests WHERE {request_is_old}", (cutoff, cutoff)
            )
            requests_deleted = max(cursor.rowcount, 0)
            await cursor.close()
            cursor = await self._db.execute(_PURGE_CONNECTIONS_SQL, (cutoff,))
            connections_deleted = max(cursor.rowcount, 0)
            await cursor.close()
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise
        return requests_deleted, connections_deleted
