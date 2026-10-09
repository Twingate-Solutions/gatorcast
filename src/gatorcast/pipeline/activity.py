"""kubectl activity grouping: discovery, activity sessions, and commands (spec §7).

Pure functions over :class:`~gatorcast.store.activity.ApiRequestRow` values. No
I/O, no database, no logging: the web routes fetch rows (and the findings and
recording maps for them) from ``ActivityStore`` and pass them in. Nothing is cached.

Three concepts:

  * **Discovery** (:func:`is_discovery`) — a ``GET`` on an API-discovery path
    (``/api``, ``/apis/<group>/<version>``, ``/openapi/…``, ``/version``). Matched on
    the URL *path only*: discovery URLs carry query strings (``/api?timeout=32s``).
    Discovery requests count toward session timing but are hidden from command
    tables by default.
  * **Activity session** (:func:`group_activity`) — one user's requests on one
    cluster, split when the gap since the previous request exceeds ``gap_s`` or the
    span since the session's first request reaches ``max_s``.
  * **Command** (:func:`group_commands`) — the requests of one kubectl run, keyed
    by ``Kubectl-Session``, falling back to ``conn_id`` only when that header is
    absent. A command links its exec/attach recordings through the audit
    ``request_id`` (``recordings`` maps it to the recording's ``conn_id``), never
    through ``conn_id``: one exec run can span two connections.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

from gatorcast.pipeline.detect import SEVERITY_RANK

if TYPE_CHECKING:
    from gatorcast.store.activity import ApiRequestRow

# Methods that change cluster state; a command's primary request prefers these.
MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Label used when a command has neither ``Kubectl-Command`` nor a ``User-Agent``.
UNKNOWN_CLIENT_LABEL = "(unknown client)"

# Discovery paths (spec §7), matched with ``fullmatch`` against the path only.
_DISCOVERY_PATH = re.compile(
    r"/api/?"
    r"|/apis/?"
    r"|/api/v1/?"
    r"|/apis/[^/]+/?"
    r"|/apis/[^/]+/[^/]+/?"
    r"|/openapi(?:/.*)?"
    r"|/version/?",
    re.DOTALL,
)


class FindingLike(Protocol):
    """The finding attributes grouping reads (``ApiFindingRow`` satisfies this)."""

    @property
    def severity(self) -> str:
        """The finding's severity (a :data:`SEVERITY_RANK` key)."""
        ...

    @property
    def label(self) -> str:
        """The finding's human-readable rule label."""
        ...


# --- discovery -----------------------------------------------------------------


def request_path(url: str) -> str:
    """Return the path part of a stored request URL (everything before ``?``).

    Args:
        url: A stored request URL, e.g. ``/api/v1/pods?limit=500``.

    Returns:
        The path, e.g. ``/api/v1/pods``.
    """
    return url.split("?", 1)[0]


def is_discovery(method: str, url: str) -> bool:
    """Tell whether a request is an API-discovery request.

    A request is discovery when its method is ``GET`` and its *path* (the query
    string is ignored) is one of the discovery endpoints listed in spec §7.

    Args:
        method: The HTTP method (case-insensitive).
        url: The stored request URL, with or without a query string.

    Returns:
        True for discovery (``GET /api?timeout=32s``), False otherwise
        (``GET /api/v1/pods?limit=500``).
    """
    if method.upper() != "GET":
        return False
    return _DISCOVERY_PATH.fullmatch(request_path(url)) is not None


# A discovery predicate: ``(method, url) -> bool``. :func:`is_discovery` is the
# kubectl default; a web caller passes one that always returns False (spec §7.2).
DiscoveryPredicate = Callable[[str, str], bool]


def _row_is_discovery(row: ApiRequestRow) -> bool:
    """Apply :func:`is_discovery` to a stored request row."""
    return is_discovery(row.method, row.url)


# --- shared helpers ----------------------------------------------------------------


def parse_requested_at(value: str) -> datetime:
    """Parse a stored ``requested_at`` (``YYYY-MM-DDTHH:MM:SS.mmmZ``) to a datetime.

    Args:
        value: The stored timestamp.

    Returns:
        The timezone-aware UTC datetime.

    Raises:
        ValueError: If ``value`` is not ISO 8601. Stored values are normalized by
            the classifier, so this indicates a corrupted row.
    """
    return datetime.fromisoformat(value)


def _max_severity(severities: Iterable[str]) -> str | None:
    """Return the highest-ranked severity, or ``None`` when there are none."""
    best: str | None = None
    for severity in severities:
        if best is None or SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(best, 0):
            best = severity
    return best


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    """De-duplicate ``values``, preserving first-seen order."""
    return tuple(dict.fromkeys(values))


def _linked_recordings(
    rows: Iterable[ApiRequestRow], recordings: Mapping[str, str]
) -> tuple[str, ...]:
    """Recording ``conn_id`` values linked to ``rows`` through ``request_id`` only."""
    return _unique(recordings[r.request_id] for r in rows if r.request_id in recordings)


def _command_key(row: ApiRequestRow) -> tuple[str, str]:
    """Internal grouping key: ``Kubectl-Session``, else the connection.

    A tagged tuple, so a ``Kubectl-Session`` header value can never collide with a
    connection-fallback key.
    """
    if row.kubectl_session:
        return ("session", row.kubectl_session)
    return ("conn", row.conn_id)


def _display_key(key: tuple[str, str]) -> str:
    """Render an internal key in the spec §7 form (``<session>`` or ``conn:<id>``)."""
    kind, value = key
    return value if kind == "session" else f"conn:{value}"


# --- activity sessions -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ActivitySession:
    """One user's kubectl activity on one cluster, bounded by gap and max window.

    ``started_at`` / ``ended_at`` are the first and last requests' stored
    ``requested_at`` values (the inclusive bounds the activity page queries with).
    ``command_count`` counts commands that have at least one non-discovery request
    (the commands visible on the activity page by default). Finding and recording
    fields are zero / ``None`` unless the maps were passed to
    :func:`group_activity`.
    """

    user_key: str | None
    username: str | None
    resource_address: str | None
    started_at: str
    ended_at: str
    start_t: datetime
    end_t: datetime
    request_count: int
    command_count: int
    finding_count: int
    max_severity: str | None
    recording_count: int
    request_ids: tuple[str, ...]

    @property
    def duration_seconds(self) -> float:
        """Span from the first to the last request, in seconds."""
        return (self.end_t - self.start_t).total_seconds()


class _SessionBuilder:
    """Mutable accumulator for one activity session during the linear pass."""

    __slots__ = ("user_key", "start_t", "last_t", "rows")

    def __init__(self, row: ApiRequestRow, t: datetime) -> None:
        """Open a session at ``row`` (``start_t = last_t = t``)."""
        self.user_key = row.user_key
        self.start_t = t
        self.last_t = t
        self.rows: list[ApiRequestRow] = []

    def add(self, row: ApiRequestRow, t: datetime) -> None:
        """Append ``row`` and advance ``last_t``."""
        self.rows.append(row)
        self.last_t = t

    def build(
        self,
        findings: Mapping[str, Sequence[FindingLike]],
        recordings: Mapping[str, str],
        discovery: DiscoveryPredicate,
    ) -> ActivitySession:
        """Freeze the accumulated rows into an :class:`ActivitySession`."""
        rows = self.rows
        visible_commands = {_command_key(r) for r in rows if not discovery(r.method, r.url)}
        session_findings = [f for r in rows for f in findings.get(r.request_id, ())]
        return ActivitySession(
            user_key=self.user_key,
            username=next((r.username for r in rows if r.username), None),
            resource_address=rows[0].resource_address,
            started_at=rows[0].requested_at,
            ended_at=rows[-1].requested_at,
            start_t=self.start_t,
            end_t=self.last_t,
            request_count=len(rows),
            command_count=len(visible_commands),
            finding_count=len(session_findings),
            max_severity=_max_severity(f.severity for f in session_findings),
            recording_count=len(_linked_recordings(rows, recordings)),
            request_ids=tuple(r.request_id for r in rows),
        )


def group_activity(
    rows: Iterable[ApiRequestRow],
    gap_s: int,
    max_s: int,
    *,
    findings: Mapping[str, Sequence[FindingLike]] | None = None,
    recordings: Mapping[str, str] | None = None,
    discovery: DiscoveryPredicate = is_discovery,
) -> list[ActivitySession]:
    """Group one cluster's API requests into activity sessions.

    One linear pass over the rows in ``(user_key, requested_at)`` order (the rows
    are sorted defensively first, so any input order is accepted). A new session
    starts when the user changes, when the gap since the previous request is
    greater than ``gap_s``, or when the span since the session's first request is
    at least ``max_s``. Discovery requests count toward timing like any other.

    Args:
        rows: API requests for a single ``resource_address`` (as returned by
            ``ActivityStore.requests_for_system``).
        gap_s: Inactivity gap that splits sessions (``KUBECTL_ACTIVITY_GAP_SECONDS``).
        max_s: Hard cap on one session's span (``KUBECTL_ACTIVITY_MAX_SECONDS``).
        findings: Optional ``request_id → findings`` map
            (``ActivityStore.findings_for_requests``) to fill ``finding_count`` and
            ``max_severity``.
        recordings: Optional ``request_id → recording conn_id`` map
            (``ActivityStore.recordings_for_requests``) to fill ``recording_count``.
        discovery: ``(method, url) -> bool`` predicate deciding which requests are
            discovery, for ``command_count``. Defaults to :func:`is_discovery`
            (kubectl); a web caller passes one that always returns False so
            ``GET /api`` on a web app is not treated as discovery (spec §7.2).

    Returns:
        The activity sessions, newest first (ties broken by ``user_key``).

    Raises:
        ValueError: If a row's ``requested_at`` is not ISO 8601.
    """
    findings = findings or {}
    recordings = recordings or {}
    ordered = sorted(
        rows,
        key=lambda r: (r.user_key is not None, r.user_key or "", r.requested_at, r.request_id),
    )
    builders: list[_SessionBuilder] = []
    cur: _SessionBuilder | None = None
    for row in ordered:
        t = parse_requested_at(row.requested_at)
        if (
            cur is None
            or row.user_key != cur.user_key
            or (t - cur.last_t).total_seconds() > gap_s
            or (t - cur.start_t).total_seconds() >= max_s
        ):
            cur = _SessionBuilder(row, t)
            builders.append(cur)
        cur.add(row, t)
    sessions = [b.build(findings, recordings, discovery) for b in builders]
    sessions.sort(key=lambda s: s.user_key or "")
    sessions.sort(key=lambda s: s.start_t, reverse=True)
    return sessions


# --- commands ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Command:
    """One kubectl run inside an activity session.

    ``key`` is the ``Kubectl-Session`` value, or ``conn:<conn_id>`` when the header
    is absent. ``requests`` holds every request (discovery included) in
    ``requested_at`` order; ``discovery_count`` is how many of them are discovery
    and therefore hidden by default. ``conn_ids`` lists every connection the run
    used, first-seen order. ``recordings`` lists recording ``conn_id`` values linked
    through ``request_id`` (for example the exec's status-101 audit line).
    """

    key: str
    kubectl_session: str | None
    label: str
    primary: ApiRequestRow
    requests: tuple[ApiRequestRow, ...]
    discovery_count: int
    conn_ids: tuple[str, ...]
    recordings: tuple[str, ...]
    started_at: str
    ended_at: str
    finding_count: int
    max_severity: str | None
    finding_labels: tuple[str, ...]

    @property
    def request_count(self) -> int:
        """Total requests in the command, discovery included."""
        return len(self.requests)

    @property
    def primary_path(self) -> str:
        """The primary request's path (query string removed)."""
        return request_path(self.primary.url)

    @property
    def is_discovery_only(self) -> bool:
        """True when every request is discovery (hidden unless ``?discovery=1``)."""
        return self.discovery_count == len(self.requests)

    def visible_requests(self, include_discovery: bool = False) -> tuple[ApiRequestRow, ...]:
        """The requests to list for this command.

        Args:
            include_discovery: True to include discovery requests (``?discovery=1``).

        Returns:
            The requests in ``requested_at`` order.
        """
        if include_discovery:
            return self.requests
        return tuple(r for r in self.requests if not _row_is_discovery(r))


def _pick_primary(requests: Sequence[ApiRequestRow]) -> ApiRequestRow:
    """Choose a command's primary request (spec §7).

    The first non-discovery mutating request, else the first non-discovery
    request, else the first request.
    """
    non_discovery = [r for r in requests if not _row_is_discovery(r)]
    for r in non_discovery:
        if r.method.upper() in MUTATING_METHODS:
            return r
    return non_discovery[0] if non_discovery else requests[0]


def _user_agent_product(user_agent: str | None) -> str | None:
    """Return a User-Agent's product token (text before the first ``/``), if any."""
    if not user_agent:
        return None
    product = user_agent.split("/", 1)[0].strip()
    return product or None


def pick_label(primary: ApiRequestRow, requests: Sequence[ApiRequestRow]) -> str:
    """Choose a command's label.

    ``Kubectl-Command`` (the primary's, else the first present), else the
    User-Agent product token (the primary's, else the first present), else
    :data:`UNKNOWN_CLIENT_LABEL`. Public because the timeline hydration
    (``store.timeline``) recomputes the label when it picks the primary itself.

    Args:
        primary: The command's primary request.
        requests: The command's (listed) requests, ``requested_at`` order.

    Returns:
        The label text.
    """
    for r in (primary, *requests):
        if r.kubectl_command:
            return r.kubectl_command
    for r in (primary, *requests):
        product = _user_agent_product(r.user_agent)
        if product:
            return product
    return UNKNOWN_CLIENT_LABEL


def group_commands(
    rows: Iterable[ApiRequestRow],
    recordings: Mapping[str, str],
    *,
    findings: Mapping[str, Sequence[FindingLike]] | None = None,
) -> list[Command]:
    """Group one activity session's requests into commands.

    Requests are keyed by ``Kubectl-Session``, falling back to ``conn_id`` only
    when the header is absent, so an exec run whose preparatory GETs and WebSocket
    exec used two connections is still one command. Commands keep first-seen order
    (by ``requested_at``); each holds its requests in ``requested_at`` order.

    Recordings attach only through ``request_id``: ``recordings`` maps an audit
    ``request_id`` (the exec's status-101 line) to the recording's ``conn_id``. The
    link appears once that audit line has arrived; ``conn_id`` is never matched.

    Args:
        rows: The session's requests (``ActivityStore.requests_in_bounds``).
        recordings: ``request_id → recording conn_id``
            (``ActivityStore.recordings_for_requests``).
        findings: Optional ``request_id → findings`` map
            (``ActivityStore.findings_for_requests``) for the finding fields.

    Returns:
        The commands in first-seen order.
    """
    findings = findings or {}
    ordered = sorted(rows, key=lambda r: (r.requested_at, r.request_id))
    groups: dict[tuple[str, str], list[ApiRequestRow]] = {}
    for row in ordered:
        groups.setdefault(_command_key(row), []).append(row)

    commands: list[Command] = []
    for key, requests in groups.items():
        primary = _pick_primary(requests)
        command_findings = [f for r in requests for f in findings.get(r.request_id, ())]
        commands.append(
            Command(
                key=_display_key(key),
                kubectl_session=key[1] if key[0] == "session" else None,
                label=pick_label(primary, requests),
                primary=primary,
                requests=tuple(requests),
                discovery_count=sum(1 for r in requests if _row_is_discovery(r)),
                conn_ids=_unique(r.conn_id for r in requests),
                recordings=_linked_recordings(requests, recordings),
                started_at=requests[0].requested_at,
                ended_at=requests[-1].requested_at,
                finding_count=len(command_findings),
                max_severity=_max_severity(f.severity for f in command_findings),
                finding_labels=_unique(f.label for f in command_findings),
            )
        )
    return commands
