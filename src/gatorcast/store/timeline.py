"""Unified timeline: the search engine behind ``/search`` (Session 10, spec §6).

One interleaved, keyset-paged timeline over every event kind:

* the **sessions** source (:class:`SessionsSource`) serves the three ``sessions``
  table kinds — ``ssh``, ``exec`` and ``failed`` (spec §4.2, §6.2): queries Q1/Q2,
  the lazy budgeted content scan Q3, and findings hydration Q8;
* the **api_commands** source (:class:`ApiCommandSource`) serves ``kubectl``
  commands (spec §6.3): scan mode Q4/Q4b (with the two-arm ``user`` union),
  flagged mode Q5, the risk phases ``F``→``T``, hydration Q6a–c/Q7 through
  :func:`gatorcast.pipeline.activity.group_commands`, and focus Q9;
* :func:`run_timeline` queries each selected source, merges by a total sort key
  with the frontier rule, hydrates only the emitted items, and builds the next
  :class:`Cursor` (spec §6.4).

Layering (decided by Ben, 2026-10-05; overrides spec §4/§5 where they differ):
the store layer never imports from :mod:`gatorcast.web`. Everything the engine
consumes is defined here, and the web layer imports it:

* :class:`UnifiedQuery` — validated search parameters. Built by
  :func:`gatorcast.web.params.parse_unified_query`; nothing here reads a request.
* :class:`Cursor` — a decoded paging cursor (one keyset position per source).
  Encoding and decoding of the URL form live in :mod:`gatorcast.web.params`; the
  per-source position *shapes* are validated here by :func:`check_position`,
  next to the engine that defines them.
* The kind identifiers (``KIND_*``), source names (``SOURCE_*``), the kind → source
  map, and :func:`session_kind`. The presentation registry and ``resolve_kinds``
  stay in :mod:`gatorcast.web.kinds`. The route calls ``resolve_kinds`` and passes
  the resolved kinds and exclusions into :func:`run_timeline`.

Security (CLAUDE.md rules 2, 5, 6; spec §10):
  * Raw, parameterized SQL only. The only dynamic SQL text is static fragments
    (``CMD_KEY_SQL``, ``SESSION_AT_SQL``, ``FAILED_SQL``, the severity-rank ``CASE``
    built from :data:`~gatorcast.pipeline.detect.SEVERITY_RANK`) and placeholder
    lists sized by validated counts.
  * Sidecar text is read only to test a match and is never logged or returned.
    The single log line, ``timeline.content_budget_hit``, carries counters only.
"""

from __future__ import annotations

import asyncio
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Final, Literal, Protocol

import aiosqlite

from gatorcast.db import FAILED_SQL, cmd_key, session_at
from gatorcast.logging import get_logger
from gatorcast.models import Session
from gatorcast.pipeline.activity import Command, group_commands, parse_requested_at
from gatorcast.pipeline.detect import SEVERITY_RANK
from gatorcast.store.activity import (
    _REQUEST_COLUMNS,
    ApiFindingRow,
    _row_to_finding,
    _row_to_request,
)
from gatorcast.store.casts import CastStore
from gatorcast.store.sessions import _SESSION_COLUMNS, _row_to_session

log = get_logger(__name__)

# --- kind identifiers (spec §4.1) ------------------------------------------------
# The URL ``type`` values for single kinds and the CSV ``kind`` column. Display order
# (and the order of ``KINDS`` in web/kinds.py) is the order of ``KIND_KEYS``.

KIND_SSH: Final = "ssh"
KIND_EXEC: Final = "exec"
KIND_FAILED: Final = "failed"
KIND_KUBECTL: Final = "kubectl"
KIND_KEYS: Final[tuple[str, ...]] = (KIND_SSH, KIND_EXEC, KIND_FAILED, KIND_KUBECTL)

# --- timeline sources (spec §6.1, §6.4) -----------------------------------------
# A source is one keyset-paged query family. ``sessions`` serves the three
# sessions-table kinds; ``api_commands`` serves kubectl commands. The rank breaks
# merge ties (sessions before api_commands; a future source takes rank 2).

SOURCE_SESSIONS: Final = "sessions"
SOURCE_API_COMMANDS: Final = "api_commands"
SOURCE_RANK: Final[Mapping[str, int]] = {SOURCE_SESSIONS: 0, SOURCE_API_COMMANDS: 1}

KIND_SOURCE: Final[Mapping[str, str]] = {
    KIND_SSH: SOURCE_SESSIONS,
    KIND_EXEC: SOURCE_SESSIONS,
    KIND_FAILED: SOURCE_SESSIONS,
    KIND_KUBECTL: SOURCE_API_COMMANDS,
}

# --- sorts --------------------------------------------------------------------

SORT_NEWEST: Final = "newest"
SORT_RISK: Final = "risk"
SORT_DURATION: Final = "duration"
SORTS: Final[tuple[str, ...]] = (SORT_NEWEST, SORT_RISK, SORT_DURATION)

# --- cursor contract (spec §5.4) ------------------------------------------------

CURSOR_VERSION: Final = 1
CURSOR_MAX_LEN: Final = 2048
"""Upper bound on an encoded cursor (``_CURSOR_MAX_LEN`` in spec §6.5)."""

POSITION_DONE: Final = "done"
"""Cursor marker for a source that is exhausted and is not queried again."""

# Phases of the api_commands source: ``F`` = flagged mode, ``T`` = time scan.
PHASE_FLAGGED: Final = "F"
PHASE_SCAN: Final = "T"

# --- budgets and caps (spec §6.5) -----------------------------------------------
# Module constants, not settings (Session 9's ``_ACTIVITY_*`` precedent). They are
# read at call time, so tests can patch them on this module.

_API_SCAN_BUDGET = 20000
"""``api_requests`` rows one scan-mode query (Q4) may examine."""

_FLAGGED_CMD_CAP = 5000
"""Distinct flagged commands one flagged-mode query (Q5) considers."""

_CMD_MAX_REQUESTS = 200
"""Requests listed per expanded command (Q7); aggregates still cover every row."""

_CONTENT_BATCH = 100
"""Rows fetched per batch of the lazy content scan (Q3)."""

DEFAULT_CONTENT_BUDGET: Final = 2000
"""Default sidecars read per page (the ``SEARCH_REGEX_MAX_CANDIDATES`` default)."""

# Notice names a source may raise (``SourcePage.notices``).
NOTICE_SCAN_BUDGET: Final = "scan_budget_hit"
NOTICE_CONTENT_BUDGET: Final = "content_budget_hit"
NOTICE_FLAGGED_CAP: Final = "flagged_cap_hit"
NOTICE_FOCUS_MISSING: Final = "focus_not_found"

# ``YYYY-MM-DDTHH:MM:SS.mmmZ``: the stored ``requested_at`` format and the output
# of ``SESSION_AT_SQL``. ASCII digits only.
_AT_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", re.ASCII)
# A conn_id: same safe-token pattern as ``classify._SAFE_CONN_ID``.
_CONN_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}", re.ASCII)
# A request_id: the safe token, or the ``h:<32 hex>`` id classify derives for a
# line with no usable request_id.
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}|h:[0-9a-f]{32}", re.ASCII)

_MAX_RANK = 4  # SEVERITY_RANK["critical"]; 0 = no finding

Position = tuple[str | int | float, ...]
"""One source's keyset position (shapes in :func:`check_position`)."""

SortKey = tuple[Any, ...]
"""A merge key: compared descending; ends in ``(source rank, id)`` so it is total."""


@dataclass(frozen=True, slots=True)
class UnifiedQuery:
    """Validated search parameters for the unified timeline (spec §6.1).

    Built by :func:`gatorcast.web.params.parse_unified_query`; nothing in the store
    reads the request. Every string is a bound SQL parameter, never SQL text.

    Attributes:
        kinds: The kinds selected by ``type`` (before applicability exclusions;
            ``gatorcast.web.kinds.resolve_kinds`` narrows them).
        system: ``resource_address`` to match, or ``None``. With ``system_set``
            true and ``system`` ``None``, the NULL (unknown) system bucket.
        system_set: True when a ``system`` filter was given (distinguishes the
            ``_unknown`` NULL bucket from "no filter").
        user: Exact ``username`` or ``user_id`` to match.
        from_: Inclusive lower time bound, ``YYYY-MM-DDTHH:MM:SS.mmmZ``.
        to: Inclusive upper time bound, same format.
        severity: At-or-above severity (``low``/``medium``/``high``/``critical``).
        max_severity: Exact highest severity.
        has_findings: ``True``/``False`` tri-state, ``None`` when absent.
        category: Finding category.
        rule_ids: Finding rule ids (any of), deduplicated, in given order.
        status: Recording status (recordings only).
        min_duration: Minimum duration in seconds (recordings only).
        max_duration: Maximum duration in seconds (recordings only).
        text: Case-insensitive substring (text mode / legacy ``keyword``).
        regex: Python regex, already validated to compile (recordings only).
        sort: ``newest`` | ``risk`` | ``duration``.
        discovery: True to include discovery-only kubectl commands.
        cmd: Focus on the kubectl command containing this ``request_id``.
    """

    kinds: frozenset[str]
    system: str | None = None
    system_set: bool = False
    user: str | None = None
    from_: str | None = None
    to: str | None = None
    severity: str | None = None
    max_severity: str | None = None
    has_findings: bool | None = None
    category: str | None = None
    rule_ids: tuple[str, ...] = ()
    status: str | None = None
    min_duration: float | None = None
    max_duration: float | None = None
    text: str | None = None
    regex: str | None = None
    sort: str = SORT_NEWEST
    discovery: bool = False
    cmd: str | None = None


@dataclass(frozen=True, slots=True)
class Cursor:
    """A decoded paging cursor (spec §5.4).

    Attributes:
        sort: The sort the cursor was issued for; must equal the request's.
        kinds: Sorted kinds actually queried (after exclusions); must equal the
            request's.
        positions: Source name → keyset position, or :data:`POSITION_DONE`. A
            source absent from the map starts at its beginning.
    """

    sort: str
    kinds: tuple[str, ...]
    positions: Mapping[str, Position | Literal["done"]] = field(default_factory=dict)


def session_kind(row: object) -> str:
    """Return the kind of one ``sessions`` row (spec §4.2).

    The Python twin of the SQL predicates built from :data:`gatorcast.db.FAILED_SQL`
    (``FAILED_SQL.format(a="s.")``) and ``request_id IS NOT NULL``; both must
    agree on every row. Evaluated in order: ``failed`` when ``status = 'error'``,
    ``COALESCE(chunk_count, 0) = 0`` and ``cast_path IS NULL``; else ``exec`` when
    ``request_id`` is set; else ``ssh``.

    Args:
        row: A :class:`gatorcast.models.Session`, a mapping (``dict`` or
            ``sqlite3.Row``/``aiosqlite.Row``) or any object with ``status``,
            ``chunk_count``, ``cast_path`` and ``request_id``. Missing fields read
            as ``None``.

    Returns:
        :data:`KIND_FAILED`, :data:`KIND_EXEC`, or :data:`KIND_SSH`.
    """

    def get(name: str) -> object:
        if isinstance(row, Mapping):
            return row.get(name)
        try:
            return row[name]  # type: ignore[index]  # sqlite3.Row is not a Mapping
        except (TypeError, KeyError, IndexError):
            return getattr(row, name, None)

    if get("status") == "error" and not get("chunk_count") and get("cast_path") is None:
        return KIND_FAILED
    if get("request_id") is not None:
        return KIND_EXEC
    return KIND_SSH


def _is_rank(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_RANK


def _is_at(value: object) -> bool:
    return isinstance(value, str) and _AT_RE.fullmatch(value) is not None


def _is_conn_id(value: object) -> bool:
    return isinstance(value, str) and _CONN_ID_RE.fullmatch(value) is not None


def _is_request_id(value: object) -> bool:
    return isinstance(value, str) and _REQUEST_ID_RE.fullmatch(value) is not None


def _is_duration(value: object) -> bool:
    return (
        type(value) in (int, float)
        and math.isfinite(value)  # type: ignore[arg-type]
        and value >= 0  # type: ignore[operator]
    )


def check_position(source: str, sort: str, value: object) -> Position:
    """Validate one source's cursor position and return it as a tuple.

    Shapes (spec §6.2, §6.3):

    ============  =========  =============================================
    source        sort       position
    ============  =========  =============================================
    sessions      newest     ``(at, conn_id)``
    sessions      risk       ``(rank, at, conn_id)``
    sessions      duration   ``(has_duration 0|1, duration, conn_id)``
    api_commands  newest     ``("T", at, request_id)`` or ``("F", at, request_id)``
    api_commands  risk       ``("F", rank, at, request_id)`` or ``("T", at, request_id)``
    ============  =========  =============================================

    ``at`` is ``YYYY-MM-DDTHH:MM:SS.mmmZ``; ``rank`` an int 0–4; ``duration`` a
    finite number ≥ 0; ``conn_id``/``request_id`` the classify safe-token patterns.
    Booleans are never accepted as numbers. ``api_commands`` has no ``duration``
    position (kubectl is excluded under that sort).

    Args:
        source: The source name (a key of :data:`SOURCE_RANK`).
        sort: The cursor's sort.
        value: The decoded JSON value (a list or tuple).

    Returns:
        The position as a tuple.

    Raises:
        ValueError: If the source, sort, or shape is not valid. The message never
            contains the value.
    """
    if not isinstance(value, (list, tuple)):
        raise ValueError("position is not a list")
    pos = tuple(value)
    ok = False
    if source == SOURCE_SESSIONS:
        match sort, pos:
            case "newest", (at, cid):
                ok = _is_at(at) and _is_conn_id(cid)
            case "risk", (rank, at, cid):
                ok = _is_rank(rank) and _is_at(at) and _is_conn_id(cid)
            case "duration", (flag, dur, cid):
                ok = type(flag) is int and flag in (0, 1) and _is_duration(dur) and _is_conn_id(cid)
    elif source == SOURCE_API_COMMANDS:
        match sort, pos:
            case "newest", (phase, at, rid):
                ok = phase in (PHASE_SCAN, PHASE_FLAGGED) and _is_at(at) and _is_request_id(rid)
            case "risk", ("F", rank, at, rid):  # PHASE_FLAGGED (literal: a bare name would capture)
                ok = _is_rank(rank) and _is_at(at) and _is_request_id(rid)
            case "risk", ("T", at, rid):  # PHASE_SCAN
                ok = _is_at(at) and _is_request_id(rid)
    if not ok:
        raise ValueError("position does not match its source and sort")
    return pos


# =================================================================================
# Result types
# =================================================================================


@dataclass(frozen=True, slots=True)
class RecordingFinding:
    """One ``findings`` row of a recording: rule metadata and offset, never text."""

    id: int
    conn_id: str
    rule_id: str
    category: str
    severity: str
    label: str
    offset_seconds: float | None


@dataclass(frozen=True, slots=True)
class RecordingHit:
    """A hydrated ``sessions`` item: the row, its kind, and its findings (Q8).

    Attributes:
        session: The ``sessions`` row (metadata only).
        kind: ``ssh``, ``exec`` or ``failed`` (:func:`session_kind`).
        findings: The recording's findings, earliest offset first (NULLs last).
    """

    session: Session
    kind: str
    findings: tuple[RecordingFinding, ...] = ()


@dataclass(frozen=True, slots=True)
class CommandRef:
    """Identity and start row of one kubectl command (an item before hydration).

    A command is ``(resource_address, user_key, CMD_KEY)`` (spec §3, §6.3); its id
    is the ``request_id`` of its start row, the row with the smallest
    ``(requested_at, request_id)``.

    Attributes:
        request_id: The start row's ``request_id`` (the command id).
        requested_at: The start row's ``requested_at`` (the command's ``at``).
        resource_address: The cluster (``None`` = unknown bucket).
        user_key: The user key (``None`` = unknown bucket).
        ck: The command key (``CMD_KEY_SQL`` value: ``s:<session>`` or ``c:<conn>``).
        rank: Highest finding rank (0 when unknown or none; set in flagged mode).
    """

    request_id: str
    requested_at: str
    resource_address: str | None
    user_key: str | None
    ck: str
    rank: int = 0


@dataclass(frozen=True, slots=True)
class CommandHit:
    """A hydrated kubectl command (Q6a–c, Q7).

    ``command`` is :func:`~gatorcast.pipeline.activity.group_commands` over the
    first :data:`_CMD_MAX_REQUESTS` requests (label, primary, listed requests).
    The aggregate fields cover **every** row of the command and override the
    command's own (spec §6.3 "Hydration").

    Attributes:
        ref: The command's identity and start row.
        command: The grouped command over the listed requests.
        request_count: Requests in the command, discovery included.
        discovery_count: Discovery requests in the command.
        started_at: First ``requested_at``.
        ended_at: Last ``requested_at``.
        finding_count: API findings over the whole command.
        max_severity: Highest finding severity over the whole command.
        finding_labels: Distinct finding labels, first-seen order.
        findings: ``request_id`` → findings, for every request of the command.
        recordings: Linked recording ``conn_id`` values (``request_id`` join only).
    """

    ref: CommandRef
    command: Command
    request_count: int
    discovery_count: int
    started_at: str
    ended_at: str
    finding_count: int
    max_severity: str | None
    finding_labels: tuple[str, ...]
    findings: Mapping[str, list[ApiFindingRow]]
    recordings: tuple[str, ...]

    @property
    def command_id(self) -> str:
        """The command id: its start row's ``request_id`` (``/search?cmd=``)."""
        return self.ref.request_id

    @property
    def resource_address(self) -> str | None:
        """The cluster."""
        return self.ref.resource_address

    @property
    def user_key(self) -> str | None:
        """The user key (user id, else username)."""
        return self.ref.user_key

    @property
    def conn_id(self) -> str:
        """The start row's ``conn_id`` (CSV column 1)."""
        return self.command.requests[0].conn_id

    @property
    def username(self) -> str | None:
        """The first username among the listed requests, if any."""
        return next((r.username for r in self.command.requests if r.username), None)

    @property
    def user_id(self) -> str | None:
        """The first user id among the listed requests, if any."""
        return next((r.user_id for r in self.command.requests if r.user_id), None)

    @property
    def label(self) -> str:
        """The command label (``Kubectl-Command``, else UA product, else unknown)."""
        return self.command.label

    @property
    def listed_count(self) -> int:
        """Requests listed (at most :data:`_CMD_MAX_REQUESTS`)."""
        return len(self.command.requests)

    @property
    def requests_truncated(self) -> bool:
        """True when more requests exist than are listed."""
        return self.request_count > self.listed_count

    @property
    def is_discovery_only(self) -> bool:
        """True when every request is discovery."""
        return self.discovery_count == self.request_count

    @property
    def duration_seconds(self) -> float:
        """Span from the first to the last request, in seconds (CSV column 7)."""
        return (
            parse_requested_at(self.ended_at) - parse_requested_at(self.started_at)
        ).total_seconds()

    def visible_requests(self, include_discovery: bool = False) -> tuple[Any, ...]:
        """The listed requests to render (discovery hidden unless asked).

        Args:
            include_discovery: True to include discovery requests.

        Returns:
            The listed :class:`~gatorcast.store.activity.ApiRequestRow` values.
        """
        return self.command.visible_requests(include_discovery)


@dataclass(frozen=True, slots=True)
class TimelineItem:
    """One timeline item (spec §6.1).

    Attributes:
        kind: The kind key (``ssh`` / ``exec`` / ``failed`` / ``kubectl``).
        source: The source name.
        sort_key: Merge key, compared descending; ends in ``(source rank, id)``.
        position: The source's keyset position for this item.
        at: The item's start, ``YYYY-MM-DDTHH:MM:SS.mmmZ``.
        data: Before hydration a :class:`~gatorcast.models.Session` or a
            :class:`CommandRef`; after hydration a :class:`RecordingHit` or a
            :class:`CommandHit`.
    """

    kind: str
    source: str
    sort_key: SortKey
    position: Position
    at: str
    data: Session | CommandRef | RecordingHit | CommandHit


@dataclass(frozen=True, slots=True)
class SourcePage:
    """One source's contribution to a page (spec §6.1).

    Attributes:
        items: Items in the source's order, at most ``limit + 1``.
        exhausted: True when nothing exists after the last item.
        frontier: Set when the work budget ran out: the last position examined.
        frontier_key: Merge key of ``frontier``.
        notices: Notice names raised (``NOTICE_*``).
    """

    items: list[TimelineItem]
    exhausted: bool
    frontier: Position | None = None
    frontier_key: SortKey | None = None
    notices: frozenset[str] = frozenset()


class TimelineSource(Protocol):
    """A keyset-paged event source (spec §6.1, §13).

    Contract: ``page`` returns items in the source's own descending merge-key
    order, at most ``limit + 1`` of them; ``exhausted`` when nothing follows the
    last item; and, when a work budget stops it early, ``frontier`` (the last
    position examined) with its merge key. ``hydrate`` loads display data for the
    items actually emitted.
    """

    name: str

    async def page(
        self,
        q: UnifiedQuery,
        kinds: frozenset[str],
        after: Position | None,
        limit: int,
    ) -> SourcePage:
        """Return up to ``limit + 1`` items after ``after`` (``None`` = from the top)."""
        ...

    async def hydrate(
        self, q: UnifiedQuery, items: Sequence[TimelineItem]
    ) -> list[TimelineItem | None]:
        """Return ``items`` with display data, aligned; ``None`` for a vanished item."""
        ...


@dataclass(frozen=True, slots=True)
class TimelinePage:
    """One page of the unified timeline (spec §6.1, §6.4).

    Attributes:
        items: Hydrated items, merge order (``data`` is a :class:`RecordingHit` or
            a :class:`CommandHit`).
        next_cursor: Cursor for the next page, or ``None`` when every source is
            exhausted. Encode it with ``gatorcast.web.params.encode_cursor``.
        kinds: Sorted kinds queried (what a cursor must carry).
        excluded: Excluded kind → reason, passed through from ``resolve_kinds``.
        budget_hit: The page is short because a budget stopped a source; the UI
            shows *Continue scanning ›* (with ``next_cursor``) instead of *Next ›*.
        scan_budget_hit: ``budget_hit`` and the kubectl scan budget caused it.
        content_budget_hit: ``budget_hit`` and the recording content budget caused it.
        flagged_cap_hit: More flagged kubectl commands match than the cap.
        focus_not_found: ``cmd=`` named no stored request.
        scan_budget: The kubectl row budget in force (for the notice text).
        content_budget: The sidecar budget in force (for the notice text).
        flagged_cap: The flagged-command cap in force (for the notice text).
    """

    items: list[TimelineItem]
    next_cursor: Cursor | None
    kinds: tuple[str, ...]
    excluded: Mapping[str, str] = field(default_factory=dict)
    budget_hit: bool = False
    scan_budget_hit: bool = False
    content_budget_hit: bool = False
    flagged_cap_hit: bool = False
    focus_not_found: bool = False
    scan_budget: int = 0
    content_budget: int = 0
    flagged_cap: int = 0


# =================================================================================
# Shared SQL fragments (static; no user value is ever interpolated)
# =================================================================================


def _rank_case(column: str) -> str:
    """Return ``CASE <column> WHEN 'critical' THEN 4 … ELSE 0 END`` (static).

    Args:
        column: A code-supplied, qualified column name (never user input).

    Returns:
        The severity-rank ``CASE`` expression.
    """
    whens = " ".join(f"WHEN '{name}' THEN {rank}" for name, rank in SEVERITY_RANK.items())
    return f"CASE {column} {whens} ELSE 0 END"


def _severities_at_or_above(severity: str) -> list[str]:
    """Return the severities ranked at or above ``severity`` (``[]`` if unknown)."""
    floor = SEVERITY_RANK.get(severity)
    if floor is None:
        return []
    return [name for name, rank in SEVERITY_RANK.items() if rank >= floor]


def _placeholders(n: int) -> str:
    """Return ``?, ?, …`` for ``n`` bound parameters."""
    return ", ".join("?" for _ in range(n))


# sessions (alias ``s``)
_S_AT = session_at("s")
_S_FAILED = FAILED_SQL.format(a="s.")
_S_IS_FAILED = f"COALESCE({_S_FAILED}, 0) = 1"
_S_NOT_FAILED = f"COALESCE({_S_FAILED}, 0) = 0"
_S_RANK = _rank_case("s.max_severity")
_S_HAS_DURATION = "(s.duration_seconds IS NOT NULL)"
_S_DURATION = "COALESCE(s.duration_seconds, 0)"

# api_requests: the path part of a URL (before ``?``), lower-cased, for text search.
_PATH_LOWER = (
    "lower(substr({a}.url, 1, CASE WHEN instr({a}.url, '?') > 0 "
    "THEN instr({a}.url, '?') - 1 ELSE length({a}.url) END))"
)


def _same_cmd(q: str, x: str, x_key: str | None = None) -> str:
    """``SAME_CMD(q, x)``: row ``q`` belongs to the command identified by ``x``.

    Args:
        q: Alias of the probed ``api_requests`` row.
        x: Alias of the row (or CTE row) identifying the command.
        x_key: SQL for ``x``'s command key; default renders ``CMD_KEY_SQL`` over
            ``x``'s columns. Pass ``"<x>.ck"`` for a CTE that carries the key.

    Returns:
        The SQL predicate (matches ``idx_api_req_cmd`` on ``q``).
    """
    key = x_key if x_key is not None else cmd_key(x)
    # Unary ``+`` keeps the planner off idx_api_req_sys_user_time (two equality
    # columns look cheaper than one expression) so the probe uses idx_api_req_cmd.
    return (
        f"{cmd_key(q)} = {key} AND +{q}.resource_address IS {x}.resource_address "
        f"AND +{q}.user_key IS {x}.user_key"
    )


def _text_exists(x: str, x_key: str | None = None) -> str:
    """``EXISTS`` a request of ``x``'s command whose path or command matches (2 params)."""
    path = _PATH_LOWER.format(a="t")
    return (
        f"EXISTS (SELECT 1 FROM api_requests t WHERE {_same_cmd('t', x, x_key)} "
        f"AND (instr({path}, ?) > 0 OR instr(lower(COALESCE(t.kubectl_command, '')), ?) > 0))"
    )


def _has_flag_filters(q: UnifiedQuery) -> bool:
    """True when the query needs flagged mode (spec §6.3 "Mode selection")."""
    return bool(
        q.severity is not None
        or q.max_severity is not None
        or q.has_findings is True
        or q.category is not None
        or q.rule_ids
    )


# =================================================================================
# Sessions source (spec §6.2)
# =================================================================================


def _session_kind_sql(kinds: frozenset[str]) -> str | None:
    """The §4.2 kind predicate for the selected sessions kinds (``None`` = all)."""
    selected = kinds & {KIND_SSH, KIND_EXEC, KIND_FAILED}
    if selected == {KIND_SSH, KIND_EXEC, KIND_FAILED}:
        return None
    parts: list[str] = []
    if KIND_FAILED in selected:
        parts.append(_S_IS_FAILED)
    if KIND_EXEC in selected:
        parts.append(f"(+s.request_id IS NOT NULL AND {_S_NOT_FAILED})")
    if KIND_SSH in selected:
        parts.append(f"(+s.request_id IS NULL AND {_S_NOT_FAILED})")
    return "(" + " OR ".join(parts) + ")" if parts else "0"


def _sessions_where(q: UnifiedQuery, kinds: frozenset[str]) -> tuple[list[str], list[object]]:
    """Build the sessions row filters (spec §4.3) as ``(clauses, params)``."""
    # Equality terms on indexed columns (system, status, the kind's request_id) are
    # written with unary ``+`` so Q1 keeps walking idx_sessions_at in order and stops
    # at its LIMIT, instead of collecting a range of another index and sorting it.
    # A row whose start renders NULL (no parseable started_at/created_at) has no
    # place in the keyset order, so it is never listed.
    clauses: list[str] = [f"{_S_AT} IS NOT NULL"]
    params: list[object] = []
    kind_sql = _session_kind_sql(kinds)
    if kind_sql is not None:
        clauses.append(kind_sql)
    if q.system_set:
        clauses.append("+s.resource_address IS ?")
        params.append(q.system)
    if q.user is not None:
        # sessions has no user_id: the user_id half goes through the connection row.
        clauses.append(
            "(s.username = ? OR EXISTS (SELECT 1 FROM connections c "
            "WHERE c.conn_id = s.conn_id AND c.user_id = ?))"
        )
        params.extend((q.user, q.user))
    if q.from_ is not None:
        clauses.append(f"{_S_AT} >= ?")
        params.append(q.from_)
    if q.to is not None:
        clauses.append(f"{_S_AT} <= ?")
        params.append(q.to)
    if q.status is not None:
        clauses.append("+s.status = ?")
        params.append(q.status)
    if q.min_duration is not None:
        clauses.append("s.duration_seconds >= ?")
        params.append(q.min_duration)
    if q.max_duration is not None:
        clauses.append("s.duration_seconds <= ?")
        params.append(q.max_duration)
    if q.has_findings is True:
        clauses.append("s.finding_count > 0")
    elif q.has_findings is False:
        clauses.append("COALESCE(s.finding_count, 0) = 0")
    if q.max_severity is not None:
        clauses.append("s.max_severity = ?")
        params.append(q.max_severity)
    if q.category is not None:
        clauses.append(
            "EXISTS (SELECT 1 FROM findings f WHERE f.conn_id = s.conn_id AND f.category = ?)"
        )
        params.append(q.category)
    if q.rule_ids:
        clauses.append(
            "EXISTS (SELECT 1 FROM findings f WHERE f.conn_id = s.conn_id "
            f"AND f.rule_id IN ({_placeholders(len(q.rule_ids))}))"
        )
        params.extend(q.rule_ids)
    if q.severity is not None:
        allowed = _severities_at_or_above(q.severity)
        if not allowed:
            clauses.append("0")
        else:
            clauses.append(
                "EXISTS (SELECT 1 FROM findings f WHERE f.conn_id = s.conn_id "
                f"AND f.severity IN ({_placeholders(len(allowed))}))"
            )
            params.extend(allowed)
    return clauses, params


def sessions_page_sql(
    q: UnifiedQuery, kinds: frozenset[str], after: Position | None, limit: int
) -> tuple[str, list[object]]:
    """Build Q1 (``newest``) or Q2 (``risk`` / ``duration``) for the sessions source.

    The ``newest`` keyset is written ``at <= ? AND (at < ? OR conn_id < ?)``: the
    first term is a range on ``idx_sessions_at`` (a row-value ``(at, conn_id) <
    (?, ?)`` plans as a full covering-index scan); the rest is a residual filter.

    Args:
        q: The query.
        kinds: The selected sessions kinds.
        after: Keyset position (shape per :func:`check_position`), or ``None``.
        limit: ``LIMIT`` value.

    Returns:
        ``(sql, params)``.
    """
    clauses, params = _sessions_where(q, kinds)
    if q.sort == SORT_RISK:
        order = f"{_S_RANK} DESC, {_S_AT} DESC, s.conn_id DESC"
        if after is not None:
            clauses.append(f"({_S_RANK}, {_S_AT}, s.conn_id) < (?, ?, ?)")
            params.extend(after)
    elif q.sort == SORT_DURATION:
        order = f"{_S_HAS_DURATION} DESC, {_S_DURATION} DESC, s.conn_id DESC"
        if after is not None:
            clauses.append(f"({_S_HAS_DURATION}, {_S_DURATION}, s.conn_id) < (?, ?, ?)")
            params.extend(after)
    else:
        order = f"{_S_AT} DESC, s.conn_id DESC"
        if after is not None:
            at, cid = after
            clauses.append(f"{_S_AT} <= ? AND ({_S_AT} < ? OR s.conn_id < ?)")
            params.extend((at, at, cid))
    sql = (
        f"SELECT {_SESSION_COLUMNS}, {_S_AT} AS gc_at, {_S_RANK} AS gc_rank, "
        f"{_S_HAS_DURATION} AS gc_has_dur, {_S_DURATION} AS gc_dur "
        f"FROM sessions s WHERE {' AND '.join(clauses)} ORDER BY {order} LIMIT ?"
    )
    params.append(int(limit))
    return sql, params


_FINDINGS_FOR_SESSIONS_SQL = (
    "SELECT id, conn_id, rule_id, category, severity, label, offset_seconds "
    "FROM findings WHERE conn_id IN ({ph}) "
    "ORDER BY conn_id, offset_seconds IS NULL, offset_seconds, id"
)
"""Q8: findings for a page of recordings (``{ph}`` = placeholders)."""


def _session_item(row: aiosqlite.Row, sort: str) -> TimelineItem:
    """Map a Q1/Q2 row to an unhydrated :class:`TimelineItem`."""
    session = _row_to_session(row)
    at: str = row["gc_at"]
    cid = session.conn_id
    rank_src = SOURCE_RANK[SOURCE_SESSIONS]
    position: Position
    key: SortKey
    if sort == SORT_RISK:
        rank = int(row["gc_rank"])
        position = (rank, at, cid)
        key = (rank, at, rank_src, cid)
    elif sort == SORT_DURATION:
        has = int(row["gc_has_dur"])
        dur = float(row["gc_dur"])
        position = (has, dur, cid)
        key = (has, dur, rank_src, cid)
    else:
        position = (at, cid)
        key = (at, rank_src, cid)
    return TimelineItem(
        kind=session_kind(session),
        source=SOURCE_SESSIONS,
        sort_key=key,
        position=position,
        at=at,
        data=session,
    )


def _scan_matches(
    texts: Sequence[tuple[str, str]],
    needle: str | None,
    compiled: re.Pattern[str] | None,
) -> set[str]:
    """Return the conn_ids whose text satisfies every content filter (runs off-loop).

    Pure CPU work for ``asyncio.to_thread``; never logs text.

    Args:
        texts: ``(conn_id, sidecar_text)`` pairs.
        needle: Lower-cased substring to require, or ``None``.
        compiled: Compiled regex to require, or ``None``.

    Returns:
        The matching conn_ids.
    """
    matched: set[str] = set()
    for conn_id, text in texts:
        if needle is not None and needle not in text.lower():
            continue
        if compiled is not None and compiled.search(text) is None:
            continue
        matched.add(conn_id)
    return matched


class SessionsSource:
    """The ``sessions`` timeline source: ``ssh``, ``exec`` and ``failed`` (spec §6.2)."""

    name: str = SOURCE_SESSIONS

    def __init__(
        self,
        db: aiosqlite.Connection,
        casts: CastStore,
        *,
        content_budget: int = DEFAULT_CONTENT_BUDGET,
    ) -> None:
        """Initialize the source.

        Args:
            db: The shared aiosqlite connection.
            casts: The cast store (sidecars are read for content search).
            content_budget: Sidecars read per page (``SEARCH_REGEX_MAX_CANDIDATES``).
        """
        self._db = db
        self._casts = casts
        self.content_budget = max(1, int(content_budget))

    async def _fetch(
        self, q: UnifiedQuery, kinds: frozenset[str], after: Position | None, limit: int
    ) -> list[TimelineItem]:
        """Run Q1/Q2 and map the rows."""
        sql, params = sessions_page_sql(q, kinds, after, limit)
        cursor = await self._db.execute(sql, params)
        rows = await cursor.fetchall()
        await cursor.close()
        return [_session_item(row, q.sort) for row in rows]

    async def page(
        self,
        q: UnifiedQuery,
        kinds: frozenset[str],
        after: Position | None,
        limit: int,
    ) -> SourcePage:
        """Return up to ``limit + 1`` recordings after ``after``.

        Without content search this is one Q1/Q2 query. With ``q.text`` /
        ``q.regex`` it is the lazy scan (Q3): batches of at most
        :data:`_CONTENT_BATCH` rows, sidecars read and matched off-loop, until
        ``limit + 1`` hits, the end, or :attr:`content_budget` sidecars read. A
        budget stop returns a ``frontier`` at the last row examined.

        Args:
            q: The query.
            kinds: The selected sessions kinds.
            after: Keyset position, or ``None`` for the top.
            limit: Page size.

        Returns:
            The :class:`SourcePage`.
        """
        if q.text is None and q.regex is None:
            items = await self._fetch(q, kinds, after, limit + 1)
            return SourcePage(items=items, exhausted=len(items) <= limit)
        return await self._content_page(q, kinds, after, limit)

    async def _content_page(
        self,
        q: UnifiedQuery,
        kinds: frozenset[str],
        after: Position | None,
        limit: int,
    ) -> SourcePage:
        """The budgeted lazy content scan (spec §6.2, Q3)."""
        compiled = re.compile(q.regex) if q.regex is not None else None
        needle = q.text.lower() if q.text is not None else None
        budget = self.content_budget
        pos = after
        scanned = 0
        hits: list[TimelineItem] = []
        last_examined: TimelineItem | None = None
        exhausted = False
        while len(hits) < limit + 1 and scanned < budget:
            want = min(_CONTENT_BATCH, budget - scanned)
            batch = await self._fetch(q, kinds, pos, want)
            texts: list[tuple[str, str]] = []
            for item in batch:
                conn_id = item.data.conn_id  # type: ignore[union-attr]
                try:
                    text = await self._casts.read_sidecar(conn_id)
                except FileNotFoundError:
                    continue  # no sidecar (in progress, failed, or not yet backfilled)
                texts.append((conn_id, text))
            matched = await asyncio.to_thread(_scan_matches, texts, needle, compiled)
            del texts
            for item in batch:
                last_examined = item
                if item.data.conn_id in matched:  # type: ignore[union-attr]
                    hits.append(item)
                    if len(hits) == limit + 1:
                        break
            scanned += len(batch)
            if len(batch) < want:
                exhausted = True
                break
            pos = batch[-1].position
        if len(hits) == limit + 1:
            return SourcePage(items=hits, exhausted=False)
        if exhausted:
            return SourcePage(items=hits, exhausted=True)
        # Budget spent without filling the page: stop at the last row examined.
        log.info("timeline.content_budget_hit", scanned=scanned, matched=len(hits))
        assert last_examined is not None  # budget >= 1, so at least one batch ran
        return SourcePage(
            items=hits,
            exhausted=False,
            frontier=last_examined.position,
            frontier_key=last_examined.sort_key,
            notices=frozenset({NOTICE_CONTENT_BUDGET}),
        )

    async def hydrate(
        self, q: UnifiedQuery, items: Sequence[TimelineItem]
    ) -> list[TimelineItem | None]:
        """Attach findings (Q8, one ``IN (…)`` query) and the kind to each item.

        Args:
            q: The query (unused; part of the source contract).
            items: Unhydrated sessions items.

        Returns:
            The items with :class:`RecordingHit` data, aligned with ``items``.
        """
        by_conn: dict[str, list[RecordingFinding]] = {}
        conn_ids = list(dict.fromkeys(it.data.conn_id for it in items))  # type: ignore[union-attr]
        for start in range(0, len(conn_ids), 500):
            chunk = conn_ids[start : start + 500]
            cursor = await self._db.execute(
                _FINDINGS_FOR_SESSIONS_SQL.format(ph=_placeholders(len(chunk))), chunk
            )
            rows = await cursor.fetchall()
            await cursor.close()
            for row in rows:
                by_conn.setdefault(row["conn_id"], []).append(
                    RecordingFinding(
                        id=row["id"],
                        conn_id=row["conn_id"],
                        rule_id=row["rule_id"],
                        category=row["category"],
                        severity=row["severity"],
                        label=row["label"],
                        offset_seconds=row["offset_seconds"],
                    )
                )
        out: list[TimelineItem | None] = []
        for it in items:
            session = it.data
            assert isinstance(session, Session)
            hit = RecordingHit(
                session=session,
                kind=it.kind,
                findings=tuple(by_conn.get(session.conn_id, ())),
            )
            out.append(replace(it, data=hit))
        return out


# =================================================================================
# kubectl command source (spec §6.3)
# =================================================================================

_SCAN_COLS = (
    "r.request_id AS request_id, r.requested_at AS requested_at, "
    "r.resource_address AS resource_address, r.user_key AS user_key, "
    "r.conn_id AS conn_id, r.kubectl_session AS kubectl_session"
)
# ``r.method`` is in no index, so Q4b cannot pick a covering full scan + sort over
# idx_api_req_cmd; it walks the same time index as Q4.
_FRONTIER_COLS = "r.requested_at AS requested_at, r.request_id AS request_id, r.method AS method"
_ORDER_R = "ORDER BY r.requested_at DESC, r.request_id DESC"
_API_RANK_F2 = _rank_case("f2.severity")


def _api_row_filters(
    q: UnifiedQuery, after: tuple[str, str] | None
) -> tuple[list[str], list[object]]:
    """Row filters of a scan arm (system, window, keyset), alias ``r``."""
    clauses: list[str] = []
    params: list[object] = []
    if q.system_set:
        clauses.append("r.resource_address IS ?")
        params.append(q.system)
    if q.from_ is not None:
        clauses.append("r.requested_at >= ?")
        params.append(q.from_)
    if q.to is not None:
        clauses.append("r.requested_at <= ?")
        params.append(q.to)
    if after is not None:
        at, rid = after
        # Range on requested_at (seekable) plus a residual tie-break on request_id.
        clauses.append("r.requested_at <= ? AND (r.requested_at < ? OR r.request_id < ?)")
        params.extend((at, at, rid))
    return clauses, params


def _scan_rows_sql(
    q: UnifiedQuery,
    after: tuple[str, str] | None,
    *,
    cols: str,
    arm_limit: int,
    outer_limit: int,
) -> tuple[str, list[object]]:
    """The ``api_requests`` walk in ``(requested_at, request_id)`` DESC order.

    Without ``user``: one range on ``idx_api_req_sys_time`` / ``idx_api_req_time``.
    With ``user``: a ``UNION`` of two keyset arms (``username = ?`` on
    ``idx_api_req_user_time``, ``user_id = ?`` on ``idx_api_req_userid_time``),
    each stopping at ``arm_limit``; ``UNION`` drops a row matched by both.

    Args:
        q: The query.
        after: ``(at, request_id)`` keyset, or ``None``.
        cols: Select list (aliased to bare names).
        arm_limit: Per-arm ``LIMIT`` (user union only).
        outer_limit: Final ``LIMIT``.

    Returns:
        ``(sql, params)``.
    """
    base, base_params = _api_row_filters(q, after)
    tail = " LIMIT ?"
    tail_params: list[object] = [int(outer_limit)]
    if q.user is None:
        where = f" WHERE {' AND '.join(base)}" if base else ""
        sql = f"SELECT {cols} FROM api_requests r{where} {_ORDER_R}{tail}"
        return sql, [*base_params, *tail_params]
    arms: list[str] = []
    params: list[object] = []
    for column in ("r.username", "r.user_id"):
        where = " AND ".join([f"{column} = ?", *base])
        arms.append(
            f"SELECT * FROM (SELECT {cols} FROM api_requests r WHERE {where} "
            f"{_ORDER_R} LIMIT ?)"
        )
        params.extend((q.user, *base_params, int(arm_limit)))
    sql = f"{arms[0]} UNION {arms[1]} ORDER BY requested_at DESC, request_id DESC{tail}"
    return sql, [*params, *tail_params]


def api_scan_sql(
    q: UnifiedQuery,
    after: tuple[str, str] | None,
    *,
    want: int,
    budget: int,
    no_findings: bool,
) -> tuple[str, list[object]]:
    """Build Q4: one page of command start rows, examining at most ``budget`` rows.

    The ``scanned`` CTE has a ``LIMIT`` and the outer query a ``WHERE``, so SQLite
    runs it as a co-routine (not flattened) and the budget is enforced.

    Args:
        q: The query (``system``, ``user``, window, ``text``, ``discovery``).
        after: ``(at, request_id)`` keyset, or ``None``.
        want: Start rows wanted (``LIMIT``).
        budget: Rows examined at most (:data:`_API_SCAN_BUDGET`).
        no_findings: Add the command-has-no-finding clause (``has_findings=false``,
            risk phase ``T``).

    Returns:
        ``(sql, params)``. Columns: ``request_id, requested_at, resource_address,
        user_key, ck``.
    """
    scanned, params = _scan_rows_sql(
        q, after, cols=_SCAN_COLS, arm_limit=budget, outer_limit=budget
    )
    conds = [
        "NOT EXISTS (SELECT 1 FROM api_requests p WHERE "
        f"{_same_cmd('p', 's')} AND p.requested_at <= s.requested_at "
        "AND (p.requested_at < s.requested_at OR p.request_id < s.request_id))"
    ]
    if not q.discovery:
        conds.append(
            f"EXISTS (SELECT 1 FROM api_requests d WHERE {_same_cmd('d', 's')} "
            "AND gc_is_discovery(d.method, d.url) = 0)"
        )
    if q.text is not None:
        conds.append(_text_exists("s"))
        needle = q.text.lower()
        params.extend((needle, needle))
    if no_findings:
        conds.append(
            "NOT EXISTS (SELECT 1 FROM api_requests n JOIN api_findings nf "
            f"ON nf.request_id = n.request_id WHERE {_same_cmd('n', 's')})"
        )
    sql = (
        f"WITH scanned AS ({scanned}) "
        "SELECT s.request_id AS request_id, s.requested_at AS requested_at, "
        "s.resource_address AS resource_address, s.user_key AS user_key, "
        f"{cmd_key('s')} AS ck "
        f"FROM scanned s WHERE {' AND '.join(conds)} "
        "ORDER BY s.requested_at DESC, s.request_id DESC LIMIT ?"
    )
    params.append(int(want))
    return sql, params


def api_scan_frontier_sql(
    q: UnifiedQuery, after: tuple[str, str] | None, *, budget: int
) -> tuple[str, list[object]]:
    """Build Q4b: the rows at offsets ``budget - 1`` and ``budget`` of the Q4 walk.

    Two rows → the budget was hit, and the first is the frontier (the last row
    examined). One or none → the walk ended inside the budget (exhausted).

    Args:
        q: The query.
        after: The same keyset as Q4.
        budget: The Q4 budget.

    Returns:
        ``(sql, params)``. Columns: ``requested_at, request_id``.
    """
    # The walk is written exactly like Q4's ``scanned`` CTE (same shape, so the same
    # range index), limited to ``budget + 1`` rows; the outer query reads the two
    # edge rows from that co-routine without re-sorting.
    walk, params = _scan_rows_sql(
        q, after, cols=_FRONTIER_COLS, arm_limit=budget + 1, outer_limit=budget + 1
    )
    sql = (
        f"WITH walk AS ({walk}) SELECT requested_at, request_id FROM walk "
        "ORDER BY requested_at DESC, request_id DESC LIMIT 2 OFFSET ?"
    )
    params.append(int(budget) - 1)
    return sql, params


def _hit_sql(q: UnifiedQuery, cap: int) -> tuple[str, list[object]]:
    """The ``hit`` CTE body of Q5: distinct commands with a qualifying finding."""
    clauses: list[str] = []
    params: list[object] = []
    if q.severity is not None:
        allowed = _severities_at_or_above(q.severity)
        if allowed:
            clauses.append(f"f.severity IN ({_placeholders(len(allowed))})")
            params.extend(allowed)
        else:
            clauses.append("0")
    if q.max_severity is not None:
        clauses.append("f.severity = ?")
        params.append(q.max_severity)
    if q.category is not None:
        clauses.append("f.category = ?")
        params.append(q.category)
    if q.rule_ids:
        clauses.append(f"f.rule_id IN ({_placeholders(len(q.rule_ids))})")
        params.extend(q.rule_ids)
    if q.system_set:
        clauses.append("r.resource_address IS ?")
        params.append(q.system)
    if q.user is not None:
        clauses.append("(r.username = ? OR r.user_id = ?)")
        params.extend((q.user, q.user))
    if q.from_ is not None:
        # Valid prefilter: a command's start is <= any of its hits, and >= from.
        clauses.append("r.requested_at >= ?")
        params.append(q.from_)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (
        "SELECT DISTINCT r.resource_address AS resource_address, r.user_key AS user_key, "
        f"{cmd_key('r')} AS ck "
        f"FROM api_findings f JOIN api_requests r ON r.request_id = f.request_id{where} "
        "LIMIT ?"
    )
    params.append(int(cap) + 1)
    return sql, params


def api_flagged_count_sql(q: UnifiedQuery, *, cap: int) -> tuple[str, list[object]]:
    """Count the ``hit`` set of Q5 (at most ``cap + 1``), for the cap notice."""
    hit, params = _hit_sql(q, cap)
    return f"SELECT COUNT(*) AS n FROM ({hit})", params


def api_flagged_sql(
    q: UnifiedQuery,
    after: tuple[Any, ...] | None,
    *,
    want: int,
    cap: int,
    risk: bool,
    any_finding: bool,
) -> tuple[str, list[object]]:
    """Build Q5: flagged commands found from ``api_findings`` (spec §6.3).

    Args:
        q: The query (finding filters, ``system``, ``user``, window, ``text``).
        after: Keyset ``(rank, at, id)`` (risk) or ``(at, id)`` (newest), or ``None``.
        want: ``LIMIT``.
        cap: :data:`_FLAGGED_CMD_CAP`; ``hit`` reads at most ``cap + 1`` commands.
        risk: Order by max rank first.
        any_finding: Risk phase ``F`` with no finding filter (``max_rank >= 1``).

    Returns:
        ``(sql, params)``. Columns: ``request_id, requested_at, resource_address,
        user_key, ck, max_rank, hit_n``.
    """
    hit, params = _hit_sql(q, cap)
    same_h = _same_cmd("q", "h", "h.ck")
    conds: list[str] = ["c.start_id IS NOT NULL"]
    if q.from_ is not None:
        conds.append("c.start_at >= ?")
        params.append(q.from_)
    if q.to is not None:
        conds.append("c.start_at <= ?")
        params.append(q.to)
    if q.max_severity is not None:
        conds.append("c.max_rank = ?")
        params.append(SEVERITY_RANK.get(q.max_severity, -1))
    if any_finding:
        conds.append("c.max_rank >= 1")
    if q.text is not None:
        conds.append(_text_exists("c", "c.ck"))
        needle = q.text.lower()
        params.extend((needle, needle))
    if after is not None:
        if risk:
            conds.append("(c.max_rank, c.start_at, c.start_id) < (?, ?, ?)")
        else:
            conds.append("(c.start_at, c.start_id) < (?, ?)")
        params.extend(after)
    order = (
        "ORDER BY c.max_rank DESC, c.start_at DESC, c.start_id DESC"
        if risk
        else "ORDER BY c.start_at DESC, c.start_id DESC"
    )
    sql = (
        f"WITH hit AS ({hit}), "
        "cmd AS (SELECT h.resource_address AS resource_address, h.user_key AS user_key, "
        "h.ck AS ck, "
        f"(SELECT q.requested_at FROM api_requests q WHERE {same_h} "
        "ORDER BY q.requested_at, q.request_id LIMIT 1) AS start_at, "
        f"(SELECT q.request_id FROM api_requests q WHERE {same_h} "
        "ORDER BY q.requested_at, q.request_id LIMIT 1) AS start_id, "
        f"(SELECT MAX({_API_RANK_F2}) FROM api_requests q JOIN api_findings f2 "
        f"ON f2.request_id = q.request_id WHERE {same_h}) AS max_rank "
        "FROM hit h) "
        "SELECT c.start_id AS request_id, c.start_at AS requested_at, "
        "c.resource_address AS resource_address, c.user_key AS user_key, c.ck AS ck, "
        "COALESCE(c.max_rank, 0) AS max_rank, (SELECT COUNT(*) FROM hit) AS hit_n "
        f"FROM cmd c WHERE {' AND '.join(conds)} {order} LIMIT ?"
    )
    params.append(int(want))
    return sql, params


# Q9 focus: resolve any request of a command to the command, then its start row.
FOCUS_RESOLVE_SQL: Final = (
    f"SELECT resource_address, user_key, {cmd_key()} AS ck "
    "FROM api_requests WHERE request_id = ?"
)
# Unary ``+``: see _same_cmd (keeps these lookups on idx_api_req_cmd).
_SAME_KEY = f"{cmd_key('q')} = ? AND +q.resource_address IS ? AND +q.user_key IS ?"
FOCUS_START_SQL: Final = (
    "SELECT q.request_id AS request_id, q.requested_at AS requested_at "
    f"FROM api_requests q WHERE {_SAME_KEY} ORDER BY q.requested_at, q.request_id LIMIT 1"
)

# Hydration, per command; params ``(ck, resource_address, user_key)``.
CMD_AGGREGATE_SQL: Final = (  # Q6a
    "SELECT COUNT(*) AS request_count, MIN(q.requested_at) AS first_at, "
    "MAX(q.requested_at) AS last_at, "
    "COALESCE(SUM(gc_is_discovery(q.method, q.url)), 0) AS discovery_count "
    f"FROM api_requests q WHERE {_SAME_KEY}"
)
CMD_FINDINGS_SQL: Final = (  # Q6b (rule metadata only)
    "SELECT f.id AS id, f.request_id AS request_id, f.rule_id AS rule_id, "
    "f.category AS category, f.severity AS severity, f.label AS label, "
    "f.created_at AS created_at "
    "FROM api_requests q JOIN api_findings f ON f.request_id = q.request_id "
    f"WHERE {_SAME_KEY} ORDER BY f.id"
)
CMD_RECORDINGS_SQL: Final = (  # Q6c (request_id join only, never conn_id)
    "SELECT q.request_id AS request_id, s.conn_id AS conn_id "
    "FROM api_requests q JOIN sessions s ON s.request_id = q.request_id "
    f"WHERE {_SAME_KEY} ORDER BY COALESCE(s.started_at, s.created_at), s.conn_id"
)
CMD_REQUESTS_SQL: Final = (  # Q7 (params + LIMIT)
    f"SELECT {_REQUEST_COLUMNS} FROM api_requests q WHERE {_SAME_KEY} "
    "ORDER BY q.requested_at, q.request_id LIMIT ?"
)


def _max_severity(severities: Iterable[str]) -> str | None:
    """Return the highest-ranked known severity, or ``None``."""
    best: str | None = None
    for sev in severities:
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(best or "", 0):
            best = sev
    return best


class ApiCommandSource:
    """The ``api_commands`` timeline source: kubectl commands (spec §6.3)."""

    name: str = SOURCE_API_COMMANDS

    def __init__(self, db: aiosqlite.Connection) -> None:
        """Initialize the source.

        Args:
            db: The shared aiosqlite connection (``gc_is_discovery`` registered).
        """
        self._db = db

    async def _all(self, sql: str, params: Sequence[object]) -> list[aiosqlite.Row]:
        cursor = await self._db.execute(sql, params)
        rows = await cursor.fetchall()
        await cursor.close()
        return list(rows)

    async def page(
        self,
        q: UnifiedQuery,
        kinds: frozenset[str],
        after: Position | None,
        limit: int,
    ) -> SourcePage:
        """Return up to ``limit + 1`` commands after ``after`` (mode per spec §6.3).

        Args:
            q: The query.
            kinds: The selected kinds (must include ``kubectl``).
            after: Keyset position, or ``None`` for the top.
            limit: Page size.

        Returns:
            The :class:`SourcePage`.
        """
        if KIND_KUBECTL not in kinds:
            return SourcePage(items=[], exhausted=True)
        if q.cmd is not None:
            return await self._focus(q, after)
        flagged = _has_flag_filters(q)
        if flagged and q.has_findings is False:
            # "Has a qualifying finding" and "has no finding" cannot both hold.
            return SourcePage(items=[], exhausted=True)
        if q.sort == SORT_RISK:
            if flagged:
                if after is not None and after[0] != PHASE_FLAGGED:
                    return SourcePage(items=[], exhausted=True)
                return await self._flagged(q, _tail(after), limit, risk=True, any_finding=False)
            if q.has_findings is False:
                if after is not None and after[0] != PHASE_SCAN:
                    return SourcePage(items=[], exhausted=True)
                return await self._scan(q, _tail(after), limit + 1, risk=True, no_findings=True)
            return await self._risk_two_phase(q, after, limit)
        if flagged:
            return await self._flagged(q, _tail(after), limit, risk=False, any_finding=False)
        return await self._scan(
            q, _tail(after), limit + 1, risk=False, no_findings=q.has_findings is False
        )

    async def _risk_two_phase(
        self, q: UnifiedQuery, after: Position | None, limit: int
    ) -> SourcePage:
        """Risk sort with no finding filter: phase ``F`` (flagged), then phase ``T``."""
        if after is not None and after[0] == PHASE_SCAN:
            return await self._scan(q, _tail(after), limit + 1, risk=True, no_findings=True)
        fpage = await self._flagged(q, _tail(after), limit, risk=True, any_finding=True)
        if not fpage.exhausted:
            return fpage
        # Phase F is done: continue with phase T from the top, in the same request.
        tpage = await self._scan(
            q, None, limit + 1 - len(fpage.items), risk=True, no_findings=True
        )
        return SourcePage(
            items=fpage.items + tpage.items,
            exhausted=tpage.exhausted,
            frontier=tpage.frontier,
            frontier_key=tpage.frontier_key,
            notices=fpage.notices | tpage.notices,
        )

    async def _scan(
        self,
        q: UnifiedQuery,
        after: tuple[str, str] | None,
        want: int,
        *,
        risk: bool,
        no_findings: bool,
    ) -> SourcePage:
        """Scan mode: Q4, then Q4b when the page is short (spec §6.3)."""
        budget = max(1, int(_API_SCAN_BUDGET))
        sql, params = api_scan_sql(q, after, want=want, budget=budget, no_findings=no_findings)
        rows = await self._all(sql, params)
        items = [_command_item(row, PHASE_SCAN, 0, risk) for row in rows]
        if len(items) >= want:
            return SourcePage(items=items, exhausted=False)
        sql, params = api_scan_frontier_sql(q, after, budget=budget)
        edge = await self._all(sql, params)
        if len(edge) < 2:
            return SourcePage(items=items, exhausted=True)
        at, rid = edge[0]["requested_at"], edge[0]["request_id"]
        rank_src = SOURCE_RANK[SOURCE_API_COMMANDS]
        key: SortKey = (0, at, rank_src, rid) if risk else (at, rank_src, rid)
        return SourcePage(
            items=items,
            exhausted=False,
            frontier=(PHASE_SCAN, at, rid),
            frontier_key=key,
            notices=frozenset({NOTICE_SCAN_BUDGET}),
        )

    async def _flagged(
        self,
        q: UnifiedQuery,
        after: tuple[Any, ...] | None,
        limit: int,
        *,
        risk: bool,
        any_finding: bool,
    ) -> SourcePage:
        """Flagged mode: Q5 (spec §6.3)."""
        cap = max(1, int(_FLAGGED_CMD_CAP))
        sql, params = api_flagged_sql(
            q, after, want=limit + 1, cap=cap, risk=risk, any_finding=any_finding
        )
        rows = await self._all(sql, params)
        if rows:
            hit_n = int(rows[0]["hit_n"])
        else:
            sql, params = api_flagged_count_sql(q, cap=cap)
            hit_n = int((await self._all(sql, params))[0]["n"])
        items = [
            _command_item(row, PHASE_FLAGGED, int(row["max_rank"]), risk) for row in rows
        ]
        notices = frozenset({NOTICE_FLAGGED_CAP}) if hit_n > cap else frozenset()
        return SourcePage(items=items, exhausted=len(items) <= limit, notices=notices)

    async def _focus(self, q: UnifiedQuery, after: Position | None) -> SourcePage:
        """Focus (Q9): the one command containing ``q.cmd``; other filters ignored."""
        if after is not None:
            return SourcePage(items=[], exhausted=True)
        rows = await self._all(FOCUS_RESOLVE_SQL, (q.cmd,))
        if not rows:
            return SourcePage(
                items=[], exhausted=True, notices=frozenset({NOTICE_FOCUS_MISSING})
            )
        ident = rows[0]
        key_params = (ident["ck"], ident["resource_address"], ident["user_key"])
        start = await self._all(FOCUS_START_SQL, key_params)
        if not start:  # pragma: no cover - the resolved row itself always matches
            return SourcePage(
                items=[], exhausted=True, notices=frozenset({NOTICE_FOCUS_MISSING})
            )
        ref = CommandRef(
            request_id=start[0]["request_id"],
            requested_at=start[0]["requested_at"],
            resource_address=ident["resource_address"],
            user_key=ident["user_key"],
            ck=ident["ck"],
        )
        rank_src = SOURCE_RANK[SOURCE_API_COMMANDS]
        key: SortKey
        if q.sort == SORT_RISK:
            key = (0, ref.requested_at, rank_src, ref.request_id)
        elif q.sort == SORT_DURATION:
            key = (0, 0.0, rank_src, ref.request_id)
        else:
            key = (ref.requested_at, rank_src, ref.request_id)
        item = TimelineItem(
            kind=KIND_KUBECTL,
            source=SOURCE_API_COMMANDS,
            sort_key=key,
            position=(PHASE_SCAN, ref.requested_at, ref.request_id),
            at=ref.requested_at,
            data=ref,
        )
        return SourcePage(items=[item], exhausted=True)

    async def hydrate(
        self, q: UnifiedQuery, items: Sequence[TimelineItem]
    ) -> list[TimelineItem | None]:
        """Hydrate each command: Q6a aggregates, Q6b findings, Q6c recordings, Q7 list.

        Args:
            q: The query (unused; part of the source contract).
            items: Unhydrated command items.

        Returns:
            Items with :class:`CommandHit` data, aligned; ``None`` for a command
            whose rows vanished (retention) between paging and hydration.
        """
        out: list[TimelineItem | None] = []
        for it in items:
            ref = it.data
            assert isinstance(ref, CommandRef)
            hit = await self._hydrate_one(ref)
            out.append(replace(it, data=hit) if hit is not None else None)
        return out

    async def _hydrate_one(self, ref: CommandRef) -> CommandHit | None:
        """Load one command's display data (spec §6.3 "Hydration")."""
        key = (ref.ck, ref.resource_address, ref.user_key)
        rows = [
            _row_to_request(r)
            for r in await self._all(CMD_REQUESTS_SQL, (*key, max(1, int(_CMD_MAX_REQUESTS))))
        ]
        if not rows:
            return None
        agg = (await self._all(CMD_AGGREGATE_SQL, key))[0]
        findings: dict[str, list[ApiFindingRow]] = {}
        for row in await self._all(CMD_FINDINGS_SQL, key):
            finding = _row_to_finding(row)
            findings.setdefault(finding.request_id, []).append(finding)
        recordings: dict[str, str] = {}
        recording_order: list[str] = []
        for row in await self._all(CMD_RECORDINGS_SQL, key):
            recordings.setdefault(row["request_id"], row["conn_id"])
            recording_order.append(row["conn_id"])
        command = group_commands(rows, recordings, findings=findings)[0]
        all_findings = sorted(
            (f for fs in findings.values() for f in fs), key=lambda f: f.id
        )
        return CommandHit(
            ref=ref,
            command=command,
            request_count=int(agg["request_count"]),
            discovery_count=int(agg["discovery_count"]),
            started_at=agg["first_at"],
            ended_at=agg["last_at"],
            finding_count=len(all_findings),
            max_severity=_max_severity(f.severity for f in all_findings),
            finding_labels=tuple(dict.fromkeys(f.label for f in all_findings)),
            findings=findings,
            recordings=tuple(dict.fromkeys(recording_order)),
        )


def _tail(after: Position | None) -> tuple[Any, ...] | None:
    """Strip the phase tag from an ``api_commands`` position."""
    return None if after is None else tuple(after[1:])


def _command_item(row: aiosqlite.Row, phase: str, rank: int, risk: bool) -> TimelineItem:
    """Map a Q4/Q5 row to an unhydrated command item."""
    ref = CommandRef(
        request_id=row["request_id"],
        requested_at=row["requested_at"],
        resource_address=row["resource_address"],
        user_key=row["user_key"],
        ck=row["ck"],
        rank=rank,
    )
    rank_src = SOURCE_RANK[SOURCE_API_COMMANDS]
    position: Position
    key: SortKey
    if risk:
        key = (rank, ref.requested_at, rank_src, ref.request_id)
        position = (
            (PHASE_FLAGGED, rank, ref.requested_at, ref.request_id)
            if phase == PHASE_FLAGGED
            else (PHASE_SCAN, ref.requested_at, ref.request_id)
        )
    else:
        key = (ref.requested_at, rank_src, ref.request_id)
        position = (phase, ref.requested_at, ref.request_id)
    return TimelineItem(
        kind=KIND_KUBECTL,
        source=SOURCE_API_COMMANDS,
        sort_key=key,
        position=position,
        at=ref.requested_at,
        data=ref,
    )


# =================================================================================
# Merge and paging (spec §6.4)
# =================================================================================


def build_sources(
    db: aiosqlite.Connection,
    casts: CastStore,
    *,
    content_budget: int = DEFAULT_CONTENT_BUDGET,
) -> list[TimelineSource]:
    """Return the default sources, in source-rank order.

    Args:
        db: The shared aiosqlite connection.
        casts: The cast store (sidecars for content search).
        content_budget: Sidecars read per page (``SEARCH_REGEX_MAX_CANDIDATES``).

    Returns:
        ``[SessionsSource, ApiCommandSource]``.
    """
    return [SessionsSource(db, casts, content_budget=content_budget), ApiCommandSource(db)]


async def run_timeline(
    sources: Sequence[TimelineSource],
    q: UnifiedQuery,
    kinds: Iterable[str],
    *,
    cursor: Cursor | None = None,
    limit: int,
    excluded: Mapping[str, str] | None = None,
) -> TimelinePage:
    """Query each selected source, merge (frontier rule), hydrate, build the cursor.

    1. The sources are those of ``kinds``, minus those marked ``done`` in the cursor.
    2. Each returns up to ``limit + 1`` items after its cursor position.
    3. **Bound:** a non-exhausted source's bound is its frontier key when its
       budget ran out, else the key of its last item.
    4. **Emit:** items merged by ``sort_key`` descending, kept only at or above
       every bound, first ``limit`` taken.
    5. **Next positions** (per source, *R* returned, *T* taken): *T* = *R* and
       exhausted → ``done``; *T* = *R* and budget hit → its frontier; *T* not
       empty → its last taken position; else unchanged.

    Args:
        sources: The available sources (:func:`build_sources`); matched by name.
        q: The query.
        kinds: Kinds to query, already resolved by ``web.kinds.resolve_kinds``.
        cursor: The decoded cursor, or ``None`` for the first page. Its ``sort``
            and ``kinds`` must equal ``q.sort`` and ``kinds``.
        limit: Page size (≥ 1).
        excluded: Excluded kind → reason, passed through to the result.

    Returns:
        The :class:`TimelinePage`.

    Raises:
        ValueError: If the cursor does not match the query, or a needed source is
            missing from ``sources``.
    """
    limit = max(1, int(limit))
    kind_set = frozenset(kinds)
    kinds_sorted = tuple(sorted(kind_set))
    if cursor is not None and (cursor.sort != q.sort or tuple(cursor.kinds) != kinds_sorted):
        raise ValueError("cursor does not match the query")
    positions: dict[str, Position | Literal["done"]] = (
        dict(cursor.positions) if cursor is not None else {}
    )
    by_name = {src.name: src for src in sources}
    wanted = sorted({KIND_SOURCE[k] for k in kind_set}, key=lambda n: SOURCE_RANK.get(n, 99))
    for name in wanted:
        if name not in by_name:
            raise ValueError("no source for a selected kind")

    pages: dict[str, SourcePage] = {}
    for name in wanted:
        after = positions.get(name)
        if after == POSITION_DONE:
            continue
        src_kinds = frozenset(k for k in kind_set if KIND_SOURCE[k] == name)
        pages[name] = await by_name[name].page(q, src_kinds, after, limit)  # type: ignore[arg-type]

    # 3. bounds
    bounds: list[SortKey] = []
    for page in pages.values():
        if page.exhausted:
            continue
        if page.frontier_key is not None:
            bounds.append(page.frontier_key)
        elif page.items:
            bounds.append(page.items[-1].sort_key)
    floor = max(bounds) if bounds else None

    # 4. emit
    merged = sorted(
        (it for page in pages.values() for it in page.items),
        key=lambda it: it.sort_key,
        reverse=True,
    )
    taken = [it for it in merged if floor is None or it.sort_key >= floor][:limit]

    # 5. next positions
    new_positions = dict(positions)
    frontier_used: set[str] = set()
    for name, page in pages.items():
        took = [it for it in taken if it.source == name]
        returned = page.items
        if len(took) == len(returned):
            if page.frontier is not None and not page.exhausted:
                new_positions[name] = page.frontier
                frontier_used.add(name)
            elif page.exhausted or not returned:
                new_positions[name] = POSITION_DONE
            else:
                new_positions[name] = took[-1].position
        elif took:
            new_positions[name] = took[-1].position
        # else: unchanged — its returned items were not reached.
    all_done = all(new_positions.get(name) == POSITION_DONE for name in wanted)
    next_cursor = (
        None
        if all_done
        else Cursor(sort=q.sort, kinds=kinds_sorted, positions=new_positions)
    )

    # hydrate only what is emitted
    hydrated: dict[int, TimelineItem | None] = {}
    for name in pages:
        mine = [(i, it) for i, it in enumerate(taken) if it.source == name]
        if not mine:
            continue
        result = await by_name[name].hydrate(q, [it for _, it in mine])
        for (i, _), h in zip(mine, result, strict=True):
            hydrated[i] = h
    items = [h for i in range(len(taken)) if (h := hydrated.get(i)) is not None]

    notices: frozenset[str] = frozenset().union(*(p.notices for p in pages.values()))
    budget_hit = len(taken) < limit and next_cursor is not None
    return TimelinePage(
        items=items,
        next_cursor=next_cursor,
        kinds=kinds_sorted,
        excluded=dict(excluded or {}),
        budget_hit=budget_hit,
        scan_budget_hit=budget_hit and SOURCE_API_COMMANDS in frontier_used,
        content_budget_hit=budget_hit and SOURCE_SESSIONS in frontier_used,
        flagged_cap_hit=NOTICE_FLAGGED_CAP in notices,
        focus_not_found=NOTICE_FOCUS_MISSING in notices,
        scan_budget=int(_API_SCAN_BUDGET),
        content_budget=next(
            (int(getattr(s, "content_budget", 0)) for s in sources if s.name == SOURCE_SESSIONS),
            0,
        ),
        flagged_cap=int(_FLAGGED_CMD_CAP),
    )
