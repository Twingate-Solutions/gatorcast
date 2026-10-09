"""Unified timeline: the search engine behind ``/search`` (Session 10, spec §6).

One interleaved, keyset-paged timeline over every event kind:

* the **sessions** source (:class:`SessionsSource`) serves the three ``sessions``
  table kinds — ``ssh``, ``exec`` and ``failed`` (spec §4.2, §6.2): queries Q1/Q2,
  the lazy budgeted content scan Q3, and findings hydration Q8;
* the **api_commands** source (:class:`ApiCommandSource`) serves ``kubectl``
  commands (spec §6.3): scan mode Q4/Q4b (with the two-arm ``user`` union),
  flagged mode Q5, the risk phases ``F``→``T``, hydration Q6a–c/Q7 through
  :func:`gatorcast.pipeline.activity.group_commands`, and focus Q9;
* the **web_conns** source is a second instance of the same class, parametrized by
  ``api_kind`` (WEBAPP_SPEC §8.1): one item per web connection, no discovery step,
  a text filter over the stored URL, the ``scheme``/``upstream`` TLS filters on the
  connection's start row, and the connection's ``gwops`` snapshot on hydration;
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
from functools import cache
from typing import Any, Final, Literal, Protocol

import aiosqlite

from gatorcast.db import FAILED_SQL, cmd_key, session_at
from gatorcast.logging import get_logger
from gatorcast.models import Session
from gatorcast.pipeline.activity import (
    MUTATING_METHODS,
    Command,
    group_commands,
    is_discovery,
    parse_requested_at,
    pick_label,
)
from gatorcast.pipeline.detect import SEVERITY_RANK
from gatorcast.store.activity import (
    _REQUEST_COLUMNS,
    ActivityStore,
    ApiFindingRow,
    ApiRequestRow,
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
KIND_WEB: Final = "web"
KIND_KEYS: Final[tuple[str, ...]] = (KIND_SSH, KIND_EXEC, KIND_FAILED, KIND_KUBECTL, KIND_WEB)

# --- timeline sources (spec §6.1, §6.4, WEBAPP_SPEC §8.1) -------------------------
# A source is one keyset-paged query family. ``sessions`` serves the three
# sessions-table kinds; ``api_commands`` serves kubectl commands; ``web_conns``
# serves web-app connections (one item per connection, WEBAPP_SPEC §8.2). The rank
# breaks merge ties (sessions, then api_commands, then web_conns).
# ``api_requests.api_kind`` holds the same two strings as ``KIND_KUBECTL`` /
# ``KIND_WEB``, so a kind key doubles as the stored discriminator.

SOURCE_SESSIONS: Final = "sessions"
SOURCE_API_COMMANDS: Final = "api_commands"
SOURCE_WEB: Final = "web_conns"
SOURCE_RANK: Final[Mapping[str, int]] = {
    SOURCE_SESSIONS: 0,
    SOURCE_API_COMMANDS: 1,
    SOURCE_WEB: 2,
}

KIND_SOURCE: Final[Mapping[str, str]] = {
    KIND_SSH: SOURCE_SESSIONS,
    KIND_EXEC: SOURCE_SESSIONS,
    KIND_FAILED: SOURCE_SESSIONS,
    KIND_KUBECTL: SOURCE_API_COMMANDS,
    KIND_WEB: SOURCE_WEB,
}

# Sources backed by ``api_requests`` (one :class:`ApiCommandSource` each).
API_SOURCES: Final[frozenset[str]] = frozenset({SOURCE_API_COMMANDS, SOURCE_WEB})

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


class CursorMismatch(ValueError):
    """A paging cursor is malformed or does not fit the search it is used with.

    Raised only by cursor validation: :func:`check_position` (a position of the wrong
    shape for its source and sort), ``gatorcast.web.params.decode_cursor``, and the
    cursor check at the top of :func:`run_timeline` (sort or kinds differ from the
    query). Callers turn exactly this into a ``400``; any other ``ValueError`` from
    the engine is an internal error and must propagate (``500``). Subclasses
    ``ValueError`` so existing ``except ValueError`` callers keep working. The
    message never contains the cursor value.
    """

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
        cmd: Focus on the command or web connection containing this ``request_id``.
        scheme: Stored ``downstream_tls`` value to match on a web connection's start
            row: ``'tls13'`` (``scheme=https``) or ``'none'`` (``scheme=http``).
            ``None`` = no value filter.
        scheme_null: True for ``scheme=unknown`` (``downstream_tls IS NULL``). When
            true, ``scheme`` is ignored; ``parse_unified_query`` leaves it ``None``.
        upstream: Stored ``upstream_tls`` value to match on the start row:
            ``'verify_full'`` (``verified``), ``'verify_ca'`` (``ca_only``),
            ``'insecure'`` (``unverified``) or ``'none'`` (``plaintext``).
            ``None`` = no value filter.
        upstream_null: True for ``upstream=unknown`` (``upstream_tls IS NULL``). When
            true, ``upstream`` is ignored.

    The TLS filters are stored values plus an is-null flag (WEBAPP_SPEC §8.3), so the
    store never sees the URL vocabulary. Each value is a bound parameter; the SQL text
    is a fixed fragment per column. Only the web source applies them; the kubectl
    source ignores them (``gatorcast.web.kinds`` excludes kubectl when they are set).
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
    scheme: str | None = None
    scheme_null: bool = False
    upstream: str | None = None
    upstream_null: bool = False


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
    web_conns     (as ``api_commands``: same shapes for each sort)
    ============  =========  =============================================

    ``at`` is ``YYYY-MM-DDTHH:MM:SS.mmmZ``; ``rank`` an int 0–4; ``duration`` a
    finite number ≥ 0; ``conn_id``/``request_id`` the classify safe-token patterns.
    Booleans are never accepted as numbers. ``api_commands`` and ``web_conns`` have
    no ``duration`` position (both kinds are excluded under that sort).

    Args:
        source: The source name (a key of :data:`SOURCE_RANK`).
        sort: The cursor's sort.
        value: The decoded JSON value (a list or tuple).

    Returns:
        The position as a tuple.

    Raises:
        CursorMismatch: If the source, sort, or shape is not valid. The message
            never contains the value.
    """
    if not isinstance(value, (list, tuple)):
        raise CursorMismatch("position is not a list")
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
    elif source in API_SOURCES:
        match sort, pos:
            case "newest", (phase, at, rid):
                ok = phase in (PHASE_SCAN, PHASE_FLAGGED) and _is_at(at) and _is_request_id(rid)
            case "risk", ("F", rank, at, rid):  # PHASE_FLAGGED (literal: a bare name would capture)
                ok = _is_rank(rank) and _is_at(at) and _is_request_id(rid)
            case "risk", ("T", at, rid):  # PHASE_SCAN
                ok = _is_at(at) and _is_request_id(rid)
    if not ok:
        raise CursorMismatch("position does not match its source and sort")
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
    """A hydrated kubectl command or web connection (Q6a–c, Q7).

    ``command`` is :func:`~gatorcast.pipeline.activity.group_commands` over the
    first :data:`_CMD_MAX_REQUESTS` requests (label, listed requests). Its
    ``primary`` is chosen over **every** row of the command
    (:meth:`ApiCommandSource._primary`), so it may lie past the listed requests.
    The aggregate fields cover every row of the command and override the
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
        kind: ``"kubectl"`` or ``"web"``. A web hit is one connection; its
            ``discovery_count`` is 0 and its primary request is the first
            ``POST``/``PUT``/``PATCH``/``DELETE``, else the first request.
        downstream_tls: Configured client-facing TLS mode on the start row
            (``tls13`` | ``none``), or ``None`` (unknown; always ``None`` for kubectl).
        upstream_tls: Configured app-facing TLS mode on the start row
            (``verify_full`` | ``verify_ca`` | ``insecure`` | ``none``), or ``None``.
        gwops_match: The connection's ``gwops`` match (``exact`` | ``none`` |
            ``ambiguous``), or ``None``. Web hits only. ``gwops_app`` and
            ``gwops_managed`` are stored only for ``exact``; show them only then.
        gwops_gateway_id: The reporting gateway id. Web hits only; never log it.
        gwops_app: The app name gwops reported (``exact`` only). Web hits only;
            display only, never log it.
        gwops_managed: ``True`` | ``False`` (``exact`` only), else ``None``.
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
    kind: str = KIND_KUBECTL
    downstream_tls: str | None = None
    upstream_tls: str | None = None
    gwops_match: str | None = None
    gwops_gateway_id: str | None = field(default=None, repr=False)
    gwops_app: str | None = field(default=None, repr=False)
    gwops_managed: bool | None = None

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
        """The listed requests to render (kubectl discovery hidden unless asked).

        A web hit has no discovery step (WEBAPP_SPEC §7.2), so every listed request
        is returned whatever ``include_discovery`` says.

        Args:
            include_discovery: True to include discovery requests (kubectl only).

        Returns:
            The listed :class:`~gatorcast.store.activity.ApiRequestRow` values.
        """
        if self.kind == KIND_WEB:
            return self.command.requests
        return self.command.visible_requests(include_discovery)


@dataclass(frozen=True, slots=True)
class TimelineItem:
    """One timeline item (spec §6.1).

    Attributes:
        kind: The kind key (``ssh`` / ``exec`` / ``failed`` / ``kubectl`` / ``web``).
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
        scan_budget_hit: ``budget_hit`` and a kubectl or web scan budget caused it.
        scan_budget_sources: The api sources (``api_commands`` / ``web_conns``) whose
            scan budget stopped them on this page; empty unless ``scan_budget_hit``.
            Lets the notice name the kind(s) actually cut short.
        content_budget_hit: ``budget_hit`` and the recording content budget caused it.
        flagged_cap_hit: More flagged kubectl commands match than the cap.
        focus_not_found: ``cmd=`` was given, an api source was queried, and no item
            survived hydration: the request is unknown to every queried api kind,
            or its rows vanished (retention) between resolving and hydrating it.
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
    scan_budget_sources: frozenset[str] = frozenset()
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


# ``api_kind`` as a SQL string literal. The value is chosen from this fixed map by the
# code that builds a query (a source's own kind), never from request input, so the
# fragment is static text (spec §10 "Parameters").
_API_KIND_SQL: Final[Mapping[str, str]] = {KIND_KUBECTL: "'kubectl'", KIND_WEB: "'web'"}


def _kind_sql(api_kind: str) -> str:
    """Return the SQL literal for an ``api_kind`` (``'kubectl'`` or ``'web'``).

    Args:
        api_kind: A key of :data:`_API_KIND_SQL`.

    Returns:
        The quoted literal.

    Raises:
        ValueError: If ``api_kind`` is not a known kind.
    """
    try:
        return _API_KIND_SQL[api_kind]
    except KeyError:
        raise ValueError("unknown api_kind") from None


def _same_cmd(q: str, x: str, x_key: str | None = None, api_kind: str = KIND_KUBECTL) -> str:
    """``SAME_CMD(q, x)``: row ``q`` belongs to the command identified by ``x``.

    Args:
        q: Alias of the probed ``api_requests`` row.
        x: Alias of the row (or CTE row) identifying the command.
        x_key: SQL for ``x``'s command key; default renders ``CMD_KEY_SQL`` over
            ``x``'s columns. Pass ``"<x>.ck"`` for a CTE that carries the key.
        api_kind: The kind the probe is restricted to.

    Returns:
        The SQL predicate (matches ``idx_api_req_cmd`` on ``q``).
    """
    key = x_key if x_key is not None else cmd_key(x)
    # Unary ``+`` keeps the planner off idx_api_req_sys_kind_user_time (two equality
    # columns look cheaper than one expression) so the probe uses idx_api_req_cmd. The
    # ``api_kind`` term carries the same ``+``: a plain equality flips the probe to a
    # scan of the kind's rows, while ``+`` leaves it a residual filter on the probed
    # row. A command key is single-kind, so the term never removes a row of a command.
    return (
        f"{cmd_key(q)} = {key} AND +{q}.resource_address IS {x}.resource_address "
        f"AND +{q}.user_key IS {x}.user_key AND +{q}.api_kind = {_kind_sql(api_kind)}"
    )


def _text_exists(x: str, x_key: str | None = None, api_kind: str = KIND_KUBECTL) -> str:
    """``EXISTS`` a request of ``x``'s command (or web connection) matching the text.

    kubectl: the lower-cased path (before ``?``) or ``kubectl_command`` contains the
    needle (2 params). web: the lower-cased stored ``url`` (normalized path plus
    masked query) contains the needle (1 param). Use :func:`_text_params` for the
    parameters.
    """
    same = _same_cmd("t", x, x_key, api_kind)
    if api_kind == KIND_WEB:
        return f"EXISTS (SELECT 1 FROM api_requests t WHERE {same} AND instr(lower(t.url), ?) > 0)"
    path = _PATH_LOWER.format(a="t")
    return (
        f"EXISTS (SELECT 1 FROM api_requests t WHERE {same} "
        f"AND (instr({path}, ?) > 0 OR instr(lower(COALESCE(t.kubectl_command, '')), ?) > 0))"
    )


def _text_params(needle: str, api_kind: str) -> tuple[str, ...]:
    """The bound parameters of :func:`_text_exists` for a lower-cased ``needle``."""
    return (needle,) if api_kind == KIND_WEB else (needle, needle)


def _tls_clauses(q: UnifiedQuery, alias: str) -> tuple[list[str], list[object]]:
    """The ``scheme`` / ``upstream`` predicates over a start row (web, spec §8.3).

    Args:
        q: The query (``scheme``, ``scheme_null``, ``upstream``, ``upstream_null``).
        alias: Alias of the start row (code-supplied, never input).

    Returns:
        ``(clauses, params)``: ``<alias>.<column> IS NULL`` for an is-null flag, else
        ``<alias>.<column> = ?`` with the stored value bound. Empty when neither
        filter is set.
    """
    clauses: list[str] = []
    params: list[object] = []
    for column, value, is_null in (
        ("downstream_tls", q.scheme, q.scheme_null),
        ("upstream_tls", q.upstream, q.upstream_null),
    ):
        if is_null:
            clauses.append(f"{alias}.{column} IS NULL")
        elif value is not None:
            clauses.append(f"{alias}.{column} = ?")
            params.append(value)
    return clauses, params


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
    "r.conn_id AS conn_id, r.kubectl_session AS kubectl_session, "
    "r.downstream_tls AS downstream_tls, r.upstream_tls AS upstream_tls"
)
# ``r.method`` is in no index, so Q4b cannot pick a covering full scan + sort over
# idx_api_req_cmd; it walks the same time index as Q4.
_FRONTIER_COLS = "r.requested_at AS requested_at, r.request_id AS request_id, r.method AS method"
_ORDER_R = "ORDER BY r.requested_at DESC, r.request_id DESC"
_API_RANK_F2 = _rank_case("f2.severity")


def _api_row_filters(
    q: UnifiedQuery, after: tuple[str, str] | None, api_kind: str
) -> tuple[list[str], list[object]]:
    """Row filters of a scan arm (kind, system, window, keyset), alias ``r``."""
    _kind_sql(api_kind)  # reject an unknown kind before it is bound
    clauses: list[str] = ["r.api_kind = ?"]
    params: list[object] = [api_kind]
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
    api_kind: str,
) -> tuple[str, list[object]]:
    """The ``api_requests`` walk in ``(requested_at, request_id)`` DESC order.

    Every arm is restricted to ``api_kind = ?`` (bound). Without ``user``: one range
    on ``idx_api_req_sys_kind_time`` / ``idx_api_req_kind_time``. With ``user``: a
    ``UNION`` of two keyset arms (``username = ?`` on ``idx_api_req_kind_user_time``,
    ``user_id = ?`` on ``idx_api_req_kind_userid_time``),
    each stopping at ``arm_limit``; ``UNION`` drops a row matched by both.

    Args:
        q: The query.
        after: ``(at, request_id)`` keyset, or ``None``.
        cols: Select list (aliased to bare names).
        arm_limit: Per-arm ``LIMIT`` (user union only).
        outer_limit: Final ``LIMIT``.
        api_kind: ``'kubectl'`` or ``'web'``.

    Returns:
        ``(sql, params)``.
    """
    base, base_params = _api_row_filters(q, after, api_kind)
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
    api_kind: str = KIND_KUBECTL,
    discovery: bool = True,
) -> tuple[str, list[object]]:
    """Build Q4: one page of command start rows, examining at most ``budget`` rows.

    The ``scanned`` CTE has a ``LIMIT`` and the outer query a ``WHERE``, so SQLite
    runs it as a co-routine (not flattened) and the budget is enforced.

    For web (``discovery=False``): no discovery condition (a web connection has no
    discovery step), the text filter reads the stored ``url``, and the ``scheme`` /
    ``upstream`` filters are residual predicates on the start row ``s`` (the
    ``scanned`` row that passed the earliest-row test), so the connection's single
    snapshot decides.

    Args:
        q: The query (``system``, ``user``, window, ``text``, ``discovery``, and for
            web ``scheme``/``upstream``).
        after: ``(at, request_id)`` keyset, or ``None``.
        want: Start rows wanted (``LIMIT``).
        budget: Rows examined at most (:data:`_API_SCAN_BUDGET`).
        no_findings: Add the command-has-no-finding clause (``has_findings=false``,
            risk phase ``T``).
        api_kind: ``'kubectl'`` (default) or ``'web'``.
        discovery: True (kubectl) to require a non-discovery request in the command
            unless ``q.discovery``; False (web) for no discovery condition.

    Returns:
        ``(sql, params)``. Columns: ``request_id, requested_at, resource_address,
        user_key, ck``.
    """
    scanned, params = _scan_rows_sql(
        q, after, cols=_SCAN_COLS, arm_limit=budget, outer_limit=budget, api_kind=api_kind
    )
    conds = [
        "NOT EXISTS (SELECT 1 FROM api_requests p WHERE "
        f"{_same_cmd('p', 's', None, api_kind)} AND p.requested_at <= s.requested_at "
        "AND (p.requested_at < s.requested_at OR p.request_id < s.request_id))"
    ]
    if discovery and not q.discovery:
        conds.append(
            f"EXISTS (SELECT 1 FROM api_requests d WHERE {_same_cmd('d', 's', None, api_kind)} "
            "AND gc_is_discovery(d.method, d.url) = 0)"
        )
    if q.text is not None:
        conds.append(_text_exists("s", None, api_kind))
        params.extend(_text_params(q.text.lower(), api_kind))
    if no_findings:
        conds.append(
            "NOT EXISTS (SELECT 1 FROM api_requests n JOIN api_findings nf "
            f"ON nf.request_id = n.request_id WHERE {_same_cmd('n', 's', None, api_kind)})"
        )
    if api_kind == KIND_WEB:
        tls_conds, tls_params = _tls_clauses(q, "s")
        conds.extend(tls_conds)
        params.extend(tls_params)
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
    q: UnifiedQuery,
    after: tuple[str, str] | None,
    *,
    budget: int,
    api_kind: str = KIND_KUBECTL,
) -> tuple[str, list[object]]:
    """Build Q4b: the rows at offsets ``budget - 1`` and ``budget`` of the Q4 walk.

    Two rows → the budget was hit, and the first is the frontier (the last row
    examined). One or none → the walk ended inside the budget (exhausted).

    Args:
        q: The query.
        after: The same keyset as Q4.
        budget: The Q4 budget.
        api_kind: The same kind as Q4.

    Returns:
        ``(sql, params)``. Columns: ``requested_at, request_id``.
    """
    # The walk is written exactly like Q4's ``scanned`` CTE (same shape, so the same
    # range index), limited to ``budget + 1`` rows; the outer query reads the two
    # edge rows from that co-routine without re-sorting.
    walk, params = _scan_rows_sql(
        q,
        after,
        cols=_FRONTIER_COLS,
        arm_limit=budget + 1,
        outer_limit=budget + 1,
        api_kind=api_kind,
    )
    sql = (
        f"WITH walk AS ({walk}) SELECT requested_at, request_id FROM walk "
        "ORDER BY requested_at DESC, request_id DESC LIMIT 2 OFFSET ?"
    )
    params.append(int(budget) - 1)
    return sql, params


def _hit_sql(q: UnifiedQuery, cap: int, api_kind: str) -> tuple[str, list[object]]:
    """The ``hit`` CTE body of Q5: distinct commands with a qualifying finding."""
    _kind_sql(api_kind)  # reject an unknown kind before it is bound
    clauses: list[str] = ["r.api_kind = ?"]
    params: list[object] = [api_kind]
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
        "FROM api_findings f CROSS JOIN api_requests r "
        f"ON r.request_id = f.request_id{where} "
        "LIMIT ?"
    )
    params.append(int(cap) + 1)
    return sql, params


def api_flagged_count_sql(
    q: UnifiedQuery, *, cap: int, api_kind: str = KIND_KUBECTL
) -> tuple[str, list[object]]:
    """Count the ``hit`` set of Q5 (at most ``cap + 1``), for the cap notice."""
    hit, params = _hit_sql(q, cap, api_kind)
    return f"SELECT COUNT(*) AS n FROM ({hit})", params


def api_flagged_sql(
    q: UnifiedQuery,
    after: tuple[Any, ...] | None,
    *,
    want: int,
    cap: int,
    risk: bool,
    any_finding: bool,
    api_kind: str = KIND_KUBECTL,
) -> tuple[str, list[object]]:
    """Build Q5: flagged commands found from ``api_findings`` (spec §6.3).

    For ``api_kind='web'`` the text filter reads the stored ``url`` and the
    ``scheme`` / ``upstream`` filters are residual predicates on the connection's
    start row, read by a primary-key join on ``c.start_id`` (added only when a TLS
    filter is set).

    Args:
        q: The query (finding filters, ``system``, ``user``, window, ``text``, and
            for web ``scheme``/``upstream``).
        after: Keyset ``(rank, at, id)`` (risk) or ``(at, id)`` (newest), or ``None``.
        want: ``LIMIT``.
        cap: :data:`_FLAGGED_CMD_CAP`; ``hit`` reads at most ``cap + 1`` commands.
        risk: Order by max rank first.
        any_finding: Risk phase ``F`` with no finding filter (``max_rank >= 1``).
        api_kind: ``'kubectl'`` (default) or ``'web'``.

    Returns:
        ``(sql, params)``. Columns: ``request_id, requested_at, resource_address,
        user_key, ck, max_rank, hit_n``.
    """
    hit, params = _hit_sql(q, cap, api_kind)
    same_h = _same_cmd("q", "h", "h.ck", api_kind)
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
        conds.append(_text_exists("c", "c.ck", api_kind))
        params.extend(_text_params(q.text.lower(), api_kind))
    start_join = ""
    if api_kind == KIND_WEB:
        tls_conds, tls_params = _tls_clauses(q, "sr")
        if tls_conds:
            start_join = " JOIN api_requests sr ON sr.request_id = c.start_id"
            conds.extend(tls_conds)
            params.extend(tls_params)
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
        f"FROM cmd c{start_join} WHERE {' AND '.join(conds)} {order} LIMIT ?"
    )
    params.append(int(want))
    return sql, params


# Per-kind focus (Q9) and hydration (Q6a-c, Q7) SQL. Every statement carries an
# ``api_kind`` term chosen from a fixed two-value map (:func:`_kind_sql`), never from
# input. The module-level ``FOCUS_*`` / ``CMD_*`` constants below are the kubectl set
# with their original binding shapes (``tests/test_query_plans.py`` binds them as
# ``(ck, resource_address, user_key)``); a web source builds its own set with ``_cmd_sql``.


@dataclass(frozen=True, slots=True)
class _CmdSql:
    """The focus and hydration statements of one ``api_kind``.

    ``resolve`` takes ``(request_id,)``; ``start``, ``aggregate``, ``findings``,
    ``recordings``, ``first_mutating`` and ``first_non_discovery`` take ``(ck,
    resource_address, user_key)``; ``requests`` takes the same plus a ``LIMIT``.

    ``first_mutating`` / ``first_non_discovery`` pick the primary request when it is
    not among the listed (``requests``) rows: each walks the command's rows on
    ``idx_api_req_cmd`` in ``(requested_at, request_id)`` order with the method /
    discovery test as a residual filter and stops at the first match (``LIMIT 1``).
    ``first_non_discovery`` is empty for a kind without discovery (web).
    """

    resolve: str
    start: str
    aggregate: str
    findings: str
    recordings: str
    requests: str
    first_mutating: str
    first_non_discovery: str


@cache
def _cmd_sql(api_kind: str, discovery: bool = True) -> _CmdSql:
    """Build the Q9 / Q6a–c / Q7 statements for ``api_kind``.

    Args:
        api_kind: ``'kubectl'`` or ``'web'``.
        discovery: True to count discovery requests in the aggregate
            (``gc_is_discovery``). False (web) reports ``discovery_count`` 0 without
            calling it.

    Returns:
        The statement set.
    """
    kind = _kind_sql(api_kind)
    # Unary ``+``: see _same_cmd (keeps these lookups on idx_api_req_cmd rather than
    # idx_api_req_sys_kind_user_time, with ``api_kind`` a residual filter on the row).
    same_key = (
        f"{cmd_key('q')} = ? AND +q.resource_address IS ? AND +q.user_key IS ? "
        f"AND +q.api_kind = {kind}"
    )
    discovery_sql = (
        "COALESCE(SUM(gc_is_discovery(q.method, q.url)), 0)" if discovery else "0"
    )
    # Static literal list from the code-defined MUTATING_METHODS (never input).
    mutating_sql = ", ".join(f"'{m}'" for m in sorted(MUTATING_METHODS))
    first_by = "ORDER BY q.requested_at, q.request_id LIMIT 1"
    return _CmdSql(
        resolve=(
            f"SELECT resource_address, user_key, {cmd_key()} AS ck "
            f"FROM api_requests WHERE request_id = ? AND api_kind = {kind}"
        ),
        start=(
            "SELECT q.request_id AS request_id, q.requested_at AS requested_at "
            f"FROM api_requests q WHERE {same_key} "
            "ORDER BY q.requested_at, q.request_id LIMIT 1"
        ),
        aggregate=(
            "SELECT COUNT(*) AS request_count, MIN(q.requested_at) AS first_at, "
            f"MAX(q.requested_at) AS last_at, {discovery_sql} AS discovery_count "
            f"FROM api_requests q WHERE {same_key}"
        ),
        findings=(  # rule metadata only
            "SELECT f.id AS id, f.request_id AS request_id, f.rule_id AS rule_id, "
            "f.category AS category, f.severity AS severity, f.label AS label, "
            "f.created_at AS created_at "
            "FROM api_requests q JOIN api_findings f ON f.request_id = q.request_id "
            f"WHERE {same_key} ORDER BY f.id"
        ),
        recordings=(  # request_id join only, never conn_id
            "SELECT q.request_id AS request_id, s.conn_id AS conn_id "
            "FROM api_requests q JOIN sessions s ON s.request_id = q.request_id "
            f"WHERE {same_key} ORDER BY COALESCE(s.started_at, s.created_at), s.conn_id"
        ),
        # ``gc_ds`` / ``gc_us``: the configured TLS modes; ``_row_to_request`` ignores
        # them, and the first row (the start row) supplies the hit's modes.
        requests=(
            f"SELECT {_REQUEST_COLUMNS}, q.downstream_tls AS gc_ds, q.upstream_tls AS gc_us "
            f"FROM api_requests q WHERE {same_key} "
            "ORDER BY q.requested_at, q.request_id LIMIT ?"
        ),
        first_mutating=(
            f"SELECT {_REQUEST_COLUMNS} FROM api_requests q WHERE {same_key} "
            f"AND upper(q.method) IN ({mutating_sql}) {first_by}"
        ),
        first_non_discovery=(
            f"SELECT {_REQUEST_COLUMNS} FROM api_requests q WHERE {same_key} "
            f"AND gc_is_discovery(q.method, q.url) = 0 {first_by}"
            if discovery
            else ""
        ),
    )


_KUBECTL_SQL: Final = _cmd_sql(KIND_KUBECTL, True)

# Q9 focus: resolve any request of a command to the command, then its start row.
FOCUS_RESOLVE_SQL: Final = _KUBECTL_SQL.resolve
FOCUS_START_SQL: Final = _KUBECTL_SQL.start
# Hydration, per command; params ``(ck, resource_address, user_key)``.
CMD_AGGREGATE_SQL: Final = _KUBECTL_SQL.aggregate  # Q6a
CMD_FINDINGS_SQL: Final = _KUBECTL_SQL.findings  # Q6b
CMD_RECORDINGS_SQL: Final = _KUBECTL_SQL.recordings  # Q6c
CMD_REQUESTS_SQL: Final = _KUBECTL_SQL.requests  # Q7 (params + LIMIT)


def _max_severity(severities: Iterable[str]) -> str | None:
    """Return the highest-ranked known severity, or ``None``."""
    best: str | None = None
    for sev in severities:
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(best or "", 0):
            best = sev
    return best


class ApiCommandSource:
    """An ``api_requests``-backed timeline source (spec §6.3, WEBAPP_SPEC §8.1).

    One class, two instances (:func:`build_sources`): kubectl commands
    (``api_commands``, ``api_kind='kubectl'``, discovery logic on) and web
    connections (``web_conns``, ``api_kind='web'``, discovery off). Every query the
    instance runs is restricted to its ``api_kind``.
    """

    name: str = SOURCE_API_COMMANDS

    def __init__(
        self,
        db: aiosqlite.Connection,
        *,
        api_kind: str = KIND_KUBECTL,
        name: str = SOURCE_API_COMMANDS,
        kind: str | None = None,
        discovery: bool = True,
        findings: bool = True,
    ) -> None:
        """Initialize the source.

        Args:
            db: The shared aiosqlite connection (``gc_is_discovery`` registered).
            api_kind: The ``api_requests.api_kind`` this instance serves
                (``'kubectl'`` or ``'web'``).
            name: The source name (a key of :data:`SOURCE_RANK`).
            kind: The timeline kind of its items; defaults to ``api_kind``.
            discovery: True to apply the kubectl discovery logic (hide discovery-only
                commands, count discovery requests); False for web.
            findings: True when this kind can have ``api_findings`` rows. False (web)
                makes flagged mode (Q5 and its count) return an empty, exhausted page
                without running SQL.

        Raises:
            ValueError: If ``api_kind`` or ``name`` is unknown.
        """
        _kind_sql(api_kind)
        if name not in API_SOURCES:
            raise ValueError("unknown source name")
        self._db = db
        self._api_kind = api_kind
        self._kind = kind if kind is not None else api_kind
        self._discovery = discovery
        self._findings = findings
        self._cmd = _cmd_sql(api_kind, discovery)
        self.name = name

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
            kinds: The selected kinds (must include this source's kind).
            after: Keyset position, or ``None`` for the top.
            limit: Page size.

        Returns:
            The :class:`SourcePage`.
        """
        if self._kind not in kinds:
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
        sql, params = api_scan_sql(
            q,
            after,
            want=want,
            budget=budget,
            no_findings=no_findings,
            api_kind=self._api_kind,
            discovery=self._discovery,
        )
        rows = await self._all(sql, params)
        items = [self._item(row, PHASE_SCAN, 0, risk) for row in rows]
        if len(items) >= want:
            return SourcePage(items=items, exhausted=False)
        sql, params = api_scan_frontier_sql(q, after, budget=budget, api_kind=self._api_kind)
        edge = await self._all(sql, params)
        if len(edge) < 2:
            return SourcePage(items=items, exhausted=True)
        at, rid = edge[0]["requested_at"], edge[0]["request_id"]
        rank_src = SOURCE_RANK[self.name]
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
        if not self._findings:
            # Web has no detection rules (every built-in ApiRule is KUBERNETES-only and
            # ``detect_api`` skips other resource types), so no web request has an
            # ``api_findings`` row and Q5 could only return nothing. Q5 already binds
            # ``r.api_kind = ?`` (``_hit_sql``), but its ``hit`` CTE drives from
            # ``api_findings``: every finding row (all kubectl today) is joined to its
            # request before the kind test discards it, so running Q5 for web would
            # cost a pass over all findings for no result (spec §10 "Bounded work").
            # Enabling a future web rule needs ``findings=True`` for the web source in
            # ``build_sources`` plus a query-plan check of Q5 under ``api_kind='web'``.
            return SourcePage(items=[], exhausted=True)
        cap = max(1, int(_FLAGGED_CMD_CAP))
        sql, params = api_flagged_sql(
            q,
            after,
            want=limit + 1,
            cap=cap,
            risk=risk,
            any_finding=any_finding,
            api_kind=self._api_kind,
        )
        rows = await self._all(sql, params)
        if rows:
            hit_n = int(rows[0]["hit_n"])
        else:
            sql, params = api_flagged_count_sql(q, cap=cap, api_kind=self._api_kind)
            hit_n = int((await self._all(sql, params))[0]["n"])
        items = [self._item(row, PHASE_FLAGGED, int(row["max_rank"]), risk) for row in rows]
        notices = frozenset({NOTICE_FLAGGED_CAP}) if hit_n > cap else frozenset()
        return SourcePage(items=items, exhausted=len(items) <= limit, notices=notices)

    async def _focus(self, q: UnifiedQuery, after: Position | None) -> SourcePage:
        """Focus (Q9): the one command containing ``q.cmd``; other filters ignored."""
        if after is not None:
            return SourcePage(items=[], exhausted=True)
        rows = await self._all(self._cmd.resolve, (q.cmd,))
        if not rows:
            return SourcePage(
                items=[], exhausted=True, notices=frozenset({NOTICE_FOCUS_MISSING})
            )
        ident = rows[0]
        key_params = (ident["ck"], ident["resource_address"], ident["user_key"])
        start = await self._all(self._cmd.start, key_params)
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
        rank_src = SOURCE_RANK[self.name]
        key: SortKey
        if q.sort == SORT_RISK:
            key = (0, ref.requested_at, rank_src, ref.request_id)
        elif q.sort == SORT_DURATION:
            key = (0, 0.0, rank_src, ref.request_id)
        else:
            key = (ref.requested_at, rank_src, ref.request_id)
        item = TimelineItem(
            kind=self._kind,
            source=self.name,
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

        A web instance then reads the ``gwops`` snapshot of every hydrated
        connection with one primary-key ``IN (...)`` read
        (:meth:`~gatorcast.store.activity.ActivityStore.gwops_for_connections`),
        bounded by the page size.

        Args:
            q: The query (unused; part of the source contract).
            items: Unhydrated command items.

        Returns:
            Items with :class:`CommandHit` data, aligned; ``None`` for a command
            whose rows vanished (retention) between paging and hydration.
        """
        hits: list[CommandHit | None] = []
        for it in items:
            ref = it.data
            assert isinstance(ref, CommandRef)
            hits.append(await self._hydrate_one(ref))
        if self._kind == KIND_WEB:
            hits = await self._attach_gwops(hits)
        return [
            replace(it, data=hit) if hit is not None else None
            for it, hit in zip(items, hits, strict=True)
        ]

    async def _attach_gwops(self, hits: list[CommandHit | None]) -> list[CommandHit | None]:
        """Fill the ``gwops_*`` fields of web hits from ``connections`` (one read)."""
        conn_ids = [h.conn_id for h in hits if h is not None]
        if not conn_ids:
            return hits
        snapshots = await ActivityStore(self._db).gwops_for_connections(conn_ids)
        out: list[CommandHit | None] = []
        for hit in hits:
            snap = snapshots.get(hit.conn_id) if hit is not None else None
            if hit is None or snap is None:
                out.append(hit)
                continue
            out.append(
                replace(
                    hit,
                    gwops_match=snap.gwops_match,
                    gwops_gateway_id=snap.gwops_gateway_id,
                    gwops_app=snap.gwops_app,
                    gwops_managed=snap.gwops_managed,
                )
            )
        return out

    async def _hydrate_one(self, ref: CommandRef) -> CommandHit | None:
        """Load one command's display data (spec §6.3 "Hydration")."""
        key = (ref.ck, ref.resource_address, ref.user_key)
        raw = await self._all(self._cmd.requests, (*key, max(1, int(_CMD_MAX_REQUESTS))))
        if not raw:
            return None
        rows = [_row_to_request(r) for r in raw]
        # The first row is the start row (ordered by requested_at, request_id).
        downstream_tls: str | None = raw[0]["gc_ds"]
        upstream_tls: str | None = raw[0]["gc_us"]
        agg = (await self._all(self._cmd.aggregate, key))[0]
        findings: dict[str, list[ApiFindingRow]] = {}
        for row in await self._all(self._cmd.findings, key):
            finding = _row_to_finding(row)
            findings.setdefault(finding.request_id, []).append(finding)
        recordings: dict[str, str] = {}
        recording_order: list[str] = []
        for row in await self._all(self._cmd.recordings, key):
            recordings.setdefault(row["request_id"], row["conn_id"])
            recording_order.append(row["conn_id"])
        command = group_commands(rows, recordings, findings=findings)[0]
        request_count = int(agg["request_count"])
        primary = await self._primary(key, rows, truncated=request_count > len(rows))
        if not self._discovery:
            # No discovery step (WEBAPP_SPEC §7.2): nothing counts as discovery.
            command = replace(
                command, primary=primary, label=pick_label(primary, rows), discovery_count=0
            )
        elif primary.request_id != command.primary.request_id:
            command = replace(command, primary=primary, label=pick_label(primary, rows))
        all_findings = sorted(
            (f for fs in findings.values() for f in fs), key=lambda f: f.id
        )
        return CommandHit(
            ref=ref,
            command=command,
            request_count=request_count,
            discovery_count=int(agg["discovery_count"]),
            started_at=agg["first_at"],
            ended_at=agg["last_at"],
            finding_count=len(all_findings),
            max_severity=_max_severity(f.severity for f in all_findings),
            finding_labels=tuple(dict.fromkeys(f.label for f in all_findings)),
            findings=findings,
            recordings=tuple(dict.fromkeys(recording_order)),
            kind=self._kind,
            downstream_tls=downstream_tls,
            upstream_tls=upstream_tls,
        )

    async def _primary(
        self,
        key: tuple[str, str | None, str | None],
        rows: Sequence[ApiRequestRow],
        *,
        truncated: bool,
    ) -> ApiRequestRow:
        """Pick the primary request over **every** row of the command, not only the listed.

        Rules (kubectl spec §7; WEBAPP_SPEC §8.1): kubectl — the first mutating
        (``POST``/``PUT``/``PATCH``/``DELETE``) request, else the first non-discovery
        request, else the first request (a mutating request is never discovery, which
        requires ``GET``). Web — the first mutating request, else the first request.

        ``rows`` are the first :data:`_CMD_MAX_REQUESTS` rows in order, so a match
        among them is the first overall and needs no query. Only when the list is
        ``truncated`` and holds no match does a bounded ``LIMIT 1`` query on
        ``idx_api_req_cmd`` look past it (``first_mutating``, then for kubectl
        ``first_non_discovery``). A primary found that way is not among the listed
        requests.

        Args:
            key: ``(ck, resource_address, user_key)``.
            rows: The listed requests (non-empty), ``(requested_at, request_id)`` order.
            truncated: True when the command has more rows than ``rows``.

        Returns:
            The primary request row.
        """
        mutating = next((r for r in rows if r.method.upper() in MUTATING_METHODS), None)
        if mutating is not None:
            return mutating
        if truncated:
            found = await self._all(self._cmd.first_mutating, key)
            if found:
                return _row_to_request(found[0])
        if not self._discovery:
            return rows[0]
        listed = next((r for r in rows if not is_discovery(r.method, r.url)), None)
        if listed is not None:
            return listed
        if truncated:
            found = await self._all(self._cmd.first_non_discovery, key)
            if found:
                return _row_to_request(found[0])
        return rows[0]

    def _item(self, row: aiosqlite.Row, phase: str, rank: int, risk: bool) -> TimelineItem:
        """Map a Q4/Q5 row to an unhydrated item of this source."""
        return _command_item(row, phase, rank, risk, kind=self._kind, source=self.name)


def _tail(after: Position | None) -> tuple[Any, ...] | None:
    """Strip the phase tag from an ``api_commands`` position."""
    return None if after is None else tuple(after[1:])


def _command_item(
    row: aiosqlite.Row, phase: str, rank: int, risk: bool, *, kind: str, source: str
) -> TimelineItem:
    """Map a Q4/Q5 row to an unhydrated command (or web connection) item."""
    ref = CommandRef(
        request_id=row["request_id"],
        requested_at=row["requested_at"],
        resource_address=row["resource_address"],
        user_key=row["user_key"],
        ck=row["ck"],
        rank=rank,
    )
    rank_src = SOURCE_RANK[source]
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
        kind=kind,
        source=source,
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
    kinds: Iterable[str] | None = None,
) -> list[TimelineSource]:
    """Return the sources for the wanted kinds, in source-rank order.

    Args:
        db: The shared aiosqlite connection.
        casts: The cast store (sidecars for content search).
        content_budget: Sidecars read per page (``SEARCH_REGEX_MAX_CANDIDATES``).
        kinds: The kinds the caller will query, or ``None`` for every kind. A source
            is built only when one of its kinds is wanted.

    Returns:
        Up to ``[SessionsSource, ApiCommandSource (kubectl, api_commands),
        ApiCommandSource (web, web_conns)]``.
    """
    wanted = frozenset(KIND_KEYS if kinds is None else kinds)
    sources: list[TimelineSource] = []
    if wanted & {KIND_SSH, KIND_EXEC, KIND_FAILED}:
        sources.append(SessionsSource(db, casts, content_budget=content_budget))
    if KIND_KUBECTL in wanted:
        sources.append(
            ApiCommandSource(
                db,
                api_kind=KIND_KUBECTL,
                name=SOURCE_API_COMMANDS,
                kind=KIND_KUBECTL,
                discovery=True,
            )
        )
    if KIND_WEB in wanted:
        sources.append(
            ApiCommandSource(
                db,
                api_kind=KIND_WEB,
                name=SOURCE_WEB,
                kind=KIND_WEB,
                discovery=False,
                findings=False,
            )
        )
    return sources


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
        CursorMismatch: If the cursor's sort or kinds do not match the query.
        ValueError: If a needed source is missing from ``sources`` (an internal
            error, deliberately not a :class:`CursorMismatch`).
    """
    limit = max(1, int(limit))
    kind_set = frozenset(kinds)
    kinds_sorted = tuple(sorted(kind_set))
    if cursor is not None and (cursor.sort != q.sort or tuple(cursor.kinds) != kinds_sorted):
        raise CursorMismatch("cursor does not match the query")
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
    # A focus (``cmd``) is missing when no api source found the request (the kubectl
    # and web sources each look it up under their own ``api_kind``), or when one
    # resolved it but its rows vanished (retention) before hydration. ``focus_found``
    # is therefore read from the hydrated items, not from the source pages.
    focus_found = any(isinstance(it.data, CommandHit) for it in items)
    focus_resolved = any(p.items for name, p in pages.items() if name in API_SOURCES)
    focus_not_found = (
        q.cmd is not None
        and (NOTICE_FOCUS_MISSING in notices or focus_resolved)
        and not focus_found
    )
    budget_hit = len(taken) < limit and next_cursor is not None
    scan_sources = frozenset(frontier_used & API_SOURCES) if budget_hit else frozenset()
    return TimelinePage(
        items=items,
        next_cursor=next_cursor,
        kinds=kinds_sorted,
        excluded=dict(excluded or {}),
        budget_hit=budget_hit,
        scan_budget_hit=bool(scan_sources),
        scan_budget_sources=scan_sources,
        content_budget_hit=budget_hit and SOURCE_SESSIONS in frontier_used,
        flagged_cap_hit=NOTICE_FLAGGED_CAP in notices,
        focus_not_found=focus_not_found,
        scan_budget=int(_API_SCAN_BUDGET),
        content_budget=next(
            (int(getattr(s, "content_budget", 0)) for s in sources if s.name == SOURCE_SESSIONS),
            0,
        ),
        flagged_cap=int(_FLAGGED_CMD_CAP),
    )


# =================================================================================
# Row-level configured TLS (WEBAPP_SPEC §8.4, §8.5)
# =================================================================================

_TLS_CHUNK = 500
"""Request ids per primary-key ``IN (...)`` read in :func:`request_tls_modes`."""


async def request_tls_modes(
    db: aiosqlite.Connection, request_ids: Iterable[str]
) -> dict[str, tuple[str | None, str | None]]:
    """Read the configured TLS modes stored on each of a set of ``api_requests`` rows.

    The row-level ``downstream_tls`` / ``upstream_tls`` are what the ``scheme`` /
    ``upstream`` search filters test, so the visit view and the "Configured web app
    TLS" block prefer them over the connection snapshot. ``ApiRequestRow`` does not
    carry the two columns, so they are read here: primary-key lookups, at most
    :data:`_TLS_CHUNK` ids per query, duplicates ignored. Values are returned as
    stored (never logged).

    Args:
        db: The shared aiosqlite connection.
        request_ids: The ``request_id`` values to look up.

    Returns:
        ``request_id → (downstream_tls, upstream_tls)`` for every id that has a row.
    """
    ids = list(dict.fromkeys(request_ids))
    result: dict[str, tuple[str | None, str | None]] = {}
    for start in range(0, len(ids), _TLS_CHUNK):
        chunk = ids[start : start + _TLS_CHUNK]
        cursor = await db.execute(
            "SELECT request_id, downstream_tls, upstream_tls FROM api_requests "
            f"WHERE request_id IN ({_placeholders(len(chunk))})",
            chunk,
        )
        rows = await cursor.fetchall()
        await cursor.close()
        for row in rows:
            result[row["request_id"]] = (row["downstream_tls"], row["upstream_tls"])
    return result
