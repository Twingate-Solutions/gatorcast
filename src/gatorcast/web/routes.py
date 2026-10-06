"""Web UI routes: systems → sessions → replay, plus the cast byte stream.

Every route here is gated behind :func:`gatorcast.web.auth.require_ui_auth` because the
UI exposes secret-grade recordings (CLAUDE.md rule 5). Recording *content* is never
rendered as HTML — the templates show metadata only, and the ``.cast`` bytes are
served solely for the vendored asciinema player to consume (CLAUDE.md rule 6).

The repository and cast store are read from ``app.state`` (wired in ``gatorcast.main``).
The cast route resolves paths strictly inside ``casts_dir`` as defense in depth,
even though ``conn_id`` is already validated upstream in ``classify`` (rule 5/9).

kubectl activity (kubectl activity spec §9): the system page adds a per-user
activity-session table computed on view from ``ActivityStore`` rows, and
``/systems/{slug}/activity`` renders one activity session's commands with their
exec/attach recording links (joined by ``request_id``). Only allowlisted stored
columns reach the templates, every URL renders autoescaped (never ``|safe``), and
the ``user``/``from``/``to``/``activity_before``/``discovery`` query params are
validated strictly (400 on bad input) and used only as bound SQL parameters.

Unified search (Session 10, spec §8.3): ``/search`` parses its query with
``web.params.parse_unified_query`` and pages ``store.timeline.run_timeline`` over
recordings (ssh / exec / failed) and kubectl commands. Rows are built here as plain
dicts from allowlisted columns; templates never receive raw request rows (so never
``user_agent``). ``/search/export.csv`` uses the same parser and engine, walking
pages into a 15-column CSV (spec §9).

Dashboard (Session 10, spec §8.2): every tile, chip, and top-user link is built
with ``search_url`` and carries an explicit ``type`` and the selected ``window``,
so each figure (except the "kubectl API requests" request total) equals the item
count of the search it links to. The recent-activity feed is one
``run_timeline`` page (any kind, newest first, discovery-only commands hidden,
all time) rendered with the shared ``_rows.html`` macros in compact form.

Systems list and cross-links (Session 10, spec §8.4, §8.5): ``/systems`` shows Type
badges, "Last session" / "Last API request", and count links into search; the
system, activity, and session pages link usernames to ``/search?user=…`` and the
session page links an exec recording to its kubectl command (``/search?cmd=…``).
Every ``/search`` URL is built by ``search_url``; templates never build one.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from gatorcast.logging import get_logger
from gatorcast.models import Session
from gatorcast.pipeline.activity import (
    ActivitySession,
    Command,
    group_activity,
    group_commands,
    is_discovery,
)
from gatorcast.pipeline.detect import SEVERITY_RANK, load_rules
from gatorcast.store.activity import (
    ActivityStore,
    ApiFindingRow,
    ApiRequestRow,
    to_requested_at_format,
)
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import SessionRepository, SystemSummary
from gatorcast.store.timeline import (
    KIND_EXEC,
    KIND_FAILED,
    KIND_KUBECTL,
    CommandHit,
    Cursor,
    RecordingHit,
    TimelinePage,
    UnifiedQuery,
    build_sources,
    run_timeline,
)
from gatorcast.web.auth import require_ui_auth
from gatorcast.web.kinds import (
    EXCLUSION_LABELS,
    KINDS,
    TYPE_GROUPS,
    TYPE_LABELS,
    resolve_kinds,
)
from gatorcast.web.params import (
    MAX_PAGE_SIZE,
    STATUS_VALUES,
    UNKNOWN_SYSTEM,
    WINDOW_VALUES,
    ParsedSearch,
    _bad_request,
    _has_control_chars,
    _parse_discovery_param,
    _parse_time_param,
    _single_param,
    encode_cursor,
    parse_unified_query,
    search_url,
)

log = get_logger(__name__)

# Templates live alongside this module under ./templates. autoescape is on by
# default for .html via Jinja2Templates (rule 6 — metadata is always escaped).
_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# Sentinel path segment representing the NULL/unknown resource_address bucket.
# resource_address values are real host addresses and never collide with this.
_UNKNOWN_SLUG = "_unknown"
_UNKNOWN_LABEL = "(unknown)"

# Asciicast media type served to the player for the .cast byte stream.
_CAST_MEDIA_TYPE = "application/x-asciicast"

# Severity options offered in the search form's severity <select>, highest first.
# Derived from SEVERITY_RANK so the UI stays in sync with the detector.
_SEVERITY_OPTIONS = [name for name, _ in sorted(SEVERITY_RANK.items(), key=lambda kv: -kv[1])]

# Sort options offered in the search form (value, label).
_SORT_OPTIONS = [
    ("newest", "Newest first"),
    ("duration", "Longest first"),
    ("risk", "Highest risk first"),
]

# Upper bound on items in one CSV export (spec §9). The export walks timeline pages
# until this many items are written; reaching it sets ``X-Gatorcast-Truncated``.
_CSV_EXPORT_CAP = 10000

# Dashboard time-window options (query value, label). Findings/counts and the
# drill-down links are scoped to the selected window; "all" disables the cutoff.
# The values are exactly search's ``window`` values, so a link carries the same one.
_WINDOW_OPTIONS: list[tuple[str, str]] = [
    ("7", "Last 7 days"),
    ("30", "Last 30 days"),
    ("90", "Last 90 days"),
    ("all", "All time"),
]
assert tuple(v for v, _ in _WINDOW_OPTIONS) == WINDOW_VALUES, "dashboard windows = search windows"
_DEFAULT_WINDOW = "30"

# Items in the dashboard's recent-activity feed (spec §8.2, Q11).
_FEED_LIMIT = 15

# Severity badge order (highest first) for dashboard rendering.
_SEVERITY_DISPLAY_ORDER = ["critical", "high", "medium", "low"]

# kubectl activity (spec §8/§9). Route-module constants, not settings: the system
# page shows one window of this span at a time (paged by ``activity_before``), and
# both activity reads are bounded by the row cap. Hitting the cap shows a notice.
_ACTIVITY_PAGE_SPAN = timedelta(days=7)
_ACTIVITY_MAX_ROWS = 20000

# ``user`` query value that selects the NULL user_key bucket (requests that carried
# neither a user id nor a username). Mirrors ``_UNKNOWN_SLUG`` for systems.
_UNKNOWN_USER = "_unknown"

# Upper bound on a ``user`` query value. Real user keys are a Twingate user id or a
# username (email); anything longer is rejected rather than queried.
_MAX_USER_KEY_LEN = 512


def _window_cutoff(window: str, now: datetime) -> str | None:
    """Return the dashboard cutoff for a window value, or ``None`` for all time.

    Computed exactly as search computes ``window`` (``now - N days``, normalized to
    ``YYYY-MM-DDTHH:MM:SS.mmmZ``), so a figure and its linked list use the same
    lower bound up to the moment each request is served.

    Args:
        window: One of :data:`WINDOW_VALUES` (``"7"``/``"30"``/``"90"``/``"all"``).
        now: The current UTC time.

    Returns:
        The normalized cutoff, or ``None`` when the window is ``"all"``.
    """
    if window == "all":
        return None
    return to_requested_at_format(now - timedelta(days=int(window)))


router = APIRouter(dependencies=[Depends(require_ui_auth)])


class SystemBadge(BaseModel):
    """One Type badge on the systems index (fixed label and CSS class, never stored text)."""

    label: str
    css_class: str


# Type badges (spec §7.5, §8.4), in display order. A future web-app kind adds a
# ``Web`` badge here (spec §13).
_SSH_BADGE = SystemBadge(label="SSH", css_class="pill-ssh")
_KUBERNETES_BADGE = SystemBadge(label="Kubernetes", css_class="pill-kubectl")


class SystemView(BaseModel):
    """Presentation wrapper for one system row on the systems index.

    ``sessions_url`` lists the system's recordings and failed connections
    (``type=recordings``, matching ``session_count``); ``api_url`` lists its kubectl
    commands (``type=kubectl``). Both are built with :func:`search_url`.
    """

    summary: SystemSummary
    label: str
    address_slug: str
    badges: list[SystemBadge]
    sessions_url: str
    api_url: str


def _system_label(resource_address: str | None) -> str:
    """Return the display label for a system, mapping NULL to the unknown bucket."""
    return resource_address if resource_address else _UNKNOWN_LABEL


def _search_system(resource_address: str | None) -> str:
    """Return the ``/search`` ``system`` value for a system (NULL → the unknown sentinel)."""
    return resource_address if resource_address else UNKNOWN_SYSTEM


def _system_badges(summary: SystemSummary) -> list[SystemBadge]:
    """Return a system's Type badges (spec §7.5).

    ``SSH`` when it has an SSH recording (``ssh_count > 0``, which requires recording
    data); ``Kubernetes`` when it has exec recordings or API requests. A system with
    only start-only ``error`` rows gets none.
    """
    badges: list[SystemBadge] = []
    if summary.has_ssh:
        badges.append(_SSH_BADGE)
    if summary.has_kubernetes:
        badges.append(_KUBERNETES_BADGE)
    return badges


def _user_search_url(username: str | None, user_key: str | None = None) -> str | None:
    """Return ``/search?user=…`` for a user: the username, else the user key.

    The search ``user`` filter matches ``username`` or an exact ``user_id``, and a
    ``user_key`` is the user id else the username, so either value finds the user's
    activity (spec §8.1). Returns ``None`` for the NULL-user bucket (no link).
    """
    value = username or user_key
    return search_url(user=value) if value else None


def _system_slug(resource_address: str | None) -> str:
    """Return the URL path segment for a system.

    The NULL bucket maps to a fixed sentinel; real addresses are percent-encoded
    (``safe=""`` so dots and slashes in the address survive a round trip).

    Args:
        resource_address: The target system address, or ``None`` for the unknown
            bucket.

    Returns:
        A URL-safe path segment.
    """
    if not resource_address:
        return _UNKNOWN_SLUG
    return quote(resource_address, safe="")


def _slug_to_address(slug: str) -> str | None:
    """Reverse :func:`_system_slug`: a path segment back to a resource_address.

    Args:
        slug: The raw path segment from the URL.

    Returns:
        The decoded resource_address, or ``None`` for the unknown bucket.
    """
    if slug == _UNKNOWN_SLUG:
        return None
    return unquote(slug)


def _duration_display(duration_seconds: float | None) -> str:
    """Format a duration in seconds as ``M:SS`` (or ``H:MM:SS``), or a dash."""
    if duration_seconds is None:
        return "—"
    total = int(duration_seconds)
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{seconds:02d}"
    return f"{minutes}:{seconds:02d}"


def _session_view(session: Session) -> dict[str, object]:
    """Build the template context for a session row/detail.

    Wraps the model with a precomputed ``duration_display`` and exposes the model
    fields the templates read, plus ``user_url`` (``/search?user=<username>``, or
    ``None`` when no username is known — ``sessions`` holds no user id). Recording
    content is never included.
    """
    return {
        "conn_id": session.conn_id,
        "username": session.username,
        "user_url": _user_search_url(session.username),
        "resource_address": session.resource_address,
        "shell_user": session.shell_user,
        "started_at": session.started_at,
        "ended_at": session.ended_at,
        "duration_seconds": session.duration_seconds,
        "duration_display": _duration_display(session.duration_seconds),
        "width": session.width,
        "height": session.height,
        "status": session.status,
        "cast_path": session.cast_path,
        "finding_count": session.finding_count,
        "max_severity": session.max_severity,
    }


def _get_repo(request: Request) -> SessionRepository:
    """Return the session repository from application state."""
    return request.app.state.repo


def _get_casts(request: Request) -> CastStore:
    """Return the cast store from application state."""
    return request.app.state.casts


def _get_search(request: Request) -> SearchStore:
    """Return the search store from application state."""
    return request.app.state.search


def _get_activity(request: Request) -> ActivityStore:
    """Return the kubectl activity store from application state."""
    return request.app.state.activity


# --- kubectl activity: strict query-param validation -------------------------------
# The generic helpers (_bad_request, _single_param, _has_control_chars,
# _parse_time_param, _parse_discovery_param) live in gatorcast.web.params.


def _parse_user_param(raw: str | None) -> str | None:
    """Validate the ``user`` query parameter (an activity session's ``user_key``).

    Args:
        raw: The raw query value.

    Returns:
        The user key, or ``None`` for the unknown-user sentinel (NULL bucket).

    Raises:
        HTTPException: ``400`` if absent, blank, over-long, or containing control
            characters.
    """
    if raw is None or raw == "":
        raise _bad_request("'user' is required")
    if len(raw) > _MAX_USER_KEY_LEN or _has_control_chars(raw):
        raise _bad_request("'user' is not a valid user key")
    if raw == _UNKNOWN_USER:
        return None
    return raw


# --- kubectl activity: presentation ------------------------------------------------


def _user_param(user_key: str | None) -> str:
    """Return the ``user`` query value for a user key (NULL → unknown sentinel)."""
    return user_key if user_key is not None else _UNKNOWN_USER


def _user_label(username: str | None, user_key: str | None) -> str:
    """Return the display label for an activity session's user.

    Identity is the envelope ``user.username`` (rule 4); the user key (Gateway user
    id) is the fallback when no username was recorded.
    """
    return username or user_key or "(unknown user)"


def _activity_url(
    address_slug: str,
    user_key: str | None,
    from_: str,
    to: str,
    *,
    discovery: bool = False,
) -> str:
    """Build the self-describing activity-page URL for one activity session.

    Args:
        address_slug: The system's URL path segment (already slug-encoded).
        user_key: The session's user key, or ``None`` for the unknown bucket.
        from_: Inclusive lower bound (the session's first ``requested_at``).
        to: Inclusive upper bound (the session's last ``requested_at``).
        discovery: True to add ``discovery=1``.

    Returns:
        ``/systems/{slug}/activity?user=…&from=…&to=…[&discovery=1]`` with every
        value URL-encoded.
    """
    pairs = [("user", _user_param(user_key)), ("from", from_), ("to", to)]
    if discovery:
        pairs.append(("discovery", "1"))
    return f"/systems/{address_slug}/activity?{urlencode(pairs)}"


def _recording_link(conn_id: str) -> dict[str, str]:
    """Return ``{conn_id, url}`` for a linked recording (``/sessions/{conn_id}``)."""
    return {"conn_id": conn_id, "url": f"/sessions/{quote(conn_id, safe='')}"}


def _activity_session_view(session: ActivitySession, address_slug: str) -> dict[str, object]:
    """Build one row of the system page's kubectl activity table.

    Only grouping aggregates are exposed — no URL, header, or request detail.
    """
    return {
        "user_key": session.user_key,
        "user_label": _user_label(session.username, session.user_key),
        "user_search_url": _user_search_url(session.username, session.user_key),
        "started_at": session.started_at,
        "ended_at": session.ended_at,
        "duration_seconds": session.duration_seconds,
        "duration_display": _duration_display(session.duration_seconds),
        "command_count": session.command_count,
        "request_count": session.request_count,
        "recording_count": session.recording_count,
        "finding_count": session.finding_count,
        "max_severity": session.max_severity,
        "url": _activity_url(
            address_slug, session.user_key, session.started_at, session.ended_at
        ),
    }


def _request_view(
    row: ApiRequestRow, findings: dict[str, list[ApiFindingRow]]
) -> dict[str, object]:
    """Build one request line of a command's ``<details>`` list.

    Exposes only allowlisted, stored columns (time, method, sanitized URL, status,
    outcome) plus finding labels. Header-derived values are not rendered here.
    """
    return {
        "request_id": row.request_id,
        "requested_at": row.requested_at,
        "method": row.method,
        "url": row.url,
        "status_code": row.status_code,
        "outcome": row.outcome,
        "is_discovery": is_discovery(row.method, row.url),
        "finding_labels": [f.label for f in findings.get(row.request_id, [])],
    }


def _command_view(
    command: Command,
    findings: dict[str, list[ApiFindingRow]],
    *,
    include_discovery: bool,
) -> dict[str, object]:
    """Build one row of the activity page's command table (plus its request list)."""
    return {
        "key": command.key,
        "label": command.label,
        "method": command.primary.method,
        "path": command.primary_path,
        "status_code": command.primary.status_code,
        "outcome": command.primary.outcome,
        "started_at": command.started_at,
        "ended_at": command.ended_at,
        "request_count": command.request_count,
        "discovery_count": command.discovery_count,
        "is_discovery_only": command.is_discovery_only,
        "finding_count": command.finding_count,
        "max_severity": command.max_severity,
        "finding_labels": list(command.finding_labels),
        "recordings": [_recording_link(conn_id) for conn_id in command.recordings],
        "requests": [
            _request_view(r, findings)
            for r in command.visible_requests(include_discovery=include_discovery)
        ],
    }


def _dangerous_command_rules() -> list[dict[str, str]]:
    """Return the dangerous-command rules as ``{id, label}`` for the form multiselect.

    Only the ``dangerous-command`` category is exposed (the rule_ids multiselect is
    scoped to commands); secret-exposure rules are filtered out here. No rule pattern
    or recorded content is exposed — id and label only.
    """
    return [
        {"id": rule.id, "label": rule.label}
        for rule in load_rules()
        if rule.category == "dangerous-command"
    ]


@router.get("/", include_in_schema=False)
async def index() -> RedirectResponse:
    """Redirect the site root to the dashboard."""
    return RedirectResponse(
        url="/dashboard", status_code=status.HTTP_307_TEMPORARY_REDIRECT
    )


def _dashboard_window(request: Request) -> str:
    """Return the dashboard's ``window`` value; absent, blank, or unknown → the default.

    The dashboard stays lenient (it is a landing page, not a search): an invalid
    value renders the default window rather than a ``400``.
    """
    raw = (request.query_params.get("window") or "").strip()
    return raw if raw in WINDOW_VALUES else _DEFAULT_WINDOW


async def _recent_activity(request: Request) -> list[dict[str, object]]:
    """Build the dashboard's recent-activity feed (spec §8.2, Q11).

    One :func:`run_timeline` page: every kind (``type=any``), newest first,
    discovery-only commands hidden, no window, :data:`_FEED_LIMIT` items. Rows are
    the same dicts the search page renders. A budget hit just yields a shorter feed,
    with no notice.
    """
    settings = request.app.state.settings
    query = UnifiedQuery(kinds=TYPE_GROUPS["any"])
    kinds, excluded = resolve_kinds(query)
    sources = build_sources(
        request.app.state.db,
        _get_casts(request),
        content_budget=settings.search_regex_max_candidates,
    )
    page = await run_timeline(sources, query, kinds, limit=_FEED_LIMIT, excluded=excluded)
    linked = await _linked_command_ids(request, page)
    return _item_views(page, show_discovery=False, focused=False, linked_command_ids=linked)


@router.get("/dashboard")
async def dashboard(request: Request) -> object:
    """Render the dashboard: windowed figures that drill into search, plus a recent feed.

    Figures come from :meth:`SearchStore.dashboard_stats` for the selected window
    (``?window=7|30|90|all``, default 30 days; an invalid value falls back to the
    default). Every drill-down is built with :func:`search_url` and carries an
    explicit ``type`` and the same ``window`` (spec §8.1):

    * Total sessions → ``type=recordings``; Flagged sessions → ``type=recordings&
      has_findings=true``; session severity chips → ``type=recordings&max_severity=S``;
      category chips → ``type=recordings&category=C``.
    * kubectl API requests → ``type=kubectl``; flagged commands →
      ``type=kubectl&has_findings=true``; API severity chips →
      ``type=kubectl&max_severity=S``.
    * Top users → ``user=U`` (every kind); top systems → ``/systems/{slug}``.

    The recent-activity feed (:func:`_recent_activity`) is not windowed. Only
    metadata and rule-derived figures are shown; no recording text is read or
    rendered (CLAUDE.md rules 5/6).
    """
    window = _dashboard_window(request)
    cutoff = _window_cutoff(window, datetime.now(tz=timezone.utc))
    stats = await _get_search(request).dashboard_stats(started_after=cutoff)

    def link(**params: object) -> str:
        return search_url(**params, window=window)

    severity_rows = [
        {
            "label": sev,
            "count": stats.by_severity[sev],
            "url": link(type="recordings", max_severity=sev),
        }
        for sev in _SEVERITY_DISPLAY_ORDER
        if sev in stats.by_severity
    ]
    # Counts findings per category; the chip lists the sessions holding one, so the
    # two numbers differ by design.
    category_rows = [
        {"label": cat, "count": count, "url": link(type="recordings", category=cat)}
        for cat, count in stats.by_category.items()
    ]
    # Counts sessions per user; the link lists every kind for that user (commands
    # too), so the two numbers differ by design.
    user_rows = [
        {"label": u.label, "count": u.count, "url": link(user=u.label)}
        for u in stats.top_users
    ]
    system_rows = [
        {"label": s.label, "count": s.count, "url": f"/systems/{_system_slug(s.label)}"}
        for s in stats.top_systems
    ]
    # Flagged kubectl commands, each counted once at its highest severity. Only known
    # severities get a chip (SEVERITY_RANK keys, so the class name is never stored text).
    api_severity_rows = [
        {
            "label": sev,
            "count": stats.api_commands_by_severity[sev],
            "url": link(type=KIND_KUBECTL, max_severity=sev),
        }
        for sev in _SEVERITY_DISPLAY_ORDER
        if sev in stats.api_commands_by_severity
    ]
    flagged_commands = stats.api_flagged_commands

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "stats": stats,
            "window": window,
            "window_options": _WINDOW_OPTIONS,
            "total_sessions_url": link(type="recordings"),
            "flagged_sessions_url": link(type="recordings", has_findings=True),
            "api_requests_url": link(type=KIND_KUBECTL),
            "flagged_commands_url": link(type=KIND_KUBECTL, has_findings=True),
            "flagged_commands_label": (
                f"{flagged_commands}+" if stats.api_flagged_truncated else str(flagged_commands)
            ),
            "flagged_commands_plural": flagged_commands != 1 or stats.api_flagged_truncated,
            "severity_rows": severity_rows,
            "category_rows": category_rows,
            "user_rows": user_rows,
            "system_rows": system_rows,
            "api_severity_rows": api_severity_rows,
            "feed_items": await _recent_activity(request),
            "view_all_url": search_url(),
        },
    )


# --- unified search: presentation (spec §8.3) ----------------------------------------
# Every value below is built from allowlisted stored columns or fixed strings. Class
# names come from the kind registry (badge_class), fixed status maps, and
# SEVERITY_RANK keys — never from stored text (spec §10). ``user_agent`` and raw
# ApiRequestRow objects never reach a template.

# Recording status → (label, CSS class). Anything else renders as "unknown".
_STATUS_DISPLAY: dict[str, tuple[str, str]] = {
    "complete": ("complete", "pill-complete"),
    "provisional": ("in progress", "pill-provisional"),
    "error": ("error", "pill-error"),
}
_STATUS_UNKNOWN = ("unknown", "pill-unknown")

# Plural kind labels for notices ("SSH sessions", "kubectl commands", …).
_KIND_PLURALS: dict[str, str] = {k: label for k, label in TYPE_LABELS if k in KINDS}

# Filters that live in the form's "Recording filters" <details> (spec §8.3); the
# <details> opens when any of them is set.
_RECORDING_FILTER_FIELDS = ("status", "min_duration", "max_duration", "category", "rule_ids")

_FOCUS_NOT_FOUND_TEXT = "Command not found. It may have been removed by retention."
_FLAGGED_CAP_TEXT = (
    "More than {cap:,} flagged kubectl commands match. Narrow by system, user, or time."
)
_SCAN_BUDGET_TEXT = "Scanned {n:,} kubectl requests without filling the page."
_CONTENT_BUDGET_TEXT = "Scanned {n:,} recordings without filling the page."
_SEARCH_WINDOW_OPTIONS: list[tuple[str, str]] = [("", "—"), *_WINDOW_OPTIONS]
_MODE_OPTIONS: list[tuple[str, str]] = [("text", "text"), ("regex", "regex")]


def _session_url(conn_id: str) -> str:
    """Return the session detail / replay page URL for a recording."""
    return f"/sessions/{quote(conn_id, safe='')}"


def _safe_severity(value: str | None) -> str | None:
    """Return ``value`` when it is a known severity (a SEVERITY_RANK key), else ``None``."""
    return value if value in SEVERITY_RANK else None


def _number_str(value: float | None) -> str:
    """Render an optional duration for a form field: ``60`` rather than ``60.0``."""
    if value is None:
        return ""
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def _is_htmx_partial(request: Request) -> bool:
    """Tell whether to answer with the results partial rather than the full page.

    True for an HTMX request, except htmx's history-restore request (a cache miss
    after Back/Forward), which replaces the whole body and so needs the full page.
    """
    headers = request.headers
    if headers.get("HX-Request", "").lower() != "true":
        return False
    return headers.get("HX-History-Restore-Request", "").lower() != "true"


def _recording_item_view(
    at: str, hit: RecordingHit, *, linked_command_ids: set[str]
) -> dict[str, object]:
    """Build one ``recording_row`` context (ssh / exec / failed).

    Metadata and finding rule metadata only — never recording content (rule 6).
    """
    s = hit.session
    kind = KINDS[hit.kind]
    url = _session_url(s.conn_id)
    is_failed = hit.kind == KIND_FAILED
    status_label, status_class = _STATUS_DISPLAY.get(s.status, _STATUS_UNKNOWN)
    findings = [
        {
            "label": f.label,
            "severity": _safe_severity(f.severity),
            "category": f.category,
            "offset_seconds": f.offset_seconds,
            "jump_url": (
                f"{url}?{urlencode([('t', f.offset_seconds)])}"
                if f.offset_seconds is not None
                else None
            ),
        }
        for f in hit.findings
    ]
    command_url = (
        search_url(cmd=s.request_id)
        if hit.kind == KIND_EXEC and s.request_id and s.request_id in linked_command_ids
        else None
    )
    return {
        "kind": kind.key,
        "kind_label": kind.label,
        "badge_class": kind.badge_class,
        "row_macro": kind.row_macro,
        "at": at,
        "conn_id": s.conn_id,
        "session_url": url,
        "action": "details" if is_failed else "replay",
        "system_label": _system_label(s.resource_address),
        "system_url": f"/systems/{_system_slug(s.resource_address)}",
        "username": s.username,
        "user_label": s.username or "(unknown user)",
        "user_url": search_url(user=s.username) if s.username else None,
        "shell_user": s.shell_user,
        "status": s.status,
        "status_label": status_label,
        "status_class": status_class,
        "started_at": s.started_at,
        "ended_at": s.ended_at,
        "duration_seconds": None if is_failed else s.duration_seconds,
        "duration_display": None if is_failed else _duration_display(s.duration_seconds),
        "finding_count": s.finding_count,
        "max_severity": _safe_severity(s.max_severity),
        "findings": findings,
        "command_url": command_url,
    }


def _command_item_view(
    at: str, hit: CommandHit, *, show_discovery: bool, focused: bool
) -> dict[str, object]:
    """Build one ``command_row`` context (a kubectl command, spec §8.3).

    Aggregates (counts, end, severity, labels, recordings) cover every request of the
    command; ``requests`` is the listed (≤ 200) requests, discovery hidden unless
    ``discovery=1``. Only allowlisted stored columns are exposed.
    """
    kind = KINDS[KIND_KUBECTL]
    primary = hit.command.primary
    slug = _system_slug(hit.resource_address)
    username = hit.username
    user_value = username or hit.user_key
    return {
        "kind": kind.key,
        "kind_label": kind.label,
        "badge_class": kind.badge_class,
        "row_macro": kind.row_macro,
        "at": at,
        "command_id": hit.command_id,
        "focus_url": search_url(cmd=hit.command_id),
        "open": focused,
        "label": hit.label,
        "method": primary.method,
        "path": hit.command.primary_path,
        "status_code": primary.status_code,
        "outcome": primary.outcome,
        "started_at": hit.started_at,
        "ended_at": hit.ended_at,
        "duration_seconds": hit.duration_seconds,
        "duration_display": _duration_display(hit.duration_seconds),
        "request_count": hit.request_count,
        "discovery_count": hit.discovery_count,
        "hidden_discovery_count": 0 if show_discovery else hit.discovery_count,
        "is_discovery_only": hit.is_discovery_only,
        "listed_count": hit.listed_count,
        "requests_truncated": hit.requests_truncated,
        "finding_count": hit.finding_count,
        "max_severity": _safe_severity(hit.max_severity),
        "finding_labels": list(hit.finding_labels),
        "recordings": [_recording_link(conn_id) for conn_id in hit.recordings],
        "requests": [
            _request_view(r, dict(hit.findings))
            for r in hit.visible_requests(include_discovery=show_discovery)
        ],
        "activity_url": _activity_url(slug, hit.user_key, hit.started_at, hit.ended_at),
        "system_label": _system_label(hit.resource_address),
        "system_url": f"/systems/{slug}",
        "username": username,
        "user_label": _user_label(username, hit.user_key),
        "user_url": search_url(user=user_value) if user_value else None,
    }


def _item_views(
    page: TimelinePage,
    *,
    show_discovery: bool,
    focused: bool,
    linked_command_ids: set[str],
) -> list[dict[str, object]]:
    """Build the row dicts for a timeline page (search results and the dashboard feed)."""
    items: list[dict[str, object]] = []
    for item in page.items:
        if isinstance(item.data, RecordingHit):
            items.append(
                _recording_item_view(item.at, item.data, linked_command_ids=linked_command_ids)
            )
        elif isinstance(item.data, CommandHit):
            items.append(
                _command_item_view(
                    item.at, item.data, show_discovery=show_discovery, focused=focused
                )
            )
    return items


async def _linked_command_ids(request: Request, page: TimelinePage) -> set[str]:
    """Return the exec recordings' ``request_id``\\s on ``page`` that have a stored command.

    One batched ``api_requests`` primary-key lookup (Q13), so an exec row links to its
    command only when the command exists.
    """
    exec_request_ids = [
        item.data.session.request_id
        for item in page.items
        if isinstance(item.data, RecordingHit)
        and item.data.kind == KIND_EXEC
        and item.data.session.request_id
    ]
    if not exec_request_ids:
        return set()
    return await _get_activity(request).known_request_ids(exec_request_ids)


def _exclusion_notices(excluded: dict[str, str], *, focused: bool) -> list[dict[str, object]]:
    """Build the "<kinds> not searched: the <filter> applies to … only." notices.

    Kinds excluded for the same reason share one notice; the three recording kinds
    together read "Recordings". Under a ``cmd`` focus the recording kinds' ``cmd``
    exclusions are not listed (the focus banner already says one command is shown).
    Fixed strings only; no request value is interpolated.
    """
    by_reason: dict[str, list[str]] = {}
    for kind, reason in excluded.items():
        if focused and reason == "cmd":
            continue
        by_reason.setdefault(reason, []).append(kind)
    notices: list[dict[str, object]] = []
    for reason, kinds in by_reason.items():
        if frozenset(kinds) == TYPE_GROUPS["recordings"]:
            subject = "Recordings"
        else:
            names = [_KIND_PLURALS[k] for k in kinds]
            subject = names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"
        what = EXCLUSION_LABELS.get(reason, "filter")
        scope = "kubectl commands" if reason == "cmd" else "recordings"
        notices.append(
            {
                "kinds": kinds,
                "reason": reason,
                "text": f"{subject} not searched: the {what} applies to {scope} only.",
            }
        )
    return notices


def _search_context(
    parsed: ParsedSearch,
    page: TimelinePage,
    *,
    linked_command_ids: set[str],
) -> dict[str, object]:
    """Build the context shared by ``search.html`` and ``_results.html`` (spec §8.3).

    See the template context contract for every key. URLs are built only through
    :func:`search_url` (canonical names; the cursor is unsigned base64url and is
    URL-encoded like any other value).
    """
    q = parsed.query
    params = parsed.url_params()
    focused = q.cmd is not None
    items = _item_views(
        page,
        show_discovery=q.discovery,
        focused=focused,
        linked_command_ids=linked_command_ids,
    )

    cursor_url: str | None = None
    if page.next_cursor is not None:
        cursor_url = search_url(**params, cursor=encode_cursor(page.next_cursor))

    summary: list[dict[str, str]] = []
    if not focused:
        if params["system"] is not None:
            summary.append(
                {
                    "name": "system",
                    "value": _system_label(q.system),
                    "clear_url": search_url(**{**params, "system": None}),
                }
            )
        if params["user"] is not None:
            summary.append(
                {
                    "name": "user",
                    "value": str(params["user"]),
                    "clear_url": search_url(**{**params, "user": None}),
                }
            )

    budget_notices: list[str] = []
    if page.scan_budget_hit:
        budget_notices.append(_SCAN_BUDGET_TEXT.format(n=page.scan_budget))
    if page.content_budget_hit:
        budget_notices.append(_CONTENT_BUDGET_TEXT.format(n=page.content_budget))

    export_query = search_url(**{**params, "page_size": None})[len("/search"):]
    return {
        "items": items,
        "shown_count": len(items),
        "summary": summary,
        "exclusion_notices": _exclusion_notices(dict(parsed.excluded), focused=focused),
        "all_excluded": not parsed.kinds,
        "budget_notices": budget_notices,
        "flagged_cap_notice": (
            _FLAGGED_CAP_TEXT.format(cap=page.flagged_cap) if page.flagged_cap_hit else None
        ),
        "focus": (
            {
                "command_id": q.cmd,
                "not_found": page.focus_not_found,
                "not_found_text": _FOCUS_NOT_FOUND_TEXT,
                "clear_url": search_url(type=KIND_KUBECTL),
            }
            if focused
            else None
        ),
        "show_discovery": q.discovery,
        "next_url": cursor_url if not page.budget_hit else None,
        "continue_url": cursor_url if page.budget_hit else None,
        "first_page_url": search_url(**params) if parsed.cursor is not None else None,
        "export_url": f"/search/export.csv{export_query}",
    }


def _search_form_context(parsed: ParsedSearch) -> dict[str, object]:
    """Build the sticky form values and option lists for ``search.html``.

    The form never carries ``cursor`` (a submit starts at the first page) or ``cmd``
    (a submit leaves the single-command focus).
    """
    q = parsed.query
    params = parsed.url_params()
    has_findings = "" if q.has_findings is None else ("true" if q.has_findings else "false")
    form: dict[str, object] = {
        "type": parsed.type,
        "system": params["system"] or "",
        "user": q.user or "",
        "window": parsed.window or "",
        "from": "" if parsed.window is not None else (q.from_ or ""),
        "to": "" if parsed.window is not None else (q.to or ""),
        "severity": q.severity or "",
        "max_severity": q.max_severity or "",
        "has_findings": has_findings,
        "category": q.category or "",
        "rule_ids": list(q.rule_ids),
        "status": q.status or "",
        "min_duration": _number_str(q.min_duration),
        "max_duration": _number_str(q.max_duration),
        "q": params["q"] or "",
        "mode": params["mode"] or "text",
        "sort": q.sort,
        "discovery": q.discovery,
        "page_size": parsed.page_size if parsed.page_size_explicit else None,
    }
    categories = sorted({rule.category for rule in load_rules()})
    if q.category and q.category not in categories:
        categories.append(q.category)
    return {
        "form": form,
        "recording_filters_open": any(form[name] for name in _RECORDING_FILTER_FIELDS),
        "type_options": TYPE_LABELS,
        "window_options": _SEARCH_WINDOW_OPTIONS,
        "severity_options": _SEVERITY_OPTIONS,
        "status_options": list(STATUS_VALUES),
        "category_options": categories,
        "mode_options": _MODE_OPTIONS,
        "sort_options": _SORT_OPTIONS,
        "rules": _dangerous_command_rules(),
    }


def _search_error_response(request: Request, exc: HTTPException) -> Response:
    """Render the HTMX ``400`` partial (spec §5.3).

    The detail is one of ``web.params``' fixed messages, which name the parameter
    only; the submitted value is never echoed or logged.
    """
    return templates.TemplateResponse(
        request,
        "_search_error.html",
        {"error_message": str(exc.detail)},
        status_code=status.HTTP_400_BAD_REQUEST,
        headers={"Vary": "HX-Request"},
    )


@router.get("/search")
async def search(request: Request) -> Response:
    """Render the unified search (spec §8.3): full page, or the results partial for HTMX.

    Parameters are parsed strictly by :func:`parse_unified_query` (canonical names
    plus legacy aliases; ``400`` on any invalid, repeated, or conflicting value). The
    resolved kinds run through :func:`run_timeline` over the default sources, one
    keyset page of ``page_size`` items. Exec recordings on the page are checked
    against ``api_requests`` (batched Q13) so their row can link to their command.

    Responses:
        * ``HX-Request: true`` (not a history restore) → ``_results.html`` only.
          A ``400`` renders ``_search_error.html`` with status ``400``.
        * Otherwise → ``search.html`` (form + results). A ``400`` is FastAPI's JSON
          ``{"detail": …}``.

    Recording content is never rendered — rows carry metadata plus finding label,
    severity, and offset only (CLAUDE.md rules 5/6).
    """
    settings = request.app.state.settings
    partial = _is_htmx_partial(request)
    try:
        parsed = parse_unified_query(request, default_page_size=settings.search_page_size)
    except HTTPException as exc:
        if partial and exc.status_code == status.HTTP_400_BAD_REQUEST:
            return _search_error_response(request, exc)
        raise

    sources = build_sources(
        request.app.state.db,
        _get_casts(request),
        content_budget=settings.search_regex_max_candidates,
    )
    try:
        page = await run_timeline(
            sources,
            parsed.query,
            parsed.kinds,
            cursor=parsed.cursor,
            limit=parsed.page_size,
            excluded=parsed.excluded,
        )
    except ValueError:
        # parse_unified_query already checks the cursor against the search; this is
        # defense in depth. Fixed message, no value.
        exc = _bad_request("'cursor' does not match the current search")
        if partial:
            return _search_error_response(request, exc)
        raise exc from None

    linked = await _linked_command_ids(request, page)

    context = _search_context(parsed, page, linked_command_ids=linked)
    if partial:
        template = "_results.html"
    else:
        template = "search.html"
        context.update(_search_form_context(parsed))
    return templates.TemplateResponse(
        request, template, context, headers={"Vary": "HX-Request"}
    )


# CSV export columns (spec §9). The first ten are Session 8's, unchanged in name
# and order; the last five were appended in Session 10.
CSV_COLUMNS: tuple[str, ...] = (
    "conn_id",
    "username",
    "resource_address",
    "status",
    "started_at",
    "ended_at",
    "duration_seconds",
    "finding_count",
    "max_severity",
    "findings",
    "kind",
    "command",
    "method",
    "path",
    "request_count",
)

# Leading characters a spreadsheet may treat as a formula (or that hide one). A
# text cell starting with any of them is written with a leading "'" (spec §9).
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Items requested per run_timeline call while walking an export (the UI maximum).
_CSV_PAGE_SIZE = MAX_PAGE_SIZE

_CSV_TRUNCATED_HEADER = "X-Gatorcast-Truncated"


def _csv_safe(value: object) -> object:
    """Neutralize a formula-like text cell by prefixing ``'`` (spec §9).

    Applies to every column. Only text cells are changed; numbers are written as-is
    (they are produced by this module, never taken from a client).

    Args:
        value: A cell value.

    Returns:
        ``value``, or ``"'" + value`` when it is a string starting with ``=``, ``+``,
        ``-``, ``@``, tab, or carriage return.
    """
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _csv_recording_row(hit: RecordingHit) -> list[object]:
    """Build the 15 CSV cells of a recording (ssh / exec / failed).

    Columns 1–10 are exactly Session 8's (values as stored). The ``findings`` cell
    joins ``"<label>@<offset>s"`` entries with ``"; "``: rule label and offset only,
    never recorded text (CLAUDE.md rule 6). Columns 12–15 are empty.
    """
    s = hit.session
    findings = "; ".join(
        f"{f.label}@{f.offset_seconds if f.offset_seconds is not None else '?'}s"
        for f in hit.findings
    )
    return [
        s.conn_id,
        s.username or "",
        s.resource_address or "",
        s.status,
        s.started_at or "",
        s.ended_at or "",
        s.duration_seconds if s.duration_seconds is not None else "",
        s.finding_count,
        s.max_severity or "",
        findings,
        hit.kind,
        "",
        "",
        "",
        "",
    ]


def _csv_command_row(hit: CommandHit) -> list[object]:
    """Build the 15 CSV cells of a kubectl command (spec §9).

    Only allowlisted stored values: the command label (``Kubectl-Command``, else the
    User-Agent product token, else ``(unknown client)``; never the full User-Agent),
    the primary request's method, and its path with the query string removed (so no
    query value, and never ``command=``). API findings have no offset, so the
    ``findings`` cell is their distinct labels joined by ``"; "``.
    """
    return [
        hit.conn_id,
        hit.username or "",
        hit.resource_address or "",
        "",
        hit.started_at,
        hit.ended_at,
        round(hit.duration_seconds, 3),
        hit.finding_count,
        hit.max_severity or "",
        "; ".join(hit.finding_labels),
        KIND_KUBECTL,
        hit.label,
        hit.command.primary.method or "",
        hit.command.primary_path,
        hit.request_count,
    ]


class _CountingSidecars:
    """Cast-store stand-in for one export: counts sidecar reads across pages.

    The timeline's content budget is per page; an export walks many pages, so it
    hands each page the budget left over from the export-wide total. Only
    ``read_sidecar`` is used by the sessions source.
    """

    def __init__(self, casts: CastStore) -> None:
        """Wrap ``casts``; no reads counted yet."""
        self._casts = casts
        self.reads = 0

    async def read_sidecar(self, conn_id: str) -> str:
        """Count the attempt, then delegate to :meth:`CastStore.read_sidecar`."""
        self.reads += 1
        return await self._casts.read_sidecar(conn_id)


@router.get("/search/export.csv")
async def search_export_csv(request: Request) -> Response:
    """Export the current search as a CSV download (spec §9: the export follows the page).

    Parameters are parsed by :func:`parse_unified_query` exactly as for ``/search``
    (canonical names plus legacy aliases, ``400`` on invalid input); ``cursor`` and
    ``page_size`` are validated, then ignored. Pages of :func:`run_timeline` are
    walked from the first page and written as they arrive. The walk stops when every
    source is exhausted, at :data:`_CSV_EXPORT_CAP` items, or at the first page a
    budget cut short. Sidecar reads (content search) are bounded by
    ``SEARCH_REGEX_MAX_CANDIDATES`` for the whole export, not per page.

    The response carries ``X-Gatorcast-Truncated: true`` when the export stopped
    before the end: the cap was reached, a budget stopped a page, the export-wide
    sidecar budget ran out, or more flagged kubectl commands match than the flagged
    cap lists.

    Each row is a recording or a kubectl command, in page order, with the 15
    :data:`CSV_COLUMNS`. Every text cell goes through :func:`_csv_safe`. Recorded
    content is never written (CLAUDE.md rule 6).
    """
    settings = request.app.state.settings
    parsed = parse_unified_query(request, default_page_size=settings.search_page_size)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)

    sidecars = _CountingSidecars(_get_casts(request))
    sidecar_budget = max(1, int(settings.search_regex_max_candidates))
    written = 0
    truncated = False
    cursor: Cursor | None = None
    while parsed.kinds:
        remaining_reads = sidecar_budget - sidecars.reads
        if remaining_reads <= 0:
            truncated = True
            break
        sources = build_sources(
            request.app.state.db,
            sidecars,  # type: ignore[arg-type]  # duck-typed: only read_sidecar is used
            content_budget=remaining_reads,
        )
        try:
            page = await run_timeline(
                sources,
                parsed.query,
                parsed.kinds,
                cursor=cursor,
                limit=min(_CSV_PAGE_SIZE, _CSV_EXPORT_CAP - written),
                excluded=parsed.excluded,
            )
        except ValueError:
            raise _bad_request("'cursor' does not match the current search") from None
        for item in page.items:
            if isinstance(item.data, RecordingHit):
                row = _csv_recording_row(item.data)
            elif isinstance(item.data, CommandHit):
                row = _csv_command_row(item.data)
            else:  # pragma: no cover - run_timeline only returns hydrated items
                continue
            writer.writerow([_csv_safe(cell) for cell in row])
            written += 1
        if page.flagged_cap_hit:
            truncated = True
        if page.next_cursor is None:
            break
        if page.budget_hit or written >= _CSV_EXPORT_CAP:
            truncated = True
            break
        cursor = page.next_cursor

    headers = {"Content-Disposition": 'attachment; filename="gatorcast-search.csv"'}
    if truncated:
        headers[_CSV_TRUNCATED_HEADER] = "true"
        log.info("search.export_truncated", rows=written, sidecar_reads=sidecars.reads)
    return Response(content=buffer.getvalue(), media_type="text/csv", headers=headers)


@router.get("/systems")
async def systems(request: Request) -> object:
    """Render the systems index (spec §8.4).

    One row per distinct ``resource_address`` with Type badges, the session count
    and "Last session", the API-request count and "Last API request" (both in the
    ``requested_at`` format), and the recording findings summary. Rows are sorted by
    the newer of the two timestamps (``list_systems``). The counts and "Last API
    request" link into search via :func:`search_url` (spec §8.1).
    """
    repo = _get_repo(request)
    summaries = await repo.list_systems()
    views = []
    for summary in summaries:
        system = _search_system(summary.resource_address)
        views.append(
            SystemView(
                summary=summary,
                label=_system_label(summary.resource_address),
                address_slug=_system_slug(summary.resource_address),
                badges=_system_badges(summary),
                sessions_url=search_url(type="recordings", system=system),
                api_url=search_url(type=KIND_KUBECTL, system=system),
            )
        )
    return templates.TemplateResponse(
        request, "systems.html", {"systems": views}
    )


@router.get("/systems/{address_slug}")
async def system_sessions(request: Request, address_slug: str) -> object:
    """Render one system: its recordings (newest first) and its kubectl activity.

    The kubectl activity table covers the half-open window
    ``[activity_before - 7 days, activity_before)``. Requests are fetched with
    ``requests_for_system`` (bounded by ``_ACTIVITY_MAX_ROWS``), their findings and
    linked recordings are resolved in one call each, and ``group_activity`` splits
    them into per-user activity sessions on the configured gap / max window. Each
    row links to the activity page by its own bounds. An "Older" link pages to the
    previous window; an activity session straddling a window edge appears split at
    that edge. When the row cap is hit, a truncation notice is shown.

    Cross-links (spec §8.5): a "Search this system" header link
    (``/search?system=A``), a "kubectl commands in search" link by the activity
    heading (``/search?type=kubectl&system=A``), and a trailing ``⌕`` link per user in
    both tables (``/search?user=…``; username, else user key; none for the NULL-user
    bucket). The NULL system bucket searches as ``system=_unknown``.

    Query params:
        activity_before: Optional ISO 8601 upper bound of the activity window
            (default: now). Invalid or repeated → 400.

    Args:
        address_slug: The percent-encoded resource_address, or the unknown
            sentinel.

    Raises:
        HTTPException: ``400`` if ``activity_before`` is invalid.
    """
    raw_before = _single_param(request, "activity_before")
    before = _parse_time_param("activity_before", raw_before, required=False)
    paged = before is not None
    if before is None:
        before = datetime.now(tz=timezone.utc)
    try:
        since = before - _ACTIVITY_PAGE_SPAN
        since_str = to_requested_at_format(since)
        before_str = to_requested_at_format(before)
    except (ValueError, OverflowError):
        raise _bad_request("'activity_before' is out of range") from None

    repo = _get_repo(request)
    resource_address = _slug_to_address(address_slug)
    sessions_list = await repo.list_sessions(resource_address)

    settings = request.app.state.settings
    activity = _get_activity(request)
    rows = await activity.requests_for_system(
        resource_address, since_str, before_str, _ACTIVITY_MAX_ROWS
    )
    request_ids = [r.request_id for r in rows]
    findings = await activity.findings_for_requests(request_ids)
    recordings = await activity.recordings_for_requests(request_ids)
    activity_sessions = group_activity(
        rows,
        settings.kubectl_activity_gap_seconds,
        settings.kubectl_activity_max_seconds,
        findings=findings,
        recordings=recordings,
    )

    system = _search_system(resource_address)
    return templates.TemplateResponse(
        request,
        "sessions.html",
        {
            "sessions": [_session_view(s) for s in sessions_list],
            "system_label": _system_label(resource_address),
            "system_slug": address_slug,
            "search_system_url": search_url(system=system),
            "kubectl_search_url": search_url(type=KIND_KUBECTL, system=system),
            "activity_sessions": [
                _activity_session_view(s, address_slug) for s in activity_sessions
            ],
            "activity_window_since": since_str,
            "activity_window_until": before_str,
            "activity_truncated": len(rows) >= _ACTIVITY_MAX_ROWS,
            "activity_max_rows": _ACTIVITY_MAX_ROWS,
            "activity_older_url": (
                f"/systems/{address_slug}?{urlencode([('activity_before', since_str)])}"
            ),
            "activity_latest_url": f"/systems/{address_slug}" if paged else None,
        },
    )


@router.get("/systems/{address_slug}/activity")
async def system_activity(request: Request, address_slug: str) -> object:
    """Render one kubectl activity session: its commands and their requests.

    The activity session is identified by self-describing bounds, so the link stays
    valid however the system page was windowed. Requests are read with
    ``requests_in_bounds`` (inclusive bounds, bounded by ``_ACTIVITY_MAX_ROWS``) and
    grouped into commands by ``Kubectl-Session``. Each command links its exec/attach
    recordings through ``request_id`` (``recordings_for_requests``) to
    ``/sessions/{conn_id}``. Discovery requests are hidden (and discovery-only
    commands omitted) unless ``discovery=1``. No player is used, and only
    allowlisted stored columns are rendered. The header's user label links to
    ``/search?user=…`` (the username, else the user key; no link for the NULL-user
    bucket, spec §8.5).

    Query params:
        user: Required. The activity session's ``user_key``, or ``_unknown`` for the
            NULL bucket. Max 512 chars, no control characters.
        from: Required. Inclusive ISO 8601 lower bound.
        to: Required. Inclusive ISO 8601 upper bound; must not precede ``from``.
        discovery: Optional, ``0`` (default) or ``1``.
        Each may be given at most once.

    Args:
        address_slug: The percent-encoded resource_address, or the unknown
            sentinel.

    Raises:
        HTTPException: ``400`` for a missing/invalid/repeated parameter or
            ``from > to``; ``404`` when no requests fall in the bounds.
    """
    user_key = _parse_user_param(_single_param(request, "user"))
    from_dt = _parse_time_param("from", _single_param(request, "from"), required=True)
    to_dt = _parse_time_param("to", _single_param(request, "to"), required=True)
    show_discovery = _parse_discovery_param(_single_param(request, "discovery"))
    if from_dt is None or to_dt is None:  # unreachable: required=True raises first
        raise _bad_request("'from' and 'to' are required")
    if from_dt > to_dt:
        raise _bad_request("'from' must not be after 'to'")
    from_str = to_requested_at_format(from_dt)
    to_str = to_requested_at_format(to_dt)

    resource_address = _slug_to_address(address_slug)
    activity = _get_activity(request)
    rows = await activity.requests_in_bounds(
        resource_address, user_key, from_str, to_str, _ACTIVITY_MAX_ROWS
    )
    if not rows:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No kubectl activity in these bounds"
        )

    request_ids = [r.request_id for r in rows]
    findings = await activity.findings_for_requests(request_ids)
    recordings = await activity.recordings_for_requests(request_ids)
    commands = group_commands(rows, recordings, findings=findings)
    visible = [c for c in commands if show_discovery or not c.is_discovery_only]

    all_findings = [f for r in rows for f in findings.get(r.request_id, [])]
    max_severity: str | None = None
    for f in all_findings:
        if max_severity is None or SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(
            max_severity, 0
        ):
            max_severity = f.severity
    linked_recordings = list(dict.fromkeys(c for cmd in commands for c in cmd.recordings))
    discovery_total = sum(c.discovery_count for c in commands)

    first, last = rows[0], rows[-1]
    username = next((r.username for r in rows if r.username), None)
    duration = (
        datetime.fromisoformat(last.requested_at) - datetime.fromisoformat(first.requested_at)
    ).total_seconds()

    return templates.TemplateResponse(
        request,
        "activity.html",
        {
            "system_label": _system_label(resource_address),
            "system_slug": address_slug,
            "user_key": user_key,
            "user_label": _user_label(username, user_key),
            "user_search_url": _user_search_url(username, user_key),
            "span_from": first.requested_at,
            "span_to": last.requested_at,
            "duration_seconds": duration,
            "duration_display": _duration_display(duration),
            "request_count": len(rows),
            "command_count": len(visible),
            "discovery_count": discovery_total,
            "hidden_discovery_count": 0 if show_discovery else discovery_total,
            "finding_count": len(all_findings),
            "max_severity": max_severity,
            "recordings": [_recording_link(c) for c in linked_recordings],
            "commands": [
                _command_view(c, findings, include_discovery=show_discovery) for c in visible
            ],
            "show_discovery": show_discovery,
            "discovery_toggle_url": _activity_url(
                address_slug, user_key, from_str, to_str, discovery=not show_discovery
            ),
            "truncated": len(rows) >= _ACTIVITY_MAX_ROWS,
            "max_rows": _ACTIVITY_MAX_ROWS,
        },
    )


@router.get("/sessions/{conn_id}")
async def session_detail(request: Request, conn_id: str) -> object:
    """Render the detail/replay page for a single session.

    The User value links to ``/search?user=<username>`` when a username is known
    (spec §8.5). For a kubectl exec/attach recording whose ``request_id`` matches a
    stored ``api_requests`` row (Q13, a primary-key lookup), a "kubectl command" row
    links to ``/search?cmd=<request_id>``, which opens that command expanded.

    Args:
        conn_id: The connection id of the session.

    Raises:
        HTTPException: ``404`` if no such session exists.
    """
    repo = _get_repo(request)
    session = await repo.get(conn_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    casts = _get_casts(request)
    has_cast = _resolve_cast_path(casts, session) is not None

    search = _get_search(request)
    findings = await search.list_findings(conn_id)

    command_url: str | None = None
    if session.request_id:
        known = await _get_activity(request).known_request_ids([session.request_id])
        if session.request_id in known:
            command_url = search_url(cmd=session.request_id)

    return templates.TemplateResponse(
        request,
        "session.html",
        {
            "session": _session_view(session),
            "system_label": _system_label(session.resource_address),
            "system_slug": _system_slug(session.resource_address),
            "has_cast": has_cast,
            "findings": findings,
            "command_url": command_url,
        },
    )


@router.get("/sessions/{conn_id}/cast")
async def session_cast(request: Request, conn_id: str) -> Response:
    """Serve a session's ``.cast`` recording for the asciinema player.

    The path is built via the cast store and verified to resolve strictly inside
    ``casts_dir`` before serving — defense in depth against traversal even though
    ``conn_id`` is validated upstream in ``classify`` (CLAUDE.md rules 5/9).

    When encryption is enabled the file on disk is ciphertext, so it is decrypted
    in memory via ``CastStore.read_cast`` and returned as a ``Response`` (the bytes
    are still only ever loaded by the vendored player — rule 6 intact). When
    encryption is off the plaintext file is streamed with ``FileResponse`` as
    before. Recording content is never logged (rule 5).

    Args:
        conn_id: The connection id of the session.

    Raises:
        HTTPException: ``404`` if the row or its ``.cast`` file is missing or
            cannot be decrypted.
    """
    repo = _get_repo(request)
    session = await repo.get(conn_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")

    casts = _get_casts(request)
    path = _resolve_cast_path(casts, session)
    if path is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")

    # In the file-first model an in-progress (provisional) recording is plaintext on
    # disk and only encrypted when sealed to 'complete'/'error'. So serve plaintext
    # when encryption is off OR the session is still in progress; decrypt only a
    # sealed row under encryption.
    sealed = session.status in ("complete", "error")
    if not casts.encryption_enabled or not sealed:
        return FileResponse(
            path=path,
            media_type=_CAST_MEDIA_TYPE,
            filename=f"{conn_id}.cast",
        )

    # Encrypted at rest: decrypt in memory and serve the asciicast bytes. A decrypt
    # failure (wrong key / tamper) becomes a 404 — never leak crypto detail/content.
    try:
        text = await casts.read_cast(path)
    except Exception:
        log.warning("cast.decrypt_failed", conn_id=session.conn_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found"
        )
    return Response(
        content=text.encode("utf-8"),
        media_type=_CAST_MEDIA_TYPE,
        headers={"Content-Disposition": f'inline; filename="{conn_id}.cast"'},
    )


def _resolve_cast_path(casts: CastStore, session: Session) -> Path | None:
    """Resolve a session's ``.cast`` path, confined to ``casts_dir``.

    Builds the canonical path from the connection id (never trusting a stored
    ``cast_path`` string for traversal), resolves it, and confirms it lives inside
    ``casts_dir`` and exists. Anything outside the directory, or a missing file,
    yields ``None``.

    Args:
        casts: The cast store providing ``casts_dir`` and ``path_for``.
        session: The session whose recording is requested.

    Returns:
        The verified absolute path, or ``None`` if absent/out of bounds.
    """
    casts_root = casts.casts_dir.resolve()
    candidate = casts.path_for(session.conn_id).resolve()

    # Confinement check: the resolved file must be inside casts_dir.
    if not candidate.is_relative_to(casts_root):
        log.warning("cast.path_out_of_bounds", conn_id=session.conn_id)
        return None
    if not candidate.is_file():
        return None
    return candidate
