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
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, RedirectResponse, Response, StreamingResponse
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
from gatorcast.store.search import SearchFilters, SearchStore, SessionWithFindings
from gatorcast.store.sessions import SessionRepository, SystemSummary
from gatorcast.web.auth import require_ui_auth

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

# Upper bound on rows pulled for a CSV export — the export covers the full filtered
# set in a single page rather than honoring the UI page size.
_CSV_EXPORT_CAP = 10000

# Dashboard time-window options (query value, label). Findings/counts and the
# drill-down links are scoped to the selected window; "all" disables the cutoff.
_WINDOW_OPTIONS: list[tuple[str, str]] = [
    ("7", "Last 7 days"),
    ("30", "Last 30 days"),
    ("90", "Last 90 days"),
    ("all", "All time"),
]
_DEFAULT_WINDOW = "30"

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

# Upper bound on an ISO 8601 time-bound query value (generous for nanosecond
# fractions plus an offset); longer values are rejected before parsing.
_MAX_TIME_PARAM_LEN = 64


def _window_cutoff(window: str) -> str | None:
    """Return the ISO8601 cutoff for a dashboard window value, or None for all-time.

    Args:
        window: One of the ``_WINDOW_OPTIONS`` values (``"7"``/``"30"``/``"90"``/``"all"``).

    Returns:
        An ISO8601 ``...Z`` cutoff string, or ``None`` when the window is ``"all"`` or
        unparseable.
    """
    if window == "all":
        return None
    try:
        days = max(1, int(window))
    except ValueError:
        return None
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


def _search_url(**params: str | None) -> str:
    """Build a ``/search`` URL from non-empty query params (values are URL-encoded).

    Args:
        **params: Candidate query params; ``None``/empty values are dropped.

    Returns:
        A ``/search`` URL with an encoded query string (or bare ``/search`` if none).
    """
    pairs = [(k, v) for k, v in params.items() if v]
    return f"/search?{urlencode(pairs)}" if pairs else "/search"

router = APIRouter(dependencies=[Depends(require_ui_auth)])


class SystemView(BaseModel):
    """Presentation wrapper for one system row on the systems index."""

    summary: SystemSummary
    label: str
    address_slug: str


def _system_label(resource_address: str | None) -> str:
    """Return the display label for a system, mapping NULL to the unknown bucket."""
    return resource_address if resource_address else _UNKNOWN_LABEL


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
    fields the templates read. Recording content is never included.
    """
    return {
        "conn_id": session.conn_id,
        "username": session.username,
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


def _bad_request(detail: str) -> HTTPException:
    """Build a ``400 Bad Request`` for an invalid query parameter.

    The detail names the parameter only; the submitted value is never echoed.
    """
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _single_param(request: Request, name: str) -> str | None:
    """Return a query parameter that may appear at most once.

    Args:
        request: The incoming request.
        name: The query parameter name.

    Returns:
        The raw value, or ``None`` when the parameter is absent.

    Raises:
        HTTPException: ``400`` if the parameter is repeated.
    """
    values = request.query_params.getlist(name)
    if len(values) > 1:
        raise _bad_request(f"'{name}' may be given only once")
    return values[0] if values else None


def _has_control_chars(value: str) -> bool:
    """Tell whether ``value`` contains ASCII/C1 control characters."""
    return any(ord(ch) < 0x20 or 0x7F <= ord(ch) < 0xA0 for ch in value)


def _parse_time_param(name: str, raw: str | None, *, required: bool) -> datetime | None:
    """Parse an ISO 8601 time-bound query parameter to an aware UTC datetime.

    Accepts any ``datetime.fromisoformat`` shape (``Z`` or offset suffix; naive
    values are taken as UTC). The value is only ever used as a bound SQL parameter
    after normalization to the stored ``requested_at`` format.

    Args:
        name: The parameter name (for the error detail).
        raw: The raw query value, or ``None`` when absent.
        required: True to reject an absent/blank value.

    Returns:
        The aware UTC datetime, or ``None`` when optional and absent/blank.

    Raises:
        HTTPException: ``400`` if the value is missing (when required), too long,
            or not parseable ISO 8601.
    """
    if raw is None or not raw.strip():
        if required:
            raise _bad_request(f"'{name}' is required")
        return None
    value = raw.strip()
    if len(value) > _MAX_TIME_PARAM_LEN:
        raise _bad_request(f"'{name}' is not a valid ISO 8601 timestamp")
    try:
        dt = datetime.fromisoformat(value)
        dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        # Round-trip through the stored format so an unrepresentable value fails
        # here (400) rather than inside the store.
        to_requested_at_format(dt)
    except (ValueError, OverflowError):
        raise _bad_request(f"'{name}' is not a valid ISO 8601 timestamp") from None
    return dt


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


def _parse_discovery_param(raw: str | None) -> bool:
    """Parse the ``discovery`` toggle: ``1`` shows discovery requests, ``0``/absent hides.

    Raises:
        HTTPException: ``400`` for any other value.
    """
    if raw is None or raw == "0":
        return False
    if raw == "1":
        return True
    raise _bad_request("'discovery' must be 0 or 1")


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


def _clean_str(value: str | None) -> str | None:
    """Normalize a query-string value: blank/whitespace-only becomes ``None``.

    Args:
        value: The raw query-param value, or ``None`` if the param was absent.

    Returns:
        The stripped value, or ``None`` when it is missing or empty.
    """
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _clean_float(value: str | None) -> float | None:
    """Parse a query-string value as a float, tolerating blanks/invalid input.

    Args:
        value: The raw query-param value.

    Returns:
        The parsed float, or ``None`` when blank or not a valid number.
    """
    cleaned = _clean_str(value)
    if cleaned is None:
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


def _clean_bool(value: str | None) -> bool | None:
    """Parse an optional tri-state boolean (``"true"``/``"false"``/absent).

    Args:
        value: The raw query-param value.

    Returns:
        ``True``/``False`` for the recognized strings, else ``None``.
    """
    cleaned = _clean_str(value)
    if cleaned is None:
        return None
    match cleaned.lower():
        case "true":
            return True
        case "false":
            return False
        case _:
            return None


def _parse_filters(request: Request, *, default_page_size: int) -> SearchFilters:
    """Build :class:`SearchFilters` from the request query string.

    Empty-string values become ``None`` so a blank form field never filters. The
    repeated ``rule_ids`` param is collected into a list. Page defaults to 1 and
    page size to the configured default when absent/invalid.

    Args:
        request: The incoming request whose query params drive the filters.
        default_page_size: The page size to use when none is supplied.

    Returns:
        The parsed :class:`SearchFilters`.
    """
    qp = request.query_params

    page = 1
    raw_page = _clean_str(qp.get("page"))
    if raw_page is not None:
        try:
            page = max(1, int(raw_page))
        except ValueError:
            page = 1

    page_size = default_page_size
    raw_size = _clean_str(qp.get("page_size"))
    if raw_size is not None:
        try:
            page_size = max(1, int(raw_size))
        except ValueError:
            page_size = default_page_size

    rule_ids = [rid for rid in qp.getlist("rule_ids") if rid.strip()]

    return SearchFilters(
        username=_clean_str(qp.get("username")),
        resource_address=_clean_str(qp.get("resource_address")),
        status=_clean_str(qp.get("status")),
        started_after=_clean_str(qp.get("started_after")),
        started_before=_clean_str(qp.get("started_before")),
        min_duration=_clean_float(qp.get("min_duration")),
        max_duration=_clean_float(qp.get("max_duration")),
        category=_clean_str(qp.get("category")),
        severity=_clean_str(qp.get("severity")),
        max_severity=_clean_str(qp.get("max_severity")),
        rule_ids=rule_ids,
        has_findings=_clean_bool(qp.get("has_findings")),
        keyword=_clean_str(qp.get("keyword")),
        regex=_clean_str(qp.get("regex")),
        sort=_clean_str(qp.get("sort")) or "newest",
        page=page,
        page_size=page_size,
    )


@router.get("/", include_in_schema=False)
async def index() -> RedirectResponse:
    """Redirect the site root to the dashboard."""
    return RedirectResponse(
        url="/dashboard", status_code=status.HTTP_307_TEMPORARY_REDIRECT
    )


@router.get("/dashboard")
async def dashboard(request: Request) -> object:
    """Render the dashboard: time-windowed counts + risk breakdowns, all drillable.

    Figures come from :meth:`SearchStore.dashboard_stats` scoped to the selected time
    window (``?window=7|30|90|all``, default 30 days) — session/finding counts and
    rule-derived severities/categories only; no recording text is read or shown
    (CLAUDE.md rules 5/6). Each breakdown is rendered with a link: severities and
    categories deep-link into ``/search`` (carrying the same window via
    ``started_after``), top users link to that user's sessions in search, and top
    systems link to the system's session list.
    """
    search = _get_search(request)

    window = _clean_str(request.query_params.get("window")) or _DEFAULT_WINDOW
    if window not in {value for value, _ in _WINDOW_OPTIONS}:
        window = _DEFAULT_WINDOW
    cutoff = _window_cutoff(window)

    stats = await search.dashboard_stats(started_after=cutoff)

    severity_rows = [
        {
            "label": sev,
            "count": stats.by_severity[sev],
            "url": _search_url(max_severity=sev, started_after=cutoff),
        }
        for sev in _SEVERITY_DISPLAY_ORDER
        if sev in stats.by_severity
    ]
    category_rows = [
        {
            "label": cat,
            "count": count,
            "url": _search_url(category=cat, started_after=cutoff),
        }
        for cat, count in stats.by_category.items()
    ]
    user_rows = [
        {
            "label": u.label,
            "count": u.count,
            "url": _search_url(username=u.label, started_after=cutoff),
        }
        for u in stats.top_users
    ]
    system_rows = [
        {
            "label": s.label,
            "count": s.count,
            "url": f"/systems/{_system_slug(s.label)}",
        }
        for s in stats.top_systems
    ]
    # kubectl API requests by each flagged request's highest severity. No search
    # integration exists for API requests (spec §2 non-goal), so rows carry no URL.
    api_severity_rows = [
        {"label": sev, "count": stats.api_by_severity[sev]}
        for sev in _SEVERITY_DISPLAY_ORDER
        if sev in stats.api_by_severity
    ]

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "stats": stats,
            "window": window,
            "window_options": _WINDOW_OPTIONS,
            "severity_rows": severity_rows,
            "category_rows": category_rows,
            "user_rows": user_rows,
            "system_rows": system_rows,
            "api_severity_rows": api_severity_rows,
        },
    )


@router.get("/search")
async def search(request: Request) -> object:
    """Render the search page (or, for HTMX requests, the results fragment only).

    Query params are parsed into :class:`SearchFilters` (blanks → ``None``), the search
    runs, and the result page is rendered. When the ``HX-Request`` header is present the
    response is the bare ``_results.html`` partial so HTMX can swap the results region
    in place; otherwise the full ``search.html`` page (form + results) is returned.

    Recording content is never rendered — results show metadata plus finding label,
    severity, and offset only (CLAUDE.md rules 5/6).
    """
    settings = request.app.state.settings
    store = _get_search(request)
    filters = _parse_filters(request, default_page_size=settings.search_page_size)
    result = await store.search(
        filters, regex_max_candidates=settings.search_regex_max_candidates
    )

    context = {
        "result": result,
        "filters": filters,
        "rules": _dangerous_command_rules(),
        "severity_options": _SEVERITY_OPTIONS,
        "sort_options": _SORT_OPTIONS,
        "query_string": str(request.query_params),
    }

    template = (
        "_results.html"
        if request.headers.get("HX-Request", "").lower() == "true"
        else "search.html"
    )
    return templates.TemplateResponse(request, template, context)


def _csv_row_for(item: SessionWithFindings) -> list[object]:
    """Build one CSV row (metadata + finding SUMMARY only) for a result item.

    The ``findings`` cell joins ``"<label>@<offset>s"`` entries with ``;`` — label and
    offset only, never any matched/recorded text (CLAUDE.md rule 6).
    """
    s = item.session
    finding_descriptors = [
        f"{f.label}@{f.offset_seconds if f.offset_seconds is not None else '?'}s"
        for f in item.findings
    ]
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
        "; ".join(finding_descriptors),
    ]


@router.get("/search/export.csv")
async def search_export_csv(request: Request) -> StreamingResponse:
    """Export the current filtered search as a CSV download (metadata + summary only).

    Uses the same filter parsing as :func:`search` but pages the full filtered set in a
    single large page. Columns carry session metadata plus a finding SUMMARY (label +
    offset); recorded content is never written (CLAUDE.md rule 6).
    """
    settings = request.app.state.settings
    store = _get_search(request)
    filters = _parse_filters(request, default_page_size=settings.search_page_size)
    filters.page = 1
    filters.page_size = _CSV_EXPORT_CAP
    result = await store.search(
        filters, regex_max_candidates=settings.search_regex_max_candidates
    )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
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
        ]
    )
    for item in result.items:
        writer.writerow(_csv_row_for(item))
    buffer.seek(0)

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="gatorcast-search.csv"'},
    )


@router.get("/systems")
async def systems(request: Request) -> object:
    """Render the systems index: distinct resource_address with counts/last-seen."""
    repo = _get_repo(request)
    summaries = await repo.list_systems()
    views = [
        SystemView(
            summary=summary,
            label=_system_label(summary.resource_address),
            address_slug=_system_slug(summary.resource_address),
        )
        for summary in summaries
    ]
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

    return templates.TemplateResponse(
        request,
        "sessions.html",
        {
            "sessions": [_session_view(s) for s in sessions_list],
            "system_label": _system_label(resource_address),
            "system_slug": address_slug,
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
    allowlisted stored columns are rendered.

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

    return templates.TemplateResponse(
        request,
        "session.html",
        {
            "session": _session_view(session),
            "system_label": _system_label(session.resource_address),
            "system_slug": _system_slug(session.resource_address),
            "has_cast": has_cast,
            "findings": findings,
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
