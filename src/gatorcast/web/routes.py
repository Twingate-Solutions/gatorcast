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
pages into a 22-column CSV (spec §9; columns 16–22 per WEBAPP_SPEC §8.7).

Web apps (WEBAPP_SPEC §8.4–§8.7): a ``web`` search row is one connection
(``_web_item_view``); the systems list adds the ``Web`` badge and the configured-TLS
badge and marker of the newest web request; the system page adds a Web activity
table and a "Configured web app TLS (from gwops)" block; ``/systems/{slug}/web`` is
the visit view. Every TLS badge, upstream marker, and managed marker comes from a
fixed map keyed by the stored value, with a static tooltip: stored text never
becomes a label, class, tooltip, or URL. TLS is the **configured** state gwops
reported, never proof of the negotiated mode. ``gwops_app`` and
``gwops_gateway_id`` are display-only escaped text, never part of a URL, class, or
filter, and never logged; no URL (masked or not) is logged either.

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
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote_to_bytes, urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict

from gatorcast.logging import get_logger
from gatorcast.models import GwopsSnapshot, Session
from gatorcast.pipeline.activity import (
    ActivitySession,
    Command,
    group_activity,
    group_commands,
    is_discovery,
    request_path,
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
    KIND_WEB,
    SOURCE_API_COMMANDS,
    SOURCE_WEB,
    CommandHit,
    Cursor,
    CursorMismatch,
    RecordingHit,
    TimelinePage,
    UnifiedQuery,
    build_sources,
    request_tls_modes,
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
    SCHEME_VALUES,
    STATUS_VALUES,
    UPSTREAM_VALUES,
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
# Shown when a system page's kubectl or web table hit the row cap. The read orders by
# user_key, then time, so the cap drops whole users at the end of that order (not the
# oldest rows). Fixed text; ``n`` is the module constant above.
_ACTIVITY_CAP_TEXT = (
    "Showing the first {n:,} requests in this window, ordered by user; users later "
    "in the list may be omitted."
)

# ``user`` query value that selects the NULL user_key bucket (requests that carried
# neither a user id nor a username). Mirrors ``_UNKNOWN_SLUG`` for systems.
_UNKNOWN_USER = "_unknown"

# Upper bound on a ``user`` query value. Real user keys are a Twingate user id or a
# username (email); anything longer is rejected rather than queried.
_MAX_USER_KEY_LEN = 512

# Web apps (WEBAPP_SPEC §8.5). Route-module constants, not settings: the most
# distinct gwops configurations one "Configured web app TLS" block lists (a notice
# says when more exist), and the most requests one visit view reads (a notice says
# when the visit was cut short).
_WEB_CONFIG_MAX = 10
_WEB_VISIT_MAX_REQUESTS = 2000


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
    """One fixed badge or marker: label, CSS class, and tooltip are fixed strings.

    Used for the systems index Type badges and for every configured-TLS badge,
    upstream marker, and managed marker (WEBAPP_SPEC §8.4). Every value comes from a
    map in this module keyed by a stored value; stored text never becomes a label,
    class, or tooltip.

    Attributes:
        label: Display text.
        css_class: CSS class (``pill-*`` for badges, ``marker-*`` for markers).
        title: Static tooltip text, or ``None`` for no tooltip.
        is_marker: True for an upstream marker (rendered as a marker, not a pill).
    """

    model_config = ConfigDict(frozen=True)

    label: str
    css_class: str
    title: str | None = None
    is_marker: bool = False


# Type badges (spec §7.5, §8.4; WEBAPP_SPEC §8.5), in display order.
_SSH_BADGE = SystemBadge(label="SSH", css_class="pill-ssh")
_KUBERNETES_BADGE = SystemBadge(label="Kubernetes", css_class="pill-kubectl")
_WEB_BADGE = SystemBadge(label="Web", css_class="pill-web")

# Configured-TLS presentation (WEBAPP_SPEC §8.4). Configured state from gwops, not
# proof (GW-23): every tooltip says so. Keyed by the stored value; nothing stored is
# interpolated into a label, class, or tooltip.
_CONFIGURED_NOTE = (
    "TLS mode gwops reported as configured when the connection was authenticated; "
    "not proof of the negotiated mode."
)
_UPSTREAM_CONFIGURED_NOTE = (
    "upstream TLS mode gwops reported as configured when the connection was "
    "authenticated; not proof of the negotiated mode."
)
_DOWNSTREAM_TLS_BADGES: dict[str, SystemBadge] = {
    "tls13": SystemBadge(
        label="HTTPS", css_class="pill-https", title=f"HTTPS (configured): {_CONFIGURED_NOTE}"
    ),
    "none": SystemBadge(
        label="HTTP", css_class="pill-http", title=f"HTTP (configured): {_CONFIGURED_NOTE}"
    ),
}
_TLS_UNKNOWN_BADGE = SystemBadge(
    label="TLS unknown",
    css_class="pill-tls-unknown",
    title=(
        "No configured TLS data for this connection (no gwops data, or gwops found "
        "no single matching web app)."
    ),
)
# A stored mode outside the known vocabulary (a row written by another version, or a
# corrupted value) gets its own warning marker, never the "TLS unknown" (NULL) badge or
# the no-marker look of ``verify_full``. Fixed text: the stored value is never shown.
_UNRECOGNISED_TLS_BADGE = SystemBadge(
    label="Unrecognised TLS mode",
    css_class="marker-warn",
    title=(
        "The stored configured client TLS mode is not one Gatorcast recognises; "
        "treat this connection's TLS as unknown."
    ),
    is_marker=True,
)
_UNRECOGNISED_UPSTREAM_MARKER = SystemBadge(
    label="Unrecognised upstream TLS mode",
    css_class="marker-warn",
    title=(
        "The stored configured upstream TLS mode is not one Gatorcast recognises; "
        "treat this connection's upstream TLS as unknown."
    ),
    is_marker=True,
)
# ``verify_full`` and NULL have no marker; any other unknown value gets
# ``_UNRECOGNISED_UPSTREAM_MARKER``.
_UPSTREAM_TLS_MARKERS: dict[str, SystemBadge] = {
    "none": SystemBadge(
        label="Plaintext upstream",
        css_class="marker-warn",
        title=f"Plaintext upstream (configured): {_UPSTREAM_CONFIGURED_NOTE}",
        is_marker=True,
    ),
    "insecure": SystemBadge(
        label="Unverified upstream",
        css_class="marker-warn",
        title=f"Unverified upstream (configured): {_UPSTREAM_CONFIGURED_NOTE}",
        is_marker=True,
    ),
    "verify_ca": SystemBadge(
        label="CA-only upstream",
        css_class="marker-info",
        title=f"CA-only upstream (configured): {_UPSTREAM_CONFIGURED_NOTE}",
        is_marker=True,
    ),
}
# Stored ``connections.gwops_managed`` (read as a bool) → managed marker (§8.5).
_MANAGED_MARKERS: dict[bool, SystemBadge] = {
    True: SystemBadge(
        label="managed",
        css_class="pill-managed",
        title="Managed by gwops (as gwops reported when the connection was authenticated).",
    ),
    False: SystemBadge(
        label="unmanaged",
        css_class="pill-unmanaged",
        title=(
            "Not managed by gwops; the name is the Twingate resource name (as gwops "
            "reported when the connection was authenticated)."
        ),
    ),
}
# Upstream mode text on the configuration block's ``exact`` line, keyed by the
# stored value (the text is fixed even though it matches the stored vocabulary).
_UPSTREAM_MODE_TEXT: dict[str, str] = {
    "verify_full": "verify_full",
    "verify_ca": "verify_ca",
    "insecure": "insecure",
    "none": "none",
}
_UNKNOWN_MODE_TEXT = "unknown"
_UNRECOGNISED_MODE_TEXT = "unrecognised"
# Stored ``upstream_tls`` values with no marker (verified upstream).
_UPSTREAM_NO_MARKER: frozenset[str] = frozenset({"verify_full"})

# Stored modes → the CSV / filter vocabulary (WEBAPP_SPEC §8.3, §8.7). Anything else,
# NULL included, exports as ``unknown``.
_CSV_SCHEME: dict[str, str] = {"tls13": "https", "none": "http"}
_CSV_UPSTREAM: dict[str, str] = {
    "verify_full": "verified",
    "verify_ca": "ca_only",
    "insecure": "unverified",
    "none": "plaintext",
}
_CSV_UNKNOWN = "unknown"
assert {*_CSV_SCHEME.values(), _CSV_UNKNOWN} == set(SCHEME_VALUES), "CSV scheme vocabulary"
assert {*_CSV_UPSTREAM.values(), _CSV_UNKNOWN} == set(UPSTREAM_VALUES), "CSV upstream vocabulary"

# Fixed texts for web rows and the configuration block (WEBAPP_SPEC §8.5).
_UNNAMED_APP_TEXT = "(unnamed)"
_NO_GATEWAY_ID_TEXT = "gateway id not yet assigned"
_WEB_CONFIG_HEADING = "Configured web app TLS (from gwops)"
_WEB_CONFIG_MORE_TEXT = "More configurations not shown."
_WEB_CONFIG_FOOTNOTE = (
    "Configured state reported by gwops when each connection was authenticated; not "
    "proof of the negotiated mode. After a TLS change, connections on an older token "
    "can differ for up to about 55 minutes."
)
# ``match: none`` also arises "for want of data" (gwops behaviour doc §7: no tenant
# listing has succeeded yet, including while gateway_id is null), so the text does not
# claim the address has no web app. With an id, the line reads ``text`` + id +
# ``text_after``; without one, ``text`` alone.
_GWOPS_NONE_TEXT = "gwops matched no web app at this address on gateway"
_GWOPS_NONE_AFTER_ID_TEXT = "(or had not yet read the tenant's web apps)"
_GWOPS_AMBIGUOUS_TEXT = "gwops found more than one web app at this address on gateway"
_GWOPS_NONE_NO_ID_TEXT = (
    "gwops matched no web app at this address (or had not yet read the tenant's web "
    "apps); gateway id not yet assigned"
)
_GWOPS_AMBIGUOUS_NO_ID_TEXT = (
    "gwops found more than one web app at this address (gateway id not yet assigned)"
)
_GWOPS_NO_DATA_TEXT = "No gwops data on these connections"

# Status label for a WebSocket upgrade in the visit view (§8.5).
_WEBSOCKET_STATUS = 101
_WEBSOCKET_STATUS_LABEL = "101 WebSocket"

# Systems list column labels (WEBAPP_SPEC §8.5).
_REQUESTS_HEADING = "Requests"
_LAST_REQUEST_HEADING = "Last request"


def _scheme_badge(downstream_tls: str | None) -> SystemBadge:
    """Return the configured client-TLS badge for a stored ``downstream_tls`` (§8.4).

    ``tls13`` → ``HTTPS``; ``none`` → ``HTTP``; NULL → ``TLS unknown``; any other
    stored value → the ``Unrecognised TLS mode`` warning marker.
    """
    if downstream_tls is None:
        return _TLS_UNKNOWN_BADGE
    return _DOWNSTREAM_TLS_BADGES.get(downstream_tls, _UNRECOGNISED_TLS_BADGE)


def _upstream_marker(upstream_tls: str | None) -> SystemBadge | None:
    """Return the configured upstream-TLS marker for a stored ``upstream_tls`` (§8.4).

    ``none`` / ``insecure`` → a warning marker; ``verify_ca`` → an info marker;
    ``verify_full`` or NULL → no marker; any other stored value → the
    ``Unrecognised upstream TLS mode`` warning marker (never the verified look).
    """
    if upstream_tls is None or upstream_tls in _UPSTREAM_NO_MARKER:
        return None
    return _UPSTREAM_TLS_MARKERS.get(upstream_tls, _UNRECOGNISED_UPSTREAM_MARKER)


# Unicode categories percent-encoded in displayed URLs/paths (fix D): control (Cc),
# format (Cf: bidi overrides/isolates such as U+202E, zero-width characters), and
# line / paragraph separators (Zl, Zp). Any of them can visually disguise an audit row.
_DISPLAY_ESCAPE_CATEGORIES: frozenset[str] = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _display_url(value: str | None) -> str | None:
    """Return a stored URL or path in a display-safe form (view building only).

    Every character in Unicode category Cc, Cf, Zl, or Zp (``\\n``, ``\\t``,
    U+202E RIGHT-TO-LEFT OVERRIDE, zero-width spaces and joiners, U+2028, …) is
    replaced by its UTF-8 percent-encoding (``%E2%80%AE``), so it is visible and
    cannot reorder or hide the surrounding text. Everything else, ``%`` included, is
    unchanged. Storage, search matching, and the CSV export keep the stored value;
    the template still autoescapes the result (never ``|safe``).

    Args:
        value: The stored URL or path, or ``None``.

    Returns:
        The display string, or ``None`` for ``None``.
    """
    if value is None:
        return None
    if not any(unicodedata.category(ch) in _DISPLAY_ESCAPE_CATEGORIES for ch in value):
        return value
    return "".join(
        quote(ch, safe="") if unicodedata.category(ch) in _DISPLAY_ESCAPE_CATEGORIES else ch
        for ch in value
    )


def _managed_marker(managed: bool | None) -> SystemBadge | None:
    """Return the managed / unmanaged marker for a stored ``gwops_managed``, or ``None``."""
    if managed is None:
        return None
    return _MANAGED_MARKERS[bool(managed)]


def _gateway_title(gateway_id: str | None) -> str:
    """Return the app element's tooltip: ``gateway <id>``, or the fixed no-id text.

    The id is charset-restricted at ingest and rendered only through autoescape in a
    double-quoted attribute (WEBAPP_SPEC §8.5, §10).
    """
    return f"gateway {gateway_id}" if gateway_id is not None else _NO_GATEWAY_ID_TEXT


class RequestLink(BaseModel):
    """One per-kind link in the systems list's Requests column (WEBAPP_SPEC §8.5).

    ``text`` is built from a count and a fixed kind word (``"412 kubectl"``); the
    template adds the ``›``. ``url`` is built with :func:`search_url`.
    """

    model_config = ConfigDict(frozen=True)

    kind: str
    count: int
    text: str
    url: str


class SystemView(BaseModel):
    """Presentation wrapper for one system row on the systems index.

    ``sessions_url`` lists the system's recordings and failed connections
    (``type=recordings``, matching ``session_count``); ``api_url`` (kept for
    existing templates) and ``kubectl_url`` list its kubectl commands
    (``type=kubectl``); ``web_url`` lists its web connections (``type=web``).
    ``request_links`` holds one :class:`RequestLink` per kind present (kubectl, then
    web). ``last_request_url`` is the link behind "Last request": the one kind's
    search when the system has a single API kind, else every kind on the system.
    ``badges`` is in display order: SSH, Kubernetes, Web, then for web systems the
    configured-TLS badge and the upstream marker of the newest web request.
    ``tls_badge`` / ``upstream_marker`` repeat those two (``None`` for non-web
    systems or no marker). Every URL is built with :func:`search_url`.
    """

    summary: SystemSummary
    label: str
    address_slug: str
    badges: list[SystemBadge]
    sessions_url: str
    api_url: str
    kubectl_url: str
    web_url: str
    request_links: list[RequestLink]
    last_request_url: str | None
    tls_badge: SystemBadge | None = None
    upstream_marker: SystemBadge | None = None


def _system_label(resource_address: str | None) -> str:
    """Return the display label for a system, mapping NULL to the unknown bucket."""
    return resource_address if resource_address else _UNKNOWN_LABEL


def _search_system(resource_address: str | None) -> str:
    """Return the ``/search`` ``system`` value for a system (NULL → the unknown sentinel)."""
    return resource_address if resource_address else UNKNOWN_SYSTEM


def _system_badges(summary: SystemSummary) -> list[SystemBadge]:
    """Return a system's Type badges and markers, in display order (spec §7.5, WEBAPP_SPEC §8.5).

    ``SSH`` when it has an SSH recording (``ssh_count > 0``, which requires recording
    data); ``Kubernetes`` when it has exec recordings or kubectl requests (never for
    a web-only system); ``Web`` when it has web requests, followed by the configured
    client-TLS badge and the upstream marker (if any) of its newest web request. A
    system with only start-only ``error`` rows gets none.
    """
    badges: list[SystemBadge] = []
    if summary.has_ssh:
        badges.append(_SSH_BADGE)
    if summary.has_kubernetes:
        badges.append(_KUBERNETES_BADGE)
    if summary.has_web:
        badges.append(_WEB_BADGE)
        badges.append(_scheme_badge(summary.web_downstream_tls))
        marker = _upstream_marker(summary.web_upstream_tls)
        if marker is not None:
            badges.append(marker)
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
    with ``safe=""``, so ``/``, ``?``, ``#``, ``%``, and spaces are all encoded and
    the address is one path segment. ``/systems/…`` routing reads the raw (still
    encoded) path to split it back (:func:`_split_system_path`), so an address
    containing ``/`` (a CIDR) round-trips.

    Args:
        resource_address: The target system address, or ``None`` for the unknown
            bucket.

    Returns:
        A URL-safe path segment.
    """
    if not resource_address:
        return _UNKNOWN_SLUG
    return quote(resource_address, safe="")


def _slug_to_address(address: str) -> str | None:
    """Map a **decoded** system path segment to a resource_address.

    The segment arrives already percent-decoded once (the server decodes the path,
    or :func:`_split_system_path` decodes the raw segment), so it is not decoded a
    second time: an address containing ``%`` stays intact.

    Args:
        address: The decoded path segment.

    Returns:
        The resource_address, or ``None`` for the unknown-bucket sentinel.
    """
    if address == _UNKNOWN_SLUG:
        return None
    return address


# Sub-pages of ``/systems/{slug}`` (the last raw path segment).
_SYSTEM_SUBPAGES: frozenset[str] = frozenset({"activity", "web"})
_SYSTEMS_PREFIX = "/systems/"


def _split_system_path(request: Request, rest: str) -> tuple[str, str]:
    """Split ``/systems/<rest>`` into ``(decoded address segment, sub-page)``.

    ``sub-page`` is ``""`` (system page), ``"activity"``, or ``"web"``. The server
    decodes ``%2F`` to ``/`` before routing, so the decoded ``rest`` cannot tell an
    address containing ``/`` from a sub-page. The raw path (``scope["raw_path"]``)
    still holds the encoded slug, so it is split on literal ``/`` first:

    * one raw segment → the system page for that segment, decoded once;
    * two raw segments ending in a literal ``activity`` / ``web`` → that sub-page.

    The raw segment is decoded here, not taken from ``rest``, because the raw bytes
    are what the client sent (Starlette's ``TestClient``, unlike uvicorn, decodes
    ``scope["path"]`` twice). Anything else (no usable raw path, or a link written
    with literal slashes) falls back to the decoded ``rest``: a trailing
    ``/activity`` or ``/web`` selects the sub-page, else the whole of ``rest`` is
    the address.

    Args:
        request: The incoming request.
        rest: The decoded remainder after ``/systems/`` (the ``path`` converter).

    Returns:
        ``(address segment, sub-page)``; the segment is decoded exactly once.
    """
    raw = request.scope.get("raw_path")
    if isinstance(raw, bytes):
        try:
            raw_str = raw.decode("ascii")
            idx = raw_str.find(_SYSTEMS_PREFIX)
            if idx >= 0:
                parts = raw_str[idx + len(_SYSTEMS_PREFIX):].split("/")
                if len(parts) == 1:
                    return unquote_to_bytes(parts[0]).decode("utf-8"), ""
                if len(parts) == 2 and parts[1] in _SYSTEM_SUBPAGES:
                    return unquote_to_bytes(parts[0]).decode("utf-8"), parts[1]
        except UnicodeDecodeError:
            pass  # not ASCII / not UTF-8 once decoded: use the decoded path below
    head, sep, last = rest.rpartition("/")
    if sep and last in _SYSTEM_SUBPAGES:
        return head, last
    return rest, ""


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
        "url": _display_url(row.url),
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
        "path": _display_url(command.primary_path),
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


# --- web apps: presentation (WEBAPP_SPEC §8.4, §8.5) ---------------------------------


def _no_discovery(method: str, url: str) -> bool:
    """Discovery predicate for web rows: never discovery (WEBAPP_SPEC §7.2)."""
    return False


def _web_visit_url(address_slug: str, user_key: str | None, from_: str, to: str) -> str:
    """Build the self-describing visit-view URL (``/systems/{slug}/web``).

    Built with ``urlencode`` from stored keys only (user key and two stored
    ``requested_at`` bounds). No gwops value or URL ever enters it.

    Args:
        address_slug: The system's URL path segment (already slug-encoded).
        user_key: The user key, or ``None`` for the unknown bucket.
        from_: Inclusive lower bound (a stored ``requested_at``).
        to: Inclusive upper bound (a stored ``requested_at``).

    Returns:
        ``/systems/{slug}/web?user=…&from=…&to=…`` with every value URL-encoded.
    """
    pairs = [("user", _user_param(user_key)), ("from", from_), ("to", to)]
    return f"/systems/{address_slug}/web?{urlencode(pairs)}"


def _status_label(status_code: int | None) -> str | None:
    """Return a request's status text: ``101 WebSocket`` for 101, else the code, else ``None``."""
    if status_code is None:
        return None
    if status_code == _WEBSOCKET_STATUS:
        return _WEBSOCKET_STATUS_LABEL
    return str(status_code)


def _is_error_status(status_code: int | None) -> bool:
    """True for a 4xx/5xx status (``400 <= status <= 599``); a NULL status is not counted."""
    return status_code is not None and 400 <= status_code <= 599


def _web_request_view(
    row: ApiRequestRow, findings: Mapping[str, list[ApiFindingRow]]
) -> dict[str, object]:
    """Build one request line of a web connection's request list.

    The stored URL (normalized path, masked query) plus time, method, status, and
    outcome. Keys match :func:`_request_view` so the shared request table renders
    it; ``is_discovery`` is always False (no discovery for web, WEBAPP_SPEC §7.2).
    Never ``user_agent`` or any header value.
    """
    return {
        "request_id": row.request_id,
        "requested_at": row.requested_at,
        "method": row.method,
        "url": _display_url(row.url),
        "status_code": row.status_code,
        "status_label": _status_label(row.status_code),
        "outcome": row.outcome,
        "is_discovery": False,
        "finding_labels": [f.label for f in findings.get(row.request_id, [])],
    }


def _web_activity_view(
    visit: ActivitySession,
    rows_by_id: Mapping[str, ApiRequestRow],
    address_slug: str,
) -> dict[str, object]:
    """Build one row of the system page's Web activity table (WEBAPP_SPEC §8.5).

    ``connection_count`` is the distinct ``conn_id``\\s over the visit's rows;
    ``error_count`` counts 4xx/5xx statuses (a failed row with no status is not
    counted). Aggregates only; no URL, header, or gwops value.
    """
    rows = [rows_by_id[rid] for rid in visit.request_ids if rid in rows_by_id]
    return {
        "user_key": visit.user_key,
        "user_label": _user_label(visit.username, visit.user_key),
        "user_search_url": _user_search_url(visit.username, visit.user_key),
        "started_at": visit.started_at,
        "ended_at": visit.ended_at,
        "duration_seconds": visit.duration_seconds,
        "duration_display": _duration_display(visit.duration_seconds),
        "connection_count": len({r.conn_id for r in rows}),
        "request_count": visit.request_count,
        "error_count": sum(1 for r in rows if _is_error_status(r.status_code)),
        "url": _web_visit_url(address_slug, visit.user_key, visit.started_at, visit.ended_at),
    }


_EMPTY_SNAPSHOT = GwopsSnapshot()

# A configuration's grouping key (WEBAPP_SPEC §8.5): match, gateway id, app, managed,
# downstream mode and port, upstream mode and port.
_ConfigKey = tuple[
    str | None, str | None, str | None, bool | None, str | None, int | None, str | None, int | None
]


def _config_key(snap: GwopsSnapshot) -> _ConfigKey:
    """Return the grouping key of one connection's snapshot."""
    return (
        snap.gwops_match,
        snap.gwops_gateway_id,
        snap.gwops_app,
        snap.gwops_managed,
        snap.downstream_tls,
        snap.downstream_port,
        snap.upstream_tls,
        snap.upstream_port,
    )


def _web_config_line(
    snap: GwopsSnapshot, connection_count: int, first_at: str, last_at: str
) -> dict[str, object]:
    """Build one line of the "Configured web app TLS (from gwops)" block.

    Structured parts only (no HTML): fixed texts and badges from this module's maps,
    plus the stored gwops values as plain text for autoescaped rendering. ``match``
    is ``exact`` / ``none`` / ``ambiguous`` / ``no_data``. A rejected object was
    stored as no object, so it reads ``no_data`` (WEBAPP_SPEC §13 Q19); there is no
    rejected or invalid state.

    For ``exact``: ``tls_badge``, ``downstream_port``, ``upstream_mode`` (fixed text),
    ``upstream_marker``, ``upstream_port``, ``app_label`` (the name, else
    ``(unnamed)``), ``managed_marker``, and ``gateway_label`` (``gateway <id>``, else
    the fixed no-id text). For ``none`` / ``ambiguous``: ``text`` (fixed),
    ``gateway_id`` (rendered after ``text`` when present), and for ``none`` with an
    id ``text_after`` (fixed, rendered after the id; ``None`` otherwise). For
    ``no_data``: ``text``. An unrecognised stored mode yields the fixed
    "Unrecognised" badge / marker and ``upstream_mode`` ``unrecognised``.
    """
    match = snap.gwops_match
    line: dict[str, object] = {
        "match": match if match in ("exact", "none", "ambiguous") else "no_data",
        "connection_count": connection_count,
        "first_at": first_at,
        "last_at": last_at,
        "tls_badge": _scheme_badge(snap.downstream_tls),
        "upstream_marker": _upstream_marker(snap.upstream_tls),
        "downstream_port": None,
        "upstream_mode": None,
        "upstream_port": None,
        "app_label": None,
        "app_unnamed": False,
        "managed_marker": None,
        "gateway_id": snap.gwops_gateway_id if match is not None else None,
        "gateway_label": None,
        "text": None,
        "text_after": None,
    }
    if match == "exact":
        line.update(
            {
                "downstream_port": snap.downstream_port,
                "upstream_mode": (
                    _UPSTREAM_MODE_TEXT.get(snap.upstream_tls, _UNRECOGNISED_MODE_TEXT)
                    if snap.upstream_tls is not None
                    else _UNKNOWN_MODE_TEXT
                ),
                "upstream_port": snap.upstream_port,
                "app_label": snap.gwops_app if snap.gwops_app is not None else _UNNAMED_APP_TEXT,
                "app_unnamed": snap.gwops_app is None,
                "managed_marker": _managed_marker(snap.gwops_managed),
                "gateway_label": _gateway_title(snap.gwops_gateway_id),
            }
        )
    elif match == "none":
        if snap.gwops_gateway_id is not None:
            line["text"] = _GWOPS_NONE_TEXT
            line["text_after"] = _GWOPS_NONE_AFTER_ID_TEXT
        else:
            line["text"] = _GWOPS_NONE_NO_ID_TEXT
    elif match == "ambiguous":
        line["text"] = (
            _GWOPS_AMBIGUOUS_TEXT
            if snap.gwops_gateway_id is not None
            else _GWOPS_AMBIGUOUS_NO_ID_TEXT
        )
    else:
        line["text"] = _GWOPS_NO_DATA_TEXT
        line["tls_badge"] = _TLS_UNKNOWN_BADGE
        line["upstream_marker"] = None
    return line


TlsModes = tuple[str | None, str | None]
"""``(downstream_tls, upstream_tls)`` as stored on one ``api_requests`` row."""


def _effective_tls(
    snap: GwopsSnapshot, row_modes: TlsModes | None
) -> tuple[str | None, str | None]:
    """Return the configured TLS pair to show for a request: row-level first (fix I).

    The row-level modes are what the ``scheme`` / ``upstream`` filters test, so they
    win when the row carries either one; a row with both NULL (or no row-level
    data read) falls back to the connection snapshot.

    Args:
        snap: The connection's gwops snapshot.
        row_modes: The row's stored ``(downstream_tls, upstream_tls)``, or ``None``.

    Returns:
        ``(downstream_tls, upstream_tls)``.
    """
    if row_modes is not None and (row_modes[0] is not None or row_modes[1] is not None):
        return row_modes
    return snap.downstream_tls, snap.upstream_tls


def _web_config_block(
    rows: Sequence[ApiRequestRow],
    snapshots: Mapping[str, GwopsSnapshot],
    row_tls: Mapping[str, TlsModes] | None = None,
) -> dict[str, object]:
    """Build the "Configured web app TLS (from gwops)" block (WEBAPP_SPEC §8.5).

    The distinct connections behind ``rows`` are grouped by their snapshot
    (:func:`_config_key`); a connection with no ``connections`` row reads as no
    gwops data. Each connection's TLS modes are those stored on its earliest row
    in ``rows`` when ``row_tls`` has them (:func:`_effective_tls`), else the
    snapshot's; ports, app, managed flag, and gateway id always come from the
    snapshot. One line per configuration, newest last request first, at most
    :data:`_WEB_CONFIG_MAX`, each with its connection count and first and last
    request time. Reads only the rows and snapshots already loaded for the page.

    Args:
        rows: The page's web request rows.
        snapshots: ``conn_id → GwopsSnapshot`` for those rows' connections.
        row_tls: ``request_id → (downstream_tls, upstream_tls)`` for (at least) each
            connection's earliest row, or ``None`` to use snapshots only.

    Returns:
        ``{heading, lines, more, more_text, footnote}``; ``lines`` is empty when
        ``rows`` is.
    """
    conn_first: dict[str, str] = {}
    conn_first_id: dict[str, str] = {}
    conn_last: dict[str, str] = {}
    for r in rows:
        if r.conn_id not in conn_first or r.requested_at < conn_first[r.conn_id]:
            conn_first[r.conn_id] = r.requested_at
            conn_first_id[r.conn_id] = r.request_id
        if r.conn_id not in conn_last or r.requested_at > conn_last[r.conn_id]:
            conn_last[r.conn_id] = r.requested_at

    groups: dict[_ConfigKey, tuple[GwopsSnapshot, set[str]]] = {}
    for conn_id in conn_first:
        snap = snapshots.get(conn_id, _EMPTY_SNAPSHOT)
        if row_tls is not None:
            ds, us = _effective_tls(snap, row_tls.get(conn_first_id[conn_id]))
            if (ds, us) != (snap.downstream_tls, snap.upstream_tls):
                snap = snap.model_copy(update={"downstream_tls": ds, "upstream_tls": us})
        groups.setdefault(_config_key(snap), (snap, set()))[1].add(conn_id)

    lines = []
    for snap, conn_ids in groups.values():
        first_at = min(conn_first[c] for c in conn_ids)
        last_at = max(conn_last[c] for c in conn_ids)
        lines.append(_web_config_line(snap, len(conn_ids), first_at, last_at))
    lines.sort(key=lambda line: (str(line["last_at"]), str(line["first_at"])), reverse=True)
    return {
        "heading": _WEB_CONFIG_HEADING,
        "lines": lines[:_WEB_CONFIG_MAX],
        "more": len(lines) > _WEB_CONFIG_MAX,
        "more_text": _WEB_CONFIG_MORE_TEXT,
        "max": _WEB_CONFIG_MAX,
        "footnote": _WEB_CONFIG_FOOTNOTE,
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
        kinds=kinds,
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
    * Web requests → ``type=web`` (WEBAPP_SPEC §8.6; the tile counts requests, the
      list shows connections).
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
            "web_requests_url": link(type=KIND_WEB),
            "web_requests_label": "Web requests",
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

# cmd focus banner (WEBAPP_SPEC §8.1: ``cmd`` focuses whichever kind holds the
# request). Fixed strings only; no stored value is interpolated.
_FOCUS_NOT_FOUND_TEXT = (
    "Command or web connection not found. It may have been removed by retention."
)
_FOCUS_HEADINGS: dict[str, str] = {
    KIND_KUBECTL: "Showing one kubectl command",
    KIND_WEB: "Showing one web connection",
}
_FOCUS_NOT_FOUND_HEADING = "Showing no command or web connection"
_FLAGGED_CAP_TEXT = (
    "More than {cap:,} flagged kubectl commands match. Narrow by system, user, or time."
)
# Scan-budget notice, by which api source(s) the budget stopped (fix K). Each source
# examines up to ``n`` rows of its own kind per page.
_SCAN_BUDGET_TEXTS: dict[frozenset[str], str] = {
    frozenset({SOURCE_API_COMMANDS}): "Scanned {n:,} kubectl requests without filling the page.",
    frozenset({SOURCE_WEB}): "Scanned {n:,} web requests without filling the page.",
    frozenset({SOURCE_API_COMMANDS, SOURCE_WEB}): (
        "Scanned {n:,} kubectl requests and {n:,} web requests without filling the page."
    ),
}
_SCAN_BUDGET_FALLBACK_TEXT = "Scanned {n:,} requests per kind without filling the page."
# Findings filters web connections cannot satisfy (fix J): no detection rule
# evaluates web requests, so these filters return no web rows.
_WEB_NO_DETECTION_TEXT = "Web connections are not evaluated by detection rules."
_WEB_NO_DETECTION_REASON = "detection"
_CONTENT_BUDGET_TEXT = "Scanned {n:,} recordings without filling the page."
_SEARCH_WINDOW_OPTIONS: list[tuple[str, str]] = [("", "—"), *_WINDOW_OPTIONS]
_MODE_OPTIONS: list[tuple[str, str]] = [("text", "text"), ("regex", "regex")]

# Exclusion reason → the kinds it applies to, for "… applies to <scope> only." Every
# other reason (status, durations, regex, sort) applies to recordings only.
_EXCLUSION_SCOPES: dict[str, str] = {
    "cmd": "kubectl commands and web connections",
    "scheme": "web connections",
    "upstream": "web connections",
}

# Web filter selects (WEBAPP_SPEC §8.3): (value, label), "Any" first. Configured TLS.
_SCHEME_OPTIONS: list[tuple[str, str]] = [
    ("", "Any"),
    ("https", "HTTPS"),
    ("http", "HTTP"),
    ("unknown", "Unknown"),
]
_UPSTREAM_OPTIONS: list[tuple[str, str]] = [
    ("", "Any"),
    ("verified", "Verified"),
    ("ca_only", "CA only"),
    ("unverified", "Unverified"),
    ("plaintext", "Plaintext"),
    ("unknown", "Unknown"),
]
assert tuple(v for v, _ in _SCHEME_OPTIONS[1:]) == SCHEME_VALUES, "scheme options = values"
assert tuple(v for v, _ in _UPSTREAM_OPTIONS[1:]) == UPSTREAM_VALUES, "upstream options = values"
_WEB_FILTER_FIELDS = ("scheme", "upstream")


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
    ``discovery=1``. Only allowlisted stored columns are exposed. The kind badge
    comes from the registry entry of ``hit.kind``.
    """
    kind = KINDS[hit.kind]
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
        "path": _display_url(hit.command.primary_path),
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


def _web_item_view(at: str, hit: CommandHit, *, focused: bool) -> dict[str, object]:
    """Build one ``web_row`` context: one web connection (WEBAPP_SPEC §8.1, §8.5).

    Allowlisted fields only: time, user, system, the primary request's method, path,
    stored URL (normalized path, masked query) and status, request count, duration,
    the listed requests, the configured-TLS badge and upstream marker (fixed maps),
    and, only for an ``exact`` gwops snapshot, the app name (``(unnamed)`` when
    NULL), the managed marker, and the gateway id with the app element's tooltip.
    Never ``user_agent`` or the command ``label`` (the User-Agent product token,
    WEBAPP_SPEC G10). gwops values never enter a URL: the Visit link carries only
    the user key and the connection's first and last ``requested_at``, and the
    Focus link only the start row's ``request_id``.
    """
    kind = KINDS[hit.kind]
    primary = hit.command.primary
    slug = _system_slug(hit.resource_address)
    username = hit.username
    user_value = username or hit.user_key
    exact = hit.gwops_match == "exact"
    findings = dict(hit.findings)
    return {
        "kind": kind.key,
        "kind_label": kind.label,
        "badge_class": kind.badge_class,
        "row_macro": kind.row_macro,
        "at": at,
        "command_id": hit.command_id,
        "focus_url": search_url(cmd=hit.command_id),
        "visit_url": _web_visit_url(slug, hit.user_key, hit.started_at, hit.ended_at),
        "open": focused,
        "method": primary.method,
        "path": _display_url(hit.command.primary_path),
        "url": _display_url(primary.url),
        "status_code": primary.status_code,
        "status_label": _status_label(primary.status_code),
        "outcome": primary.outcome,
        "started_at": hit.started_at,
        "ended_at": hit.ended_at,
        "duration_seconds": hit.duration_seconds,
        "duration_display": _duration_display(hit.duration_seconds),
        "request_count": hit.request_count,
        "listed_count": hit.listed_count,
        "requests_truncated": hit.requests_truncated,
        "finding_count": hit.finding_count,
        "max_severity": _safe_severity(hit.max_severity),
        "finding_labels": list(hit.finding_labels),
        "requests": [_web_request_view(r, findings) for r in hit.visible_requests()],
        "tls_badge": _scheme_badge(hit.downstream_tls),
        "upstream_marker": _upstream_marker(hit.upstream_tls),
        "has_app": exact,
        "app_label": (
            (hit.gwops_app if hit.gwops_app is not None else _UNNAMED_APP_TEXT) if exact else None
        ),
        "app_unnamed": exact and hit.gwops_app is None,
        "gwops_app": hit.gwops_app if exact else None,
        "gwops_gateway_id": hit.gwops_gateway_id if exact else None,
        "app_title": _gateway_title(hit.gwops_gateway_id) if exact else None,
        "managed_marker": _managed_marker(hit.gwops_managed) if exact else None,
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
    """Build the row dicts for a timeline page (search results and the dashboard feed).

    A :class:`CommandHit` is dispatched by ``hit.kind``: kubectl →
    :func:`_command_item_view` (``command_row``), web → :func:`_web_item_view`
    (``web_row``).
    """
    items: list[dict[str, object]] = []
    for item in page.items:
        if isinstance(item.data, RecordingHit):
            items.append(
                _recording_item_view(item.at, item.data, linked_command_ids=linked_command_ids)
            )
        elif isinstance(item.data, CommandHit) and item.data.kind == KIND_WEB:
            items.append(_web_item_view(item.at, item.data, focused=focused))
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
        scope = _EXCLUSION_SCOPES.get(reason, "recordings")
        notices.append(
            {
                "kinds": kinds,
                "reason": reason,
                "text": f"{subject} not searched: the {what} applies to {scope} only.",
            }
        )
    return notices


def _has_findings_filter(q: UnifiedQuery) -> bool:
    """True when ``q`` filters on findings in a way no web connection can satisfy.

    ``has_findings=true``, ``severity``, ``max_severity``, ``category``, or
    ``rule_ids``. ``has_findings=false`` is excluded: every web connection has no
    findings, so it matches them all.
    """
    return bool(
        q.has_findings is True
        or q.severity is not None
        or q.max_severity is not None
        or q.category is not None
        or q.rule_ids
    )


def _focus_context(command_id: str | None, page: TimelinePage) -> dict[str, object]:
    """Build the ``cmd`` focus banner context (WEBAPP_SPEC §8.1).

    ``cmd`` focuses whichever kind holds the request, so the banner follows the
    focused item's kind: ``kind`` is ``kubectl`` or ``web`` (``None`` when nothing
    was found), ``heading`` is a fixed string for that kind, and ``clear_url``
    returns to that kind's list (``type=kubectl`` / ``type=web``). When nothing was
    found the kind is unknown, so ``clear_url`` is the unfiltered ``/search``
    (``type=any``). Fixed strings only; the request id is never interpolated into
    any text here (``command_id`` is passed through for the template to escape).
    """
    kind = next(
        (item.data.kind for item in page.items if isinstance(item.data, CommandHit)), None
    )
    if kind not in _FOCUS_HEADINGS:
        kind = None
    return {
        "command_id": command_id,
        "kind": kind,
        "heading": _FOCUS_HEADINGS[kind] if kind is not None else _FOCUS_NOT_FOUND_HEADING,
        "not_found": page.focus_not_found,
        "not_found_text": _FOCUS_NOT_FOUND_TEXT,
        "clear_url": search_url(type=kind) if kind is not None else search_url(),
    }


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
        text = _SCAN_BUDGET_TEXTS.get(page.scan_budget_sources, _SCAN_BUDGET_FALLBACK_TEXT)
        budget_notices.append(text.format(n=page.scan_budget))
    if page.content_budget_hit:
        budget_notices.append(_CONTENT_BUDGET_TEXT.format(n=page.content_budget))

    exclusion_notices = _exclusion_notices(dict(parsed.excluded), focused=focused)
    if not focused and KIND_WEB in parsed.kinds and _has_findings_filter(q):
        exclusion_notices.append(
            {
                "kinds": [KIND_WEB],
                "reason": _WEB_NO_DETECTION_REASON,
                "text": _WEB_NO_DETECTION_TEXT,
            }
        )

    export_query = search_url(**{**params, "page_size": None})[len("/search"):]
    return {
        "items": items,
        "shown_count": len(items),
        "summary": summary,
        "exclusion_notices": exclusion_notices,
        "all_excluded": not parsed.kinds,
        "budget_notices": budget_notices,
        "flagged_cap_notice": (
            _FLAGGED_CAP_TEXT.format(cap=page.flagged_cap) if page.flagged_cap_hit else None
        ),
        "focus": _focus_context(q.cmd, page) if focused else None,
        "show_discovery": q.discovery,
        "next_url": cursor_url if not page.budget_hit else None,
        "continue_url": cursor_url if page.budget_hit else None,
        "first_page_url": search_url(**params) if parsed.cursor is not None else None,
        "export_url": f"/search/export.csv{export_query}",
    }


def _search_form_context(parsed: ParsedSearch) -> dict[str, object]:
    """Build the sticky form values and option lists for ``search.html``.

    The form never carries ``cursor`` (a submit starts at the first page) or ``cmd``
    (a submit leaves the single-command focus). ``form.scheme`` / ``form.upstream``
    hold the canonical URL values (``""`` for Any), offered by ``scheme_options`` /
    ``upstream_options`` (WEBAPP_SPEC §8.3); ``web_filters_open`` opens the "Web
    filters" ``<details>`` when either is set.
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
        "scheme": params["scheme"] or "",
        "upstream": params["upstream"] or "",
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
        "web_filters_open": any(form[name] for name in _WEB_FILTER_FIELDS),
        "scheme_options": _SCHEME_OPTIONS,
        "upstream_options": _UPSTREAM_OPTIONS,
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
        kinds=parsed.kinds,
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
    except CursorMismatch:
        # parse_unified_query already checks the cursor against the search; this is
        # defense in depth. Only a cursor mismatch becomes a 400: any other error
        # from the engine propagates as a 500. Fixed message and log, no value.
        log.warning("search.cursor_mismatch")
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
# and order; 11–15 were appended in Session 10; 16–22 in Session 12 (WEBAPP_SPEC
# §8.7). ``configured_*`` values are configured state from gwops, not proof.
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
    "resource_type",
    "configured_scheme",
    "configured_upstream_tls",
    "query",
    "gwops_gateway_id",
    "gwops_app",
    "gwops_managed",
)

# CSV column 16 for every kubectl / web row (WEBAPP_SPEC §8.7).
_CSV_RESOURCE_TYPE: dict[str, str] = {KIND_KUBECTL: "KUBERNETES", KIND_WEB: "WEB_APP"}
# Columns 17–22 of a row that is not a web connection.
_CSV_NO_WEB_CELLS: tuple[str, ...] = ("",) * 6

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
    """Build the 22 CSV cells of a recording (ssh / exec / failed).

    Columns 1–10 are exactly Session 8's (values as stored). The ``findings`` cell
    joins ``"<label>@<offset>s"`` entries with ``"; "``: rule label and offset only,
    never recorded text (CLAUDE.md rule 6). Columns 12–15 are empty. Column 16 is
    the session's stored ``resource_type`` (empty when unknown); 17–22 are empty
    (WEBAPP_SPEC §8.7).
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
        s.resource_type or "",
        *_CSV_NO_WEB_CELLS,
    ]


def _csv_command_row(hit: CommandHit) -> list[object]:
    """Build the 22 CSV cells of a kubectl command or a web connection.

    The kind comes from the hit. A web hit is built by :func:`_csv_web_row`.

    kubectl (spec §9): only allowlisted stored values: the command label
    (``Kubectl-Command``, else the User-Agent product token, else ``(unknown
    client)``; never the full User-Agent), the primary request's method, and its
    path with the query string removed (so no query value, and never
    ``command=``). API findings have no offset, so the ``findings`` cell is their
    distinct labels joined by ``"; "``. Column 16 is ``KUBERNETES``; 17–22 are empty.
    """
    if hit.kind == KIND_WEB:
        return _csv_web_row(hit)
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
        hit.kind,
        hit.label,
        hit.command.primary.method or "",
        hit.command.primary_path,
        hit.request_count,
        _CSV_RESOURCE_TYPE.get(hit.kind, ""),
        *_CSV_NO_WEB_CELLS,
    ]


def _csv_web_row(hit: CommandHit) -> list[object]:
    """Build the 22 CSV cells of a web connection (WEBAPP_SPEC §8.7).

    ``kind`` is ``web``; ``command`` is empty (never the User-Agent or its product
    token); ``method`` and ``path`` are the primary request's (the stored path, query
    removed); ``status``, ``findings``, ``max_severity`` are empty and
    ``finding_count`` is 0. Column 16 is ``WEB_APP``; 17–18 map the stored TLS modes
    to the filter vocabulary (``unknown`` for NULL); 19 is the primary request's
    masked query without ``?``; 20 is the gateway id for any non-NULL gwops match;
    21–22 are the app name and ``true``/``false`` for an ``exact`` match only. An
    absent or rejected gwops object leaves 20–22 empty (WEBAPP_SPEC §13 Q19). The
    caller passes every cell through :func:`_csv_safe`.
    """
    primary = hit.command.primary
    _, sep, query = primary.url.partition("?")
    exact = hit.gwops_match == "exact"
    managed = hit.gwops_managed if exact else None
    return [
        hit.conn_id,
        hit.username or "",
        hit.resource_address or "",
        "",
        hit.started_at,
        hit.ended_at,
        round(hit.duration_seconds, 3),
        0,
        "",
        "",
        hit.kind,
        "",
        primary.method or "",
        request_path(primary.url),
        hit.request_count,
        _CSV_RESOURCE_TYPE[KIND_WEB],
        _CSV_SCHEME.get(hit.downstream_tls or "", _CSV_UNKNOWN),
        _CSV_UPSTREAM.get(hit.upstream_tls or "", _CSV_UNKNOWN),
        query if sep else "",
        (hit.gwops_gateway_id or "") if hit.gwops_match is not None else "",
        (hit.gwops_app or "") if exact else "",
        "" if managed is None else ("true" if managed else "false"),
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

    Each row is a recording, a kubectl command, or a web connection, in page order,
    with the 22 :data:`CSV_COLUMNS`. Every cell goes through :func:`_csv_safe`.
    Recorded content is never written (CLAUDE.md rule 6). The body is UTF-8 with no
    byte-order mark (WEBAPP_SPEC §13 Q12).
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
            kinds=parsed.kinds,
        )
        # No client cursor reaches the engine here (the request's ``cursor`` is
        # validated by parse_unified_query and ignored); ``cursor`` is always one the
        # engine issued for this same query. A CursorMismatch would be an engine bug,
        # so nothing is caught: every error propagates as a 500, never a false 400.
        page = await run_timeline(
            sources,
            parsed.query,
            parsed.kinds,
            cursor=cursor,
            limit=min(_CSV_PAGE_SIZE, _CSV_EXPORT_CAP - written),
            excluded=parsed.excluded,
        )
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
    """Render the systems index (spec §8.4, WEBAPP_SPEC §8.5).

    One row per distinct ``resource_address`` with Type badges (SSH, Kubernetes,
    Web, then the newest web request's configured-TLS badge and upstream marker),
    the session count and "Last session", the Requests column (one link per kind
    present: ``N kubectl`` → ``type=kubectl``, ``N web`` → ``type=web``) and "Last
    request" (both timestamps in the ``requested_at`` format), and the recording
    findings summary. Rows are sorted by the newer of the two timestamps
    (``list_systems``). Every link into search is built with :func:`search_url`.

    Context: ``systems`` (:class:`SystemView` list), ``requests_heading``
    ("Requests"), ``last_request_heading`` ("Last request").
    """
    repo = _get_repo(request)
    summaries = await repo.list_systems()
    views = []
    for summary in summaries:
        system = _search_system(summary.resource_address)
        kubectl_url = search_url(type=KIND_KUBECTL, system=system)
        web_url = search_url(type=KIND_WEB, system=system)
        links: list[RequestLink] = []
        if summary.kubectl_request_count:
            n = summary.kubectl_request_count
            links.append(RequestLink(kind=KIND_KUBECTL, count=n, text=f"{n:,} kubectl", url=kubectl_url))
        if summary.web_request_count:
            n = summary.web_request_count
            links.append(RequestLink(kind=KIND_WEB, count=n, text=f"{n:,} web", url=web_url))
        if len(links) == 1:
            last_request_url: str | None = links[0].url
        elif links:
            last_request_url = search_url(system=system)
        else:
            last_request_url = None
        views.append(
            SystemView(
                summary=summary,
                label=_system_label(summary.resource_address),
                address_slug=_system_slug(summary.resource_address),
                badges=_system_badges(summary),
                sessions_url=search_url(type="recordings", system=system),
                api_url=kubectl_url,
                kubectl_url=kubectl_url,
                web_url=web_url,
                request_links=links,
                last_request_url=last_request_url,
                tls_badge=_scheme_badge(summary.web_downstream_tls) if summary.has_web else None,
                upstream_marker=(
                    _upstream_marker(summary.web_upstream_tls) if summary.has_web else None
                ),
            )
        )
    return templates.TemplateResponse(
        request,
        "systems.html",
        {
            "systems": views,
            "requests_heading": _REQUESTS_HEADING,
            "last_request_heading": _LAST_REQUEST_HEADING,
        },
    )


async def system_sessions(
    request: Request, resource_address: str | None, slug: str
) -> object:
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

    Web apps (WEBAPP_SPEC §8.5): when the system has web requests, the same window
    (and row cap) is read for ``api_kind = 'web'``, grouped into visits by
    ``group_activity`` (no discovery; the kubectl gap / max settings reused), and
    shown as the Web activity table (``web_activity_visits``: user, start, end,
    duration, distinct connections, requests, 4xx/5xx count, visit-view link). The
    window's distinct web connections feed the "Configured web app TLS (from gwops)"
    block (``web_config``, from :meth:`ActivityStore.gwops_for_connections`). The
    kubectl table is suppressed only for a system with web requests and no kubectl
    requests (``show_kubectl_activity``).

    Query params:
        activity_before: Optional ISO 8601 upper bound of the activity window
            (default: now). Invalid or repeated → 400.

    Args:
        request: The incoming request.
        resource_address: The system (decoded exactly once by
            :func:`system_pages`), or ``None`` for the unknown bucket.
        slug: ``_system_slug(resource_address)``: the canonical encoded segment
            every link on the page is built from.

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
    sessions_list = await repo.list_sessions(resource_address)
    has_kubectl, has_web = await repo.system_api_kinds(resource_address)
    # The kubectl table shows as before, except on a system with web requests and no
    # kubectl requests ever (WEBAPP_SPEC §8.5); the web section needs web requests.
    show_kubectl = has_kubectl or not has_web
    show_web = has_web

    settings = request.app.state.settings
    gap_s = settings.kubectl_activity_gap_seconds
    max_s = settings.kubectl_activity_max_seconds
    activity = _get_activity(request)

    rows: list[ApiRequestRow] = []
    activity_sessions: list[ActivitySession] = []
    if show_kubectl:
        rows = await activity.requests_for_system(
            resource_address, since_str, before_str, _ACTIVITY_MAX_ROWS, api_kind="kubectl"
        )
        request_ids = [r.request_id for r in rows]
        findings = await activity.findings_for_requests(request_ids)
        recordings = await activity.recordings_for_requests(request_ids)
        activity_sessions = group_activity(
            rows, gap_s, max_s, findings=findings, recordings=recordings
        )

    web_rows: list[ApiRequestRow] = []
    web_visits: list[dict[str, object]] = []
    web_config: dict[str, object] | None = None
    if show_web:
        web_rows = await activity.requests_for_system(
            resource_address, since_str, before_str, _ACTIVITY_MAX_ROWS, api_kind="web"
        )
        rows_by_id = {r.request_id: r for r in web_rows}
        web_visits = [
            _web_activity_view(v, rows_by_id, slug)
            for v in group_activity(web_rows, gap_s, max_s, discovery=_no_discovery)
        ]
        snapshots = await activity.gwops_for_connections(r.conn_id for r in web_rows)
        # Row-level TLS of each connection's earliest row in the window (fix I);
        # rows are ordered user_key, requested_at, so the first seen per conn_id is it.
        first_ids = list({r.conn_id: r.request_id for r in reversed(web_rows)}.values())
        row_tls = await request_tls_modes(request.app.state.db, first_ids)
        web_config = _web_config_block(web_rows, snapshots, row_tls)

    system = _search_system(resource_address)
    return templates.TemplateResponse(
        request,
        "sessions.html",
        {
            "sessions": [_session_view(s) for s in sessions_list],
            "system_label": _system_label(resource_address),
            "system_slug": slug,
            "search_system_url": search_url(system=system),
            "kubectl_search_url": search_url(type=KIND_KUBECTL, system=system),
            "web_search_url": search_url(type=KIND_WEB, system=system),
            "show_kubectl_activity": show_kubectl,
            "show_web_activity": show_web,
            "activity_sessions": [
                _activity_session_view(s, slug) for s in activity_sessions
            ],
            "activity_window_since": since_str,
            "activity_window_until": before_str,
            "activity_truncated": len(rows) >= _ACTIVITY_MAX_ROWS,
            "activity_max_rows": _ACTIVITY_MAX_ROWS,
            "activity_cap_notice": _ACTIVITY_CAP_TEXT.format(n=_ACTIVITY_MAX_ROWS),
            "activity_older_url": (
                f"/systems/{slug}?{urlencode([('activity_before', since_str)])}"
            ),
            "activity_latest_url": f"/systems/{slug}" if paged else None,
            "web_activity_visits": web_visits,
            "web_activity_truncated": len(web_rows) >= _ACTIVITY_MAX_ROWS,
            "web_config": web_config,
        },
    )


async def system_activity(
    request: Request, resource_address: str | None, slug: str
) -> object:
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
        request: The incoming request.
        resource_address: The system (decoded exactly once by
            :func:`system_pages`), or ``None`` for the unknown bucket.
        slug: ``_system_slug(resource_address)``: the canonical encoded segment
            every link on the page is built from.

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

    activity = _get_activity(request)
    rows = await activity.requests_in_bounds(
        resource_address, user_key, from_str, to_str, _ACTIVITY_MAX_ROWS, api_kind="kubectl"
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
            "system_slug": slug,
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
                slug, user_key, from_str, to_str, discovery=not show_discovery
            ),
            "truncated": len(rows) >= _ACTIVITY_MAX_ROWS,
            "max_rows": _ACTIVITY_MAX_ROWS,
        },
    )


def _web_visit_row(
    row: ApiRequestRow,
    snapshots: Mapping[str, GwopsSnapshot],
    row_tls: Mapping[str, TlsModes] | None = None,
) -> dict[str, object]:
    """Build one request row of the visit view (WEBAPP_SPEC §8.5).

    Time, method, stored URL (normalized path, masked query; display-escaped by
    :func:`_display_url`), status (``101 WebSocket`` for 101), outcome, the
    configured-TLS badge and upstream marker, and the first 8 characters of
    ``conn_id``. The TLS pair is the row's own stored modes when ``row_tls`` has
    them, else the connection snapshot's (:func:`_effective_tls`); a snapshot can
    differ between connections in one visit. Never ``user_agent``.
    """
    snap = snapshots.get(row.conn_id, _EMPTY_SNAPSHOT)
    downstream_tls, upstream_tls = _effective_tls(
        snap, row_tls.get(row.request_id) if row_tls is not None else None
    )
    return {
        "request_id": row.request_id,
        "requested_at": row.requested_at,
        "method": row.method,
        "url": _display_url(row.url),
        "status_code": row.status_code,
        "status_label": _status_label(row.status_code),
        "outcome": row.outcome,
        "tls_badge": _scheme_badge(downstream_tls),
        "upstream_marker": _upstream_marker(upstream_tls),
        "conn_short": row.conn_id[:8],
    }


async def system_web_visit(
    request: Request, resource_address: str | None, slug: str
) -> object:
    """Render one web visit: a user's web requests on a system within bounds.

    The visit is identified by self-describing bounds (the same parameters and
    validation as ``/systems/{slug}/activity``, minus ``discovery``). Requests are
    read with ``requests_in_bounds(…, api_kind='web')`` (inclusive bounds), at most
    :data:`_WEB_VISIT_MAX_REQUESTS`; ``truncated`` says the visit was cut short.
    Each row carries a configured-TLS badge and upstream marker from the modes stored
    on the row itself (:func:`~gatorcast.store.timeline.request_tls_modes`, what the
    search filters test), else from its connection's gwops snapshot. The "Configured
    web app TLS (from gwops)" block (``web_config``) covers the visit's connections
    only, with the same preference. Only allowlisted stored
    columns are rendered; no URL or gwops value is logged (WEBAPP_SPEC §8.5, §10).

    Query params:
        user: Required. The ``user_key``, or ``_unknown`` for the NULL bucket. Max
            512 chars, no control characters.
        from: Required. Inclusive ISO 8601 lower bound.
        to: Required. Inclusive ISO 8601 upper bound; must not precede ``from``.
        Each may be given at most once.

    Args:
        request: The incoming request.
        resource_address: The system (decoded exactly once by
            :func:`system_pages`), or ``None`` for the unknown bucket.
        slug: ``_system_slug(resource_address)``: the canonical encoded segment
            every link on the page is built from.

    Raises:
        HTTPException: ``400`` for a missing/invalid/repeated parameter or
            ``from > to``; ``404`` when no web requests fall in the bounds.
    """
    user_key = _parse_user_param(_single_param(request, "user"))
    from_dt = _parse_time_param("from", _single_param(request, "from"), required=True)
    to_dt = _parse_time_param("to", _single_param(request, "to"), required=True)
    if from_dt is None or to_dt is None:  # unreachable: required=True raises first
        raise _bad_request("'from' and 'to' are required")
    if from_dt > to_dt:
        raise _bad_request("'from' must not be after 'to'")
    from_str = to_requested_at_format(from_dt)
    to_str = to_requested_at_format(to_dt)

    activity = _get_activity(request)
    # One extra row tells a full visit of exactly the cap apart from a truncated one.
    fetched = await activity.requests_in_bounds(
        resource_address,
        user_key,
        from_str,
        to_str,
        _WEB_VISIT_MAX_REQUESTS + 1,
        api_kind="web",
    )
    if not fetched:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No web activity in these bounds"
        )
    truncated = len(fetched) > _WEB_VISIT_MAX_REQUESTS
    rows = fetched[:_WEB_VISIT_MAX_REQUESTS]

    snapshots = await activity.gwops_for_connections(r.conn_id for r in rows)
    row_tls = await request_tls_modes(request.app.state.db, (r.request_id for r in rows))
    first, last = rows[0], rows[-1]
    username = next((r.username for r in rows if r.username), None)
    duration = (
        datetime.fromisoformat(last.requested_at) - datetime.fromisoformat(first.requested_at)
    ).total_seconds()
    system = _search_system(resource_address)

    return templates.TemplateResponse(
        request,
        "web_activity.html",
        {
            "system_label": _system_label(resource_address),
            "system_slug": slug,
            "system_url": f"/systems/{slug}",
            "web_search_url": search_url(type=KIND_WEB, system=system),
            "user_key": user_key,
            "user_label": _user_label(username, user_key),
            "user_search_url": _user_search_url(username, user_key),
            "span_from": first.requested_at,
            "span_to": last.requested_at,
            "duration_seconds": duration,
            "duration_display": _duration_display(duration),
            "request_count": len(rows),
            "connection_count": len({r.conn_id for r in rows}),
            "error_count": sum(1 for r in rows if _is_error_status(r.status_code)),
            "requests": [_web_visit_row(r, snapshots, row_tls) for r in rows],
            "web_config": _web_config_block(rows, snapshots, row_tls),
            "truncated": truncated,
            "max_rows": _WEB_VISIT_MAX_REQUESTS,
        },
    )


@router.get("/systems/{rest:path}")
async def system_pages(request: Request, rest: str) -> object:
    """Route ``/systems/{slug}``, ``/systems/{slug}/activity``, and ``/systems/{slug}/web``.

    One ``path`` route so an address containing ``/`` (a CIDR, encoded ``%2F`` by
    :func:`_system_slug`) resolves: the server decodes ``%2F`` before routing, so a
    single-segment parameter would 404 and suffix routes would be ambiguous.
    :func:`_split_system_path` splits on the raw path instead, and the address
    segment is decoded exactly once (no second ``unquote``, so ``%``, ``?``, ``#``,
    and spaces survive). Every link the pages build uses ``_system_slug`` of the
    decoded address, never the incoming segment.

    Args:
        request: The incoming request.
        rest: The decoded remainder after ``/systems/``.

    Returns:
        The system page, kubectl activity page, or web visit view.

    Raises:
        HTTPException: ``404`` for an empty address segment; otherwise whatever the
            selected page raises.
    """
    if rest == "":
        # ``/systems/`` keeps redirecting to the index, as before this route existed.
        return RedirectResponse(url="/systems", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    segment, subpage = _split_system_path(request, rest)
    if segment == "":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="System not found")
    resource_address = _slug_to_address(segment)
    slug = _system_slug(resource_address)
    if subpage == "activity":
        return await system_activity(request, resource_address, slug)
    if subpage == "web":
        return await system_web_visit(request, resource_address, slug)
    return await system_sessions(request, resource_address, slug)


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
