"""Search URL parameters: strict parsing, legacy aliases, cursor, URL builder (spec §5).

``parse_unified_query`` turns a ``/search`` (or ``/search/export.csv``) request into
a :class:`ParsedSearch`: the engine-facing :class:`~gatorcast.store.timeline.UnifiedQuery`
plus the paging and presentation values the route needs (``type``, ``window``,
``mode``, ``page_size``, the decoded cursor, and the resolved kinds/exclusions).

Rules (spec §5.1–§5.3):

* Blank values are absent. Every parameter may appear at most once, except
  ``rule_ids``. Unknown parameters are ignored.
* Every failure is a ``400`` whose detail names the parameter only. The submitted
  value is never echoed, in the body or in a log line.
* Legacy names (``username``, ``resource_address``, ``started_after``,
  ``started_before``, ``keyword``, ``regex``, ``page``) are accepted and never
  emitted; combining one with its canonical twin is a ``400``. A missing ``type``
  is ``any``, also when only legacy parameters are present. ``page`` is validated
  and then ignored.
* The cursor is unsigned base64url JSON (no padding, ≤ 2048 chars), decoded with a
  strict Pydantic model and the per-source position shapes from
  :func:`gatorcast.store.timeline.check_position`. Its ``sort`` and kinds must equal
  the request's.

Layering (Ben, 2026-10-05): ``UnifiedQuery`` and ``Cursor`` are defined in
:mod:`gatorcast.store.timeline` (the store never imports ``gatorcast.web``) and
imported here. The generic query-param helpers used by the activity route
(``_bad_request``, ``_single_param``, ``_has_control_chars``, ``_parse_time_param``,
``_parse_discovery_param``) moved here from ``routes.py``, which imports them back.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Final, Literal
from urllib.parse import urlencode

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, ValidationError

from gatorcast.pipeline.detect import SEVERITY_RANK
from gatorcast.store.activity import to_requested_at_format
from gatorcast.store.timeline import (
    CURSOR_MAX_LEN,
    CURSOR_VERSION,
    KIND_KEYS,
    KIND_SOURCE,
    POSITION_DONE,
    SORT_NEWEST,
    SORTS,
    Cursor,
    Position,
    UnifiedQuery,
    check_position,
)
from gatorcast.web.kinds import TYPE_GROUPS, resolve_kinds

# --- limits and vocabularies (spec §5.1, §6.5) ----------------------------------------

# Upper bound on an ISO 8601 time-bound query value (generous for nanosecond
# fractions plus an offset); longer values are rejected before parsing.
_MAX_TIME_PARAM_LEN = 64
_MAX_SYSTEM_LEN = 512
_MAX_USER_LEN = 512
_MAX_Q_LEN = 256
_MAX_RULE_IDS = 50
MAX_PAGE_SIZE: Final = 200
"""Upper bound on ``page_size`` (``_MAX_PAGE_SIZE`` in spec §6.5)."""

UNKNOWN_SYSTEM: Final = "_unknown"
"""``system`` value selecting the NULL ``resource_address`` bucket (as system slugs)."""

DEFAULT_TYPE: Final = "any"
DEFAULT_MODE: Final = "text"
MODES: Final[tuple[str, ...]] = ("text", "regex")
WINDOW_VALUES: Final[tuple[str, ...]] = ("7", "30", "90", "all")
STATUS_VALUES: Final[tuple[str, ...]] = ("complete", "provisional", "error")
SEVERITY_VALUES: Final[tuple[str, ...]] = tuple(
    name for name, _ in sorted(SEVERITY_RANK.items(), key=lambda kv: kv[1])
)

_SLUG_RE = re.compile(r"[a-z0-9-]{1,64}", re.ASCII)  # category, rule_ids
# A command focus id: any stored request_id shape — the classify safe token (Gateway
# UUIDs match it) or the derived ``h:<32 hex>`` id.
_CMD_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}|h:[0-9a-f]{32}", re.ASCII)
_INT_RE = re.compile(r"[0-9]{1,9}", re.ASCII)
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]+", re.ASCII)

# Fixed emission order for search_url (spec §5.5). Canonical names only.
SEARCH_URL_ORDER: Final[tuple[str, ...]] = (
    "type",
    "system",
    "user",
    "window",
    "from",
    "to",
    "severity",
    "max_severity",
    "has_findings",
    "category",
    "rule_ids",
    "status",
    "min_duration",
    "max_duration",
    "q",
    "mode",
    "sort",
    "discovery",
    "page_size",
    "cmd",
    "cursor",
)
# Values search_url drops because they are the default.
_URL_DEFAULTS: Final[dict[str, str]] = {
    "type": DEFAULT_TYPE,
    "mode": DEFAULT_MODE,
    "sort": SORT_NEWEST,
    "discovery": "0",
}


# --- generic query-param helpers (moved from routes.py) -------------------------------


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


# --- cursor (spec §5.4) ---------------------------------------------------------------


class _CursorModel(BaseModel):
    """Strict wire shape of a cursor; positions are checked by ``check_position``."""

    model_config = ConfigDict(extra="forbid", strict=True)

    v: int
    sort: str
    k: list[str]
    p: dict[str, list[object] | Literal["done"]]


def _reject_constant(name: str) -> object:
    """``json.loads`` hook: reject ``NaN``/``Infinity`` literals."""
    raise ValueError("non-finite number")


def encode_cursor(cursor: Cursor) -> str:
    """Encode a cursor as unpadded base64url JSON (spec §5.4).

    Args:
        cursor: The cursor to encode. ``kinds`` is written sorted.

    Returns:
        The URL-safe cursor string.

    Raises:
        ValueError: If the encoded cursor would exceed :data:`CURSOR_MAX_LEN`.
    """
    payload = {
        "v": CURSOR_VERSION,
        "sort": cursor.sort,
        "k": sorted(cursor.kinds),
        "p": {
            source: (POSITION_DONE if pos == POSITION_DONE else list(pos))
            for source, pos in cursor.positions.items()
        },
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    token = base64.urlsafe_b64encode(raw.encode("ascii")).rstrip(b"=").decode("ascii")
    if len(token) > CURSOR_MAX_LEN:
        raise ValueError("cursor too long")
    return token


def decode_cursor(raw: str) -> Cursor:
    """Decode and strictly validate a cursor string (spec §5.4).

    Checks: length ≤ :data:`CURSOR_MAX_LEN`; base64url alphabet; JSON with no
    non-finite numbers; exactly the keys ``v``/``sort``/``k``/``p``; ``v`` = 1;
    ``sort`` a known sort; ``k`` a non-empty, sorted, duplicate-free list of known
    kinds; ``p`` keys limited to the sources of ``k``; each value ``"done"`` or a
    position of the right shape for its source and sort.

    Args:
        raw: The cursor query value.

    Returns:
        The decoded :class:`Cursor` (positions as tuples).

    Raises:
        ValueError: On any failure. The message never contains the value.
    """
    if not raw or len(raw) > CURSOR_MAX_LEN or _B64URL_RE.fullmatch(raw) is None:
        raise ValueError("cursor is not base64url")
    try:
        data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        obj = json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
        model = _CursorModel.model_validate(obj)
    except (binascii.Error, UnicodeDecodeError, ValueError, ValidationError):
        raise ValueError("cursor is malformed") from None
    if type(model.v) is not int or model.v != CURSOR_VERSION:
        raise ValueError("cursor version")
    if model.sort not in SORTS:
        raise ValueError("cursor sort")
    kinds = model.k
    if not kinds or kinds != sorted(set(kinds)) or any(k not in KIND_KEYS for k in kinds):
        raise ValueError("cursor kinds")
    sources = {KIND_SOURCE[k] for k in kinds}
    positions: dict[str, Position | Literal["done"]] = {}
    for source, value in model.p.items():
        if source not in sources:
            raise ValueError("cursor source")
        positions[source] = (
            POSITION_DONE if value == POSITION_DONE else check_position(source, model.sort, value)
        )
    return Cursor(sort=model.sort, kinds=tuple(kinds), positions=positions)


# --- URL builder (spec §5.5) -----------------------------------------------------------


def _format_number(value: float) -> str:
    """Render a duration for a URL: ``60`` rather than ``60.0``."""
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def _url_value(name: str, value: object) -> str | None:
    """Render one search_url value as a string, or ``None`` to drop it."""
    if value is None:
        return None
    if isinstance(value, bool):
        if name == "has_findings":
            return "true" if value else "false"
        if name == "discovery":
            return "1" if value else "0"
        raise TypeError(f"search_url: {name} does not take a bool")
    if isinstance(value, (int, float)):
        return _format_number(value) if name in ("min_duration", "max_duration") else str(value)
    if isinstance(value, str):
        return value or None
    raise TypeError(f"search_url: unsupported value type for {name}")


def search_url(**params: object) -> str:
    """Build a ``/search`` URL from canonical parameters (spec §5.5).

    The only way the UI builds a ``/search`` link. Names are emitted in the fixed
    :data:`SEARCH_URL_ORDER`; ``None``, empty strings, and default values
    (``type=any``, ``mode=text``, ``sort=newest``, ``discovery=0``) are dropped.
    ``window`` is emitted as given, including ``window=all``. ``rule_ids`` takes an
    iterable and is emitted repeated. Values are URL-encoded with ``urlencode``.

    Keyword names use the canonical parameter names; ``from`` is a Python keyword,
    so pass it as ``from_`` (or ``**{"from": …}``).

    Args:
        **params: Canonical parameter values (``str``, ``int``, ``float``,
            ``bool`` for ``has_findings``/``discovery``, an iterable of ``str`` for
            ``rule_ids``, or ``None``).

    Returns:
        ``/search`` with an encoded query string, or bare ``/search``.

    Raises:
        TypeError: For a non-canonical name (legacy names are never emitted) or an
            unsupported value type.
    """
    if "from_" in params:
        if "from" in params:
            raise TypeError("search_url: give 'from' or 'from_', not both")
        params["from"] = params.pop("from_")
    unknown = set(params) - set(SEARCH_URL_ORDER)
    if unknown:
        raise TypeError(f"search_url: non-canonical parameter(s): {sorted(unknown)}")
    pairs: list[tuple[str, str]] = []
    for name in SEARCH_URL_ORDER:
        if name not in params:
            continue
        value = params[name]
        if name == "rule_ids":
            if value is None:
                continue
            if isinstance(value, str) or not isinstance(value, Iterable):
                raise TypeError("search_url: rule_ids takes an iterable of strings")
            pairs.extend(("rule_ids", str(rid)) for rid in value if rid)
            continue
        rendered = _url_value(name, value)
        if rendered is None or _URL_DEFAULTS.get(name) == rendered:
            continue
        pairs.append((name, rendered))
    return f"/search?{urlencode(pairs)}" if pairs else "/search"


# --- parsed request --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParsedSearch:
    """A validated ``/search`` request.

    Attributes:
        query: The engine-facing query (``query.kinds`` is the ``type`` group).
        type: The canonical ``type`` value (default ``any``).
        window: ``7``/``30``/``90``/``all`` when given, else ``None``. When set,
            ``query.from_`` holds the computed cutoff (``None`` for ``all``).
        mode: ``text`` or ``regex`` (the ``q`` interpretation).
        page_size: Items per page (``page_size`` or the configured default).
        page_size_explicit: True when ``page_size`` was given in the URL.
        cursor: The decoded cursor, or ``None`` for the first page.
        kinds: Kinds to query after applicability exclusions.
        excluded: Excluded kind → reason (see ``gatorcast.web.kinds.resolve_kinds``).
    """

    query: UnifiedQuery
    type: str
    window: str | None
    mode: str
    page_size: int
    page_size_explicit: bool
    cursor: Cursor | None
    kinds: frozenset[str]
    excluded: dict[str, str] = field(default_factory=dict)

    def url_params(self) -> dict[str, object]:
        """Return the canonical parameters of this search, for :func:`search_url`.

        ``cursor`` is not included (add it for **Next ›**; omit it for **First
        page**). ``window`` is emitted instead of the ``from`` it computed.
        ``page_size`` is included only when it was given explicitly.

        Legacy ``keyword`` + ``regex`` together have no canonical form (``q`` holds
        one mode). The regex is emitted (``q`` + ``mode=regex``) and the keyword is
        dropped, so such a link widens to the regex alone on the next page.

        Returns:
            Keyword arguments for :func:`search_url`.
        """
        q = self.query
        if q.regex is not None:
            text, mode = q.regex, "regex"
        else:
            text, mode = q.text, "text"
        system: str | None = None
        if q.system_set:
            system = q.system if q.system is not None else UNKNOWN_SYSTEM
        params: dict[str, object] = {
            "type": self.type,
            "system": system,
            "user": q.user,
            "window": self.window,
            "from": None if self.window is not None else q.from_,
            "to": None if self.window is not None else q.to,
            "severity": q.severity,
            "max_severity": q.max_severity,
            "has_findings": q.has_findings,
            "category": q.category,
            "rule_ids": list(q.rule_ids),
            "status": q.status,
            "min_duration": q.min_duration,
            "max_duration": q.max_duration,
            "q": text,
            "mode": mode if text is not None else None,
            "sort": q.sort,
            "discovery": q.discovery,
            "page_size": self.page_size if self.page_size_explicit else None,
            "cmd": q.cmd,
        }
        return params


# --- per-parameter validation -----------------------------------------------------------


def _opt(request: Request, name: str) -> str | None:
    """Return a single-valued parameter, stripped; blank is absent."""
    raw = _single_param(request, name)
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def _choice(request: Request, name: str, allowed: Iterable[str]) -> str | None:
    """Return a single-valued enum parameter, or ``None`` when absent."""
    value = _opt(request, name)
    if value is not None and value not in allowed:
        raise _bad_request(f"'{name}' is not a valid value")
    return value


def _free_text(request: Request, name: str, max_len: int) -> str | None:
    """Return a single-valued free-text parameter (length cap, no control chars)."""
    value = _opt(request, name)
    if value is not None and (len(value) > max_len or _has_control_chars(value)):
        raise _bad_request(f"'{name}' is not a valid value")
    return value


def _duration(request: Request, name: str) -> float | None:
    """Return a finite, non-negative float parameter, or ``None`` when absent."""
    value = _opt(request, name)
    if value is None:
        return None
    try:
        number = float(value)
    except ValueError:
        raise _bad_request(f"'{name}' must be a non-negative number") from None
    if not math.isfinite(number) or number < 0:
        raise _bad_request(f"'{name}' must be a non-negative number")
    return number


def _bool(request: Request, name: str) -> bool | None:
    """Return a ``true``/``false`` parameter (case-insensitive), or ``None``."""
    value = _opt(request, name)
    if value is None:
        return None
    match value.lower():
        case "true":
            return True
        case "false":
            return False
        case _:
            raise _bad_request(f"'{name}' must be true or false")


def _regex(request: Request, name: str) -> str | None:
    """Return a regex parameter that compiles, or ``None`` when absent."""
    value = _free_text(request, name, _MAX_Q_LEN)
    if value is not None:
        _check_regex(name, value)
    return value


def _check_regex(name: str, pattern: str) -> None:
    """Raise ``400`` if ``pattern`` does not compile."""
    try:
        re.compile(pattern)
    except (re.error, RecursionError, OverflowError):
        raise _bad_request(f"'{name}' is not a valid regular expression") from None


def _rule_ids(request: Request) -> tuple[str, ...]:
    """Return the repeated ``rule_ids`` (blank entries dropped, deduplicated)."""
    values = [v.strip() for v in request.query_params.getlist("rule_ids")]
    values = [v for v in values if v]
    if len(values) > _MAX_RULE_IDS:
        raise _bad_request("'rule_ids' has too many values")
    if any(_SLUG_RE.fullmatch(v) is None for v in values):
        raise _bad_request("'rule_ids' is not a valid value")
    return tuple(dict.fromkeys(values))


def _system(raw: str | None, name: str) -> tuple[str | None, bool]:
    """Validate a system value; return ``(resource_address, system_set)``."""
    if raw is None:
        return None, False
    if len(raw) > _MAX_SYSTEM_LEN or _has_control_chars(raw):
        raise _bad_request(f"'{name}' is not a valid value")
    return (None, True) if raw == UNKNOWN_SYSTEM else (raw, True)


def _exclusive(
    request: Request, canonical: str, legacy: str, max_len: int
) -> tuple[str | None, str]:
    """Read a canonical/legacy pair; both present → ``400``. Returns ``(value, name)``."""
    canon = _free_text(request, canonical, max_len)
    old = _free_text(request, legacy, max_len)
    if canon is not None and old is not None:
        raise _bad_request(f"'{canonical}' and '{legacy}' cannot be combined")
    return (canon, canonical) if old is None else (old, legacy)


def _page_size(request: Request, default: int) -> tuple[int, bool]:
    """Return ``(page_size, explicit)``; must be an integer 1–200."""
    value = _opt(request, "page_size")
    if value is None:
        return default, False
    if _INT_RE.fullmatch(value) is None or not 1 <= int(value) <= MAX_PAGE_SIZE:
        raise _bad_request(f"'page_size' must be an integer from 1 to {MAX_PAGE_SIZE}")
    return int(value), True


def _check_page(request: Request) -> None:
    """Validate the legacy ``page`` (integer ≥ 1); its value is then ignored."""
    value = _opt(request, "page")
    if value is not None and (_INT_RE.fullmatch(value) is None or int(value) < 1):
        raise _bad_request("'page' must be a positive integer")


def _time_bounds(
    request: Request, now: datetime
) -> tuple[str | None, str | None, str | None]:
    """Resolve ``window`` / ``from`` / ``to`` (and legacy aliases) to ``(window, from, to)``.

    ``window`` is mutually exclusive with ``from``/``to`` and their legacy aliases
    ``started_after``/``started_before``; a canonical bound and its alias together
    are a ``400``; ``from`` after ``to`` is a ``400``. Bounds are normalized to
    ``YYYY-MM-DDTHH:MM:SS.mmmZ``.
    """
    window = _choice(request, "window", WINDOW_VALUES)
    bounds: dict[str, datetime | None] = {}
    for canonical, legacy in (("from", "started_after"), ("to", "started_before")):
        canon = _parse_time_param(canonical, _opt(request, canonical), required=False)
        old = _parse_time_param(legacy, _opt(request, legacy), required=False)
        if canon is not None and old is not None:
            raise _bad_request(f"'{canonical}' and '{legacy}' cannot be combined")
        bounds[canonical] = canon if canon is not None else old
    from_dt, to_dt = bounds["from"], bounds["to"]
    if window is not None and (from_dt is not None or to_dt is not None):
        raise _bad_request("'window' cannot be combined with 'from' or 'to'")
    if from_dt is not None and to_dt is not None and from_dt > to_dt:
        raise _bad_request("'from' must not be after 'to'")
    if window is not None and window != "all":
        try:
            from_dt = now - timedelta(days=int(window))
        except OverflowError:  # pragma: no cover - fixed small windows
            raise _bad_request("'window' is out of range") from None
    return (
        window,
        to_requested_at_format(from_dt) if from_dt is not None else None,
        to_requested_at_format(to_dt) if to_dt is not None else None,
    )


def parse_unified_query(
    request: Request, *, default_page_size: int, now: datetime | None = None
) -> ParsedSearch:
    """Parse and strictly validate a unified search request (spec §5).

    Args:
        request: The ``/search`` or ``/search/export.csv`` request.
        default_page_size: ``page_size`` when absent (``SEARCH_PAGE_SIZE``).
        now: Clock for ``window`` cutoffs (default: current UTC time).

    Returns:
        The :class:`ParsedSearch`, with the cursor (if any) already checked against
        this request's sort and resolved kinds.

    Raises:
        HTTPException: ``400`` for any invalid, repeated, or conflicting parameter.
            The detail names the parameter, never its value.
    """
    clock = now if now is not None else datetime.now(tz=timezone.utc)

    _check_page(request)
    type_ = _choice(request, "type", TYPE_GROUPS) or DEFAULT_TYPE

    raw_system, system_name = _exclusive(request, "system", "resource_address", _MAX_SYSTEM_LEN)
    system, system_set = _system(raw_system, system_name)
    user, _ = _exclusive(request, "user", "username", _MAX_USER_LEN)

    window, from_, to = _time_bounds(request, clock)

    severity = _choice(request, "severity", SEVERITY_VALUES)
    max_severity = _choice(request, "max_severity", SEVERITY_VALUES)
    has_findings = _bool(request, "has_findings")
    category = _opt(request, "category")
    if category is not None and _SLUG_RE.fullmatch(category) is None:
        raise _bad_request("'category' is not a valid value")
    rule_ids = _rule_ids(request)
    status_ = _choice(request, "status", STATUS_VALUES)
    min_duration = _duration(request, "min_duration")
    max_duration = _duration(request, "max_duration")

    # Content search: q (+ mode), or the legacy keyword / regex pair.
    q = _free_text(request, "q", _MAX_Q_LEN)
    mode = _choice(request, "mode", MODES) or DEFAULT_MODE
    keyword = _free_text(request, "keyword", _MAX_Q_LEN)
    legacy_regex = _regex(request, "regex")
    if q is not None and keyword is not None:
        raise _bad_request("'q' and 'keyword' cannot be combined")
    if q is not None and legacy_regex is not None:
        raise _bad_request("'q' and 'regex' cannot be combined")
    text: str | None = keyword
    regex: str | None = legacy_regex
    if q is not None:
        if mode == "regex":
            _check_regex("q", q)
            regex = q
        else:
            text = q
    elif legacy_regex is not None and keyword is None:
        mode = "regex"  # legacy regex-only link: present it as q + mode=regex

    sort = _choice(request, "sort", SORTS) or SORT_NEWEST
    raw_discovery = _opt(request, "discovery")
    discovery = _parse_discovery_param(raw_discovery)
    page_size, page_size_explicit = _page_size(request, default_page_size)
    cmd = _opt(request, "cmd")
    if cmd is not None and _CMD_RE.fullmatch(cmd) is None:
        raise _bad_request("'cmd' is not a valid value")
    raw_cursor = _opt(request, "cursor")

    query = UnifiedQuery(
        kinds=TYPE_GROUPS[type_],
        system=system,
        system_set=system_set,
        user=user,
        from_=from_,
        to=to,
        severity=severity,
        max_severity=max_severity,
        has_findings=has_findings,
        category=category,
        rule_ids=rule_ids,
        status=status_,
        min_duration=min_duration,
        max_duration=max_duration,
        text=text,
        regex=regex,
        sort=sort,
        discovery=discovery,
        cmd=cmd,
    )
    kinds, excluded = resolve_kinds(query)

    cursor: Cursor | None = None
    if raw_cursor is not None:
        try:
            cursor = decode_cursor(raw_cursor)
        except ValueError:
            raise _bad_request("'cursor' is invalid") from None
        if cursor.sort != sort or cursor.kinds != tuple(sorted(kinds)):
            raise _bad_request("'cursor' does not match the current search")

    return ParsedSearch(
        query=query,
        type=type_,
        window=window,
        mode=mode,
        page_size=page_size,
        page_size_explicit=page_size_explicit,
        cursor=cursor,
        kinds=kinds,
        excluded=excluded,
    )
