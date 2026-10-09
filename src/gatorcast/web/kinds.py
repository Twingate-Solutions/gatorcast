"""Event-kind registry for the unified search (Session 10, spec §4).

Kinds are data. Each :class:`EventKind` names one event family shown in the
unified timeline, with its label, badge, row macro, timeline source, and the
filters and sorts it can evaluate. ``type=`` values select a group of kinds
(:data:`TYPE_GROUPS`); :func:`resolve_kinds` then drops every kind that cannot
evaluate an active filter or sort and records why, for the exclusion notice.

Layering (Ben, 2026-10-05): the store never imports from ``gatorcast.web``. The kind
identifiers, source names, and :func:`session_kind` are defined in
:mod:`gatorcast.store.timeline` (the engine needs them) and imported here; this
module adds only the presentation and applicability data. The route calls
:func:`resolve_kinds` and passes the resolved kinds and exclusions into the engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from gatorcast.store.timeline import (
    KIND_EXEC,
    KIND_FAILED,
    KIND_KEYS,
    KIND_KUBECTL,
    KIND_SOURCE,
    KIND_SSH,
    KIND_WEB,
    SORT_DURATION,
    SORT_NEWEST,
    SORT_RISK,
    UnifiedQuery,
    session_kind,
)

__all__ = [
    "EXCLUSION_LABELS",
    "FILTER_NAMES",
    "KINDS",
    "TYPE_GROUPS",
    "TYPE_LABELS",
    "TYPE_VALUES",
    "EventKind",
    "active_filters",
    "resolve_kinds",
    "session_kind",
]

# --- filter names (spec §4.3) -----------------------------------------------------
# One name per constraint a UnifiedQuery can carry, in the fixed order
# resolve_kinds checks them ("the first filter it cannot evaluate"). Names match the
# canonical URL parameter, except ``text``/``regex`` (``q`` in either mode, or the
# legacy ``keyword``/``regex``) and ``from``/``to`` (also set by ``window``).
# ``scheme``/``upstream`` are the web connections' configured-TLS filters (spec §8.3).

FILTER_NAMES: Final[tuple[str, ...]] = (
    "system",
    "user",
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
    "text",
    "regex",
    "scheme",
    "upstream",
    "cmd",
)

# Filters evaluable by the sessions-table kinds: not ``cmd`` or the web TLS filters.
# ``discovery`` is not a constraint for recordings (ignored), so it is never checked.
_REC_FILTERS: Final = frozenset(FILTER_NAMES) - {"cmd", "scheme", "upstream"}
_REC_SORTS: Final = frozenset({SORT_NEWEST, SORT_RISK, SORT_DURATION})

# Filters evaluable by kubectl commands: not status, durations, regex, or the web TLS filters.
_CMD_FILTERS: Final = frozenset(FILTER_NAMES) - {
    "status", "min_duration", "max_duration", "regex", "scheme", "upstream",
}
_CMD_SORTS: Final = frozenset({SORT_NEWEST, SORT_RISK})

# Filters evaluable by web connections: not status, durations, or regex (spec §8.3).
# Web shares the kubectl sorts.
_WEB_FILTERS: Final = frozenset(FILTER_NAMES) - {"status", "min_duration", "max_duration", "regex"}


@dataclass(frozen=True, slots=True)
class EventKind:
    """One event family shown in the unified timeline (spec §4.1).

    Attributes:
        key: URL ``type`` value and CSV ``kind`` (``ssh``/``exec``/``failed``/``kubectl``/``web``).
        label: Human label for the type badge.
        badge_class: CSS modifier for the badge (registry-supplied, never stored data).
        source: Timeline source name (``sessions`` | ``api_commands`` | ``web_conns``).
        row_macro: Macro in ``_rows.html`` that renders the row.
        filters: Filter names (:data:`FILTER_NAMES`) this kind can evaluate.
        sorts: Sort values this kind supports.
    """

    key: str
    label: str
    badge_class: str
    source: str
    row_macro: str
    filters: frozenset[str]
    sorts: frozenset[str]


# Insertion order = display order in the type select (ssh, exec, failed, kubectl, web).
KINDS: Final[dict[str, EventKind]] = {
    KIND_SSH: EventKind(
        KIND_SSH, "SSH session", "pill-ssh", KIND_SOURCE[KIND_SSH], "recording_row",
        _REC_FILTERS, _REC_SORTS,
    ),
    KIND_EXEC: EventKind(
        KIND_EXEC, "kubectl exec", "pill-exec", KIND_SOURCE[KIND_EXEC], "recording_row",
        _REC_FILTERS, _REC_SORTS,
    ),
    KIND_FAILED: EventKind(
        KIND_FAILED, "Failed connection", "pill-failed", KIND_SOURCE[KIND_FAILED],
        "recording_row", _REC_FILTERS, _REC_SORTS,
    ),
    KIND_KUBECTL: EventKind(
        KIND_KUBECTL, "kubectl command", "pill-kubectl", KIND_SOURCE[KIND_KUBECTL],
        "command_row", _CMD_FILTERS, _CMD_SORTS,
    ),
    KIND_WEB: EventKind(
        KIND_WEB, "Web connection", "pill-web", KIND_SOURCE[KIND_WEB],
        "web_row", _WEB_FILTERS, _CMD_SORTS,
    ),
}
assert tuple(KINDS) == KIND_KEYS, "KINDS must follow store.timeline.KIND_KEYS"

# ``type`` value → kinds it selects. ``any`` follows the registry, so a future kind
# is included automatically; ``recordings`` is every sessions row ("All sessions",
# matching the dashboard's "Total sessions" tile).
TYPE_GROUPS: Final[dict[str, frozenset[str]]] = {
    "any": frozenset(KINDS),
    "recordings": frozenset({KIND_SSH, KIND_EXEC, KIND_FAILED}),
    KIND_SSH: frozenset({KIND_SSH}),
    KIND_EXEC: frozenset({KIND_EXEC}),
    KIND_FAILED: frozenset({KIND_FAILED}),
    KIND_KUBECTL: frozenset({KIND_KUBECTL}),
    KIND_WEB: frozenset({KIND_WEB}),
}
TYPE_VALUES: Final[tuple[str, ...]] = tuple(TYPE_GROUPS)

# (value, label) pairs for the type <select>, in display order.
TYPE_LABELS: Final[list[tuple[str, str]]] = [
    ("any", "Any"),
    ("recordings", "All sessions"),
    (KIND_SSH, "SSH sessions"),
    (KIND_EXEC, "kubectl exec recordings"),
    (KIND_FAILED, "Failed connections"),
    (KIND_KUBECTL, "kubectl commands"),
    (KIND_WEB, "Web requests"),
]

# Exclusion reason (a FILTER_NAMES entry, or "sort") → wording for the notice
# "<kind label>s not searched: the <label> applies to …". Fixed strings only.
EXCLUSION_LABELS: Final[dict[str, str]] = {
    "status": "Status filter",
    "min_duration": "Minimum duration filter",
    "max_duration": "Maximum duration filter",
    "regex": "regex search",
    "sort": "Longest-first sort",
    "scheme": "HTTP/HTTPS filter",
    "upstream": "Upstream TLS filter",
    "cmd": "Command/connection focus",
}


def active_filters(query: UnifiedQuery) -> list[str]:
    """Return the names of the constraints ``query`` carries, in :data:`FILTER_NAMES` order.

    A ``cmd`` focus overrides every other filter (spec §5.1, §6.3), so when it is set
    the result is ``["cmd"]`` alone. ``discovery`` is never listed: it is not a
    constraint for recordings and is evaluable by kubectl commands.

    Args:
        query: The validated query.

    Returns:
        Active filter names.
    """
    if query.cmd is not None:
        return ["cmd"]
    present = {
        "system": query.system_set,
        "user": query.user is not None,
        "from": query.from_ is not None,
        "to": query.to is not None,
        "severity": query.severity is not None,
        "max_severity": query.max_severity is not None,
        "has_findings": query.has_findings is not None,
        "category": query.category is not None,
        "rule_ids": bool(query.rule_ids),
        "status": query.status is not None,
        "min_duration": query.min_duration is not None,
        "max_duration": query.max_duration is not None,
        "text": query.text is not None,
        "regex": query.regex is not None,
        "scheme": query.scheme is not None or query.scheme_null,
        "upstream": query.upstream is not None or query.upstream_null,
    }
    return [name for name in FILTER_NAMES if present.get(name, False)]


def resolve_kinds(query: UnifiedQuery) -> tuple[frozenset[str], dict[str, str]]:
    """Split the selected kinds into those to query and those excluded (spec §4.3).

    A kind is excluded when it cannot evaluate an active filter or the sort. The
    reason recorded is the first such filter in :data:`FILTER_NAMES` order, else
    ``"sort"``. Under a ``cmd`` focus only ``cmd`` is checked (the sort does not
    apply to a single command). ``type`` is not overridden: ``type=ssh&cmd=…``
    excludes ``ssh`` and queries nothing.

    Args:
        query: The validated query; ``query.kinds`` is the ``type`` group.

    Returns:
        ``(kinds to query, {excluded kind: reason})``. The reason is a
        :data:`FILTER_NAMES` entry or ``"sort"`` (see :data:`EXCLUSION_LABELS`).
        When every selected kind is excluded the first element is empty; that is a
        valid, empty result (not a ``400``).
    """
    active = active_filters(query)
    check_sort = query.cmd is None
    queried: set[str] = set()
    excluded: dict[str, str] = {}
    for key, kind in KINDS.items():  # registry order, so exclusions read in display order
        if key not in query.kinds:
            continue
        reason = next((name for name in active if name not in kind.filters), None)
        if reason is None and check_sort and query.sort not in kind.sorts:
            reason = "sort"
        if reason is None:
            queried.add(key)
        else:
            excluded[key] = reason
    return frozenset(queried), excluded
