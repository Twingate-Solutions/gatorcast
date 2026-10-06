"""Tests for unified-search parameters, cursor, URL builder, and kind registry.

Covers Session 10 T2 (``gatorcast.web.params``) and T3 (``gatorcast.web.kinds``,
plus the shared kind constants and ``session_kind`` in ``gatorcast.store.timeline``),
per spec §4, §5, and §12 (``test_search_params.py`` row).
"""

from __future__ import annotations

import ast
import base64
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from gatorcast.db import FAILED_SQL
from gatorcast.models import Session
from gatorcast.store.activity import to_requested_at_format
from gatorcast.store.timeline import (
    KIND_KEYS,
    KIND_SOURCE,
    SOURCE_API_COMMANDS,
    SOURCE_SESSIONS,
    Cursor,
    UnifiedQuery,
    check_position,
    session_kind,
)
from gatorcast.web import params, routes
from gatorcast.web.kinds import (
    EXCLUSION_LABELS,
    KINDS,
    TYPE_GROUPS,
    TYPE_LABELS,
    resolve_kinds,
)
from gatorcast.web.params import (
    SEARCH_URL_ORDER,
    ParsedSearch,
    decode_cursor,
    encode_cursor,
    parse_unified_query,
    search_url,
)

NOW = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)
SENTINEL = "GCSENTINELVALUE"
ALL_KINDS = frozenset({"ssh", "exec", "failed", "kubectl"})
REC_KINDS = frozenset({"ssh", "exec", "failed"})
AT = "2026-10-05T10:04:11.250Z"
UUID = "11111111-1111-4111-8111-111111111111"
HREQ = "h:" + "0123456789abcdef" * 2

LEGACY_NAMES = {
    "username",
    "resource_address",
    "started_after",
    "started_before",
    "keyword",
    "regex",
    "page",
}


# --- helpers -------------------------------------------------------------------------


def _request(query: str | list[tuple[str, str]]) -> Request:
    """Build a bare GET /search request carrying ``query``."""
    qs = query if isinstance(query, str) else urlencode(query)
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/search",
            "query_string": qs.encode("latin-1"),
            "headers": [],
        }
    )


def _parse(query: str | list[tuple[str, str]] = "") -> ParsedSearch:
    return parse_unified_query(_request(query), default_page_size=50, now=NOW)


def _bad(query: str | list[tuple[str, str]], name: str) -> str:
    """Assert ``query`` is a 400 naming ``name`` and never echoing the sentinel."""
    with pytest.raises(HTTPException) as exc_info:
        _parse(query)
    exc = exc_info.value
    assert exc.status_code == 400
    detail = str(exc.detail)
    assert f"'{name}'" in detail
    assert SENTINEL not in detail
    return detail


def _token(obj: object) -> str:
    """Encode an arbitrary object as a cursor token (bypassing encode_cursor)."""
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _cursor_obj(**overrides: object) -> dict[str, object]:
    obj: dict[str, object] = {
        "v": 1,
        "sort": "newest",
        "k": ["exec", "failed", "kubectl", "ssh"],
        "p": {
            "sessions": [AT, "aaaaaaaa-0000-4000-8000-000000000001"],
            "api_commands": ["T", "2026-10-05T10:02:07.000Z", UUID],
        },
    }
    obj.update(overrides)
    return obj


# --- defaults and canonical parse ---------------------------------------------------


def test_defaults_with_no_params() -> None:
    parsed = _parse("")
    assert parsed.type == "any"
    assert parsed.query == UnifiedQuery(kinds=ALL_KINDS)
    assert parsed.kinds == ALL_KINDS
    assert parsed.excluded == {}
    assert parsed.mode == "text"
    assert parsed.window is None
    assert parsed.page_size == 50
    assert parsed.page_size_explicit is False
    assert parsed.cursor is None


def test_canonical_parse_into_unified_query() -> None:
    parsed = _parse(
        [
            ("type", "recordings"),
            ("system", "web-01"),
            ("user", "alice@example.com"),
            ("from", "2026-10-01T00:00:00Z"),
            ("to", "2026-10-02T00:00:00+02:00"),
            ("severity", "medium"),
            ("max_severity", "high"),
            ("has_findings", "true"),
            ("category", "dangerous-command"),
            ("rule_ids", "rm-rf"),
            ("rule_ids", "curl-pipe-sh"),
            ("status", "complete"),
            ("min_duration", "1.5"),
            ("max_duration", "600"),
            ("q", "vault"),
            ("mode", "text"),
            ("sort", "risk"),
            ("discovery", "1"),
            ("page_size", "25"),
        ]
    )
    q = parsed.query
    assert q.kinds == REC_KINDS
    assert (q.system, q.system_set) == ("web-01", True)
    assert q.user == "alice@example.com"
    assert q.from_ == "2026-10-01T00:00:00.000Z"
    assert q.to == "2026-10-01T22:00:00.000Z"  # offset normalized to UTC
    assert (q.severity, q.max_severity, q.has_findings) == ("medium", "high", True)
    assert q.category == "dangerous-command"
    assert q.rule_ids == ("rm-rf", "curl-pipe-sh")
    assert q.status == "complete"
    assert (q.min_duration, q.max_duration) == (1.5, 600.0)
    assert (q.text, q.regex) == ("vault", None)
    assert q.sort == "risk"
    assert q.discovery is True
    assert q.cmd is None
    assert (parsed.page_size, parsed.page_size_explicit) == (25, True)
    assert parsed.kinds == REC_KINDS


def test_blank_values_are_absent() -> None:
    blank = "&".join(
        f"{name}=" for name in SEARCH_URL_ORDER if name != "rule_ids"
    ) + "&rule_ids=&rule_ids=%20&username=&keyword=&regex=&page=&started_after="
    parsed = _parse(blank)
    assert parsed.query == UnifiedQuery(kinds=ALL_KINDS)
    assert parsed.type == "any"
    assert parsed.cursor is None
    assert parsed.page_size == 50


def test_whitespace_only_is_blank() -> None:
    assert _parse("user=%20%20&system=%09").query.user is None


def test_system_unknown_sentinel_is_null_bucket() -> None:
    q = _parse("system=_unknown").query
    assert (q.system, q.system_set) == (None, True)
    q = _parse("resource_address=_unknown").query
    assert (q.system, q.system_set) == (None, True)


def test_unknown_params_are_ignored() -> None:
    assert _parse(f"foo={SENTINEL}&bar=1").query == UnifiedQuery(kinds=ALL_KINDS)


# --- type values ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("type_", "kinds"),
    [
        ("any", ALL_KINDS),
        ("recordings", REC_KINDS),
        ("ssh", {"ssh"}),
        ("exec", {"exec"}),
        ("failed", {"failed"}),
        ("kubectl", {"kubectl"}),
    ],
)
def test_type_accepts_six_values(type_: str, kinds: set[str]) -> None:
    parsed = _parse(f"type={type_}")
    assert parsed.type == type_
    assert parsed.query.kinds == frozenset(kinds)
    assert parsed.kinds == frozenset(kinds)


def test_registry_shape() -> None:
    assert list(KINDS) == ["ssh", "exec", "failed", "kubectl"]
    assert tuple(KINDS) == KIND_KEYS
    assert set(TYPE_GROUPS) == {"any", "recordings", "ssh", "exec", "failed", "kubectl"}
    assert len(TYPE_GROUPS) == 6
    assert TYPE_GROUPS["recordings"] == REC_KINDS
    assert TYPE_GROUPS["any"] == frozenset(KINDS)
    assert [v for v, _ in TYPE_LABELS] == list(TYPE_GROUPS)
    assert KINDS["failed"].label == "Failed connection"
    assert KINDS["failed"].badge_class == "pill-failed"
    for key, kind in KINDS.items():
        assert kind.key == key
        assert kind.source == KIND_SOURCE[key]
    assert {KINDS[k].source for k in REC_KINDS} == {SOURCE_SESSIONS}
    assert KINDS["kubectl"].source == SOURCE_API_COMMANDS
    assert KINDS["kubectl"].row_macro == "command_row"


# --- enum / format validation -----------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "type",
        "window",
        "severity",
        "max_severity",
        "status",
        "mode",
        "sort",
        "has_findings",
        "discovery",
        "category",
        "rule_ids",
        "min_duration",
        "max_duration",
        "page_size",
        "page",
        "cmd",
        "from",
        "to",
        "started_after",
        "started_before",
    ],
)
def test_invalid_values_rejected_without_echo(name: str) -> None:
    _bad([(name, f"{SENTINEL}!")], name)


@pytest.mark.parametrize(
    ("name", "limit"),
    [("system", 512), ("user", 512), ("q", 256), ("keyword", 256), ("regex", 256),
     ("resource_address", 512), ("username", 512)],
)
def test_length_caps(name: str, limit: int) -> None:
    _parse([(name, "a" * limit)])  # at the cap: accepted
    _bad([(name, SENTINEL + "a" * limit)], name)


def test_time_param_length_cap() -> None:
    _bad([("from", "2026-10-05T00:00:00" + "0" * 50 + SENTINEL)], "from")


@pytest.mark.parametrize("name", ["system", "user", "q", "keyword", "regex", "username"])
@pytest.mark.parametrize("ch", ["\x00", "\x1b", "\x7f", "\x85"])
def test_control_chars_rejected(name: str, ch: str) -> None:
    _bad([(name, f"{SENTINEL}{ch}x")], name)


@pytest.mark.parametrize(
    "name",
    ["type", "system", "user", "window", "from", "to", "q", "mode", "sort", "cursor",
     "page_size", "cmd", "username", "keyword", "page", "discovery"],
)
def test_repeated_single_valued_param(name: str) -> None:
    detail = _bad([(name, SENTINEL), (name, SENTINEL)], name)
    assert "only once" in detail


def test_rule_ids_may_repeat_and_are_deduplicated() -> None:
    q = _parse("rule_ids=a-1&rule_ids=b&rule_ids=a-1&rule_ids=").query
    assert q.rule_ids == ("a-1", "b")


def test_rule_ids_cap() -> None:
    _parse([("rule_ids", f"r{i}") for i in range(50)])
    _bad([("rule_ids", f"r{i}") for i in range(51)], "rule_ids")


@pytest.mark.parametrize("value", ["Upper", "a_b", "a" * 65, "a b"])
def test_slug_patterns(value: str) -> None:
    _bad([("category", value)], "category")
    _bad([("rule_ids", value)], "rule_ids")


@pytest.mark.parametrize("value", ["0", "201", "-1", "1.5", "abc", "+5"])
def test_page_size_bounds(value: str) -> None:
    _bad([("page_size", value)], "page_size")


@pytest.mark.parametrize("value", ["1", "200"])
def test_page_size_accepted(value: str) -> None:
    assert _parse(f"page_size={value}").page_size == int(value)


@pytest.mark.parametrize("value", ["-1", "nan", "inf", "-inf", "1e400", "abc"])
def test_duration_must_be_finite_non_negative(value: str) -> None:
    _bad([("min_duration", value)], "min_duration")
    _bad([("max_duration", value)], "max_duration")


@pytest.mark.parametrize(("raw", "expected"), [("true", True), ("FALSE", False), ("True", True)])
def test_has_findings_tri_state(raw: str, expected: bool) -> None:
    assert _parse(f"has_findings={raw}").query.has_findings is expected


def test_uncompilable_regex_rejected() -> None:
    _bad([("q", "(" + SENTINEL), ("mode", "regex")], "q")
    _bad([("regex", "[" + SENTINEL)], "regex")
    # In text mode the same string is a plain substring.
    assert _parse([("q", "(abc")]).query.text == "(abc"


@pytest.mark.parametrize("value", [UUID, HREQ, "req-1"])
def test_cmd_accepts_stored_request_id_shapes(value: str) -> None:
    assert _parse(f"cmd={value}").query.cmd == value


@pytest.mark.parametrize("value", ["a b", "x/y", "a" * 129, "h:XYZ", "i\nd"])
def test_cmd_pattern_rejects(value: str) -> None:
    _bad([("cmd", value)], "cmd")


# --- time bounds -----------------------------------------------------------------------


def test_from_after_to_rejected() -> None:
    _bad("from=2026-10-05T00:00:01Z&to=2026-10-05T00:00:00Z", "from")
    q = _parse("from=2026-10-05T00:00:00Z&to=2026-10-05T00:00:00Z").query
    assert q.from_ == q.to == "2026-10-05T00:00:00.000Z"


def test_naive_bound_is_utc_and_normalized() -> None:
    q = _parse("from=2026-10-05T01:02:03.456789").query
    assert q.from_ == "2026-10-05T01:02:03.456Z"


@pytest.mark.parametrize("days", ["7", "30", "90"])
def test_window_computes_cutoff(days: str) -> None:
    parsed = _parse(f"window={days}")
    assert parsed.window == days
    assert parsed.query.from_ == to_requested_at_format(NOW - timedelta(days=int(days)))
    assert parsed.query.to is None


def test_window_all_is_unbounded_but_kept() -> None:
    parsed = _parse("window=all")
    assert parsed.window == "all"
    assert parsed.query.from_ is None


@pytest.mark.parametrize(
    "other",
    ["from=2026-10-01T00:00:00Z", "to=2026-10-01T00:00:00Z",
     "started_after=2026-10-01T00:00:00Z", "started_before=2026-10-01T00:00:00Z"],
)
def test_window_with_bounds_rejected(other: str) -> None:
    _bad(f"window=7&{other}", "window")
    _bad(f"window=all&{other}", "window")


# --- legacy aliases (spec §5.2) ---------------------------------------------------


def test_legacy_aliases_map() -> None:
    q = _parse(
        "username=alice&resource_address=web-01&started_after=2026-10-01T00:00:00Z"
        "&started_before=2026-10-02T00:00:00Z&keyword=vault"
    ).query
    assert q.user == "alice"
    assert (q.system, q.system_set) == ("web-01", True)
    assert q.from_ == "2026-10-01T00:00:00.000Z"
    assert q.to == "2026-10-02T00:00:00.000Z"
    assert (q.text, q.regex) == ("vault", None)


def test_legacy_regex_maps_to_regex_mode() -> None:
    parsed = _parse("regex=ab%2Bc")
    assert (parsed.query.text, parsed.query.regex, parsed.mode) == (None, "ab+c", "regex")


def test_legacy_keyword_and_regex_keep_and_semantics() -> None:
    q = _parse("keyword=vault&regex=hvs%5C.").query
    assert (q.text, q.regex) == ("vault", r"hvs\.")


@pytest.mark.parametrize(
    ("query", "name"),
    [
        ("user=a&username=b", "user"),
        ("system=a&resource_address=b", "system"),
        ("from=2026-10-01T00:00:00Z&started_after=2026-10-01T00:00:00Z", "from"),
        ("to=2026-10-01T00:00:00Z&started_before=2026-10-01T00:00:00Z", "to"),
        ("q=a&keyword=b", "q"),
        ("q=a&regex=b", "q"),
        ("q=a&mode=regex&regex=b", "q"),
    ],
)
def test_legacy_canonical_conflicts(query: str, name: str) -> None:
    detail = _bad(query, name)
    assert "cannot be combined" in detail


def test_legacy_only_url_resolves_to_any() -> None:
    for query in (
        "max_severity=high&started_after=2026-09-05T12:00:00Z",
        "category=dangerous-command&started_after=2026-09-05T12:00:00Z",
        "username=alice%40example.com&started_after=2026-09-05T12:00:00Z",
    ):
        parsed = _parse(query)
        assert parsed.type == "any"
        assert parsed.query.kinds == ALL_KINDS
        assert parsed.kinds == ALL_KINDS


@pytest.mark.parametrize("value", ["0", "-1", "x", "1.0", "9999999999"])
def test_page_validated(value: str) -> None:
    _bad([("page", value)], "page")


def test_page_valid_then_ignored() -> None:
    parsed = _parse("page=3")
    assert parsed.cursor is None
    assert parsed == _parse("")


# --- resolve_kinds (spec §4.3) ------------------------------------------------------


@pytest.mark.parametrize(
    ("query", "reason"),
    [
        ("status=error", "status"),
        ("min_duration=5", "min_duration"),
        ("max_duration=5", "max_duration"),
        ("q=a.%2B&mode=regex", "regex"),
        ("regex=a", "regex"),
        ("sort=duration", "sort"),
    ],
)
def test_recordings_only_filters_exclude_kubectl(query: str, reason: str) -> None:
    parsed = _parse(query)
    assert parsed.kinds == REC_KINDS
    assert parsed.excluded == {"kubectl": reason}
    assert reason in EXCLUSION_LABELS


def test_cmd_excludes_recording_kinds() -> None:
    parsed = _parse(f"cmd={UUID}")
    assert parsed.kinds == frozenset({"kubectl"})
    assert parsed.excluded == {"ssh": "cmd", "exec": "cmd", "failed": "cmd"}
    assert list(parsed.excluded) == ["ssh", "exec", "failed"]  # registry order


def test_cmd_overrides_other_filters_for_kubectl() -> None:
    parsed = _parse(f"cmd={UUID}&status=error&sort=duration&mode=regex&q=x")
    assert parsed.kinds == frozenset({"kubectl"})


def test_cmd_does_not_override_type() -> None:
    parsed = _parse(f"type=ssh&cmd={UUID}")
    assert parsed.kinds == frozenset()
    assert parsed.excluded == {"ssh": "cmd"}


def test_first_unevaluable_filter_is_the_reason() -> None:
    assert _parse("status=error&min_duration=1&regex=x").excluded == {"kubectl": "status"}
    assert _parse("max_duration=1&sort=duration").excluded == {"kubectl": "max_duration"}


def test_common_filters_exclude_nothing() -> None:
    parsed = _parse(
        "system=a&user=b&window=7&severity=low&max_severity=high&has_findings=false"
        "&category=kube-api&rule_ids=kube-delete&q=pods&sort=risk&discovery=1"
    )
    assert parsed.kinds == ALL_KINDS
    assert parsed.excluded == {}


def test_every_selected_kind_excluded_is_empty_not_error() -> None:
    parsed = _parse("type=kubectl&status=error")
    assert parsed.kinds == frozenset()
    assert parsed.excluded == {"kubectl": "status"}


def test_resolve_kinds_on_constructed_query() -> None:
    kinds, excluded = resolve_kinds(UnifiedQuery(kinds=REC_KINDS, status="complete"))
    assert (kinds, excluded) == (REC_KINDS, {})


# --- session_kind agrees with FAILED_SQL (spec §4.2) ---------------------------------

_KIND_ROWS = [
    # (status, chunk_count, cast_path, request_id)
    ("error", 0, None, None),          # failed connection
    ("error", None, None, None),       # failed: NULL chunk_count
    ("error", 0, None, "R"),           # failed wins over request_id
    ("error", 3, None, None),          # SSH error row with chunks
    ("error", 0, "/data/c.cast", None),  # sealed error row with a cast
    ("error", 2, "/data/c.cast", "R"),  # exec error row
    ("complete", 0, None, None),       # not error -> ssh
    ("complete", 5, "/data/c.cast", None),
    ("complete", 5, "/data/c.cast", "R"),
    ("provisional", 1, "/data/c.cast", None),
    ("provisional", 0, None, "R"),
]


def test_session_kind_agrees_with_failed_sql() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE sessions (conn_id TEXT, status TEXT, chunk_count INTEGER,"
        " cast_path TEXT, request_id TEXT)"
    )
    conn.executemany(
        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
        [(f"c{i}", *row) for i, row in enumerate(_KIND_ROWS)],
    )
    sql = (
        "SELECT s.*, CASE WHEN " + FAILED_SQL.format(a="s.") + " THEN 'failed' "
        "WHEN s.request_id IS NOT NULL THEN 'exec' ELSE 'ssh' END AS sql_kind "
        "FROM sessions s ORDER BY s.rowid"
    )
    rows = conn.execute(sql).fetchall()
    assert len(rows) == len(_KIND_ROWS)
    seen = set()
    for row in rows:
        expected = row["sql_kind"]
        seen.add(expected)
        assert session_kind(row) == expected  # sqlite3.Row
        assert session_kind(dict(row)) == expected  # mapping
        model = Session(
            conn_id=row["conn_id"],
            status=row["status"],
            chunk_count=row["chunk_count"] or 0,
            cast_path=row["cast_path"],
            request_id=row["request_id"],
        )
        assert session_kind(model) == expected  # model attributes
    assert seen == {"failed", "exec", "ssh"}
    conn.close()


def test_session_kind_examples() -> None:
    assert session_kind({"status": "error", "chunk_count": 0}) == "failed"
    assert session_kind({"status": "error", "chunk_count": 4}) == "ssh"
    assert session_kind({"status": "complete", "request_id": "R"}) == "exec"


# --- cursor (spec §5.4) ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("sort", "positions"),
    [
        ("newest", {"sessions": (AT, "conn-1"), "api_commands": ("T", AT, UUID)}),
        ("newest", {"sessions": "done", "api_commands": ("F", AT, HREQ)}),
        ("risk", {"sessions": (3, AT, "conn-1"), "api_commands": ("F", 4, AT, UUID)}),
        ("risk", {"sessions": (0, AT, "conn-1"), "api_commands": ("T", AT, "req-1")}),
        ("duration", {"sessions": (1, 12.5, "conn-1")}),
        ("duration", {"sessions": (0, 0, "conn-1")}),
        ("newest", {}),
    ],
)
def test_cursor_round_trip(sort: str, positions: dict[str, object]) -> None:
    kinds = ("ssh",) if sort == "duration" else ("exec", "failed", "kubectl", "ssh")
    cursor = Cursor(sort=sort, kinds=kinds, positions=positions)
    token = encode_cursor(cursor)
    assert len(token) <= 2048
    assert "=" not in token
    assert decode_cursor(token) == cursor


def test_cursor_round_trip_through_parse() -> None:
    cursor = Cursor(
        sort="risk",
        kinds=("exec", "failed", "ssh"),
        positions={"sessions": (2, AT, "conn-1")},
    )
    parsed = _parse([("sort", "risk"), ("status", "complete"), ("cursor", encode_cursor(cursor))])
    assert parsed.cursor == cursor


def test_cursor_truncated() -> None:
    token = _token(_cursor_obj())
    _bad([("cursor", token[:-7])], "cursor")


def test_cursor_oversized() -> None:
    _bad([("cursor", "A" * 2049)], "cursor")


def test_cursor_not_base64url() -> None:
    _bad([("cursor", "abc+/=")], "cursor")
    _bad([("cursor", "a")], "cursor")  # impossible base64 length


@pytest.mark.parametrize(
    "obj",
    [
        _cursor_obj(extra=1),  # extra top-level field
        _cursor_obj(v=2),
        _cursor_obj(v=True),
        _cursor_obj(v="1"),
        _cursor_obj(sort="oldest"),
        _cursor_obj(k=[]),
        _cursor_obj(k=["ssh", "exec"]),  # not sorted
        _cursor_obj(k=["ssh", "ssh"]),
        _cursor_obj(k=["web"]),
        {k: v for k, v in _cursor_obj().items() if k != "p"},  # missing field
        _cursor_obj(p={"web": "done"}),  # unknown source
        _cursor_obj(p={"sessions": ["2026-10-05T10:04:11Z", "c"]}),  # no millis
        _cursor_obj(p={"sessions": [AT, "bad/conn"]}),
        _cursor_obj(p={"sessions": [AT, "c", "extra"]}),
        _cursor_obj(p={"sessions": "finished"}),
        _cursor_obj(p={"api_commands": ["X", AT, UUID]}),  # bad phase
        _cursor_obj(p={"api_commands": ["T", AT, "h:short"]}),
        _cursor_obj(sort="risk", p={"sessions": [5, AT, "c"]}),  # rank > 4
        _cursor_obj(sort="risk", p={"sessions": [True, AT, "c"]}),  # bool rank
        _cursor_obj(sort="risk", p={"api_commands": ["F", AT, UUID]}),  # risk F lacks rank
        _cursor_obj(sort="duration", k=["ssh"], p={"sessions": [2, 1.0, "c"]}),  # bad flag
        _cursor_obj(sort="duration", k=["ssh"], p={"sessions": [1, -1.0, "c"]}),
        _cursor_obj(sort="duration", k=["ssh"], p={"sessions": [1, 1e999, "c"]}),
        _cursor_obj(k=["ssh"], p={"api_commands": ["T", AT, UUID]}),  # source not queried
        _cursor_obj(p={"sessions": [AT, SENTINEL + "/x"]}),
    ],
)
def test_cursor_invalid_shapes(obj: dict[str, object]) -> None:
    detail = _bad([("cursor", _token(obj))], "cursor")
    assert "invalid" in detail


def test_cursor_nan_literal_rejected() -> None:
    raw = b'{"v":1,"sort":"duration","k":["ssh"],"p":{"sessions":[1,NaN,"c"]}}'
    token = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    _bad([("cursor", token)], "cursor")


def test_cursor_wrong_sort() -> None:
    token = _token(_cursor_obj(sort="risk", p={}))
    detail = _bad([("cursor", token)], "cursor")  # request sort is newest
    assert "does not match" in detail


def test_cursor_wrong_kinds() -> None:
    token = _token(_cursor_obj())  # all four kinds
    detail = _bad([("type", "ssh"), ("cursor", token)], "cursor")
    assert "does not match" in detail
    # Kinds are compared after exclusions: status drops kubectl.
    detail = _bad([("status", "error"), ("cursor", token)], "cursor")
    assert "does not match" in detail


def test_cursor_matches_resolved_kinds() -> None:
    token = _token(_cursor_obj(k=["exec", "failed", "ssh"], p={"sessions": "done"}))
    parsed = _parse([("status", "error"), ("cursor", token)])
    assert parsed.cursor is not None
    assert parsed.cursor.positions == {"sessions": "done"}


def test_check_position_rejects_duration_for_api_commands() -> None:
    with pytest.raises(ValueError):
        check_position(SOURCE_API_COMMANDS, "duration", [1, 2.0, UUID])


def test_encode_cursor_rejects_oversize() -> None:
    long_id = "a" * 128
    positions = {"sessions": (AT, long_id)}
    cursor = Cursor(sort="newest", kinds=("ssh",), positions=positions)
    assert len(encode_cursor(cursor)) <= 2048
    with pytest.raises(ValueError):
        encode_cursor(Cursor(sort="newest", kinds=("ssh",), positions={"sessions": (AT, "a" * 2000)}))


# --- search_url (spec §5.5) -----------------------------------------------------------


def _names(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]


def test_search_url_fixed_order() -> None:
    values = {
        "cursor": "abc",
        "cmd": UUID,
        "page_size": 20,
        "discovery": True,
        "sort": "risk",
        "mode": "regex",
        "q": "x",
        "max_duration": 9,
        "min_duration": 1.5,
        "status": "error",
        "rule_ids": ["a", "b"],
        "category": "kube-api",
        "has_findings": True,
        "max_severity": "high",
        "severity": "low",
        "to": "2026-10-05T00:00:00.000Z",
        "from_": "2026-10-01T00:00:00.000Z",
        "window": None,
        "user": "u",
        "system": "s",
        "type": "kubectl",
    }
    url = search_url(**values)
    names = _names(url)
    expected = [n for n in SEARCH_URL_ORDER if n != "window"]
    expected.insert(expected.index("rule_ids") + 1, "rule_ids")
    assert names == expected
    assert dict(parse_qsl(urlsplit(url).query))["min_duration"] == "1.5"


def test_search_url_drops_none_blank_and_defaults() -> None:
    assert search_url() == "/search"
    assert (
        search_url(type="any", mode="text", sort="newest", discovery=False, user=None, q="")
        == "/search"
    )
    assert search_url(discovery="0", rule_ids=[]) == "/search"


def test_search_url_keeps_window_all() -> None:
    assert search_url(type="recordings", window="all") == "/search?type=recordings&window=all"
    assert search_url(window="7") == "/search?window=7"


def test_search_url_encodes_values() -> None:
    url = search_url(user="a&b c@example.com", system="10.0.0.1:22")
    assert url == "/search?system=10.0.0.1%3A22&user=a%26b+c%40example.com"


def test_search_url_formats_bools_and_numbers() -> None:
    assert search_url(has_findings=False) == "/search?has_findings=false"
    assert search_url(has_findings=True, discovery=1) == "/search?has_findings=true&discovery=1"
    assert search_url(min_duration=60.0) == "/search?min_duration=60"


@pytest.mark.parametrize("name", sorted(LEGACY_NAMES))
def test_search_url_rejects_legacy_names(name: str) -> None:
    with pytest.raises(TypeError):
        search_url(**{name: "x"})


def test_url_params_round_trip_never_emits_legacy() -> None:
    query = (
        "username=alice&resource_address=_unknown&started_after=2026-10-01T00:00:00Z"
        "&keyword=vault&max_severity=high&has_findings=true&rule_ids=rm-rf&page=4"
        "&min_duration=60&sort=risk&discovery=1&page_size=10"
    )
    parsed = _parse(query)
    url = search_url(**parsed.url_params())
    assert not LEGACY_NAMES & set(_names(url))
    reparsed = _parse(urlsplit(url).query)
    assert reparsed.query == parsed.query
    assert reparsed.page_size == 10


def test_url_params_window_emitted_not_computed_from() -> None:
    parsed = _parse("type=kubectl&window=30")
    url = search_url(**parsed.url_params())
    assert url == "/search?type=kubectl&window=30"
    parsed_all = _parse("window=all")
    assert search_url(**parsed_all.url_params()) == "/search?window=all"


def test_url_params_regex_mode() -> None:
    parsed = _parse("regex=ab%2Bc")
    url = search_url(**parsed.url_params())
    assert url == "/search?q=ab%2Bc&mode=regex"
    assert _parse(urlsplit(url).query).query == parsed.query


def test_url_params_with_cursor_for_next_link() -> None:
    cursor = Cursor(sort="newest", kinds=("kubectl",), positions={"api_commands": ("T", AT, UUID)})
    token = encode_cursor(cursor)
    parsed = _parse("type=kubectl")
    url = search_url(**parsed.url_params(), cursor=token)
    assert _names(url)[-1] == "cursor"
    assert _parse(urlsplit(url).query).cursor == cursor


# --- module layout ----------------------------------------------------------------------


def test_routes_reuses_moved_helpers() -> None:
    for name in (
        "_bad_request",
        "_single_param",
        "_has_control_chars",
        "_parse_time_param",
        "_parse_discovery_param",
    ):
        assert getattr(routes, name) is getattr(params, name)


def test_store_never_imports_web() -> None:
    store_dir = Path(__file__).resolve().parents[1] / "src" / "gatorcast" / "store"
    for path in store_dir.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("gatorcast.web"), path.name
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("gatorcast.web"), path.name
