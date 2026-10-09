"""Pinned query plans for the unified timeline (Session 10 T4, spec §7.4, §12).

Each test runs ``EXPLAIN QUERY PLAN`` over the exact SQL the engine builds and pins
the *index names* used (not the full plan text), so the assertions hold across
SQLite releases (local 3.49; the ``python:3.12-slim`` image ships ~3.40).

Session 11 (WEBAPP_SPEC 4.2): every ``api_requests`` scan index leads with ``api_kind``, so a
kubectl query is pinned to the ``idx_api_req_kind_*`` / ``idx_api_req_sys_kind_*`` names and
its index lines carry ``api_kind=?``. The all-time ``api_requests_total`` count and the
system-plus-user Q4 combination are deliberately not pinned (the planner's choice there is
not part of the contract).

Session 12 (WEBAPP_SPEC 8.1, 12.2): the web source runs the same statements as kubectl with
``api_kind = 'web'`` bound, so its Q4 / Q4b, Q6a-c, Q7 and Q9 are pinned to the same index names
(Q4 scan, user-led and system-led, Q4b, and the hydration set via ``timeline._cmd_sql("web",
False)``). Web Q5 is not pinned: the web source skips flagged mode and never builds it.

Q12 (``list_systems``, T8) is pinned at the end: its API arm is a covering scan of
``idx_api_req_sys_kind_time`` and it uses no Session 10 index (spec §7.5).
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import aiosqlite
import pytest

from gatorcast.db import init_db
from gatorcast.store import timeline as t
from gatorcast.store.sessions import LIST_SYSTEMS_SQL
from gatorcast.store.timeline import UnifiedQuery
from gatorcast.web.kinds import TYPE_GROUPS
from tests.fixtures.timeline import ALICE, PROD, WEB, WIKI, at, build_scenario, build_web_scenario

REC = TYPE_GROUPS["recordings"]
ANY = TYPE_GROUPS["any"]
AT = at("12:00:00.000")
KEY = ("s:ks-1", PROD, "uid-bob")

PlanRow = tuple[int, int, str]


@pytest.fixture
async def db(tmp_path: Path) -> aiosqlite.Connection:
    """A schema-initialized database holding the timeline scenario."""
    conn = await init_db(tmp_path / "plans.db")
    await build_scenario(conn)
    yield conn
    await conn.close()


async def plan(db: aiosqlite.Connection, sql: str, params: Sequence[object]) -> list[PlanRow]:
    """``EXPLAIN QUERY PLAN`` rows as ``(id, parent, detail)``."""
    cursor = await db.execute(f"EXPLAIN QUERY PLAN {sql}", tuple(params))
    rows = [(int(r[0]), int(r[1]), str(r[3])) for r in await cursor.fetchall()]
    await cursor.close()
    assert rows
    return rows


def details(rows: list[PlanRow]) -> list[str]:
    """Plan detail strings."""
    return [d for _, _, d in rows]


def lines_for(rows: list[PlanRow], alias: str) -> list[str]:
    """Plan lines that access table alias ``alias`` (``SCAN x`` / ``SEARCH x``)."""
    return [
        d for d in details(rows) if d.startswith((f"SCAN {alias} ", f"SEARCH {alias} "))
        or d in (f"SCAN {alias}", f"SEARCH {alias}")
    ]


def assert_alias_uses(rows: list[PlanRow], alias: str, index: str) -> None:
    """Every access to ``alias`` uses ``index``."""
    access = lines_for(rows, alias)
    assert access, f"no access to {alias} in plan: {details(rows)}"
    for line in access:
        assert f"INDEX {index}" in line, f"{alias}: {line}"


# --- Q1: sessions page, newest ----------------------------------------------------------


@pytest.mark.parametrize(
    ("q", "after"),
    [
        (UnifiedQuery(kinds=REC), None),
        (UnifiedQuery(kinds=REC), (AT, "s-x")),
        (UnifiedQuery(kinds=REC, from_=at("09:00:00.000"), to=AT), None),
        (UnifiedQuery(kinds=REC, user=ALICE), (AT, "s-x")),
        (UnifiedQuery(kinds=REC, system=WEB, system_set=True), None),
        (UnifiedQuery(kinds=TYPE_GROUPS["ssh"], status="complete"), None),
        (UnifiedQuery(kinds=TYPE_GROUPS["exec"]), (AT, "s-x")),
        (UnifiedQuery(kinds=TYPE_GROUPS["failed"]), None),
    ],
    ids=["plain", "keyset", "window", "user", "system", "ssh-status", "exec", "failed"],
)
async def test_q1_walks_idx_sessions_at_in_order(
    db: aiosqlite.Connection, q: UnifiedQuery, after: tuple[str, str] | None
) -> None:
    sql, params = t.sessions_page_sql(q, q.kinds, after, 51)
    rows = await plan(db, sql, params)
    assert_alias_uses(rows, "s", "idx_sessions_at")
    assert not any("TEMP B-TREE" in d for d in details(rows)), details(rows)
    if q.user is not None:
        assert_alias_uses(rows, "c", "sqlite_autoindex_connections_1")  # PK probe


async def test_q1_keyset_is_a_range_seek(db: aiosqlite.Connection) -> None:
    sql, params = t.sessions_page_sql(UnifiedQuery(kinds=REC), REC, (AT, "s-x"), 51)
    (line,) = lines_for(await plan(db, sql, params), "s")
    assert line.startswith("SEARCH s USING INDEX idx_sessions_at (")


# --- Q4 / Q4b: kubectl scan mode ---------------------------------------------------------


def _q4(q: UnifiedQuery, after: tuple[str, str] | None = (AT, "r-x")) -> tuple[str, list[object]]:
    return t.api_scan_sql(q, after, want=51, budget=20000, no_findings=True)


@pytest.mark.parametrize(
    ("q", "index"),
    [
        (UnifiedQuery(kinds=ANY), "idx_api_req_kind_time"),
        (UnifiedQuery(kinds=ANY, from_=at("09:00:00.000")), "idx_api_req_kind_time"),
        (UnifiedQuery(kinds=ANY, system=PROD, system_set=True), "idx_api_req_sys_kind_time"),
    ],
    ids=["time", "window", "system"],
)
async def test_q4_walks_a_time_range(
    db: aiosqlite.Connection, q: UnifiedQuery, index: str
) -> None:
    for sql, params in (_q4(q), _q4(q, None)):
        rows = await plan(db, sql, params)
        assert_alias_uses(rows, "r", index)
        assert any(d.startswith("CO-ROUTINE scanned") for d in details(rows))
        # The kind is an equality column of the index, so web rows are never walked.
        assert all("api_kind=?" in line for line in lines_for(rows, "r")), lines_for(rows, "r")
    sql, params = t.api_scan_frontier_sql(q, (AT, "r-x"), budget=20000)
    assert_alias_uses(await plan(db, sql, params), "r", index)
    sql, params = t.api_scan_frontier_sql(q, None, budget=20000)
    assert_alias_uses(await plan(db, sql, params), "r", index)


async def test_q4_user_union_uses_both_user_indexes_without_sorting_an_arm(
    db: aiosqlite.Connection,
) -> None:
    q = UnifiedQuery(kinds=ANY, user="uid-bob", text="pods")
    for sql, params in (_q4(q), _q4(q, None), t.api_scan_frontier_sql(q, (AT, "r-x"), budget=20000)):
        rows = await plan(db, sql, params)
        access = lines_for(rows, "r")
        assert len(access) == 2, details(rows)
        assert any("INDEX idx_api_req_kind_user_time (api_kind=? AND username=?" in a for a in access)
        assert any("INDEX idx_api_req_kind_userid_time (api_kind=? AND user_id=?" in a for a in access)
        # Each arm is a co-routine walking its index in order: nothing below it sorts
        # the range before the arm's LIMIT.
        arm_ids = [i for i, _, d in rows if d.startswith("CO-ROUTINE (subquery")]
        assert len(arm_ids) == 2
        for arm in arm_ids:
            children = [d for _, parent, d in rows if parent == arm]
            assert children and all(c.startswith("SEARCH r ") for c in children), children


async def test_q4_command_probes_use_idx_api_req_cmd(db: aiosqlite.Connection) -> None:
    q = UnifiedQuery(kinds=ANY, text="pods")  # start-row, discovery, text, no-findings
    rows = await plan(db, *_q4(q))
    for alias in ("p", "d", "t", "n"):
        assert_alias_uses(rows, alias, "idx_api_req_cmd")
    # the start-row probe is a range on the expression index
    (start_probe,) = lines_for(rows, "p")
    assert "<expr>=?" in start_probe and "requested_at<" in start_probe


# --- Q5: flagged mode -------------------------------------------------------------------


@pytest.mark.parametrize(
    "q",
    [
        UnifiedQuery(kinds=ANY, severity="high", sort="risk"),
        UnifiedQuery(kinds=ANY, has_findings=True, text="pods", user=ALICE),
        UnifiedQuery(kinds=ANY, max_severity="medium", from_=at("09:00:00.000")),
    ],
    ids=["severity", "user-text", "max-severity"],
)
async def test_q5_per_command_subqueries_use_idx_api_req_cmd(
    db: aiosqlite.Connection, q: UnifiedQuery
) -> None:
    sql, params = t.api_flagged_sql(
        q, None, want=51, cap=5000, risk=q.sort == "risk", any_finding=False
    )
    rows = await plan(db, sql, params)
    assert_alias_uses(rows, "q", "idx_api_req_cmd")
    if q.text is not None:
        assert_alias_uses(rows, "t", "idx_api_req_cmd")
    # hit is driven from api_findings (``api_findings f CROSS JOIN api_requests r``) and
    # joins through the api_requests primary key, with or without ``user``: the user and
    # kind predicates are filters on the probed row, not a second access path.
    assert_alias_uses(rows, "r", "sqlite_autoindex_api_requests_1")
    if q.user is not None:
        assert_alias_uses(rows, "f", "idx_api_findings_request")
    if q.severity is not None or q.max_severity is not None:
        assert_alias_uses(rows, "f", "idx_api_findings_severity")


# --- Q6a–c, Q7, Q9: hydration and focus --------------------------------------------------


@pytest.mark.parametrize(
    ("name", "params"),
    [
        ("CMD_AGGREGATE_SQL", KEY),
        ("CMD_FINDINGS_SQL", KEY),
        ("CMD_RECORDINGS_SQL", KEY),
        ("CMD_REQUESTS_SQL", (*KEY, 200)),
        ("FOCUS_START_SQL", KEY),
    ],
)
async def test_hydration_uses_idx_api_req_cmd(
    db: aiosqlite.Connection, name: str, params: tuple[object, ...]
) -> None:
    rows = await plan(db, getattr(t, name), params)
    assert_alias_uses(rows, "q", "idx_api_req_cmd")
    if name == "CMD_FINDINGS_SQL":
        assert_alias_uses(rows, "f", "idx_api_findings_request")
    if name == "CMD_RECORDINGS_SQL":
        assert_alias_uses(rows, "s", "idx_sessions_request")
    if name in ("CMD_REQUESTS_SQL", "FOCUS_START_SQL"):
        assert not any("TEMP B-TREE" in d for d in details(rows)), details(rows)


async def test_q9_focus_resolves_by_primary_key(db: aiosqlite.Connection) -> None:
    rows = await plan(db, t.FOCUS_RESOLVE_SQL, ("r-c1-2",))
    assert any("sqlite_autoindex_api_requests_1 (request_id=?)" in d for d in details(rows))


# --- Session 12: the web source (api_kind = 'web') ----------------------------------------------------

WEB_KEY = ("c:wc-a", WIKI, "uid-alice")  # (ck, resource_address, user_key) of a web connection


@pytest.fixture
async def web_db(db: aiosqlite.Connection) -> aiosqlite.Connection:
    """The scenario plus the web connections (so the planner sees both kinds)."""
    await build_web_scenario(db)
    return db


def _q4_web(
    q: UnifiedQuery, after: tuple[str, str] | None = (AT, "r-x"), *, no_findings: bool = True
) -> tuple[str, list[object]]:
    return t.api_scan_sql(
        q, after, want=51, budget=20000, no_findings=no_findings, api_kind="web", discovery=False
    )


@pytest.mark.parametrize(
    ("q", "index"),
    [
        (UnifiedQuery(kinds=ANY), "idx_api_req_kind_time"),
        (UnifiedQuery(kinds=ANY, from_=at("09:00:00.000")), "idx_api_req_kind_time"),
        (UnifiedQuery(kinds=ANY, scheme="tls13", upstream_null=True), "idx_api_req_kind_time"),
        (UnifiedQuery(kinds=ANY, system=WIKI, system_set=True), "idx_api_req_sys_kind_time"),
        (UnifiedQuery(kinds=ANY, system=None, system_set=True), "idx_api_req_sys_kind_time"),
        (
            UnifiedQuery(kinds=ANY, system=WIKI, system_set=True, scheme_null=True, text="home"),
            "idx_api_req_sys_kind_time",
        ),
    ],
    ids=["time", "window", "tls-filters", "system", "unknown-system", "system-tls-text"],
)
@pytest.mark.parametrize("no_findings", [True, False])
async def test_web_q4_walks_a_time_range_of_its_kind(
    web_db: aiosqlite.Connection, q: UnifiedQuery, index: str, no_findings: bool
) -> None:
    for after in ((AT, "r-x"), None):
        sql, params = _q4_web(q, after, no_findings=no_findings)
        assert "web" in params and "kubectl" not in params
        assert "gc_is_discovery" not in sql  # web has no discovery step
        rows = await plan(web_db, sql, params)
        assert_alias_uses(rows, "r", index)
        assert any(d.startswith("CO-ROUTINE scanned") for d in details(rows))
        # the kind is an equality column of the index, so kubectl rows are never walked
        assert all("api_kind=?" in line for line in lines_for(rows, "r")), lines_for(rows, "r")
        assert lines_for(rows, "d") == []  # no discovery probe
        for alias in ("p", "t", "n"):
            for line in lines_for(rows, alias):
                assert "INDEX idx_api_req_cmd" in line, (alias, line)
        assert lines_for(rows, "p"), "the start-row probe is always present"
        assert bool(lines_for(rows, "n")) is no_findings
    for after in ((AT, "r-x"), None):
        sql, params = t.api_scan_frontier_sql(q, after, budget=20000, api_kind="web")
        assert "web" in params
        assert_alias_uses(await plan(web_db, sql, params), "r", index)


async def test_web_q4_user_union_uses_both_user_indexes_without_sorting_an_arm(
    web_db: aiosqlite.Connection,
) -> None:
    q = UnifiedQuery(kinds=ANY, user="uid-bob", text="home", scheme="tls13")
    frontier = t.api_scan_frontier_sql(q, (AT, "r-x"), budget=20000, api_kind="web")
    for sql, params in (_q4_web(q), _q4_web(q, None), frontier):
        rows = await plan(web_db, sql, params)
        access = lines_for(rows, "r")
        assert len(access) == 2, details(rows)
        assert any("INDEX idx_api_req_kind_user_time (api_kind=? AND username=?" in a for a in access)
        assert any("INDEX idx_api_req_kind_userid_time (api_kind=? AND user_id=?" in a for a in access)
        arm_ids = [i for i, _, d in rows if d.startswith("CO-ROUTINE (subquery")]
        assert len(arm_ids) == 2
        for arm in arm_ids:
            children = [d for _, parent, d in rows if parent == arm]
            assert children and all(c.startswith("SEARCH r ") for c in children), children


async def test_web_q4_command_probes_use_idx_api_req_cmd(web_db: aiosqlite.Connection) -> None:
    q = UnifiedQuery(kinds=ANY, text="home", scheme="tls13")  # start-row, text, no-findings probes
    rows = await plan(web_db, *_q4_web(q))
    for alias in ("p", "t", "n"):
        assert_alias_uses(rows, alias, "idx_api_req_cmd")
    (start_probe,) = lines_for(rows, "p")
    assert "<expr>=?" in start_probe and "requested_at<" in start_probe
    assert_alias_uses(rows, "nf", "idx_api_findings_request")


# Q6a-c, Q7, Q9: the hydration and focus statements of the web instance.
_WEB_SQL = t._cmd_sql("web", False)


@pytest.mark.parametrize(
    ("name", "params"),
    [
        ("aggregate", WEB_KEY),
        ("findings", WEB_KEY),
        ("recordings", WEB_KEY),
        ("requests", (*WEB_KEY, 200)),
        ("start", WEB_KEY),
    ],
)
async def test_web_hydration_uses_idx_api_req_cmd(
    web_db: aiosqlite.Connection, name: str, params: tuple[object, ...]
) -> None:
    sql = getattr(_WEB_SQL, name)
    assert "api_kind" in sql and "'web'" in sql and "'kubectl'" not in sql
    rows = await plan(web_db, sql, params)
    assert_alias_uses(rows, "q", "idx_api_req_cmd")
    if name == "findings":
        assert_alias_uses(rows, "f", "idx_api_findings_request")
    if name == "recordings":
        assert_alias_uses(rows, "s", "idx_sessions_request")
    if name in ("requests", "start"):
        assert not any("TEMP B-TREE" in d for d in details(rows)), details(rows)


async def test_web_aggregate_does_not_call_the_discovery_function(web_db: aiosqlite.Connection) -> None:
    assert "gc_is_discovery" not in _WEB_SQL.aggregate
    assert "gc_is_discovery" in t._cmd_sql("kubectl", True).aggregate


async def test_web_q9_focus_resolves_by_primary_key(web_db: aiosqlite.Connection) -> None:
    assert "api_kind = 'web'" in _WEB_SQL.resolve
    rows = await plan(web_db, _WEB_SQL.resolve, ("ww-a2",))
    assert any("sqlite_autoindex_api_requests_1 (request_id=?)" in d for d in details(rows)), details(rows)
    # the kind is a residual filter on the one row found, never a second access path
    assert len(lines_for(rows, "api_requests")) == 1
    cursor = await web_db.execute(_WEB_SQL.resolve, ("ww-a2",))
    assert len(await cursor.fetchall()) == 1
    await cursor.close()
    cursor = await web_db.execute(_WEB_SQL.resolve, ("r-c1-1",))  # a kubectl request id
    assert await cursor.fetchall() == []
    await cursor.close()


# --- Q8: recording findings ------------------------------------------------------------------


async def test_q8_uses_idx_findings_conn(db: aiosqlite.Connection) -> None:
    sql = t._FINDINGS_FOR_SESSIONS_SQL.format(ph="?, ?, ?")
    rows = await plan(db, sql, ("s-ssh-alice", "s-crit", "s-low"))
    assert any("INDEX idx_findings_conn" in d for d in details(rows)), details(rows)


# --- Q12: list_systems ------------------------------------------------------------------------

# Indexes Session 10 added (spec §7.1). ``list_systems`` must use none of them (§7.5).
_SESSION_10_INDEXES = (
    "idx_api_req_cmd",
    "idx_api_req_kind_user_time",
    "idx_api_req_kind_userid_time",
    "idx_sessions_at",
)


async def test_q12_list_systems_needs_no_new_index(db: aiosqlite.Connection) -> None:
    rows = await plan(db, LIST_SYSTEMS_SQL, ())
    # API arm: one covering scan of an index led by resource_address (no per-row table
    # lookup). Which one varies by SQLite version: 3.49 picks idx_api_req_sys_kind_time,
    # older builds (CI's Ubuntu libsqlite3) may pick idx_api_req_sys_kind_user_time, which
    # covers the same three columns.
    (api_access,) = lines_for(rows, "r")
    assert api_access.startswith("SCAN r "), api_access
    assert any(
        f"COVERING INDEX {name}" in api_access
        for name in ("idx_api_req_sys_kind_time", "idx_api_req_sys_kind_user_time")
    ), api_access
    # The kind split is two conditional aggregates, never a WHERE filter (which would
    # flip the plan to a non-covering scan with a temp b-tree).
    assert "api_kind=?" not in api_access, api_access
    # Sessions arm: a full scan of the small sessions table (in address order through
    # idx_sessions_resource when the planner picks it), never a Session 10 index.
    (sessions_access,) = lines_for(rows, "s")
    assert sessions_access.startswith("SCAN s"), sessions_access
    if "INDEX" in sessions_access:
        assert "INDEX idx_sessions_resource" in sessions_access, sessions_access
    for line in details(rows):
        assert not any(name in line for name in _SESSION_10_INDEXES), line


# --- activity reads (requests_for_system / requests_in_bounds) -------------------------------


async def _captured_select(db: aiosqlite.Connection, run) -> str:
    """Run ``run()`` and return the last ``SELECT`` it executed, with parameters expanded."""
    statements: list[str] = []
    await db.set_trace_callback(statements.append)
    try:
        await run()
    finally:
        await db.set_trace_callback(None)
    selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert selects, statements
    return selects[-1]


async def test_requests_for_system_walks_the_system_kind_time_index_without_a_sort(
    db: aiosqlite.Connection,
) -> None:
    from gatorcast.store.activity import ActivityStore

    store = ActivityStore(db)
    sql = await _captured_select(
        db,
        lambda: store.requests_for_system(PROD, at("00:00:00.000"), at("23:00:00.000"), api_kind="kubectl"),
    )
    rows = await plan(db, sql, ())
    assert_alias_uses(rows, "api_requests", "idx_api_req_sys_kind_time")
    (line,) = lines_for(rows, "api_requests")
    assert "resource_address=? AND api_kind=?" in line, line


async def test_requests_in_bounds_walks_the_system_kind_user_index_without_a_sort(
    db: aiosqlite.Connection,
) -> None:
    from gatorcast.store.activity import ActivityStore

    store = ActivityStore(db)
    sql = await _captured_select(
        db,
        lambda: store.requests_in_bounds(PROD, "uid-bob", at("00:00:00.000"), at("23:00:00.000")),
    )
    rows = await plan(db, sql, ())
    assert_alias_uses(rows, "api_requests", "idx_api_req_sys_kind_user_time")
    assert not any("TEMP B-TREE" in d for d in details(rows)), details(rows)
    (line,) = lines_for(rows, "api_requests")
    assert "resource_address=? AND api_kind=? AND user_key=?" in line, line


async def test_no_plan_uses_a_retired_index(db: aiosqlite.Connection) -> None:
    """The five replaced indexes no longer exist, so no query can name one."""
    cursor = await db.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
    names = {r[0] for r in await cursor.fetchall()}
    for retired in (
        "idx_api_req_time",
        "idx_api_req_user_time",
        "idx_api_req_userid_time",
        "idx_api_req_sys_time",
        "idx_api_req_sys_user_time",
    ):
        assert retired not in names
