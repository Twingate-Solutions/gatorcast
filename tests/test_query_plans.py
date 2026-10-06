"""Pinned query plans for the unified timeline (Session 10 T4, spec §7.4, §12).

Each test runs ``EXPLAIN QUERY PLAN`` over the exact SQL the engine builds and pins
the *index names* used (not the full plan text), so the assertions hold across
SQLite releases (local 3.49; the ``python:3.12-slim`` image ships ~3.40).

Q12 (``list_systems``, T8) is pinned at the end: its API arm is a covering scan of
``idx_api_req_sys_time`` and it uses no Session 10 index (spec §7.5).
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
from tests.fixtures.timeline import ALICE, PROD, WEB, at, build_scenario

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
        (UnifiedQuery(kinds=ANY), "idx_api_req_time"),
        (UnifiedQuery(kinds=ANY, from_=at("09:00:00.000")), "idx_api_req_time"),
        (UnifiedQuery(kinds=ANY, system=PROD, system_set=True), "idx_api_req_sys_time"),
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
        assert any("INDEX idx_api_req_user_time (username=?" in a for a in access)
        assert any("INDEX idx_api_req_userid_time (user_id=?" in a for a in access)
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
    if q.user is None:
        # hit is driven from api_findings and joins through the api_requests PK
        assert_alias_uses(rows, "r", "sqlite_autoindex_api_requests_1")
    else:
        # with `user`, hit walks the two user indexes (OR) and probes the findings
        access = " ".join(lines_for(rows, "r"))
        assert "idx_api_req_user_time" in access and "idx_api_req_userid_time" in access
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


# --- Q8: recording findings ------------------------------------------------------------------


async def test_q8_uses_idx_findings_conn(db: aiosqlite.Connection) -> None:
    sql = t._FINDINGS_FOR_SESSIONS_SQL.format(ph="?, ?, ?")
    rows = await plan(db, sql, ("s-ssh-alice", "s-crit", "s-low"))
    assert any("INDEX idx_findings_conn" in d for d in details(rows)), details(rows)


# --- Q12: list_systems ------------------------------------------------------------------------

# Indexes Session 10 added (spec §7.1). ``list_systems`` must use none of them (§7.5).
_SESSION_10_INDEXES = (
    "idx_api_req_cmd",
    "idx_api_req_user_time",
    "idx_api_req_userid_time",
    "idx_sessions_at",
)


async def test_q12_list_systems_needs_no_new_index(db: aiosqlite.Connection) -> None:
    rows = await plan(db, LIST_SYSTEMS_SQL, ())
    # API arm: one covering scan of idx_api_req_sys_time (no per-row table lookup).
    (api_access,) = lines_for(rows, "r")
    assert api_access.startswith("SCAN r "), api_access
    assert "COVERING INDEX idx_api_req_sys_time" in api_access
    # Sessions arm: a full scan of the small sessions table (in address order through
    # idx_sessions_resource when the planner picks it), never a Session 10 index.
    (sessions_access,) = lines_for(rows, "s")
    assert sessions_access.startswith("SCAN s"), sessions_access
    if "INDEX" in sessions_access:
        assert "INDEX idx_sessions_resource" in sessions_access, sessions_access
    for line in details(rows):
        assert not any(name in line for name in _SESSION_10_INDEXES), line
