"""Tests for the unified timeline engine (Session 10 T4, spec §6, §12).

Every paging test walks ``run_timeline`` page by page (round-tripping each cursor
through the URL encoder, as the route will) and compares the result with an
independent brute-force oracle written in plain Python over the same rows.
"""

from __future__ import annotations

import io
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import aiosqlite
import pytest
import structlog

from gatorcast.db import FAILED_SQL, init_db
from gatorcast.pipeline.activity import is_discovery
from gatorcast.pipeline.detect import SEVERITY_RANK
from gatorcast.store import timeline
from gatorcast.store.casts import CastStore
from gatorcast.store.timeline import (
    KIND_EXEC,
    KIND_FAILED,
    KIND_KUBECTL,
    KIND_SSH,
    PHASE_FLAGGED,
    PHASE_SCAN,
    POSITION_DONE,
    SOURCE_API_COMMANDS,
    SOURCE_SESSIONS,
    CommandHit,
    Cursor,
    RecordingHit,
    TimelineItem,
    TimelinePage,
    UnifiedQuery,
    build_sources,
    run_timeline,
    session_kind,
)
from gatorcast.web.kinds import TYPE_GROUPS, resolve_kinds
from gatorcast.web.params import decode_cursor, encode_cursor
from tests.fixtures.timeline import (
    ALICE,
    ALICE_ID,
    BOB,
    BOB_ID,
    CAROL,
    CAROL_ID,
    DAVE_ID,
    DEV,
    K9S_REQUESTS,
    PROD,
    WEB,
    at,
    build_scenario,
)

REC = TYPE_GROUPS["recordings"]
ANY = TYPE_GROUPS["any"]
KUBECTL = TYPE_GROUPS["kubectl"]
SENTINEL = "GC_SENTINEL_SIDECAR_TEXT"

Ident = tuple[str, str]


# --- environment -----------------------------------------------------------------------


@dataclass
class Env:
    """A scenario database plus a cast store."""

    db: aiosqlite.Connection
    casts: CastStore
    tmp: Path


@pytest.fixture
async def env(tmp_path: Path) -> Env:
    """The full spec §12 scenario in a fresh database."""
    db = await init_db(tmp_path / "timeline.db")
    casts = CastStore(tmp_path / "casts")
    await build_scenario(db)
    yield Env(db=db, casts=casts, tmp=tmp_path)
    await db.close()


def ident(item: TimelineItem) -> Ident:
    """Stable identity of a hydrated item: ``("rec", conn_id)`` / ``("cmd", id)``."""
    if isinstance(item.data, RecordingHit):
        return ("rec", item.data.session.conn_id)
    assert isinstance(item.data, CommandHit)
    return ("cmd", item.data.command_id)


def q_(kinds: frozenset[str] = ANY, **kw: Any) -> UnifiedQuery:
    """Build a query."""
    return UnifiedQuery(kinds=kinds, **kw)


async def run_page(
    env: Env,
    q: UnifiedQuery,
    *,
    limit: int = 50,
    cursor: Cursor | None = None,
    content_budget: int = 2000,
) -> TimelinePage:
    """One page with the kinds resolved as the route resolves them."""
    kinds, excluded = resolve_kinds(q)
    sources = build_sources(env.db, env.casts, content_budget=content_budget)
    return await run_timeline(sources, q, kinds, cursor=cursor, limit=limit, excluded=excluded)


async def walk(
    env: Env,
    q: UnifiedQuery,
    *,
    page_size: int,
    content_budget: int = 2000,
    max_pages: int = 2000,
) -> tuple[list[TimelineItem], list[TimelinePage]]:
    """Walk every page, round-tripping the cursor through the URL codec."""
    kinds, excluded = resolve_kinds(q)
    sources = build_sources(env.db, env.casts, content_budget=content_budget)
    cursor: Cursor | None = None
    items: list[TimelineItem] = []
    pages: list[TimelinePage] = []
    for _ in range(max_pages):
        page = await run_timeline(
            sources, q, kinds, cursor=cursor, limit=page_size, excluded=excluded
        )
        assert len(page.items) <= page_size
        pages.append(page)
        items.extend(page.items)
        if page.next_cursor is None:
            break
        cursor = decode_cursor(encode_cursor(page.next_cursor))
    else:  # pragma: no cover - a walk that never ends is a failure
        pytest.fail("walk did not terminate")
    ids = [ident(it) for it in items]
    assert len(ids) == len(set(ids)), "an item was emitted twice"
    return items, pages


# --- brute-force oracle -------------------------------------------------------------------


def _rank(sev: str | None) -> int:
    return SEVERITY_RANK.get(sev or "", 0)


async def _rows(db: aiosqlite.Connection, sql: str) -> list[dict[str, Any]]:
    cursor = await db.execute(sql)
    rows = [dict(r) for r in await cursor.fetchall()]
    await cursor.close()
    return rows


async def oracle(
    env: Env, q: UnifiedQuery, sidecars: dict[str, str] | None = None
) -> list[Ident]:
    """Every expected item, in expected order, computed in plain Python (spec §4.3, §6)."""
    kinds, _ = resolve_kinds(q)
    sidecars = sidecars or {}
    keyed: list[tuple[tuple[Any, ...], Ident]] = []

    if kinds & REC:
        sessions = await _rows(
            env.db,
            "SELECT *, strftime('%Y-%m-%dT%H:%M:%fZ', COALESCE(started_at, created_at)) AS gc_at "
            "FROM sessions",
        )
        conn_uid = {
            r["conn_id"]: r["user_id"]
            for r in await _rows(env.db, "SELECT conn_id, user_id FROM connections")
        }
        fnd: dict[str, list[dict[str, Any]]] = {}
        for f in await _rows(env.db, "SELECT * FROM findings"):
            fnd.setdefault(f["conn_id"], []).append(f)
        compiled = re.compile(q.regex) if q.regex else None
        for s in sessions:
            cid = s["conn_id"]
            if session_kind(s) not in kinds or s["gc_at"] is None:
                continue
            fs = fnd.get(cid, [])
            a = s["gc_at"]
            if q.system_set and s["resource_address"] != q.system:
                continue
            if q.user is not None and not (s["username"] == q.user or conn_uid.get(cid) == q.user):
                continue
            if q.from_ is not None and a < q.from_:
                continue
            if q.to is not None and a > q.to:
                continue
            if q.status is not None and s["status"] != q.status:
                continue
            dur = s["duration_seconds"]
            if q.min_duration is not None and (dur is None or dur < q.min_duration):
                continue
            if q.max_duration is not None and (dur is None or dur > q.max_duration):
                continue
            if q.has_findings is True and not s["finding_count"]:
                continue
            if q.has_findings is False and s["finding_count"]:
                continue
            if q.max_severity is not None and s["max_severity"] != q.max_severity:
                continue
            if q.category is not None and not any(f["category"] == q.category for f in fs):
                continue
            if q.rule_ids and not any(f["rule_id"] in q.rule_ids for f in fs):
                continue
            if q.severity is not None and not any(
                _rank(f["severity"]) >= _rank(q.severity) for f in fs
            ):
                continue
            if q.text is not None or q.regex is not None:
                text = sidecars.get(cid)
                if text is None:
                    continue
                if q.text is not None and q.text.lower() not in text.lower():
                    continue
                if compiled is not None and compiled.search(text) is None:
                    continue
            match q.sort:
                case "risk":
                    key: tuple[Any, ...] = (_rank(s["max_severity"]), a, 0, cid)
                case "duration":
                    key = (int(dur is not None), float(dur or 0), 0, cid)
                case _:
                    key = (a, 0, cid)
            keyed.append((key, ("rec", cid)))

    if KIND_KUBECTL in kinds:
        reqs = await _rows(env.db, "SELECT * FROM api_requests")
        afnd: dict[str, list[dict[str, Any]]] = {}
        for f in await _rows(env.db, "SELECT * FROM api_findings"):
            afnd.setdefault(f["request_id"], []).append(f)
        groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        for r in reqs:
            ck = f"s:{r['kubectl_session']}" if r["kubectl_session"] else f"c:{r['conn_id']}"
            groups.setdefault((r["resource_address"], r["user_key"], ck), []).append(r)
        for rows in groups.values():
            rows.sort(key=lambda r: (r["requested_at"], r["request_id"]))
            start = rows[0]
            fs = [f for r in rows for f in afnd.get(r["request_id"], [])]
            max_rank = max((_rank(f["severity"]) for f in fs), default=0)
            if q.cmd is not None:
                if any(r["request_id"] == q.cmd for r in rows):
                    keyed.append(((start["requested_at"], 1, start["request_id"]),
                                  ("cmd", start["request_id"])))
                continue
            a = start["requested_at"]
            if q.system_set and start["resource_address"] != q.system:
                continue
            if q.user is not None and q.user not in (start["username"], start["user_id"]):
                continue
            if q.from_ is not None and a < q.from_:
                continue
            if q.to is not None and a > q.to:
                continue
            flagged = bool(
                q.severity or q.max_severity or q.has_findings is True or q.category or q.rule_ids
            )
            if not q.discovery and not flagged and all(
                is_discovery(r["method"], r["url"]) for r in rows
            ):
                continue
            if q.text is not None:
                needle = q.text.lower()
                if not any(
                    needle in r["url"].split("?", 1)[0].lower()
                    or needle in (r["kubectl_command"] or "").lower()
                    for r in rows
                ):
                    continue
            if q.has_findings is False and fs:
                continue
            if flagged:
                def ok(f: dict[str, Any]) -> bool:
                    return (
                        (q.severity is None or _rank(f["severity"]) >= _rank(q.severity))
                        and (q.max_severity is None or f["severity"] == q.max_severity)
                        and (q.category is None or f["category"] == q.category)
                        and (not q.rule_ids or f["rule_id"] in q.rule_ids)
                    )

                if not any(ok(f) for f in fs):
                    continue
                if q.max_severity is not None and max_rank != _rank(q.max_severity):
                    continue
            if q.sort == "risk":
                key = (max_rank, a, 1, start["request_id"])
            else:
                key = (a, 1, start["request_id"])
            keyed.append((key, ("cmd", start["request_id"])))

    keyed.sort(key=lambda kv: kv[0], reverse=True)
    return [i for _, i in keyed]


async def ids_of(env: Env, q: UnifiedQuery, *, page_size: int = 200) -> list[Ident]:
    """All item idents of a query, in order."""
    items, _ = await walk(env, q, page_size=page_size)
    return [ident(it) for it in items]


def cmds(ids: Iterable[Ident]) -> set[str]:
    """Command ids among idents."""
    return {i for k, i in ids if k == "cmd"}


def recs(ids: Iterable[Ident]) -> set[str]:
    """Recording ids among idents."""
    return {i for k, i in ids if k == "rec"}


async def item_for(env: Env, q: UnifiedQuery, want: Ident) -> TimelineItem:
    """The hydrated item with identity ``want``."""
    items, _ = await walk(env, q, page_size=200)
    for it in items:
        if ident(it) == want:
            return it
    pytest.fail(f"{want} not listed")


# --- identity (spec §3, §6.3) ----------------------------------------------------------------


async def test_kubectl_session_groups_across_two_connections(env: Env) -> None:
    item = await item_for(env, q_(KUBECTL, discovery=True), ("cmd", "r-c1-1"))
    hit = item.data
    assert isinstance(hit, CommandHit)
    assert hit.request_count == 3
    assert hit.command.conn_ids == ("conn-a", "conn-b")
    assert hit.started_at == at("11:00:00.000")
    assert hit.ended_at == at("11:00:01.000")
    assert hit.discovery_count == 1
    assert hit.label == "kubectl get"


async def test_empty_header_is_absent_and_groups_by_connection(env: Env) -> None:
    ids = await ids_of(env, q_(KUBECTL))
    assert "r-empty-1" in cmds(ids)
    assert "r-empty-2" not in cmds(ids)
    item = await item_for(env, q_(KUBECTL), ("cmd", "r-empty-1"))
    assert item.data.request_count == 2  # type: ignore[union-attr]


async def test_header_shaped_like_connection_key_does_not_merge(env: Env) -> None:
    ids = cmds(await ids_of(env, q_(KUBECTL)))
    assert {"r-cx-1", "r-k9s-000"} <= ids
    item = await item_for(env, q_(KUBECTL), ("cmd", "r-cx-1"))
    assert item.data.request_count == 1  # type: ignore[union-attr]


async def test_same_session_id_under_two_users_is_two_commands(env: Env) -> None:
    ids = cmds(await ids_of(env, q_(KUBECTL)))
    assert {"r-sh-a", "r-sh-b"} <= ids


# --- window (spec §3) --------------------------------------------------------------------------


async def test_command_starting_before_window_is_excluded(env: Env) -> None:
    ids = cmds(await ids_of(env, q_(KUBECTL, from_=at("09:00:00.000"))))
    assert "r-early-1" not in ids and "r-early-2" not in ids
    assert "r-dave-1" in ids  # starts inside the window


async def test_command_starting_inside_window_is_shown_whole(env: Env) -> None:
    q = q_(KUBECTL, from_=at("13:59:00.000"), to=at("14:00:00.000"))
    ids = await ids_of(env, q)
    assert ids == [("cmd", "r-late-1")]
    item = await item_for(env, q, ("cmd", "r-late-1"))
    hit = item.data
    assert isinstance(hit, CommandHit)
    assert hit.request_count == 2
    assert hit.ended_at == at("14:00:10.000")  # after `to`, still included


async def test_recording_window_uses_normalized_start(env: Env) -> None:
    ids = recs(await ids_of(env, q_(REC, from_=at("09:00:00.000"), to=at("09:59:59.999"))))
    assert ids == {"s-created"}  # NULL started_at → created_at 09:30:00


# --- paging: every page exactly once, per source and sort (spec §6.4) -------------------------


@pytest.mark.parametrize("page_size", [1, 3, 7])
@pytest.mark.parametrize(
    ("kinds", "sort"),
    [
        (REC, "newest"),
        (REC, "risk"),
        (REC, "duration"),
        (KUBECTL, "newest"),
        (KUBECTL, "risk"),
    ],
)
async def test_walk_each_source_and_sort(
    env: Env, kinds: frozenset[str], sort: str, page_size: int
) -> None:
    q = q_(kinds, sort=sort)
    items, pages = await walk(env, q, page_size=page_size)
    assert [ident(it) for it in items] == await oracle(env, q)
    assert pages[-1].next_cursor is None
    assert all(not p.budget_hit for p in pages)
    # full pages until the last
    assert all(len(p.items) == page_size for p in pages[:-1])


@pytest.mark.parametrize("page_size", [1, 4, 50])
@pytest.mark.parametrize("sort", ["newest", "risk"])
@pytest.mark.parametrize("discovery", [False, True])
async def test_mixed_walk_equals_brute_force(
    env: Env, sort: str, page_size: int, discovery: bool
) -> None:
    q = q_(ANY, sort=sort, discovery=discovery)
    items, _ = await walk(env, q, page_size=page_size)
    expected = await oracle(env, q)
    assert [ident(it) for it in items] == expected
    assert recs(expected) and cmds(expected)  # really mixed


async def test_mixed_walk_duration_lists_recordings_only(env: Env) -> None:
    q = q_(ANY, sort="duration")
    page = await run_page(env, q)
    assert page.excluded == {KIND_KUBECTL: "sort"}
    items, _ = await walk(env, q, page_size=2)
    assert [ident(it) for it in items] == await oracle(env, q)
    assert not cmds(ident(it) for it in items)


async def test_equal_timestamps_are_ordered_by_source_then_id(env: Env) -> None:
    ids = await ids_of(env, q_(ANY, discovery=True), page_size=1)
    # session and command share 11:00:00.000: api_commands (rank 1) first under DESC.
    assert ids.index(("cmd", "r-c1-1")) + 1 == ids.index(("rec", "s-same-at"))
    # two commands at 12:40:00.000 and two recordings at 10:30:00.000: id DESC.
    assert ids.index(("cmd", "r-xss")) + 1 == ids.index(("cmd", "r-eq"))
    assert ids.index(("rec", "s-tie-b")) + 1 == ids.index(("rec", "s-tie-a"))


async def test_last_page_marks_every_source_done(env: Env) -> None:
    _, pages = await walk(env, q_(ANY), page_size=5)
    assert pages[-1].next_cursor is None
    for page in pages[:-1]:
        assert page.next_cursor is not None
        assert page.next_cursor.kinds == tuple(sorted(ANY))
    second_to_last = pages[-2].next_cursor if len(pages) > 1 else None
    if second_to_last is not None:
        assert set(second_to_last.positions) <= {SOURCE_SESSIONS, SOURCE_API_COMMANDS}


async def test_cursor_for_other_query_is_rejected(env: Env) -> None:
    page = await run_page(env, q_(ANY), limit=2)
    assert page.next_cursor is not None
    with pytest.raises(ValueError):
        await run_page(env, q_(ANY, sort="risk"), limit=2, cursor=page.next_cursor)


async def test_no_kinds_is_an_empty_final_page(env: Env) -> None:
    q = q_(TYPE_GROUPS["ssh"], cmd="r-c1-1")
    page = await run_page(env, q)
    assert page.items == [] and page.next_cursor is None
    assert page.excluded == {KIND_SSH: "cmd"}


# --- frontier and Continue (spec §6.4) --------------------------------------------------------


@pytest.mark.parametrize(
    "q",
    [
        q_(KUBECTL),
        q_(KUBECTL, text="nodes"),
        q_(KUBECTL, sort="risk"),
        q_(KUBECTL, user=ALICE),
        q_(KUBECTL, system=PROD, system_set=True, has_findings=False),
        q_(ANY),
        q_(ANY, sort="risk"),
    ],
    ids=["kubectl", "text", "risk", "user", "system-nofindings", "any", "any-risk"],
)
async def test_scan_budget_frontier_resumes_without_loss(
    env: Env, monkeypatch: pytest.MonkeyPatch, q: UnifiedQuery
) -> None:
    monkeypatch.setattr(timeline, "_API_SCAN_BUDGET", 7)
    items, pages = await walk(env, q, page_size=3)
    assert [ident(it) for it in items] == await oracle(env, q)
    short = [p for p in pages if p.budget_hit]
    assert short, "the patched budget never stopped a page"
    assert all(p.scan_budget_hit and p.next_cursor is not None for p in short)
    assert all(p.scan_budget == 7 for p in pages)
    # the 250-row k9s connection forces pages that hold nothing yet still advance
    empty = [p for p in pages if not p.items and p.next_cursor is not None]
    assert empty
    for page in empty:
        pos = page.next_cursor.positions[SOURCE_API_COMMANDS]  # type: ignore[union-attr]
        assert pos != POSITION_DONE and pos[0] == PHASE_SCAN


async def test_zero_item_page_advances_the_cursor(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(timeline, "_API_SCAN_BUDGET", 5)
    q = q_(KUBECTL, from_=at("12:00:00.000"), to=at("12:00:24.900"), text="nodes")
    first = await run_page(env, q, limit=2)
    assert first.items == [] and first.budget_hit and first.scan_budget_hit
    assert first.next_cursor is not None
    second = await run_page(env, q, limit=2, cursor=first.next_cursor)
    assert second.next_cursor != first.next_cursor


# --- content search (spec §6.2) ----------------------------------------------------------------


async def _write_sidecars(env: Env) -> dict[str, str]:
    """Sidecars for every recording with a cast; three contain the needle."""
    texts: dict[str, str] = {}
    cursor = await env.db.execute("SELECT conn_id, cast_path FROM sessions")
    for row in await cursor.fetchall():
        if row["cast_path"] is None:
            continue  # failed connection: no sidecar
        texts[row["conn_id"]] = f"$ ls\nplain output {SENTINEL}\n"
    await cursor.close()
    texts["s-ssh-alice"] += "found NeedleWord here\n"
    texts["s-tie-b"] += "needleword lower\n"
    texts["s-created"] += "NEEDLEWORD upper\n"
    texts["s-exec-bob"] += "kubectl get pods\n"
    del texts["s-prov"]  # in progress: no sidecar until seal
    for conn_id, text in texts.items():
        await env.casts.write_sidecar(conn_id, text)
    return texts


@pytest.fixture
def timeline_log(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    """Swap the timeline logger for one rendering JSON lines to a buffer."""
    buffer = io.StringIO()
    logger = structlog.wrap_logger(
        structlog.PrintLogger(file=buffer),
        processors=[structlog.processors.add_log_level, structlog.processors.JSONRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
    )
    monkeypatch.setattr(timeline, "log", logger)
    return buffer


async def test_content_search_matches_case_insensitively(env: Env) -> None:
    texts = await _write_sidecars(env)
    q = q_(REC, text="needleword")
    ids = await ids_of(env, q)
    assert recs(ids) == {"s-ssh-alice", "s-tie-b", "s-created"}
    assert ids == await oracle(env, q, texts)


async def test_regex_search_and_legacy_keyword_and_regex(env: Env) -> None:
    texts = await _write_sidecars(env)
    q = q_(REC, regex=r"Needle\w+")
    assert recs(await ids_of(env, q)) == {"s-ssh-alice"}
    both = q_(REC, text="needleword", regex=r"[A-Z]{10}")
    assert recs(await ids_of(env, both)) == {"s-created"}
    assert await ids_of(env, both) == await oracle(env, both, texts)


async def test_content_budget_frontier_and_counters_only_log(
    env: Env, monkeypatch: pytest.MonkeyPatch, timeline_log: io.StringIO
) -> None:
    texts = await _write_sidecars(env)
    reads: list[str] = []
    real = env.casts.read_sidecar

    async def counting(conn_id: str) -> str:
        reads.append(conn_id)
        return await real(conn_id)

    monkeypatch.setattr(env.casts, "read_sidecar", counting)
    q = q_(REC, text="needleword")
    kinds, excluded = resolve_kinds(q)
    sources = build_sources(env.db, env.casts, content_budget=2)
    cursor: Cursor | None = None
    got: list[Ident] = []
    pages: list[TimelinePage] = []
    while True:
        reads.clear()
        page = await run_timeline(sources, q, kinds, cursor=cursor, limit=2, excluded=excluded)
        assert len(reads) <= 2, "more sidecars read than the per-page budget"
        pages.append(page)
        got.extend(ident(it) for it in page.items)
        if page.next_cursor is None:
            break
        cursor = decode_cursor(encode_cursor(page.next_cursor))
    assert got == await oracle(env, q, texts)
    assert any(p.content_budget_hit and not p.items for p in pages)
    assert all(p.content_budget == 2 for p in pages)
    events = [json.loads(line) for line in timeline_log.getvalue().splitlines() if line]
    hits = [e for e in events if e["event"] == "timeline.content_budget_hit"]
    assert hits
    for e in hits:
        assert set(e) == {"event", "level", "scanned", "matched"}
    assert SENTINEL not in timeline_log.getvalue()
    assert "needleword" not in timeline_log.getvalue().lower()


async def test_mixed_text_search_with_small_content_budget(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    texts = await _write_sidecars(env)
    monkeypatch.setattr(timeline, "_API_SCAN_BUDGET", 9)
    q = q_(ANY, text="kubectl get pods")
    items, pages = await walk(env, q, page_size=1, content_budget=3)
    ids = [ident(it) for it in items]
    assert ids == await oracle(env, q, texts)
    assert ("rec", "s-exec-bob") in ids and ("cmd", "r-dev-1") in ids
    assert any(p.budget_hit for p in pages)


async def test_provisional_and_failed_rows_never_match_content(env: Env) -> None:
    await _write_sidecars(env)
    ids = recs(await ids_of(env, q_(REC, text="plain output")))
    assert "s-prov" not in ids and "s-failed" not in ids
    assert "s-ssh-bob" in ids


# --- filters (spec §4.3) ----------------------------------------------------------------------------


async def test_discovery_only_hidden_by_default(env: Env) -> None:
    assert "r-disc-1" not in cmds(await ids_of(env, q_(KUBECTL)))
    assert "r-disc-1" in cmds(await ids_of(env, q_(KUBECTL, discovery=True)))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("zebrafish", set()),  # only in a query string
        ("/secrets/", {"r-med", "r-hm-1"}),  # path
        ("kubectl cordon", {"r-low"}),  # Kubectl-Command
        ("PODS/WEB-2", {"r-high"}),  # case-insensitive
    ],
)
async def test_text_matches_path_and_command_not_query(
    env: Env, text: str, expected: set[str]
) -> None:
    q = q_(KUBECTL, text=text)
    ids = await ids_of(env, q)
    assert cmds(ids) == expected
    assert ids == await oracle(env, q)


async def test_regex_and_status_exclude_kubectl_with_reason(env: Env) -> None:
    page = await run_page(env, q_(ANY, regex="x"))
    assert page.excluded == {KIND_KUBECTL: "regex"}
    page = await run_page(env, q_(ANY, status="complete"))
    assert page.excluded == {KIND_KUBECTL: "status"}
    assert not cmds(ident(it) for it in page.items)
    assert recs(ident(it) for it in page.items)


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"severity": "high"}, {"r-exec-get", "r-high", "r-crit", "r-hm-1"}),
        ({"severity": "medium"}, {"r-exec-get", "r-high", "r-crit", "r-hm-1", "r-med"}),
        ({"max_severity": "high"}, {"r-exec-get", "r-high", "r-hm-1"}),
        ({"max_severity": "medium"}, {"r-med"}),  # high+medium command is high only
        ({"max_severity": "critical"}, {"r-crit"}),
        ({"has_findings": True}, {"r-exec-get", "r-low", "r-med", "r-high", "r-crit", "r-hm-1"}),
        ({"category": "kube-api"}, {"r-exec-get", "r-low", "r-med", "r-high", "r-crit", "r-hm-1"}),
        ({"category": "dangerous-command"}, set()),
        ({"rule_ids": ("kube-delete",)}, {"r-high", "r-hm-1"}),
        ({"rule_ids": ("rm-rf",)}, set()),
    ],
)
@pytest.mark.parametrize("sort", ["newest", "risk"])
async def test_finding_filters_on_commands(
    env: Env, kw: dict[str, Any], expected: set[str], sort: str
) -> None:
    q = q_(KUBECTL, sort=sort, **kw)
    ids = await ids_of(env, q, page_size=2)
    assert cmds(ids) == expected
    assert ids == await oracle(env, q)


async def test_has_findings_false_lists_unflagged_commands(env: Env) -> None:
    flagged = {"r-exec-get", "r-low", "r-med", "r-high", "r-crit", "r-hm-1"}
    everything = cmds(await ids_of(env, q_(KUBECTL)))
    for sort in ("newest", "risk"):
        q = q_(KUBECTL, has_findings=False, sort=sort)
        ids = await ids_of(env, q, page_size=3)
        assert cmds(ids) == everything - flagged
        assert ids == await oracle(env, q)


async def test_contradictory_finding_filters_match_nothing(env: Env) -> None:
    page = await run_page(env, q_(KUBECTL, has_findings=False, severity="low"))
    assert page.items == [] and page.next_cursor is None


@pytest.mark.parametrize(
    "kw",
    [
        {"max_severity": "high"},
        {"severity": "medium"},
        {"has_findings": True},
        {"has_findings": False},
        {"category": "secret-exposure"},
        {"rule_ids": ("rm-rf",)},
        {"min_duration": 30.0},
        {"max_duration": 10.0},
        {"status": "error"},
        {"system": WEB, "system_set": True},
        {"system": None, "system_set": True},
    ],
)
async def test_recording_filters(env: Env, kw: dict[str, Any]) -> None:
    q = q_(REC, **kw)
    assert await ids_of(env, q, page_size=3) == await oracle(env, q)


async def test_recording_finding_filters_explicit(env: Env) -> None:
    assert recs(await ids_of(env, q_(REC, max_severity="high"))) == {"s-ssh-alice"}
    assert recs(await ids_of(env, q_(REC, severity="high"))) == {"s-ssh-alice", "s-crit"}
    assert recs(await ids_of(env, q_(REC, rule_ids=("rm-rf",)))) == {"s-ssh-alice"}


async def test_system_filter_on_commands(env: Env) -> None:
    ids = cmds(await ids_of(env, q_(KUBECTL, system=DEV, system_set=True)))
    assert ids == {"r-dave-1", "r-dev-1"}


# --- risk sort (spec §6.3) ----------------------------------------------------------------------------


async def test_risk_orders_flagged_by_rank_then_unflagged_newest(env: Env) -> None:
    ids = [i for _, i in await ids_of(env, q_(KUBECTL, sort="risk"))]
    assert ids[:6] == ["r-crit", "r-hm-1", "r-high", "r-exec-get", "r-med", "r-low"]
    assert ids[6:9] == ["r-late-1", "r-qs", "r-xss"]


async def test_risk_phase_change_across_a_page_boundary(env: Env) -> None:
    q = q_(KUBECTL, sort="risk")
    first = await run_page(env, q, limit=4)
    assert [ident(i)[1] for i in first.items] == ["r-crit", "r-hm-1", "r-high", "r-exec-get"]
    pos = first.next_cursor.positions[SOURCE_API_COMMANDS]  # type: ignore[union-attr]
    assert pos[0] == PHASE_FLAGGED and pos[1] == SEVERITY_RANK["high"]
    second = await run_page(env, q, limit=4, cursor=decode_cursor(encode_cursor(first.next_cursor)))
    assert [ident(i)[1] for i in second.items] == ["r-med", "r-low", "r-late-1", "r-qs"]
    pos = second.next_cursor.positions[SOURCE_API_COMMANDS]  # type: ignore[union-attr]
    assert pos == (PHASE_SCAN, at("12:50:00.000"), "r-qs")
    third = await run_page(env, q, limit=4, cursor=second.next_cursor)
    assert ident(third.items[0])[1] == "r-xss"


async def test_risk_sort_on_recordings(env: Env) -> None:
    ids = [i for _, i in await ids_of(env, q_(REC, sort="risk"))]
    assert ids[:4] == ["s-crit", "s-ssh-alice", "s-exec-bob", "s-low"]


# --- caps (spec §6.5) ---------------------------------------------------------------------------------


async def test_flagged_cap_sets_notice(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    q = q_(KUBECTL, has_findings=True)
    assert not (await run_page(env, q)).flagged_cap_hit
    monkeypatch.setattr(timeline, "_FLAGGED_CMD_CAP", 2)
    page = await run_page(env, q)
    assert page.flagged_cap_hit and page.flagged_cap == 2
    # an empty page (``to`` is applied after the capped hit set) still reports the cap
    later = await run_page(env, q_(KUBECTL, has_findings=True, to=at("08:00:00.000")))
    assert later.items == [] and later.flagged_cap_hit


async def test_long_command_reports_all_and_lists_first_200(env: Env) -> None:
    item = await item_for(env, q_(KUBECTL), ("cmd", "r-k9s-000"))
    hit = item.data
    assert isinstance(hit, CommandHit)
    assert hit.request_count == K9S_REQUESTS == 250
    assert hit.listed_count == 200 and hit.requests_truncated
    assert hit.command.requests[0].request_id == "r-k9s-000"
    assert hit.command.requests[-1].request_id == "r-k9s-199"
    assert hit.ended_at == at("12:00:24.900")
    assert hit.label == "k9s"
    assert hit.duration_seconds == pytest.approx(24.9)


# --- links (spec §3) -------------------------------------------------------------------------------------


async def test_exec_recording_listed_twice_under_any(env: Env) -> None:
    items, _ = await walk(env, q_(ANY), page_size=50)
    by_id = {ident(it): it for it in items}
    rec = by_id[("rec", "s-exec-bob")]
    assert rec.kind == KIND_EXEC
    assert by_id[("rec", "s-ssh-bob")].kind == KIND_SSH
    cmd = by_id[("cmd", "r-exec-get")].data
    assert isinstance(cmd, CommandHit)
    assert cmd.recordings == ("s-exec-bob",)
    assert cmd.max_severity == "high" and cmd.finding_labels == ("Pod exec",)
    assert cmd.findings["req-exec-101"][0].rule_id == "kube-exec"


async def test_recording_hydration_carries_findings_in_offset_order(env: Env) -> None:
    item = await item_for(env, q_(REC), ("rec", "s-ssh-alice"))
    hit = item.data
    assert isinstance(hit, RecordingHit)
    assert [f.label for f in hit.findings] == ["Recursive delete", "AWS access key"]
    assert hit.session.username == ALICE


# --- failed connections (spec §4.2) ------------------------------------------------------------------


async def test_failed_kind_selection(env: Env) -> None:
    assert await ids_of(env, q_(TYPE_GROUPS["failed"])) == [("rec", "s-failed")]
    ssh = recs(await ids_of(env, q_(TYPE_GROUPS["ssh"])))
    assert "s-failed" not in ssh and "s-ssh-error" in ssh
    assert "s-failed" in recs(await ids_of(env, q_(REC)))
    item = await item_for(env, q_(REC), ("rec", "s-failed"))
    assert item.kind == KIND_FAILED and item.data.kind == KIND_FAILED  # type: ignore[union-attr]
    item = await item_for(env, q_(REC), ("rec", "s-ssh-error"))
    assert item.kind == KIND_SSH


async def test_session_kind_agrees_with_failed_sql_on_every_row(env: Env) -> None:
    failed = FAILED_SQL.format(a="")
    cursor = await env.db.execute(
        f"SELECT *, CASE WHEN COALESCE({failed}, 0) = 1 THEN 'failed' "
        "WHEN request_id IS NOT NULL THEN 'exec' ELSE 'ssh' END AS sql_kind FROM sessions"
    )
    rows = await cursor.fetchall()
    await cursor.close()
    assert rows
    for row in rows:
        assert session_kind(row) == row["sql_kind"], row["conn_id"]


@pytest.mark.parametrize("kinds", [frozenset({KIND_SSH, KIND_EXEC}), frozenset({KIND_FAILED, KIND_EXEC})])
async def test_kind_subsets_walk(env: Env, kinds: frozenset[str]) -> None:
    q = q_(kinds)
    assert await ids_of(env, q, page_size=2) == await oracle(env, q)


# --- user (spec §3, §6.2, §6.3) ---------------------------------------------------------------------


@pytest.mark.parametrize(("name", "uid"), [(ALICE, ALICE_ID), (BOB, BOB_ID)])
async def test_user_by_username_equals_by_user_id(env: Env, name: str, uid: str) -> None:
    by_name = await ids_of(env, q_(ANY, user=name), page_size=3)
    by_id = await ids_of(env, q_(ANY, user=uid), page_size=3)
    assert by_name == by_id == await oracle(env, q_(ANY, user=name))
    assert recs(by_name) and cmds(by_name)


async def test_user_id_only_requests_found_by_user_id(env: Env) -> None:
    assert await ids_of(env, q_(ANY, user=DAVE_ID)) == [("cmd", "r-dave-1")]


async def test_recording_found_through_connection_user_id(env: Env) -> None:
    assert await ids_of(env, q_(ANY, user=CAROL_ID)) == [("rec", "s-carol")]
    assert await ids_of(env, q_(ANY, user=CAROL)) == [("rec", "s-carol")]


# --- focus (spec §6.3) ------------------------------------------------------------------------------------


@pytest.mark.parametrize("request_id", ["r-c1-1", "r-c1-2", "r-c1-3"])
async def test_focus_on_any_request_resolves_the_command(env: Env, request_id: str) -> None:
    q = q_(KUBECTL, cmd=request_id, severity="critical", from_=at("23:00:00.000"))
    page = await run_page(env, q)
    assert [ident(i) for i in page.items] == [("cmd", "r-c1-1")]
    assert page.next_cursor is None and not page.focus_not_found
    assert page.items[0].data.request_count == 3  # type: ignore[union-attr]


async def test_focus_on_long_command_from_late_request(env: Env) -> None:
    page = await run_page(env, q_(ANY, cmd="r-k9s-249"))
    assert [ident(i) for i in page.items] == [("cmd", "r-k9s-000")]
    assert set(page.excluded) == {KIND_SSH, KIND_EXEC, KIND_FAILED}


async def test_focus_unknown_command(env: Env) -> None:
    page = await run_page(env, q_(KUBECTL, cmd="no-such-request"))
    assert page.items == [] and page.focus_not_found and page.next_cursor is None


# --- hydration robustness ------------------------------------------------------------------------------


async def test_command_removed_before_hydration_is_dropped(env: Env) -> None:
    sources = build_sources(env.db, env.casts)
    api = next(s for s in sources if s.name == SOURCE_API_COMMANDS)
    page = await api.page(q_(KUBECTL), KUBECTL, None, 3)
    gone = replace(page.items[0], data=replace(page.items[0].data, ck="s:missing"))  # type: ignore[arg-type]
    hydrated = await api.hydrate(q_(KUBECTL), [gone, page.items[1]])
    assert hydrated[0] is None and hydrated[1] is not None
