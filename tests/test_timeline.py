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
from gatorcast.pipeline.detect import BUILTIN_API_RULES, SEVERITY_RANK
from gatorcast.store import timeline
from gatorcast.store.casts import CastStore
from gatorcast.store.timeline import (
    KIND_EXEC,
    KIND_FAILED,
    KIND_KUBECTL,
    KIND_SSH,
    KIND_WEB,
    PHASE_FLAGGED,
    PHASE_SCAN,
    POSITION_DONE,
    SOURCE_API_COMMANDS,
    SOURCE_RANK,
    SOURCE_SESSIONS,
    SOURCE_WEB,
    ApiCommandSource,
    CommandHit,
    Cursor,
    RecordingHit,
    TimelineItem,
    TimelinePage,
    UnifiedQuery,
    build_sources,
    check_position,
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
    GRAFANA,
    K9S_REQUESTS,
    PROD,
    WEB,
    WEB_START_IDS,
    WIKI,
    at,
    build_scenario,
    build_web_scenario,
)

REC = TYPE_GROUPS["recordings"]
ANY = TYPE_GROUPS["any"]
KUBECTL = TYPE_GROUPS["kubectl"]
WEBK = TYPE_GROUPS["web"]
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


@pytest.fixture
async def web_env(env: Env) -> Env:
    """The scenario plus the Session 12 web connections (``build_web_scenario``)."""
    await build_web_scenario(env.db)
    return env


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

    api_rows = await _rows(env.db, "SELECT * FROM api_requests")
    afnd: dict[str, list[dict[str, Any]]] = {}
    for f in await _rows(env.db, "SELECT * FROM api_findings"):
        afnd.setdefault(f["request_id"], []).append(f)
    for api_kind, src_rank in ((KIND_KUBECTL, 1), (KIND_WEB, 2)):
        if api_kind not in kinds:
            continue
        is_web = api_kind == KIND_WEB
        groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        for r in api_rows:
            if r["api_kind"] != api_kind:
                continue
            ck = f"s:{r['kubectl_session']}" if r["kubectl_session"] else f"c:{r['conn_id']}"
            groups.setdefault((r["resource_address"], r["user_key"], ck), []).append(r)
        for rows in groups.values():
            rows.sort(key=lambda r: (r["requested_at"], r["request_id"]))
            start = rows[0]
            fs = [f for r in rows for f in afnd.get(r["request_id"], [])]
            max_rank = max((_rank(f["severity"]) for f in fs), default=0)
            if q.cmd is not None:
                if any(r["request_id"] == q.cmd for r in rows):
                    keyed.append(((start["requested_at"], src_rank, start["request_id"]),
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
            if (
                not is_web
                and not q.discovery
                and not flagged
                and all(is_discovery(r["method"], r["url"]) for r in rows)
            ):
                continue
            if q.text is not None:
                needle = q.text.lower()
                if is_web:  # the stored URL: unmasked path plus masked query
                    hit = any(needle in r["url"].lower() for r in rows)
                else:  # path before "?" or Kubectl-Command
                    hit = any(
                        needle in r["url"].split("?", 1)[0].lower()
                        or needle in (r["kubectl_command"] or "").lower()
                        for r in rows
                    )
                if not hit:
                    continue
            if is_web:
                # the start row's configured modes decide (one snapshot per connection)
                if q.scheme_null and start["downstream_tls"] is not None:
                    continue
                if not q.scheme_null and q.scheme is not None and start["downstream_tls"] != q.scheme:
                    continue
                if q.upstream_null and start["upstream_tls"] is not None:
                    continue
                if (
                    not q.upstream_null
                    and q.upstream is not None
                    and start["upstream_tls"] != q.upstream
                ):
                    continue
            if q.has_findings is False and fs:
                continue
            if flagged:
                if is_web:  # web has no detection rules: nothing can qualify
                    continue

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
                key = (max_rank, a, src_rank, start["request_id"])
            else:
                key = (a, src_rank, start["request_id"])
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


async def test_mixed_walk_duration_lists_recordings_only(web_env: Env) -> None:
    """Longest-first has no meaning for commands or web connections: both are excluded."""
    q = q_(ANY, sort="duration")
    page = await run_page(web_env, q)
    assert page.excluded == {KIND_KUBECTL: "sort", KIND_WEB: "sort"}
    items, _ = await walk(web_env, q, page_size=2)
    assert [ident(it) for it in items] == await oracle(web_env, q)
    assert not cmds(ident(it) for it in items)
    assert {it.kind for it in items} <= {KIND_SSH, KIND_EXEC, KIND_FAILED}


async def test_equal_timestamps_are_ordered_by_source_then_id(env: Env) -> None:
    ids = await ids_of(env, q_(ANY, discovery=True), page_size=1)
    # session and command share 11:00:00.000: api_commands (rank 1) first under DESC.
    assert ids.index(("cmd", "r-c1-1")) + 1 == ids.index(("rec", "s-same-at"))
    # two commands at 12:40:00.000 and two recordings at 10:30:00.000: id DESC.
    assert ids.index(("cmd", "r-xss")) + 1 == ids.index(("cmd", "r-eq"))
    assert ids.index(("rec", "s-tie-b")) + 1 == ids.index(("rec", "s-tie-a"))


async def test_last_page_marks_every_source_done(web_env: Env) -> None:
    _, pages = await walk(web_env, q_(ANY), page_size=5)
    assert pages[-1].next_cursor is None
    for page in pages[:-1]:
        assert page.next_cursor is not None
        assert page.next_cursor.kinds == tuple(sorted(ANY)) and KIND_WEB in page.next_cursor.kinds
        assert set(page.next_cursor.positions) <= {SOURCE_SESSIONS, SOURCE_API_COMMANDS, SOURCE_WEB}
    # one page holding everything: every source exhausted, so no cursor at all
    everything = await run_page(web_env, q_(ANY), limit=500)
    assert everything.next_cursor is None
    # the web source participates from the first cursor on: its position is a scan position
    first = pages[0].next_cursor
    assert first is not None and first.positions[SOURCE_WEB][0] == PHASE_SCAN  # type: ignore[index]


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


async def test_regex_and_status_exclude_kubectl_and_web_with_reason(web_env: Env) -> None:
    """Neither command kind can evaluate a recording-only filter, so both are excluded."""
    page = await run_page(web_env, q_(ANY, regex="x"))
    assert page.excluded == {KIND_KUBECTL: "regex", KIND_WEB: "regex"}
    for kw in ({"status": "complete"}, {"min_duration": 1.0}, {"max_duration": 99.0}):
        (name,) = kw
        page = await run_page(web_env, q_(ANY, **kw))
        assert page.excluded == {KIND_KUBECTL: name, KIND_WEB: name}
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


# --- Session 11 isolation: web rows never change a kubectl listing (WEBAPP_SPEC 7.2, 8.6) --------
# Session 12 reverses one half of the Session 11 contract: ``type=any`` now lists web
# connections (WEBAPP_SPEC 8.1), so the ANY checks below assert "other kinds unchanged, web
# rows added", while every kubectl-only check is unchanged.

from tests.fixtures.timeline import add_connection, add_request  # noqa: E402

WEB_SYSTEM = "wiki.corp.internal"
WEB_NEEDLE = "web-needle-xyzzy"


async def add_web_rows(env: Env) -> list[str]:
    """Web rows interleaved with the scenario: same users, systems and times, plus findings.

    Several rows reuse kubectl-looking paths, one is ``GET /api`` (discovery look-alike), and
    two carry ``kube-api`` findings that no Kubernetes rule would attach to a web row, so a
    missing ``api_kind`` predicate in any flagged-mode query would list them. As web
    connections (one per ``conn_id`` + system + user) the rows form three items, whose ids
    are the start rows ``w-1``, ``w-4`` and ``w-6``; ``w-5`` shares ``w-4``'s connection.
    """
    db = env.db
    await add_connection(db, "web-c1", user_id=ALICE_ID, username=ALICE, resource_address=PROD, state="api")
    await add_connection(db, "web-c2", user_id=BOB_ID, username=BOB, resource_address=WEB_SYSTEM, state="api")
    spec = [
        ("w-1", "web-c1", "10:00:30.000", PROD, ALICE_ID, ALICE, "GET", f"/{WEB_NEEDLE}", ()),
        ("w-2", "web-c1", "10:30:00.000", PROD, ALICE_ID, ALICE, "DELETE", "/items/42",
         (("kube-delete", "high", "Delete"),)),
        ("w-3", "web-c1", "11:00:00.000", PROD, ALICE_ID, ALICE, "GET", "/api", ()),
        ("w-4", "web-c2", "11:30:00.000", WEB_SYSTEM, BOB_ID, BOB, "GET", f"/{WEB_NEEDLE}/home", ()),
        ("w-5", "web-c2", "12:30:00.000", WEB_SYSTEM, BOB_ID, BOB, "POST", "/api/v1/namespaces/default/secrets/x",
         (("kube-secrets", "critical", "Secrets"),)),
        ("w-6", "web-c2", "23:59:00.000", None, None, None, "GET", "/late", ()),
    ]
    for rid, conn, hms, system, uid, name, method, url, findings in spec:
        await add_request(
            db, rid, conn_id=conn, requested_at=at(hms), resource_address=system, user_id=uid,
            username=name, method=method, url=url, api_kind="web", kubectl_session=None,
            kubectl_command=None, user_agent="Mozilla/5.0 (test)", findings=findings,
        )
    return [r[0] for r in spec]


S11_WEB_STARTS = frozenset({"w-1", "w-4", "w-6"})

_KUBECTL_QUERIES = [
    q_(KUBECTL),
    q_(KUBECTL, discovery=True),
    q_(KUBECTL, has_findings=True),
    q_(KUBECTL, has_findings=False),
    q_(KUBECTL, severity="high"),
    q_(KUBECTL, max_severity="critical"),
    q_(KUBECTL, sort="risk"),
    q_(KUBECTL, user=ALICE),
    q_(KUBECTL, user=BOB_ID),
    q_(KUBECTL, system=PROD, system_set=True),
    q_(KUBECTL, system=WEB_SYSTEM, system_set=True),
    q_(KUBECTL, from_=at("10:00:00.000"), to=at("23:59:59.000")),
    q_(KUBECTL, text="secrets"),
]

# Queries whose result includes the web kind; with the Session 11 rows added the other
# kinds' items must be exactly the items found before.
_ANY_QUERIES = [
    q_(ANY),
    q_(ANY, sort="risk"),
    q_(ANY, discovery=True),
    q_(ANY, user=ALICE),
    q_(ANY, system=PROD, system_set=True),
    q_(ANY, text="secrets"),
    q_(ANY, severity="high"),
    q_(ANY, has_findings=True),
]


async def test_web_rows_change_no_kubectl_listing(env: Env) -> None:
    """Listing every kubectl query before and after adding web rows gives identical item ids."""
    before = [await ids_of(env, q) for q in _KUBECTL_QUERIES]
    await add_web_rows(env)
    after = [await ids_of(env, q) for q in _KUBECTL_QUERIES]
    for q, b, a in zip(_KUBECTL_QUERIES, before, after, strict=True):
        assert a == b, q
    assert any(before), "the baseline must not be vacuous"


async def test_web_rows_add_items_to_any_without_changing_other_kinds(env: Env) -> None:
    """``type=any`` now lists web connections; recordings and kubectl items are untouched."""
    before = [await ids_of(env, q) for q in _ANY_QUERIES]
    await add_web_rows(env)
    after = [await ids_of(env, q) for q in _ANY_QUERIES]
    for q, b, a in zip(_ANY_QUERIES, before, after, strict=True):
        assert [i for i in a if i[1] not in S11_WEB_STARTS] == b, q
    # the plain newest listing shows all three web connections
    newest = after[0]
    assert {i for _, i in newest} >= S11_WEB_STARTS


async def test_web_only_system_lists_only_web_items(env: Env) -> None:
    await add_web_rows(env)
    assert await ids_of(env, q_(KUBECTL, system=WEB_SYSTEM, system_set=True)) == []
    expected = [("cmd", "w-4")]
    assert await ids_of(env, q_(ANY, system=WEB_SYSTEM, system_set=True)) == expected
    assert await ids_of(env, q_(WEBK, system=WEB_SYSTEM, system_set=True)) == expected


async def test_text_search_is_scoped_per_kind(env: Env) -> None:
    """Web URLs match under the web kind (``any`` or ``web``) and never under kubectl."""
    await add_web_rows(env)
    assert await ids_of(env, q_(KUBECTL, text=WEB_NEEDLE)) == []
    for kinds in (ANY, WEBK):
        q = q_(kinds, text=WEB_NEEDLE)
        ids = await ids_of(env, q)
        assert cmds(ids) == {"w-1", "w-4"}
        assert ids == await oracle(env, q)


@pytest.mark.parametrize(
    "q",
    [
        q_(KUBECTL, severity="critical"),
        q_(KUBECTL, has_findings=True),
        q_(KUBECTL, sort="risk"),
        q_(KUBECTL, max_severity="critical"),
    ],
)
async def test_web_rows_with_findings_are_never_flagged_commands(env: Env, q: UnifiedQuery) -> None:
    """api_findings rows on web requests (impossible through the assembler) are ignored by kubectl flagged mode."""
    before = await ids_of(env, q)
    await add_web_rows(env)
    after = await ids_of(env, q)
    assert after == before
    assert not {i for k, i in after if k == "cmd"} & {"w-2", "w-5"}


async def test_focus_on_a_web_request_resolves_only_for_web_capable_queries(env: Env) -> None:
    """Q9 runs per source with its ``api_kind``: kubectl alone cannot see a web request."""
    await add_web_rows(env)
    for request_id, command_id in (("w-1", "w-1"), ("w-2", "w-1"), ("w-5", "w-4")):
        page = await run_page(env, q_(KUBECTL, cmd=request_id))
        assert page.items == [] and page.focus_not_found, request_id
        for kinds in (ANY, WEBK):
            page = await run_page(env, q_(kinds, cmd=request_id))
            assert [ident(i) for i in page.items] == [("cmd", command_id)], (kinds, request_id)
            assert page.items[0].kind == KIND_WEB
            assert not page.focus_not_found


async def test_kubectl_command_total_and_request_counts_ignore_web_rows(env: Env) -> None:
    before = {i: await item_for(env, q_(KUBECTL), i) for i in await ids_of(env, q_(KUBECTL))}
    await add_web_rows(env)
    after = {i: await item_for(env, q_(KUBECTL), i) for i in await ids_of(env, q_(KUBECTL))}
    assert set(before) == set(after)
    for key, item in after.items():
        assert item.data.request_count == before[key].data.request_count, key  # type: ignore[union-attr]
        assert item.data.finding_count == before[key].data.finding_count, key  # type: ignore[union-attr]


# --- Session 12: the web source (WEBAPP_SPEC 8.1-8.3) -------------------------------------------
# Fixture: ``build_web_scenario`` (tests/fixtures/timeline.py) holds eleven connections, one item
# each, with configured TLS by start row:
#   tls13/verify_full: a, i, k   tls13/verify_ca: b   tls13/insecure: j   tls13/none: g
#   none/none: c                 none/insecure: h     NULL/NULL: d (gwops none), e (ambiguous), f (absent)

ALL_WEB = frozenset(WEB_START_IDS.values())


def starts(*conns: str) -> set[str]:
    """The item ids (start request ids) of web connections ``wc-<x>``."""
    return {WEB_START_IDS[f"wc-{c}"] for c in conns}


def web_items(items: Iterable[TimelineItem]) -> list[TimelineItem]:
    """The web-kind items among ``items``."""
    return [it for it in items if it.kind == KIND_WEB]


async def web_hit(env: Env, conn: str) -> CommandHit:
    """The hydrated hit of web connection ``wc-<conn>``."""
    item = await item_for(env, q_(WEBK), ("cmd", WEB_START_IDS[f"wc-{conn}"]))
    assert isinstance(item.data, CommandHit)
    return item.data


async def test_web_source_lists_one_item_per_connection(web_env: Env) -> None:
    q = q_(WEBK)
    items, _ = await walk(web_env, q, page_size=50)
    assert {i for _, i in (ident(it) for it in items)} == ALL_WEB
    assert len(items) == len(WEB_START_IDS) == 11
    for it in items:
        assert it.kind == KIND_WEB and it.source == SOURCE_WEB
        assert isinstance(it.data, CommandHit) and it.data.kind == KIND_WEB
    assert [ident(it) for it in items] == await oracle(web_env, q)


@pytest.mark.parametrize("page_size", [1, 3, 7])
@pytest.mark.parametrize("sort", ["newest", "risk"])
async def test_walk_web_source_every_page_exactly_once(web_env: Env, sort: str, page_size: int) -> None:
    q = q_(WEBK, sort=sort)
    items, pages = await walk(web_env, q, page_size=page_size)
    assert [ident(it) for it in items] == await oracle(web_env, q)
    assert pages[-1].next_cursor is None
    assert all(not p.budget_hit for p in pages)
    assert all(len(p.items) == page_size for p in pages[:-1])
    # only the web source holds a position, and it is never a flagged-phase one
    for page in pages[:-1]:
        assert page.next_cursor is not None
        assert set(page.next_cursor.positions) == {SOURCE_WEB}
        pos = page.next_cursor.positions[SOURCE_WEB]
        assert pos != POSITION_DONE and pos[0] == PHASE_SCAN


@pytest.mark.parametrize("page_size", [1, 4, 50])
@pytest.mark.parametrize("sort", ["newest", "risk"])
@pytest.mark.parametrize("discovery", [False, True])
async def test_mixed_walk_with_web_equals_brute_force(
    web_env: Env, sort: str, page_size: int, discovery: bool
) -> None:
    q = q_(ANY, sort=sort, discovery=discovery)
    items, _ = await walk(web_env, q, page_size=page_size)
    expected = await oracle(web_env, q)
    assert [ident(it) for it in items] == expected
    assert recs(expected) and cmds(expected) - ALL_WEB and cmds(expected) & ALL_WEB  # all three
    assert {it.kind for it in items} == set(ANY)


async def test_equal_timestamps_are_ordered_by_source_rank_then_id(web_env: Env) -> None:
    assert (SOURCE_RANK[SOURCE_SESSIONS], SOURCE_RANK[SOURCE_API_COMMANDS], SOURCE_RANK[SOURCE_WEB]) == (0, 1, 2)
    ids = await ids_of(web_env, q_(ANY, discovery=True), page_size=1)
    # 11:00:00.000: web connection, then kubectl command, then recording (rank DESC)
    i = ids.index(("cmd", "ww-c1"))
    assert ids[i : i + 3] == [("cmd", "ww-c1"), ("cmd", "r-c1-1"), ("rec", "s-same-at")]
    # 12:40:00.000: web (rank 2) before the two commands, which tie-break by id DESC
    i = ids.index(("cmd", "ww-f1"))
    assert ids[i : i + 3] == [("cmd", "ww-f1"), ("cmd", "r-xss"), ("cmd", "r-eq")]
    # 10:00:30.000: two web connections, id DESC
    i = ids.index(("cmd", "ww-j1"))
    assert ids[i : i + 2] == [("cmd", "ww-j1"), ("cmd", "ww-a1")]
    # the merge key of each item ends in (source rank, id)
    items, _ = await walk(web_env, q_(ANY), page_size=50)
    for it in items:
        assert it.sort_key[-2] == SOURCE_RANK[it.source]


async def test_web_hit_ordering_matches_kind_rank_in_sort_keys(web_env: Env) -> None:
    items, _ = await walk(web_env, q_(ANY), page_size=50)
    ranks = {it.kind: it.sort_key[-2] for it in items}
    assert ranks == {
        KIND_SSH: 0, KIND_EXEC: 0, KIND_FAILED: 0, KIND_KUBECTL: 1, KIND_WEB: 2,
    }


# --- cursor shapes and check_position (WEBAPP_SPEC 8.1) ---------------------------------------------


async def test_web_cursor_position_shape_newest(web_env: Env) -> None:
    page = await run_page(web_env, q_(WEBK), limit=2)
    assert page.next_cursor is not None
    last = page.items[-1]
    pos = page.next_cursor.positions[SOURCE_WEB]
    assert pos == (PHASE_SCAN, last.at, ident(last)[1])
    assert check_position(SOURCE_WEB, "newest", list(pos)) == pos
    # the cursor survives the URL codec and resumes at the third item
    resumed = await run_page(
        web_env, q_(WEBK), limit=2, cursor=decode_cursor(encode_cursor(page.next_cursor))
    )
    expected = await oracle(web_env, q_(WEBK))
    assert [ident(i) for i in page.items + resumed.items] == expected[:4]


async def test_web_cursor_position_shape_risk_is_scan_phase_only(web_env: Env) -> None:
    page = await run_page(web_env, q_(WEBK, sort="risk"), limit=2)
    assert page.next_cursor is not None
    pos = page.next_cursor.positions[SOURCE_WEB]
    assert pos == (PHASE_SCAN, page.items[-1].at, ident(page.items[-1])[1])  # web has no flagged phase
    assert check_position(SOURCE_WEB, "risk", list(pos)) == pos


async def test_cursor_for_web_kinds_is_rejected_for_other_kinds(web_env: Env) -> None:
    page = await run_page(web_env, q_(WEBK), limit=2)
    assert page.next_cursor is not None
    with pytest.raises(ValueError):
        await run_page(web_env, q_(ANY), limit=2, cursor=page.next_cursor)


_RID = "ww-a1"
_AT = at("10:00:30.000")


@pytest.mark.parametrize("source", [SOURCE_API_COMMANDS, SOURCE_WEB])
@pytest.mark.parametrize(
    ("sort", "position"),
    [
        ("newest", ["T", _AT, _RID]),
        ("newest", ["F", _AT, "h:" + "0" * 32]),
        ("risk", ["F", 4, _AT, _RID]),
        ("risk", ["F", 0, _AT, _RID]),
        ("risk", ["T", _AT, _RID]),
    ],
)
def test_check_position_accepts_api_shapes_for_both_api_sources(
    source: str, sort: str, position: list[object]
) -> None:
    assert check_position(source, sort, position) == tuple(position)


@pytest.mark.parametrize("source", [SOURCE_API_COMMANDS, SOURCE_WEB])
@pytest.mark.parametrize(
    ("sort", "position"),
    [
        ("duration", [1, 2.0, _RID]),
        ("newest", ["X", _AT, _RID]),
        ("newest", ["T", "2026-10-01T10:00:30Z", _RID]),  # no milliseconds
        ("newest", ["T", _AT, "bad/id"]),
        ("newest", ["T", _AT]),
        ("newest", ["T", _AT, _RID, "extra"]),
        ("risk", ["F", _AT, _RID]),  # flagged phase lacks its rank
        ("risk", ["F", True, _AT, _RID]),  # a bool is not a rank
        ("risk", ["F", 5, _AT, _RID]),
        ("risk", ["T", _AT, _RID, "extra"]),
    ],
)
def test_check_position_rejects_malformed_api_shapes(
    source: str, sort: str, position: list[object]
) -> None:
    with pytest.raises(ValueError) as exc_info:
        check_position(source, sort, position)
    assert _RID not in str(exc_info.value) and _AT not in str(exc_info.value)


def test_check_position_rejects_non_list_and_unknown_source() -> None:
    with pytest.raises(ValueError):
        check_position(SOURCE_WEB, "newest", "T")
    with pytest.raises(ValueError):
        check_position("web", "newest", ["T", _AT, _RID])  # the source is web_conns, not the kind


# --- windows, users, systems ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "q",
    [
        q_(WEBK, from_=at("09:00:00.000")),
        q_(WEBK, to=at("10:00:30.500")),
        q_(WEBK, from_=at("10:00:30.000"), to=at("10:30:00.000")),
        q_(WEBK, user=ALICE),
        q_(WEBK, user=ALICE_ID),
        q_(WEBK, user=BOB),
        q_(WEBK, user=CAROL),
        q_(WEBK, user=CAROL_ID),
        q_(WEBK, user=DAVE_ID),
        q_(WEBK, system=GRAFANA, system_set=True),
        q_(WEBK, system=WIKI, system_set=True, user=BOB),
        q_(WEBK, system=None, system_set=True),
        q_(WEBK, system=PROD, system_set=True),
        q_(WEBK, user=ALICE, sort="risk"),
        q_(WEBK, has_findings=False),
        q_(WEBK, has_findings=False, sort="risk"),
        q_(WEBK, discovery=True),
    ],
    ids=[
        "from", "to", "window", "alice", "alice-id", "bob", "carol", "carol-id", "dave-id",
        "system", "system-user", "unknown-system", "kubectl-system", "alice-risk",
        "no-findings", "no-findings-risk", "discovery-ignored",
    ],
)
async def test_web_filters_equal_brute_force(web_env: Env, q: UnifiedQuery) -> None:
    ids = await ids_of(web_env, q, page_size=2)
    assert ids == await oracle(web_env, q)
    assert (not ids) == (q.system == PROD)  # no web connection is on the kubectl cluster


async def test_web_window_places_a_connection_by_its_first_request(web_env: Env) -> None:
    ids = cmds(await ids_of(web_env, q_(WEBK, from_=at("09:00:00.000"))))
    assert WEB_START_IDS["wc-h"] not in ids  # first request 08:59:59, second inside the window
    assert ALL_WEB - starts("h") == ids
    q = q_(WEBK, from_=at("23:59:00.000"), to=at("23:59:00.500"))
    assert await ids_of(web_env, q) == [("cmd", "ww-g1")]
    hit = await web_hit(web_env, "g")
    assert hit.request_count == 2 and hit.ended_at == at("23:59:01.000")  # shown whole


async def test_web_user_and_system_buckets(web_env: Env) -> None:
    assert cmds(await ids_of(web_env, q_(WEBK, user=DAVE_ID))) == starts("g")
    assert cmds(await ids_of(web_env, q_(WEBK, user=CAROL))) == starts("e")
    assert cmds(await ids_of(web_env, q_(WEBK, system=GRAFANA, system_set=True))) == starts("c", "d", "e")
    assert cmds(await ids_of(web_env, q_(WEBK, system=None, system_set=True))) == starts("g")


# --- text filter: the stored URL (WEBAPP_SPEC 8.1) --------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("/home", {"a", "j", "d"}),
        ("/LOGIN", {"a"}),  # case-insensitive, and the match is on a non-start request
        ("zebra-path/FILES", {"f"}),  # second request of the connection
        ("docs/search", {"b"}),
        ("term=se…(9)", {"b"}),  # the masked query, as stored
        ("page=…(1)", {"b"}),  # a query part: kubectl ignores the query, web matches it
        ("secretxyz", set()),  # the unmasked value is not stored
        ("/api", {"c", "d", "i"}),  # also matches kubectl-looking paths
        ("secrets", {"i"}),
        ("%", set()),  # a literal, not a wildcard
        ("_", set()),
    ],
)
async def test_text_matches_the_stored_url_of_any_request(
    web_env: Env, text: str, expected: set[str]
) -> None:
    q = q_(WEBK, text=text)
    ids = await ids_of(web_env, q, page_size=2)
    assert cmds(ids) == starts(*expected)
    assert ids == await oracle(web_env, q)
    # newest-first and risk produce the same set
    assert cmds(await ids_of(web_env, q_(WEBK, text=text, sort="risk"))) == starts(*expected)


async def test_masked_query_matches_only_its_masked_form_for_web(web_env: Env) -> None:
    """Kubectl text search never matches a web URL, and a masked value never matches its secret."""
    assert await ids_of(web_env, q_(KUBECTL, text="term=se…(9)")) == []
    assert cmds(await ids_of(web_env, q_(ANY, text="term=se…(9)"))) == starts("b")
    assert await ids_of(web_env, q_(ANY, text="secretxyz")) == []


async def test_kubectl_text_rule_is_unchanged_next_to_web_rows(web_env: Env) -> None:
    for text, expected in (
        ("zebrafish", set()),  # only in a kubectl query string
        ("/secrets/", {"r-med", "r-hm-1"}),  # kubectl path matches; the web "/secrets/db" row does not
        ("kubectl cordon", {"r-low"}),
    ):
        ids = await ids_of(web_env, q_(KUBECTL, text=text))
        assert cmds(ids) == expected
    # under any, the web row with the same path is listed in addition
    assert cmds(await ids_of(web_env, q_(ANY, text="/secrets/"))) == {"r-med", "r-hm-1"} | starts("i")


# --- scheme / upstream filters (WEBAPP_SPEC 8.3) ----------------------------------------------------


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"scheme": "tls13"}, {"a", "b", "g", "i", "j", "k"}),  # scheme=https
        ({"scheme": "none"}, {"c", "h"}),  # scheme=http
        ({"scheme_null": True}, {"d", "e", "f"}),  # scheme=unknown
        ({"upstream": "verify_full"}, {"a", "i", "k"}),  # upstream=verified
        ({"upstream": "verify_ca"}, {"b"}),  # upstream=ca_only
        ({"upstream": "insecure"}, {"h", "j"}),  # upstream=unverified
        ({"upstream": "none"}, {"c", "g"}),  # upstream=plaintext
        ({"upstream_null": True}, {"d", "e", "f"}),  # upstream=unknown
        ({"scheme": "tls13", "upstream": "insecure"}, {"j"}),
        ({"scheme": "tls13", "upstream": "none"}, {"g"}),
        ({"scheme": "none", "upstream": "none"}, {"c"}),
        ({"scheme_null": True, "upstream_null": True}, {"d", "e", "f"}),
        ({"scheme": "none", "upstream_null": True}, set()),
        ({"scheme_null": True, "upstream": "none"}, set()),
    ],
    ids=[
        "https", "http", "scheme-unknown", "verified", "ca-only", "unverified", "plaintext",
        "upstream-unknown", "https+unverified", "https+plaintext", "http+plaintext",
        "both-unknown", "http+upstream-unknown", "scheme-unknown+plaintext",
    ],
)
@pytest.mark.parametrize("sort", ["newest", "risk"])
async def test_scheme_and_upstream_select_the_start_rows_configured_modes(
    web_env: Env, kw: dict[str, Any], expected: set[str], sort: str
) -> None:
    q = q_(WEBK, sort=sort, **kw)
    ids = await ids_of(web_env, q, page_size=2)
    assert cmds(ids) == starts(*expected)
    if sort == "newest":
        assert ids == await oracle(web_env, q)


async def test_unknown_covers_absent_none_and_ambiguous_snapshots_and_not_a_none_mode(web_env: Env) -> None:
    """``unknown`` is ``IS NULL``: no object, ``match: none`` and ``ambiguous`` all land in it."""
    unknown = cmds(await ids_of(web_env, q_(WEBK, scheme_null=True)))
    assert unknown == starts("d", "e", "f")  # none, ambiguous, absent object
    hits = {c: await web_hit(web_env, c) for c in "def"}
    assert [hits[c].gwops_match for c in "def"] == ["none", "ambiguous", None]
    assert all(h.downstream_tls is None and h.upstream_tls is None for h in hits.values())
    # the stored mode "none" (plaintext) is a different bucket from unknown
    assert cmds(await ids_of(web_env, q_(WEBK, scheme="none"))).isdisjoint(unknown)
    assert cmds(await ids_of(web_env, q_(WEBK, upstream="none"))).isdisjoint(unknown)


async def test_connection_without_a_connections_row_still_filters_by_its_request_modes(web_env: Env) -> None:
    """The filter reads the start row of ``api_requests``, not ``connections`` (wc-i has no row)."""
    assert WEB_START_IDS["wc-i"] in cmds(await ids_of(web_env, q_(WEBK, scheme="tls13", upstream="verify_full")))


async def test_a_mode_change_inside_a_connection_does_not_split_or_double_list_it(web_env: Env) -> None:
    """wc-k's second request is none/none; the start row (tls13/verify_full) decides."""
    assert WEB_START_IDS["wc-k"] in cmds(await ids_of(web_env, q_(WEBK, scheme="tls13")))
    assert WEB_START_IDS["wc-k"] not in cmds(await ids_of(web_env, q_(WEBK, scheme="none")))
    assert WEB_START_IDS["wc-k"] not in cmds(await ids_of(web_env, q_(WEBK, upstream="none")))
    hit = await web_hit(web_env, "k")
    assert hit.request_count == 2
    assert (hit.downstream_tls, hit.upstream_tls) == ("tls13", "verify_full")


@pytest.mark.parametrize(
    "q",
    [
        q_(WEBK, scheme="tls13", user=ALICE),
        q_(WEBK, scheme="tls13", user=ALICE_ID, sort="risk"),
        q_(WEBK, upstream="verify_full", system=WIKI, system_set=True),
        q_(WEBK, scheme_null=True, text="home"),
        q_(WEBK, upstream="none", has_findings=False),
        q_(WEBK, scheme="none", from_=at("09:00:00.000"), to=at("11:00:00.000")),
    ],
    ids=["user", "user-risk", "system", "text", "no-findings", "window"],
)
async def test_tls_filters_combine_with_the_other_scan_filters(web_env: Env, q: UnifiedQuery) -> None:
    ids = await ids_of(web_env, q, page_size=2)
    assert ids == await oracle(web_env, q)
    assert ids, "the combination must not be vacuous"


# --- exclusion of other kinds (WEBAPP_SPEC 8.3) ------------------------------------------------------


@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        ({"scheme": "tls13"}, "scheme"),
        ({"scheme": "none"}, "scheme"),
        ({"scheme_null": True}, "scheme"),
        ({"upstream": "verify_ca"}, "upstream"),
        ({"upstream_null": True}, "upstream"),
    ],
)
async def test_web_filters_exclude_every_other_kind(web_env: Env, kw: dict[str, Any], reason: str) -> None:
    page = await run_page(web_env, q_(ANY, **kw), limit=200)
    assert page.excluded == {
        KIND_SSH: reason, KIND_EXEC: reason, KIND_FAILED: reason, KIND_KUBECTL: reason,
    }
    assert page.items and all(it.kind == KIND_WEB for it in page.items)
    assert page.kinds == (KIND_WEB,)


async def test_web_filters_with_only_other_kinds_selected_is_an_empty_final_page(web_env: Env) -> None:
    page = await run_page(web_env, q_(KUBECTL, scheme="tls13"))
    assert page.items == [] and page.next_cursor is None
    assert page.excluded == {KIND_KUBECTL: "scheme"}
    page = await run_page(web_env, q_(REC, upstream="none"))
    assert page.items == [] and page.next_cursor is None
    assert page.excluded == {KIND_SSH: "upstream", KIND_EXEC: "upstream", KIND_FAILED: "upstream"}


async def test_first_unevaluable_filter_names_the_reason_with_web_filters(web_env: Env) -> None:
    """``status`` precedes ``scheme`` in filter order: web and kubectl cannot evaluate it, recordings cannot do scheme."""
    page = await run_page(web_env, q_(ANY, scheme="tls13", status="error"))
    assert page.excluded == {
        KIND_SSH: "scheme", KIND_EXEC: "scheme", KIND_FAILED: "scheme",
        KIND_KUBECTL: "status", KIND_WEB: "status",
    }
    assert page.items == [] and page.next_cursor is None


async def test_finding_filters_keep_web_selected_but_list_no_web_rows(web_env: Env) -> None:
    for kw in ({"severity": "high"}, {"max_severity": "critical"}, {"has_findings": True},
               {"category": "kube-api"}, {"rule_ids": ("kube-delete",)}):
        q = q_(ANY, **kw)
        page = await run_page(web_env, q, limit=200)
        assert page.excluded == {}, kw  # web evaluates finding filters (it simply has none)
        assert KIND_WEB in page.kinds
        assert not web_items(page.items), kw
        assert page.items, kw


# --- web hit hydration (WEBAPP_SPEC 8.1, 8.2) -------------------------------------------------------


@pytest.mark.parametrize(
    ("conn", "primary", "method", "count"),
    [
        ("a", "ww-a2", "POST", 3),  # first mutating, not the first request
        ("j", "ww-j2", "delete", 2),  # lower-case mutating method
        ("b", "ww-b2", "DELETE", 2),
        ("c", "ww-c1", "GET", 1),  # no mutating request: the first
        ("d", "ww-d2", "PUT", 2),
        ("e", "ww-e1", "PATCH", 1),
        ("f", "ww-f1", "GET", 2),  # PROPFIND is not mutating: the first request
        ("k", "ww-k1", "GET", 2),
        ("g", "ww-g1", "POST", 2),  # POST then DELETE: the first mutating one
        ("h", "ww-h1", "GET", 2),
    ],
)
async def test_web_primary_request_is_first_mutating_else_first(
    web_env: Env, conn: str, primary: str, method: str, count: int
) -> None:
    hit = await web_hit(web_env, conn)
    assert hit.command.primary.request_id == primary
    assert hit.command.primary.method == method
    assert hit.request_count == count and hit.listed_count == count
    assert hit.command_id == WEB_START_IDS[f"wc-{conn}"]  # the start row, not the primary
    assert hit.kind == KIND_WEB


async def test_web_hit_has_no_discovery_and_lists_every_request(web_env: Env) -> None:
    hit = await web_hit(web_env, "c")  # GET /api: discovery for kubectl
    assert hit.discovery_count == 0 and hit.command.discovery_count == 0
    assert not hit.is_discovery_only
    assert hit.command.primary.url == "/api"
    assert [r.request_id for r in hit.visible_requests()] == ["ww-c1"]
    assert [r.request_id for r in hit.visible_requests(True)] == ["ww-c1"]
    assert [r.request_id for r in hit.visible_requests(False)] == ["ww-c1"]
    # listed by default, where a kubectl discovery-only command is hidden
    assert ("cmd", "ww-c1") in await ids_of(web_env, q_(WEBK))
    assert ("cmd", "r-disc-1") not in await ids_of(web_env, q_(KUBECTL))


async def test_visible_requests_still_hides_kubectl_discovery(web_env: Env) -> None:
    item = await item_for(web_env, q_(KUBECTL, discovery=True), ("cmd", "r-c1-1"))
    hit = item.data
    assert isinstance(hit, CommandHit) and hit.kind == KIND_KUBECTL
    assert hit.discovery_count == 1
    assert len(hit.visible_requests()) == 2 and len(hit.visible_requests(True)) == 3


async def test_web_hit_aggregates_and_label(web_env: Env) -> None:
    hit = await web_hit(web_env, "a")
    assert hit.started_at == at("10:00:30.000") and hit.ended_at == at("10:00:32.000")
    assert hit.duration_seconds == pytest.approx(2.0)
    assert hit.label == "Mozilla"  # the User-Agent product: web rows carry no Kubectl-Command
    assert (hit.username, hit.user_id) == (ALICE, ALICE_ID)
    assert hit.resource_address == WIKI and hit.conn_id == "wc-a"
    assert hit.recordings == () and hit.findings == {}
    assert hit.finding_count == 0 and hit.max_severity is None and hit.finding_labels == ()
    assert [r.request_id for r in hit.command.requests] == ["ww-a1", "ww-a2", "ww-a3"]


async def test_web_hit_carries_the_start_rows_configured_tls(web_env: Env) -> None:
    expected = {
        "a": ("tls13", "verify_full"), "b": ("tls13", "verify_ca"), "c": ("none", "none"),
        "d": (None, None), "e": (None, None), "f": (None, None), "g": ("tls13", "none"),
        "h": ("none", "insecure"), "i": ("tls13", "verify_full"), "j": ("tls13", "insecure"),
        "k": ("tls13", "verify_full"),
    }
    for conn, modes in expected.items():
        hit = await web_hit(web_env, conn)
        assert (hit.downstream_tls, hit.upstream_tls) == modes, conn


@pytest.mark.parametrize(
    ("conn", "gwops"),
    [
        ("a", ("exact", "gw-aaa", "Wiki Prod", True)),
        ("b", ("exact", "gw-bbb", "Docs (beta)", False)),  # unmanaged, free-text name
        ("c", ("exact", "gw-ccc", "Grafana", True)),
        ("d", ("none", "gw-ddd", None, None)),  # no app fields on none
        ("e", ("ambiguous", "gw-eee", None, None)),
        ("f", (None, None, None, None)),  # a connections row with no object
        ("i", (None, None, None, None)),  # no connections row at all
        ("g", ("exact", None, "Legacy", True)),  # gwops Mode B: no gateway id
    ],
)
async def test_gwops_fields_are_populated_on_web_hits_from_connections(
    web_env: Env, conn: str, gwops: tuple[object, ...]
) -> None:
    hit = await web_hit(web_env, conn)
    assert (hit.gwops_match, hit.gwops_gateway_id, hit.gwops_app, hit.gwops_managed) == gwops


async def test_gwops_fields_are_never_set_on_kubectl_hits(web_env: Env) -> None:
    # even a kubectl connection whose ``connections`` row carries a (bogus) snapshot
    await add_connection(
        web_env.db, "conn-a", user_id=BOB_ID, username=BOB, resource_address=PROD,
        state="api", gwops_match="exact", gwops_gateway_id="gw-leak", gwops_app="LEAK-APP",
        gwops_managed=True, downstream_tls="tls13", upstream_tls="verify_full",
    )
    items, _ = await walk(web_env, q_(KUBECTL, discovery=True), page_size=50)
    assert items
    for it in items:
        hit = it.data
        assert isinstance(hit, CommandHit) and hit.kind == KIND_KUBECTL
        assert (hit.gwops_match, hit.gwops_gateway_id, hit.gwops_app, hit.gwops_managed) == (
            None, None, None, None,
        )
        assert (hit.downstream_tls, hit.upstream_tls) == (None, None)


async def test_gwops_app_and_gateway_id_stay_out_of_repr(web_env: Env) -> None:
    hit = await web_hit(web_env, "a")
    assert hit.gwops_app == "Wiki Prod" and hit.gwops_gateway_id == "gw-aaa"
    text = repr(hit)
    assert "Wiki Prod" not in text and "gw-aaa" not in text


async def test_web_hydration_reads_connections_once_per_page(
    web_env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gatorcast.store.activity import ActivityStore

    calls: list[list[str]] = []
    real = ActivityStore.gwops_for_connections

    async def counting(self: ActivityStore, conn_ids: Iterable[str]) -> Any:
        ids = list(conn_ids)
        calls.append(ids)
        return await real(self, ids)

    monkeypatch.setattr(ActivityStore, "gwops_for_connections", counting)
    page = await run_page(web_env, q_(WEBK), limit=5)
    assert len(calls) == 1 and len(calls[0]) == len(page.items) == 5
    calls.clear()
    await run_page(web_env, q_(KUBECTL), limit=5)
    assert calls == []  # kubectl hits never read the snapshot


# --- focus (cmd) finds web requests (WEBAPP_SPEC 8.1) ------------------------------------------------


@pytest.mark.parametrize("request_id", ["ww-a1", "ww-a2", "ww-a3"])
async def test_focus_on_any_request_of_a_web_connection_resolves_it(web_env: Env, request_id: str) -> None:
    for kinds in (WEBK, ANY):
        page = await run_page(web_env, q_(kinds, cmd=request_id))
        assert [ident(i) for i in page.items] == [("cmd", "ww-a1")]
        assert page.items[0].kind == KIND_WEB and page.items[0].source == SOURCE_WEB
        assert page.next_cursor is None and not page.focus_not_found
        assert page.items[0].data.request_count == 3  # type: ignore[union-attr]
        assert page.items[0].data.gwops_app == "Wiki Prod"  # type: ignore[union-attr]


async def test_focus_under_any_excludes_recordings_and_lists_one_kind(web_env: Env) -> None:
    page = await run_page(web_env, q_(ANY, cmd="ww-a3"))
    assert page.excluded == {KIND_SSH: "cmd", KIND_EXEC: "cmd", KIND_FAILED: "cmd"}
    assert [it.kind for it in page.items] == [KIND_WEB]
    page = await run_page(web_env, q_(ANY, cmd="r-c1-2"))
    assert [(ident(i), i.kind) for i in page.items] == [(("cmd", "r-c1-1"), KIND_KUBECTL)]
    assert not page.focus_not_found  # the web source found nothing; the kubectl source did


async def test_focus_is_missing_only_when_no_api_source_returned_an_item(web_env: Env) -> None:
    page = await run_page(web_env, q_(ANY, cmd="no-such-request"))
    assert page.items == [] and page.focus_not_found
    # each kind looks a request up under its own api_kind
    page = await run_page(web_env, q_(KUBECTL, cmd="ww-a1"))
    assert page.items == [] and page.focus_not_found
    page = await run_page(web_env, q_(WEBK, cmd="r-c1-1"))
    assert page.items == [] and page.focus_not_found


async def test_focus_overrides_every_other_web_filter(web_env: Env) -> None:
    q = q_(
        WEBK, cmd="ww-a2", scheme="none", upstream_null=True, user=BOB, text="zzz",
        severity="critical", from_=at("23:00:00.000"), system=GRAFANA, system_set=True,
    )
    page = await run_page(web_env, q)
    assert [ident(i) for i in page.items] == [("cmd", "ww-a1")]


# --- budgets: per source instance (spec 6.5) ---------------------------------------------------------


@pytest.mark.parametrize(
    "q",
    [
        q_(WEBK),
        q_(WEBK, text="home"),
        q_(WEBK, sort="risk"),
        q_(WEBK, user=ALICE),
        q_(WEBK, scheme="tls13"),
        q_(ANY),
        q_(ANY, sort="risk"),
        q_(ANY, scheme_null=True),
    ],
    ids=["web", "text", "risk", "user", "scheme", "any", "any-risk", "any-scheme"],
)
async def test_web_scan_budget_frontier_resumes_without_loss(
    web_env: Env, monkeypatch: pytest.MonkeyPatch, q: UnifiedQuery
) -> None:
    monkeypatch.setattr(timeline, "_API_SCAN_BUDGET", 4)
    items, pages = await walk(web_env, q, page_size=3)
    assert [ident(it) for it in items] == await oracle(web_env, q)
    short = [p for p in pages if p.budget_hit]
    assert short, "the patched budget never stopped a page"
    assert all(p.scan_budget_hit and p.next_cursor is not None for p in short)
    assert all(p.scan_budget == 4 for p in pages)
    if q.kinds == WEBK:
        for page in pages[:-1]:
            assert set(page.next_cursor.positions) == {SOURCE_WEB}  # type: ignore[union-attr]


async def test_each_source_instance_spends_its_own_scan_budget(
    web_env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 250 k9s kubectl rows do not count against the web source, and vice versa."""
    monkeypatch.setattr(timeline, "_API_SCAN_BUDGET", 5)
    window = {"from_": at("12:00:00.000"), "to": at("12:00:24.900")}  # only k9s rows
    only_web = await run_page(web_env, q_(WEBK, **window), limit=2)
    assert only_web.items == [] and only_web.next_cursor is None and not only_web.budget_hit

    q = q_(ANY, text="nodes", **window)
    first = await run_page(web_env, q, limit=2)
    assert first.items == [] and first.budget_hit and first.scan_budget_hit
    assert first.next_cursor is not None
    positions = first.next_cursor.positions
    assert positions[SOURCE_WEB] == POSITION_DONE  # web finished inside its own budget
    assert positions[SOURCE_API_COMMANDS] != POSITION_DONE
    assert positions[SOURCE_API_COMMANDS][0] == PHASE_SCAN  # type: ignore[index]
    # the walk still ends with nothing listed
    items, _ = await walk(web_env, q, page_size=2)
    assert items == []


# --- flagged mode is skipped for web (no detection rules) -------------------------------------------


async def _trace(env: Env, run: Any) -> tuple[Any, list[str]]:
    """Run ``run()`` and return its result with every statement SQLite executed."""
    statements: list[str] = []
    await env.db.set_trace_callback(statements.append)
    try:
        result = await run()
    finally:
        await env.db.set_trace_callback(None)
    return result, statements


_FLAG_FILTERS = [
    {"severity": "low"},
    {"severity": "high"},
    {"max_severity": "critical"},
    {"max_severity": "medium"},
    {"category": "kube-api"},
    {"rule_ids": ("kube-delete",)},
    {"has_findings": True},
    {"severity": "low", "scheme": "tls13"},
    {"has_findings": True, "sort": "risk"},
    {"severity": "high", "sort": "risk", "user": ALICE, "text": "home"},
]


@pytest.mark.parametrize("kw", _FLAG_FILTERS)
async def test_web_flagged_mode_returns_nothing_and_runs_no_findings_sql(
    web_env: Env, monkeypatch: pytest.MonkeyPatch, kw: dict[str, Any]
) -> None:
    monkeypatch.setattr(timeline, "_FLAGGED_CMD_CAP", 1)
    q = q_(WEBK, **kw)
    page, statements = await _trace(web_env, lambda: run_page(web_env, q, limit=50))
    assert page.items == [] and page.next_cursor is None
    assert not page.flagged_cap_hit and not page.budget_hit
    assert page.excluded == {}
    findings_sql = [s for s in statements if "api_findings" in s]
    assert findings_sql == [], findings_sql
    assert not [s for s in statements if "api_requests" in s], statements  # nothing was queried


async def test_kubectl_flagged_mode_runs_findings_sql_so_the_trace_is_meaningful(web_env: Env) -> None:
    page, statements = await _trace(web_env, lambda: run_page(web_env, q_(KUBECTL, severity="high")))
    assert page.items
    assert any("api_findings" in s for s in statements)


async def test_stray_findings_on_web_rows_cannot_make_web_flagged_mode_list_them(web_env: Env) -> None:
    """Flagged Q5 would find this row if it ran: the skip is what keeps web out of it."""
    await add_connection(web_env.db, "wc-stray", user_id=ALICE_ID, username=ALICE,
                         resource_address=WIKI, state="api")
    await add_request(
        web_env.db, "ww-stray", conn_id="wc-stray", requested_at=at("15:00:00.000"),
        resource_address=WIKI, user_id=ALICE_ID, username=ALICE, method="DELETE", url="/x",
        api_kind="web", kubectl_session=None, kubectl_command=None,
        findings=[("kube-delete", "critical", "Resource delete")],
    )
    for kw in ({"severity": "critical"}, {"has_findings": True}, {"rule_ids": ("kube-delete",)}):
        assert await ids_of(web_env, q_(WEBK, **kw)) == [], kw
        assert ("cmd", "ww-stray") not in await ids_of(web_env, q_(KUBECTL, **kw)), kw
        assert ("cmd", "ww-stray") not in await ids_of(web_env, q_(ANY, **kw)), kw


async def test_risk_sort_still_lists_web_rows_after_the_skipped_flagged_phase(web_env: Env) -> None:
    q = q_(WEBK, sort="risk")
    ids = await ids_of(web_env, q, page_size=4)
    assert cmds(ids) == ALL_WEB
    assert ids == await oracle(web_env, q)
    # newest-first within the scan phase (no rank to order by)
    assert ids == await ids_of(web_env, q_(WEBK))
    # under any, unflagged web rows interleave with the unflagged kubectl commands
    mixed = await ids_of(web_env, q_(ANY, sort="risk"))
    assert ALL_WEB <= cmds(mixed)


async def test_has_findings_false_lists_every_web_connection(web_env: Env) -> None:
    for sort in ("newest", "risk"):
        assert cmds(await ids_of(web_env, q_(WEBK, has_findings=False, sort=sort))) == ALL_WEB
    page = await run_page(web_env, q_(WEBK, has_findings=False, severity="low"))
    assert page.items == [] and page.next_cursor is None


def test_every_builtin_api_rule_is_kubernetes_only() -> None:
    """Guard for the web flagged-mode skip (``ApiCommandSource(findings=False)``).

    Q5 drives from ``api_findings`` across every ``api_kind``. It is skipped for web only
    because no rule can attach a finding to a web request.
    """
    for rule in BUILTIN_API_RULES:
        assert rule.resource_types == frozenset({"KUBERNETES"}), (
            f"ApiRule {rule.id!r} now applies to {sorted(rule.resource_types)}. The web timeline "
            "source skips flagged mode (Q5) because web has no detection rules; Q5 then needs a "
            "kind restriction on api_findings (an api_kind filter on the join) and the web "
            "ApiCommandSource must be built with findings=True before this rule can ship."
        )


async def test_web_source_is_built_without_findings_and_kubectl_with(env: Env) -> None:
    sources = {s.name: s for s in build_sources(env.db, env.casts)}
    assert set(sources) == {SOURCE_SESSIONS, SOURCE_API_COMMANDS, SOURCE_WEB}
    assert [s.name for s in build_sources(env.db, env.casts)] == [
        SOURCE_SESSIONS, SOURCE_API_COMMANDS, SOURCE_WEB,
    ]
    web = sources[SOURCE_WEB]
    kubectl = sources[SOURCE_API_COMMANDS]
    assert isinstance(web, ApiCommandSource) and isinstance(kubectl, ApiCommandSource)
    assert web._findings is False and kubectl._findings is True
    assert web._discovery is False and kubectl._discovery is True
    assert [s.name for s in build_sources(env.db, env.casts, kinds={KIND_WEB})] == [SOURCE_WEB]
    assert [s.name for s in build_sources(env.db, env.casts, kinds={KIND_KUBECTL, KIND_SSH})] == [
        SOURCE_SESSIONS, SOURCE_API_COMMANDS,
    ]


# --- kubectl regression next to web rows (WEBAPP_SPEC 12.3) ------------------------------------------

_REGRESSION_QUERIES = [
    q_(KUBECTL),
    q_(KUBECTL, discovery=True),
    q_(KUBECTL, sort="risk"),
    q_(KUBECTL, severity="high"),
    q_(KUBECTL, has_findings=True),
    q_(KUBECTL, has_findings=False),
    q_(KUBECTL, user=ALICE),
    q_(KUBECTL, user=BOB_ID),
    q_(KUBECTL, system=PROD, system_set=True),
    q_(KUBECTL, system=WIKI, system_set=True),
    q_(KUBECTL, system=None, system_set=True),
    q_(KUBECTL, from_=at("09:00:00.000"), to=at("13:00:00.000")),
    q_(KUBECTL, text="/api"),
    q_(KUBECTL, text="home"),
]


async def test_kubectl_results_are_unchanged_by_the_web_scenario(env: Env) -> None:
    before = [await ids_of(env, q, page_size=3) for q in _REGRESSION_QUERIES]
    counts = {i: (await item_for(env, q_(KUBECTL), i)).data.request_count  # type: ignore[union-attr]
              for i in await ids_of(env, q_(KUBECTL))}
    await build_web_scenario(env.db)
    after = [await ids_of(env, q, page_size=3) for q in _REGRESSION_QUERIES]
    for q, b, a in zip(_REGRESSION_QUERIES, before, after, strict=True):
        assert a == b, q
        assert a == await oracle(env, q)
        assert not {i for _, i in a} & ALL_WEB, q
    assert counts == {
        i: (await item_for(env, q_(KUBECTL), i)).data.request_count  # type: ignore[union-attr]
        for i in await ids_of(env, q_(KUBECTL))
    }
    assert any(before)


async def test_recordings_and_kubectl_under_any_are_unchanged_by_web_rows(env: Env) -> None:
    queries = [q_(ANY), q_(ANY, sort="risk"), q_(ANY, user=BOB), q_(ANY, system=PROD, system_set=True)]
    before = [await ids_of(env, q, page_size=5) for q in queries]
    await build_web_scenario(env.db)
    for q, b in zip(queries, before, strict=True):
        after = await ids_of(env, q, page_size=5)
        assert [i for i in after if i[1] not in ALL_WEB] == b, q


async def test_type_kubectl_never_lists_web_rows(web_env: Env) -> None:
    items, _ = await walk(web_env, q_(KUBECTL, discovery=True), page_size=7)
    assert items and {it.kind for it in items} == {KIND_KUBECTL}
    assert not {i for _, i in (ident(it) for it in items)} & ALL_WEB
    items, _ = await walk(web_env, q_(WEBK), page_size=7)
    assert {it.kind for it in items} == {KIND_WEB}
    assert not {i for _, i in (ident(it) for it in items)} - ALL_WEB


# =================================================================================================
# Session 12 fix loop: CursorMismatch (F), scan-budget sources (K), purged focus (N),
# primary beyond the listed 200 rows (P), row-level TLS read (I)
# =================================================================================================

from gatorcast.store.timeline import CursorMismatch, request_tls_modes  # noqa: E402

# --- F: only cursor validation raises CursorMismatch --------------------------------------------


def test_cursor_mismatch_is_a_value_error_subclass_so_older_handlers_keep_working() -> None:
    assert issubclass(CursorMismatch, ValueError)


@pytest.mark.parametrize(
    ("source", "sort", "position"),
    [
        (SOURCE_WEB, "newest", ["T", _AT]),
        (SOURCE_WEB, "newest", "T"),
        (SOURCE_API_COMMANDS, "risk", ["F", 9, _AT, _RID]),
        (SOURCE_SESSIONS, "newest", ["x"]),
        ("web", "newest", ["T", _AT, _RID]),
    ],
)
def test_check_position_raises_cursor_mismatch_without_the_value(
    source: str, sort: str, position: object
) -> None:
    """F: a malformed position is a CursorMismatch (the only thing the route turns into a 400)."""
    with pytest.raises(CursorMismatch) as exc_info:
        check_position(source, sort, position)
    assert _RID not in str(exc_info.value) and _AT not in str(exc_info.value)


async def test_run_timeline_raises_cursor_mismatch_for_another_kind_set_or_sort(web_env: Env) -> None:
    """F: the cursor check at the top of ``run_timeline`` raises CursorMismatch, naming no value."""
    page = await run_page(web_env, q_(WEBK), limit=2)
    assert page.next_cursor is not None
    with pytest.raises(CursorMismatch) as other_kinds:
        await run_page(web_env, q_(ANY), limit=2, cursor=page.next_cursor)
    with pytest.raises(CursorMismatch):
        await run_page(web_env, q_(WEBK, sort="risk"), limit=2, cursor=page.next_cursor)
    assert page.next_cursor.positions[SOURCE_WEB][1] not in str(other_kinds.value)  # type: ignore[index]


async def test_a_missing_source_is_a_plain_value_error_not_a_cursor_mismatch(env: Env) -> None:
    """F: an internal ValueError (no source for a selected kind) must not look like a bad cursor."""
    sources = build_sources(env.db, env.casts, kinds=TYPE_GROUPS["ssh"])  # no api source built
    with pytest.raises(ValueError) as exc_info:
        await run_timeline(sources, q_(KUBECTL), KUBECTL, limit=5)
    assert not isinstance(exc_info.value, CursorMismatch)


# --- K: the scan-budget notice names the source(s) that spent their budget ----------------------


async def test_scan_budget_sources_name_kubectl_only(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(timeline, "_API_SCAN_BUDGET", 5)
    q = q_(KUBECTL, from_=at("12:00:00.000"), to=at("12:00:24.900"), text="nodes")
    page = await run_page(env, q, limit=2)
    assert page.scan_budget_hit and page.scan_budget == 5
    assert page.scan_budget_sources == frozenset({SOURCE_API_COMMANDS})


async def test_scan_budget_sources_name_web_only(web_env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(timeline, "_API_SCAN_BUDGET", 3)
    page = await run_page(web_env, q_(WEBK, text="no-such-text-anywhere"), limit=2)
    assert page.items == [] and page.budget_hit and page.scan_budget_hit
    assert page.scan_budget_sources == frozenset({SOURCE_WEB})


async def test_scan_budget_sources_name_both_when_both_spend_their_budget(
    web_env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(timeline, "_API_SCAN_BUDGET", 3)
    page = await run_page(web_env, q_(ANY, text="no-such-text-anywhere"), limit=2)
    assert page.scan_budget_hit
    assert page.scan_budget_sources == frozenset({SOURCE_API_COMMANDS, SOURCE_WEB})


async def test_scan_budget_sources_are_empty_without_a_budget_stop(web_env: Env) -> None:
    page = await run_page(web_env, q_(WEBK), limit=3)
    assert not page.scan_budget_hit and page.scan_budget_sources == frozenset()


# --- N: a focus that resolves but is purged before hydration reads as not found -----------------


@pytest.mark.parametrize(
    ("kinds", "request_id"),
    [(KUBECTL, "r-c1-2"), (WEBK, "ww-a2"), (ANY, "ww-a3"), (ANY, "r-c1-2")],
    ids=["kubectl", "web", "any-web", "any-kubectl"],
)
async def test_focus_resolved_but_purged_before_hydration_is_not_found(
    web_env: Env, monkeypatch: pytest.MonkeyPatch, kinds: frozenset[str], request_id: str
) -> None:
    """N: ``_hydrate_one`` finds the rows gone (retention ran between resolve and hydrate)."""
    before = await run_page(web_env, q_(kinds, cmd=request_id))
    assert before.items and not before.focus_not_found  # resolves and hydrates normally

    async def purged(self: ApiCommandSource, ref: Any) -> None:
        return None

    monkeypatch.setattr(ApiCommandSource, "_hydrate_one", purged)
    page = await run_page(web_env, q_(kinds, cmd=request_id))
    assert page.items == []
    assert page.focus_not_found


async def test_focus_that_never_resolved_is_still_not_found(web_env: Env) -> None:
    page = await run_page(web_env, q_(ANY, cmd="no-such-request-id"))
    assert page.items == [] and page.focus_not_found


# --- P: the primary request is chosen over EVERY row, not only the listed 200 -------------------

BIG = 250
LISTED = 200


async def _seed_long_connection(
    db: aiosqlite.Connection,
    *,
    api_kind: str,
    methods: dict[int, str],
    urls: dict[int, str] | None = None,
    conn_id: str,
    address: str,
    default_url: str = "/page",
) -> None:
    """``BIG`` requests, one second apart, GET ``default_url`` except the listed indexes."""
    web = api_kind == KIND_WEB
    await add_connection(
        db, conn_id, user_id="uid-long", username="long@example.com", resource_address=address,
        state="api", resource_type="WEB_APP" if web else "KUBERNETES",
    )
    for i in range(BIG):
        await add_request(
            db, f"{conn_id}-{i:03d}", conn_id=conn_id, requested_at=f"2026-10-02T09:{i // 60:02d}:{i % 60:02d}.000Z",
            resource_address=address, user_id="uid-long", username="long@example.com",
            method=methods.get(i, "GET"), url=(urls or {}).get(i, default_url),
            api_kind=api_kind, commit=False,
            kubectl_session=None if web else f"ks-{conn_id}",
            kubectl_command=None if web else "kubectl get",
            user_agent="Mozilla/5.0 (test)" if web else "kubectl/v1.33.0",
        )
    await db.commit()


async def _only_hit(
    env: Env, kinds: frozenset[str], system: str, *, discovery: bool = False
) -> CommandHit:
    page = await run_page(env, q_(kinds, system=system, system_set=True, discovery=discovery), limit=5)
    assert len(page.items) == 1
    hit = page.items[0].data
    assert isinstance(hit, CommandHit)
    return hit


async def test_web_primary_is_found_beyond_the_listed_rows(env: Env) -> None:
    """P: first mutating request at #230 (the 231st) of a 250-request web connection."""
    await _seed_long_connection(
        env.db, api_kind=KIND_WEB, methods={230: "DELETE", 240: "POST"}, conn_id="wlong",
        address="long.corp.internal", urls={230: "/items/230"},
    )
    hit = await _only_hit(env, WEBK, "long.corp.internal")
    assert hit.request_count == BIG and hit.listed_count == LISTED and hit.requests_truncated
    assert hit.command.primary.request_id == "wlong-230"
    assert (hit.command.primary.method, hit.command.primary.url) == ("DELETE", "/items/230")
    assert hit.command.primary not in hit.command.requests  # beyond the listed rows
    assert hit.command_id == "wlong-000"  # still keyed by the start row


async def test_web_primary_with_no_mutating_request_is_the_first_request(env: Env) -> None:
    await _seed_long_connection(
        env.db, api_kind=KIND_WEB, methods={}, conn_id="wget", address="get.corp.internal",
    )
    hit = await _only_hit(env, WEBK, "get.corp.internal")
    assert hit.request_count == BIG and hit.requests_truncated
    assert hit.command.primary.request_id == "wget-000"


async def test_web_primary_inside_the_listed_rows_is_unchanged(env: Env) -> None:
    await _seed_long_connection(
        env.db, api_kind=KIND_WEB, methods={5: "PUT", 230: "DELETE"}, conn_id="wearly",
        address="early.corp.internal",
    )
    hit = await _only_hit(env, WEBK, "early.corp.internal")
    assert hit.command.primary.request_id == "wearly-005"
    assert hit.command.primary in hit.command.requests


async def test_kubectl_primary_first_mutating_is_found_beyond_the_listed_rows(env: Env) -> None:
    """P: kubectl, first mutating request at #230."""
    await _seed_long_connection(
        env.db, api_kind=KIND_KUBECTL, methods={230: "DELETE"}, conn_id="klong",
        address="klong.example.internal", default_url="/api/v1/namespaces/default/pods",
        urls={230: "/api/v1/namespaces/default/pods/victim"},
    )
    hit = await _only_hit(env, KUBECTL, "klong.example.internal")
    assert hit.request_count == BIG and hit.listed_count == LISTED and hit.requests_truncated
    assert hit.command.primary.request_id == "klong-230"
    assert hit.command.primary.method == "DELETE"
    assert hit.label == "kubectl get"


async def test_kubectl_primary_first_non_discovery_is_found_beyond_the_listed_rows(env: Env) -> None:
    """P: no mutating request; the first 210 are discovery GETs, so the primary is the first
    non-discovery request at #210, past the listed rows (the same rule as before)."""
    discovery_url = "/api?timeout=32s"
    await _seed_long_connection(
        env.db, api_kind=KIND_KUBECTL, methods={}, conn_id="kdisc",
        address="kdisc.example.internal", default_url=discovery_url,
        urls={i: "/api/v1/namespaces/default/pods" for i in range(210, BIG)},
    )
    hit = await _only_hit(env, KUBECTL, "kdisc.example.internal")
    assert hit.request_count == BIG and hit.listed_count == LISTED and hit.requests_truncated
    assert hit.command.primary.request_id == "kdisc-210"
    assert hit.command.primary.url == "/api/v1/namespaces/default/pods"


async def test_kubectl_primary_all_discovery_is_the_first_request(env: Env) -> None:
    await _seed_long_connection(
        env.db, api_kind=KIND_KUBECTL, methods={}, conn_id="kall",
        address="kall.example.internal", default_url="/api?timeout=32s",
    )
    hit = await _only_hit(env, KUBECTL, "kall.example.internal", discovery=True)
    assert hit.command.primary.request_id == "kall-000"
    assert hit.is_discovery_only


# --- I: request_tls_modes reads the modes stored on the rows ------------------------------------


async def test_request_tls_modes_returns_stored_values_and_skips_unknown_ids(env: Env) -> None:
    await add_request(
        env.db, "tls-1", conn_id="tls-c", requested_at=at("09:00:00.000"), api_kind=KIND_WEB,
        resource_address="tls.corp.internal", downstream_tls="tls13", upstream_tls="insecure",
    )
    await add_request(
        env.db, "tls-2", conn_id="tls-c", requested_at=at("09:00:01.000"), api_kind=KIND_WEB,
        resource_address="tls.corp.internal", downstream_tls="surprise", upstream_tls=None,
    )
    got = await request_tls_modes(env.db, ["tls-1", "tls-2", "tls-1", "no-such-id"])
    assert got == {"tls-1": ("tls13", "insecure"), "tls-2": ("surprise", None)}
    assert await request_tls_modes(env.db, []) == {}
