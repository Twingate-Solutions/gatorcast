"""Tests for store.search (SearchStore): findings persistence + composite search.

Covers:
  - replace_findings idempotency; list_findings ordering; delete_findings
  - metadata filters (username, resource_address, status, started_after/before,
    min/max duration)
  - finding filters (category, rule_ids any-of, severity at-or-above, has_findings)
  - content scan: keyword (case-insensitive), regex match, invalid regex -> empty,
    candidate cap -> truncated, pagination
  - sort modes (newest, duration, risk)
  - dashboard_stats aggregates
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gatorcast.db import init_db
from gatorcast.pipeline.detect import Finding, max_severity
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchFilters, SearchStore
from gatorcast.store.sessions import SessionRepository

# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def db(tmp_path: Path):
    """A fresh schema-initialized aiosqlite connection."""
    conn = await init_db(tmp_path / "gatorcast.db")
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db) -> SessionRepository:
    """A SessionRepository over the fixture DB."""
    return SessionRepository(db)


@pytest.fixture
def casts(tmp_path: Path) -> CastStore:
    """A plaintext (no-encryption) CastStore for sidecar reads."""
    return CastStore(tmp_path / "casts")


@pytest.fixture
async def search_store(db, casts: CastStore) -> SearchStore:
    """A SearchStore over the fixture DB + cast store."""
    return SearchStore(db, casts)


async def seed_session(
    repo: SessionRepository,
    *,
    conn_id: str,
    username: str | None = "u@x",
    resource_address: str | None = "sysA",
    started_at: str | None = "2026-06-01T00:00:00Z",
    ended_at: str | None = "2026-06-01T00:01:00Z",
    duration_seconds: float | None = 60.0,
    status: str = "complete",
) -> None:
    """Create a complete session row with the given metadata."""
    await repo.upsert_start(conn_id, username, resource_address, started_at)
    await repo.finalize(
        conn_id,
        username=username,
        shell_user="ubuntu",
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=duration_seconds,
        width=80,
        height=24,
        chunk_count=1,
        size_bytes=10,
        cast_path=f"/d/{conn_id}.cast",
        status=status,
    )


async def attach_findings(
    repo: SessionRepository,
    store: SearchStore,
    conn_id: str,
    findings: list[Finding],
) -> None:
    """Persist findings and update the denormalized session summary."""
    await store.replace_findings(conn_id, findings)
    await repo.update_finding_summary(conn_id, len(findings), max_severity(findings))


# ---------------------------------------------------------------------------
# findings persistence
# ---------------------------------------------------------------------------


async def test_replace_findings_idempotent(
    search_store: SearchStore, repo: SessionRepository
) -> None:
    """replace_findings run twice yields the same rows, no duplicates."""
    await seed_session(repo, conn_id="c1")
    findings = [
        Finding("recursive-delete", "dangerous-command", "high", "Recursive delete (rm -rf)", 1.0),
        Finding("chmod-777", "dangerous-command", "medium", "World-writable chmod 777", 2.0),
    ]
    await search_store.replace_findings("c1", findings)
    first = await search_store.list_findings("c1")
    await search_store.replace_findings("c1", findings)
    second = await search_store.list_findings("c1")
    assert len(first) == 2
    assert len(second) == 2
    assert [f.rule_id for f in second] == ["recursive-delete", "chmod-777"]


async def test_list_findings_orders_by_offset(search_store: SearchStore, repo: SessionRepository) -> None:
    """list_findings orders by offset_seconds (NULLs last), then id."""
    await seed_session(repo, conn_id="c1")
    await search_store.replace_findings(
        "c1",
        [
            Finding("a", "cat", "low", "A", None),
            Finding("b", "cat", "low", "B", 5.0),
            Finding("c", "cat", "low", "C", 1.0),
        ],
    )
    rows = await search_store.list_findings("c1")
    assert [r.rule_id for r in rows] == ["c", "b", "a"]


async def test_delete_findings_empties(search_store: SearchStore, repo: SessionRepository) -> None:
    """delete_findings removes all rows for a conn_id."""
    await seed_session(repo, conn_id="c1")
    await search_store.replace_findings("c1", [Finding("a", "cat", "low", "A", 1.0)])
    await search_store.delete_findings("c1")
    assert await search_store.list_findings("c1") == []


# ---------------------------------------------------------------------------
# content scan
# ---------------------------------------------------------------------------


async def test_keyword_and_rule_filter(
    search_store: SearchStore, repo: SessionRepository, casts: CastStore
) -> None:
    """Keyword (case-insensitive) selects matching sidecars; rule filter joins findings."""
    await seed_session(repo, conn_id="c1")
    await casts.write_sidecar("c1", "rm -rf /var\n")
    await attach_findings(
        repo,
        search_store,
        "c1",
        [Finding("recursive-delete", "dangerous-command", "high", "Recursive delete (rm -rf)", 1.0)],
    )
    res = await search_store.search(SearchFilters(keyword="RM"))
    assert [i.session.conn_id for i in res.items] == ["c1"]

    res2 = await search_store.search(SearchFilters(rule_ids=["recursive-delete"]))
    assert res2.items[0].findings[0].rule_id == "recursive-delete"

    res3 = await search_store.search(SearchFilters(rule_ids=["nope"]))
    assert res3.total == 0


async def test_keyword_non_matching(
    search_store: SearchStore, repo: SessionRepository, casts: CastStore
) -> None:
    """A keyword absent from all sidecars yields total 0."""
    await seed_session(repo, conn_id="c1")
    await casts.write_sidecar("c1", "hello world\n")
    res = await search_store.search(SearchFilters(keyword="not-present"))
    assert res.total == 0
    assert res.items == []


async def test_regex_match_and_invalid(
    search_store: SearchStore, repo: SessionRepository, casts: CastStore
) -> None:
    """A valid regex selects; an invalid regex returns an empty result (no raise)."""
    await seed_session(repo, conn_id="c1")
    await casts.write_sidecar("c1", "ssh root@host\n")
    res = await search_store.search(SearchFilters(regex=r"root@\w+"))
    assert [i.session.conn_id for i in res.items] == ["c1"]

    bad = await search_store.search(SearchFilters(regex=r"([unclosed"))
    assert bad.total == 0
    assert bad.truncated is False


async def test_candidate_cap_truncates(
    search_store: SearchStore, repo: SessionRepository, casts: CastStore
) -> None:
    """A content scan over more candidates than the cap sets truncated and bounds total."""
    for i in range(5):
        cid = f"c{i}"
        await seed_session(repo, conn_id=cid, started_at=f"2026-06-0{i + 1}T00:00:00Z")
        await casts.write_sidecar(cid, "match me\n")
    res = await search_store.search(SearchFilters(keyword="match"), regex_max_candidates=2)
    assert res.truncated is True
    assert res.total <= 2


async def test_content_pagination(
    search_store: SearchStore, repo: SessionRepository, casts: CastStore
) -> None:
    """total reflects all matches; items <= page_size; page 2 returns the next slice."""
    for i in range(5):
        cid = f"c{i}"
        await seed_session(repo, conn_id=cid, started_at=f"2026-06-0{i + 1}T00:00:00Z")
        await casts.write_sidecar(cid, "match me\n")
    page1 = await search_store.search(SearchFilters(keyword="match", page=1, page_size=2))
    page2 = await search_store.search(SearchFilters(keyword="match", page=2, page_size=2))
    assert page1.total == 5
    assert len(page1.items) == 2
    assert len(page2.items) == 2
    ids1 = {i.session.conn_id for i in page1.items}
    ids2 = {i.session.conn_id for i in page2.items}
    assert ids1.isdisjoint(ids2)


# ---------------------------------------------------------------------------
# metadata filters
# ---------------------------------------------------------------------------


async def test_metadata_filters(search_store: SearchStore, repo: SessionRepository) -> None:
    """username / resource_address / status filters select exact matches only."""
    await seed_session(repo, conn_id="c1", username="alice@x", resource_address="sysA", status="complete")
    await seed_session(repo, conn_id="c2", username="bob@x", resource_address="sysB", status="error")

    by_user = await search_store.search(SearchFilters(username="alice@x"))
    assert [i.session.conn_id for i in by_user.items] == ["c1"]

    by_addr = await search_store.search(SearchFilters(resource_address="sysB"))
    assert [i.session.conn_id for i in by_addr.items] == ["c2"]

    by_status = await search_store.search(SearchFilters(status="error"))
    assert [i.session.conn_id for i in by_status.items] == ["c2"]


async def test_started_after_before_filters(search_store: SearchStore, repo: SessionRepository) -> None:
    """started_after / started_before (after-only, before-only, both, neither)."""
    await seed_session(repo, conn_id="early", started_at="2026-01-01T00:00:00Z")
    await seed_session(repo, conn_id="late", started_at="2026-12-01T00:00:00Z")

    after = await search_store.search(SearchFilters(started_after="2026-06-01T00:00:00Z"))
    assert [i.session.conn_id for i in after.items] == ["late"]

    before = await search_store.search(SearchFilters(started_before="2026-06-01T00:00:00Z"))
    assert [i.session.conn_id for i in before.items] == ["early"]

    both = await search_store.search(
        SearchFilters(started_after="2026-05-01T00:00:00Z", started_before="2026-07-01T00:00:00Z")
    )
    assert both.total == 0

    neither = await search_store.search(SearchFilters())
    assert neither.total == 2


async def test_duration_filters(search_store: SearchStore, repo: SessionRepository) -> None:
    """min_duration / max_duration bound the duration_seconds column."""
    await seed_session(repo, conn_id="short", duration_seconds=10.0)
    await seed_session(repo, conn_id="long", duration_seconds=300.0)

    long_only = await search_store.search(SearchFilters(min_duration=100.0))
    assert [i.session.conn_id for i in long_only.items] == ["long"]

    short_only = await search_store.search(SearchFilters(max_duration=100.0))
    assert [i.session.conn_id for i in short_only.items] == ["short"]


# ---------------------------------------------------------------------------
# finding filters
# ---------------------------------------------------------------------------


async def test_rule_ids_any_of(search_store: SearchStore, repo: SessionRepository) -> None:
    """rule_ids is any-of; empty rule_ids imposes no constraint."""
    await seed_session(repo, conn_id="c1")
    await seed_session(repo, conn_id="c2")
    await attach_findings(repo, search_store, "c1", [Finding("mkfs", "dangerous-command", "high", "mkfs", 1.0)])
    await attach_findings(repo, search_store, "c2", [Finding("jwt", "secret-exposure", "medium", "JWT", 1.0)])

    any_of = await search_store.search(SearchFilters(rule_ids=["mkfs", "fork-bomb"]))
    assert [i.session.conn_id for i in any_of.items] == ["c1"]

    no_constraint = await search_store.search(SearchFilters(rule_ids=[]))
    assert no_constraint.total == 2


async def test_severity_at_or_above(search_store: SearchStore, repo: SessionRepository) -> None:
    """severity matches findings at or above the requested rank."""
    await seed_session(repo, conn_id="hi")
    await attach_findings(repo, search_store, "hi", [Finding("r", "dangerous-command", "high", "H", 1.0)])

    assert (await search_store.search(SearchFilters(severity="medium"))).total == 1
    assert (await search_store.search(SearchFilters(severity="high"))).total == 1
    assert (await search_store.search(SearchFilters(severity="critical"))).total == 0
    # Unknown severity matches nothing.
    assert (await search_store.search(SearchFilters(severity="bogus"))).total == 0


async def test_has_findings(search_store: SearchStore, repo: SessionRepository) -> None:
    """has_findings True selects flagged sessions; False selects clean ones."""
    await seed_session(repo, conn_id="flagged")
    await seed_session(repo, conn_id="clean")
    await attach_findings(repo, search_store, "flagged", [Finding("r", "cat", "low", "L", 1.0)])

    yes = await search_store.search(SearchFilters(has_findings=True))
    assert [i.session.conn_id for i in yes.items] == ["flagged"]

    no = await search_store.search(SearchFilters(has_findings=False))
    assert [i.session.conn_id for i in no.items] == ["clean"]


# ---------------------------------------------------------------------------
# sort modes
# ---------------------------------------------------------------------------


async def test_sort_modes(search_store: SearchStore, repo: SessionRepository) -> None:
    """newest / duration / risk produce the expected first element."""
    await seed_session(
        repo, conn_id="old_long", started_at="2026-01-01T00:00:00Z", duration_seconds=500.0
    )
    await seed_session(
        repo, conn_id="new_short", started_at="2026-12-01T00:00:00Z", duration_seconds=5.0
    )
    await attach_findings(
        repo, search_store, "old_long", [Finding("r", "dangerous-command", "critical", "C", 1.0)]
    )

    newest = await search_store.search(SearchFilters(sort="newest"))
    assert newest.items[0].session.conn_id == "new_short"

    duration = await search_store.search(SearchFilters(sort="duration"))
    assert duration.items[0].session.conn_id == "old_long"

    risk = await search_store.search(SearchFilters(sort="risk"))
    assert risk.items[0].session.conn_id == "old_long"


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


async def test_dashboard_stats(search_store: SearchStore, repo: SessionRepository) -> None:
    """dashboard_stats aggregates totals, severity, category, top users/systems."""
    await seed_session(repo, conn_id="c1", username="alice@x", resource_address="sysA")
    await seed_session(repo, conn_id="c2", username="alice@x", resource_address="sysA")
    await seed_session(repo, conn_id="c3", username="bob@x", resource_address="sysB")
    await attach_findings(
        repo,
        search_store,
        "c1",
        [
            Finding("r1", "dangerous-command", "high", "H", 1.0),
            Finding("r2", "secret-exposure", "critical", "C", 2.0),
        ],
    )
    await attach_findings(
        repo, search_store, "c2", [Finding("r3", "dangerous-command", "medium", "M", 1.0)]
    )

    stats = await search_store.dashboard_stats()
    assert stats.total_sessions == 3
    assert stats.flagged_sessions == 2
    # c1's max is critical, c2's max is medium.
    assert stats.by_severity == {"critical": 1, "medium": 1}
    # 2 dangerous-command findings, 1 secret-exposure.
    assert stats.by_category == {"dangerous-command": 2, "secret-exposure": 1}
    top_users = {lc.label: lc.count for lc in stats.top_users}
    assert top_users == {"alice@x": 2, "bob@x": 1}
    top_systems = {lc.label: lc.count for lc in stats.top_systems}
    assert top_systems == {"sysA": 2, "sysB": 1}


async def test_dashboard_stats_time_window(
    search_store: SearchStore, repo: SessionRepository
) -> None:
    """A started_after cutoff scopes every dashboard aggregate to that window."""
    await seed_session(repo, conn_id="recent", username="r@x", resource_address="sysR",
                       started_at="2026-06-10T00:00:00Z")
    await seed_session(repo, conn_id="old", username="o@x", resource_address="sysO",
                       started_at="2026-01-01T00:00:00Z")
    await attach_findings(
        repo, search_store, "recent", [Finding("r1", "dangerous-command", "high", "H", 1.0)]
    )
    await attach_findings(
        repo, search_store, "old", [Finding("r2", "secret-exposure", "critical", "C", 1.0)]
    )

    stats = await search_store.dashboard_stats(started_after="2026-06-01T00:00:00Z")
    assert stats.total_sessions == 1  # only the recent session
    assert stats.flagged_sessions == 1
    assert stats.by_severity == {"high": 1}  # the old critical is excluded
    assert stats.by_category == {"dangerous-command": 1}
    assert {lc.label for lc in stats.top_users} == {"r@x"}
    assert {lc.label for lc in stats.top_systems} == {"sysR"}


# ---------------------------------------------------------------------------
# exact max_severity filter (dashboard severity drill-down)
# ---------------------------------------------------------------------------


async def test_search_max_severity_exact(
    search_store: SearchStore, repo: SessionRepository
) -> None:
    """The max_severity filter matches a session's highest severity exactly."""
    await seed_session(repo, conn_id="crit", resource_address="sysA")
    await seed_session(repo, conn_id="high", resource_address="sysA")
    await attach_findings(
        repo, search_store, "crit", [Finding("r1", "secret-exposure", "critical", "C", 1.0)]
    )
    await attach_findings(
        repo, search_store, "high", [Finding("r2", "dangerous-command", "high", "H", 1.0)]
    )

    crit = await search_store.search(SearchFilters(max_severity="critical"))
    assert [i.session.conn_id for i in crit.items] == ["crit"]

    high = await search_store.search(SearchFilters(max_severity="high"))
    assert [i.session.conn_id for i in high.items] == ["high"]

    # Contrast: the at-or-above `severity` filter is broader (high includes critical).
    at_or_above = await search_store.search(SearchFilters(severity="high"))
    assert {i.session.conn_id for i in at_or_above.items} == {"crit", "high"}
