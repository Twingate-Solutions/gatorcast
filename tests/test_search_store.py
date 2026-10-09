"""Tests for store.search (SearchStore): findings persistence + composite search.

Covers:
  - replace_findings idempotency; list_findings ordering; delete_findings
  - metadata filters (username, resource_address, status, started_after/before,
    min/max duration)
  - finding filters (category, rule_ids any-of, severity at-or-above, has_findings)
  - content scan: keyword (case-insensitive), regex match, invalid regex -> empty,
    candidate cap -> truncated, pagination
  - sort modes (newest, duration, risk)
  - dashboard_stats aggregates; session window on SESSION_AT_SQL (NULL start,
    fractional boundary second, failed connections); kubectl flagged-command
    figures from Q10 (one per command at its max severity, windowed on the command
    start, cap + truncation flag, deprecated aliases, pinned plan)
"""

from __future__ import annotations

from pathlib import Path

import pytest

import gatorcast.store.search as search_mod
from gatorcast.db import init_db
from gatorcast.models import ApiRequest
from gatorcast.pipeline.detect import Finding, max_severity
from gatorcast.store.activity import ActivityStore, RequestStorage
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


# ---------------------------------------------------------------------------
# dashboard: session window on SESSION_AT_SQL (spec §8.2)
# ---------------------------------------------------------------------------
#
# Every cutoff below is an explicit, fixed timestamp passed to dashboard_stats, and
# every seeded row sits well clear of it except the deliberate boundary rows, so no
# "now minus N days" clock race is possible. created_at is pinned with an UPDATE
# rather than taken from SQLite's clock.

_CUTOFF = "2026-06-01T00:00:00Z"


async def test_dashboard_session_window_uses_session_at(
    search_store: SearchStore, repo: SessionRepository, db
) -> None:
    """Sessions are windowed on COALESCE(started_at, created_at) in requested_at format.

    Covers the two cases the old ``started_at >= ?`` string compare got wrong: a NULL
    ``started_at`` (placed by ``created_at``) and a fractional-second start at the
    boundary second. A failed connection (error, no chunks, no cast) counts too,
    because "Total sessions" links to ``type=recordings``, which includes it.
    """
    # Boundary second with a fraction: "...00.250Z" sorts before "...00Z" as text.
    await seed_session(repo, conn_id="frac", started_at="2026-06-01T00:00:00.250Z")
    # Exactly at the cutoff (inclusive).
    await seed_session(repo, conn_id="edge", started_at="2026-06-01T00:00:00Z")
    # Just before the cutoff.
    await seed_session(repo, conn_id="before", started_at="2026-05-31T23:59:59.999Z")
    # Well inside / well outside.
    await seed_session(repo, conn_id="inside", started_at="2026-06-20T08:00:00Z")
    await seed_session(repo, conn_id="old", started_at="2026-01-01T00:00:00Z")
    # NULL started_at: placed by created_at (pinned inside the window).
    await repo.upsert_start("nullstart", "n@x", "sysN", None)
    await db.execute(
        "UPDATE sessions SET created_at = '2026-06-05 00:00:00' WHERE conn_id = 'nullstart'"
    )
    # NULL started_at with created_at outside the window.
    await repo.upsert_start("nullold", "n@x", "sysN", None)
    await db.execute(
        "UPDATE sessions SET created_at = '2026-02-01 00:00:00' WHERE conn_id = 'nullold'"
    )
    # A failed connection inside the window.
    await repo.upsert_start("failed", "f@x", "sysF", "2026-06-10T00:00:00Z")
    await db.execute("UPDATE sessions SET status = 'error' WHERE conn_id = 'failed'")
    await db.commit()

    await attach_findings(
        repo, search_store, "frac", [Finding("r1", "dangerous-command", "high", "H", 1.0)]
    )
    await attach_findings(
        repo, search_store, "before", [Finding("r2", "dangerous-command", "critical", "C", 1.0)]
    )
    await attach_findings(
        repo, search_store, "nullstart", [Finding("r3", "secret-exposure", "medium", "M", 1.0)]
    )

    stats = await search_store.dashboard_stats(started_after=_CUTOFF)
    # frac, edge, inside, nullstart, failed
    assert stats.total_sessions == 5
    assert stats.flagged_sessions == 2  # frac, nullstart
    assert stats.by_severity == {"high": 1, "medium": 1}  # "before"'s critical is out
    assert stats.by_category == {"dangerous-command": 1, "secret-exposure": 1}
    assert {lc.label for lc in stats.top_users} == {"u@x", "n@x", "f@x"}

    # Any fromisoformat shape of the same instant gives the same figures.
    same = await search_store.dashboard_stats(started_after="2026-06-01T00:00:00+00:00")
    naive = await search_store.dashboard_stats(started_after="2026-06-01T00:00:00")
    assert same == stats
    assert naive == stats

    all_time = await search_store.dashboard_stats()
    assert all_time.total_sessions == 8


async def test_dashboard_bad_cutoff_raises(search_store: SearchStore) -> None:
    """An unparseable cutoff is a ValueError (the route validates before calling)."""
    with pytest.raises(ValueError):
        await search_store.dashboard_stats(started_after="not-a-date")


# ---------------------------------------------------------------------------
# dashboard: kubectl flagged commands (spec §8.2, Q10)
# ---------------------------------------------------------------------------


async def seed_api(
    activity: ActivityStore,
    request_id: str,
    requested_at: str,
    *,
    kubectl_session: str | None = "sess-A",
    conn_id: str = "conn-1",
    username: str | None = "alice@x",
    user_id: str | None = "U-alice",
    resource_address: str | None = "k8s",
    method: str = "GET",
    url: str = "/api/v1/namespaces/default/pods",
    findings: tuple[Finding, ...] = (),
) -> None:
    """Store one API request (and its findings) through the ActivityStore."""
    req = ApiRequest(
        conn_id=conn_id,
        request_id=request_id,
        requested_at=requested_at,
        user_id=user_id,
        username=username,
        method=method,
        url=url,
        url_web=url,
        status_code=200,
        kubectl_command="kubectl get",
        kubectl_session=kubectl_session,
        user_agent="kubectl/v1.33.0 (linux/amd64)",
    )
    await activity.insert_request_with_findings(req, resource_address, findings)


def _api_finding(severity: str, rule_id: str = "kube-rule") -> Finding:
    """An API finding with the given severity (rule metadata only)."""
    return Finding(rule_id, "kube-api", severity, f"{severity} rule", None)


@pytest.fixture
async def activity(db) -> ActivityStore:
    """An ActivityStore over the fixture DB."""
    return ActivityStore(db)


async def _seed_commands(activity: ActivityStore) -> None:
    """Seed kubectl commands around ``_CUTOFF`` (2026-06-01T00:00:00Z).

    ====  ==========================================  =========  ===========
    cmd   identity                                    start      max sev
    ====  ==========================================  =========  ===========
    A     sess-A, alice, k8s (3 requests)             06-10      high
    B     no Kubectl-Session → conn-B, alice          06-10      medium
    C     sess-C, alice (+ discovery request)         06-10      none
    D     sess-D, alice; flagged row after cutoff     05-20      critical
    E     sess-A again but user bob → own command     06-10      low
    F     sess-F, finding of unknown severity         06-10      (rank 0)
    G     sess-G, starts exactly at the cutoff        06-01      high
    H1/2  empty Kubectl-Session → split by conn       06-11      medium x2
    ====  ==========================================  =========  ===========
    """
    await seed_api(activity, "rA1", "2026-06-10T10:00:00.000Z")
    await seed_api(activity, "rA2", "2026-06-10T10:00:01.000Z", method="DELETE",
                   findings=(_api_finding("high"),))
    await seed_api(activity, "rA3", "2026-06-10T10:00:02.000Z",
                   findings=(_api_finding("medium"), _api_finding("low", "kube-other")))
    await seed_api(activity, "rB1", "2026-06-10T11:00:00.000Z", kubectl_session=None,
                   conn_id="conn-B", findings=(_api_finding("medium"),))
    await seed_api(activity, "rC1", "2026-06-10T12:00:00.000Z", kubectl_session="sess-C")
    await seed_api(activity, "rC2", "2026-06-10T12:00:00.100Z", kubectl_session="sess-C",
                   url="/api")
    await seed_api(activity, "rD1", "2026-05-20T00:00:00.000Z", kubectl_session="sess-D")
    await seed_api(activity, "rD2", "2026-06-15T00:00:00.000Z", kubectl_session="sess-D",
                   findings=(_api_finding("critical"),))
    await seed_api(activity, "rE1", "2026-06-10T13:00:00.000Z", username="bob@x",
                   user_id="U-bob", findings=(_api_finding("low"),))
    await seed_api(activity, "rF1", "2026-06-10T14:00:00.000Z", kubectl_session="sess-F",
                   findings=(_api_finding("bogus"),))
    await seed_api(activity, "rG1", "2026-06-01T00:00:00.000Z", kubectl_session="sess-G",
                   findings=(_api_finding("high"),))
    await seed_api(activity, "rH1", "2026-06-11T00:00:00.000Z", kubectl_session="",
                   conn_id="conn-H1", findings=(_api_finding("medium"),))
    await seed_api(activity, "rH2", "2026-06-11T00:00:01.000Z", kubectl_session="",
                   conn_id="conn-H2", findings=(_api_finding("medium"),))


async def test_dashboard_api_flagged_commands_all_time(
    search_store: SearchStore, activity: ActivityStore
) -> None:
    """Each flagged command counts once, at its max severity; the total counts requests."""
    await _seed_commands(activity)
    stats = await search_store.dashboard_stats()

    # A, B, D, E, F, G, H1, H2 (C has no finding).
    assert stats.api_flagged_commands == 8
    assert stats.api_commands_by_severity == {
        "critical": 1,  # D
        "high": 2,  # A (high beats its medium/low), G
        "medium": 3,  # B, H1, H2
        "low": 1,  # E: same Kubectl-Session as A, different user
    }
    # F (unknown severity) is flagged but in no chip.
    assert sum(stats.api_commands_by_severity.values()) == stats.api_flagged_commands - 1
    assert stats.api_flagged_truncated is False
    # Requests, not commands, and discovery (rC2) included.
    assert stats.api_requests_total == 13


async def test_dashboard_api_flagged_commands_windowed_on_command_start(
    search_store: SearchStore, activity: ActivityStore
) -> None:
    """A command belongs to the window containing its first request (spec §3).

    D's flagged request is inside the window but its start row is not, so D is
    excluded, exactly as ``type=kubectl&has_findings=true&window=W`` excludes it.
    G starts exactly at the cutoff (``...SSZ`` vs stored ``...SS.000Z``) and is in.
    """
    await _seed_commands(activity)
    stats = await search_store.dashboard_stats(started_after=_CUTOFF)

    assert stats.api_flagged_commands == 7
    assert stats.api_commands_by_severity == {"high": 2, "medium": 3, "low": 1}
    assert stats.api_flagged_truncated is False
    # The request total is windowed on requested_at: only rD1 falls out.
    assert stats.api_requests_total == 12

    late = await search_store.dashboard_stats(started_after="2026-06-10T10:00:01Z")
    # A starts at 10:00:00 (out) although its flagged rows are in; D and G are out.
    # B, E, F, H1, H2 remain.
    assert late.api_flagged_commands == 5
    assert late.api_commands_by_severity == {"medium": 3, "low": 1}


async def test_dashboard_api_figures_empty(search_store: SearchStore) -> None:
    """With no API data the kubectl figures are zero / empty and not truncated."""
    stats = await search_store.dashboard_stats(started_after=_CUTOFF)
    assert stats.api_requests_total == 0
    assert stats.api_flagged_commands == 0
    assert stats.api_commands_by_severity == {}
    assert stats.api_flagged_truncated is False


async def test_dashboard_api_flagged_cap(
    search_store: SearchStore, activity: ActivityStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Over the cap, the figure is clamped and api_flagged_truncated is set."""
    for i in range(3):
        await seed_api(activity, f"r{i}", f"2026-06-1{i}T00:00:00.000Z",
                       kubectl_session=f"cap-{i}", findings=(_api_finding("high"),))

    monkeypatch.setattr(search_mod, "_FLAGGED_CMD_CAP", 2)
    capped = await search_store.dashboard_stats()
    assert capped.api_flagged_truncated is True
    assert capped.api_flagged_commands == 2

    monkeypatch.setattr(search_mod, "_FLAGGED_CMD_CAP", 3)
    exact = await search_store.dashboard_stats()
    assert exact.api_flagged_truncated is False
    assert exact.api_flagged_commands == 3
    assert exact.api_commands_by_severity == {"high": 3}


async def test_dashboard_request_based_api_fields_are_gone(
    search_store: SearchStore, activity: ActivityStore
) -> None:
    """The Session 9 request-based names were removed with the T7 dashboard switch."""
    await _seed_commands(activity)
    stats = await search_store.dashboard_stats()
    for name in ("api_flagged_requests", "api_by_severity"):
        assert not hasattr(stats, name)
        assert name not in stats.model_dump()


@pytest.mark.parametrize("windowed", [False, True])
async def test_flagged_command_stats_plan(db, windowed: bool) -> None:
    """Q10 is driven from api_findings and probes idx_api_req_cmd per command."""
    params: dict[str, object] = {"cap": 5001}
    if windowed:
        params["cutoff"] = "2026-06-01T00:00:00.000Z"
    cursor = await db.execute(
        "EXPLAIN QUERY PLAN " + search_mod.flagged_command_stats_sql(windowed=windowed),
        params,
    )
    details = [row["detail"] for row in await cursor.fetchall()]
    await cursor.close()
    plan = "\n".join(details)

    # hit: scan api_findings, reach api_requests by primary key.
    assert any(d.startswith("SCAN f") for d in details), plan
    assert any(
        d.startswith("SEARCH r USING") and "request_id=?" in d for d in details
    ), plan
    # Every per-command subquery uses the command-key expression index. Unwindowed,
    # start_at is unused and SQLite drops its subquery, leaving only max_rank. Older
    # SQLite builds list a correlated subquery once per reference, so the probe lines
    # can repeat: require at least one per subquery and that every probe of q is an
    # idx_api_req_cmd seek.
    expected = 2 if windowed else 1
    q_access = [d for d in details if d.startswith(("SEARCH q ", "SCAN q "))]
    assert len(q_access) >= expected, plan
    assert all(d.startswith("SEARCH q USING INDEX idx_api_req_cmd") for d in q_access), plan
    assert "idx_api_req_sys_user_time" not in plan  # retired in Session 11
    assert "idx_api_req_sys_kind_user_time" not in plan


# --- Session 11: web rows never count toward the kubectl dashboard figures (WEBAPP_SPEC 8.6) ---


async def seed_web(
    activity: ActivityStore,
    request_id: str,
    requested_at: str,
    *,
    conn_id: str = "web-conn",
    findings: tuple[Finding, ...] = (),
    resource_address: str | None = "wiki.corp.internal",
) -> None:
    """Store one web-policy request (api_kind 'web'), optionally with findings."""
    req = ApiRequest(
        conn_id=conn_id,
        request_id=request_id,
        requested_at=requested_at,
        user_id="U-alice",
        username="alice@x",
        method="DELETE",
        url="/items/42",
        url_web="/items/42",
        status_code=200,
        user_agent="Mozilla/5.0 (test)",
    )
    storage = RequestStorage(
        api_kind="web", url=req.url, user_agent=req.user_agent, kubectl_command=None, kubectl_session=None
    )
    await activity.insert_request_with_findings(req, resource_address, findings, storage=storage)


async def test_dashboard_api_requests_total_ignores_web_rows(
    search_store: SearchStore, activity: ActivityStore
) -> None:
    await _seed_commands(activity)
    before = await search_store.dashboard_stats()
    for i in range(6):
        await seed_web(activity, f"w{i}", f"2026-06-10T12:00:0{i}.000Z")

    after = await search_store.dashboard_stats()
    windowed = await search_store.dashboard_stats(started_after=_CUTOFF)

    assert after.api_requests_total == before.api_requests_total == 13
    assert windowed.api_requests_total == 12


async def test_dashboard_flagged_commands_ignore_web_rows_even_with_findings(
    search_store: SearchStore, activity: ActivityStore
) -> None:
    """A web row that somehow carries a finding is not a flagged kubectl command."""
    await _seed_commands(activity)
    before = await search_store.dashboard_stats()
    await seed_web(activity, "w-flagged", "2026-06-10T12:00:00.000Z", findings=(_api_finding("critical"),))

    after = await search_store.dashboard_stats()

    assert after.api_flagged_commands == before.api_flagged_commands == 8
    assert after.api_commands_by_severity == before.api_commands_by_severity
    assert after.api_requests_total == before.api_requests_total


async def test_dashboard_figures_are_zero_when_only_web_rows_exist(
    search_store: SearchStore, activity: ActivityStore
) -> None:
    for i in range(3):
        await seed_web(activity, f"w{i}", f"2026-06-10T12:00:0{i}.000Z", findings=(_api_finding("high"),))
    stats = await search_store.dashboard_stats()
    assert stats.api_requests_total == 0
    assert stats.api_flagged_commands == 0
    assert stats.api_commands_by_severity == {}
    assert stats.api_flagged_truncated is False
