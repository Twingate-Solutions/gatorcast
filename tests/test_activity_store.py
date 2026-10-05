"""Tests for store.activity (ActivityStore): connections, API requests, findings.

Covers (spec section 13, ``test_activity_store.py``, plus extra edge cases):
  - insert_request dedup: a redelivered request_id returns False, keeps the first
    row, and (with the caller's insert-findings-only-on-True rule) never duplicates
    findings
  - allowlisted columns only: the api_requests schema and stored values carry no
    Authorization / cookie / remote_addr / panic data
  - user_key derivation (user id, else username, else NULL)
  - to_requested_at_format and the bound normalization (seconds-only ``Z`` input,
    offsets, naive datetimes, microsecond truncation, invalid input)
  - upsert_connection_start: insert pending, non-null replaces, NULL never clears,
    started_at first-wins, state / has_api never changed, last_seen_at bumped
  - late start line backfills api_requests.resource_address (NULL rows only)
  - set_state: upsert of a minimal row, sticky has_api, unknown state -> ValueError
  - expire_pending: uses last_seen_at, boundary, only pending, oldest first, idempotent
  - requests_for_system: half-open window, ordering, NULL bucket, limit
  - requests_in_bounds: inclusive bounds, NULL cluster/user buckets, limit
  - findings_for_requests (including more than one 500-id chunk)
  - recordings_for_requests: maps by request_id (never conn_id), earliest-started
    wins, more than 1000 ids across chunk boundaries
  - purge_before: counts, boundary, findings cascade (also with foreign keys off),
    connections by created_at
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import aiosqlite
import pytest

from gatorcast.db import init_db
from gatorcast.models import ApiRequest
from gatorcast.pipeline.detect import Finding
from gatorcast.store.activity import (
    ActivityStore,
    ApiFindingRow,
    ApiRequestRow,
    ConnectionRow,
    to_requested_at_format,
)
from gatorcast.store.sessions import SessionRepository

CLUSTER = "k8s.example.internal"
USER_ID = "VXNlcjox"
USERNAME = "user@example.com"

# Fixed, millisecond-precision timestamps in the stored format.
T0 = "2026-10-01T10:00:00.000Z"
T1 = "2026-10-01T10:00:01.000Z"
T2 = "2026-10-01T10:00:02.500Z"
T3 = "2026-10-01T10:00:03.000Z"


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def db(tmp_path: Path):
    """A fresh schema-initialized aiosqlite connection (real init_db)."""
    conn = await init_db(tmp_path / "gatorcast.db")
    yield conn
    await conn.close()


@pytest.fixture
async def store(db) -> ActivityStore:
    """An ActivityStore over the fixture DB."""
    return ActivityStore(db)


@pytest.fixture
async def repo(db) -> SessionRepository:
    """A SessionRepository over the fixture DB (for recording-link tests)."""
    return SessionRepository(db)


def make_req(
    request_id: str = "req-1",
    *,
    conn_id: str = "conn-a",
    requested_at: str = T0,
    user_id: str | None = USER_ID,
    username: str | None = USERNAME,
    method: str = "GET",
    url: str = "/api/v1/pods",
    status_code: int | None = 200,
    outcome: str = "completed",
    kubectl_command: str | None = "kubectl get",
    kubectl_session: str | None = "sess-1",
    user_agent: str | None = "kubectl/v1.33.0 (linux/amd64)",
) -> ApiRequest:
    """Build an allowlisted ApiRequest with sensible defaults."""
    return ApiRequest(
        conn_id=conn_id,
        request_id=request_id,
        requested_at=requested_at,
        user_id=user_id,
        username=username,
        method=method,
        url=url,
        status_code=status_code,
        outcome=outcome,
        kubectl_command=kubectl_command,
        kubectl_session=kubectl_session,
        user_agent=user_agent,
    )


def make_finding(rule_id: str = "kube-exec", severity: str = "high") -> Finding:
    """Build an API finding (no offset)."""
    return Finding(
        rule_id=rule_id,
        category="kube-api",
        severity=severity,
        label=f"label for {rule_id}",
        offset_seconds=None,
    )


async def add_request(
    store: ActivityStore,
    request_id: str,
    *,
    resource_address: str | None = CLUSTER,
    **overrides,
) -> None:
    """Insert one request, asserting it was new."""
    assert await store.insert_request(make_req(request_id, **overrides), resource_address)


async def rows(db, sql: str, params: tuple = ()) -> list[aiosqlite.Row]:
    """Run a read query and return all rows."""
    cur = await db.execute(sql, params)
    result = await cur.fetchall()
    await cur.close()
    return list(result)


async def count(db, table: str) -> int:
    """Row count of a table."""
    return (await rows(db, f"SELECT COUNT(*) AS n FROM {table}"))[0]["n"]


async def set_connection_times(
    db, conn_id: str, *, last_seen: str | None = None, created: str | None = None
) -> None:
    """Override connections.last_seen_at / created_at with raw SQL expressions or values."""
    if last_seen is not None:
        await db.execute(
            "UPDATE connections SET last_seen_at = ? WHERE conn_id = ?", (last_seen, conn_id)
        )
    if created is not None:
        await db.execute(
            "UPDATE connections SET created_at = ? WHERE conn_id = ?", (created, conn_id)
        )
    await db.commit()


async def seconds_ago(db, seconds: int) -> str:
    """SQLite 'now' minus N seconds, in connections' datetime() text format."""
    return (await rows(db, "SELECT datetime('now', ?) AS t", (f"-{seconds} seconds",)))[0]["t"]


async def insert_session_row(
    db,
    conn_id: str,
    request_id: str | None,
    *,
    started_at: str | None = None,
    created_at: str = "2026-10-01 00:00:00",
) -> None:
    """Insert a bare sessions row carrying a request_id."""
    await db.execute(
        """
        INSERT INTO sessions (conn_id, request_id, status, started_at, created_at, updated_at)
        VALUES (?, ?, 'complete', ?, ?, ?)
        """,
        (conn_id, request_id, started_at, created_at, created_at),
    )
    await db.commit()


# ---------------------------------------------------------------------------
# to_requested_at_format
# ---------------------------------------------------------------------------


def test_format_passthrough_of_stored_format() -> None:
    """A value already in the stored format is unchanged."""
    assert to_requested_at_format("2026-10-01T10:00:01.250Z") == "2026-10-01T10:00:01.250Z"


def test_format_seconds_only_z_gets_millis() -> None:
    """Seconds-only Z input gains a .000 fraction."""
    assert to_requested_at_format("2026-10-01T10:00:01Z") == "2026-10-01T10:00:01.000Z"


def test_format_offset_converted_to_utc() -> None:
    """A +00:00 or non-UTC offset string is converted to UTC and rendered with Z."""
    assert to_requested_at_format("2026-10-01T10:00:01+00:00") == "2026-10-01T10:00:01.000Z"
    assert to_requested_at_format("2026-10-01T12:00:01+02:00") == "2026-10-01T10:00:01.000Z"


def test_format_truncates_sub_millisecond_precision() -> None:
    """Microseconds are truncated (not rounded) to milliseconds."""
    assert to_requested_at_format("2026-10-01T10:00:01.123987Z") == "2026-10-01T10:00:01.123Z"


def test_format_naive_datetime_is_utc_and_aware_converted() -> None:
    """Naive datetimes are taken as UTC; aware ones are converted."""
    naive = datetime(2026, 10, 1, 10, 0, 1, 5000)
    assert to_requested_at_format(naive) == "2026-10-01T10:00:01.005Z"
    plus_two = datetime(2026, 10, 1, 12, 0, 1, tzinfo=timezone(timedelta(hours=2)))
    assert to_requested_at_format(plus_two) == "2026-10-01T10:00:01.000Z"
    assert to_requested_at_format(datetime(2026, 10, 1, 10, 0, 1, tzinfo=UTC)) == (
        "2026-10-01T10:00:01.000Z"
    )


def test_format_strips_surrounding_whitespace() -> None:
    """Leading/trailing whitespace in a string bound is tolerated."""
    assert to_requested_at_format("  2026-10-01T10:00:01Z \n") == "2026-10-01T10:00:01.000Z"


@pytest.mark.parametrize("bad", ["", "not-a-time", "yesterday"])
def test_format_invalid_string_raises_value_error(bad: str) -> None:
    """An unparseable string bound raises ValueError."""
    with pytest.raises(ValueError):
        to_requested_at_format(bad)


# ---------------------------------------------------------------------------
# insert_request: dedup, allowlisted columns, user_key
# ---------------------------------------------------------------------------


async def test_insert_request_returns_true_and_stores_row(store: ActivityStore) -> None:
    """A new request is inserted (True) and read back with every allowlisted field."""
    inserted = await store.insert_request(make_req("r1", url="/api/v1/pods?limit=5"), CLUSTER)
    assert inserted is True

    got = await store.requests_for_system(CLUSTER, T0, T3)
    assert got == [
        ApiRequestRow(
            request_id="r1",
            conn_id="conn-a",
            resource_address=CLUSTER,
            user_key=USER_ID,
            user_id=USER_ID,
            username=USERNAME,
            requested_at=T0,
            method="GET",
            url="/api/v1/pods?limit=5",
            status_code=200,
            outcome="completed",
            kubectl_command="kubectl get",
            kubectl_session="sess-1",
            user_agent="kubectl/v1.33.0 (linux/amd64)",
            created_at=got[0].created_at,
        )
    ]
    assert got[0].created_at is not None


async def test_insert_request_dedup_second_insert_false(store: ActivityStore, db) -> None:
    """A redelivered request_id returns False and leaves exactly one row."""
    assert await store.insert_request(make_req("dup"), CLUSTER) is True
    assert await store.insert_request(make_req("dup"), CLUSTER) is False
    assert await count(db, "api_requests") == 1


async def test_insert_request_dedup_keeps_first_row(store: ActivityStore) -> None:
    """A duplicate with different content does not overwrite the stored row."""
    await store.insert_request(make_req("dup", url="/first", status_code=200), CLUSTER)
    again = await store.insert_request(
        make_req("dup", url="/second", status_code=502, requested_at=T2), "other-cluster"
    )
    assert again is False

    got = await store.requests_for_system(CLUSTER, T0, T3)
    assert [(r.url, r.status_code, r.requested_at) for r in got] == [("/first", 200, T0)]
    assert await store.requests_for_system("other-cluster", T0, T3) == []


async def test_redelivery_does_not_duplicate_findings(store: ActivityStore, db) -> None:
    """Callers store findings only when insert_request is True, so redelivery adds none."""
    findings = [make_finding("kube-exec"), make_finding("kube-secrets", "medium")]
    for _ in range(3):
        if await store.insert_request(make_req("redelivered"), CLUSTER):
            await store.insert_api_findings("redelivered", findings)

    assert await count(db, "api_requests") == 1
    assert await count(db, "api_findings") == 2
    got = (await store.findings_for_requests(["redelivered"]))["redelivered"]
    assert [f.rule_id for f in got] == ["kube-exec", "kube-secrets"]


async def test_api_requests_schema_has_only_allowlisted_columns(db) -> None:
    """The table has no column that could hold Authorization/cookies/remote_addr/panic."""
    cols = {r["name"] for r in await rows(db, "PRAGMA table_info(api_requests)")}
    assert cols == {
        "request_id",
        "conn_id",
        "resource_address",
        "user_key",
        "user_id",
        "username",
        "requested_at",
        "method",
        "url",
        "status_code",
        "outcome",
        "kubectl_command",
        "kubectl_session",
        "user_agent",
        "created_at",
    }


async def test_insert_request_stores_no_extra_input_data(store: ActivityStore, db) -> None:
    """Extra fields on the input (Authorization, cookie, remote_addr, panic) never reach disk."""
    req = ApiRequest.model_validate(
        {
            "conn_id": "conn-a",
            "request_id": "leaky",
            "requested_at": T0,
            "method": "GET",
            "url": "/api",
            "authorization": "Bearer GC_SENTINEL_TOKEN",
            "cookie": "session=GC_SENTINEL_TOKEN",
            "remote_addr": "10.0.0.5:51000",
            "panic": "GC_SENTINEL_PANIC",
        }
    )
    await store.insert_request(req, CLUSTER)

    for row in await rows(db, "SELECT * FROM api_requests"):
        for value in tuple(row):
            assert "GC_SENTINEL" not in str(value)
            assert "10.0.0.5" not in str(value)


async def test_user_key_is_user_id_when_present(store: ActivityStore) -> None:
    """user_key prefers user_id over username."""
    await add_request(store, "r1", user_id="uid-1", username="a@x")
    (row,) = await store.requests_for_system(CLUSTER, T0, T3)
    assert (row.user_key, row.user_id, row.username) == ("uid-1", "uid-1", "a@x")


async def test_user_key_falls_back_to_username(store: ActivityStore) -> None:
    """With no user_id, user_key is the username."""
    await add_request(store, "r1", user_id=None, username="a@x")
    (row,) = await store.requests_for_system(CLUSTER, T0, T3)
    assert (row.user_key, row.user_id, row.username) == ("a@x", None, "a@x")


async def test_user_key_null_when_no_identity(store: ActivityStore) -> None:
    """With neither id nor username, user_key is NULL."""
    await add_request(store, "r1", user_id=None, username=None)
    (row,) = await store.requests_for_system(CLUSTER, T0, T3)
    assert (row.user_key, row.user_id, row.username) == (None, None, None)


async def test_insert_request_failed_outcome_and_null_status(store: ActivityStore) -> None:
    """An 'API request failed' line stores outcome 'failed' with a NULL status code."""
    await add_request(store, "r1", outcome="failed", status_code=None)
    (row,) = await store.requests_for_system(CLUSTER, T0, T3)
    assert row.outcome == "failed"
    assert row.status_code is None


async def test_insert_request_optional_headers_null(store: ActivityStore) -> None:
    """Missing kubectl/user-agent metadata is stored as NULL."""
    await add_request(
        store, "r1", kubectl_command=None, kubectl_session=None, user_agent=None
    )
    (row,) = await store.requests_for_system(CLUSTER, T0, T3)
    assert (row.kubectl_command, row.kubectl_session, row.user_agent) == (None, None, None)


# ---------------------------------------------------------------------------
# insert_api_findings / findings_for_requests
# ---------------------------------------------------------------------------


async def test_insert_api_findings_roundtrip_and_order(store: ActivityStore) -> None:
    """Findings round-trip as ApiFindingRow in insertion order, without an offset column."""
    await add_request(store, "r1")
    await store.insert_api_findings(
        "r1", [make_finding("kube-exec", "high"), make_finding("kube-delete", "critical")]
    )
    got = (await store.findings_for_requests(["r1"]))["r1"]
    assert all(isinstance(f, ApiFindingRow) for f in got)
    assert [(f.rule_id, f.category, f.severity, f.label) for f in got] == [
        ("kube-exec", "kube-api", "high", "label for kube-exec"),
        ("kube-delete", "kube-api", "critical", "label for kube-delete"),
    ]
    assert got[0].id < got[1].id
    assert all(f.request_id == "r1" and f.created_at for f in got)


async def test_insert_api_findings_empty_is_noop(store: ActivityStore, db) -> None:
    """An empty findings list inserts nothing."""
    await add_request(store, "r1")
    await store.insert_api_findings("r1", [])
    assert await count(db, "api_findings") == 0


async def test_insert_api_findings_requires_existing_request(store: ActivityStore) -> None:
    """The FK is enforced: findings for an unknown request_id are rejected."""
    with pytest.raises(aiosqlite.IntegrityError):
        await store.insert_api_findings("no-such-request", [make_finding()])


async def test_findings_for_requests_groups_and_omits_clean(store: ActivityStore) -> None:
    """Result maps request_id -> findings; requests without findings are absent."""
    await add_request(store, "r1")
    await add_request(store, "r2", requested_at=T1)
    await add_request(store, "r3", requested_at=T2)
    await store.insert_api_findings("r1", [make_finding("a")])
    await store.insert_api_findings("r3", [make_finding("b"), make_finding("c")])

    got = await store.findings_for_requests(["r1", "r2", "r3", "unknown"])
    assert set(got) == {"r1", "r3"}
    assert [f.rule_id for f in got["r3"]] == ["b", "c"]


async def test_findings_for_requests_empty_input(store: ActivityStore) -> None:
    """No ids -> empty mapping, no query error."""
    assert await store.findings_for_requests([]) == {}


async def test_findings_for_requests_ignores_duplicate_ids(store: ActivityStore) -> None:
    """Duplicate ids in the input do not duplicate findings in the output."""
    await add_request(store, "r1")
    await store.insert_api_findings("r1", [make_finding("a")])
    got = await store.findings_for_requests(["r1", "r1", "r1"])
    assert [f.rule_id for f in got["r1"]] == ["a"]


async def test_findings_for_requests_spans_multiple_chunks(store: ActivityStore) -> None:
    """More than 500 ids are queried across chunks without losing rows."""
    ids = [f"req-{i:04d}" for i in range(1100)]
    for rid in ids:
        await store._db.execute(  # bulk seed; avoids 1100 commits
            "INSERT INTO api_requests (request_id, conn_id, requested_at, method, url) "
            "VALUES (?, 'c', ?, 'GET', '/')",
            (rid, T0),
        )
    await store._db.commit()
    # Findings straddling the 500-id chunk boundaries (indexes 0, 499, 500, 999, 1000, 1099).
    with_findings = [ids[i] for i in (0, 499, 500, 999, 1000, 1099)]
    for rid in with_findings:
        await store.insert_api_findings(rid, [make_finding("x")])

    got = await store.findings_for_requests(ids)
    assert set(got) == set(with_findings)
    assert all(len(v) == 1 for v in got.values())


# ---------------------------------------------------------------------------
# connections: upsert_connection_start / get_connection
# ---------------------------------------------------------------------------


async def test_get_connection_unknown_returns_none(store: ActivityStore) -> None:
    """An unknown conn_id yields None."""
    assert await store.get_connection("nope") is None


async def test_upsert_connection_start_inserts_pending(store: ActivityStore) -> None:
    """The first start line creates a hidden pending connection with has_api False."""
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, "2026-10-01T09:59:59Z")
    conn = await store.get_connection("c1")
    assert isinstance(conn, ConnectionRow)
    assert conn.conn_id == "c1"
    assert (conn.user_id, conn.username) == (USER_ID, USERNAME)
    assert conn.resource_address == CLUSTER
    assert conn.started_at == "2026-10-01T09:59:59Z"
    assert conn.state == "pending"
    assert conn.has_api is False
    assert conn.created_at is not None
    assert conn.last_seen_at is not None


async def test_upsert_connection_start_does_not_create_session_row(
    store: ActivityStore, db
) -> None:
    """A start line is a hidden connection, never a visible sessions row."""
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    assert await count(db, "sessions") == 0


async def test_upsert_connection_start_non_null_replaces_identity(
    store: ActivityStore,
) -> None:
    """On conflict, incoming non-null identity/cluster values replace stored ones."""
    await store.upsert_connection_start("c1", "old-id", "old@x", "old-cluster", T0)
    await store.upsert_connection_start("c1", "new-id", "new@x", "new-cluster", T1)
    conn = await store.get_connection("c1")
    assert (conn.user_id, conn.username, conn.resource_address) == (
        "new-id",
        "new@x",
        "new-cluster",
    )


async def test_upsert_connection_start_null_never_clears(store: ActivityStore) -> None:
    """Incoming NULLs keep the stored identity/cluster values."""
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    await store.upsert_connection_start("c1", None, None, None, None)
    conn = await store.get_connection("c1")
    assert (conn.user_id, conn.username, conn.resource_address) == (USER_ID, USERNAME, CLUSTER)
    assert conn.started_at == T0


async def test_upsert_connection_start_backfills_null_fields(store: ActivityStore) -> None:
    """A first row with NULL fields is filled in by a later start line."""
    await store.upsert_connection_start("c1", None, None, None, None)
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    conn = await store.get_connection("c1")
    assert (conn.user_id, conn.username, conn.resource_address, conn.started_at) == (
        USER_ID,
        USERNAME,
        CLUSTER,
        T0,
    )


async def test_upsert_connection_start_keeps_first_started_at(store: ActivityStore) -> None:
    """started_at is first-wins."""
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T3)
    assert (await store.get_connection("c1")).started_at == T0


async def test_upsert_connection_start_never_changes_state(store: ActivityStore) -> None:
    """A connection already promoted stays promoted when its start line is redelivered."""
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    await store.set_state("c1", "recording")
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    assert (await store.get_connection("c1")).state == "recording"

    await store.set_state("c1", "error")
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    assert (await store.get_connection("c1")).state == "error"


async def test_upsert_connection_start_never_changes_has_api(store: ActivityStore) -> None:
    """has_api set earlier survives a later start line."""
    await store.set_state("c1", "api", has_api=True)
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    conn = await store.get_connection("c1")
    assert conn.has_api is True
    assert conn.state == "api"


async def test_upsert_connection_start_bumps_last_seen(store: ActivityStore, db) -> None:
    """Re-seeing a start line refreshes last_seen_at."""
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    old = await seconds_ago(db, 3600)
    await set_connection_times(db, "c1", last_seen=old)
    assert (await store.get_connection("c1")).last_seen_at == old

    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    assert (await store.get_connection("c1")).last_seen_at > old


# ---------------------------------------------------------------------------
# late start line backfills api_requests.resource_address
# ---------------------------------------------------------------------------


async def test_late_start_backfills_resource_address(store: ActivityStore) -> None:
    """Requests stored with a NULL cluster gain it when the start line arrives."""
    await add_request(store, "r1", conn_id="c1", resource_address=None)
    await add_request(store, "r2", conn_id="c1", resource_address=None, requested_at=T1)
    assert await store.requests_for_system(CLUSTER, T0, T3) == []
    assert len(await store.requests_for_system(None, T0, T3)) == 2

    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)

    got = await store.requests_for_system(CLUSTER, T0, T3)
    assert sorted(r.request_id for r in got) == ["r1", "r2"]
    assert await store.requests_for_system(None, T0, T3) == []


async def test_backfill_leaves_other_connections_and_set_clusters(
    store: ActivityStore,
) -> None:
    """Backfill touches only this connection's NULL-cluster rows."""
    await add_request(store, "mine-null", conn_id="c1", resource_address=None)
    await add_request(store, "mine-set", conn_id="c1", resource_address="already")
    await add_request(store, "other-null", conn_id="c2", resource_address=None)

    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)

    by_id = {
        r.request_id: r
        for addr in (CLUSTER, "already", None)
        for r in await store.requests_for_system(addr, T0, T3)
    }
    assert by_id["mine-null"].resource_address == CLUSTER
    assert by_id["mine-set"].resource_address == "already"
    assert by_id["other-null"].resource_address is None


async def test_start_without_address_does_not_backfill(store: ActivityStore) -> None:
    """A start line carrying no resource_address leaves NULL-cluster requests alone."""
    await add_request(store, "r1", conn_id="c1", resource_address=None)
    await store.upsert_connection_start("c1", USER_ID, USERNAME, None, T0)
    (row,) = await store.requests_for_system(None, T0, T3)
    assert row.request_id == "r1"


async def test_backfill_after_request_inserted_via_set_state_first(
    store: ActivityStore,
) -> None:
    """Audit-before-start order: set_state minimal row, then start fills identity + cluster."""
    await add_request(store, "r1", conn_id="c1", resource_address=None)
    await store.set_state("c1", "api", has_api=True)
    conn = await store.get_connection("c1")
    assert conn.resource_address is None and conn.username is None

    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)

    conn = await store.get_connection("c1")
    assert (conn.state, conn.has_api, conn.resource_address, conn.username) == (
        "api",
        True,
        CLUSTER,
        USERNAME,
    )
    assert [r.request_id for r in await store.requests_for_system(CLUSTER, T0, T3)] == ["r1"]


# ---------------------------------------------------------------------------
# set_state
# ---------------------------------------------------------------------------


async def test_set_state_inserts_minimal_row(store: ActivityStore) -> None:
    """With no start line seen, set_state inserts a row with no identity or cluster."""
    await store.set_state("c-new", "api", has_api=True)
    conn = await store.get_connection("c-new")
    assert conn is not None
    assert conn.state == "api"
    assert conn.has_api is True
    assert conn.user_id is None
    assert conn.username is None
    assert conn.resource_address is None
    assert conn.started_at is None
    assert conn.created_at is not None and conn.last_seen_at is not None


async def test_set_state_updates_existing_and_keeps_identity(store: ActivityStore) -> None:
    """set_state on an existing row changes state only; identity/cluster are kept."""
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    await store.set_state("c1", "recording")
    conn = await store.get_connection("c1")
    assert conn.state == "recording"
    assert (conn.user_id, conn.username, conn.resource_address, conn.started_at) == (
        USER_ID,
        USERNAME,
        CLUSTER,
        T0,
    )


@pytest.mark.parametrize("state", ["pending", "recording", "api", "error"])
async def test_set_state_accepts_all_known_states(store: ActivityStore, state: str) -> None:
    """Each documented state is accepted and stored."""
    await store.set_state("c1", state)
    assert (await store.get_connection("c1")).state == state


async def test_set_state_has_api_is_sticky(store: ActivityStore) -> None:
    """Once has_api is True, a later has_api=False (the default) never clears it."""
    await store.set_state("c1", "api", has_api=True)
    await store.set_state("c1", "recording")  # has_api defaults to False
    conn = await store.get_connection("c1")
    assert conn.state == "recording"
    assert conn.has_api is True

    await store.set_state("c1", "error", has_api=False)
    assert (await store.get_connection("c1")).has_api is True


async def test_set_state_has_api_can_be_set_later(store: ActivityStore) -> None:
    """has_api starts False and is set by a later has_api=True call."""
    await store.set_state("c1", "recording")
    assert (await store.get_connection("c1")).has_api is False
    await store.set_state("c1", "recording", has_api=True)
    assert (await store.get_connection("c1")).has_api is True


@pytest.mark.parametrize("bad", ["", "complete", "provisional", "PENDING", "api; DROP TABLE x"])
async def test_set_state_unknown_state_raises(store: ActivityStore, db, bad: str) -> None:
    """An unknown state raises ValueError and writes nothing."""
    with pytest.raises(ValueError):
        await store.set_state("c1", bad)
    assert await store.get_connection("c1") is None
    assert await count(db, "connections") == 0


async def test_set_state_unknown_state_does_not_change_existing(
    store: ActivityStore,
) -> None:
    """A rejected state leaves an existing row untouched."""
    await store.set_state("c1", "recording", has_api=True)
    with pytest.raises(ValueError):
        await store.set_state("c1", "bogus")
    conn = await store.get_connection("c1")
    assert (conn.state, conn.has_api) == ("recording", True)


async def test_set_state_bumps_last_seen(store: ActivityStore, db) -> None:
    """set_state refreshes last_seen_at."""
    await store.set_state("c1", "pending")
    old = await seconds_ago(db, 3600)
    await set_connection_times(db, "c1", last_seen=old)
    await store.set_state("c1", "pending")
    assert (await store.get_connection("c1")).last_seen_at > old


# ---------------------------------------------------------------------------
# expire_pending
# ---------------------------------------------------------------------------


async def test_expire_pending_expires_idle_pending(store: ActivityStore, db) -> None:
    """A pending connection idle past the window becomes error and is returned."""
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    await set_connection_times(db, "c1", last_seen=await seconds_ago(db, 120))

    expired = await store.expire_pending(60)

    assert [c.conn_id for c in expired] == ["c1"]
    assert expired[0].state == "error"
    assert expired[0].resource_address == CLUSTER
    assert expired[0].username == USERNAME
    assert (await store.get_connection("c1")).state == "error"


async def test_expire_pending_keeps_recent_pending(store: ActivityStore, db) -> None:
    """A pending connection seen within the window is not expired."""
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    await set_connection_times(db, "c1", last_seen=await seconds_ago(db, 30))

    assert await store.expire_pending(60) == []
    assert (await store.get_connection("c1")).state == "pending"


async def test_expire_pending_boundary(store: ActivityStore, db) -> None:
    """Just past the window expires; just inside does not (margins avoid clock races)."""
    await store.upsert_connection_start("past", None, None, None, None)
    await store.upsert_connection_start("inside", None, None, None, None)
    await set_connection_times(db, "past", last_seen=await seconds_ago(db, 65))
    await set_connection_times(db, "inside", last_seen=await seconds_ago(db, 55))

    expired = await store.expire_pending(60)

    assert [c.conn_id for c in expired] == ["past"]
    assert (await store.get_connection("inside")).state == "pending"


async def test_expire_pending_uses_last_seen_not_created(store: ActivityStore, db) -> None:
    """An old connection recently touched (last_seen_at fresh) is not expired."""
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    await set_connection_times(
        db, "c1", created=await seconds_ago(db, 7200), last_seen=await seconds_ago(db, 5)
    )
    assert await store.expire_pending(60) == []


async def test_expire_pending_refreshed_by_start_line(store: ActivityStore, db) -> None:
    """Touching a stale pending connection (start redelivery) rescues it from expiry."""
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    await set_connection_times(db, "c1", last_seen=await seconds_ago(db, 600))
    await store.upsert_connection_start("c1", USER_ID, USERNAME, CLUSTER, T0)
    assert await store.expire_pending(60) == []


async def test_expire_pending_ignores_non_pending_states(store: ActivityStore, db) -> None:
    """Only pending connections expire; recording/api/error rows are left alone."""
    for conn_id, state in (("rec", "recording"), ("api", "api"), ("err", "error")):
        await store.set_state(conn_id, state)
        await set_connection_times(db, conn_id, last_seen=await seconds_ago(db, 9999))

    assert await store.expire_pending(60) == []
    assert (await store.get_connection("rec")).state == "recording"
    assert (await store.get_connection("api")).state == "api"
    assert (await store.get_connection("err")).state == "error"


async def test_expire_pending_is_idempotent(store: ActivityStore, db) -> None:
    """A second sweep returns nothing: expired rows are already error."""
    await store.upsert_connection_start("c1", None, None, None, None)
    await set_connection_times(db, "c1", last_seen=await seconds_ago(db, 600))
    assert len(await store.expire_pending(60)) == 1
    assert await store.expire_pending(60) == []


async def test_expire_pending_returns_oldest_first(store: ActivityStore, db) -> None:
    """Expired rows are returned ordered by last_seen_at ascending."""
    for conn_id, age in (("mid", 300), ("oldest", 900), ("newest", 120)):
        await store.upsert_connection_start(conn_id, None, None, None, None)
        await set_connection_times(db, conn_id, last_seen=await seconds_ago(db, age))

    expired = await store.expire_pending(60)
    assert [c.conn_id for c in expired] == ["oldest", "mid", "newest"]
    assert all(c.state == "error" for c in expired)


async def test_expire_pending_zero_window_expires_older_than_now(
    store: ActivityStore, db
) -> None:
    """A zero window expires anything last seen before this second."""
    await store.upsert_connection_start("c1", None, None, None, None)
    await set_connection_times(db, "c1", last_seen=await seconds_ago(db, 5))
    assert [c.conn_id for c in await store.expire_pending(0)] == ["c1"]


async def test_expire_pending_negative_window_clamped(store: ActivityStore, db) -> None:
    """A negative window is clamped to zero rather than producing a future cutoff."""
    await store.upsert_connection_start("c1", None, None, None, None)
    await set_connection_times(db, "c1", last_seen=await seconds_ago(db, 5))
    assert [c.conn_id for c in await store.expire_pending(-30)] == ["c1"]


# ---------------------------------------------------------------------------
# requests_for_system
# ---------------------------------------------------------------------------


async def test_requests_for_system_filters_by_cluster(store: ActivityStore) -> None:
    """Only the requested cluster's requests are returned."""
    await add_request(store, "a1", resource_address="cluster-a")
    await add_request(store, "b1", resource_address="cluster-b")
    got = await store.requests_for_system("cluster-a", T0, T3)
    assert [r.request_id for r in got] == ["a1"]


async def test_requests_for_system_null_bucket(store: ActivityStore) -> None:
    """None selects the unknown-cluster bucket only, not named clusters."""
    await add_request(store, "known", resource_address=CLUSTER)
    await add_request(store, "unknown", resource_address=None, requested_at=T1)
    got = await store.requests_for_system(None, T0, T3)
    assert [r.request_id for r in got] == ["unknown"]


async def test_requests_for_system_window_is_half_open(store: ActivityStore) -> None:
    """since is inclusive, until is exclusive."""
    await add_request(store, "at-since", requested_at=T0)
    await add_request(store, "inside", requested_at=T1)
    await add_request(store, "at-until", requested_at=T2)

    got = await store.requests_for_system(CLUSTER, T0, T2)
    assert [r.request_id for r in got] == ["at-since", "inside"]


async def test_requests_for_system_adjacent_windows_do_not_repeat(
    store: ActivityStore,
) -> None:
    """until of one page == since of the next: every request appears exactly once."""
    for i, ts in enumerate((T0, T1, T2, T3)):
        await add_request(store, f"r{i}", requested_at=ts)

    first = await store.requests_for_system(CLUSTER, T0, T2)
    second = await store.requests_for_system(CLUSTER, T2, "2026-10-01T10:00:10.000Z")
    ids = [r.request_id for r in first + second]
    assert sorted(ids) == ["r0", "r1", "r2", "r3"]
    assert len(set(ids)) == 4


async def test_requests_for_system_orders_by_user_key_then_time(
    store: ActivityStore,
) -> None:
    """Rows are ordered user_key, requested_at (group_activity's requirement)."""
    await add_request(store, "b-late", user_id="b-user", username=None, requested_at=T2)
    await add_request(store, "a-late", user_id="a-user", username=None, requested_at=T2)
    await add_request(store, "b-early", user_id="b-user", username=None, requested_at=T0)
    await add_request(store, "a-early", user_id="a-user", username=None, requested_at=T1)

    got = await store.requests_for_system(CLUSTER, T0, T3)
    assert [r.request_id for r in got] == ["a-early", "a-late", "b-early", "b-late"]


async def test_requests_for_system_limit(store: ActivityStore) -> None:
    """limit caps the row count; a result of exactly limit rows signals truncation."""
    for i in range(5):
        await add_request(store, f"r{i}", requested_at=f"2026-10-01T10:00:0{i}.000Z")
    got = await store.requests_for_system(CLUSTER, T0, "2026-10-01T11:00:00.000Z", limit=3)
    assert [r.request_id for r in got] == ["r0", "r1", "r2"]


async def test_requests_for_system_empty_window(store: ActivityStore) -> None:
    """A window containing nothing returns an empty list."""
    await add_request(store, "r1", requested_at=T0)
    assert await store.requests_for_system(CLUSTER, T1, T3) == []
    assert await store.requests_for_system("no-such-cluster", T0, T3) == []


# ---------------------------------------------------------------------------
# bound normalization (seconds-only Z input and friends)
# ---------------------------------------------------------------------------


async def test_since_seconds_only_z_includes_exact_boundary_request(
    store: ActivityStore,
) -> None:
    """since='...:00Z' must include a request stored at '...:00.000Z'.

    Compared as raw strings, '...:00.000Z' < '...:00Z' ('.' sorts before 'Z') and
    the boundary row would be wrongly excluded; normalization prevents that.
    """
    await add_request(store, "boundary", requested_at="2026-10-01T10:00:00.000Z")
    got = await store.requests_for_system(CLUSTER, "2026-10-01T10:00:00Z", T3)
    assert [r.request_id for r in got] == ["boundary"]


async def test_until_seconds_only_z_excludes_exact_boundary_request(
    store: ActivityStore,
) -> None:
    """until='...:01Z' must exclude a request stored at '...:01.000Z' (half-open)."""
    await add_request(store, "before", requested_at="2026-10-01T10:00:00.999Z")
    await add_request(store, "boundary", requested_at="2026-10-01T10:00:01.000Z")
    got = await store.requests_for_system(CLUSTER, T0, "2026-10-01T10:00:01Z")
    assert [r.request_id for r in got] == ["before"]


async def test_bounds_accept_offset_and_datetime_forms(store: ActivityStore) -> None:
    """+00:00 strings, aware non-UTC datetimes and naive datetimes all bound correctly."""
    await add_request(store, "r1", requested_at="2026-10-01T10:00:01.000Z")

    as_offset = await store.requests_for_system(
        CLUSTER, "2026-10-01T10:00:01+00:00", "2026-10-01T10:00:02+00:00"
    )
    plus_two = timezone(timedelta(hours=2))
    as_aware = await store.requests_for_system(
        CLUSTER,
        datetime(2026, 10, 1, 12, 0, 1, tzinfo=plus_two),
        datetime(2026, 10, 1, 12, 0, 2, tzinfo=plus_two),
    )
    as_naive = await store.requests_for_system(
        CLUSTER, datetime(2026, 10, 1, 10, 0, 1), datetime(2026, 10, 1, 10, 0, 2)
    )
    assert [r.request_id for r in as_offset] == ["r1"]
    assert [r.request_id for r in as_aware] == ["r1"]
    assert [r.request_id for r in as_naive] == ["r1"]


async def test_bounds_truncate_microseconds(store: ActivityStore) -> None:
    """A microsecond bound is truncated to milliseconds before comparison."""
    await add_request(store, "r1", requested_at="2026-10-01T10:00:01.123Z")
    got = await store.requests_for_system(
        CLUSTER, "2026-10-01T10:00:01.123999Z", "2026-10-01T10:00:02Z"
    )
    assert [r.request_id for r in got] == ["r1"]


async def test_invalid_bound_raises_value_error(store: ActivityStore) -> None:
    """A non-ISO string bound raises ValueError from every window query."""
    with pytest.raises(ValueError):
        await store.requests_for_system(CLUSTER, "garbage", T3)
    with pytest.raises(ValueError):
        await store.requests_for_system(CLUSTER, T0, "garbage")
    with pytest.raises(ValueError):
        await store.requests_in_bounds(CLUSTER, USER_ID, "garbage", T3)
    with pytest.raises(ValueError):
        await store.purge_before("garbage")


async def test_bound_is_bound_parameter_not_sql(store: ActivityStore, db) -> None:
    """A hostile string bound is rejected as invalid time, never executed as SQL."""
    await add_request(store, "r1")
    with pytest.raises(ValueError):
        await store.requests_for_system(CLUSTER, "x'; DROP TABLE api_requests; --", T3)
    assert await count(db, "api_requests") == 1


# ---------------------------------------------------------------------------
# requests_in_bounds
# ---------------------------------------------------------------------------


async def test_requests_in_bounds_inclusive(store: ActivityStore) -> None:
    """Both bounds are inclusive and results are ordered by requested_at."""
    await add_request(store, "before", requested_at="2026-10-01T09:59:59.999Z")
    await add_request(store, "at-from", requested_at=T1)
    await add_request(store, "middle", requested_at="2026-10-01T10:00:02.000Z")
    await add_request(store, "at-to", requested_at=T2)
    await add_request(store, "after", requested_at="2026-10-01T10:00:02.501Z")

    got = await store.requests_in_bounds(CLUSTER, USER_ID, T1, T2)
    assert [r.request_id for r in got] == ["at-from", "middle", "at-to"]


async def test_requests_in_bounds_seconds_only_z(store: ActivityStore) -> None:
    """Seconds-only Z bounds are normalized: the exact-boundary rows are included."""
    await add_request(store, "at-from", requested_at="2026-10-01T10:00:01.000Z")
    await add_request(store, "at-to", requested_at="2026-10-01T10:00:02.000Z")
    got = await store.requests_in_bounds(
        CLUSTER, USER_ID, "2026-10-01T10:00:01Z", "2026-10-01T10:00:02Z"
    )
    assert [r.request_id for r in got] == ["at-from", "at-to"]


async def test_requests_in_bounds_filters_user_and_cluster(store: ActivityStore) -> None:
    """Only the given user_key on the given cluster is returned."""
    await add_request(store, "mine", user_id="u1", username=None)
    await add_request(store, "other-user", user_id="u2", username=None)
    await add_request(store, "other-cluster", user_id="u1", username=None, resource_address="x")

    got = await store.requests_in_bounds(CLUSTER, "u1", T0, T3)
    assert [r.request_id for r in got] == ["mine"]


async def test_requests_in_bounds_null_user_bucket(store: ActivityStore) -> None:
    """user_key=None matches only requests with no identity."""
    await add_request(store, "anon", user_id=None, username=None)
    await add_request(store, "named", user_id="u1", username=None, requested_at=T1)
    got = await store.requests_in_bounds(CLUSTER, None, T0, T3)
    assert [r.request_id for r in got] == ["anon"]


async def test_requests_in_bounds_null_cluster_bucket(store: ActivityStore) -> None:
    """resource_address=None matches only the unknown-cluster bucket."""
    await add_request(store, "unknown", resource_address=None)
    await add_request(store, "known", resource_address=CLUSTER, requested_at=T1)
    got = await store.requests_in_bounds(None, USER_ID, T0, T3)
    assert [r.request_id for r in got] == ["unknown"]


async def test_requests_in_bounds_limit(store: ActivityStore) -> None:
    """limit caps the row count, keeping the earliest requests."""
    for i in range(4):
        await add_request(store, f"r{i}", requested_at=f"2026-10-01T10:00:0{i}.000Z")
    got = await store.requests_in_bounds(CLUSTER, USER_ID, T0, T3, limit=2)
    assert [r.request_id for r in got] == ["r0", "r1"]


async def test_requests_in_bounds_ties_ordered_by_request_id(store: ActivityStore) -> None:
    """Requests with an identical timestamp have a deterministic order."""
    for rid in ("rb", "ra", "rc"):
        await add_request(store, rid, requested_at=T1)
    got = await store.requests_in_bounds(CLUSTER, USER_ID, T1, T1)
    assert [r.request_id for r in got] == ["ra", "rb", "rc"]


# ---------------------------------------------------------------------------
# recordings_for_requests
# ---------------------------------------------------------------------------


async def test_recordings_for_requests_maps_by_request_id(
    store: ActivityStore, repo: SessionRepository
) -> None:
    """An audit request_id resolves to the recording session's conn_id."""
    await repo.add_chunk_meta("rec-conn-B", USERNAME, T0, request_id="R")
    assert await store.recordings_for_requests(["R"]) == {"R": "rec-conn-B"}


async def test_recordings_for_requests_two_connection_exec_never_joins_on_conn_id(
    store: ActivityStore, repo: SessionRepository
) -> None:
    """The exec audit line on conn A links to the recording on conn B via request_id.

    One exec run spans two connections; a conn_id join would link the wrong (or no)
    session. Here a decoy session on conn A carries a different request_id.
    """
    await add_request(store, "R", conn_id="conn-A", url="/api/v1/namespaces/d/pods/w/exec")
    await repo.add_chunk_meta("conn-B", USERNAME, T0, request_id="R")  # the exec WebSocket
    await repo.add_chunk_meta("conn-A", USERNAME, T0, request_id="other")  # decoy on audit conn

    assert await store.recordings_for_requests(["R"]) == {"R": "conn-B"}


async def test_recordings_for_requests_conn_id_equal_to_request_id_not_matched(
    store: ActivityStore, repo: SessionRepository
) -> None:
    """A session whose conn_id happens to equal the request_id is not a match."""
    await repo.add_chunk_meta("R", USERNAME, T0, request_id=None)  # conn_id 'R', no request_id
    assert await store.recordings_for_requests(["R"]) == {}


async def test_recordings_for_requests_omits_unmatched_and_null(
    store: ActivityStore, repo: SessionRepository
) -> None:
    """Ids with no recording are absent; SSH sessions (NULL request_id) never match."""
    await repo.add_chunk_meta("ssh-conn", USERNAME, T0)  # request_id NULL
    await repo.add_chunk_meta("k8s-conn", USERNAME, T0, request_id="has-rec")
    got = await store.recordings_for_requests(["has-rec", "no-rec"])
    assert got == {"has-rec": "k8s-conn"}


async def test_recordings_for_requests_empty_input(store: ActivityStore) -> None:
    """No ids -> empty mapping."""
    assert await store.recordings_for_requests([]) == {}


async def test_recordings_for_requests_duplicate_input_ids(
    store: ActivityStore, repo: SessionRepository
) -> None:
    """Duplicate input ids resolve once."""
    await repo.add_chunk_meta("c1", USERNAME, T0, request_id="R")
    assert await store.recordings_for_requests(["R", "R", "R"]) == {"R": "c1"}


async def test_recordings_for_requests_earliest_started_wins(
    store: ActivityStore, db
) -> None:
    """If two sessions share a request_id, the earliest-started one wins."""
    await insert_session_row(db, "late", "R", started_at="2026-10-01T10:05:00Z")
    await insert_session_row(db, "early", "R", started_at="2026-10-01T10:00:00Z")
    await insert_session_row(db, "mid", "R", started_at="2026-10-01T10:02:00Z")
    assert await store.recordings_for_requests(["R"]) == {"R": "early"}


async def test_recordings_for_requests_null_started_at_uses_created_at(
    store: ActivityStore, db
) -> None:
    """A NULL started_at falls back to created_at for the earliest-wins ordering."""
    await insert_session_row(db, "has-start", "R", started_at="2026-10-01T10:00:00Z")
    await insert_session_row(
        db, "no-start-older-created", "R", started_at=None, created_at="2026-10-01 09:00:00"
    )
    assert await store.recordings_for_requests(["R"]) == {"R": "no-start-older-created"}


async def test_recordings_for_requests_tie_broken_by_conn_id(store: ActivityStore, db) -> None:
    """Identical start times resolve deterministically by conn_id."""
    for conn_id in ("zz", "aa", "mm"):
        await insert_session_row(db, conn_id, "R", started_at="2026-10-01T10:00:00Z")
    assert await store.recordings_for_requests(["R"]) == {"R": "aa"}


async def test_recordings_for_requests_over_1000_ids(store: ActivityStore, db) -> None:
    """More than 1000 ids (three 500-id chunks) resolve, including at chunk boundaries."""
    ids = [f"req-{i:05d}" for i in range(1250)]
    matched_idx = [0, 1, 499, 500, 501, 999, 1000, 1001, 1249]
    for i in matched_idx:
        await db.execute(
            "INSERT INTO sessions (conn_id, request_id, status, started_at) "
            "VALUES (?, ?, 'complete', ?)",
            (f"conn-{i}", ids[i], "2026-10-01T10:00:00Z"),
        )
    await db.commit()

    got = await store.recordings_for_requests(ids)

    assert got == {ids[i]: f"conn-{i}" for i in matched_idx}


async def test_recordings_for_requests_over_1000_ids_with_duplicates_across_chunks(
    store: ActivityStore, db
) -> None:
    """Duplicates in a >1000 id input are collapsed and do not break chunking."""
    ids = [f"req-{i:05d}" for i in range(1100)]
    await insert_session_row(db, "only", ids[700], started_at="2026-10-01T10:00:00Z")
    got = await store.recordings_for_requests(ids + ids)
    assert got == {ids[700]: "only"}


# ---------------------------------------------------------------------------
# purge_before
# ---------------------------------------------------------------------------


async def test_purge_before_deletes_old_requests_only(store: ActivityStore) -> None:
    """Requests strictly older than the cutoff go; a request at the cutoff stays."""
    cutoff = "2026-10-01T10:00:02.000Z"
    await add_request(store, "old1", requested_at=T0)
    await add_request(store, "old2", requested_at="2026-10-01T10:00:01.999Z")
    await add_request(store, "at-cutoff", requested_at=cutoff)
    await add_request(store, "new", requested_at=T3)

    api_deleted, conns_deleted = await store.purge_before(cutoff)

    assert (api_deleted, conns_deleted) == (2, 0)
    left = await store.requests_for_system(CLUSTER, T0, "2026-10-02T00:00:00Z")
    assert sorted(r.request_id for r in left) == ["at-cutoff", "new"]


async def test_purge_before_cascades_findings(store: ActivityStore, db) -> None:
    """Findings of purged requests are deleted; findings of kept requests remain."""
    await add_request(store, "old", requested_at=T0)
    await add_request(store, "new", requested_at=T3)
    await store.insert_api_findings("old", [make_finding("a"), make_finding("b")])
    await store.insert_api_findings("new", [make_finding("c")])

    await store.purge_before(T2)

    assert await count(db, "api_requests") == 1
    remaining = await store.findings_for_requests(["old", "new"])
    assert set(remaining) == {"new"}
    assert await count(db, "api_findings") == 1


async def test_purge_before_cascades_findings_with_foreign_keys_off(
    store: ActivityStore, db
) -> None:
    """The purge removes findings explicitly, so it is correct even without FK enforcement."""
    await add_request(store, "old", requested_at=T0)
    await store.insert_api_findings("old", [make_finding("a")])
    await db.execute("PRAGMA foreign_keys=OFF")
    assert (await rows(db, "PRAGMA foreign_keys"))[0][0] == 0

    await store.purge_before(T2)

    assert await count(db, "api_requests") == 0
    assert await count(db, "api_findings") == 0


async def test_purge_before_connections_by_created_at(store: ActivityStore, db) -> None:
    """Connections are purged by created_at against the same cutoff."""
    for conn_id in ("old", "boundary", "new"):
        await store.upsert_connection_start(conn_id, None, None, None, None)
    await set_connection_times(db, "old", created="2026-09-30 23:59:59")
    await set_connection_times(db, "boundary", created="2026-10-01 00:00:00")
    await set_connection_times(db, "new", created="2026-10-02 00:00:00")

    api_deleted, conns_deleted = await store.purge_before("2026-10-01T00:00:00Z")

    assert (api_deleted, conns_deleted) == (0, 1)
    assert await store.get_connection("old") is None
    assert await store.get_connection("boundary") is not None
    assert await store.get_connection("new") is not None


async def test_purge_before_counts_both_tables(store: ActivityStore, db) -> None:
    """The returned tuple is (api_requests_deleted, connections_deleted)."""
    for i in range(3):
        await add_request(store, f"old{i}", requested_at=f"2026-09-01T00:00:0{i}.000Z")
    await add_request(store, "keep", requested_at="2026-10-05T00:00:00.000Z")
    for conn_id in ("c-old1", "c-old2"):
        await store.upsert_connection_start(conn_id, None, None, None, None)
        await set_connection_times(db, conn_id, created="2026-09-01 00:00:00")
    await store.upsert_connection_start("c-new", None, None, None, None)

    assert await store.purge_before("2026-10-01T00:00:00Z") == (3, 2)
    assert await count(db, "api_requests") == 1
    assert await count(db, "connections") == 1


async def test_purge_before_nothing_to_delete(store: ActivityStore) -> None:
    """An empty database (or an old cutoff) purges nothing and returns zeros."""
    assert await store.purge_before("2026-10-01T00:00:00Z") == (0, 0)
    await add_request(store, "r1", requested_at=T0)
    await store.upsert_connection_start("c1", None, None, None, None)
    assert await store.purge_before("2000-01-01T00:00:00Z") == (0, 0)


async def test_purge_before_leaves_sessions_alone(
    store: ActivityStore, repo: SessionRepository, db
) -> None:
    """The activity purge never touches recordings (retention.py handles sessions)."""
    await repo.add_chunk_meta("rec", USERNAME, T0, request_id="R")
    await add_request(store, "R", requested_at=T0)
    await store.purge_before("2030-01-01T00:00:00Z")
    assert await count(db, "sessions") == 1


async def test_purge_before_accepts_datetime_cutoff(store: ActivityStore) -> None:
    """A datetime cutoff is normalized like a string one."""
    await add_request(store, "old", requested_at=T0)
    await add_request(store, "new", requested_at=T3)
    deleted, _ = await store.purge_before(datetime(2026, 10, 1, 10, 0, 2, tzinfo=UTC))
    assert deleted == 1


# ---------------------------------------------------------------------------
# insert_request_with_findings: request + findings in one transaction (P1)
# ---------------------------------------------------------------------------


async def test_insert_request_with_findings_stores_both(store: ActivityStore, db) -> None:
    """A new request and its findings land together; the call returns True."""
    findings = [make_finding("kube-delete"), make_finding("kube-exec")]
    assert await store.insert_request_with_findings(make_req("r1"), CLUSTER, findings) is True
    assert await count(db, "api_requests") == 1
    got = await store.findings_for_requests(["r1"])
    assert [f.rule_id for f in got["r1"]] == ["kube-delete", "kube-exec"]


async def test_insert_request_with_findings_redelivery_adds_nothing(
    store: ActivityStore, db
) -> None:
    """A redelivered request_id returns False and writes no request or findings."""
    findings = [make_finding("kube-delete")]
    assert await store.insert_request_with_findings(make_req("dup"), CLUSTER, findings)
    for _ in range(2):
        assert (
            await store.insert_request_with_findings(make_req("dup"), CLUSTER, findings)
            is False
        )
    assert await count(db, "api_requests") == 1
    assert await count(db, "api_findings") == 1


async def test_insert_request_with_findings_empty_findings(store: ActivityStore, db) -> None:
    """No findings stores the request alone (what insert_request does)."""
    assert await store.insert_request_with_findings(make_req("r1"), CLUSTER, []) is True
    assert await count(db, "api_requests") == 1
    assert await count(db, "api_findings") == 0


async def test_insert_request_with_findings_rolls_back_as_a_unit(
    store: ActivityStore, db, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure after the request insert, inside the transaction, rolls back the
    request too, so a redelivery is not a dedup hit and stores both."""
    findings = [make_finding("kube-delete")]

    async def boom(request_id: str, findings_arg) -> None:
        raise RuntimeError("simulated failure between request and findings")

    monkeypatch.setattr(store, "_insert_finding_rows", boom)
    with pytest.raises(RuntimeError):
        await store.insert_request_with_findings(make_req("r1"), CLUSTER, findings)
    assert await count(db, "api_requests") == 0
    assert await count(db, "api_findings") == 0

    monkeypatch.undo()
    assert await store.insert_request_with_findings(make_req("r1"), CLUSTER, findings) is True
    assert await count(db, "api_requests") == 1
    assert await count(db, "api_findings") == 1


async def test_insert_request_with_findings_db_error_rolls_back(
    store: ActivityStore, db
) -> None:
    """A real DB constraint failure on a finding rolls back the request row too."""
    bad = Finding(
        rule_id="r", category="kube-api", severity=None, label="l", offset_seconds=None  # type: ignore[arg-type]
    )
    with pytest.raises(aiosqlite.IntegrityError):
        await store.insert_request_with_findings(make_req("r1"), CLUSTER, [bad])
    assert await count(db, "api_requests") == 0
    assert await count(db, "api_findings") == 0
    # The connection is clean afterwards: a later write commits normally.
    assert await store.insert_request(make_req("r2"), CLUSTER) is True
    assert await count(db, "api_requests") == 1


# ---------------------------------------------------------------------------
# purge_before: future-dated rows and year zero-padding (F5)
# ---------------------------------------------------------------------------


async def _set_request_created_at(db, request_id: str, created_at: str) -> None:
    """Override api_requests.created_at (server insert time) for one row."""
    await db.execute(
        "UPDATE api_requests SET created_at = ? WHERE request_id = ?", (created_at, request_id)
    )
    await db.commit()


async def test_purge_before_removes_future_dated_request_by_created_at(
    store: ActivityStore, db
) -> None:
    """A request the Gateway dated 9999 is purged once its server created_at is old,
    and its findings go with it."""
    await add_request(store, "future", requested_at="9999-01-01T00:00:00.000Z")
    await store.insert_api_findings("future", [make_finding("a")])
    await _set_request_created_at(db, "future", "2026-09-01 00:00:00")

    api_deleted, _ = await store.purge_before("2026-10-01T00:00:00Z")

    assert api_deleted == 1
    assert await count(db, "api_requests") == 0
    assert await count(db, "api_findings") == 0


async def test_purge_before_keeps_future_dated_request_with_recent_created_at(
    store: ActivityStore, db
) -> None:
    """Either clock being old purges; a future-dated row inserted recently stays."""
    await add_request(store, "future", requested_at="9999-01-01T00:00:00.000Z")
    await store.insert_api_findings("future", [make_finding("a")])
    await _set_request_created_at(db, "future", "2026-10-02 00:00:00")

    assert await store.purge_before("2026-10-01T00:00:00Z") == (0, 0)
    assert await count(db, "api_requests") == 1
    assert await count(db, "api_findings") == 1


async def test_purge_before_connection_with_null_created_at_uses_last_seen(
    store: ActivityStore, db
) -> None:
    """A connection with no created_at is aged on last_seen_at instead of living forever."""
    await store.upsert_connection_start("no-created", None, None, None, None)
    await store.upsert_connection_start("no-created-recent", None, None, None, None)
    await db.execute("UPDATE connections SET created_at = NULL")
    await set_connection_times(db, "no-created", last_seen="2026-09-01 00:00:00")
    await set_connection_times(db, "no-created-recent", last_seen="2026-10-02 00:00:00")

    _, conns_deleted = await store.purge_before("2026-10-01T00:00:00Z")

    assert conns_deleted == 1
    assert await store.get_connection("no-created") is None
    assert await store.get_connection("no-created-recent") is not None


def test_format_zero_pads_years_below_1000() -> None:
    """Years below 1000 are zero-padded to four digits (glibc %Y does not pad)."""
    assert (
        to_requested_at_format(datetime(999, 1, 2, 3, 4, 5, 6000, tzinfo=UTC))
        == "0999-01-02T03:04:05.006Z"
    )
    assert to_requested_at_format(datetime(1, 1, 1)) == "0001-01-01T00:00:00.000Z"


async def test_purge_before_early_year_cutoff_is_valid(store: ActivityStore, db) -> None:
    """A year-<1000 cutoff compares correctly: nothing newer is purged."""
    await add_request(store, "r1", requested_at=T0)
    await store.upsert_connection_start("c1", None, None, None, None)
    assert await store.purge_before(datetime(999, 1, 1, tzinfo=UTC)) == (0, 0)
    assert await count(db, "api_requests") == 1
