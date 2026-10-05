"""Tests for the pure kubectl activity grouping in ``gatorcast.pipeline.activity``.

Covers spec §7 / §13: path-only discovery, activity-session splitting (gap, max
window, per user), command grouping by ``Kubectl-Session`` with the ``conn_id``
fallback, the two-connection exec forming one command linked to its recording by
``request_id``, primary-request selection, and label fallbacks.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from itertools import count

import pytest

from gatorcast.pipeline.activity import (
    UNKNOWN_CLIENT_LABEL,
    ActivitySession,
    Command,
    group_activity,
    group_commands,
    is_discovery,
    request_path,
)
from gatorcast.store.activity import ApiRequestRow

CLUSTER = "k8s.example.internal"
BASE = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)
_ids = count(1)


def _ts(seconds: float) -> str:
    """Stored ``requested_at`` for ``BASE + seconds`` (millisecond ``Z`` format)."""
    dt = BASE + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _row(
    at: float,
    *,
    method: str = "GET",
    url: str = "/api/v1/namespaces/default/pods",
    conn_id: str = "conn-a",
    user_key: str | None = "user-1",
    username: str | None = "alice@example.com",
    kubectl_session: str | None = "ks-1",
    kubectl_command: str | None = "kubectl get",
    user_agent: str | None = "kubectl/v1.30.0 (linux/amd64) kubernetes/abcdef",
    status_code: int | None = 200,
    request_id: str | None = None,
) -> ApiRequestRow:
    """Build an ``ApiRequestRow`` ``at`` seconds after ``BASE``."""
    return ApiRequestRow(
        request_id=request_id or f"req-{next(_ids)}",
        conn_id=conn_id,
        resource_address=CLUSTER,
        user_key=user_key,
        user_id=user_key,
        username=username,
        requested_at=_ts(at),
        method=method,
        url=url,
        status_code=status_code,
        outcome="completed",
        kubectl_command=kubectl_command,
        kubectl_session=kubectl_session,
        user_agent=user_agent,
        created_at=None,
    )


@dataclass(frozen=True)
class _Finding:
    """Minimal stand-in for ``ApiFindingRow`` (severity + label)."""

    severity: str
    label: str


# --- discovery -----------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "/api",
        "/api/",
        "/api?timeout=32s",
        "/apis",
        "/apis?timeout=32s",
        "/api/v1",
        "/api/v1?timeout=32s",
        "/apis/apps",
        "/apis/apps/v1",
        "/apis/apps/v1/?timeout=32s",
        "/openapi/v2",
        "/openapi/v3/apis/apps/v1?hash=abc",
        "/openapi",
        "/version",
        "/version?timeout=32s",
    ],
)
def test_is_discovery_true(url: str) -> None:
    """GETs on discovery paths are discovery, with or without a query string."""
    assert is_discovery("GET", url) is True


@pytest.mark.parametrize(
    "url",
    [
        "/api/v1/pods?limit=500",
        "/api/v1/namespaces/default/pods",
        "/apis/apps/v1/namespaces/default/deployments/web",
        "/apis/apps/v1/deployments",
        "/healthz",
        "/versions",
        "/apiserver",
        "/api/v2/foo",
        # A discovery-looking string in the query never makes a request discovery.
        "/api/v1/namespaces?next=/api",
    ],
)
def test_is_discovery_false(url: str) -> None:
    """Resource paths are not discovery even when the query looks like one."""
    assert is_discovery("GET", url) is False


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD"])
def test_is_discovery_requires_get(method: str) -> None:
    """Only GET requests can be discovery."""
    assert is_discovery(method, "/api") is False


def test_is_discovery_method_case_insensitive() -> None:
    """The method comparison ignores case."""
    assert is_discovery("get", "/apis?timeout=32s") is True


def test_request_path_strips_query() -> None:
    """``request_path`` keeps everything before the first ``?``."""
    assert request_path("/api/v1/pods?limit=500&x=?y") == "/api/v1/pods"
    assert request_path("/api/v1/pods") == "/api/v1/pods"


# --- group_activity ------------------------------------------------------------


def test_group_activity_empty() -> None:
    """No rows → no sessions."""
    assert group_activity([], 900, 14400) == []


def test_group_activity_single_session_fields() -> None:
    """Rows within the gap form one session with correct bounds and counts."""
    rows = [
        _row(0, url="/api?timeout=32s", kubectl_session="ks-1"),
        _row(5, kubectl_session="ks-1"),
        _row(60, kubectl_session="ks-2", conn_id="conn-b"),
    ]
    [s] = group_activity(rows, 900, 14400)
    assert isinstance(s, ActivitySession)
    assert s.user_key == "user-1"
    assert s.username == "alice@example.com"
    assert s.resource_address == CLUSTER
    assert s.started_at == rows[0].requested_at
    assert s.ended_at == rows[-1].requested_at
    assert s.duration_seconds == 60
    assert s.request_count == 3
    assert s.command_count == 2
    assert s.request_ids == tuple(r.request_id for r in rows)
    assert s.finding_count == 0
    assert s.max_severity is None
    assert s.recording_count == 0


def test_group_activity_splits_on_gap() -> None:
    """A gap greater than ``gap_s`` starts a new session; equal to it does not."""
    rows = [_row(0), _row(100), _row(201), _row(301)]
    sessions = group_activity(rows, 100, 14400)
    # 0→100 is exactly the gap (kept), 100→201 exceeds it (split), 201→301 kept.
    assert [s.request_count for s in sessions] == [2, 2]
    newest, oldest = sessions
    assert oldest.started_at == _ts(0) and oldest.ended_at == _ts(100)
    assert newest.started_at == _ts(201) and newest.ended_at == _ts(301)


def test_group_activity_splits_on_max_window() -> None:
    """A steady client never leaves a gap but is still capped at ``max_s``."""
    rows = [_row(t) for t in range(0, 1000, 60)]  # every minute for ~16 minutes
    sessions = group_activity(rows, 900, 300)
    # Span since session start reaching 300 s starts a new session: 0..240, 300..540, ...
    assert all(s.duration_seconds < 300 for s in sessions)
    assert sum(s.request_count for s in sessions) == len(rows)
    starts = sorted(s.started_at for s in sessions)
    assert starts == [_ts(0), _ts(300), _ts(600), _ts(900)]


def test_group_activity_max_window_boundary_is_inclusive() -> None:
    """A request exactly ``max_s`` after the session start opens a new session."""
    sessions = group_activity([_row(0), _row(299.999), _row(300)], 900, 300)
    assert sorted(s.request_count for s in sessions) == [1, 2]


def test_group_activity_splits_per_user() -> None:
    """Different users never share a session, even when interleaved in time."""
    rows = [
        _row(0, user_key="user-1"),
        _row(1, user_key="user-2", username="bob@example.com"),
        _row(2, user_key="user-1"),
        _row(3, user_key="user-2", username="bob@example.com"),
    ]
    sessions = group_activity(rows, 900, 14400)
    assert len(sessions) == 2
    by_user = {s.user_key: s for s in sessions}
    assert by_user["user-1"].request_count == 2
    assert by_user["user-2"].request_count == 2
    assert by_user["user-2"].username == "bob@example.com"


def test_group_activity_null_user_bucket() -> None:
    """Rows with no user key group together as their own bucket."""
    rows = [_row(0, user_key=None, username=None), _row(1, user_key=None, username=None)]
    [s] = group_activity(rows, 900, 14400)
    assert s.user_key is None
    assert s.username is None
    assert s.request_count == 2


def test_group_activity_sorted_newest_first() -> None:
    """Sessions come back newest first regardless of input order."""
    rows = [_row(5000), _row(0), _row(10000)]
    sessions = group_activity(rows, 900, 14400)
    assert [s.started_at for s in sessions] == [_ts(10000), _ts(5000), _ts(0)]


def test_group_activity_discovery_counts_toward_timing() -> None:
    """Discovery requests keep a session alive but are not counted as commands."""
    rows = [
        _row(0, kubectl_session="ks-1"),
        _row(800, url="/api?timeout=32s", kubectl_session="ks-2"),
        _row(1600, kubectl_session="ks-3"),
    ]
    [s] = group_activity(rows, 900, 14400)
    assert s.request_count == 3
    assert s.command_count == 2  # ks-2 is discovery-only


def test_group_activity_findings_and_recordings() -> None:
    """Finding and recording maps fill the aggregate fields."""
    r1 = _row(0)
    r2 = _row(1, method="DELETE", url="/api/v1/namespaces/default/secrets/db")
    r3 = _row(2, url="/api/v1/namespaces/default/pods/web-1/exec?container=nginx")
    findings = {
        r2.request_id: [_Finding("high", "delete"), _Finding("high", "secrets")],
        r3.request_id: [_Finding("medium", "exec")],
    }
    [s] = group_activity(
        [r1, r2, r3],
        900,
        14400,
        findings=findings,
        recordings={r3.request_id: "conn-rec", "unrelated": "conn-other"},
    )
    assert s.finding_count == 3
    assert s.max_severity == "high"
    assert s.recording_count == 1


def test_group_activity_bad_timestamp_raises() -> None:
    """A corrupt ``requested_at`` raises instead of being silently dropped."""
    bad = replace(_row(0), requested_at="not-a-time")
    with pytest.raises(ValueError):
        group_activity([bad], 900, 14400)


# --- group_commands ------------------------------------------------------------


def _exec_run() -> tuple[list[ApiRequestRow], str, str]:
    """The §13 exec run: preparatory GETs on conn A, the exec (101) on conn B.

    Returns:
        ``(rows, exec_request_id, recording_conn_id)``.
    """
    ks = "ks-exec"
    cmd = "kubectl exec"
    rows = [
        _row(0, url="/api?timeout=32s", conn_id="conn-a", kubectl_session=ks, kubectl_command=cmd),
        _row(
            0.1,
            url="/apis/apps/v1/namespaces/default/deployments/web",
            conn_id="conn-a",
            kubectl_session=ks,
            kubectl_command=cmd,
        ),
        _row(
            0.2,
            url="/api/v1/namespaces/default/pods?labelSelector=app%3Dweb",
            conn_id="conn-a",
            kubectl_session=ks,
            kubectl_command=cmd,
        ),
        _row(
            0.3,
            url=(
                "/api/v1/namespaces/default/pods/web-1/exec"
                "?container=nginx&stdin=true&stdout=true&tty=true"
            ),
            conn_id="conn-b",
            kubectl_session=ks,
            kubectl_command=cmd,
            status_code=101,
            request_id="req-exec-R",
        ),
    ]
    return rows, "req-exec-R", "conn-b"


def test_exec_spanning_two_connections_is_one_command() -> None:
    """The exec run's requests on A and B form one command linked by request_id."""
    rows, exec_rid, rec_conn = _exec_run()
    commands = group_commands(rows, {exec_rid: rec_conn})
    assert len(commands) == 1
    [c] = commands
    assert isinstance(c, Command)
    assert c.key == "ks-exec"
    assert c.kubectl_session == "ks-exec"
    assert c.conn_ids == ("conn-a", "conn-b")
    assert c.recordings == (rec_conn,)
    assert c.request_count == 4
    assert c.discovery_count == 1
    assert c.label == "kubectl exec"
    assert c.started_at == rows[0].requested_at
    assert c.ended_at == rows[-1].requested_at


def test_recording_links_only_by_request_id_never_conn_id() -> None:
    """A recording keyed by a conn_id (not a request_id) is never linked."""
    rows, _exec_rid, rec_conn = _exec_run()
    # Map keyed by conn ids, as a wrong conn_id join would produce: nothing links.
    [c] = group_commands(rows, {"conn-a": rec_conn, "conn-b": rec_conn})
    assert c.recordings == ()


def test_exec_link_absent_until_101_audit_arrives() -> None:
    """Before the exec's 101 audit line arrives, the command has no recording."""
    rows, exec_rid, rec_conn = _exec_run()
    [c] = group_commands(rows[:-1], {exec_rid: rec_conn})
    assert c.recordings == ()
    assert c.conn_ids == ("conn-a",)


def test_group_commands_by_kubectl_session() -> None:
    """Requests with the same Kubectl-Session group together across connections."""
    rows = [
        _row(0, kubectl_session="ks-1", conn_id="conn-a"),
        _row(1, kubectl_session="ks-2", conn_id="conn-a"),
        _row(2, kubectl_session="ks-1", conn_id="conn-b"),
    ]
    commands = group_commands(rows, {})
    assert [c.key for c in commands] == ["ks-1", "ks-2"]
    assert commands[0].request_count == 2
    assert commands[0].conn_ids == ("conn-a", "conn-b")


def test_group_commands_conn_fallback_only_without_header() -> None:
    """Without Kubectl-Session, requests group per connection."""
    rows = [
        _row(0, kubectl_session=None, conn_id="conn-k9s", kubectl_command=None,
             user_agent="k9s/v0.32.5 (linux/amd64)"),
        _row(1, kubectl_session=None, conn_id="conn-k9s", kubectl_command=None,
             user_agent="k9s/v0.32.5 (linux/amd64)"),
        _row(2, kubectl_session="", conn_id="conn-other"),
        _row(3, kubectl_session="ks-1", conn_id="conn-k9s"),
    ]
    commands = group_commands(rows, {})
    assert [c.key for c in commands] == ["conn:conn-k9s", "conn:conn-other", "ks-1"]
    assert commands[0].kubectl_session is None
    assert commands[0].request_count == 2
    assert commands[0].label == "k9s"
    # The header-bearing request on the same connection is its own command.
    assert commands[2].request_count == 1


def test_group_commands_session_value_cannot_collide_with_conn_key() -> None:
    """A Kubectl-Session value shaped like a fallback key stays separate."""
    rows = [
        _row(0, kubectl_session=None, conn_id="x"),
        _row(1, kubectl_session="conn:x", conn_id="y"),
    ]
    assert len(group_commands(rows, {})) == 2


def test_group_commands_first_seen_order_and_request_order() -> None:
    """Commands keep first-seen order; requests sort by requested_at."""
    rows = [
        _row(5, kubectl_session="ks-b"),
        _row(3, kubectl_session="ks-a"),
        _row(1, kubectl_session="ks-b"),
    ]
    commands = group_commands(rows, {})
    assert [c.key for c in commands] == ["ks-b", "ks-a"]
    assert [r.requested_at for r in commands[0].requests] == [_ts(1), _ts(5)]


def test_primary_prefers_mutating() -> None:
    """The first non-discovery mutating request is primary."""
    rows = [
        _row(0, url="/api?timeout=32s"),
        _row(1, url="/apis/apps/v1/namespaces/default/deployments/web"),
        _row(2, method="PATCH", url="/apis/apps/v1/namespaces/default/deployments/web"),
        _row(3, method="DELETE", url="/api/v1/namespaces/default/pods/web-1"),
    ]
    [c] = group_commands(rows, {})
    assert c.primary is rows[2]
    assert c.primary_path == "/apis/apps/v1/namespaces/default/deployments/web"


def test_primary_falls_back_to_first_non_discovery() -> None:
    """With no mutating request, the first non-discovery request is primary."""
    rows = [
        _row(0, url="/api?timeout=32s"),
        _row(1, url="/api/v1/namespaces/default/pods?limit=500"),
        _row(2, url="/api/v1/namespaces/default/services"),
    ]
    [c] = group_commands(rows, {})
    assert c.primary is rows[1]
    assert c.primary_path == "/api/v1/namespaces/default/pods"


def test_primary_falls_back_to_first_request_when_all_discovery() -> None:
    """A discovery-only command uses its first request as primary."""
    rows = [_row(0, url="/api?timeout=32s"), _row(1, url="/apis?timeout=32s")]
    [c] = group_commands(rows, {})
    assert c.primary is rows[0]
    assert c.is_discovery_only is True
    assert c.discovery_count == 2


def test_mutating_discovery_path_is_not_discovery() -> None:
    """A POST to a discovery-looking path is not discovery and can be primary."""
    rows = [_row(0, url="/api?timeout=32s"), _row(1, method="POST", url="/api")]
    [c] = group_commands(rows, {})
    assert c.primary is rows[1]
    assert c.discovery_count == 1


def test_visible_requests_hides_discovery_by_default() -> None:
    """Discovery requests are hidden unless explicitly included."""
    rows, _rid, _rec = _exec_run()
    [c] = group_commands(rows, {})
    assert len(c.visible_requests()) == 3
    assert len(c.visible_requests(include_discovery=True)) == 4
    assert all(not is_discovery(r.method, r.url) for r in c.visible_requests())


@pytest.mark.parametrize(
    ("kubectl_command", "user_agent", "expected"),
    [
        ("kubectl delete", "kubectl/v1.30.0 (linux/amd64)", "kubectl delete"),
        (None, "kubectl/v1.30.0 (linux/amd64) kubernetes/abcdef", "kubectl"),
        (None, "Go-http-client", "Go-http-client"),
        (None, "  /v1", UNKNOWN_CLIENT_LABEL),
        (None, "", UNKNOWN_CLIENT_LABEL),
        (None, None, UNKNOWN_CLIENT_LABEL),
        ("", None, UNKNOWN_CLIENT_LABEL),
    ],
)
def test_label_fallbacks(
    kubectl_command: str | None, user_agent: str | None, expected: str
) -> None:
    """Label: Kubectl-Command, else User-Agent product token, else unknown client."""
    rows = [_row(0, kubectl_command=kubectl_command, user_agent=user_agent)]
    [c] = group_commands(rows, {})
    assert c.label == expected


def test_label_uses_any_request_when_primary_lacks_header() -> None:
    """If the primary has no Kubectl-Command, another request's value is used."""
    rows = [
        _row(0, kubectl_command="kubectl apply"),
        _row(1, method="PATCH", kubectl_command=None, user_agent=None),
    ]
    [c] = group_commands(rows, {})
    assert c.primary is rows[1]
    assert c.label == "kubectl apply"


def test_group_commands_findings() -> None:
    """Finding maps fill the command's count, max severity, and distinct labels."""
    r1 = _row(0, method="DELETE", url="/api/v1/namespaces/default/secrets/db")
    r2 = _row(1, url="/api/v1/namespaces/default/secrets")
    findings = {
        r1.request_id: [_Finding("high", "delete"), _Finding("high", "secrets")],
        r2.request_id: [_Finding("high", "secrets")],
    }
    [c] = group_commands([r1, r2], {}, findings=findings)
    assert c.finding_count == 3
    assert c.max_severity == "high"
    assert c.finding_labels == ("delete", "secrets")


def test_group_commands_recordings_deduplicated() -> None:
    """Two request ids linked to the same recording yield one link."""
    r1 = _row(0, request_id="r1")
    r2 = _row(1, request_id="r2")
    [c] = group_commands([r1, r2], {"r1": "conn-rec", "r2": "conn-rec"})
    assert c.recordings == ("conn-rec",)


def test_group_commands_empty() -> None:
    """No rows → no commands."""
    assert group_commands([], {}) == []
