"""Route tests for the kubectl activity UI (Session 9, T8; spec §9 / §13).

FastAPI ``TestClient`` only (Light tier; no Playwright). Async store and pipeline
calls are driven with ``asyncio.run()`` inside the ``with TestClient`` block, after
lifespan has wired ``app.state`` (same pattern as ``test_web.py``).

The synthetic fixture ``tests/fixtures/kubectl_audit_lines.ndjson`` is fed through
``classify`` → ``Assembler.handle`` so the pages render real pipeline output:

  * connections A, B, C on ``k8s.example.internal`` for one user;
  * an exec run spanning A (discovery + preparatory GETs) and B (the recording and
    its status-101 audit line, sharing ``request_id`` R) under one Kubectl-Session;
  * a ``kubectl get`` run on C (502 then 200), one ``API request failed`` line, and
    one legacy ``path`` line with no ``request_id``.

All fixture requests fall between 10:00:01.200Z and 10:06:00.000Z on 2026-10-01,
so they form one activity session. Pages are pinned with explicit time bounds so
the tests never depend on the wall clock.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gatorcast.config import Settings
from gatorcast.main import create_app
from gatorcast.models import ApiRequest
from gatorcast.pipeline.classify import classify
from gatorcast.web import routes

FIXTURE = Path(__file__).parent / "fixtures" / "kubectl_audit_lines.ndjson"

CLUSTER = "k8s.example.internal"
USER_KEY = "VXNlcjox"
USERNAME = "user@example.com"
CONN_A = "aaaaaaaa-0000-4000-8000-000000000001"
CONN_B = "aaaaaaaa-0000-4000-8000-000000000002"
EXEC_REQUEST_ID = "22222222-2222-4222-8222-222222222222"
SPAN_FROM = "2026-10-01T10:00:01.200Z"
SPAN_TO = "2026-10-01T10:06:00.000Z"
# Pins the system page's activity window so it covers the fixture.
BEFORE = "2026-10-02T00:00:00Z"

SYSTEM_URL = f"/systems/{CLUSTER}?activity_before={BEFORE}"
ACTIVITY_URL = f"/systems/{CLUSTER}/activity?user={USER_KEY}&from={SPAN_FROM}&to={SPAN_TO}"

DISCOVERY_URL = "/api?timeout=32s"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _settings(tmp_path: Path) -> Settings:
    """Settings with syslog disabled, test auth creds, isolated data dir."""
    return Settings(
        data_dir=tmp_path,
        syslog_tcp_port=0,
        ui_auth_username="admin",
        ui_auth_password="change-me",
    )


def _auth_header(username: str = "admin", password: str = "change-me") -> dict[str, str]:
    """Build an ``Authorization: Basic`` header."""
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _feed_fixture(app) -> None:
    """Feed every fixture line through classify → Assembler.handle."""

    async def run() -> None:
        assembler = app.state.assembler
        for line in FIXTURE.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = classify(json.loads(line))
            if event is not None:
                await assembler.handle(event)

    asyncio.run(run())


def _insert_request(
    app,
    *,
    request_id: str,
    resource_address: str | None,
    requested_at: str,
    url: str = "/api/v1/namespaces/default/pods",
    method: str = "GET",
    username: str = "other@example.com",
    user_id: str | None = "VXNlcjoy",
    conn_id: str = "bbbbbbbb-0000-4000-8000-000000000001",
    kubectl_session: str | None = "5e55e55e-0000-4000-8000-0000000000ff",
) -> None:
    """Store one API request directly through the ActivityStore."""
    req = ApiRequest(
        conn_id=conn_id,
        request_id=request_id,
        requested_at=requested_at,
        user_id=user_id,
        username=username,
        method=method,
        url=url,
        status_code=200,
        kubectl_command="kubectl get",
        kubectl_session=kubectl_session,
        user_agent="kubectl/v1.33.0 (linux/amd64)",
    )
    asyncio.run(app.state.activity.insert_request(req, resource_address))


def _capture_contexts(monkeypatch) -> dict[str, dict]:
    """Record each rendered template's context, keyed by template name.

    Wraps ``routes.templates.TemplateResponse`` so tests can assert on the exact
    template context contract as well as on the rendered HTML.
    """
    captured: dict[str, dict] = {}
    original = routes.templates.TemplateResponse

    def spy(request, name, context, *args, **kwargs):
        captured[name] = context
        return original(request, name, context, *args, **kwargs)

    monkeypatch.setattr(routes.templates, "TemplateResponse", spy)
    return captured


def _iso_ms(dt: datetime) -> str:
    """Format a datetime in the stored ``YYYY-MM-DDTHH:MM:SS.mmmZ`` shape."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/systems",
        SYSTEM_URL,
        ACTIVITY_URL,
        "/dashboard",
    ],
)
def test_activity_routes_require_auth(tmp_path: Path, path: str) -> None:
    """Every activity-bearing route returns 401 without credentials."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(path, follow_redirects=False)
    assert resp.status_code == 401
    assert resp.headers.get("WWW-Authenticate") == "Basic"


def test_activity_page_wrong_credentials_401(tmp_path: Path) -> None:
    """Wrong credentials on the activity page return 401."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(ACTIVITY_URL, headers=_auth_header("admin", "nope"))
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /systems — union with API-only clusters
# ---------------------------------------------------------------------------


def test_systems_lists_api_only_cluster(tmp_path: Path) -> None:
    """A cluster with only API requests (no recordings) is listed with its count."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        for i in range(3):
            _insert_request(
                app,
                request_id=f"api-only-{i}",
                resource_address="api-only.example.internal",
                requested_at=f"2026-10-01T09:00:0{i}.000Z",
            )
        summaries = asyncio.run(app.state.repo.list_systems())
        resp = client.get("/systems", headers=_auth_header())

    assert resp.status_code == 200
    assert "api-only.example.internal" in resp.text
    assert "/systems/api-only.example.internal" in resp.text

    (summary,) = [s for s in summaries if s.resource_address == "api-only.example.internal"]
    assert summary.session_count == 0
    assert summary.api_request_count == 3
    # Timestamps are in the requested_at format (spec §7.5); last_seen is the newer.
    assert summary.last_api_at == "2026-10-01T09:00:02.000Z"
    assert summary.last_session_at is None
    assert summary.last_seen == "2026-10-01T09:00:02.000Z"
    assert (summary.has_ssh, summary.has_kubernetes) == (False, True)


def test_systems_union_merges_recordings_and_api_counts(tmp_path: Path) -> None:
    """A cluster with both a recording and API requests appears once, with both counts."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        summaries = asyncio.run(app.state.repo.list_systems())
        resp = client.get("/systems", headers=_auth_header())

    assert resp.status_code == 200
    matching = [s for s in summaries if s.resource_address == CLUSTER]
    assert len(matching) == 1
    (summary,) = matching
    # One recording (connection B's exec); A and C are API-only and create no rows.
    assert summary.session_count == 1
    # 3 on A, the exec 101 line on B, 4 on C (502, 200, failed, legacy path line).
    assert summary.api_request_count == 8
    assert CLUSTER in resp.text


def test_systems_page_timestamps_badges_and_count_links(tmp_path: Path, monkeypatch) -> None:
    """Systems page (spec §8.4): both timestamp columns, Type badges, count links."""
    app = create_app(_settings(tmp_path))
    captured = _capture_contexts(monkeypatch)
    with TestClient(app) as client:
        _feed_fixture(app)
        _insert_request(
            app,
            request_id="api-only-1",
            resource_address="api-only.example.internal",
            requested_at="2026-09-30T09:00:00.000Z",
        )
        resp = client.get("/systems", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.text
    views = {v.summary.resource_address: v for v in captured["systems.html"]["systems"]}
    cluster = views[CLUSTER].summary
    # The exec recording on B is the cluster's only session; the newest request is
    # C's legacy-path line at 10:06:00.
    assert (cluster.session_count, cluster.ssh_count, cluster.exec_count) == (1, 0, 1)
    assert cluster.last_session_at == "2026-10-01T10:00:02.900Z"
    assert cluster.last_api_at == SPAN_TO
    assert [b.label for b in views[CLUSTER].badges] == ["Kubernetes"]
    assert [b.label for b in views["api-only.example.internal"].badges] == ["Kubernetes"]
    # Newer activity first.
    assert list(views) == [CLUSTER, "api-only.example.internal"]

    for header in ("Type", "Last session", "Last API request"):
        assert f"<th>{header}</th>" in body
    assert '<span class="pill pill-kubectl">Kubernetes</span>' in body
    assert "2026-10-01T10:00:02.900Z" in body
    assert SPAN_TO in body
    # Count links into search (spec §8.1), built by search_url.
    assert f'href="/search?type=recordings&amp;system={CLUSTER}"' in body
    assert f'href="/search?type=kubectl&amp;system={CLUSTER}"' in body
    assert 'href="/search?type=kubectl&amp;system=api-only.example.internal"' in body


def test_systems_page_ssh_badge_and_no_badge_for_failed_only(tmp_path: Path) -> None:
    """An SSH recording earns the SSH badge; a start-only error row earns none."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:

        async def seed() -> None:
            db = app.state.db
            await db.execute(
                "INSERT INTO sessions (conn_id, resource_address, status, started_at, "
                "chunk_count, cast_path) VALUES "
                "('ssh-1', 'ssh.example.internal', 'complete', '2026-10-01T10:00:00Z', 2, '/x.cast'), "
                "('dead-1', 'dead.example.internal', 'error', '2026-10-01T09:00:00Z', 0, NULL)"
            )
            await db.commit()

        asyncio.run(seed())
        summaries = {s.resource_address: s for s in asyncio.run(app.state.repo.list_systems())}
        resp = client.get("/systems", headers=_auth_header())

    assert resp.status_code == 200
    assert '<span class="pill pill-ssh">SSH</span>' in resp.text
    assert "Kubernetes</span>" not in resp.text
    assert summaries["ssh.example.internal"].has_ssh is True
    dead = summaries["dead.example.internal"]
    assert (dead.has_ssh, dead.has_kubernetes) == (False, False)
    assert dead.last_session_at == "2026-10-01T09:00:00.000Z"


def test_systems_null_cluster_bucket_merges(tmp_path: Path) -> None:
    """API requests with no cluster join the (unknown) bucket."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _insert_request(
            app, request_id="no-cluster", resource_address=None, requested_at=SPAN_FROM
        )
        summaries = asyncio.run(app.state.repo.list_systems())
        resp = client.get("/systems", headers=_auth_header())

    assert [s.resource_address for s in summaries] == [None]
    assert summaries[0].api_request_count == 1
    assert "/systems/_unknown" in resp.text
    # The unknown bucket searches through the system=_unknown sentinel.
    assert 'href="/search?type=kubectl&amp;system=_unknown"' in resp.text


# ---------------------------------------------------------------------------
# System page — kubectl activity table
# ---------------------------------------------------------------------------


def test_system_page_shows_activity_table(tmp_path: Path) -> None:
    """The system page shows one activity session row with badge, user, and link."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(SYSTEM_URL, headers=_auth_header())

    assert resp.status_code == 200
    body = resp.text
    assert "kubectl activity" in body
    assert "kubectl</span>" in body  # the kubectl badge
    assert USERNAME in body
    assert SPAN_FROM in body
    assert SPAN_TO in body
    # The row links to the activity page by its own bounds (autoescaped &amp;).
    expected_link = (
        f"/systems/{CLUSTER}/activity?user={USER_KEY}"
        f"&amp;from={SPAN_FROM.replace(':', '%3A')}&amp;to={SPAN_TO.replace(':', '%3A')}"
    )
    assert expected_link in body
    # The recordings table is unchanged: the exec recording is still listed.
    assert f"/sessions/{CONN_B}" in body
    # Severity badge from the kube-exec finding on the exec request.
    assert "sev-medium" in body
    # "Older" paging link, and a "Latest" link because the window was pinned.
    assert "activity_before=2026-09-25T00%3A00%3A00.000Z" in body
    assert f'href="/systems/{CLUSTER}"' in body
    assert "truncated" not in body


def test_system_page_activity_grouping_counts(tmp_path: Path, monkeypatch) -> None:
    """The activity row aggregates commands, requests, and recordings correctly."""
    app = create_app(_settings(tmp_path))
    captured = _capture_contexts(monkeypatch)
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(SYSTEM_URL, headers=_auth_header())

    assert resp.status_code == 200
    ctx = captured["sessions.html"]
    (row,) = ctx["activity_sessions"]
    assert row["user_key"] == USER_KEY
    assert row["user_label"] == USERNAME
    assert row["request_count"] == 8
    assert row["command_count"] == 2  # kubectl exec + kubectl get
    assert row["recording_count"] == 1
    assert row["finding_count"] == 1
    assert row["max_severity"] == "medium"
    assert row["started_at"] == SPAN_FROM
    assert row["ended_at"] == SPAN_TO
    assert ctx["activity_truncated"] is False
    assert ctx["activity_window_until"] == "2026-10-02T00:00:00.000Z"
    assert ctx["activity_window_since"] == "2026-09-25T00:00:00.000Z"


def test_system_page_default_window_is_now(tmp_path: Path) -> None:
    """Without activity_before, the window ends now and shows recent activity."""
    app = create_app(_settings(tmp_path))
    recent = _iso_ms(datetime.now(tz=UTC) - timedelta(hours=1))
    with TestClient(app) as client:
        _insert_request(
            app,
            request_id="recent-1",
            resource_address="recent.example.internal",
            requested_at=recent,
            username="recent@example.com",
        )
        resp = client.get("/systems/recent.example.internal", headers=_auth_header())

    assert resp.status_code == 200
    assert "recent@example.com" in resp.text
    assert recent in resp.text


def test_system_page_older_window_excludes_activity(tmp_path: Path) -> None:
    """A window that ends before the fixture shows the empty state."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(
            f"/systems/{CLUSTER}?activity_before=2026-09-01T00:00:00Z",
            headers=_auth_header(),
        )
    assert resp.status_code == 200
    assert "No kubectl activity in this window." in resp.text


def test_system_page_truncation_notice(tmp_path: Path, monkeypatch) -> None:
    """When the row cap is hit, the system page shows a truncation notice."""
    monkeypatch.setattr(routes, "_ACTIVITY_MAX_ROWS", 3)
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(SYSTEM_URL, headers=_auth_header())
    assert resp.status_code == 200
    assert "truncated-notice" in resp.text
    assert "first 3 requests" in resp.text


def test_system_page_search_cross_links(tmp_path: Path, monkeypatch) -> None:
    """System page (spec §8.5): "Search this system", kubectl-in-search, ⌕ user links."""
    app = create_app(_settings(tmp_path))
    captured = _capture_contexts(monkeypatch)
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(SYSTEM_URL, headers=_auth_header())

    assert resp.status_code == 200
    body = resp.text
    assert f'<a href="/search?system={CLUSTER}">Search this system' in body
    assert f'<a href="/search?type=kubectl&amp;system={CLUSTER}">kubectl commands in search' in body

    user_href = "/search?user=user%40example.com"
    icon = (
        f'<a class="user-link user-link-icon" href="{user_href}" '
        f'aria-label="All activity for {USERNAME}"'
    )
    # One ⌕ link in the recordings table (exec recording) and one in the activity table.
    assert body.count(icon) == 2
    # The names keep their primary links (replay / activity page).
    assert f'href="/sessions/{CONN_B}"' in body
    ctx = captured["sessions.html"]
    (row,) = ctx["activity_sessions"]
    assert row["user_search_url"] == user_href
    (session,) = ctx["sessions"]
    assert session["user_url"] == user_href


def test_system_page_user_key_fallback_and_null_bucket(tmp_path: Path) -> None:
    """⌕ falls back to the user_key with no username; the NULL-user bucket gets none."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _insert_request(
            app,
            request_id="uid-only",
            resource_address="fallback.example.internal",
            requested_at="2026-10-01T10:00:00.000Z",
            username=None,  # type: ignore[arg-type]
            user_id="VXNlcjo5",
        )
        _insert_request(
            app,
            request_id="anon",
            resource_address="fallback.example.internal",
            requested_at="2026-10-01T10:00:01.000Z",
            username=None,  # type: ignore[arg-type]
            user_id=None,
            conn_id="cccccccc-0000-4000-8000-000000000009",
        )
        resp = client.get(
            f"/systems/fallback.example.internal?activity_before={BEFORE}",
            headers=_auth_header(),
        )

    assert resp.status_code == 200
    body = resp.text
    assert 'href="/search?user=VXNlcjo5" aria-label="All activity for VXNlcjo5"' in body
    assert "(unknown user)" in body
    assert "All activity for (unknown user)" not in body
    assert body.count("user-link-icon") == 1


# ---------------------------------------------------------------------------
# Activity page — commands, recording link, discovery
# ---------------------------------------------------------------------------


def test_activity_page_exec_run_is_one_command_with_recording_link(
    tmp_path: Path, monkeypatch
) -> None:
    """The two-connection exec run renders as one command linking /sessions/{B}."""
    app = create_app(_settings(tmp_path))
    captured = _capture_contexts(monkeypatch)
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(ACTIVITY_URL, headers=_auth_header())

    assert resp.status_code == 200
    body = resp.text
    assert f'href="/sessions/{CONN_B}"' in body
    assert "kubectl exec" in body
    assert "kubectl get" in body
    assert CLUSTER in body
    assert USERNAME in body

    ctx = captured["activity.html"]
    commands = {c["label"]: c for c in ctx["commands"]}
    assert set(commands) == {"kubectl exec", "kubectl get"}

    exec_cmd = commands["kubectl exec"]
    # Linked by request_id only: the recording lives on B, the GETs on A.
    assert exec_cmd["recordings"] == [{"conn_id": CONN_B, "url": f"/sessions/{CONN_B}"}]
    assert exec_cmd["method"] == "POST"
    assert exec_cmd["path"] == "/api/v1/namespaces/default/pods/web-1/exec"
    assert exec_cmd["status_code"] == 101
    assert exec_cmd["request_count"] == 4
    assert exec_cmd["discovery_count"] == 1
    assert exec_cmd["max_severity"] == "medium"
    assert exec_cmd["finding_count"] == 1

    get_cmd = commands["kubectl get"]
    assert get_cmd["recordings"] == []
    statuses = [r["status_code"] for r in get_cmd["requests"]]
    assert 502 in statuses and 200 in statuses
    outcomes = [r["outcome"] for r in get_cmd["requests"]]
    assert "failed" in outcomes

    assert ctx["request_count"] == 8
    assert ctx["span_from"] == SPAN_FROM
    assert ctx["span_to"] == SPAN_TO
    assert ctx["recordings"] == [{"conn_id": CONN_B, "url": f"/sessions/{CONN_B}"}]
    assert ctx["truncated"] is False


def test_activity_page_exec_url_is_sanitized(tmp_path: Path) -> None:
    """The exec URL renders without its command= params; no secret sentinels leak."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(ACTIVITY_URL, headers=_auth_header())

    body = resp.text
    assert "/pods/web-1/exec?container=nginx&amp;stdin=true&amp;stdout=true&amp;tty=true" in body
    assert "command=" not in body
    for sentinel in ("GC_SENTINEL_CMD", "GC_SENTINEL_TOKEN", "GC_SENTINEL_PANIC"):
        assert sentinel not in body


def test_activity_page_hides_discovery_by_default(tmp_path: Path) -> None:
    """Discovery requests are hidden unless discovery=1; the toggle link flips it."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        hidden = client.get(ACTIVITY_URL, headers=_auth_header())
        shown = client.get(ACTIVITY_URL + "&discovery=1", headers=_auth_header())
        explicit_off = client.get(ACTIVITY_URL + "&discovery=0", headers=_auth_header())

    assert hidden.status_code == 200
    assert DISCOVERY_URL not in hidden.text
    assert "1 discovery request(s) hidden." in hidden.text
    assert "discovery=1" in hidden.text  # "Show discovery" toggle

    assert shown.status_code == 200
    assert DISCOVERY_URL in shown.text
    assert "Hide discovery" in shown.text

    assert explicit_off.status_code == 200
    assert DISCOVERY_URL not in explicit_off.text


def test_activity_page_discovery_only_command_hidden(tmp_path: Path) -> None:
    """A command made only of discovery requests is omitted unless discovery=1."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _insert_request(
            app,
            request_id="disc-only-1",
            resource_address="disc.example.internal",
            requested_at="2026-10-01T10:00:00.000Z",
            url="/apis?timeout=32s",
            kubectl_session="5e55e55e-0000-4000-8000-0000000000aa",
        )
        _insert_request(
            app,
            request_id="real-1",
            resource_address="disc.example.internal",
            requested_at="2026-10-01T10:00:01.000Z",
            url="/api/v1/namespaces/default/configmaps",
            kubectl_session="5e55e55e-0000-4000-8000-0000000000bb",
        )
        base = (
            "/systems/disc.example.internal/activity?user=VXNlcjoy"
            "&from=2026-10-01T10:00:00.000Z&to=2026-10-01T10:00:01.000Z"
        )
        hidden = client.get(base, headers=_auth_header())
        shown = client.get(base + "&discovery=1", headers=_auth_header())

    assert hidden.status_code == 200
    assert "/apis?timeout=32s" not in hidden.text
    assert "/api/v1/namespaces/default/configmaps" in hidden.text
    assert "/apis?timeout=32s" in shown.text


def test_activity_page_escapes_script_in_url_and_username(tmp_path: Path) -> None:
    """A stored URL / username containing <script> renders escaped (autoescape on)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _insert_request(
            app,
            request_id="xss-1",
            resource_address="xss.example.internal",
            requested_at="2026-10-01T10:00:00.000Z",
            url="/api/v1/namespaces/<script>alert(1)</script>/pods",
            username="<script>alert(2)</script>@evil",
            user_id="VXNlcjoz",
        )
        page = client.get(
            "/systems/xss.example.internal/activity?user=VXNlcjoz"
            "&from=2026-10-01T10:00:00Z&to=2026-10-01T10:00:00Z",
            headers=_auth_header(),
        )
        system = client.get(
            f"/systems/xss.example.internal?activity_before={BEFORE}",
            headers=_auth_header(),
        )

    assert page.status_code == 200
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert "<script>alert(2)</script>" not in page.text
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in page.text

    assert system.status_code == 200
    assert "<script>alert(2)</script>" not in system.text
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in system.text


def test_activity_page_unknown_user_bucket(tmp_path: Path) -> None:
    """user=_unknown selects requests with no user id and no username."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _insert_request(
            app,
            request_id="anon-1",
            resource_address="anon.example.internal",
            requested_at="2026-10-01T10:00:00.000Z",
            username=None,  # type: ignore[arg-type]
            user_id=None,
        )
        resp = client.get(
            "/systems/anon.example.internal/activity?user=_unknown"
            "&from=2026-10-01T10:00:00Z&to=2026-10-01T10:00:00Z",
            headers=_auth_header(),
        )
    assert resp.status_code == 200
    assert "(unknown user)" in resp.text
    # The NULL-user bucket gets no search link.
    assert "user-link" not in resp.text


def test_activity_page_links_user_to_search(tmp_path: Path) -> None:
    """The activity header's user label links to /search?user=<username> (spec §8.5)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(ACTIVITY_URL, headers=_auth_header())

    assert resp.status_code == 200
    assert (
        f'<a class="user-link" href="/search?user=user%40example.com">{USERNAME}</a>'
        in resp.text
    )


def test_activity_page_user_link_falls_back_to_user_key(tmp_path: Path) -> None:
    """With no username, the header links with the user_key (matched as a user_id)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _insert_request(
            app,
            request_id="uid-only",
            resource_address="fallback.example.internal",
            requested_at="2026-10-01T10:00:00.000Z",
            username=None,  # type: ignore[arg-type]
            user_id="VXNlcjo5",
        )
        resp = client.get(
            "/systems/fallback.example.internal/activity?user=VXNlcjo5"
            "&from=2026-10-01T10:00:00Z&to=2026-10-01T10:00:00Z",
            headers=_auth_header(),
        )
    assert resp.status_code == 200
    assert '<a class="user-link" href="/search?user=VXNlcjo5">VXNlcjo5</a>' in resp.text


# ---------------------------------------------------------------------------
# Session page — user link and exec → command link (Q13)
# ---------------------------------------------------------------------------


def test_session_page_exec_recording_links_its_command(tmp_path: Path, monkeypatch) -> None:
    """An exec recording whose request_id is stored links /search?cmd=<request_id>."""
    app = create_app(_settings(tmp_path))
    captured = _capture_contexts(monkeypatch)
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(f"/sessions/{CONN_B}", headers=_auth_header())
        # The command link opens the command in search.
        focus = client.get(f"/search?cmd={EXEC_REQUEST_ID}", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.text
    assert captured["session.html"]["command_url"] == f"/search?cmd={EXEC_REQUEST_ID}"
    assert f'<a href="/search?cmd={EXEC_REQUEST_ID}">kubectl command' in body
    assert f'<a class="user-link" href="/search?user=user%40example.com">{USERNAME}</a>' in body
    assert focus.status_code == 200
    assert "kubectl exec" in focus.text


def test_session_page_exec_without_stored_command_has_no_link(tmp_path: Path) -> None:
    """No command link when the exec request_id has no api_requests row (or for SSH)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:

        async def seed() -> None:
            db = app.state.db
            await db.execute(
                "INSERT INTO sessions (conn_id, resource_address, status, started_at, "
                "chunk_count, request_id) VALUES "
                "('exec-orphan', 'k8s.example.internal', 'complete', "
                "'2026-10-01T10:00:00Z', 1, 'missing-request'), "
                "('ssh-plain', 'ssh.example.internal', 'complete', "
                "'2026-10-01T10:00:00Z', 1, NULL)"
            )
            await db.commit()

        asyncio.run(seed())
        orphan = client.get("/sessions/exec-orphan", headers=_auth_header())
        ssh = client.get("/sessions/ssh-plain", headers=_auth_header())

    for resp in (orphan, ssh):
        assert resp.status_code == 200
        assert "/search?cmd=" not in resp.text
        assert "kubectl command" not in resp.text
        # No username stored: the user value is plain text.
        assert "(unknown user)" in resp.text
        assert "user-link" not in resp.text


def test_activity_page_empty_bounds_404(tmp_path: Path) -> None:
    """Valid bounds with no matching requests return 404."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        wrong_window = client.get(
            f"/systems/{CLUSTER}/activity?user={USER_KEY}"
            "&from=2026-09-01T00:00:00Z&to=2026-09-01T01:00:00Z",
            headers=_auth_header(),
        )
        wrong_user = client.get(
            f"/systems/{CLUSTER}/activity?user=nobody&from={SPAN_FROM}&to={SPAN_TO}",
            headers=_auth_header(),
        )
        wrong_system = client.get(
            f"/systems/other.example.internal/activity?user={USER_KEY}"
            f"&from={SPAN_FROM}&to={SPAN_TO}",
            headers=_auth_header(),
        )
    assert wrong_window.status_code == 404
    assert wrong_user.status_code == 404
    assert wrong_system.status_code == 404


# ---------------------------------------------------------------------------
# Strict parameter validation → 4xx
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        # missing parameters
        f"from={SPAN_FROM}&to={SPAN_TO}",
        f"user={USER_KEY}&to={SPAN_TO}",
        f"user={USER_KEY}&from={SPAN_FROM}",
        f"user=&from={SPAN_FROM}&to={SPAN_TO}",
        # unparseable bounds
        f"user={USER_KEY}&from=not-a-date&to={SPAN_TO}",
        f"user={USER_KEY}&from={SPAN_FROM}&to=2026-13-45T99:00:00Z",
        f"user={USER_KEY}&from=1' OR '1'='1&to={SPAN_TO}",
        f"user={USER_KEY}&from={'9' * 100}&to={SPAN_TO}",
        # inverted bounds
        f"user={USER_KEY}&from={SPAN_TO}&to={SPAN_FROM}",
        # bad discovery toggle
        f"user={USER_KEY}&from={SPAN_FROM}&to={SPAN_TO}&discovery=yes",
        f"user={USER_KEY}&from={SPAN_FROM}&to={SPAN_TO}&discovery=2",
        # repeated parameters
        f"user={USER_KEY}&user=other&from={SPAN_FROM}&to={SPAN_TO}",
        f"user={USER_KEY}&from={SPAN_FROM}&from={SPAN_FROM}&to={SPAN_TO}",
        # control characters / over-long user key
        f"user=a%00b&from={SPAN_FROM}&to={SPAN_TO}",
        f"user=a%0Ab&from={SPAN_FROM}&to={SPAN_TO}",
        f"user={'u' * 513}&from={SPAN_FROM}&to={SPAN_TO}",
    ],
)
def test_activity_page_bad_params_400(tmp_path: Path, query: str) -> None:
    """Missing, malformed, repeated, or inverted parameters return 400."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(f"/systems/{CLUSTER}/activity?{query}", headers=_auth_header())
    assert resp.status_code == 400


@pytest.mark.parametrize(
    "value",
    [
        "garbage",
        "2026-10-01T25:00:00Z",
        "0001-01-01T00:00:00Z",  # window start would underflow datetime.min
        "x" * 100,
    ],
)
def test_system_page_bad_activity_before_400(tmp_path: Path, value: str) -> None:
    """An invalid or out-of-range activity_before returns 400."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get(
            f"/systems/{CLUSTER}?activity_before={value}", headers=_auth_header()
        )
    assert resp.status_code == 400


def test_system_page_repeated_activity_before_400(tmp_path: Path) -> None:
    """activity_before may be given only once."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get(
            f"/systems/{CLUSTER}?activity_before={BEFORE}&activity_before={BEFORE}",
            headers=_auth_header(),
        )
    assert resp.status_code == 400


def test_error_detail_does_not_echo_value(tmp_path: Path) -> None:
    """A 400 detail names the parameter but never echoes the submitted value."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get(
            f"/systems/{CLUSTER}/activity?user={USER_KEY}"
            f"&from=<script>x</script>&to={SPAN_TO}",
            headers=_auth_header(),
        )
    assert resp.status_code == 400
    assert "<script>" not in resp.text


# ---------------------------------------------------------------------------
# Dashboard card
# ---------------------------------------------------------------------------


def test_dashboard_shows_kubectl_card(tmp_path: Path) -> None:
    """The kubectl card shows the request total, flagged commands, and linked chips."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get("/dashboard?window=all", headers=_auth_header())
        stats = asyncio.run(app.state.search.dashboard_stats())

    assert resp.status_code == 200
    body = resp.text
    assert "kubectl API requests" in body
    # Flagged figures count commands (spec §8.2), singular for one.
    assert re.search(r'<span class="badge-count">1</span>\s*flagged command\s', body)
    assert 'href="/search?type=kubectl&amp;window=all&amp;has_findings=true"' in body
    assert 'href="/search?type=kubectl&amp;window=all&amp;max_severity=medium"' in body
    assert 'href="/search?type=kubectl&amp;window=all"' in body
    assert "sev-medium" in body

    assert stats.api_requests_total == 8
    assert stats.api_flagged_commands == 1
    assert stats.api_commands_by_severity == {"medium": 1}
    assert stats.api_flagged_truncated is False
    # Existing aggregates are unchanged: one recording session on the cluster.
    assert stats.total_sessions == 1


def test_dashboard_api_stats_windowed_on_requested_at(tmp_path: Path) -> None:
    """API stats honour the window cutoff on requested_at (boundary inclusive)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        # From 10:05:00 only C's four requests remain (none flagged).
        late = asyncio.run(
            app.state.search.dashboard_stats(started_after="2026-10-01T10:05:00Z")
        )
        # A ...SSZ cutoff equal to a stored ...SS.000Z value includes that request.
        boundary = asyncio.run(
            app.state.search.dashboard_stats(started_after="2026-10-01T10:06:00Z")
        )
        empty = asyncio.run(
            app.state.search.dashboard_stats(started_after="2026-11-01T00:00:00Z")
        )

    assert late.api_requests_total == 4
    assert late.api_flagged_commands == 0
    assert late.api_commands_by_severity == {}
    assert boundary.api_requests_total == 1
    assert empty.api_requests_total == 0


def test_dashboard_card_renders_with_no_api_data(tmp_path: Path) -> None:
    """With no API requests the card renders zeros and the page still works."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/dashboard", headers=_auth_header())
    assert resp.status_code == 200
    assert "kubectl API requests" in resp.text
    assert re.search(r'<span class="badge-count">0</span>\s*flagged commands\s', resp.text)
    assert "No activity recorded yet." in resp.text


def test_dashboard_flagged_cap_renders_plus_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Over the flagged-command cap the figure renders as ``N+`` with a lower-bound note."""
    from gatorcast.store import search as search_mod

    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        monkeypatch.setattr(search_mod, "_FLAGGED_CMD_CAP", 0)
        resp = client.get("/dashboard?window=all", headers=_auth_header())

    assert resp.status_code == 200
    assert re.search(r'<span class="badge-count">0\+</span>\s*flagged commands\s', resp.text)
    assert "counts are lower bounds" in resp.text
