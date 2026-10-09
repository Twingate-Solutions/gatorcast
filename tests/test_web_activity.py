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
import html
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
from gatorcast.store.activity import RequestStorage
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
        url_web=url,
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
    assert summary.kubectl_request_count == 3
    assert summary.web_request_count == 0
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
    assert summary.kubectl_request_count == 8
    assert summary.web_request_count == 0
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

    # Session 12 (WEBAPP_SPEC §8.5): "API requests" became "Requests" and "Last API
    # request" became "Last request" (the column now covers both API kinds).
    for header in ("Type", "Last session", "Last request"):
        assert f"<th>{header}</th>" in body
    assert '<th class="num">Requests</th>' in body
    assert "Last API request" not in body
    assert "API requests" not in body
    assert '<span class="pill pill-kubectl">Kubernetes</span>' in body
    assert "2026-10-01T10:00:02.900Z" in body
    assert SPAN_TO in body
    # Count links into search (spec §8.1), built by search_url.
    assert f'href="/search?type=recordings&amp;system={CLUSTER}"' in body
    assert f'href="/search?type=kubectl&amp;system={CLUSTER}"' in body
    assert 'href="/search?type=kubectl&amp;system=api-only.example.internal"' in body
    # One link per kind present: kubectl only here, so no web link and no web badge.
    assert "8 kubectl" in body
    assert "type=web" not in body
    assert "pill-web" not in body


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
    assert summaries[0].kubectl_request_count == 1
    assert summaries[0].web_request_count == 0
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


# ---------------------------------------------------------------------------
# Session 11 (web apps): web rows never reach the kubectl surfaces (WEBAPP_SPEC 7, 8.5, 8.6)
# ---------------------------------------------------------------------------

WEB_ADDR = "wiki.corp.internal"
WEB_URL_SENTINEL = "/web-only-path-xyzzy"


def _insert_web_request(
    app,
    *,
    request_id: str,
    resource_address: str | None,
    requested_at: str,
    url: str = WEB_URL_SENTINEL,
    method: str = "GET",
    username: str = "other@example.com",
    user_id: str | None = "VXNlcjoy",
    conn_id: str = "cccccccc-0000-4000-8000-000000000009",
) -> None:
    """Store one web-policy request (``api_kind = 'web'``, no kubectl headers)."""
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
        user_agent="Mozilla/5.0 (test)",
    )
    storage = RequestStorage(
        api_kind="web", url=url, user_agent=req.user_agent, kubectl_command=None, kubectl_session=None
    )
    asyncio.run(app.state.activity.insert_request(req, resource_address, storage=storage))


def test_systems_summary_splits_kubectl_and_web_counts_for_one_address(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    with TestClient(app):
        for i in range(2):
            _insert_request(app, request_id=f"k{i}", resource_address=WEB_ADDR,
                            requested_at=f"2026-10-01T09:00:0{i}.000Z")
        for i in range(5):
            _insert_web_request(app, request_id=f"w{i}", resource_address=WEB_ADDR,
                                requested_at=f"2026-10-01T09:01:0{i}.000Z")
        (summary,) = asyncio.run(app.state.repo.list_systems())

    assert summary.resource_address == WEB_ADDR
    assert (summary.kubectl_request_count, summary.web_request_count) == (2, 5)
    assert summary.has_kubernetes is True


def _system_row(body: str, address: str) -> str:
    """Return the ``<tr>`` of one system on the /systems page (matched by its link)."""
    for chunk in body.split("<tr>")[1:]:
        if f'href="/systems/{address}"' in chunk:
            return chunk
    raise AssertionError(f"no systems row for {address}")


_BADGE_RE = re.compile(
    r'<span class="pill [^"]*"[^>]*>([^<]*)</span>'
    r'|<span class="marker [^"]*"[^>]*><span aria-hidden="true">([^<]*)</span> ([^<]*)</span>'
)


def _badge_labels(row: str) -> list[str]:
    """Return the badge/marker labels of a systems row, in order.

    A pill is ``<span class="pill …" title="…">Label</span>``; a marker is
    ``<span class="marker …" title="…"><span aria-hidden="true">!</span> Label</span>``
    and is returned as ``"! Label"`` so the glyph is checked too.
    """
    cluster = re.search(r'<div class="badge-cluster">(.*?)</div>', row, re.S)
    assert cluster is not None
    return [
        m.group(1) if m.group(1) is not None else f"{m.group(2)} {m.group(3)}"
        for m in _BADGE_RE.finditer(cluster.group(1))
    ]


async def _seed_web_system(
    app,
    address: str,
    *,
    down: str | None,
    up: str | None,
    n: int = 3,
    conn_id: str = "wc-sys-1",
) -> None:
    """Insert one web connection (with the given configured TLS) and ``n`` web requests."""
    from tests.fixtures.timeline import add_connection, add_request

    await add_connection(
        app.state.db, conn_id, user_id="VXNlcjoy", username="other@example.com",
        resource_address=address, state="api", resource_type="WEB_APP",
        gwops_match="exact" if down else None, gwops_gateway_id="gw-sys" if down else None,
        gwops_app="Sys App" if down else None, gwops_managed=True if down else None,
        downstream_tls=down, upstream_tls=up,
    )
    for i in range(n):
        await add_request(
            app.state.db, f"{conn_id}-r{i}", conn_id=conn_id, resource_address=address,
            requested_at=f"2026-10-01T09:00:0{i}.000Z", user_id="VXNlcjoy",
            username="other@example.com", url="/home", api_kind="web", kubectl_session=None,
            kubectl_command=None, downstream_tls=down, upstream_tls=up,
        )


def test_web_only_system_gets_web_and_tls_badges_never_kubernetes(
    tmp_path: Path, monkeypatch
) -> None:
    """A web-only system: Web + scheme badge (+ upstream marker), no Kubernetes, web link only.

    Inverts the Session 11 rule that a web-only system had no badges at all
    (WEBAPP_SPEC §8.5): the Type column is Web, HTTPS, then the upstream marker of the
    newest web request. The Requests column has one ``N web`` link to ``type=web`` and
    no kubectl link.
    """
    app = create_app(_settings(tmp_path))
    captured = _capture_contexts(monkeypatch)
    with TestClient(app) as client:
        asyncio.run(_seed_web_system(app, WEB_ADDR, down="tls13", up="insecure", n=3))
        resp = client.get("/systems", headers=_auth_header())

    assert resp.status_code == 200
    (view,) = captured["systems.html"]["systems"]
    assert view.summary.kubectl_request_count == 0 and view.summary.web_request_count == 3
    assert [b.label for b in view.badges] == ["Web", "HTTPS", "Unverified upstream"]
    row = _system_row(resp.text, WEB_ADDR)
    assert _badge_labels(row) == ["Web", "HTTPS", "! Unverified upstream"]
    assert "Kubernetes" not in row
    assert "SSH" not in row
    assert "kubectl" not in row  # no kubectl count link for a web-only system
    assert f'href="/search?type=web&amp;system={WEB_ADDR}"' in row
    assert "3 web" in row


@pytest.mark.parametrize(
    ("down", "up", "expected"),
    [
        ("tls13", "verify_full", ["Web", "HTTPS"]),
        ("none", "none", ["Web", "HTTP", "! Plaintext upstream"]),
        ("tls13", "verify_ca", ["Web", "HTTPS", "i CA-only upstream"]),
        ("tls13", "insecure", ["Web", "HTTPS", "! Unverified upstream"]),
        (None, None, ["Web", "TLS unknown"]),
    ],
    ids=["https-verified", "http-plaintext", "https-ca-only", "https-unverified", "tls-unknown"],
)
def test_systems_page_badge_order_scheme_badge_then_upstream_marker(
    tmp_path: Path, down: str | None, up: str | None, expected: list[str]
) -> None:
    """Badges are ordered Web, scheme badge, upstream marker (none for verify_full / unknown)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_system(app, WEB_ADDR, down=down, up=up))
        resp = client.get("/systems", headers=_auth_header())
    assert resp.status_code == 200
    assert _badge_labels(_system_row(resp.text, WEB_ADDR)) == expected


def test_systems_badges_carry_configured_not_proof_tooltips(tmp_path: Path) -> None:
    """Every TLS badge and marker has a static title saying configured, not proof (§8.4)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_system(app, WEB_ADDR, down="none", up="none"))
        asyncio.run(
            _seed_web_system(app, "unknown.corp.internal", down=None, up=None, conn_id="wc-sys-2")
        )
        resp = client.get("/systems", headers=_auth_header())
    assert resp.status_code == 200
    http_row = _system_row(resp.text, WEB_ADDR)
    titles = [html.unescape(t) for t in re.findall(r'title="([^"]*)"', http_row)]
    assert len(titles) == 2  # HTTP badge + Plaintext upstream marker
    assert titles[0].startswith("HTTP (configured): ")
    assert "not proof of the negotiated mode" in titles[0]
    assert titles[1].startswith("Plaintext upstream (configured): ")
    assert "not proof of the negotiated mode" in titles[1]
    unknown_row = _system_row(resp.text, "unknown.corp.internal")
    (unknown_title,) = re.findall(r'title="([^"]*)"', unknown_row)
    assert html.unescape(unknown_title).startswith("No configured TLS data for this connection")


def test_systems_badge_follows_the_newest_web_request(tmp_path: Path) -> None:
    """The scheme badge and marker come from the system's NEWEST web request's snapshot."""
    from tests.fixtures.timeline import add_connection, add_request

    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:

        async def seed() -> None:
            await _seed_web_system(app, WEB_ADDR, down="none", up="none", n=2, conn_id="wc-old")
            await add_connection(
                app.state.db, "wc-new", user_id="VXNlcjoy", username="other@example.com",
                resource_address=WEB_ADDR, state="api", resource_type="WEB_APP",
                gwops_match="exact", gwops_gateway_id="gw", gwops_app="A", gwops_managed=True,
                downstream_tls="tls13", upstream_tls="verify_full",
            )
            await add_request(
                app.state.db, "wc-new-r0", conn_id="wc-new", resource_address=WEB_ADDR,
                requested_at="2026-10-01T12:00:00.000Z", user_id="VXNlcjoy",
                username="other@example.com", url="/new", api_kind="web", kubectl_session=None,
                kubectl_command=None, downstream_tls="tls13", upstream_tls="verify_full",
            )

        asyncio.run(seed())
        resp = client.get("/systems", headers=_auth_header())
    assert _badge_labels(_system_row(resp.text, WEB_ADDR)) == ["Web", "HTTPS"]


def test_systems_page_per_kind_request_links_when_web_rows_share_the_system(
    tmp_path: Path,
) -> None:
    """A system with both kinds shows one link per kind (kubectl first, then web).

    Replaces the Session 11 rule that the cell showed the kubectl count only. Each
    link carries its own count and its own kind-and-system filter; both badges show,
    and the "Last request" link lists every kind on the system.
    """
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        for i in range(2):
            _insert_request(
                app, request_id=f"k{i}", resource_address=WEB_ADDR,
                requested_at=f"2026-10-01T09:00:0{i}.000Z",
            )
        asyncio.run(
            _seed_web_system(app, WEB_ADDR, down="tls13", up="verify_full", n=7, conn_id="wc-share")
        )
        resp = client.get("/systems", headers=_auth_header())

    assert resp.status_code == 200
    row = _system_row(resp.text, WEB_ADDR)
    cell = re.search(r'<td class="num api-count">(.*?)</td>', row, re.S)
    assert cell is not None
    links = re.findall(r'<a href="([^"]*)"[^>]*>\s*([\d,]+ \w+)\s*<span', cell.group(1))
    assert [(html.unescape(u), t) for u, t in links] == [
        (f"/search?type=kubectl&system={WEB_ADDR}", "2 kubectl"),
        (f"/search?type=web&system={WEB_ADDR}", "7 web"),
    ]
    assert _badge_labels(row) == ["Kubernetes", "Web", "HTTPS"]
    # "Last request" spans both kinds, so it links to the system's whole search.
    assert f'href="/search?system={WEB_ADDR}"' in row


def test_systems_page_last_request_links_to_the_single_kind_search(tmp_path: Path) -> None:
    """With one API kind, "Last request" links to that kind's search (fixes the old dead link)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_system(app, WEB_ADDR, down="tls13", up="verify_full", n=2))
        resp = client.get("/systems", headers=_auth_header())
    row = _system_row(resp.text, WEB_ADDR)
    assert f'<a href="/search?type=web&amp;system={WEB_ADDR}">2026-10-01T09:00:01.000Z</a>' in row


def test_system_page_activity_ignores_web_rows_for_the_same_address(tmp_path: Path, monkeypatch) -> None:
    """kubectl activity on a system that also has web rows: same row, same counts, no web URL."""
    app = create_app(_settings(tmp_path))
    captured = _capture_contexts(monkeypatch)
    with TestClient(app) as client:
        _feed_fixture(app)
        for i in range(3):
            _insert_web_request(app, request_id=f"w{i}", resource_address=CLUSTER, user_id=USER_KEY,
                                username=USERNAME, requested_at=f"2026-10-01T10:03:0{i}.000Z")
        resp = client.get(SYSTEM_URL, headers=_auth_header())

    assert resp.status_code == 200
    (row,) = captured["sessions.html"]["activity_sessions"]
    assert row["request_count"] == 8
    assert row["command_count"] == 2
    assert row["ended_at"] == SPAN_TO
    assert WEB_URL_SENTINEL not in resp.text


def test_system_page_for_a_web_only_system_shows_web_activity_and_no_kubectl_section(
    tmp_path: Path, monkeypatch
) -> None:
    """A web-only system: the Web activity table replaces the kubectl one (§8.5).

    Inverts the Session 11 rule that the page showed an empty kubectl table: there is
    no kubectl activity section, heading, or "No kubectl activity" text at all, and
    the web section lists the visit. The visit table carries no stored URL.
    """
    app = create_app(_settings(tmp_path))
    captured = _capture_contexts(monkeypatch)
    with TestClient(app) as client:
        for i in range(3):
            _insert_web_request(app, request_id=f"w{i}", resource_address=WEB_ADDR,
                                requested_at=f"2026-10-01T09:00:0{i}.000Z")
        resp = client.get(f"/systems/{WEB_ADDR}?activity_before={BEFORE}", headers=_auth_header())

    assert resp.status_code == 200
    ctx = captured["sessions.html"]
    assert ctx["show_kubectl_activity"] is False
    assert ctx["show_web_activity"] is True
    assert ctx["activity_sessions"] == []
    assert len(ctx["web_activity_visits"]) == 1
    assert "No kubectl activity in this window." not in resp.text
    assert "kubectl activity" not in resp.text
    assert 'id="web-activity-heading"' in resp.text
    assert "No sessions for this system." not in resp.text
    assert WEB_URL_SENTINEL not in resp.text


def test_activity_page_404s_for_bounds_that_only_contain_web_rows(tmp_path: Path) -> None:
    """The kubectl activity route reads kubectl rows only: a web visit never renders in it."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        for i in range(2):
            _insert_web_request(app, request_id=f"w{i}", resource_address=WEB_ADDR,
                                requested_at=f"2026-10-01T09:00:0{i}.000Z")
        resp = client.get(
            f"/systems/{WEB_ADDR}/activity?user=VXNlcjoy"
            "&from=2026-10-01T09:00:00.000Z&to=2026-10-01T09:00:05.000Z",
            headers=_auth_header(),
        )
    assert resp.status_code == 404
    assert WEB_URL_SENTINEL not in resp.text


def test_activity_page_omits_web_rows_that_share_user_system_and_window(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        for i in range(3):
            _insert_web_request(app, request_id=f"w{i}", resource_address=CLUSTER, user_id=USER_KEY,
                                username=USERNAME, requested_at=f"2026-10-01T10:03:0{i}.000Z")
        resp = client.get(ACTIVITY_URL, headers=_auth_header())

    assert resp.status_code == 200
    assert WEB_URL_SENTINEL not in resp.text


def _tile_values(body: str) -> dict[str, str]:
    """Return ``{card label: value}`` for every dashboard tile (``card-link``)."""
    out: dict[str, str] = {}
    for m in re.finditer(
        r'<a class="card-link" href="[^"]*">\s*<span class="card-value">([^<]*)</span>\s*'
        r'<span class="card-label">([^<]*?)\s*<span',
        body,
    ):
        out[m.group(2).strip()] = m.group(1).strip()
    return out


def test_dashboard_tiles_split_kubectl_and_web_requests(tmp_path: Path) -> None:
    """The kubectl tile still excludes web rows; the web tile counts web requests; the feed has both.

    Session 12 (WEBAPP_SPEC §8.6): ``api_requests_total`` stays kubectl-only (8 and,
    in a window that spans the web rows, 4), ``web_requests_total`` counts the 5 web
    requests, and the recent-activity feed now lists the web connection (one row: the
    five requests share a connection).
    """
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        for i in range(5):
            _insert_web_request(app, request_id=f"w{i}", resource_address=CLUSTER,
                                requested_at=f"2026-10-01T10:03:0{i}.000Z")
        stats = asyncio.run(app.state.search.dashboard_stats())
        windowed = asyncio.run(app.state.search.dashboard_stats(started_after="2026-10-01T10:03:00Z"))
        resp = client.get("/dashboard?window=all", headers=_auth_header())

    assert stats.api_requests_total == 8
    assert stats.web_requests_total == 5
    assert windowed.api_requests_total == 4  # a window that spans the web rows still counts kubectl only
    assert windowed.web_requests_total == 5
    assert resp.status_code == 200
    tiles = _tile_values(resp.text)
    assert tiles["kubectl API requests"] == "8"
    assert tiles["Web requests"] == "5"
    assert 'href="/search?type=web&amp;window=all"' in resp.text
    # The feed includes the web connection (its row is compact: Details, no Focus link).
    feed = resp.text.split('id="feed-heading"')[1]
    assert feed.count('class="pill pill-web"') == 1
    assert WEB_URL_SENTINEL in feed


def test_dashboard_api_requests_total_is_zero_with_only_web_rows(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        for i in range(4):
            _insert_web_request(app, request_id=f"w{i}", resource_address=WEB_ADDR,
                                requested_at=f"2026-10-01T09:00:0{i}.000Z")
        stats = asyncio.run(app.state.search.dashboard_stats())
        resp = client.get("/dashboard?window=all", headers=_auth_header())

    assert stats.api_requests_total == 0
    assert stats.api_flagged_commands == 0
    assert stats.web_requests_total == 4
    assert resp.status_code == 200
    tiles = _tile_values(resp.text)
    assert tiles["kubectl API requests"] == "0"
    assert tiles["Web requests"] == "4"


# ---------------------------------------------------------------------------
# Session 12 (web apps): system page, Web activity table, visit view
# (WEBAPP_SPEC §8.4, §8.5, §10)
# ---------------------------------------------------------------------------

WEB_USER_ID = "uid-web-1"
WEB_USER = "web.user@example.com"
WEB_BEFORE = "2026-10-02T00:00:00Z"  # pins the 7-day system-page window over 2026-10-01
WEB_FOOTNOTE = (
    "Configured state reported by gwops when each connection was authenticated; not proof "
    "of the negotiated mode. After a TLS change, connections on an older token can differ "
    "for up to about 55 minutes."
)
NO_GWOPS = {
    "match": None, "gateway": None, "app_name": None, "managed": None,
    "down": None, "up": None, "dport": None, "uport": None,
}
HOSTILE_APP = "<script>alert(1)</script> \"q\" 'a' & <b>x</b>"


def _hms(seconds: int) -> str:
    """Return ``HH:MM:SS.000`` for seconds after midnight (on the fixture day)."""
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}.000"


async def _seed_web_conn(
    app,
    conn_id: str,
    start_s: int,
    *,
    system: str | None = WEB_ADDR,
    match: str | None = "exact",
    gateway: str | None = "gw-1",
    app_name: str | None = "Wiki Prod",
    managed: bool | None = True,
    down: str | None = "tls13",
    up: str | None = "verify_full",
    dport: int | None = 443,
    uport: int | None = 443,
    n: int = 1,
    user: tuple[str | None, str | None] = (WEB_USER_ID, WEB_USER),
    statuses: list[int | None] | None = None,
    urls: list[str] | None = None,
    row: bool = True,
) -> list[str]:
    """Insert one web connection (``row=False`` skips ``connections``) and ``n`` requests.

    Requests are one second apart from ``start_s`` seconds after midnight on the
    fixture day. ``statuses`` / ``urls`` override the per-request status / URL; a
    ``None`` status is stored as a ``failed`` row (the Gateway's failed line).
    Returns the request ids.
    """
    from tests.fixtures.timeline import add_connection, add_request, at

    db = app.state.db
    if row:
        await add_connection(
            db, conn_id, user_id=user[0], username=user[1], resource_address=system,
            state="api", resource_type="WEB_APP", gwops_match=match, gwops_gateway_id=gateway,
            gwops_app=app_name, gwops_managed=managed, downstream_tls=down, upstream_tls=up,
            downstream_port=dport, upstream_port=uport,
        )
    ids = []
    for i in range(n):
        status = statuses[i] if statuses is not None else 200
        rid = f"{conn_id}-r{i}"
        await add_request(
            db, rid, conn_id=conn_id, requested_at=at(_hms(start_s + i)), resource_address=system,
            user_id=user[0], username=user[1], url=urls[i] if urls else f"/page/{i}",
            status_code=status, outcome="failed" if status is None else "completed",
            api_kind="web", kubectl_session=None, kubectl_command=None, user_agent=None,
            downstream_tls=down, upstream_tls=up,
        )
        ids.append(rid)
    return ids


def _frag_text(fragment: str) -> str:
    """Visible text of an HTML fragment: tags dropped, entities unescaped, spaces collapsed."""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


def _config_block(body: str) -> dict[str, object]:
    """Parse the "Configured web app TLS" block: heading, line texts, notice, footnote."""
    section = re.search(r'<section class="config-block".*?</section>', body, re.S)
    assert section is not None, "no configuration block rendered"
    block = section.group(0)
    notice = re.search(r'<p class="truncated-notice">(.*?)</p>', block, re.S)
    note = re.search(r'<p class="config-note dim">(.*?)</p>', block, re.S)
    return {
        "html": block,
        "heading": _frag_text(re.search(r"<h2[^>]*>(.*?)</h2>", block, re.S).group(1)),
        "lines": [_frag_text(li) for li in re.findall(r'<li class="config-line">(.*?)</li>', block, re.S)],
        "line_html": re.findall(r'<li class="config-line">(.*?)</li>', block, re.S),
        "notice": _frag_text(notice.group(1)) if notice else None,
        "footnote": _frag_text(note.group(1)) if note else None,
    }


def _sub(tmp_path: Path, name: str) -> Path:
    """Return a fresh sub-directory of ``tmp_path`` (for a test that builds two apps)."""
    path = tmp_path / name
    path.mkdir()
    return path


def _system_url(addr: str = WEB_ADDR) -> str:
    return f"/systems/{addr}?activity_before={WEB_BEFORE}"


def _visit_url(addr: str, user: str, frm: str, to: str) -> str:
    return f"/systems/{addr}/web?user={user}&from={frm}&to={to}"


def _get_page(client: TestClient, url: str):
    return client.get(url, headers=_auth_header())


T0 = "2026-10-01T09:00:00Z"
T1 = "2026-10-01T09:30:00Z"


def test_system_page_config_block_exact_managed(tmp_path: Path) -> None:
    """``exact`` managed: badge, ports, upstream mode, app, managed pill, gateway id, counts."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=2))
        resp = _get_page(client, _system_url())
    assert resp.status_code == 200
    cfg = _config_block(resp.text)
    assert cfg["heading"] == "Configured web app TLS (from gwops)"
    assert cfg["lines"] == [
        "HTTPS :443 → to upstream verify_full :443 app: Wiki Prod managed gateway gw-1 "
        "1 connection · 2026-10-01T09:00:00.000Z → 2026-10-01T09:00:01.000Z"
    ]
    line = cfg["line_html"][0]
    assert 'class="pill pill-https"' in line
    assert 'class="pill pill-managed"' in line
    assert "marker" not in line  # verify_full carries no upstream marker
    assert 'class="app-name"' in line


def test_system_page_config_block_exact_unmanaged_with_upstream_marker(tmp_path: Path) -> None:
    """``exact`` unmanaged: ``unmanaged`` pill, plaintext client and upstream marker."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(
            app, "wc-1", 9 * 3600, app_name="Docs (beta)", managed=False, gateway="gw-2",
            down="none", up="none", dport=80, uport=8080,
        ))
        resp = _get_page(client, _system_url())
    cfg = _config_block(resp.text)
    assert cfg["lines"] == [
        "HTTP :80 → to upstream none :8080 ! Plaintext upstream app: Docs (beta) unmanaged "
        "gateway gw-2 1 connection · 2026-10-01T09:00:00.000Z → 2026-10-01T09:00:00.000Z"
    ]
    line = cfg["line_html"][0]
    assert 'class="pill pill-http"' in line
    assert 'class="marker marker-warn"' in line
    assert 'class="pill pill-unmanaged"' in line
    assert "pill-managed" not in line


def test_system_page_config_block_null_gateway_id_says_not_yet_assigned(tmp_path: Path) -> None:
    """gwops Mode B: an exact object with a NULL gateway id reads "gateway id not yet assigned"."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, gateway=None))
        resp = _get_page(client, _system_url())
    (line,) = _config_block(resp.text)["lines"]
    assert "app: Wiki Prod managed gateway id not yet assigned 1 connection" in line
    assert "gateway None" not in line and "gateway gw" not in line


def test_system_page_config_block_exact_with_null_app_says_unnamed(tmp_path: Path) -> None:
    """An exact snapshot whose ``app`` was rejected at ingest reads ``app: (unnamed)``."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, app_name=None))
        resp = _get_page(client, _system_url())
    cfg = _config_block(resp.text)
    assert "app: (unnamed) managed" in cfg["lines"][0]
    assert 'class="app-name is-unnamed"' in cfg["line_html"][0]


@pytest.mark.parametrize(
    ("match", "gateway", "text"),
    [
        (
            "none", "gw-d",
            "gwops matched no web app at this address on gateway gw-d "
            "(or had not yet read the tenant's web apps)",
        ),
        ("ambiguous", "gw-e", "gwops found more than one web app at this address on gateway gw-e"),
        (
            "none", None,
            "gwops matched no web app at this address (or had not yet read the tenant's web apps); "
            "gateway id not yet assigned",
        ),
        (
            "ambiguous", None,
            "gwops found more than one web app at this address (gateway id not yet assigned)",
        ),
    ],
    ids=["none", "ambiguous", "none-no-gateway-id", "ambiguous-no-gateway-id"],
)
def test_system_page_config_block_none_and_ambiguous(
    tmp_path: Path, match: str, gateway: str | None, text: str
) -> None:
    """``none`` / ``ambiguous``: fixed text, gateway id, ``TLS unknown``, no app element."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(
            app, "wc-1", 9 * 3600, match=match, gateway=gateway, app_name=None, managed=None,
            down=None, up=None, dport=None, uport=None,
        ))
        resp = _get_page(client, _system_url())
    cfg = _config_block(resp.text)
    assert cfg["lines"] == [
        f"TLS unknown {text} 1 connection · 2026-10-01T09:00:00.000Z → 2026-10-01T09:00:00.000Z"
    ]
    line = cfg["line_html"][0]
    assert 'class="pill pill-tls-unknown"' in line
    for absent in ("app:", "pill-managed", "pill-unmanaged", "app-name", "upstream"):
        assert absent not in line


def test_system_page_config_block_no_gwops_data(tmp_path: Path) -> None:
    """No object (and a connection with no ``connections`` row) read "No gwops data"."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, **NO_GWOPS))
        asyncio.run(_seed_web_conn(app, "wc-2", 9 * 3600 + 100, row=False, **NO_GWOPS))
        resp = _get_page(client, _system_url())
    cfg = _config_block(resp.text)
    # Both connections have the same (empty) snapshot, so they are ONE line.
    assert cfg["lines"] == [
        "TLS unknown No gwops data on these connections 2 connections · "
        "2026-10-01T09:00:00.000Z → 2026-10-01T09:01:40.000Z"
    ]
    line = cfg["line_html"][0]
    assert 'class="pill pill-tls-unknown"' in line
    for absent in ("app:", "gateway", "upstream", "pill-managed"):
        assert absent not in line


def test_system_page_config_block_two_configurations_in_one_window_newest_first(
    tmp_path: Path,
) -> None:
    """A mode change inside the window yields two lines, newest last-request first."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-old-1", 9 * 3600, down="none", up="none", dport=80, uport=80))
        asyncio.run(_seed_web_conn(app, "wc-old-2", 9 * 3600 + 60, down="none", up="none", dport=80, uport=80))
        asyncio.run(_seed_web_conn(app, "wc-new", 11 * 3600, n=3))
        resp = _get_page(client, _system_url())
    cfg = _config_block(resp.text)
    assert cfg["lines"] == [
        "HTTPS :443 → to upstream verify_full :443 app: Wiki Prod managed gateway gw-1 "
        "1 connection · 2026-10-01T11:00:00.000Z → 2026-10-01T11:00:02.000Z",
        "HTTP :80 → to upstream none :80 ! Plaintext upstream app: Wiki Prod managed gateway gw-1 "
        "2 connections · 2026-10-01T09:00:00.000Z → 2026-10-01T09:01:00.000Z",
    ]


def test_system_page_config_block_differs_by_gateway_id_for_one_address(tmp_path: Path) -> None:
    """Two gateways serving one address (GW-24) give two lines, one per gateway id."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-a", 9 * 3600, gateway="gw-aaa"))
        asyncio.run(_seed_web_conn(app, "wc-b", 9 * 3600 + 10, gateway="gw-bbb"))
        resp = _get_page(client, _system_url())
    lines = _config_block(resp.text)["lines"]
    assert len(lines) == 2
    assert any("gateway gw-aaa" in line for line in lines)
    assert any("gateway gw-bbb" in line for line in lines)


def test_system_page_config_block_caps_at_ten_lines_with_a_notice(tmp_path: Path) -> None:
    """Exactly 10 configurations: no notice. 11: the 10 newest and "More configurations not shown."."""
    app = create_app(_settings(_sub(tmp_path, "ten")))
    with TestClient(app) as client:
        for i in range(10):
            asyncio.run(_seed_web_conn(app, f"wc-{i:02d}", 9 * 3600 + i * 60, app_name=f"App {i:02d}"))
        ten = _config_block(_get_page(client, _system_url()).text)
    assert len(ten["lines"]) == 10
    assert ten["notice"] is None

    app = create_app(_settings(_sub(tmp_path, "eleven")))
    with TestClient(app) as client:
        for i in range(11):
            asyncio.run(_seed_web_conn(app, f"wc-{i:02d}", 9 * 3600 + i * 60, app_name=f"App {i:02d}"))
        eleven = _config_block(_get_page(client, _system_url()).text)
    assert len(eleven["lines"]) == 10
    assert eleven["notice"] == "More configurations not shown."
    joined = " | ".join(eleven["lines"])
    assert "App 10" in joined  # the newest is kept
    assert "App 00" not in joined  # the oldest is the one dropped
    assert eleven["footnote"] == WEB_FOOTNOTE  # the footnote still follows the notice


def test_system_page_config_block_footnote_text_is_exact(tmp_path: Path) -> None:
    """The configured-not-proof footnote (§8.5) is the exact fixed text."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600))
        resp = _get_page(client, _system_url())
    assert _config_block(resp.text)["footnote"] == WEB_FOOTNOTE


def test_system_page_config_block_escapes_app_name_with_html_metacharacters(
    tmp_path: Path,
) -> None:
    """An app name with tags, quotes, and ampersands renders as escaped text, never markup."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, app_name=HOSTILE_APP, managed=False))
        resp = _get_page(client, _system_url())
    assert resp.status_code == 200
    body = resp.text
    assert "<script>alert(1)</script>" not in body
    assert "<b>x</b>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "&lt;b&gt;x&lt;/b&gt;" in body
    assert "&amp;" in body
    (line,) = _config_block(body)["lines"]
    assert f"app: {HOSTILE_APP} unmanaged" in line  # unescapes back to the original text


def test_system_page_config_block_is_limited_to_the_window(tmp_path: Path) -> None:
    """Only connections with requests in the 7-day window feed the block (older ones do not)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-in", 9 * 3600, app_name="Inside"))
        # 2026-09-20 is before the 2026-09-25 window start.
        from tests.fixtures.timeline import add_connection, add_request

        async def old() -> None:
            await add_connection(
                app.state.db, "wc-old", user_id=WEB_USER_ID, username=WEB_USER,
                resource_address=WEB_ADDR, state="api", resource_type="WEB_APP",
                gwops_match="exact", gwops_gateway_id="gw-old", gwops_app="Outside",
                gwops_managed=True, downstream_tls="none", upstream_tls="none",
            )
            await add_request(
                app.state.db, "wc-old-r0", conn_id="wc-old",
                requested_at="2026-09-20T09:00:00.000Z", resource_address=WEB_ADDR,
                user_id=WEB_USER_ID, username=WEB_USER, url="/old", api_kind="web",
                kubectl_session=None, kubectl_command=None, downstream_tls="none",
                upstream_tls="none",
            )

        asyncio.run(old())
        resp = _get_page(client, _system_url())
    lines = _config_block(resp.text)["lines"]
    assert len(lines) == 1 and "Inside" in lines[0]
    assert "Outside" not in resp.text


def test_system_page_without_web_requests_has_no_web_sections(tmp_path: Path) -> None:
    """A kubectl-only system shows no configuration block and no Web activity table."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(SYSTEM_URL, headers=_auth_header())
    assert resp.status_code == 200
    assert "Configured web app TLS" not in resp.text
    assert "Web activity" not in resp.text
    assert "kubectl activity" in resp.text


# --- Web activity table ----------------------------------------------------------------


def _web_activity_rows(body: str) -> list[list[str]]:
    """Return the Web activity table rows as lists of visible cell texts."""
    section = re.search(
        r'<section class="activity-section" aria-labelledby="web-activity-heading">.*?</section>',
        body, re.S,
    )
    assert section is not None
    return [
        [_frag_text(td) for td in re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)]
        for tr in re.findall(r"<tr>(.*?)</tr>", section.group(0).split("<tbody>")[1], re.S)
    ]


def test_web_activity_table_row_contents_and_visit_link(tmp_path: Path) -> None:
    """One visit over two connections: user, start, end, duration, counts, and the Visit link."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=3))
        asyncio.run(_seed_web_conn(app, "wc-2", 9 * 3600 + 30, n=2, down="none", up="none"))
        resp = _get_page(client, _system_url())
        href = re.search(r'<a href="(/systems/[^"]*/web\?[^"]*)" aria-label="Visit view', resp.text)
        assert href is not None
        # Following the link renders that visit.
        visit = _get_page(client, html.unescape(href.group(1)))
    assert resp.status_code == 200
    (row,) = _web_activity_rows(resp.text)
    assert row == [
        f"{WEB_USER} ⌕", "2026-10-01T09:00:00.000Z", "2026-10-01T09:00:31.000Z", "0:31",
        "2", "5", "0", "Visit ›",
    ]
    assert html.unescape(href.group(1)) == (
        f"/systems/{WEB_ADDR}/web?user={WEB_USER_ID}"
        "&from=2026-10-01T09%3A00%3A00.000Z&to=2026-10-01T09%3A00%3A31.000Z"
    )
    assert visit.status_code == 200
    assert "<dt>Requests</dt><dd>5</dd>" in visit.text


def test_web_activity_table_counts_only_400_to_599_as_errors(tmp_path: Path) -> None:
    """4xx/5xx counts statuses 400-599: 399 and 600, 1xx, 2xx, and a NULL-status failed row are not."""
    statuses = [200, 399, 400, 404, 499, 500, 502, 599, 600, 101, None]
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=len(statuses), statuses=statuses))
        resp = _get_page(client, _system_url())
        visit_page = _get_page(
            client, _visit_url(WEB_ADDR, WEB_USER_ID, "2026-10-01T09:00:00Z", "2026-10-01T09:00:30Z")
        )
    (row,) = _web_activity_rows(resp.text)
    assert row[5] == "11"  # requests
    assert row[6] == "6"  # 400, 404, 499, 500, 502, 599
    assert '<span class="error-count">6</span>' in resp.text
    # The visit view counts the same way.
    assert "<dt>4xx/5xx</dt><dd>6</dd>" in visit_page.text
    assert "<dt>Requests</dt><dd>11</dd>" in visit_page.text


def test_web_activity_table_zero_errors_is_dim_and_visits_split_by_gap(tmp_path: Path) -> None:
    """No errors renders a dim 0; a gap over KUBECTL_ACTIVITY_GAP_SECONDS (900 s) splits visits."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=2))
        asyncio.run(_seed_web_conn(app, "wc-2", 9 * 3600 + 902, n=1))  # 901 s after the last
        asyncio.run(_seed_web_conn(app, "wc-3", 9 * 3600 + 100, n=1, user=("uid-web-2", "other.web@example.com")))
        resp = _get_page(client, _system_url())
    rows = _web_activity_rows(resp.text)
    assert len(rows) == 3  # two visits for the first user, one for the second
    assert all(r[6] == "0" for r in rows)
    assert resp.text.count('<span class="dim">0</span>') >= 3
    assert "error-count" not in resp.text


def test_web_activity_table_truncation_notice_when_the_row_cap_is_hit(
    tmp_path: Path, monkeypatch
) -> None:
    """At the window row cap the Web activity section says it is truncated."""
    monkeypatch.setattr(routes, "_ACTIVITY_MAX_ROWS", 3)
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=3))
        resp = _get_page(client, _system_url())
    assert "Showing the first 3 requests in this window" in _frag_text(resp.text)


def test_system_page_with_kubectl_and_web_rows_shows_both_activity_tables(
    tmp_path: Path, monkeypatch
) -> None:
    """A system with both kinds keeps its kubectl table and adds the Web one beside it."""
    app = create_app(_settings(tmp_path))
    captured = _capture_contexts(monkeypatch)
    with TestClient(app) as client:
        _feed_fixture(app)
        asyncio.run(_seed_web_conn(app, "wc-1", 10 * 3600 + 3 * 60, system=CLUSTER, n=2))
        resp = client.get(SYSTEM_URL, headers=_auth_header())
    ctx = captured["sessions.html"]
    assert ctx["show_kubectl_activity"] is True and ctx["show_web_activity"] is True
    assert len(ctx["activity_sessions"]) == 1 and len(ctx["web_activity_visits"]) == 1
    assert "kubectl activity" in resp.text and "Web activity" in resp.text
    # One shared window pager.
    assert resp.text.count('aria-label="Activity window"') == 1


# --- Visit route -----------------------------------------------------------------------


def test_visit_view_renders_requests_header_and_per_request_configured_tls(tmp_path: Path) -> None:
    """Visit table: time, method, stored URL, status, outcome, Configured TLS, connection (8 chars).

    The two connections have different snapshots, so the badges differ per request. The
    stored URL shows its masked query and an unmasked path.
    """
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(
            app, "https-conn-0001", 9 * 3600, n=2, urls=["/docs/search?term=se…(9)&page=…(1)", "/items/42"],
            statuses=[200, 404],
        ))
        asyncio.run(_seed_web_conn(
            app, "http-conn-00002", 9 * 3600 + 30, n=1, down="none", up="none", urls=["/legacy"],
            statuses=[101],
        ))
        resp = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    assert resp.status_code == 200
    body = resp.text
    assert "<th>Configured TLS</th>" in body
    assert body.count("<th>") == 7
    tbody = body.split("<tbody>")[1]
    rows = [
        [_frag_text(td) for td in re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)]
        for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", tbody, re.S)
    ]
    assert rows == [
        ["2026-10-01T09:00:00.000Z", "GET", "/docs/search?term=se…(9)&page=…(1)", "200", "completed",
         "HTTPS", "https-co"],
        ["2026-10-01T09:00:01.000Z", "GET", "/items/42", "404", "completed", "HTTPS", "https-co"],
        ["2026-10-01T09:00:30.000Z", "GET", "/legacy", "101 WebSocket", "completed",
         "HTTP ! Plaintext upstream", "http-con"],
    ]
    # Header block: system, span, counts.
    assert "<dt>Connections</dt><dd>2</dd>" in body
    assert "<dt>Requests</dt><dd>3</dd>" in body
    assert "<dt>4xx/5xx</dt><dd>1</dd>" in body
    assert f'<dd class="mono">{WEB_ADDR}</dd>' in body
    assert f'href="/search?type=web&amp;system={WEB_ADDR}"' in body
    assert f'<a class="user-link" href="/search?user={WEB_USER.replace("@", "%40")}">{WEB_USER}</a>' in body
    # Never a User-Agent, command, or header column.
    assert "User-Agent" not in body


def test_visit_view_shows_101_as_a_websocket_status_label(tmp_path: Path) -> None:
    """A 101 request shows its code and the fixed ``WebSocket`` label (status band 1xx)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=2, statuses=[101, 200]))
        resp = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    assert '<span class="status status-1xx">101</span> <span class="dim">WebSocket</span>' in resp.text
    # Only the 101 row carries the label.
    assert resp.text.count("WebSocket") == 1


def test_visit_view_failed_row_without_status_is_marked_failed_not_an_error(tmp_path: Path) -> None:
    """A failed (NULL-status) request shows the failed pill and a dash status, and is not a 4xx/5xx."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=2, statuses=[None, 200]))
        resp = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    assert '<span class="outcome-failed">' in resp.text
    assert 'class="is-failed"' in resp.text
    assert "<dt>4xx/5xx</dt><dd>0</dd>" in resp.text


def test_visit_view_has_its_own_configuration_block_for_the_visits_connections_only(
    tmp_path: Path,
) -> None:
    """The visit's block lists the visit's connections, not other users' on the same system."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-mine", 9 * 3600, app_name="Mine"))
        asyncio.run(_seed_web_conn(
            app, "wc-theirs", 9 * 3600 + 5, app_name="Theirs", down="none", up="none",
            user=("uid-web-2", "other.web@example.com"),
        ))
        mine = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
        system = _get_page(client, _system_url())
    cfg = _config_block(mine.text)
    assert len(cfg["lines"]) == 1 and "app: Mine managed" in cfg["lines"][0]
    assert "Theirs" not in mine.text
    assert cfg["footnote"] == WEB_FOOTNOTE
    # The system page, by contrast, lists both configurations.
    assert len(_config_block(system.text)["lines"]) == 2


def test_visit_view_escapes_hostile_app_and_url_text(tmp_path: Path) -> None:
    """The stored URL and gwops app name are attacker-influenced: escaped, never markup."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(
            app, "wc-1", 9 * 3600, app_name=HOSTILE_APP, managed=False,
            urls=['/x"><script>alert(2)</script>?a=<i>b</i>'],
        ))
        resp = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    body = resp.text
    assert "<script>alert" not in body
    assert "<i>b</i>" not in body
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_visit_view_inclusive_bounds_and_user_bucket(tmp_path: Path) -> None:
    """``from``/``to`` are inclusive; a NULL-user visit is addressed with ``user=_unknown``."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=2))
        asyncio.run(_seed_web_conn(app, "wc-anon", 10 * 3600, n=1, user=(None, None)))
        exact = _get_page(
            client, _visit_url(WEB_ADDR, WEB_USER_ID, "2026-10-01T09:00:00Z", "2026-10-01T09:00:01Z")
        )
        before = _get_page(
            client, _visit_url(WEB_ADDR, WEB_USER_ID, "2026-10-01T09:00:00.500Z", "2026-10-01T09:00:00.900Z")
        )
        anon = _get_page(
            client, _visit_url(WEB_ADDR, "_unknown", "2026-10-01T10:00:00Z", "2026-10-01T10:00:00Z")
        )
    assert exact.status_code == 200 and "<dt>Requests</dt><dd>2</dd>" in exact.text
    assert before.status_code == 404
    assert anon.status_code == 200
    assert "(unknown user)" in anon.text


def test_visit_view_unknown_system_bucket(tmp_path: Path) -> None:
    """Web requests with no resource address are reachable under the ``_unknown`` system slug."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, system=None))
        resp = _get_page(client, _visit_url("_unknown", WEB_USER_ID, T0, T1))
    assert resp.status_code == 200
    assert "(unknown)" in resp.text


def test_visit_view_requires_auth(tmp_path: Path) -> None:
    """The visit route is behind the UI Basic auth like every other page."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600))
        anonymous = client.get(_visit_url(WEB_ADDR, WEB_USER_ID, T0, T1), follow_redirects=False)
        wrong = client.get(
            _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1), headers=_auth_header("admin", "nope")
        )
    assert anonymous.status_code == 401
    assert anonymous.headers.get("WWW-Authenticate") == "Basic"
    assert wrong.status_code == 401


@pytest.mark.parametrize(
    ("query", "named"),
    [
        (f"from={T0}&to={T1}", "user"),
        (f"user=&from={T0}&to={T1}", "user"),
        (f"user={WEB_USER_ID}&to={T1}", "from"),
        (f"user={WEB_USER_ID}&from={T0}", "to"),
        (f"user={WEB_USER_ID}&from=SENTINELBAD&to={T1}", "from"),
        (f"user={WEB_USER_ID}&from={T0}&to=SENTINELBAD", "to"),
        (f"user={WEB_USER_ID}&from={'9' * 100}&to={T1}", "from"),
        (f"user={WEB_USER_ID}&user=SENTINELDUP&from={T0}&to={T1}", "user"),
        (f"user={WEB_USER_ID}&from={T0}&from={T0}&to={T1}", "from"),
        (f"user={WEB_USER_ID}&from={T0}&to={T1}&to={T1}", "to"),
        (f"user={WEB_USER_ID}&from={T1}&to={T0}", "from"),
        ("user=a%00SENTINELBAD&from=" + T0 + "&to=" + T1, "user"),
        (f"user={'u' * 513}&from={T0}&to={T1}", "user"),
    ],
    ids=[
        "no-user", "blank-user", "no-from", "no-to", "bad-from", "bad-to", "long-from",
        "dup-user", "dup-from", "dup-to", "from-after-to", "control-char-user", "long-user",
    ],
)
def test_visit_route_bad_parameters_are_400_naming_the_parameter(
    tmp_path: Path, query: str, named: str
) -> None:
    """Missing, malformed, repeated, or inverted parameters: 400 naming the parameter, not the value."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600))
        resp = _get_page(client, f"/systems/{WEB_ADDR}/web?{query}")
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert f"'{named}'" in detail
    assert "SENTINELBAD" not in resp.text and "SENTINELDUP" not in resp.text


def test_visit_route_discovery_parameter_is_not_accepted_or_needed(tmp_path: Path) -> None:
    """The visit route has no discovery toggle: an extra ``discovery`` parameter is simply ignored."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, urls=["/api"]))
        resp = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1) + "&discovery=1")
    assert resp.status_code == 200
    # GET /api is a kubectl discovery look-alike; on web it is an ordinary, listed request.
    assert '<td class="mono request-url">/api</td>' in resp.text
    assert "discovery</span>" not in resp.text


def test_visit_route_404_when_no_web_rows_in_bounds(tmp_path: Path) -> None:
    """404 for an empty window, another user, another system, or bounds holding only kubectl rows."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)  # kubectl rows on CLUSTER for USER_KEY, 2026-10-01T10:00-10:06
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600))
        empty_window = _get_page(
            client, _visit_url(WEB_ADDR, WEB_USER_ID, "2026-10-01T12:00:00Z", "2026-10-01T13:00:00Z")
        )
        wrong_user = _get_page(client, _visit_url(WEB_ADDR, "nobody", T0, T1))
        wrong_system = _get_page(client, _visit_url("other.corp.internal", WEB_USER_ID, T0, T1))
        kubectl_only = _get_page(client, _visit_url(CLUSTER, USER_KEY, SPAN_FROM, SPAN_TO))
    for resp in (empty_window, wrong_user, wrong_system, kubectl_only):
        assert resp.status_code == 404


def test_visit_route_truncation_notice_at_the_request_cap(tmp_path: Path, monkeypatch) -> None:
    """Over the cap: the first N rows and the notice. Exactly at the cap: complete, no notice."""
    monkeypatch.setattr(routes, "_WEB_VISIT_MAX_REQUESTS", 3)
    app = create_app(_settings(_sub(tmp_path, "over")))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=5))
        over = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    assert over.status_code == 200
    assert "Showing the first 3 requests of this visit" in _frag_text(over.text)
    assert "results are truncated" in over.text
    assert "<dt>Requests</dt><dd>3</dd>" in over.text
    assert len(re.findall(r'<td class="mono request-url">', over.text)) == 3
    assert "/page/2" in over.text and "/page/3" not in over.text

    app = create_app(_settings(_sub(tmp_path, "exact")))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=3))
        exact = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    assert exact.status_code == 200
    assert "results are truncated" not in exact.text
    assert len(re.findall(r'<td class="mono request-url">', exact.text)) == 3


def test_visit_route_cap_constant_is_2000() -> None:
    """The documented per-visit cap (§8.5) and the config cap (§8.5) are the shipped constants."""
    assert routes._WEB_VISIT_MAX_REQUESTS == 2000
    assert routes._WEB_CONFIG_MAX == 10


def test_kubectl_activity_route_never_renders_a_web_visit(tmp_path: Path) -> None:
    """The kubectl activity template is unreachable for web rows even with matching bounds."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=2))
        resp = _get_page(
            client,
            f"/systems/{WEB_ADDR}/activity?user={WEB_USER_ID}&from={T0}&to={T1}",
        )
    assert resp.status_code == 404


HOSTILE_SYSTEM = 'evil"><script>alert(9)<script>/sub.corp.internal'


def test_hostile_web_system_address_is_escaped_on_every_web_page(tmp_path: Path) -> None:
    """A resource address with markup, quotes and a ``/`` is escaped (and slug-encoded in links) everywhere.

    The address contains a ``/``, which ``_system_slug`` encodes as ``%2F``. The single
    ``/systems/{rest:path}`` route reads the raw path, so such an address is browsable: its
    system page and visit view both render (this used to be a 404 for every address with a ``/``).
    """
    slug = routes._system_slug(HOSTILE_SYSTEM)
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-evil", 9 * 3600, system=HOSTILE_SYSTEM, n=2))
        pages = {
            "systems": _get_page(client, "/systems"),
            "system": _get_page(client, f"/systems/{slug}?activity_before={WEB_BEFORE}"),
            "visit": _get_page(
                client, f"/systems/{slug}/web?user={WEB_USER_ID}&from={T0}&to={T1}"
            ),
            "search": _get_page(client, "/search?type=web"),
            "dashboard": _get_page(client, "/dashboard?window=all"),
        }
    for name, resp in pages.items():
        assert resp.status_code == 200, name
        assert "<script>alert(9)" not in resp.text, name
        assert 'evil"><' not in resp.text, name
        assert "evil&#34;&gt;&lt;script&gt;alert(9)&lt;script&gt;/sub.corp.internal" in resp.text, name
    # Links carry the slug-encoded form, never the raw characters.
    for href in re.findall(r'href="(/systems/[^"]*)"', pages["systems"].text):
        assert "<" not in html.unescape(href) and '"' not in html.unescape(href)


# =============================================================================================
# Session 12 fix loop: Q (one /systems/{path} route), I (row-level TLS), D (display escaping),
# cap notice, the unknown-system bucket with web rows, discovery on web connections
# =============================================================================================

from urllib.parse import quote  # noqa: E402

KUBE_USER_KEY = "VXNlcjoy"  # the user key ``_insert_request`` stores
KUBE_AT = "2026-10-01T09:30:00.000Z"

# Addresses that used to be unreachable or mis-linked: a CIDR, an encoded-looking address, one
# with ``?`` ``#`` and a space, and two that spell a sub-page name after a literal slash.
Q_ADDRESSES = [
    "10.0.0.0/24",
    "a%41.corp",
    "q?x#y z.corp",
    "100%.corp",
    "host/web",
    "host/activity",
]


def _seed_system_with_both_kinds(app, address: str | None, idx: int = 0) -> None:
    """A two-request web connection and one kubectl request on ``address``."""
    asyncio.run(_seed_web_conn(app, f"wc-q{idx}", 9 * 3600, system=address, n=2))
    _insert_request(
        app, request_id=f"kq-{idx}", resource_address=address, requested_at=KUBE_AT,
        conn_id=f"kconn-q{idx}", url="/api/v1/namespaces/default/pods/qpod",
    )


@pytest.mark.parametrize("address", Q_ADDRESSES)
def test_system_page_activity_and_visit_view_work_for_any_address(tmp_path: Path, address: str) -> None:
    """Q: system page, kubectl activity page and web visit view for an address with ``/ ? # % space``."""
    slug = routes._system_slug(address)
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_system_with_both_kinds(app, address)
        system = _get_page(client, f"/systems/{slug}?activity_before={WEB_BEFORE}")
        activity = _get_page(
            client, f"/systems/{slug}/activity?user={KUBE_USER_KEY}&from={KUBE_AT}&to={KUBE_AT}"
        )
        visit = _get_page(client, f"/systems/{slug}/web?user={WEB_USER_ID}&from={T0}&to={T1}")
    shown = html.escape(address)
    for name, resp in (("system", system), ("activity", activity), ("visit", visit)):
        assert resp.status_code == 200, (name, address, resp.status_code)
        assert shown in resp.text, (name, address)
    # Every link the pages build carries the canonical slug of the decoded address, never a re-decoded one.
    page_links = [html.unescape(h) for h in re.findall(r'href="(/systems/[^"]*)"', system.text + visit.text)]
    assert page_links, "no system links on the pages"
    for href in page_links:
        assert href == f"/systems/{slug}" or href.startswith((f"/systems/{slug}/", f"/systems/{slug}?")), href
    assert f"/systems/{slug}/web?user={WEB_USER_ID}&from=" in "".join(page_links)
    assert f"/systems/{slug}/activity?user={KUBE_USER_KEY}&from=" in "".join(page_links)


@pytest.mark.parametrize("address", Q_ADDRESSES)
def test_systems_index_and_search_rows_link_to_a_working_system_page(tmp_path: Path, address: str) -> None:
    """Q: the links the index and the search rows build (``_system_slug``) open the right system."""
    slug = routes._system_slug(address)
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_system_with_both_kinds(app, address)
        index = _get_page(client, "/systems")
        links = [html.unescape(h) for h in re.findall(r'href="(/systems/[^"]*)"', index.text)]
        assert f"/systems/{slug}" in links
        followed = _get_page(client, f"/systems/{slug}")
        search = client.get("/search?type=web", headers=_auth_header())
        search_links = [html.unescape(h) for h in re.findall(r'href="(/systems/[^"]*)"', search.text)]
    assert followed.status_code == 200 and html.escape(address) in followed.text
    assert f"/systems/{slug}" in search_links


def test_an_encoded_looking_address_is_decoded_exactly_once(tmp_path: Path) -> None:
    """Q: ``a%41.corp`` is the address ``a%41.corp``; it is not decoded a second time to ``aA.corp``."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-pct", 9 * 3600, system="a%41.corp", n=1))
        asyncio.run(_seed_web_conn(app, "wc-plain", 9 * 3600, system="aA.corp", n=1))
        real = _get_page(client, f"/systems/{quote('a%41.corp', safe='')}?activity_before={WEB_BEFORE}")
        other = _get_page(client, f"/systems/aA.corp?activity_before={WEB_BEFORE}")
    assert real.status_code == 200 and other.status_code == 200
    assert ">a%41.corp<" in real.text and "aA.corp" not in real.text
    assert ">aA.corp<" in other.text and "a%41.corp" not in other.text


def test_addresses_named_after_subpages_are_the_system_not_the_subpage(tmp_path: Path) -> None:
    """Q: the address ``host/web`` is the system ``host/web``; a literal ``/web`` after ``host`` is the visit view."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-hw", 9 * 3600, system="host/web", n=1))
        asyncio.run(_seed_web_conn(app, "wc-h", 9 * 3600, system="host", n=3))
        system_hw = _get_page(client, f"/systems/{quote('host/web', safe='')}?activity_before={WEB_BEFORE}")
        visit_h = _get_page(client, f"/systems/host/web?user={WEB_USER_ID}&from={T0}&to={T1}")
        visit_hw = _get_page(
            client, f"/systems/{quote('host/web', safe='')}/web?user={WEB_USER_ID}&from={T0}&to={T1}"
        )
    assert system_hw.status_code == 200 and "<title>" in system_hw.text
    assert ">host/web<" in system_hw.text
    assert visit_h.status_code == 200 and "<dt>Requests</dt><dd>3</dd>" in visit_h.text  # system "host"
    assert visit_hw.status_code == 200 and "<dt>Requests</dt><dd>1</dd>" in visit_hw.text  # system "host/web"


def test_systems_trailing_slash_redirects_to_the_index(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/systems/", headers=_auth_header(), follow_redirects=False)
    assert resp.status_code == 307
    assert resp.headers["location"] == "/systems"


@pytest.mark.parametrize("path", ["/systems/_unknown/activity", "/systems/_unknown/web"])
def test_unknown_system_subpages_need_their_parameters(tmp_path: Path, path: str) -> None:
    """A sub-page of the unknown bucket still validates its query (400), it is not a system page."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        assert _get_page(client, path).status_code == 400


# --- the unknown-system bucket with web rows (NULL resource_address) ---------------------------------


def test_unknown_system_page_renders_web_activity_and_the_config_block(tmp_path: Path) -> None:
    """``/systems/_unknown`` with only web rows: Web activity table, config block, no kubectl table."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-null", 9 * 3600, system=None, n=2))
        has_kinds = asyncio.run(app.state.repo.system_api_kinds(None))
        resp = _get_page(client, f"/systems/_unknown?activity_before={WEB_BEFORE}")
        systems = _get_page(client, "/systems")
    assert has_kinds == (False, True)
    assert resp.status_code == 200
    assert "(unknown)" in resp.text
    (row,) = _web_activity_rows(resp.text)
    assert row[0].startswith(WEB_USER) and row[5] == "2"
    cfg = _config_block(resp.text)
    assert len(cfg["lines"]) == 1 and "app: Wiki Prod managed" in cfg["lines"][0]
    assert "kubectl activity" not in resp.text
    assert "/systems/_unknown" in html.unescape(systems.text)


# --- cap notice ---------------------------------------------------------------------------------------


def test_activity_cap_notice_is_the_fixed_text_with_the_module_constant(
    tmp_path: Path, monkeypatch
) -> None:
    """The cap notice reads exactly as specified, formatted from ``_ACTIVITY_MAX_ROWS``."""
    monkeypatch.setattr(routes, "_ACTIVITY_MAX_ROWS", 3)
    captured = _capture_contexts(monkeypatch)
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _feed_fixture(app)
        resp = client.get(SYSTEM_URL, headers=_auth_header())
    expected = (
        "Showing the first 3 requests in this window, ordered by user; users later in the list may be omitted."
    )
    assert captured["sessions.html"]["activity_cap_notice"] == expected
    assert expected in _frag_text(resp.text)
    assert routes._ACTIVITY_CAP_TEXT.format(n=20000) == (
        "Showing the first 20,000 requests in this window, ordered by user; users later in the list "
        "may be omitted."
    )


def test_activity_cap_constant_is_20000_and_the_default_text_says_so() -> None:
    assert routes._ACTIVITY_MAX_ROWS == 20000
    assert "first 20,000 requests" in routes._ACTIVITY_CAP_TEXT.format(n=routes._ACTIVITY_MAX_ROWS)


# --- I: row-level configured TLS wins over the connection snapshot ---------------------------------


def _set_row_tls(app, request_id: str, down: str | None, up: str | None) -> None:
    """Overwrite the TLS modes stored on one request row (the snapshot is left alone)."""
    async def run() -> None:
        await app.state.db.execute(
            "UPDATE api_requests SET downstream_tls = ?, upstream_tls = ? WHERE request_id = ?",
            (down, up, request_id),
        )
        await app.state.db.commit()

    asyncio.run(run())


def _visit_row_texts(body: str) -> list[list[str]]:
    tbody = body.split("<tbody>")[1]
    return [
        [_frag_text(td) for td in re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)]
        for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", tbody, re.S)
    ]


def test_visit_view_prefers_the_modes_stored_on_the_row_over_the_snapshot(tmp_path: Path) -> None:
    """I: the row says HTTP / unverified, the snapshot says HTTPS / verified: the row wins, per request."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        ids = asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=3, down="tls13", up="verify_full"))
        _set_row_tls(app, ids[0], "none", "insecure")  # row-level differs
        _set_row_tls(app, ids[1], None, None)  # row-level absent: fall back to the snapshot
        # ids[2] keeps its row-level tls13 / verify_full
        resp = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    rows = _visit_row_texts(resp.text)
    assert [r[5] for r in rows] == ["HTTP ! Unverified upstream", "HTTPS", "HTTPS"]


def test_visit_view_falls_back_to_the_snapshot_when_the_row_carries_no_modes(tmp_path: Path) -> None:
    """I: a pre-upgrade row (both NULL) shows the connection snapshot, e.g. Plaintext upstream."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        ids = asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=1, down="none", up="none"))
        _set_row_tls(app, ids[0], None, None)
        resp = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    (row,) = _visit_row_texts(resp.text)
    assert row[5] == "HTTP ! Plaintext upstream"


def test_visit_view_marks_an_unrecognised_downstream_mode(tmp_path: Path) -> None:
    """I: a stored client mode outside the vocabulary shows the warning marker, not "TLS unknown"."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        ids = asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=1, down="tls13", up="verify_full"))
        _set_row_tls(app, ids[0], "SENTINEL-DOWN", "verify_full")
        resp = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    (row,) = _visit_row_texts(resp.text)
    assert row[5] == "! Unrecognised TLS mode"
    assert 'class="marker marker-warn"' in resp.text
    assert "TLS unknown" not in resp.text and "SENTINEL-DOWN" not in resp.text


def test_visit_view_marks_an_unrecognised_upstream_mode_never_as_verified(tmp_path: Path) -> None:
    """I: an unknown upstream mode shows its own warning marker (not the no-marker ``verify_full`` look)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        ids = asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=1))
        _set_row_tls(app, ids[0], "tls13", "SENTINEL-UP")
        resp = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    (row,) = _visit_row_texts(resp.text)
    assert row[5] == "HTTPS ! Unrecognised upstream TLS mode"
    assert 'class="marker marker-warn"' in resp.text
    assert "SENTINEL-UP" not in resp.text


def test_config_block_uses_the_first_rows_modes_and_the_snapshots_ports_and_app(tmp_path: Path) -> None:
    """I: the block's TLS pair is the earliest row's own modes; ports, app and gateway come from the snapshot."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        ids = asyncio.run(_seed_web_conn(
            app, "wc-1", 9 * 3600, n=2, down="tls13", up="verify_full", dport=443, uport=8443,
            app_name="Row Wins", gateway="gw-row",
        ))
        _set_row_tls(app, ids[0], "none", "none")
        system = _get_page(client, _system_url())
        visit = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    for resp in (system, visit):
        (line,) = _config_block(resp.text)["lines"]
        assert line.startswith("HTTP :443 → to upstream none :8443 ! Plaintext upstream app: Row Wins managed gateway gw-row")


def test_config_block_unrecognised_modes_read_unrecognised_and_never_the_raw_value(tmp_path: Path) -> None:
    """I: an ``exact`` line with unknown modes shows the warning badges and the fixed text ``unrecognised``."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=1, down="SENTINEL-D", up="SENTINEL-U"))
        system = _get_page(client, _system_url())
        visit = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    for resp in (system, visit):
        (line,) = _config_block(resp.text)["lines"]
        assert "! Unrecognised TLS mode" in line
        assert "upstream unrecognised" in line
        assert "! Unrecognised upstream TLS mode" in line
        assert "SENTINEL" not in resp.text
        assert resp.text.count('class="marker marker-warn"') >= 2


def test_config_block_exact_without_an_upstream_mode_reads_unknown(tmp_path: Path) -> None:
    """The ``unknown`` text is for a NULL mode; ``unrecognised`` is for a stored non-vocabulary value."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=1, down="tls13", up=None))
        resp = _get_page(client, _system_url())
    (line,) = _config_block(resp.text)["lines"]
    assert "upstream unknown" in line and "unrecognised" not in line


# --- D: display escaping on the visit view and the kubectl activity page --------------------------

_RLO = "‮"
_ZWSP = "​"


def test_visit_view_percent_encodes_control_and_format_characters_in_urls(tmp_path: Path) -> None:
    """D: U+202E, a tab and a zero-width space in a stored URL are shown percent-encoded."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(
            app, "wc-1", 9 * 3600, n=1, urls=[f"/doc{_RLO}/evil\tpath{_ZWSP}end"],
        ))
        resp = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    assert resp.status_code == 200
    assert _RLO not in resp.text and _ZWSP not in resp.text
    assert '<td class="mono request-url">/doc%E2%80%AE/evil%09path%E2%80%8Bend</td>' in resp.text


def test_kubectl_activity_page_percent_encodes_control_and_format_characters_in_urls(tmp_path: Path) -> None:
    """D: the kubectl activity page's primary path and request lines are display-escaped too."""
    app = create_app(_settings(tmp_path))
    url = f"/api/v1/namespaces/x/pods/a{_RLO}b\tc{_ZWSP}d"
    with TestClient(app) as client:
        _insert_request(
            app, request_id="kd-1", resource_address=CLUSTER, requested_at=KUBE_AT, url=url, method="DELETE",
        )
        resp = _get_page(
            client, f"/systems/{CLUSTER}/activity?user={KUBE_USER_KEY}&from={KUBE_AT}&to={KUBE_AT}"
        )
    assert resp.status_code == 200
    assert _RLO not in resp.text and _ZWSP not in resp.text
    shown = "/api/v1/namespaces/x/pods/a%E2%80%AEb%09c%E2%80%8Bd"
    assert f'<span class="mono request-url">{shown}</span>' in resp.text
    assert f'<td class="mono request-url">{shown}' in resp.text


# --- discovery on web connections (WEBAPP_SPEC 7.2) -------------------------------------------------


def _seed_api_discovery_rows(app) -> None:
    """A web connection whose only request is ``GET /api`` and a kubectl discovery-only command."""
    from tests.fixtures.timeline import add_connection, add_request, at

    asyncio.run(add_connection(
        app.state.db, "wd-conn", user_id="uid-w", username="w@example.com",
        resource_address="disc.corp.internal", state="api", resource_type="WEB_APP",
    ))
    asyncio.run(add_request(
        app.state.db, "wd-r0", conn_id="wd-conn", requested_at=at("09:00:00.000"),
        resource_address="disc.corp.internal", user_id="uid-w", username="w@example.com",
        url="/api", method="GET", api_kind="web", user_agent=None,
    ))
    asyncio.run(add_request(
        app.state.db, "kd-r0", conn_id="kd-conn", requested_at=at("08:00:00.000"),
        resource_address="kdisc.example.internal", user_id="uid-k", username="k@example.com",
        url="/api?timeout=32s", method="GET", kubectl_session="ks-disc", kubectl_command="kubectl get",
    ))


@pytest.mark.parametrize("discovery", ["", "&discovery=1", "&discovery=0"])
@pytest.mark.parametrize("type_", ["web", "any"])
def test_a_web_connection_with_only_get_api_is_listed_with_and_without_discovery(
    tmp_path: Path, type_: str, discovery: str
) -> None:
    """Web has no discovery step: ``GET /api`` on a web connection is a normal row either way."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_api_discovery_rows(app)
        resp = _get_page(client, f"/search?type={type_}{discovery}")
    assert resp.status_code == 200
    assert 'class="pill pill-web"' in resp.text
    assert '<span class="mono request-url">/api</span>' in resp.text
    kubectl_listed = 'class="pill pill-kubectl"' in resp.text
    assert kubectl_listed == (type_ == "any" and discovery == "&discovery=1")  # kubectl discovery stays opt-in


def test_visit_view_never_marks_a_web_request_as_discovery(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        asyncio.run(_seed_web_conn(app, "wc-1", 9 * 3600, n=2, urls=["/api", "/apis/apps/v1"]))
        resp = _get_page(client, _visit_url(WEB_ADDR, WEB_USER_ID, T0, T1))
    assert '<span class="tag">discovery</span>' not in resp.text and "is-discovery" not in resp.text
    assert "/api</td>" in resp.text and "/apis/apps/v1</td>" in resp.text
