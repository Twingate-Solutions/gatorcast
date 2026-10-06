"""Smoke tests for the search, dashboard, and findings UI (Sessions 9 + 10).

Mirrors ``tests/test_web.py``: synchronous FastAPI ``TestClient`` with async store
helpers driven by ``asyncio.run()`` inside the ``with TestClient(app)`` block (after
lifespan has wired ``app.state.repo`` / ``app.state.casts`` / ``app.state.search``).

Every assertion that touches recorded content enforces CLAUDE.md rule 6: the unique
marker baked into the seeded recording must NEVER appear in any rendered HTML or CSV.
The marker is only ever reachable through the auth-gated, player-only ``/cast`` route.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import csv
import html as html_lib
import io
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gatorcast.config import Settings
from gatorcast.main import create_app
from gatorcast.pipeline.detect import Finding

# A unique string embedded in the seeded recording + a flagged "rm -rf" command.
# The marker must never leak into HTML/CSV (rule 6); the rm -rf gives the
# recursive-delete rule something to flag.
UNIQUE_MARKER = "ZZUNIQUEMARKER42"
SEEDED_PLAINTEXT = f"hello {UNIQUE_MARKER}\nrm -rf /etc\n"
SEEDED_CAST = (
    '{"version":2,"width":80,"height":24,"timestamp":1700000000,"user":"ubuntu"}\n'
    f'[0.1,"o","hello {UNIQUE_MARKER}"]\n'
    '[0.2,"o","rm -rf /etc"]\n'
)


def _settings(tmp_path: Path) -> Settings:
    """Settings with syslog disabled, test auth creds, isolated data dir."""
    return Settings(
        data_dir=tmp_path,
        syslog_tcp_port=0,
        ui_auth_username="admin",
        ui_auth_password="change-me",
    )


def _auth_header(username: str = "admin", password: str = "change-me") -> dict[str, str]:
    """Build an Authorization: Basic header."""
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _seed_flagged(
    app,
    *,
    conn_id: str,
    username: str,
    resource_address: str | None,
    started_at: str = "2026-01-01T10:00:00Z",
) -> None:
    """Seed a complete session + cast + sidecar + a recursive-delete finding.

    Must run INSIDE ``with TestClient(app)`` so lifespan has wired app.state.
    """
    repo = app.state.repo
    casts = app.state.casts
    search = app.state.search

    asyncio.run(
        repo.upsert_start(
            conn_id=conn_id,
            username=username,
            resource_address=resource_address,
            started_at=started_at,
        )
    )
    cast_path, _ = asyncio.run(casts.write_cast(conn_id, SEEDED_CAST))
    asyncio.run(casts.write_sidecar(conn_id, SEEDED_PLAINTEXT))
    asyncio.run(
        repo.finalize(
            conn_id,
            username=username,
            shell_user="ubuntu",
            started_at=started_at,
            ended_at="2026-01-01T10:05:00Z",
            duration_seconds=300.0,
            width=80,
            height=24,
            chunk_count=1,
            size_bytes=cast_path.stat().st_size,
            cast_path=str(cast_path),
            status="complete",
        )
    )
    finding = Finding(
        rule_id="recursive-delete",
        category="dangerous-command",
        severity="high",
        label="Recursive delete (rm -rf)",
        offset_seconds=0.2,
    )
    asyncio.run(search.replace_findings(conn_id, [finding]))
    asyncio.run(repo.update_finding_summary(conn_id, 1, "high"))


_EXTERNAL_SRC_HREF = re.compile(
    r'(?:src|href)\s*=\s*["\'](?P<url>https?://[^"\']+)["\']',
    re.IGNORECASE,
)


def _external_urls_in_html(html: str) -> list[str]:
    """Return all http(s):// URLs found in src= or href= attributes."""
    return [m.group("url") for m in _EXTERNAL_SRC_HREF.finditer(html)]


def _hrefs(body: str) -> list[str]:
    """Return every ``href`` value in ``body``, HTML-unescaped (``&amp;`` → ``&``)."""
    return [html_lib.unescape(h) for h in re.findall(r'href="([^"]*)"', body)]


# ---------------------------------------------------------------------------
# Auth enforcement
# ---------------------------------------------------------------------------


def test_search_requires_auth(tmp_path: Path) -> None:
    """No credentials on /search → 401."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/search", follow_redirects=False)
    assert resp.status_code == 401


def test_dashboard_requires_auth(tmp_path: Path) -> None:
    """No credentials on /dashboard → 401."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Root redirect now points at the dashboard
# ---------------------------------------------------------------------------


def test_root_redirects_to_dashboard(tmp_path: Path) -> None:
    """GET / → 307 redirect to /dashboard."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/", headers=_auth_header(), follow_redirects=False)
    assert resp.status_code == 307
    assert resp.headers["location"] == "/dashboard"


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


def test_dashboard_shows_counts(tmp_path: Path) -> None:
    """Dashboard renders total + flagged session counts (no recorded content).

    Uses ``window=all`` so the fixed seed date is in range regardless of wall clock.
    """
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="d1", username="alice@x", resource_address="prod.host")
        resp = client.get("/dashboard?window=all", headers=_auth_header())
    assert resp.status_code == 200
    body = resp.text
    # One total session, one flagged.
    assert "alice@x" in body or "prod.host" in body  # a breakdown row rendered
    assert "1" in body
    assert UNIQUE_MARKER not in body


def test_dashboard_breakdowns_link_to_search_and_systems(tmp_path: Path) -> None:
    """Severity/category/user rows deep-link to search with canonical names; systems to its page."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="d1", username="alice@x", resource_address="prod.host")
        resp = client.get("/dashboard?window=all", headers=_auth_header())
    assert resp.status_code == 200
    hrefs = _hrefs(resp.text)
    # Severity drill-down uses the EXACT max_severity filter, scoped to recordings.
    assert "/search?type=recordings&window=all&max_severity=high" in hrefs
    # Category drill-down.
    assert "/search?type=recordings&window=all&category=dangerous-command" in hrefs
    # Top-user row links to that user's activity in search (canonical `user`).
    assert "/search?user=alice%40x&window=all" in hrefs
    # Top-system row links to the system's session list page.
    assert "/systems/prod.host" in hrefs
    # Window toggle is present.
    assert "/dashboard?window=7" in hrefs and "/dashboard?window=all" in hrefs
    # No legacy parameter name is emitted anywhere on the page.
    for legacy in ("username=", "started_after=", "started_before=", "resource_address="):
        assert not any(legacy in h for h in hrefs), legacy


def test_dashboard_window_filters_by_time(tmp_path: Path) -> None:
    """A 7-day window excludes an old session's top-user row that ``window=all`` includes."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(tz=timezone.utc)
    recent = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    old = (now - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")

    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(
            app, conn_id="recent", username="recent@x",
            resource_address="r.host", started_at=recent,
        )
        _seed_flagged(
            app, conn_id="old", username="old@x",
            resource_address="o.host", started_at=old,
        )
        within = _hrefs(client.get("/dashboard?window=7", headers=_auth_header()).text)
        everything = _hrefs(client.get("/dashboard?window=all", headers=_auth_header()).text)

    # 7-day window: only the recent user has a top-user row. (The all-time feed may
    # still link both users with a bare user= link; top-user links carry a window.)
    assert "/search?user=recent%40x&window=7" in within
    assert "/search?user=old%40x&window=7" not in within
    # All-time: both appear.
    assert "/search?user=recent%40x&window=all" in everything
    assert "/search?user=old%40x&window=all" in everything


def test_dashboard_has_no_external_asset_urls(tmp_path: Path) -> None:
    """Rule 8: dashboard HTML references no external assets."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/dashboard", headers=_auth_header())
    assert resp.status_code == 200
    assert _external_urls_in_html(resp.text) == []


# ---------------------------------------------------------------------------
# Search — keyword (content scan), rule 6 marker must not leak
# ---------------------------------------------------------------------------


def test_search_keyword_lists_flagged_session_without_leaking_marker(tmp_path: Path) -> None:
    """keyword=rm matches the flagged session; the badge/label show; marker absent."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="k1", username="bob@x", resource_address="db.host")
        resp = client.get("/search?keyword=rm", headers=_auth_header())
    assert resp.status_code == 200
    body = resp.text
    assert "k1" in body
    assert "Recursive delete (rm -rf)" in body  # rule label rendered
    # Rule 6: raw recorded content must NEVER appear in the results HTML.
    assert UNIQUE_MARKER not in body


def test_search_rule_ids_narrows_to_flagged_session(tmp_path: Path) -> None:
    """rule_ids=recursive-delete narrows results to the flagged session."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="r1", username="carol@x", resource_address="db.host")
        resp = client.get("/search?rule_ids=recursive-delete", headers=_auth_header())
    assert resp.status_code == 200
    body = resp.text
    assert "r1" in body
    assert UNIQUE_MARKER not in body


def test_search_metadata_filters_apply(tmp_path: Path) -> None:
    """username + started_after metadata filters return 200 and match."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="m1", username="dave@x", resource_address="db.host")
        resp = client.get(
            "/search?username=dave@x&started_after=2026-01-01T00:00:00Z",
            headers=_auth_header(),
        )
    assert resp.status_code == 200
    assert "m1" in resp.text


def test_search_blank_params_do_not_filter(tmp_path: Path) -> None:
    """Empty-string form fields are treated as absent, not as literal '' filters."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="b1", username="erin@x", resource_address="db.host")
        resp = client.get(
            "/search?username=&resource_address=&status=&min_duration=&max_duration=",
            headers=_auth_header(),
        )
    assert resp.status_code == 200
    assert "b1" in resp.text


def test_search_has_no_external_asset_urls(tmp_path: Path) -> None:
    """Rule 8: search HTML references no external assets."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/search", headers=_auth_header())
    assert resp.status_code == 200
    assert _external_urls_in_html(resp.text) == []


def test_search_htmx_returns_partial_only(tmp_path: Path) -> None:
    """HX-Request header → results fragment only (no <html>, no site nav)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="h1", username="fred@x", resource_address="db.host")
        resp = client.get(
            "/search", headers={**_auth_header(), "HX-Request": "true"}
        )
    assert resp.status_code == 200
    body = resp.text
    assert "<html" not in body.lower()
    assert "site-header" not in body  # nav chrome from base.html absent


# ---------------------------------------------------------------------------
# CSV export — metadata + finding summary only (no recorded content)
# ---------------------------------------------------------------------------


def test_search_export_csv(tmp_path: Path) -> None:
    """CSV export: text/csv, header + session row, finding label present, no marker."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="csv1", username="gwen@x", resource_address="db.host")
        resp = client.get("/search/export.csv", headers=_auth_header())
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    body = resp.text
    assert "conn_id" in body  # header row
    assert "csv1" in body  # session row
    assert "Recursive delete (rm -rf)" in body  # finding label summary
    # Rule 6: recorded content must NEVER appear in the CSV.
    assert UNIQUE_MARKER not in body


# ---------------------------------------------------------------------------
# CSV export on the unified engine (Session 10 T6, spec §9 / §12)
# ---------------------------------------------------------------------------

CSV_HEADER = [
    "conn_id",
    "username",
    "resource_address",
    "status",
    "started_at",
    "ended_at",
    "duration_seconds",
    "finding_count",
    "max_severity",
    "findings",
    "kind",
    "command",
    "method",
    "path",
    "request_count",
]

FORMULA_CHARS = ["=", "+", "-", "@", "\t", "\r"]


def _csv_rows(resp) -> list[list[str]]:
    """Parse a CSV response body into rows (header first)."""
    return list(csv.reader(io.StringIO(resp.text)))


def _export(client: TestClient, query: str = ""):
    """GET the CSV export with auth; ``query`` is the part after ``?``."""
    url = "/search/export.csv" + (f"?{query}" if query else "")
    return client.get(url, headers=_auth_header())


def _run(coro) -> None:
    """Run one fixture coroutine (inside ``with TestClient(app)``)."""
    asyncio.run(coro)


def test_csv_requires_auth(tmp_path: Path) -> None:
    """No credentials on the export → 401."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/search/export.csv")
    assert resp.status_code == 401


def test_csv_header_is_exactly_15_columns(tmp_path: Path) -> None:
    """The header row is the 15 spec §9 columns, in order, even with no results."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = _export(client)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert 'filename="gatorcast-search.csv"' in resp.headers["content-disposition"]
    rows = _csv_rows(resp)
    assert rows == [CSV_HEADER]
    assert "x-gatorcast-truncated" not in resp.headers


def test_csv_legacy_export_columns_1_to_10_unchanged(tmp_path: Path) -> None:
    """A Session 8 legacy-param export keeps columns 1–10 exactly; 11 = kind, 12–15 empty."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="csv1", username="gwen@x", resource_address="db.host")
        resp = _export(client, "username=gwen%40x&started_after=2026-01-01T00:00:00Z")
    assert resp.status_code == 200
    rows = _csv_rows(resp)
    assert rows[0] == CSV_HEADER
    assert len(rows) == 2
    row = rows[1]
    assert len(row) == 15
    # Exactly what the Session 8 export wrote for this session.
    assert row[:10] == [
        "csv1",
        "gwen@x",
        "db.host",
        "complete",
        "2026-01-01T10:00:00Z",
        "2026-01-01T10:05:00Z",
        "300.0",
        "1",
        "high",
        "Recursive delete (rm -rf)@0.2s",
    ]
    assert row[10:] == ["ssh", "", "", "", ""]
    assert UNIQUE_MARKER not in resp.text


def test_csv_kubectl_row_fills_columns_11_to_15(tmp_path: Path) -> None:
    """A kubectl command fills 11–15; no query string, no full User-Agent."""
    from tests.fixtures.timeline import PROD, add_request, at

    full_ua = "kubectl/v1.30.0 (linux/amd64) kubernetes/UASENTINEL"
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        db = app.state.db
        _run(add_request(
            db, "rq-1", conn_id="conn-k1", requested_at=at("11:00:00.000"),
            user_id="uid-ann", username="ann@x", url="/api/v1/namespaces/default/pods?limit=500",
            kubectl_session="ks-k1", kubectl_command="kubectl delete", user_agent=full_ua,
        ))
        _run(add_request(
            db, "rq-2", conn_id="conn-k1", requested_at=at("11:00:02.500"),
            user_id="uid-ann", username="ann@x", method="DELETE",
            url="/api/v1/namespaces/default/pods/web-2?gracePeriodSeconds=0",
            kubectl_session="ks-k1", kubectl_command="kubectl delete", user_agent=full_ua,
            findings=[("kube-delete", "high", "Resource delete")],
        ))
        # A command with no Kubectl-Command: labelled by the UA product token only.
        _run(add_request(
            db, "rq-ua", conn_id="conn-ua", requested_at=at("10:00:00.000"),
            user_id="uid-ann", username="ann@x", url="/api/v1/nodes?watch=true",
            kubectl_command=None, user_agent="k9s/v0.32.5 (linux/amd64) UASENTINEL",
        ))
        resp = _export(client, "type=kubectl")
    assert resp.status_code == 200
    rows = _csv_rows(resp)
    assert rows[0] == CSV_HEADER
    assert rows[1] == [
        "conn-k1",
        "ann@x",
        PROD,
        "",
        at("11:00:00.000"),
        at("11:00:02.500"),
        "2.5",
        "1",
        "high",
        "Resource delete",
        "kubectl",
        "kubectl delete",
        "DELETE",
        "/api/v1/namespaces/default/pods/web-2",
        "2",
    ]
    assert rows[2][10:] == ["kubectl", "k9s", "GET", "/api/v1/nodes", "1"]
    # Allowlist: no query-string values and no full User-Agent anywhere.
    assert "UASENTINEL" not in resp.text
    assert "gracePeriodSeconds" not in resp.text
    assert "limit=500" not in resp.text
    assert "?" not in resp.text


def test_csv_failed_connection_kind_is_failed(tmp_path: Path) -> None:
    """kind is failed / ssh (error with chunks) / exec per the §4.2 predicates."""
    from tests.fixtures.timeline import PROD, add_session, at

    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        db = app.state.db
        _run(add_session(db, "s-failed", started_at=at("10:15:00.000"), username="a@x",
                         status="error", chunk_count=0, cast_path=None))
        _run(add_session(db, "s-err", started_at=at("10:20:00.000"), username="a@x",
                         status="error", chunk_count=3))
        _run(add_session(db, "s-exec", started_at=at("10:10:00.000"), username="a@x",
                         resource_address=PROD, request_id="req-exec-1", duration=4.0))
        resp = _export(client, "type=recordings")
    assert resp.status_code == 200
    kinds = {row[0]: row[10] for row in _csv_rows(resp)[1:]}
    assert kinds == {"s-failed": "failed", "s-err": "ssh", "s-exec": "exec"}


def test_csv_mixed_export_interleaves_kinds(tmp_path: Path) -> None:
    """The default (type=any) export mixes recordings and commands, newest first."""
    from tests.fixtures.timeline import add_request, add_session, at

    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        db = app.state.db
        _run(add_session(db, "s-old", started_at=at("10:00:00.000"), username="a@x"))
        _run(add_request(db, "rq-mid", conn_id="conn-mid", requested_at=at("11:00:00.000"),
                         username="a@x", kubectl_session="ks-mid", kubectl_command="kubectl get"))
        _run(add_session(db, "s-new", started_at=at("12:00:00.000"), username="a@x"))
        resp = _export(client)
    assert resp.status_code == 200
    body = _csv_rows(resp)[1:]
    assert [(r[0], r[10]) for r in body] == [
        ("s-new", "ssh"),
        ("conn-mid", "kubectl"),
        ("s-old", "ssh"),
    ]
    assert "x-gatorcast-truncated" not in resp.headers


@pytest.mark.parametrize("value", ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"])
def test_csv_safe_prefixes_formula_text(value: str) -> None:
    """_csv_safe prefixes a text cell starting with each formula character."""
    from gatorcast.web.routes import _csv_safe

    assert _csv_safe(value) == "'" + value


def test_csv_safe_leaves_other_cells() -> None:
    """Plain text, inner formula characters, and numbers are unchanged."""
    from gatorcast.web.routes import _csv_safe

    assert _csv_safe("kubectl get") == "kubectl get"
    assert _csv_safe("a=b") == "a=b"
    assert _csv_safe("") == ""
    assert _csv_safe(-1.5) == -1.5
    assert _csv_safe(3) == 3


@pytest.mark.parametrize("ch", FORMULA_CHARS, ids=["eq", "plus", "minus", "at", "tab", "cr"])
def test_csv_formula_guard_every_text_column(tmp_path: Path, ch: str) -> None:
    """Each formula character is neutralized in every client-influenced text column.

    The recording carries ``ch`` in conn_id, username, resource_address, status,
    ended_at, max_severity, and its finding label; the kubectl command in conn_id,
    username, resource_address, kubectl_command, method, and path. No parsed cell in
    the export may start with a formula character.
    """
    from tests.fixtures.timeline import add_request, add_session, at

    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        db = app.state.db
        _run(add_session(db, f"{ch}rec", started_at=at("10:00:00.000"), username=f"{ch}user",
                         resource_address=f"{ch}sys", status=f"{ch}status",
                         findings=[("r1", "dangerous-command", "high", f"{ch}label", 1.0)]))
        _run(db.execute(
            "UPDATE sessions SET ended_at = ?, max_severity = ? WHERE conn_id = ?",
            (f"{ch}end", f"{ch}sev", f"{ch}rec"),
        ))
        _run(db.commit())
        _run(add_request(db, "rq-f", conn_id=f"{ch}conn", requested_at=at("11:00:00.000"),
                         username=f"{ch}kuser", resource_address=f"{ch}cluster",
                         method=f"{ch}GET", url=f"{ch}/api/v1/pods",
                         kubectl_session="ks-f", kubectl_command=f"{ch}cmd|calc"))
        resp = _export(client)
    assert resp.status_code == 200
    rows = _csv_rows(resp)[1:]
    assert len(rows) == 2
    for row in rows:
        for cell in row:
            assert not cell.startswith(tuple(FORMULA_CHARS)), (row, cell)
    by_kind = {row[10]: row for row in rows}
    cmd = by_kind["kubectl"]
    assert cmd[0] == f"'{ch}conn"
    assert cmd[1] == f"'{ch}kuser"
    assert cmd[2] == f"'{ch}cluster"
    assert cmd[11] == f"'{ch}cmd|calc"
    assert cmd[12] == f"'{ch}GET"
    assert cmd[13] == f"'{ch}/api/v1/pods"
    rec = by_kind["ssh"]
    assert rec[0] == f"'{ch}rec"
    assert rec[1] == f"'{ch}user"
    assert rec[2] == f"'{ch}sys"
    assert rec[3] == f"'{ch}status"
    assert rec[5] == f"'{ch}end"
    assert rec[8] == f"'{ch}sev"
    assert rec[9] == f"'{ch}label@1.0s"


def test_csv_truncated_when_cap_hit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With the cap patched low, the export stops at the cap and says so."""
    from gatorcast.web import routes
    from tests.fixtures.timeline import add_session, at

    monkeypatch.setattr(routes, "_CSV_EXPORT_CAP", 2)
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        for i in range(3):
            _run(add_session(app.state.db, f"s-{i}", started_at=at(f"10:0{i}:00.000")))
        resp = _export(client)
    assert resp.status_code == 200
    assert resp.headers["x-gatorcast-truncated"] == "true"
    assert [r[0] for r in _csv_rows(resp)[1:]] == ["s-2", "s-1"]


def test_csv_not_truncated_when_everything_fits_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cap equal to the item count, walked one item per page: complete, no header."""
    from gatorcast.web import routes
    from tests.fixtures.timeline import add_request, add_session, at

    monkeypatch.setattr(routes, "_CSV_EXPORT_CAP", 3)
    monkeypatch.setattr(routes, "_CSV_PAGE_SIZE", 1)
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        db = app.state.db
        _run(add_session(db, "s-a", started_at=at("10:00:00.000")))
        _run(add_request(db, "rq-b", conn_id="conn-b", requested_at=at("10:30:00.000"),
                         username="a@x", kubectl_session="ks-b", kubectl_command="kubectl get"))
        _run(add_session(db, "s-c", started_at=at("11:00:00.000")))
        resp = _export(client)
    assert resp.status_code == 200
    assert "x-gatorcast-truncated" not in resp.headers
    assert [r[0] for r in _csv_rows(resp)[1:]] == ["s-c", "conn-b", "s-a"]


def test_csv_truncated_at_first_scan_budget_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A kubectl scan budget hit stops the export at that page and sets the header."""
    from gatorcast.store import timeline
    from tests.fixtures.timeline import add_request, at

    monkeypatch.setattr(timeline, "_API_SCAN_BUDGET", 2)
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        for i in range(5):
            _run(add_request(app.state.db, f"rq-{i}", conn_id=f"conn-{i}",
                             requested_at=at(f"10:0{i}:00.000"), username="a@x",
                             kubectl_session=f"ks-{i}", kubectl_command="kubectl get"))
        resp = _export(client, "type=kubectl&q=nomatchanywhere")
    assert resp.status_code == 200
    assert resp.headers["x-gatorcast-truncated"] == "true"
    assert _csv_rows(resp) == [CSV_HEADER]


def test_csv_sidecar_reads_bounded_across_pages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Content search reads at most SEARCH_REGEX_MAX_CANDIDATES sidecars per export.

    Three matching recordings, a budget of 2, one item per page: page 1 reads two
    sidecars and fills; the export-wide budget is then spent, so it stops truncated
    instead of reading the third sidecar on a later page.
    """
    from gatorcast.web import routes
    from tests.fixtures.timeline import add_session, at

    monkeypatch.setattr(routes, "_CSV_PAGE_SIZE", 1)
    settings = _settings(tmp_path)
    settings.search_regex_max_candidates = 2
    app = create_app(settings)
    with TestClient(app) as client:
        for i in range(3):
            conn_id = f"s-{i}"
            _run(add_session(app.state.db, conn_id, started_at=at(f"10:0{i}:00.000")))
            _run(app.state.casts.write_sidecar(conn_id, f"hello {UNIQUE_MARKER}\n"))
        reads: list[str] = []
        real = app.state.casts.read_sidecar

        async def counting(conn_id: str) -> str:
            reads.append(conn_id)
            return await real(conn_id)

        monkeypatch.setattr(app.state.casts, "read_sidecar", counting)
        resp = _export(client, "q=hello")
    assert resp.status_code == 200
    assert resp.headers["x-gatorcast-truncated"] == "true"
    assert len(reads) == 2
    assert [r[0] for r in _csv_rows(resp)[1:]] == ["s-2"]
    assert UNIQUE_MARKER not in resp.text


def test_csv_content_budget_hit_stops_export(tmp_path: Path) -> None:
    """A page cut short by the content budget is written, then the export stops."""
    from tests.fixtures.timeline import add_session, at

    settings = _settings(tmp_path)
    settings.search_regex_max_candidates = 1
    app = create_app(settings)
    with TestClient(app) as client:
        for i in range(3):
            conn_id = f"s-{i}"
            _run(add_session(app.state.db, conn_id, started_at=at(f"10:0{i}:00.000")))
            _run(app.state.casts.write_sidecar(conn_id, "hello\n"))
        resp = _export(client, "q=hello")
    assert resp.status_code == 200
    assert resp.headers["x-gatorcast-truncated"] == "true"
    assert [r[0] for r in _csv_rows(resp)[1:]] == ["s-2"]


def test_csv_invalid_param_is_400(tmp_path: Path) -> None:
    """The export validates strictly like /search (400, value not echoed)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = _export(client, "type=SENTINELBAD")
    assert resp.status_code == 400
    assert "SENTINELBAD" not in resp.text


# ---------------------------------------------------------------------------
# Session detail enriched with findings (seek), marker still absent
# ---------------------------------------------------------------------------


def test_session_detail_lists_findings_with_offset(tmp_path: Path) -> None:
    """Session detail shows a finding with data-offset + the cast URL; marker absent."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="sd1", username="hank@x", resource_address="db.host")
        resp = client.get("/sessions/sd1", headers=_auth_header())
    assert resp.status_code == 200
    body = resp.text
    assert "data-offset" in body
    assert "Recursive delete (rm -rf)" in body
    assert "/sessions/sd1/cast" in body
    assert UNIQUE_MARKER not in body
    # The player glue must read a ?t= deep link and open the player at that offset
    # (startAt), so a "jump to finding" from search lands at the right timestamp.
    assert "startAt" in body
    assert 't")' in body or "'t'" in body  # reads the t query/hash param


# ---------------------------------------------------------------------------
# Unified search page (Session 10 T5, spec §8.3 / §8.6 / §12)
# ---------------------------------------------------------------------------

ALL_TYPE_VALUES = ["any", "recordings", "ssh", "exec", "failed", "kubectl"]
ALL_TYPE_LABELS = [
    "Any",
    "All sessions",
    "SSH sessions",
    "kubectl exec recordings",
    "Failed connections",
    "kubectl commands",
]


@contextlib.contextmanager
def _scenario_client(tmp_path: Path, settings: Settings | None = None):
    """Yield ``(app, client, scenario)`` with the spec §12 scenario loaded.

    The scenario is inserted inside ``with TestClient(app)`` so lifespan has wired
    ``app.state.db``.
    """
    from tests.fixtures.timeline import build_scenario

    app = create_app(settings or _settings(tmp_path))
    with TestClient(app) as client:
        scenario = asyncio.run(build_scenario(app.state.db))
        yield app, client, scenario


def _get(client: TestClient, url: str, **headers: str):
    """GET ``url`` with Basic auth plus any extra headers (e.g. ``HX-Request``)."""
    return client.get(url, headers={**_auth_header(), **headers})


def _blocks(body: str) -> list[str]:
    """Split a results page into its per-item ``<tbody class="result">`` blocks."""
    return body.split('<tbody class="result">')[1:]


def _badge(block: str) -> str:
    """Return the kind badge class (``pill-ssh`` etc.) of one result block."""
    match = re.search(r'class="pill (pill-(?:ssh|exec|failed|kubectl))"', block)
    assert match is not None, block[:300]
    return match.group(1)


def _block_at(block: str) -> str:
    """Return the Start (UTC) cell of one result block."""
    match = re.search(r'<td class="mono dim nowrap">([^<]+)</td>', block)
    assert match is not None, block[:300]
    return match.group(1)


def _ident(block: str) -> tuple[str, str]:
    """Stable identity of a result block: ``("rec", conn_id)`` or ``("cmd", command_id)``."""
    if _badge(block) == "pill-kubectl":
        match = re.search(r'href="/search\?cmd=([^"&]+)">Link to this command', block)
        assert match is not None, block[:300]
        return ("cmd", match.group(1))
    match = re.search(r'class="(?:recording-link|details-link)" href="/sessions/([^"]+)"', block)
    assert match is not None, block[:300]
    return ("rec", match.group(1))


def _next_href(body: str, label: str = "Next ›") -> str | None:
    """Return the (unescaped) href of the paging link labelled ``label``, or ``None``."""
    match = re.search(rf'<a class="page-link" href="([^"]+)"[^>]*>{re.escape(label)}</a>', body)
    return html_lib.unescape(match.group(1)) if match else None


def _walk_pages(client: TestClient, url: str, *, label: str = "Next ›", limit: int = 200):
    """Follow ``label`` links from ``url``; return the list of page bodies."""
    bodies: list[str] = []
    seen: set[str] = set()
    next_url: str | None = url
    while next_url is not None:
        assert next_url not in seen, "paging loop"
        seen.add(next_url)
        assert len(bodies) < limit, "too many pages"
        resp = _get(client, next_url)
        assert resp.status_code == 200, next_url
        bodies.append(resp.text)
        next_url = _next_href(resp.text, label)
    return bodies


def test_search_heading_and_type_select_options(tmp_path: Path) -> None:
    """The page is titled "Search" and the Type select lists all six options."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = _get(client, "/search")
    assert resp.status_code == 200
    body = resp.text
    assert "<h1>Search</h1>" in body
    assert "Search sessions" not in body
    assert "<title>Search · Gatorcast</title>" in body
    select = re.search(r'<select name="type">(.*?)</select>', body, re.DOTALL)
    assert select is not None
    options = re.findall(r'<option value="([^"]*)"( selected)?>([^<]*)</option>', select.group(1))
    assert [o[0] for o in options] == ALL_TYPE_VALUES
    assert [o[2] for o in options] == ALL_TYPE_LABELS
    # The default type is Any.
    assert [o[0] for o in options if o[1]] == ["any"]


def test_search_type_select_is_sticky(tmp_path: Path) -> None:
    """The chosen type stays selected in the form."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        body = _get(client, "/search?type=failed").text
    assert '<option value="failed" selected>' in body
    assert '<option value="any" selected>' not in body


def test_search_any_interleaves_kinds_with_badges(tmp_path: Path) -> None:
    """type=any lists recordings, failed connections and commands newest first, with badges."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        resp = _get(client, "/search?page_size=200")
    assert resp.status_code == 200
    blocks = _blocks(resp.text)
    badges = [_badge(b) for b in blocks]
    assert set(badges) == {"pill-ssh", "pill-exec", "pill-failed", "pill-kubectl"}
    # Newest first across kinds, by the Start (UTC) column.
    times = [_block_at(b) for b in blocks]
    assert times == sorted(times, reverse=True)
    # Genuinely interleaved: commands sit between recordings in both directions.
    first_cmd = badges.index("pill-kubectl")
    last_cmd = len(badges) - 1 - badges[::-1].index("pill-kubectl")
    rec_idx = [i for i, b in enumerate(badges) if b != "pill-kubectl"]
    assert first_cmd < max(rec_idx) and min(rec_idx) < last_cmd
    # Badge text per kind.
    assert "SSH session" in resp.text and "kubectl exec" in resp.text
    assert "Failed connection" in resp.text and "kubectl command" in resp.text
    # The count line is "Showing N" with no grand total.
    assert f"Showing {len(blocks)}" in resp.text


def test_search_failed_connection_row_has_details_and_no_replay(tmp_path: Path) -> None:
    """A failed connection shows the badge and a Details link, never a Replay link."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        mixed = _get(client, "/search?page_size=200").text
        only = _get(client, "/search?type=failed").text
    for body in (mixed, only):
        failed = [b for b in _blocks(body) if _badge(b) == "pill-failed"]
        assert len(failed) == 1
        block = failed[0]
        assert "Failed connection" in block
        assert 'class="details-link" href="/sessions/s-failed"' in block
        assert "Details ›" in block
        assert "Replay" not in block and "recording-link" not in block
        assert "is-failed" in block
    assert [_ident(b) for b in _blocks(only)] == [("rec", "s-failed")]


def test_search_ssh_error_row_with_chunks_stays_ssh_with_replay(tmp_path: Path) -> None:
    """An ``error`` session that has chunks is an SSH row with Replay, not a failed one."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        body = _get(client, "/search?type=ssh&page_size=200").text
    blocks = {_ident(b): b for b in _blocks(body)}
    assert ("rec", "s-failed") not in blocks
    err = blocks[("rec", "s-ssh-error")]
    assert _badge(err) == "pill-ssh"
    assert "Replay" in err and "Details ›" not in err


def test_search_exec_recording_appears_twice_under_any(tmp_path: Path) -> None:
    """Under type=any the exec recording is its own row and a Replay link in its command row."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        body = _get(client, "/search?page_size=200").text
        exec_only = _get(client, "/search?type=exec").text
    with_replay = [b for b in _blocks(body) if 'href="/sessions/s-exec-bob"' in b]
    assert sorted(_badge(b) for b in with_replay) == ["pill-exec", "pill-kubectl"]
    own = next(b for b in with_replay if _badge(b) == "pill-exec")
    command = next(b for b in with_replay if _badge(b) == "pill-kubectl")
    # The exec row links to its command; the command row links to the recording.
    assert 'class="command-link" href="/search?cmd=req-exec-101"' in own
    assert 'class="recording-link" href="/sessions/s-exec-bob"' in command
    assert _ident(command) == ("cmd", "r-exec-get")
    # Under type=exec only the recording itself is listed, still linked to its command.
    assert [_ident(b) for b in _blocks(exec_only)] == [("rec", "s-exec-bob")]


def test_search_kubectl_rows_hold_request_details(tmp_path: Path) -> None:
    """type=kubectl: each row has a closed <details> with request rows; Replay only on the linked one."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        resp = _get(client, "/search?type=kubectl&page_size=200")
    assert resp.status_code == 200
    blocks = _blocks(resp.text)
    assert blocks and all(_badge(b) == "pill-kubectl" for b in blocks)
    for block in blocks:
        assert "<details>" in block and "<details open" not in block
        assert "<summary>" in block and "<table>" in block
        assert "Open in activity view ›" in block
    by_id = {_ident(b)[1]: b for b in blocks}
    assert "/api/v1/namespaces/default/pods/web-1" in by_id["r-c1-1"]
    # Only the exec command carries a recording link.
    with_replay = [i for i, b in by_id.items() if "recording-link" in b]
    assert with_replay == ["r-exec-get"]
    # Discovery-only commands are hidden by default.
    assert "r-disc-1" not in by_id


def test_search_cmd_focus_renders_one_open_command(tmp_path: Path) -> None:
    """cmd=<request id> shows exactly that command, expanded, with the focus banner."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        resp = _get(client, "/search?cmd=r-c1-1")
        from_later_request = _get(client, "/search?cmd=r-c1-3")
    assert resp.status_code == 200
    blocks = _blocks(resp.text)
    assert len(blocks) == 1
    assert "<details open>" in blocks[0]
    assert "Showing one kubectl command" in resp.text
    assert 'href="/search?type=kubectl"' in resp.text  # the clear link
    assert "Command not found" not in resp.text
    assert "/api/v1/namespaces/default/pods/web-1" in blocks[0]
    # Any request id of the command resolves to the same single command.
    assert len(_blocks(from_later_request.text)) == 1
    assert "<details open>" in _blocks(from_later_request.text)[0]


def test_search_cmd_unknown_says_command_not_found(tmp_path: Path) -> None:
    """An unknown cmd is a 200 with "Command not found" and no rows."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        resp = _get(client, "/search?cmd=no-such-request")
    assert resp.status_code == 200
    assert "Command not found" in resp.text
    assert _blocks(resp.text) == []
    assert "Showing 0" in resp.text


def test_search_htmx_invalid_param_returns_error_partial_400(tmp_path: Path) -> None:
    """HX-Request + an invalid param → 400 with the error partial; the value is not echoed."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = _get(client, "/search?sort=SENTINELBAD", **{"HX-Request": "true"})
    assert resp.status_code == 400
    body = resp.text
    assert "SENTINELBAD" not in body
    # Autoescaping turns the quotes into entities; the fixed message names the parameter.
    assert "'sort' is not a valid value" in html_lib.unescape(body)
    assert "<html" not in body.lower()
    assert "HX-Request" in resp.headers["vary"]


def test_search_non_htmx_invalid_param_is_400(tmp_path: Path) -> None:
    """Without HX-Request an invalid param is a plain 400 (JSON detail), value not echoed."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = _get(client, "/search?type=SENTINELBAD")
        bad_cursor = _get(client, "/search?cursor=SENTINELBAD")
        conflict = _get(client, "/search?user=SENTINELA&username=SENTINELB")
    assert resp.status_code == 400
    assert "SENTINELBAD" not in resp.text
    assert "detail" in resp.json()
    assert bad_cursor.status_code == 400 and "SENTINELBAD" not in bad_cursor.text
    assert conflict.status_code == 400
    assert "SENTINELA" not in conflict.text and "SENTINELB" not in conflict.text


def test_search_next_pages_through_every_item_exactly_once(tmp_path: Path) -> None:
    """Next › carries a cursor; following it visits every item once, in single-page order."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        everything = [_ident(b) for b in _blocks(_get(client, "/search?page_size=200").text)]
        bodies = _walk_pages(client, "/search?page_size=7")
    assert len(everything) > 14, "scenario too small to page"
    paged = [_ident(b) for body in bodies for b in _blocks(body)]
    assert paged == everything
    assert len(set(paged)) == len(paged)
    assert len(bodies) == -(-len(everything) // 7)
    # Page 1 has Next but no First page; later pages have both; the last has no Next.
    assert _next_href(bodies[0], "First page") is None
    assert re.search(r"[?&]cursor=", _next_href(bodies[0]) or "")
    assert "page_size=7" in (_next_href(bodies[0]) or "")
    assert _next_href(bodies[1], "First page") is not None
    assert "cursor=" not in (_next_href(bodies[1], "First page") or "")
    assert _next_href(bodies[-1]) is None
    assert "Continue scanning" not in "".join(bodies)


def test_search_next_cursor_is_bound_to_the_search(tmp_path: Path) -> None:
    """A cursor replayed against a different type or sort is a 400."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        next_url = _next_href(_get(client, "/search?page_size=5").text)
        assert next_url is not None
        cursor = re.search(r"cursor=([^&]+)", next_url).group(1)
        other_type = _get(client, f"/search?type=ssh&page_size=5&cursor={cursor}")
        other_sort = _get(client, f"/search?sort=risk&page_size=5&cursor={cursor}")
    assert other_type.status_code == 400
    assert other_sort.status_code == 400


def test_search_continue_scanning_when_scan_budget_hit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A kubectl scan budget hit shows the notice and Continue scanning ›, never Next ›."""
    from gatorcast.store import timeline
    from tests.fixtures.timeline import add_request, at

    monkeypatch.setattr(timeline, "_API_SCAN_BUDGET", 2)
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        for i in range(5):
            # Oldest row (i == 0) is the only match, so the walk must cross budget pages.
            _run(add_request(
                app.state.db, f"rq-{i}", conn_id=f"conn-{i}",
                requested_at=at(f"10:0{i}:00.000"), username="a@x",
                kubectl_session=f"ks-{i}",
                kubectl_command="kubectl zebra" if i == 0 else "kubectl get",
            ))
        first = _get(client, "/search?type=kubectl&q=zebra")
        assert first.status_code == 200
        assert "Scanned 2 kubectl requests without filling the page." in first.text
        assert "Continue scanning ›" in first.text
        assert "Next ›" not in first.text
        assert "Nothing matched in the part searched so far" in first.text
        bodies = _walk_pages(client, "/search?type=kubectl&q=zebra", label="Continue scanning ›")
    assert len(bodies) >= 2
    found = [_ident(b) for body in bodies for b in _blocks(body)]
    assert found == [("cmd", "rq-0")]
    # The last page ends the walk: no further Continue or Next.
    assert "Continue scanning" not in bodies[-1] and "Next ›" not in bodies[-1]


def test_search_continue_scanning_when_content_budget_hit(tmp_path: Path) -> None:
    """The recording content budget short-circuits a page and offers Continue scanning ›."""
    from tests.fixtures.timeline import add_session, at

    settings = _settings(tmp_path)
    settings.search_regex_max_candidates = 1
    app = create_app(settings)
    with TestClient(app) as client:
        for i in range(3):
            conn_id = f"s-{i}"
            _run(add_session(app.state.db, conn_id, started_at=at(f"10:0{i}:00.000")))
            _run(app.state.casts.write_sidecar(conn_id, f"hello {UNIQUE_MARKER}\n"))
        resp = _get(client, "/search?type=ssh&q=hello")
        bodies = _walk_pages(client, "/search?type=ssh&q=hello", label="Continue scanning ›")
    assert resp.status_code == 200
    assert "Scanned 1 recordings without filling the page." in resp.text
    assert "Continue scanning ›" in resp.text and "Next ›" not in resp.text
    seen = [_ident(b) for body in bodies for b in _blocks(body)]
    assert sorted(seen) == [("rec", "s-0"), ("rec", "s-1"), ("rec", "s-2")]
    assert all(UNIQUE_MARKER not in body for body in bodies)


def _seed_legacy_world(app) -> None:
    """Seed ``leg1`` (flagged SSH) plus a kubectl command and a failed row for the same user."""
    from tests.fixtures.timeline import PROD, add_request, add_session, at

    _seed_flagged(app, conn_id="leg1", username="alice@x", resource_address="db.host")
    db = app.state.db
    _run(add_request(
        db, "rq-leg", conn_id="conn-leg", requested_at=at("11:00:00.000"),
        resource_address=PROD, username="alice@x", user_id="uid-alice-x", method="DELETE",
        url="/api/v1/namespaces/default/pods/web-2", kubectl_session="ks-leg",
        kubectl_command="kubectl delete", findings=[("kube-delete", "high", "Resource delete")],
    ))
    _run(add_session(
        db, "s-leg-failed", started_at=at("12:00:00.000"), username="alice@x",
        resource_address="db.host", status="error", chunk_count=0, cast_path=None,
    ))


LEGACY_URLS = [
    "keyword=rm",
    "regex=rm%20-rf",
    "keyword=rm&regex=rm%20-rf",
    "username=alice%40x",
    "resource_address=db.host",
    "started_after=2026-01-01T00:00:00Z",
    "started_after=2026-01-01T00:00:00Z&started_before=2027-01-01T00:00:00Z",
    "status=complete",
    "min_duration=100&max_duration=400",
    "max_severity=high&started_after=2026-01-01T00:00:00Z",
    "category=dangerous-command&started_after=2026-01-01T00:00:00Z",
    "rule_ids=recursive-delete",
    "username=alice%40x&started_after=2026-01-01T00:00:00Z",
    "page=3",
    "keyword=rm&page=2",
]

_LEGACY_LINK = re.compile(
    r'(?:href|hx-get)="[^"]*[?&;](?:amp;)?'
    r"(?:username|resource_address|started_after|started_before|keyword|regex|page)="
)


@pytest.mark.parametrize("query", LEGACY_URLS)
def test_search_legacy_urls_still_list_their_recordings(tmp_path: Path, query: str) -> None:
    """Every Session 8 legacy URL returns 200 and still lists the recording it used to."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_legacy_world(app)
        resp = _get(client, f"/search?{query}")
    assert resp.status_code == 200, query
    idents = [_ident(b) for b in _blocks(resp.text)]
    assert ("rec", "leg1") in idents, query
    assert UNIQUE_MARKER not in resp.text
    # Legacy names are accepted but never emitted by the UI.
    assert not _LEGACY_LINK.search(resp.text), query


def test_search_legacy_username_link_is_a_superset(tmp_path: Path) -> None:
    """A username= link now also lists that user's kubectl commands and failed connections."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_legacy_world(app)
        resp = _get(client, "/search?username=alice%40x")
    idents = [_ident(b) for b in _blocks(resp.text)]
    assert ("rec", "leg1") in idents
    assert ("cmd", "rq-leg") in idents
    assert ("rec", "s-leg-failed") in idents


def test_search_legacy_max_severity_link_is_a_superset(tmp_path: Path) -> None:
    """A Session 8 severity drill-down now also lists kubectl commands at that severity."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_legacy_world(app)
        resp = _get(client, "/search?max_severity=high&started_after=2026-01-01T00:00:00Z")
    idents = [_ident(b) for b in _blocks(resp.text)]
    assert ("rec", "leg1") in idents and ("cmd", "rq-leg") in idents
    assert ("rec", "s-leg-failed") not in idents  # no findings


def test_search_legacy_recording_only_filters_exclude_kubectl_with_notice(tmp_path: Path) -> None:
    """status/duration/regex links stay recordings-only and say kubectl was not searched."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_legacy_world(app)
        by_status = _get(client, "/search?status=complete")
        by_regex = _get(client, "/search?regex=rm")
    for resp in (by_status, by_regex):
        assert resp.status_code == 200
        assert all(_badge(b) != "pill-kubectl" for b in _blocks(resp.text))
        assert "kubectl commands not searched" in resp.text


def test_search_legacy_page_param_lands_on_first_page(tmp_path: Path) -> None:
    """page=N is validated then ignored: same results as page 1, no page= links."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        first = _get(client, "/search?page_size=5")
        legacy = _get(client, "/search?page_size=5&page=3")
        bad = _get(client, "/search?page=0")
    assert legacy.status_code == 200
    assert [_ident(b) for b in _blocks(legacy.text)] == [_ident(b) for b in _blocks(first.text)]
    assert "page=3" not in legacy.text
    assert bad.status_code == 400


def test_search_escapes_hostile_values(tmp_path: Path) -> None:
    """<script> in a command, URL, username, or query param renders escaped; = renders as text."""
    from tests.fixtures.timeline import add_request, add_session, at

    with _scenario_client(tmp_path) as (app, client, _sc):
        db = app.state.db
        _run(add_session(db, "s-hostile", started_at=at("14:30:00.000"),
                         username="<script>alert(2)</script>", resource_address="<b>sys</b>"))
        _run(add_request(db, "r-hostile-url", conn_id="conn-hu", requested_at=at("14:31:00.000"),
                         username="<img src=x>", url="/api/v1/namespaces/<script>x</script>/pods",
                         kubectl_session="ks-hu", kubectl_command="kubectl get"))
        resp = _get(client, "/search?page_size=200")
        kubectl = _get(client, "/search?type=kubectl&q=script&page_size=200")
        echoed = _get(
            client,
            "/search?q=%22%3E%3Cscript%3Ealert(3)%3C/script%3E&user=%3Cscript%3Ealert(4)%3C/script%3E"
            "&system=%3Cb%3Ex%3C/b%3E",
        )
    body = resp.text
    assert resp.status_code == 200
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body  # kubectl_command
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in body  # username
    assert "&lt;script&gt;x&lt;/script&gt;" in body  # stored request URL
    assert "&lt;b&gt;sys&lt;/b&gt;" in body and "&lt;img src=x&gt;" in body
    # "=" is plain text in HTML (the CSV guard is covered by the CSV tests).
    assert '<span class="mono command-label">=cmd|calc</span>' in body
    for page in (body, kubectl.text, echoed.text):
        assert "<script>alert" not in page
        assert "<script>x" not in page and "<img src=x>" not in page
        assert "<b>sys</b>" not in page and "<b>x</b>" not in page
    assert kubectl.status_code == 200
    assert ("cmd", "r-hostile-url") in [_ident(b) for b in _blocks(kubectl.text)]
    assert echoed.status_code == 200
    assert "&lt;script&gt;alert(3)&lt;/script&gt;" in echoed.text  # sticky q
    assert "&lt;script&gt;alert(4)&lt;/script&gt;" in echoed.text  # sticky user + chip


def test_search_usernames_link_to_user_search(tmp_path: Path) -> None:
    """Recording and command rows link the user to /search?user=…; a user_id-only user uses the id."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        resp = _get(client, "/search?page_size=200")
        by_user = _get(client, "/search?user=alice%40example.com&page_size=200")
    body = resp.text
    for user in ("alice%40example.com", "bob%40example.com", "carol%40example.com"):
        assert f'<a class="user-link" href="/search?user={user}">' in body
    # Command rows of a request with only user.id fall back to the id.
    assert '<a class="user-link" href="/search?user=uid-dave">' in body
    rec_row = next(b for b in _blocks(body) if _ident(b) == ("rec", "s-ssh-alice"))
    assert 'href="/search?user=alice%40example.com"' in rec_row
    cmd_row = next(b for b in _blocks(body) if _ident(b) == ("cmd", "r-dev-1"))
    assert 'href="/search?user=alice%40example.com"' in cmd_row
    # Following the link narrows to that user's items of every kind and shows the chip.
    assert by_user.status_code == 200
    idents = [_ident(b) for b in _blocks(by_user.text)]
    assert ("rec", "s-ssh-alice") in idents and ("cmd", "r-dev-1") in idents
    assert ("rec", "s-failed") in idents
    assert ("rec", "s-ssh-bob") not in idents
    assert 'class="filter-chip"' in by_user.text and "alice@example.com" in by_user.text


def test_search_sends_vary_hx_request(tmp_path: Path) -> None:
    """Full page, results partial, and error partial all carry Vary: HX-Request."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        full = _get(client, "/search")
        partial = _get(client, "/search", **{"HX-Request": "true"})
        error = _get(client, "/search?sort=nope", **{"HX-Request": "true"})
    for resp in (full, partial, error):
        vary = [v.strip().lower() for v in resp.headers["vary"].split(",")]
        assert "hx-request" in vary


def test_search_htmx_history_restore_gets_the_full_page(tmp_path: Path) -> None:
    """htmx's history-restore request swaps the whole body, so it must get the full page."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        restore = _get(
            client, "/search?type=kubectl",
            **{"HX-Request": "true", "HX-History-Restore-Request": "true"},
        )
        partial = _get(client, "/search?type=kubectl", **{"HX-Request": "true"})
    assert restore.status_code == 200
    assert "<html" in restore.text.lower() and "<h1>Search</h1>" in restore.text
    assert 'id="results"' in restore.text and "site-header" in restore.text
    assert "<html" not in partial.text.lower() and "<h1>" not in partial.text
    assert "Showing 0" in partial.text


def test_search_base_has_htmx_config_for_400_swap(tmp_path: Path) -> None:
    """base.html carries the htmx-config meta so an error partial swaps into #results."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        body = _get(client, "/search").text
    match = re.search(r"<meta name=\"htmx-config\" content='([^']+)'", body)
    assert match is not None
    assert '"code":"400","swap":true,"error":false' in match.group(1)


def test_search_notice_for_excluded_kinds_and_all_excluded(tmp_path: Path) -> None:
    """A recordings-only filter explains the skipped kinds; type=kubectl+status excludes everything."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        mixed = _get(client, "/search?status=complete&page_size=200")
        nothing = _get(client, "/search?type=kubectl&status=complete")
    assert "kubectl commands not searched: the Status filter applies to recordings only." in mixed.text
    assert nothing.status_code == 200
    assert "No type can be searched with these filters." in nothing.text
    assert _blocks(nothing.text) == []


# ---------------------------------------------------------------------------
# Dashboard (Session 10 T7, spec §8.1 / §8.2 / §12)
# ---------------------------------------------------------------------------
#
# The window seed is placed relative to the wall clock but far from every window
# edge: in-window items start about one day ago, out-of-window items 60 days ago,
# and the straddling command starts 7 days + 2 hours ago. The dashboard request and
# each followed search compute their cutoffs a few milliseconds apart, so no item
# can fall between them.

_DASH_SYSTEM = "dash-k8s"
_DASH_USER = "dash@example.com"
_DASH_USER_ID = "uid-dash"


def _ms(dt) -> str:
    """Format a datetime as the stored ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _seed_dashboard_window(app) -> dict[str, dict[str, object]]:
    """Seed recordings and kubectl commands inside and outside a 7-day window.

    In the window, by start (minutes before ``base`` = now - 1 day):
    ``c-disc`` (0, discovery-only, hidden), ``w-ssh-high`` (1), ``c-low`` (2),
    ``w-exec-crit`` (3), ``c-med`` (4), ``w-failed`` (5), ``c-high-1`` (6),
    ``w-ssh-med`` (7), ``c-high-2`` (8), ``w-ssh-clean-1`` (9), ``c-hm`` (10,
    medium then high), ``w-ssh-clean-2`` (11), ``c-crit`` (12), ``w-ssh-clean-3``
    (13), ``c-clean-1`` (14), ``w-ssh-clean-4`` (15), ``c-clean-2`` (16),
    ``w-null-start`` (17, NULL started_at, placed by created_at), and the second
    (high-flagged) request of ``c-straddle`` (18), whose first request is
    7 days + 2 hours ago. Outside: ``o-ssh-high``, ``o-exec`` and ``c-old-high``
    60 days ago.

    Every row belongs to ``dash@example.com``. Returns the expected figures for
    ``window=7`` and ``window=all``.
    """
    from datetime import datetime, timedelta, timezone

    from tests.fixtures.timeline import add_connection, add_request, add_session

    now = datetime.now(tz=timezone.utc)
    base = now - timedelta(days=1)

    def m(minutes: float):
        return base - timedelta(minutes=minutes)

    old = now - timedelta(days=60)
    db = app.state.db
    user = {"user_id": _DASH_USER_ID, "username": _DASH_USER}

    async def run() -> None:
        async def sess(conn_id: str, when, **kw: object) -> None:
            await add_session(db, conn_id, started_at=_ms(when), username=_DASH_USER, **kw)
            await add_connection(db, conn_id, user_id=_DASH_USER_ID, username=_DASH_USER,
                                 resource_address=kw.get("resource_address", "web-01"))

        await sess("w-ssh-high", m(1), duration=60.0,
                   findings=[("rm-rf", "dangerous-command", "high", "Recursive delete", 1.0)])
        await sess("w-exec-crit", m(3), resource_address=_DASH_SYSTEM, request_id="w-req-exec",
                   duration=9.0,
                   findings=[("private-key", "secret-exposure", "critical", "Private key", 2.0)])
        await sess("w-failed", m(5), status="error", chunk_count=0, cast_path=None)
        await sess("w-ssh-med", m(7), duration=20.0,
                   findings=[("aws-access-key", "secret-exposure", "medium", "AWS key", 3.0)])
        for i, minutes in enumerate((9, 11, 13, 15), start=1):
            await sess(f"w-ssh-clean-{i}", m(minutes), duration=5.0)
        created = m(17).strftime("%Y-%m-%d %H:%M:%S")
        await add_session(db, "w-null-start", started_at=None, created_at=created,
                          username=_DASH_USER, duration=4.0)
        await sess("o-ssh-high", old, duration=60.0,
                   findings=[("rm-rf", "dangerous-command", "high", "Recursive delete", 1.0)])
        await sess("o-exec", old - timedelta(minutes=1), resource_address=_DASH_SYSTEM,
                   request_id="o-req-exec", duration=3.0)

        async def cmd(name: str, when, *, findings=(), url="/api/v1/namespaces/default/pods",
                      method="GET", request_id: str | None = None) -> None:
            await add_request(db, request_id or f"r-{name}", conn_id=f"conn-{name}",
                              requested_at=_ms(when), resource_address=_DASH_SYSTEM,
                              method=method, url=url, kubectl_session=f"ks-{name}",
                              kubectl_command="kubectl get", findings=findings, **user)

        await cmd("disc", m(0), url="/api")
        await cmd("low", m(2), findings=[("kube-cordon", "low", "Node cordon")])
        await cmd("med", m(4), findings=[("kube-secrets", "medium", "Secret read")])
        await cmd("high-1", m(6), method="DELETE",
                  findings=[("kube-delete", "high", "Resource delete")])
        await cmd("high-2", m(8), method="DELETE",
                  findings=[("kube-delete", "high", "Resource delete")])
        await cmd("hm", m(10), findings=[("kube-secrets", "medium", "Secret read")])
        await cmd("hm", m(10) + timedelta(milliseconds=500), method="DELETE",
                  request_id="r-hm-2", findings=[("kube-delete", "high", "Resource delete")])
        await cmd("crit", m(12), findings=[("kube-node-proxy-exec", "critical", "Node proxy")])
        await cmd("clean-1", m(14))
        await cmd("clean-2", m(16))
        await cmd("straddle", now - timedelta(days=7, hours=2))
        await cmd("straddle", m(18), method="DELETE", request_id="r-straddle-2",
                  findings=[("kube-delete", "high", "Resource delete")])
        await cmd("old-high", old, method="DELETE",
                  findings=[("kube-delete", "high", "Resource delete")])

    asyncio.run(run())
    return {
        "7": {
            "total_sessions": 9,  # incl. the failed connection and the NULL-start row
            "flagged_sessions": 3,
            "api_requests": 11,  # every request at or after the cutoff, discovery included
            "kubectl_items": 8,  # commands starting in the window, discovery-only hidden
            "flagged_commands": 6,
            "api_sev": {"critical": 1, "high": 3, "medium": 1, "low": 1},
        },
        "all": {
            "total_sessions": 11,
            "flagged_sessions": 4,
            "api_requests": 13,
            "kubectl_items": 10,
            "flagged_commands": 8,
            "api_sev": {"critical": 1, "high": 5, "medium": 1, "low": 1},
        },
    }


_TILE_RE = re.compile(
    r'<a class="card-link" href="([^"]+)">\s*<span class="card-value">([^<]+)</span>\s*'
    r'<span class="card-label">([^<]+?)\s*<span'
)
_FLAGGED_CMDS_RE = re.compile(
    r'<a class="card-sub-link" href="([^"]+)"[^>]*>\s*<span class="badge-count">([^<]+)</span>'
)
_CHIP_RE = re.compile(
    r'<a class="badge-link[^"]*" href="([^"]+)">\s*<span class="sev [^"]+">([^<]+)</span>\s*'
    r'<span class="badge-count">(\d+)</span>'
)


def _tiles(body: str) -> dict[str, tuple[str, str]]:
    """Return ``{tile label: (href, value)}`` for the dashboard tiles."""
    return {
        label.strip(): (html_lib.unescape(href), value)
        for href, value, label in _TILE_RE.findall(body)
    }


def _chips(body: str, type_: str) -> dict[str, tuple[str, int]]:
    """Return ``{severity: (href, count)}`` for the max_severity chips of ``type_``."""
    out: dict[str, tuple[str, int]] = {}
    for href, label, count in _CHIP_RE.findall(body):
        url = html_lib.unescape(href)
        if f"type={type_}&" in url and "max_severity=" in url:
            out[label] = (url, int(count))
    return out


def _linked_count(client: TestClient, url: str) -> int:
    """Follow ``url`` through the app and count its items across every page."""
    return sum(len(_blocks(body)) for body in _walk_pages(client, url))


@pytest.mark.parametrize("window", ["7", "30", "90", "all"])
def test_dashboard_links_match_spec_8_1(tmp_path: Path, window: str) -> None:
    """Every tile, chip, and top-user link targets exactly the spec §8.1 URL for the window."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_dashboard_window(app)
        body = _get(client, f"/dashboard?window={window}").text
    w = f"window={window}"
    tiles = _tiles(body)
    assert tiles["Total sessions"][0] == f"/search?type=recordings&{w}"
    assert tiles["Flagged sessions"][0] == f"/search?type=recordings&{w}&has_findings=true"
    assert tiles["kubectl API requests"][0] == f"/search?type=kubectl&{w}"
    flagged = _FLAGGED_CMDS_RE.search(body)
    assert flagged is not None
    assert html_lib.unescape(flagged.group(1)) == f"/search?type=kubectl&{w}&has_findings=true"
    api_chips = _chips(body, "kubectl")
    assert api_chips, "expected API severity chips"
    for sev, (url, _n) in api_chips.items():
        assert url == f"/search?type=kubectl&{w}&max_severity={sev}"
    rec_chips = _chips(body, "recordings")
    assert rec_chips, "expected session severity chips"
    for sev, (url, _n) in rec_chips.items():
        assert url == f"/search?type=recordings&{w}&max_severity={sev}"
    hrefs = _hrefs(body)
    assert f"/search?type=recordings&{w}&category=dangerous-command" in hrefs
    assert f"/search?user=dash%40example.com&{w}" in hrefs
    assert "/systems/web-01" in hrefs
    assert "/search" in hrefs  # View all in Search


def test_dashboard_default_window_links_carry_window_30(tmp_path: Path) -> None:
    """With no (or an invalid) window the dashboard uses 30 days and says so in every link."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_dashboard_window(app)
        default = _get(client, "/dashboard").text
        bogus = _get(client, "/dashboard?window=bogus")
    assert bogus.status_code == 200
    for body in (default, bogus.text):
        assert _tiles(body)["Total sessions"][0] == "/search?type=recordings&window=30"
        assert re.search(r'href="/dashboard\?window=30"\s*class="window-opt active"', body)


@pytest.mark.parametrize("window", ["7", "all"])
def test_dashboard_figures_equal_linked_search_counts(tmp_path: Path, window: str) -> None:
    """Each figure equals the item count of the search it links to, walking every page.

    Exempt by design: the kubectl API requests tile (counts requests; its list holds
    commands), category chips (count findings), and top users (count sessions).
    """
    # A page size of 3 forces several pages per linked search.
    settings = _settings(tmp_path).model_copy(update={"search_page_size": 3})
    app = create_app(settings)
    with TestClient(app) as client:
        expected = _seed_dashboard_window(app)[window]
        body = _get(client, f"/dashboard?window={window}").text
        tiles = _tiles(body)

        total_url, total = tiles["Total sessions"]
        assert int(total) == expected["total_sessions"]
        assert _linked_count(client, total_url) == int(total)

        flagged_url, flagged = tiles["Flagged sessions"]
        assert int(flagged) == expected["flagged_sessions"]
        assert _linked_count(client, flagged_url) == int(flagged)

        rec_chips = _chips(body, "recordings")
        assert rec_chips
        for sev, (url, count) in rec_chips.items():
            assert _linked_count(client, url) == count, sev

        api_chips = _chips(body, "kubectl")
        assert {sev: n for sev, (_u, n) in api_chips.items()} == expected["api_sev"]
        for sev, (url, count) in api_chips.items():
            assert _linked_count(client, url) == count, sev

        match = _FLAGGED_CMDS_RE.search(body)
        assert match is not None
        cmds_url, cmds = html_lib.unescape(match.group(1)), match.group(2)
        assert int(cmds) == expected["flagged_commands"]
        assert _linked_count(client, cmds_url) == int(cmds)

        # Exempt: the request total is not the length of its command list.
        api_url, api_total = tiles["kubectl API requests"]
        assert int(api_total) == expected["api_requests"]
        assert _linked_count(client, api_url) == expected["kubectl_items"]
        assert expected["kubectl_items"] != expected["api_requests"]


def _feed_blocks(body: str) -> list[str]:
    """Return the dashboard feed's ``<tbody class="result">`` blocks."""
    section = body.split('<section class="feed"', 1)[1].split("</section>", 1)[0]
    return _blocks(section)


def _feed_ident(block: str) -> tuple[str, str]:
    """Identity of a feed row: ``("cmd", command_id)`` or ``("rec", conn_id)``."""
    if _badge(block) == "pill-kubectl":
        match = re.search(r'class="details-link" href="/search\?cmd=([^"&]+)"', block)
        assert match is not None, block[:300]
        return ("cmd", match.group(1))
    return _ident(block)


def test_dashboard_feed_lists_newest_15_across_kinds(tmp_path: Path) -> None:
    """The feed is the newest 15 items of every kind, discovery-only commands hidden."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_dashboard_window(app)
        body = _get(client, "/dashboard?window=7").text
        reference = _get(client, "/search?page_size=15").text

    blocks = _feed_blocks(body)
    assert len(blocks) == 15
    idents = [_feed_ident(b) for b in blocks]
    # Same items, same order as the first page of an any-kind search.
    assert idents == [_ident(b) for b in _blocks(reference)]
    # Newest first.
    ats = [_block_at(b) for b in blocks]
    assert ats == sorted(ats, reverse=True)
    # Every kind is represented; the discovery-only command (the newest item) is not.
    assert {_badge(b) for b in blocks} == {"pill-ssh", "pill-exec", "pill-failed", "pill-kubectl"}
    assert ("cmd", "r-disc") not in idents
    assert "r-disc" not in body
    # Right links: recordings replay, failed connections and commands open Details.
    for block, (kind, ident) in zip(blocks, idents, strict=True):
        if kind == "cmd":
            assert f'class="details-link" href="/search?cmd={ident}"' in block
            assert "<details" not in block  # compact: no request table in the feed
        elif _badge(block) == "pill-failed":
            assert f'class="details-link" href="/sessions/{ident}"' in block
            assert "Replay" not in block
        else:
            assert f'class="recording-link" href="/sessions/{ident}"' in block
    # Usernames link to the per-user search; the feed is not windowed.
    assert 'href="/search?user=dash%40example.com"' in "".join(blocks)
    assert "View all in Search" in body


def test_dashboard_feed_is_not_windowed(tmp_path: Path) -> None:
    """With few items, the feed shows old ones too, whatever window the tiles use."""
    from datetime import datetime, timedelta, timezone

    old = (datetime.now(tz=timezone.utc) - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="ancient", username="old@x", resource_address="o.host",
                      started_at=old)
        body = _get(client, "/dashboard?window=7").text
    assert [_ident(b) for b in _feed_blocks(body)] == [("rec", "ancient")]
    assert _tiles(body)["Total sessions"][1] == "0"
    assert UNIQUE_MARKER not in body
