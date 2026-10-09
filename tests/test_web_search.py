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
import json
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
    "resource_type",
    "configured_scheme",
    "configured_upstream_tls",
    "query",
    "gwops_gateway_id",
    "gwops_app",
    "gwops_managed",
]
# Columns 1-15 are unchanged since Session 10; 16-22 were appended in Session 12.
CSV_HEADER_FIRST_15 = CSV_HEADER[:15]
CSV_HEADER_NEW_7 = CSV_HEADER[15:]
NO_WEB_CELLS = [""] * 6  # columns 17-22 of every non-web row

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


def test_csv_header_is_exactly_22_columns(tmp_path: Path) -> None:
    """The header row is the 22 columns, in order, even with no results.

    The first 15 keep their Session 10 names and order; the seven Session 12 columns
    (WEBAPP_SPEC §8.7) follow.
    """
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = _export(client)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert 'filename="gatorcast-search.csv"' in resp.headers["content-disposition"]
    rows = _csv_rows(resp)
    assert rows == [CSV_HEADER]
    assert len(rows[0]) == 22
    assert rows[0][:15] == [
        "conn_id", "username", "resource_address", "status", "started_at", "ended_at",
        "duration_seconds", "finding_count", "max_severity", "findings", "kind", "command",
        "method", "path", "request_count",
    ]
    assert rows[0][15:] == [
        "resource_type", "configured_scheme", "configured_upstream_tls", "query",
        "gwops_gateway_id", "gwops_app", "gwops_managed",
    ]
    assert "x-gatorcast-truncated" not in resp.headers


def test_csv_legacy_export_columns_1_to_10_unchanged(tmp_path: Path) -> None:
    """A Session 8 legacy-param export keeps columns 1–10 exactly; 11 = kind, 12–15 empty.

    The row is now 22 cells wide: column 16 is the session's stored ``resource_type``
    (empty for a session that never had one) and 17–22 are empty for a recording.
    """
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="csv1", username="gwen@x", resource_address="db.host")
        resp = _export(client, "username=gwen%40x&started_after=2026-01-01T00:00:00Z")
    assert resp.status_code == 200
    rows = _csv_rows(resp)
    assert rows[0] == CSV_HEADER
    assert len(rows) == 2
    row = rows[1]
    assert len(row) == 22
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
    assert row[10:15] == ["ssh", "", "", "", ""]
    assert row[15:] == [""] + NO_WEB_CELLS
    assert UNIQUE_MARKER not in resp.text


def test_csv_recording_column_16_is_the_session_resource_type(tmp_path: Path) -> None:
    """Column 16 of a recording is its stored ``resource_type``; 17–22 stay empty (§8.7)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="csv-ssh", username="gwen@x", resource_address="db.host")
        _run(app.state.db.execute(
            "UPDATE sessions SET resource_type = 'SSH' WHERE conn_id = ?", ("csv-ssh",)
        ))
        _run(app.state.db.commit())
        resp = _export(client)
    assert resp.status_code == 200
    rows = _csv_rows(resp)
    assert rows[0] == CSV_HEADER
    assert len(rows) == 2
    assert rows[1][10] == "ssh"
    assert rows[1][15:] == ["SSH"] + NO_WEB_CELLS


def test_csv_kubectl_row_fills_columns_11_to_15(tmp_path: Path) -> None:
    """A kubectl command fills 11–15 and column 16 (``KUBERNETES``); 17–22 are empty.

    No query string and no full User-Agent anywhere (the query column is web-only).
    """
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
    assert all(len(r) == 22 for r in rows)
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
        "KUBERNETES",
        *NO_WEB_CELLS,
    ]
    assert rows[2][10:] == ["kubectl", "k9s", "GET", "/api/v1/nodes", "1", "KUBERNETES", *NO_WEB_CELLS]
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

ALL_TYPE_VALUES = ["any", "recordings", "ssh", "exec", "failed", "kubectl", "web"]
ALL_TYPE_LABELS = [
    "Any",
    "All sessions",
    "SSH sessions",
    "kubectl exec recordings",
    "Failed connections",
    "kubectl commands",
    "Web requests",
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
    """The page is titled "Search" and the Type select lists all seven options (web added)."""
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


def test_search_cmd_unknown_says_command_or_web_connection_not_found(tmp_path: Path) -> None:
    """An unknown cmd is a 200 naming both kinds, with no rows.

    ``cmd`` now focuses whichever kind holds the request (WEBAPP_SPEC §8.1), so the
    not-found text says "Command or web connection", and the banner heading is
    kind-neutral; the clear link goes to the unfiltered search (kind unknown).
    """
    with _scenario_client(tmp_path) as (_app, client, _sc):
        resp = _get(client, "/search?cmd=no-such-request")
    assert resp.status_code == 200
    assert (
        "Command or web connection not found. It may have been removed by retention."
        in resp.text
    )
    assert "Command not found" not in resp.text
    assert "Showing no command or web connection" in resp.text
    banner = re.search(r'<p class="notice notice-focus">(.*?)</p>', resp.text, re.DOTALL)
    assert banner is not None and "no-such-request" not in banner.group(1)
    assert 'href="/search"' in banner.group(1)  # the clear link: no kind to return to
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
        # Web connections are excluded by the same filters (WEBAPP_SPEC §8.1), so the
        # notice now names both skipped kinds.
        assert "kubectl commands and Web requests not searched" in resp.text
        assert 'class="pill pill-web"' not in resp.text


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
    assert (
        "kubectl commands and Web requests not searched: the Status filter applies to "
        "recordings only."
    ) in mixed.text
    assert nothing.status_code == 200
    assert "No type can be searched with these filters." in nothing.text
    assert _blocks(nothing.text) == []
    # type=web with a recordings-only filter excludes the only requested kind as well.
    with _scenario_client(tmp_path / "web") as (_app, client, _sc):
        web_nothing = _get(client, "/search?type=web&status=complete")
    assert web_nothing.status_code == 200
    assert "No type can be searched with these filters." in web_nothing.text
    assert _blocks(web_nothing.text) == []


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


# ---------------------------------------------------------------------------
# Session 11 -> 12: web rows never appear under type=kubectl; from Session 12 they are
# listed under type=web and type=any (WEBAPP_SPEC 8.1, 8.6)
# ---------------------------------------------------------------------------

WEB_PATH_SENTINEL = "/web-only-path-xyzzy"
KUBECTL_PATH = "/api/v1/namespaces/default/pods/shown-in-search"


def _seed_kubectl_and_web_requests(app) -> None:
    """One kubectl request and several web requests on the same system and user."""
    from gatorcast.models import ApiRequest
    from gatorcast.store.activity import RequestStorage

    def req(request_id: str, at: str, url: str, **extra) -> ApiRequest:
        return ApiRequest(
            conn_id="cccccccc-0000-4000-8000-000000000001",
            request_id=request_id,
            requested_at=at,
            user_id="VXNlcjox",
            username="user@example.com",
            method="GET",
            url=url,
            url_web=url,
            status_code=200,
            user_agent="agent/1.0",
            **extra,
        )

    kube = req("k-1", "2026-10-01T10:00:00.000Z", KUBECTL_PATH,
               kubectl_command="kubectl get", kubectl_session="5e55e55e-0000-4000-8000-000000000001")
    asyncio.run(app.state.activity.insert_request(kube, "shared.example.internal"))
    for i in range(4):
        web = req(f"w-{i}", f"2026-10-01T10:00:0{i + 1}.000Z", WEB_PATH_SENTINEL)
        storage = RequestStorage(api_kind="web", url=WEB_PATH_SENTINEL, user_agent="agent/1.0",
                                 kubectl_command=None, kubectl_session=None)
        asyncio.run(app.state.activity.insert_request(web, "shared.example.internal", storage=storage))


@pytest.mark.parametrize("query", ["type=kubectl&window=all"])
def test_search_kubectl_type_lists_kubectl_commands_and_no_web_rows(
    tmp_path: Path, query: str
) -> None:
    """``type=kubectl`` still lists only the kubectl command: web rows stay out of it."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_kubectl_and_web_requests(app)
        resp = client.get(f"/search?{query}", headers=_auth_header())

    assert resp.status_code == 200
    assert "shown-in-search" in resp.text
    assert WEB_PATH_SENTINEL not in resp.text
    assert 'class="pill pill-web"' not in resp.text


@pytest.mark.parametrize("query", ["type=any&window=all", "window=all"])
def test_search_any_lists_the_kubectl_command_and_the_web_connection(
    tmp_path: Path, query: str
) -> None:
    """Under ``any`` (explicit or default) web rows now appear beside the kubectl command.

    The kubectl request and the four web requests share one ``conn_id``; each source
    reads its own ``api_kind``, so the page has one kubectl row and one web row (four
    requests), not a merged or duplicated pair.
    """
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_kubectl_and_web_requests(app)
        resp = client.get(f"/search?{query}", headers=_auth_header())

    assert resp.status_code == 200
    assert "shown-in-search" in resp.text
    blocks = _blocks(resp.text)
    assert len(blocks) == 2
    web_blocks = [b for b in blocks if 'class="pill pill-web"' in b]
    assert len(web_blocks) == 1
    assert WEB_PATH_SENTINEL in web_blocks[0]
    assert "4 requests" in web_blocks[0]
    assert "shown-in-search" not in web_blocks[0]


def test_search_type_web_lists_only_the_web_connection(tmp_path: Path) -> None:
    """``type=web`` lists the web connection and never the kubectl command."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_kubectl_and_web_requests(app)
        resp = client.get("/search?type=web&window=all", headers=_auth_header())

    assert resp.status_code == 200
    assert len(_blocks(resp.text)) == 1
    assert WEB_PATH_SENTINEL in resp.text
    assert "shown-in-search" not in resp.text


def test_search_for_the_web_path_text_finds_nothing_under_kubectl(tmp_path: Path) -> None:
    """Text search under ``type=kubectl`` matches no web path; under ``type=web`` it does."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_kubectl_and_web_requests(app)
        kube = client.get(
            "/search?type=kubectl&window=all&q=web-only-path", headers=_auth_header()
        )
        web = client.get("/search?type=web&window=all&q=web-only-path", headers=_auth_header())
    assert kube.status_code == 200
    assert "shown-in-search" not in kube.text
    assert WEB_PATH_SENTINEL not in kube.text
    assert web.status_code == 200
    assert WEB_PATH_SENTINEL in web.text


def test_search_csv_export_lists_kubectl_and_web_rows_under_any(tmp_path: Path) -> None:
    """The ``any`` export has the kubectl row and the web row; ``type=kubectl`` has no web row."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_kubectl_and_web_requests(app)
        any_resp = client.get("/search/export.csv?type=any&window=all", headers=_auth_header())
        kube_resp = client.get(
            "/search/export.csv?type=kubectl&window=all", headers=_auth_header()
        )

    assert any_resp.status_code == 200
    rows = list(csv.reader(io.StringIO(any_resp.text)))
    assert len(rows) == 3  # header + the kubectl command + the web connection
    assert {r[10] for r in rows[1:]} == {"kubectl", "web"}
    web_row = next(r for r in rows[1:] if r[10] == "web")
    assert web_row[13] == WEB_PATH_SENTINEL
    assert web_row[14] == "4"
    assert web_row[15] == "WEB_APP"

    assert kube_resp.status_code == 200
    kube_rows = list(csv.reader(io.StringIO(kube_resp.text)))
    assert len(kube_rows) == 2  # header + the one kubectl command
    assert "shown-in-search" in kube_resp.text
    assert WEB_PATH_SENTINEL not in kube_resp.text


def test_search_by_system_and_user_under_kubectl_still_excludes_web_rows(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_kubectl_and_web_requests(app)
        resp = client.get(
            "/search?type=kubectl&window=all&system=shared.example.internal&user=user@example.com",
            headers=_auth_header(),
        )
    assert resp.status_code == 200
    assert "shown-in-search" in resp.text
    assert WEB_PATH_SENTINEL not in resp.text


# ---------------------------------------------------------------------------
# Session 12 (web apps): the ``web`` search kind over HTTP (WEBAPP_SPEC §8.1-§8.7)
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _web_client(tmp_path: Path, *, with_scenario: bool = False, settings: Settings | None = None):
    """Yield ``(app, client)`` with :func:`build_web_scenario` loaded (plus the §12 scenario).

    The web scenario's request time-of-day values are on 2026-10-01 (the fixture day),
    so every search uses no window (all time) unless a test says otherwise.
    """
    from tests.fixtures.timeline import build_scenario, build_web_scenario

    app = create_app(settings or _settings(tmp_path))
    with TestClient(app) as client:
        if with_scenario:
            asyncio.run(build_scenario(app.state.db))
        asyncio.run(build_web_scenario(app.state.db))
        yield app, client


def _web_start_ids() -> dict[str, str]:
    """Start (first) request id → connection id for the web scenario."""
    from tests.fixtures.timeline import WEB_START_IDS

    return {rid: conn for conn, rid in WEB_START_IDS.items()}


def _web_blocks(body: str) -> dict[str, str]:
    """Map connection id → its web ``<tbody class="result">`` block on a results page.

    Rows are identified by their Focus link (``/search?cmd=<start request id>``), which
    is omitted only on a ``cmd=`` focus page (use :func:`_blocks` there).
    """
    by_start = _web_start_ids()
    out: dict[str, str] = {}
    for block in _blocks(body):
        if 'class="pill pill-web"' not in block:
            continue
        match = re.search(r'href="/search\?cmd=([^"&]+)"', block)
        assert match is not None, block[:300]
        out[by_start[match.group(1)]] = block
    return out


def _web_ids_in(client: TestClient, url: str) -> set[str]:
    """Connection ids of every web row on every page of ``url`` (walks Next links)."""
    found: set[str] = set()
    for body in _walk_pages(client, url):
        found |= set(_web_blocks(body))
    return found


def _cell_text(fragment: str) -> str:
    """Visible text of an HTML fragment (tags dropped, entities unescaped, spaces collapsed)."""
    return re.sub(r"\s+", " ", html_lib.unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


ALL_WEB_CONNS = {"wc-h", "wc-a", "wc-j", "wc-b", "wc-c", "wc-d", "wc-e", "wc-f", "wc-i", "wc-k", "wc-g"}


def test_search_type_web_lists_one_row_per_connection_newest_first(tmp_path: Path) -> None:
    """``type=web`` lists every web connection once, by first-request time, newest first."""
    with _web_client(tmp_path) as (_app, client):
        bodies = _walk_pages(client, "/search?type=web&page_size=3")
    assert len(bodies) == 4  # 11 connections, 3 per page
    seen: list[str] = []
    times: list[str] = []
    for body in bodies:
        blocks = _blocks(body)
        assert all('class="pill pill-web"' in b for b in blocks)
        seen += list(_web_blocks(body))
        times += [_block_at(b) for b in blocks]
    assert sorted(seen) == sorted(ALL_WEB_CONNS)
    assert len(set(seen)) == len(seen)
    assert times == sorted(times, reverse=True)
    assert times[0] == "2026-10-01T23:59:00.000Z" and times[-1] == "2026-10-01T08:59:59.000Z"


def test_search_web_row_for_an_exact_managed_app(tmp_path: Path) -> None:
    """Managed ``exact`` row: kind pill, HTTPS badge, app name, managed pill, gateway-id title."""
    with _web_client(tmp_path) as (_app, client):
        blocks = _web_blocks(_get(client, "/search?type=web&page_size=200").text)
    block = blocks["wc-a"]
    summary, _, detail = block.partition('<tr class="command-requests result-detail">')
    assert '<span class="pill pill-web">Web connection</span>' in summary
    assert re.search(r'<span class="pill pill-https" title="HTTPS \(configured\): [^"]*not proof', summary)
    assert "marker" not in summary  # verify_full: no upstream marker
    assert '<div class="web-app" title="gateway gw-aaa">' in summary
    assert '<span class="dim">app:</span>' in summary
    assert '<span class="app-name">Wiki Prod</span>' in summary
    assert '<span class="pill pill-managed"' in summary and ">managed</span>" in summary
    assert '<td class="mono"><a href="/systems/wiki.corp.internal">wiki.corp.internal</a></td>' in summary
    assert "<a class=\"user-link\" href=\"/search?user=alice%40example.com\">alice@example.com</a>" in summary
    # Primary request = the first POST; the row shows its method, stored URL, and status.
    assert '<span class="method mono">POST</span>' in summary
    assert '<span class="mono request-url">/login</span>' in summary
    assert '<span class="status status-2xx">200</span>' in summary
    assert "3 requests" in _cell_text(summary)
    # Never a User-Agent or command label.
    assert "Mozilla" not in block and "command-label" not in block
    # Details: every request of the connection, in a native <details> (closed).
    assert "<summary>Requests (3)</summary>" in detail
    assert "<details>" in detail and "<details open>" not in detail
    for url in ("/home", "/login", "/static/app.js"):
        assert f'<td class="mono request-url">{url}</td>' in detail


def test_search_web_row_visit_and_focus_links(tmp_path: Path) -> None:
    """The Visit link carries the user key and the connection's own bounds; Focus carries ``cmd``."""
    with _web_client(tmp_path) as (_app, client):
        blocks = _web_blocks(_get(client, "/search?type=web&page_size=200").text)
    hrefs = _hrefs(blocks["wc-a"])
    assert "/search?cmd=ww-a1" in hrefs
    visit = [h for h in hrefs if "/web?" in h]
    assert visit == [
        "/systems/wiki.corp.internal/web?user=uid-alice"
        "&from=2026-10-01T10%3A00%3A30.000Z&to=2026-10-01T10%3A00%3A32.000Z"
    ]
    # No stored gwops value (app, gateway id) ever appears in any href.
    assert not any("Wiki" in h or "gw-aaa" in h for h in hrefs)


def test_search_web_row_for_an_exact_unmanaged_app_with_upstream_marker(tmp_path: Path) -> None:
    """Unmanaged ``exact`` row: ``unmanaged`` pill, parentheses in the name, CA-only marker."""
    with _web_client(tmp_path) as (_app, client):
        blocks = _web_blocks(_get(client, "/search?type=web&page_size=200").text)
    summary = blocks["wc-b"].partition('<tr class="command-requests')[0]
    assert '<div class="web-app" title="gateway gw-bbb">' in summary
    assert '<span class="app-name">Docs (beta)</span>' in summary
    assert '<span class="pill pill-unmanaged"' in summary and ">unmanaged</span>" in summary
    assert "pill-managed" not in summary
    assert 'class="marker marker-info"' in summary and "CA-only upstream" in summary
    # DELETE is the primary request (the first mutating method), not the earlier GET.
    assert '<span class="method mono">DELETE</span>' in summary
    assert '<span class="mono request-url">/items/42</span>' in summary


def test_search_web_row_with_null_app_says_unnamed(tmp_path: Path) -> None:
    """An ``exact`` snapshot with a NULL app shows the fixed ``(unnamed)`` label and keeps the pill."""
    from tests.fixtures.timeline import add_connection, add_request, at

    with _web_client(tmp_path) as (app, client):
        asyncio.run(add_connection(
            app.state.db, "wc-null-app", user_id="uid-x", username="x@example.com",
            resource_address="unnamed.corp.internal", state="api", resource_type="WEB_APP",
            gwops_match="exact", gwops_gateway_id="gw-n", gwops_app=None, gwops_managed=False,
            downstream_tls="tls13", upstream_tls="verify_full",
        ))
        asyncio.run(add_request(
            app.state.db, "ww-null-1", conn_id="wc-null-app", requested_at=at("15:00:00.000"),
            resource_address="unnamed.corp.internal", user_id="uid-x", username="x@example.com",
            url="/", api_kind="web", kubectl_session=None, kubectl_command=None,
            downstream_tls="tls13", upstream_tls="verify_full",
        ))
        body = _get(client, "/search?type=web&system=unnamed.corp.internal").text
    (block,) = _blocks(body)
    assert '<div class="web-app" title="gateway gw-n">' in block
    assert '<span class="app-name is-unnamed">(unnamed)</span>' in block
    assert ">unmanaged</span>" in block


def test_search_web_row_with_null_gateway_id_title_is_the_fixed_text(tmp_path: Path) -> None:
    """gwops Mode B (NULL gateway id): the title is "gateway id not yet assigned"; row is in (unknown)."""
    with _web_client(tmp_path) as (_app, client):
        blocks = _web_blocks(_get(client, "/search?type=web&page_size=200").text)
    summary = blocks["wc-g"].partition('<tr class="command-requests')[0]
    assert '<div class="web-app" title="gateway id not yet assigned">' in summary
    assert '<span class="app-name">Legacy</span>' in summary
    assert "None" not in summary
    assert '<a href="/systems/_unknown">(unknown)</a>' in summary
    # No username: the user key (the id) is the label.
    assert "uid-dave" in summary


@pytest.mark.parametrize("conn", ["wc-d", "wc-e", "wc-f", "wc-i"], ids=["none", "ambiguous", "absent", "no-conn-row"])
def test_search_web_row_without_an_exact_match_shows_no_app_element(tmp_path: Path, conn: str) -> None:
    """``none``, ``ambiguous``, absent, and connection-row-less rows carry no app element."""
    with _web_client(tmp_path) as (_app, client):
        blocks = _web_blocks(_get(client, "/search?type=web&page_size=200").text)
    summary = blocks[conn].partition('<tr class="command-requests')[0]
    for absent in ("web-app", "app:", "app-name", "pill-managed", "pill-unmanaged", "gateway gw", "(unnamed)"):
        assert absent not in summary, (conn, absent)
    # The request line and the links are still there.
    assert 'class="request-cell"' in summary and "web-row-link" in summary


def test_search_web_row_tls_unknown_badge_for_none_ambiguous_and_absent(tmp_path: Path) -> None:
    """Rows with no usable snapshot show ``TLS unknown`` and no upstream marker."""
    with _web_client(tmp_path) as (_app, client):
        blocks = _web_blocks(_get(client, "/search?type=web&page_size=200").text)
    for conn in ("wc-d", "wc-e", "wc-f"):
        cluster = re.search(r'<div class="badge-cluster">(.*?)</div>', blocks[conn], re.S)
        assert cluster is not None
        assert _cell_text(cluster.group(1)) == "Web connection TLS unknown"
    # Configured modes (not the connection row) decide the badge of a row with a start-row snapshot.
    cluster_h = re.search(r'<div class="badge-cluster">(.*?)</div>', blocks["wc-h"], re.S)
    assert _cell_text(cluster_h.group(1)) == "Web connection HTTP ! Unverified upstream"


def test_search_web_row_escapes_app_name_and_gateway_id_in_text_and_title(tmp_path: Path) -> None:
    """HTML metacharacters and quotes in the app name and gateway id never become markup.

    The gateway id is charset-restricted at ingest, so a hostile one cannot arrive
    through ``/ingest``; it is stored directly here to prove the template escapes the
    double-quoted ``title`` attribute regardless (WEBAPP_SPEC §8.5, §10).
    """
    from tests.fixtures.timeline import add_connection, add_request, at

    app_name = "<img src=x onerror=alert(1)> \"q\" 'a' & </div>"
    gateway = 'gw"><script>alert(2)</script>'
    with _web_client(tmp_path) as (app, client):
        asyncio.run(add_connection(
            app.state.db, "wc-xss", user_id="uid-x", username="x@example.com",
            resource_address="xss.corp.internal", state="api", resource_type="WEB_APP",
            gwops_match="exact", gwops_gateway_id=gateway, gwops_app=app_name, gwops_managed=False,
            downstream_tls="tls13", upstream_tls="verify_full",
        ))
        asyncio.run(add_request(
            app.state.db, "ww-xss-1", conn_id="wc-xss", requested_at=at("15:00:00.000"),
            resource_address="xss.corp.internal", user_id="uid-x", username="x@example.com",
            url="/", api_kind="web", kubectl_session=None, kubectl_command=None,
            downstream_tls="tls13", upstream_tls="verify_full",
        ))
        body = _get(client, "/search?type=web&system=xss.corp.internal").text
    assert "<img src=x" not in body and "<script>alert" not in body
    assert "onerror=alert(1)>" not in body
    (block,) = _blocks(body)
    title = re.search(r'<div class="web-app" title="([^"]*)">', block)
    assert title is not None, "the title attribute was broken by a stored value"
    assert html_lib.unescape(title.group(1)) == f"gateway {gateway}"
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in block  # also escaped inside the attribute
    name = re.search(r'<span class="app-name">(.*?)</span>', block, re.S)
    assert name is not None
    assert html_lib.unescape(name.group(1)) == app_name
    assert "&lt;img src=x onerror=alert(1)&gt;" in name.group(1)


def test_search_web_focus_banner_and_open_details(tmp_path: Path) -> None:
    """``cmd=<request id>`` focuses one web connection: banner, clear link ``type=web``, open details."""
    with _web_client(tmp_path) as (_app, client):
        # Any request of the connection resolves to it (here the connection's LAST request).
        focus = _get(client, "/search?cmd=ww-a3")
        by_start = _get(client, "/search?cmd=ww-a1")
    for resp in (focus, by_start):
        assert resp.status_code == 200
        blocks = _blocks(resp.text)
        assert len(blocks) == 1
        assert 'class="pill pill-web"' in blocks[0]
        assert "<details open>" in blocks[0]
        assert "Showing one web connection" in resp.text
        assert "Showing one kubectl command" not in resp.text
        banner = re.search(r'<p class="notice notice-focus">(.*?)</p>', resp.text, re.S)
        assert banner is not None
        assert 'href="/search?type=web"' in banner.group(1)
        assert "Command or web connection not found" not in resp.text
        # The row itself no longer offers a Focus link (it is the focus), but keeps Visit.
        assert ">Focus" not in blocks[0] and "Visit" in blocks[0]
        assert '<span class="app-name">Wiki Prod</span>' in blocks[0]


def test_search_cmd_focus_on_a_web_request_hides_the_recording_exclusion_notice(
    tmp_path: Path,
) -> None:
    """``cmd`` excludes the recording kinds, but under a focus that notice is not listed."""
    with _web_client(tmp_path, with_scenario=True) as (_app, client):
        resp = _get(client, "/search?cmd=ww-b2")
    assert resp.status_code == 200
    assert len(_blocks(resp.text)) == 1 and "Docs (beta)" in resp.text
    assert "not searched" not in resp.text


def test_search_any_interleaves_web_rows_with_other_kinds(tmp_path: Path) -> None:
    """``type=any`` merges web rows by time with recordings and kubectl commands."""
    with _web_client(tmp_path, with_scenario=True) as (_app, client):
        resp = _get(client, "/search?page_size=200")
    blocks = _blocks(resp.text)
    kinds = set(re.findall(r'class="pill (pill-(?:ssh|exec|failed|kubectl|web))"', resp.text))
    assert kinds == {"pill-ssh", "pill-exec", "pill-failed", "pill-kubectl", "pill-web"}
    times = [_block_at(b) for b in blocks]
    assert times == sorted(times, reverse=True)
    web = _web_blocks(resp.text)
    assert set(web) == ALL_WEB_CONNS
    kinds_in_order = [re.search(r'class="pill (pill-[a-z]+)"', b).group(1) for b in blocks]
    first_web = kinds_in_order.index("pill-web")
    last_web = len(kinds_in_order) - 1 - kinds_in_order[::-1].index("pill-web")
    # A genuine merge: other kinds sit between the first and the last web row.
    assert any(k != "pill-web" for k in kinds_in_order[first_web:last_web])


def test_search_web_rows_are_absent_under_every_other_type(tmp_path: Path) -> None:
    """Web rows only appear under ``web`` and ``any``: not ``recordings``, ``ssh``, ``exec``, ``failed``, ``kubectl``."""
    with _web_client(tmp_path, with_scenario=True) as (_app, client):
        bodies = {
            t: _get(client, f"/search?type={t}&page_size=200").text
            for t in ("recordings", "ssh", "exec", "failed", "kubectl")
        }
    for t, body in bodies.items():
        assert 'class="pill pill-web"' not in body, t
        assert "/zebra-path" not in body and "/wiki/start" not in body, t


# --- scheme / upstream filters ---------------------------------------------------------

SCHEME_EXPECTED = {
    "https": {"wc-a", "wc-j", "wc-b", "wc-i", "wc-k", "wc-g"},
    "http": {"wc-h", "wc-c"},
    "unknown": {"wc-d", "wc-e", "wc-f"},
}
UPSTREAM_EXPECTED = {
    "verified": {"wc-a", "wc-i", "wc-k"},
    "ca_only": {"wc-b"},
    "unverified": {"wc-h", "wc-j"},
    "plaintext": {"wc-c", "wc-g"},
    "unknown": {"wc-d", "wc-e", "wc-f"},
}


@pytest.mark.parametrize("value", sorted(SCHEME_EXPECTED))
def test_search_scheme_filter_matches_the_start_rows_configured_client_tls(
    tmp_path: Path, value: str
) -> None:
    """``scheme`` filters on the connection's START row: https = tls13, http = none, unknown = NULL.

    ``wc-k``'s second request differs (``none``), but its start row says ``tls13``.
    """
    with _web_client(tmp_path) as (_app, client):
        got = _web_ids_in(client, f"/search?type=web&scheme={value}&page_size=2")
    assert got == SCHEME_EXPECTED[value]


@pytest.mark.parametrize("value", sorted(UPSTREAM_EXPECTED))
def test_search_upstream_filter_matches_the_start_rows_configured_upstream_tls(
    tmp_path: Path, value: str
) -> None:
    """``upstream``: verified = verify_full, ca_only = verify_ca, unverified = insecure, plaintext = none."""
    with _web_client(tmp_path) as (_app, client):
        got = _web_ids_in(client, f"/search?type=web&upstream={value}&page_size=2")
    assert got == UPSTREAM_EXPECTED[value]


def test_search_scheme_and_upstream_combine_with_and(tmp_path: Path) -> None:
    """Both filters at once keep only connections matching both."""
    with _web_client(tmp_path) as (_app, client):
        both = _web_ids_in(client, "/search?type=web&scheme=https&upstream=plaintext")
        none = _web_ids_in(client, "/search?type=web&scheme=http&upstream=verified")
        unknown_both = _web_ids_in(client, "/search?type=web&scheme=unknown&upstream=unknown")
    assert both == {"wc-g"}
    assert none == set()
    assert unknown_both == {"wc-d", "wc-e", "wc-f"}


def test_search_scheme_filter_combines_with_system_user_and_text(tmp_path: Path) -> None:
    """The TLS filters narrow, never widen, the existing system / user / text filters."""
    with _web_client(tmp_path) as (_app, client):
        wiki_https = _web_ids_in(
            client, "/search?type=web&scheme=https&system=wiki.corp.internal"
        )
        bob_ca = _web_ids_in(client, "/search?type=web&upstream=ca_only&user=bob%40example.com")
        zebra_unknown = _web_ids_in(client, "/search?type=web&scheme=unknown&q=zebra")
        zebra_https = _web_ids_in(client, "/search?type=web&scheme=https&q=zebra")
    assert wiki_https == {"wc-a", "wc-j", "wc-b", "wc-i", "wc-k"}
    assert bob_ca == {"wc-b"}
    assert zebra_unknown == {"wc-f"}
    assert zebra_https == set()


@pytest.mark.parametrize(
    ("query", "name", "echo"),
    [
        ("scheme=SENTINELBAD", "scheme", "SENTINELBAD"),
        ("scheme=HTTPS", "scheme", "HTTPS"),
        ("scheme=tls13", "scheme", "tls13"),
        ("upstream=SENTINELBAD", "upstream", "SENTINELBAD"),
        ("upstream=verify_full", "upstream", "verify_full"),
        ("scheme=https&scheme=http", "scheme", "https"),
        ("upstream=verified&upstream=plaintext", "upstream", "plaintext"),
    ],
)
def test_search_invalid_or_repeated_scheme_and_upstream_are_400(
    tmp_path: Path, query: str, name: str, echo: str
) -> None:
    """Invalid, wrong-case, raw-mode, or repeated values: 400 naming the parameter, never the value."""
    with _web_client(tmp_path) as (_app, client):
        page = _get(client, f"/search?type=web&{query}")
        partial = _get(client, f"/search?type=web&{query}", **{"HX-Request": "true"})
        csv_resp = _export(client, f"type=web&{query}")
    for resp in (page, partial, csv_resp):
        assert resp.status_code == 400, query
        assert f"'{name}'" in html_lib.unescape(resp.text), query
        assert echo not in resp.text, f"{query} echoed {echo}"
    assert "detail" in page.json() and "detail" in csv_resp.json()
    assert "<html" not in partial.text.lower()


def test_search_blank_scheme_and_upstream_mean_any(tmp_path: Path) -> None:
    """The form submits ``scheme=&upstream=`` for "Any": blank values are no filter, not a 400."""
    with _web_client(tmp_path) as (_app, client):
        blank = _web_ids_in(client, "/search?type=web&scheme=&upstream=")
    assert blank == ALL_WEB_CONNS


def test_search_any_with_scheme_excludes_other_kinds_with_a_notice(tmp_path: Path) -> None:
    """``type=any&scheme=http``: only web rows, and one notice naming the skipped kinds and filter."""
    with _web_client(tmp_path, with_scenario=True) as (_app, client):
        resp = _get(client, "/search?type=any&scheme=http&page_size=200")
    assert resp.status_code == 200
    web = _web_blocks(resp.text)
    assert set(web) == SCHEME_EXPECTED["http"]
    assert len(_blocks(resp.text)) == len(web)  # nothing but web rows
    notices = re.findall(r'<p class="notice"><span aria-hidden="true">ⓘ</span> (.*?)</p>', resp.text, re.S)
    assert notices == [
        "SSH sessions, kubectl exec recordings, Failed connections and kubectl commands "
        "not searched: the HTTP/HTTPS filter applies to web connections only."
    ]


def test_search_upstream_filter_notice_names_the_upstream_label(tmp_path: Path) -> None:
    """The ``upstream`` filter has its own notice wording (``Upstream TLS filter``)."""
    with _web_client(tmp_path, with_scenario=True) as (_app, client):
        resp = _get(client, "/search?upstream=verified&page_size=200")
    assert "not searched: the Upstream TLS filter applies to web connections only." in resp.text
    assert set(_web_blocks(resp.text)) == UPSTREAM_EXPECTED["verified"]


@pytest.mark.parametrize("type_", ["kubectl", "recordings", "ssh", "exec", "failed"])
def test_search_scheme_with_a_non_web_type_excludes_everything(tmp_path: Path, type_: str) -> None:
    """A web-only filter with a type that cannot evaluate it: no type can be searched."""
    with _web_client(tmp_path, with_scenario=True) as (_app, client):
        resp = _get(client, f"/search?type={type_}&scheme=https")
    assert resp.status_code == 200
    assert "No type can be searched with these filters." in resp.text
    assert _blocks(resp.text) == []


def test_search_web_has_no_findings_so_finding_filters_return_no_web_rows(tmp_path: Path) -> None:
    """Web evaluates the finding filters but has no rules: ``has_findings=true`` lists no web row."""
    with _web_client(tmp_path) as (_app, client):
        flagged = _get(client, "/search?type=web&has_findings=true")
        severe = _get(client, "/search?type=web&severity=low")
        unflagged = _web_ids_in(client, "/search?type=web&has_findings=false")
    assert flagged.status_code == 200 and _blocks(flagged.text) == []
    assert severe.status_code == 200 and _blocks(severe.text) == []
    assert unflagged == ALL_WEB_CONNS


def test_search_web_text_matches_the_stored_url_case_insensitively(tmp_path: Path) -> None:
    """``q`` is a case-insensitive substring over the stored URL: unmasked path, masked query."""
    from urllib.parse import quote

    with _web_client(tmp_path) as (_app, client):
        path_hit = _web_ids_in(client, "/search?type=web&q=ZEBRA-PATH")
        deep_hit = _web_ids_in(client, "/search?type=web&q=static/app.js")
        masked = _web_ids_in(client, "/search?type=web&q=" + quote("term=se…(9)"))
        miss = _web_ids_in(client, "/search?type=web&q=nothing-matches-this")
    assert path_hit == {"wc-f"}
    assert deep_hit == {"wc-a"}  # a request that is not the connection's primary one
    assert masked == {"wc-b"}
    assert miss == set()


def test_search_web_user_agent_is_never_rendered_or_searchable(tmp_path: Path) -> None:
    """The stored User-Agent is not on any web row and ``q`` does not match it."""
    from tests.fixtures.timeline import WEB_UA

    with _web_client(tmp_path) as (_app, client):
        page = _get(client, "/search?type=web&page_size=200")
        by_ua = _get(client, "/search?type=web&q=Mozilla")
    assert WEB_UA not in page.text and "Mozilla" not in page.text
    assert _blocks(by_ua.text) == []


def test_search_form_has_web_filters_block_with_both_selects(tmp_path: Path) -> None:
    """The form carries a "Web filters (configured TLS)" block with two labelled selects."""
    with _web_client(tmp_path) as (_app, client):
        body = _get(client, "/search").text
        open_body = _get(client, "/search?scheme=https").text
    block = re.search(r'<details class="web-search-form-filters"( open)?>(.*?)</details>', body, re.S)
    assert block is not None and block.group(1) is None  # closed when no web filter is set
    assert "Web filters (configured TLS)" in block.group(2)
    assert "Configured client TLS" in block.group(2) and "Configured upstream TLS" in block.group(2)
    scheme = re.search(r'<select name="scheme">(.*?)</select>', block.group(2), re.S)
    upstream = re.search(r'<select name="upstream">(.*?)</select>', block.group(2), re.S)
    assert scheme is not None and upstream is not None
    opts = lambda s: re.findall(r'<option value="([^"]*)"[^>]*>([^<]*)</option>', s.group(1))  # noqa: E731
    assert opts(scheme) == [("", "Any"), ("https", "HTTPS"), ("http", "HTTP"), ("unknown", "Unknown")]
    assert opts(upstream) == [
        ("", "Any"), ("verified", "Verified"), ("ca_only", "CA only"),
        ("unverified", "Unverified"), ("plaintext", "Plaintext"), ("unknown", "Unknown"),
    ]
    # It opens, and the chosen value is sticky, when a web filter is active.
    assert re.search(r'<details class="web-search-form-filters" open>', open_body)
    assert '<option value="https" selected>HTTPS</option>' in open_body


def test_search_form_keeps_the_upstream_choice_sticky(tmp_path: Path) -> None:
    """The upstream select shows the chosen value; Export CSV carries both filters."""
    with _web_client(tmp_path) as (_app, client):
        body = _get(client, "/search?type=web&scheme=http&upstream=plaintext").text
    assert '<option value="plaintext" selected>Plaintext</option>' in body
    assert '<option value="http" selected>HTTP</option>' in body
    assert 'href="/search/export.csv?type=web&amp;scheme=http&amp;upstream=plaintext"' in body


def test_search_web_cursor_pages_keep_the_filters_and_bind_the_kind_set(tmp_path: Path) -> None:
    """A Next link under ``scheme`` carries it; the cursor binds the kind set and sort, not the values.

    Same precedent as the other filters: a cursor replayed against a different TYPE is
    a 400, while the filter values themselves are re-applied from the URL.
    """
    with _web_client(tmp_path) as (_app, client):
        first = _get(client, "/search?type=web&scheme=https&page_size=2")
        nxt = _next_href(first.text)
        assert nxt is not None and "scheme=https" in nxt and "type=web" in nxt
        other_kinds = _get(client, nxt.replace("type=web&scheme=https", "type=recordings"))
        second = _get(client, nxt)
    assert other_kinds.status_code == 400
    assert second.status_code == 200
    got = set(_web_blocks(first.text)) | set(_web_blocks(second.text))
    assert got <= SCHEME_EXPECTED["https"] and len(got) == 4


# --- Q19: a rejected gwops object looks exactly like an absent one ----------------------


def _q19_lines(conn_id: str, request_id: str, requested_at: str, gwops: object | None) -> list[str]:
    """One WEB_APP start line (``gwops`` omitted when ``None``) and one request line."""
    ident = {"id": "u-q19", "username": "q19@example.com", "groups": []}
    start: dict[str, object] = {
        "logger": "gateway", "message": "Authenticated connection", "conn_id": conn_id,
        "user": ident, "resource_type": "WEB_APP", "resource_address": "q19.corp.internal",
    }
    if gwops is not None:
        start["gwops"] = gwops
    audit = {
        "logger": "gateway.audit", "message": "API request completed", "request_id": request_id,
        "requested_at": requested_at, "method": "GET", "url": "/report?month=09", "conn_id": conn_id,
        "user": ident, "request": {"headers": {"User-Agent": ["agent/1.0"]}},
        "response": {"headers": {}, "status_code": 200},
    }
    return [json.dumps(start), json.dumps(audit)]


_Q19_VALID = {
    "schema": 1, "gateway_id": "gw-q19", "match": "exact", "app": "Q19 App", "managed": True,
    "downstream_tls": "tls13", "downstream_port": 443, "upstream_tls": "verify_full", "upstream_port": 443,
}
Q19_REJECTED = {
    "schema-2": {**_Q19_VALID, "schema": 2},
    "not-an-object": "gwops-says-hello",
    "bad-mode": {**_Q19_VALID, "downstream_tls": "TLS13"},
    "bad-port": {**_Q19_VALID, "upstream_port": "443"},
    "bad-gateway-id": {**_Q19_VALID, "gateway_id": "has space"},
    "null": None,
}


def _ingest_q19(client: TestClient, app, gwops: object, *, null_key: bool = False) -> None:
    """POST an absent-object connection and a rejected-object connection, then drain."""
    absent = _q19_lines("q19-absent", "q19-req-a", "2026-10-01T10:00:00.000Z", None)
    rejected = _q19_lines("q19-second", "q19-req-r", "2026-10-01T10:05:00.000Z", gwops)
    if null_key:  # `"gwops": null` (key present, value null) must also read as absent
        start = json.loads(rejected[0])
        start["gwops"] = None
        rejected[0] = json.dumps(start)
    resp = client.post(
        "/ingest", content="\n".join([*absent, *rejected]) + "\n",
        headers={"Authorization": "Bearer ingest-token-q19", "Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 204
    client.portal.call(app.state.ingest_queue.join)


def _normalize_q19(text: str) -> str:
    """Strip everything that legitimately differs between the two connections."""
    text = re.sub(r"\d{4}-\d{2}-\d{2}T[0-9A-Za-z%.:]+Z", "TS", text)
    text = text.replace("q19-req-a", "REQ").replace("q19-req-r", "REQ")
    text = text.replace("q19-absent", "CONN").replace("q19-second", "CONN")
    text = text.replace("q19-abse", "CONN").replace("q19-seco", "CONN")  # the visit view's 8-char id
    return text


@pytest.mark.parametrize("name", sorted(Q19_REJECTED))
def test_a_rejected_gwops_object_is_indistinguishable_from_an_absent_one_on_every_surface(
    tmp_path: Path, name: str
) -> None:
    """Q19: page, row, visit, dashboard feed, and CSV show a rejected object exactly as an absent one.

    Two connections on one system send identical traffic; one start line has no
    ``gwops`` key, the other a rejected object. The system page's configuration block
    groups them into ONE line (the same "No gwops data" configuration), their search
    rows and CSV rows are equal after removing ids and times, and the word "reject" /
    "invalid" appears nowhere.
    """
    settings = _settings(tmp_path).model_copy(update={"ingest_token": "ingest-token-q19"})
    app = create_app(settings)
    with TestClient(app) as client:
        _ingest_q19(client, app, Q19_REJECTED[name], null_key=name == "null")
        search = _get(client, "/search?type=web&page_size=200")
        system = _get(client, "/systems/q19.corp.internal?activity_before=2026-10-02T00:00:00Z")
        dashboard = _get(client, "/dashboard?window=all")
        csv_resp = _export(client, "type=web")
        visit_urls = sorted({h for h in _hrefs(search.text) if "/web?" in h})
        visits = [_get(client, u) for u in visit_urls]
        rows_in_db = asyncio.run(
            app.state.activity.gwops_for_connections(["q19-absent", "q19-second"])
        )
    # The stored snapshots are identical: no object, no TLS, no gateway id, no app.
    assert rows_in_db["q19-absent"] == rows_in_db["q19-second"]
    assert all(v is None for v in rows_in_db["q19-second"].model_dump().values())

    blocks = _blocks(search.text)
    assert len(blocks) == 2
    # The final block of a page carries the page tail; cut each at its detail row.
    first_block, second_block = (b.split("</details>")[0] for b in blocks)
    assert _normalize_q19(first_block) == _normalize_q19(second_block)
    assert "pill-tls-unknown" in first_block and "web-app" not in first_block

    cfg = re.search(r'<section class="config-block".*?</section>', system.text, re.S)
    assert cfg is not None
    lines = re.findall(r'<li class="config-line">(.*?)</li>', cfg.group(0), re.S)
    assert len(lines) == 1  # one configuration: the two connections are not told apart
    assert "No gwops data on these connections" in _cell_text(lines[0])
    assert "2 connections" in _cell_text(lines[0])

    assert len(visits) == 2
    for visit in visits:
        assert visit.status_code == 200
        vcfg = re.search(r'<section class="config-block".*?</section>', visit.text, re.S)
        assert vcfg is not None and "No gwops data on these connections" in vcfg.group(0)
        assert "1 connection" in _cell_text(vcfg.group(0))
    assert _normalize_q19(visits[0].text.split("<h1")[1]) == _normalize_q19(visits[1].text.split("<h1")[1])

    assert dashboard.text.count('class="pill pill-web"') == 2
    feed_blocks = [b.split("</tbody>")[0] for b in _blocks(dashboard.text.split('id="feed-heading"')[1])]
    assert len(feed_blocks) == 2
    assert _normalize_q19(feed_blocks[0]) == _normalize_q19(feed_blocks[1])

    rows = _csv_rows(csv_resp)
    assert len(rows) == 3
    first, second = (_normalize_q19(",".join(r)) for r in rows[1:])
    assert first == second
    for row in rows[1:]:
        assert row[15:] == ["WEB_APP", "unknown", "unknown", "month=…(2)", "", "", ""]

    for page in (search, system, dashboard, csv_resp, *visits):
        assert not re.search(r"reject|invalid|malformed", page.text, re.I), page.url


# --- Dashboard -------------------------------------------------------------------------


def _db_scalar(app, sql: str) -> int:
    """Run a one-value query on the app's database (inside ``with TestClient``)."""

    async def run() -> int:
        cursor = await app.state.db.execute(sql)
        row = await cursor.fetchone()
        await cursor.close()
        return row[0]

    return asyncio.run(run())


def _request_counts(body: str) -> int:
    """Sum the ``N requests`` figures of every web row on a results page."""
    return sum(int(n) for n in re.findall(r"(\d+) requests?\b", " ".join(
        _cell_text(b.partition('<tr class="command-requests')[0]) for b in _blocks(body)
        if 'class="pill pill-web"' in b
    )))


def test_dashboard_web_tile_counts_the_requests_of_its_linked_web_search(tmp_path: Path) -> None:
    """The web tile equals the request total of the ``type=web`` rows it links to; kubectl excludes web."""
    with _web_client(tmp_path, with_scenario=True) as (app, client):
        body = _get(client, "/dashboard?window=all").text
        tiles = _tiles(body)
        web_url, web_value = tiles["Web requests"]
        kube_url, kube_value = tiles["kubectl API requests"]
        pages = _walk_pages(client, web_url)
        kubectl_total = _db_scalar(app, "SELECT COUNT(*) FROM api_requests WHERE api_kind = 'kubectl'")
        web_total = _db_scalar(app, "SELECT COUNT(*) FROM api_requests WHERE api_kind = 'web'")
    assert web_url == "/search?type=web&window=all"
    assert int(web_value) == web_total == 20
    assert sum(_request_counts(p) for p in pages) == int(web_value)
    assert sum(len(_web_blocks(p)) for p in pages) == len(ALL_WEB_CONNS)
    # The kubectl tile counts kubectl rows only (web rows share the table but not the figure).
    assert kube_url == "/search?type=kubectl&window=all"
    assert int(kube_value) == kubectl_total
    assert int(kube_value) != kubectl_total + web_total


def test_dashboard_web_tile_is_windowed_on_requested_at(tmp_path: Path) -> None:
    """A 7-day window excludes older web requests from the tile; ``all`` counts them."""
    from datetime import datetime, timedelta, timezone

    from tests.fixtures.timeline import add_connection, add_request

    now = datetime.now(tz=timezone.utc)
    recent = _ms(now - timedelta(days=1))
    old = _ms(now - timedelta(days=60))
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        async def seed() -> None:
            for conn, when, n in (("wc-recent", recent, 2), ("wc-old", old, 5)):
                await add_connection(
                    app.state.db, conn, user_id="uid-w", username="w@example.com",
                    resource_address="dash.corp.internal", state="api", resource_type="WEB_APP",
                )
                for i in range(n):
                    await add_request(
                        app.state.db, f"{conn}-{i}", conn_id=conn, requested_at=when,
                        resource_address="dash.corp.internal", user_id="uid-w",
                        username="w@example.com", url=f"/p{i}", api_kind="web",
                        kubectl_session=None, kubectl_command=None,
                    )

        asyncio.run(seed())
        seven = _tiles(_get(client, "/dashboard?window=7").text)
        everything = _tiles(_get(client, "/dashboard?window=all").text)
    assert seven["Web requests"][1] == "2"
    assert seven["Web requests"][0] == "/search?type=web&window=7"
    assert everything["Web requests"][1] == "7"
    assert seven["kubectl API requests"][1] == "0"


def test_dashboard_feed_lists_web_rows_compactly(tmp_path: Path) -> None:
    """The recent-activity feed includes web rows in compact form: Details link, no Focus, no request table."""
    with _web_client(tmp_path) as (_app, client):
        body = _get(client, "/dashboard?window=all").text
    feed = _feed_blocks(body)
    assert feed and all('class="pill pill-web"' in b for b in feed)
    newest = feed[0]
    assert "2026-10-01T23:59:00.000Z" in newest  # wc-g, the newest connection
    assert '<span class="app-name">Legacy</span>' in newest
    assert 'class="details-link"' in newest and "Details" in newest
    assert ">Focus" not in newest
    assert "command-requests" not in newest and "<details" not in newest
    assert "/search?cmd=ww-g1" in _hrefs(newest)
    assert len(feed) == 11  # all eleven connections fit in the 15-item feed


def test_dashboard_web_tile_has_zero_and_card_when_there_is_no_web_data(tmp_path: Path) -> None:
    """With no web rows the tile still renders (zero) and links to ``type=web``."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        tiles = _tiles(_get(client, "/dashboard").text)
    assert tiles["Web requests"] == ("/search?type=web&window=30", "0")


# --- CSV (22 columns per kind) -----------------------------------------------------------

_CSV_SCHEME = {"tls13": "https", "none": "http", None: "unknown"}
_CSV_UPSTREAM = {
    "verify_full": "verified", "verify_ca": "ca_only", "insecure": "unverified",
    "none": "plaintext", None: "unknown",
}
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def _expected_csv_row(conn: dict) -> list[str]:
    """Independently derive the 22 CSV cells of a :data:`WEB_CONNECTIONS` entry (§8.7)."""
    from tests.fixtures.timeline import at

    reqs = conn["requests"]
    primary = next((r for r in reqs if r[2].upper() in _MUTATING), reqs[0])
    first, last = reqs[0], reqs[-1]
    url = primary[3]
    path, sep, query = url.partition("?")
    gw = conn["gwops"]
    has_row = conn.get("row", True)
    match = gw[0] if (gw and has_row) else None
    exact = match == "exact"
    def secs(r: tuple[str, ...]) -> float:
        h, m, s = r[1].split(":")
        return int(h) * 3600 + int(m) * 60 + float(s)

    return [
        str(conn["conn_id"]),
        conn["user"][1] or "",
        conn["system"] or "",
        "",
        at(first[1]),
        at(last[1]),
        str(round(secs(last) - secs(first), 3)),
        "0",
        "",
        "",
        "web",
        "",
        primary[2],
        path,
        str(len(reqs)),
        "WEB_APP",
        _CSV_SCHEME[conn["down"]],
        _CSV_UPSTREAM[conn["up"]],
        query if sep else "",
        (gw[1] or "") if match is not None else "",
        (gw[2] or "") if exact else "",
        ("true" if gw[3] else "false") if exact else "",
    ]


def test_csv_web_rows_have_22_columns_matching_the_stored_data(tmp_path: Path) -> None:
    """Every web connection exports 22 cells; 1–15 keep their meaning; 16–22 follow §8.7."""
    from tests.fixtures.timeline import WEB_CONNECTIONS

    with _web_client(tmp_path) as (_app, client):
        resp = _export(client, "type=web")
    assert resp.status_code == 200
    rows = _csv_rows(resp)
    assert rows[0] == CSV_HEADER and len(rows[0]) == 22
    assert all(len(r) == 22 for r in rows)
    got = {r[0]: r for r in rows[1:]}
    assert set(got) == ALL_WEB_CONNS
    for conn in WEB_CONNECTIONS:
        assert got[str(conn["conn_id"])] == _expected_csv_row(conn), conn["conn_id"]
    assert "x-gatorcast-truncated" not in resp.headers


def test_csv_web_column_rules_spot_checks(tmp_path: Path) -> None:
    """Spot-check each §8.7 rule against literal values (not derived from the fixture)."""
    with _web_client(tmp_path) as (_app, client):
        got = {r[0]: r for r in _csv_rows(_export(client, "type=web"))[1:]}
    # exact + managed: scheme, upstream, gateway id, app, managed=true; kind web, command empty.
    a = got["wc-a"]
    assert a[10:15] == ["web", "", "POST", "/login", "3"]
    assert a[3] == "" and a[7] == "0" and a[8] == "" and a[9] == ""
    assert a[15:] == ["WEB_APP", "https", "verified", "", "gw-aaa", "Wiki Prod", "true"]
    # exact + unmanaged -> managed=false; verify_ca -> ca_only; primary is the DELETE, no query.
    assert got["wc-b"][12:14] == ["DELETE", "/items/42"]
    assert got["wc-b"][15:] == ["WEB_APP", "https", "ca_only", "", "gw-bbb", "Docs (beta)", "false"]
    # insecure -> unverified; none -> plaintext; http scheme.
    assert got["wc-h"][16:19] == ["http", "unverified", ""]
    assert got["wc-c"][15:] == ["WEB_APP", "http", "plaintext", "", "gw-ccc", "Grafana", "true"]
    # none / ambiguous: gateway id only; unknown TLS.
    assert got["wc-d"][15:] == ["WEB_APP", "unknown", "unknown", "", "gw-ddd", "", ""]
    assert got["wc-e"][15:] == ["WEB_APP", "unknown", "unknown", "", "gw-eee", "", ""]
    # absent object: everything gwops-derived is empty.
    assert got["wc-f"][15:] == ["WEB_APP", "unknown", "unknown", "", "", "", ""]
    # no connections row: the request row's configured modes still export, gwops cells are empty.
    assert got["wc-i"][15:] == ["WEB_APP", "https", "verified", "", "", "", ""]
    # exact with a NULL gateway id: the id cell is empty, app and managed are filled.
    assert got["wc-g"][2] == ""  # the NULL system
    assert got["wc-g"][15:] == ["WEB_APP", "https", "plaintext", "", "", "Legacy", "true"]


def test_csv_web_query_column_is_the_masked_query_without_the_question_mark(tmp_path: Path) -> None:
    """Column 19 is the primary request's stored query (masked values) minus ``?``; the path drops it."""
    from tests.fixtures.timeline import add_connection, add_request, at

    with _web_client(tmp_path) as (app, client):
        asyncio.run(add_connection(
            app.state.db, "wc-q", user_id="uid-q", username="q@example.com",
            resource_address="query.corp.internal", state="api", resource_type="WEB_APP",
        ))
        asyncio.run(add_request(
            app.state.db, "ww-q1", conn_id="wc-q", requested_at=at("15:00:00.000"),
            resource_address="query.corp.internal", user_id="uid-q", username="q@example.com",
            url="/report?month=…(2)&token=ab…6(12)", api_kind="web", kubectl_session=None,
            kubectl_command=None,
        ))
        resp = _export(client, "type=web&system=query.corp.internal")
    (row,) = _csv_rows(resp)[1:]
    assert row[13] == "/report"
    assert row[18] == "month=…(2)&token=ab…6(12)"
    assert "?" not in row[18]
    # UTF-8, with the masking ellipsis intact and no byte-order mark (WEBAPP_SPEC Q12).
    assert "…".encode() in resp.content
    assert not resp.content.startswith(b"\xef\xbb\xbf")
    assert resp.content.startswith(b"conn_id,")


def test_csv_formula_guard_applies_to_the_gwops_and_query_columns(tmp_path: Path) -> None:
    """An unmanaged app named ``=…`` (and ``+``/``-``/``@`` gateway ids, a ``-`` query) get a leading ``'``."""
    from tests.fixtures.timeline import add_connection, add_request, at

    cases = [
        ("wc-eq", "=cmd|' /C calc'!A0", "gw-eq", "/p"),
        ("wc-plus", "+SUM(1+1)", "+gw", "/p"),
        ("wc-minus", "-2+3", "-gw", "/p?-key=…(3)"),
        ("wc-at", "@SUM(A1)", "@gw", "/p"),
    ]
    with _web_client(tmp_path) as (app, client):
        for i, (conn, app_name, gateway, url) in enumerate(cases):
            asyncio.run(add_connection(
                app.state.db, conn, user_id="uid-f", username="f@example.com",
                resource_address="formula.corp.internal", state="api", resource_type="WEB_APP",
                gwops_match="exact", gwops_gateway_id=gateway, gwops_app=app_name,
                gwops_managed=False, downstream_tls="tls13", upstream_tls="verify_full",
            ))
            asyncio.run(add_request(
                app.state.db, f"fx-{i}", conn_id=conn, requested_at=at(f"16:0{i}:00.000"),
                resource_address="formula.corp.internal", user_id="uid-f", username="f@example.com",
                url=url, api_kind="web", kubectl_session=None, kubectl_command=None,
                downstream_tls="tls13", upstream_tls="verify_full",
            ))
        resp = _export(client, "type=web&system=formula.corp.internal")
    got = {r[0]: r for r in _csv_rows(resp)[1:]}
    assert got["wc-eq"][20] == "'=cmd|' /C calc'!A0" and got["wc-eq"][19] == "gw-eq"
    assert got["wc-plus"][19:21] == ["'+gw", "'+SUM(1+1)"]
    assert got["wc-minus"][19:21] == ["'-gw", "'-2+3"]
    assert got["wc-minus"][18] == "'-key=…(3)"
    assert got["wc-at"][19:21] == ["'@gw", "'@SUM(A1)"]
    # Nothing in the export starts with a formula character.
    for row in got.values():
        for cell in row:
            assert not cell.startswith(tuple(FORMULA_CHARS)), (row[0], cell)
    # The managed column is the fixed word, never the raw integer.
    assert {r[21] for r in got.values()} == {"false"}


def test_csv_mixed_export_has_22_cells_for_every_kind(tmp_path: Path) -> None:
    """``type=any`` mixes recordings, kubectl, and web rows, each 22 cells, with the right column 16."""
    with _web_client(tmp_path, with_scenario=True) as (_app, client):
        rows = _csv_rows(_export(client))
    assert rows[0] == CSV_HEADER
    assert all(len(r) == 22 for r in rows)
    by_kind: dict[str, list[list[str]]] = {}
    for row in rows[1:]:
        by_kind.setdefault(row[10], []).append(row)
    assert set(by_kind) == {"ssh", "exec", "failed", "kubectl", "web"}
    for row in by_kind["kubectl"]:
        assert row[15:] == ["KUBERNETES", *NO_WEB_CELLS]
    for row in by_kind["web"]:
        assert row[15] == "WEB_APP" and row[16] in {"https", "http", "unknown"}
    for kind in ("ssh", "exec", "failed"):
        for row in by_kind[kind]:
            assert row[16:] == NO_WEB_CELLS  # recordings have no web cells (column 16 is their stored type)
    assert len(by_kind["web"]) == len(ALL_WEB_CONNS)


def test_csv_scheme_and_upstream_filters_apply_to_the_export(tmp_path: Path) -> None:
    """The export follows the page: the same filters select the same connections."""
    with _web_client(tmp_path) as (_app, client):
        rows = _csv_rows(_export(client, "type=web&scheme=https&upstream=plaintext"))
        any_rows = _csv_rows(_export(client, "scheme=http"))
    assert [r[0] for r in rows[1:]] == ["wc-g"]
    assert {r[0] for r in any_rows[1:]} == SCHEME_EXPECTED["http"]
    assert {r[10] for r in any_rows[1:]} == {"web"}


def test_csv_web_path_is_exported_unmasked_by_design(tmp_path: Path) -> None:
    """Accepted risk (WEBAPP_SPEC 5.3 withdrawn, 10): a path token is exported in full; query values are not.

    The CSV ``path`` column is the primary request's stored path. A password-reset style
    path keeps its token verbatim (and the search row shows it too), while the same
    request's query value stays masked.
    """
    from tests.fixtures.timeline import add_connection, add_request, at
    from tests.samples import WEBAPP_PATH_TOKENS

    token = WEBAPP_PATH_TOKENS[0]
    with _web_client(tmp_path) as (app, client):
        asyncio.run(add_connection(
            app.state.db, "wc-token", user_id="uid-t", username="t@example.com",
            resource_address="reset.corp.internal", state="api", resource_type="WEB_APP",
        ))
        asyncio.run(add_request(
            app.state.db, "ww-token-1", conn_id="wc-token", requested_at=at("15:00:00.000"),
            resource_address="reset.corp.internal", user_id="uid-t", username="t@example.com",
            url=f"/reset/{token}?next=/…(5)", api_kind="web", kubectl_session=None,
            kubectl_command=None,
        ))
        csv_resp = _export(client, "type=web&system=reset.corp.internal")
        page = _get(client, "/search?type=web&system=reset.corp.internal")
    (row,) = _csv_rows(csv_resp)[1:]
    assert row[13] == f"/reset/{token}"
    assert row[18] == "next=/…(5)"
    assert token in page.text


def test_search_web_row_for_a_connection_with_no_user_uses_the_unknown_bucket(tmp_path: Path) -> None:
    """No username and no user id: plain "(unknown user)" label, no user link, ``user=_unknown`` visit link."""
    from tests.fixtures.timeline import add_request, at

    with _web_client(tmp_path) as (app, client):
        asyncio.run(add_request(
            app.state.db, "ww-anon-1", conn_id="wc-anon", requested_at=at("15:30:00.000"),
            resource_address="anon.corp.internal", url="/anon", api_kind="web",
            kubectl_session=None, kubectl_command=None, user_agent=None,
        ))
        body = _get(client, "/search?type=web&system=anon.corp.internal").text
        visit = re.search(r'href="(/systems/anon\.corp\.internal/web\?[^"]*)"', body)
        assert visit is not None
        visit_resp = _get(client, html_lib.unescape(visit.group(1)))
    (block,) = _blocks(body)
    summary = block.partition('<tr class="command-requests')[0]
    assert "(unknown user)" in summary
    assert "/search?user=" not in summary
    assert "user=_unknown" in html_lib.unescape(visit.group(1))
    assert visit_resp.status_code == 200 and "(unknown user)" in visit_resp.text


# =============================================================================================
# Session 12 fix loop (route level): F cursor errors, J no-detection notice, K scan-budget text,
# N purged focus, O resolved kinds, P primary beyond 200, D display escaping, R fixed maps,
# I unrecognised TLS in the CSV, and the coverage gaps (101 / failed primary rows).
# =============================================================================================


class _LogSpy:
    """Stand-in for ``routes.log`` that records ``(event, kwargs)`` of every call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def _record(self, event: str, **kw: object) -> None:
        self.calls.append((event, kw))

    debug = info = warning = error = exception = _record


def _fresh_client(tmp_path: Path, *, raise_server_exceptions: bool = True):
    """``(app, client)`` context manager over an empty app (seed inside the ``with``)."""

    @contextlib.contextmanager
    def cm():
        app = create_app(_settings(tmp_path))
        with TestClient(app, raise_server_exceptions=raise_server_exceptions) as client:
            yield app, client

    return cm()


# --- F: only a cursor mismatch is a 400 -------------------------------------------------------------


def test_search_tampered_cursor_is_a_400_for_full_page_and_htmx(tmp_path: Path) -> None:
    """F: a cursor that does not decode, or decodes for another search, is a 400 (never a 500)."""
    with _scenario_client(tmp_path) as (_app, client, _sc):
        next_url = _next_href(_get(client, "/search?page_size=5").text)
        assert next_url is not None
        good = re.search(r"cursor=([^&]+)", next_url).group(1)
        tampered = [good[:-9], "!!!not-a-cursor!!!", good[::-1]]
        for cursor in tampered:
            full = _get(client, f"/search?page_size=5&cursor={cursor}")
            partial = _get(client, f"/search?page_size=5&cursor={cursor}", **{"HX-Request": "true"})
            assert full.status_code == 400, cursor
            assert partial.status_code == 400, cursor
            assert "cursor" in partial.text
        other = _get(client, f"/search?type=ssh&page_size=5&cursor={good}")
    assert other.status_code == 400


def test_search_engine_cursor_mismatch_is_a_400_and_is_logged_without_the_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F: ``run_timeline`` raising CursorMismatch (defense in depth) becomes a 400 + ``search.cursor_mismatch``."""
    from gatorcast.store.timeline import CursorMismatch
    from gatorcast.web import routes

    spy = _LogSpy()
    monkeypatch.setattr(routes, "log", spy)

    async def boom(*args, **kwargs):
        raise CursorMismatch("SENTINEL-CURSOR-VALUE")

    monkeypatch.setattr(routes, "run_timeline", boom)
    with _fresh_client(tmp_path) as (_app, client):
        full = _get(client, "/search")
        partial = _get(client, "/search", **{"HX-Request": "true"})
    assert full.status_code == 400 and partial.status_code == 400
    assert "SENTINEL-CURSOR-VALUE" not in full.text + partial.text
    assert [c for c in spy.calls if c[0] == "search.cursor_mismatch"] == [("search.cursor_mismatch", {})] * 2
    assert "SENTINEL-CURSOR-VALUE" not in repr(spy.calls)


@pytest.mark.parametrize("headers", [{}, {"HX-Request": "true"}], ids=["full", "htmx"])
def test_search_internal_value_error_is_a_500_not_a_400(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, headers: dict[str, str]
) -> None:
    """F: any other ValueError from the engine is an internal error: it must not read as a bad cursor."""
    from gatorcast.web import routes

    spy = _LogSpy()
    monkeypatch.setattr(routes, "log", spy)

    async def boom(*args, **kwargs):
        raise ValueError("internal engine bug")

    monkeypatch.setattr(routes, "run_timeline", boom)
    with _fresh_client(tmp_path, raise_server_exceptions=False) as (_app, client):
        resp = _get(client, "/search", **headers)
    assert resp.status_code == 500
    assert "search.cursor_mismatch" not in [c[0] for c in spy.calls]


def test_search_export_does_not_catch_engine_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """F: the CSV walk has no catch: even a CursorMismatch from the engine is a 500, never a false 400."""
    from gatorcast.store.timeline import CursorMismatch
    from gatorcast.web import routes

    async def boom(*args, **kwargs):
        raise CursorMismatch("engine bug")

    monkeypatch.setattr(routes, "run_timeline", boom)
    with _fresh_client(tmp_path, raise_server_exceptions=False) as (_app, client):
        assert _get(client, "/search/export.csv").status_code == 500
        # ... while a bad client cursor is still rejected before the walk starts.
        assert _get(client, "/search/export.csv?cursor=!!!").status_code == 400


# --- J: the no-detection notice for web ---------------------------------------------------------------

NO_DETECTION = "Web connections are not evaluated by detection rules."


@pytest.mark.parametrize(
    "query",
    [
        "type=web&has_findings=true",
        "type=any&has_findings=true",
        "type=web&severity=high",
        "type=any&max_severity=low",
        "type=web&category=kube-api",
        "type=any&rule_ids=recursive-delete",
        "has_findings=true",
    ],
)
def test_search_notes_that_web_is_not_evaluated_when_a_findings_filter_includes_web(
    tmp_path: Path, query: str
) -> None:
    """J: a findings filter with web among the resolved kinds gets the fixed notice (once)."""
    with _web_client(tmp_path) as (_app, client):
        resp = _get(client, f"/search?{query}")
    assert resp.status_code == 200
    assert resp.text.count(NO_DETECTION) == 1


@pytest.mark.parametrize(
    "query",
    [
        "type=web",
        "type=web&has_findings=false",
        "type=kubectl&has_findings=true",
        "type=recordings&has_findings=true",
        "type=ssh&severity=high",
        "type=any&has_findings=false",
        "type=any",
    ],
)
def test_search_does_not_note_web_detection_when_it_would_be_untrue_or_irrelevant(
    tmp_path: Path, query: str
) -> None:
    """J: no notice for ``has_findings=false`` (web matches), for web-free kind sets, or without a filter."""
    with _web_client(tmp_path, with_scenario=True) as (_app, client):
        resp = _get(client, f"/search?{query}")
    assert resp.status_code == 200
    assert NO_DETECTION not in resp.text


def test_search_cmd_focus_never_shows_the_no_detection_notice(tmp_path: Path) -> None:
    """J: under a ``cmd`` focus the notice is not listed (the focus banner already narrows the page)."""
    with _web_client(tmp_path) as (_app, client):
        resp = _get(client, "/search?cmd=ww-a1&has_findings=true")
    assert resp.status_code == 200
    assert NO_DETECTION not in resp.text


# --- K: the scan-budget text names the kind(s) --------------------------------------------------------


def _seed_many_requests(app, n: int, *, api_kind: str, prefix: str) -> None:
    """``n`` one-request connections of ``api_kind`` (distinct commands), oldest first."""
    from tests.fixtures.timeline import add_connection, add_request, at

    for i in range(n):
        conn = f"{prefix}-{i}"
        asyncio.run(add_connection(
            app.state.db, conn, user_id="uid-k", username="k@example.com",
            resource_address=f"{prefix}.corp.internal", state="api",
            resource_type="WEB_APP" if api_kind == "web" else "KUBERNETES",
        ))
        asyncio.run(add_request(
            app.state.db, f"{conn}-r", conn_id=conn, requested_at=at(f"10:0{i}:00.000"),
            resource_address=f"{prefix}.corp.internal", user_id="uid-k", username="k@example.com",
            api_kind=api_kind, kubectl_session=None if api_kind == "web" else f"ks-{conn}",
            kubectl_command=None if api_kind == "web" else "kubectl get",
        ))


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("type=kubectl", "Scanned 2 kubectl requests without filling the page."),
        ("type=web", "Scanned 2 web requests without filling the page."),
        ("type=any", "Scanned 2 kubectl requests and 2 web requests without filling the page."),
    ],
    ids=["kubectl", "web", "both"],
)
def test_search_scan_budget_text_names_the_kind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, query: str, expected: str
) -> None:
    """K: the notice says which kind(s) the budget stopped (kubectl, web, or both)."""
    from gatorcast.store import timeline

    monkeypatch.setattr(timeline, "_API_SCAN_BUDGET", 2)
    with _fresh_client(tmp_path) as (app, client):
        _seed_many_requests(app, 5, api_kind="kubectl", prefix="kk")
        _seed_many_requests(app, 5, api_kind="web", prefix="ww")
        resp = _get(client, f"/search?{query}&q=no-such-text-anywhere")
    assert resp.status_code == 200
    texts = [_cell_text(n) for n in re.findall(r'<p class="truncated-notice">(.*?)</p>', resp.text, re.S)]
    assert expected in texts, texts
    assert "Continue scanning ›" in resp.text


def test_search_scan_budget_text_without_a_known_source_uses_the_generic_fallback() -> None:
    """K: an unexpected source set reads the neutral per-kind text rather than guessing a kind."""
    from gatorcast.web import routes

    assert routes._SCAN_BUDGET_FALLBACK_TEXT.format(n=7) == "Scanned 7 requests per kind without filling the page."
    assert routes._SCAN_BUDGET_TEXTS.get(frozenset({"sessions"}), routes._SCAN_BUDGET_FALLBACK_TEXT) == (
        routes._SCAN_BUDGET_FALLBACK_TEXT
    )


# --- N: a focus that resolves but is purged before hydration ---------------------------------------


@pytest.mark.parametrize("request_id", ["ww-a2", "r-c1-2"], ids=["web", "kubectl"])
def test_search_focus_purged_before_hydration_shows_the_not_found_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request_id: str
) -> None:
    """N: resolved by the source, rows gone by hydration (retention): the not-found notice, no row."""
    from gatorcast.store.timeline import ApiCommandSource

    async def purged(self, ref):
        return None

    with _web_client(tmp_path, with_scenario=True) as (_app, client):
        ok = _get(client, f"/search?cmd={request_id}")
        assert ok.status_code == 200 and len(_blocks(ok.text)) == 1
        monkeypatch.setattr(ApiCommandSource, "_hydrate_one", purged)
        gone = _get(client, f"/search?cmd={request_id}")
    assert gone.status_code == 200
    assert _blocks(gone.text) == []
    assert "Command or web connection not found. It may have been removed by retention." in gone.text
    assert "Showing no command or web connection" in gone.text


# --- O: the routes pass the resolved kinds to build_sources ----------------------------------------


@pytest.mark.parametrize(
    ("url", "expected_names"),
    [
        ("/search?type=kubectl", {"api_commands"}),
        ("/search?type=web", {"web_conns"}),
        ("/search?type=ssh", {"sessions"}),
        ("/search?type=any", {"sessions", "api_commands", "web_conns"}),
        ("/search?type=any&scheme=https", {"web_conns"}),  # kubectl and recordings are excluded
    ],
)
def test_search_builds_only_the_sources_of_the_resolved_kinds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, url: str, expected_names: set[str]
) -> None:
    from gatorcast.web import routes

    seen: list[set[str]] = []
    real = routes.build_sources

    def spy(db, casts, **kwargs):
        sources = real(db, casts, **kwargs)
        seen.append({s.name for s in sources})
        return sources

    monkeypatch.setattr(routes, "build_sources", spy)
    with _fresh_client(tmp_path) as (_app, client):
        assert _get(client, url).status_code == 200
    assert seen == [expected_names]


def test_dashboard_feed_builds_every_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gatorcast.web import routes

    seen: list[set[str]] = []
    real = routes.build_sources

    def spy(db, casts, **kwargs):
        sources = real(db, casts, **kwargs)
        seen.append({s.name for s in sources})
        return sources

    monkeypatch.setattr(routes, "build_sources", spy)
    with _fresh_client(tmp_path) as (_app, client):
        assert _get(client, "/dashboard").status_code == 200
    assert seen == [{"sessions", "api_commands", "web_conns"}]


def test_pick_label_is_public_on_the_activity_module() -> None:
    """O: the timeline recomputes labels through the public helper."""
    from gatorcast.pipeline import activity
    from gatorcast.store import timeline

    assert activity.pick_label is timeline.pick_label
    assert "_pick_label" not in vars(activity)


# --- P: a primary request beyond the first 200 rows, on the search row and in the CSV -------------


def _seed_long_connection_rows(app, *, api_kind: str, conn_id: str, address: str, delete_at: int) -> None:
    """250 requests one second apart; GET everywhere except a DELETE at index ``delete_at``."""
    from tests.fixtures.timeline import add_connection, add_request

    web = api_kind == "web"
    asyncio.run(add_connection(
        app.state.db, conn_id, user_id="uid-long", username="long@example.com", resource_address=address,
        state="api", resource_type="WEB_APP" if web else "KUBERNETES",
    ))

    async def rows() -> None:
        for i in range(250):
            await add_request(
                app.state.db, f"{conn_id}-{i:03d}", conn_id=conn_id,
                requested_at=f"2026-10-02T09:{i // 60:02d}:{i % 60:02d}.000Z", resource_address=address,
                user_id="uid-long", username="long@example.com",
                method="DELETE" if i == delete_at else "GET",
                url=f"/items/{i:03d}" if web else f"/api/v1/namespaces/default/pods/p{i:03d}",
                api_kind=api_kind, commit=False,
                kubectl_session=None if web else f"ks-{conn_id}",
                kubectl_command=None if web else "kubectl get",
            )
        await app.state.db.commit()

    asyncio.run(rows())


def test_search_web_row_shows_a_primary_delete_beyond_the_listed_rows(tmp_path: Path) -> None:
    """P: 250-request web connection, first DELETE at #230: counts, primary, notice, Visit link, CSV."""
    with _fresh_client(tmp_path) as (app, client):
        _seed_long_connection_rows(app, api_kind="web", conn_id="wlong", address="long.corp.internal", delete_at=230)
        page = _get(client, "/search?type=web")
        csv_resp = _get(client, "/search/export.csv?type=web")
    (block,) = _blocks(page.text)
    summary, _, detail = block.partition('<tr class="command-requests result-detail">')
    assert '<span class="method mono">DELETE</span>' in summary
    assert '<span class="mono request-url">/items/230</span>' in summary
    assert "250 requests" in _cell_text(summary)
    assert "<summary>Requests (200)</summary>" in detail
    assert "First 200 of 250 requests — open the visit view for all." in detail
    assert '<td class="mono request-url">/items/230</td>' not in detail  # past the listed rows
    visit = [h for h in _hrefs(block) if "/web?" in h]
    assert visit == [
        "/systems/long.corp.internal/web?user=uid-long"
        "&from=2026-10-02T09%3A00%3A00.000Z&to=2026-10-02T09%3A04%3A09.000Z"
    ]
    (row,) = _csv_rows(csv_resp)[1:]
    assert (row[10], row[12], row[13], row[14]) == ("web", "DELETE", "/items/230", "250")


def test_search_kubectl_row_shows_a_primary_delete_beyond_the_listed_rows(tmp_path: Path) -> None:
    """P (kubectl): the same, with the activity-view link in the notice."""
    with _fresh_client(tmp_path) as (app, client):
        _seed_long_connection_rows(
            app, api_kind="kubectl", conn_id="klong", address="klong.example.internal", delete_at=230
        )
        page = _get(client, "/search?type=kubectl")
        csv_resp = _get(client, "/search/export.csv?type=kubectl")
    (block,) = _blocks(page.text)
    summary, _, detail = block.partition('<tr class="command-requests result-detail">')
    assert '<span class="method mono">DELETE</span>' in summary
    assert '<span class="mono request-url">/api/v1/namespaces/default/pods/p230</span>' in summary
    assert "250 requests" in _cell_text(summary)
    assert "First 200 of 250 requests — open the activity view for all." in detail
    (row,) = _csv_rows(csv_resp)[1:]
    assert (row[10], row[12], row[13], row[14]) == (
        "kubectl", "DELETE", "/api/v1/namespaces/default/pods/p230", "250"
    )


# --- D: display escaping of control / format / separator characters --------------------------------

RLO = "‮"
ZWSP = "​"
BIDI_PATH = f"/doc{RLO}/evil\tpath{ZWSP}end"
BIDI_SHOWN = "/doc%E2%80%AE/evil%09path%E2%80%8Bend"


def _seed_bidi_rows(app) -> None:
    from tests.fixtures.timeline import add_connection, add_request, at

    asyncio.run(add_connection(
        app.state.db, "wb-1", user_id="uid-d", username="d@example.com", resource_address="bidi.corp.internal",
        state="api", resource_type="WEB_APP", gwops_match="exact", gwops_gateway_id="gw-d",
        gwops_app="Bidi", gwops_managed=True, downstream_tls="tls13", upstream_tls="verify_full",
    ))
    for i, url in enumerate((BIDI_PATH, "/plain")):
        asyncio.run(add_request(
            app.state.db, f"wb-r{i}", conn_id="wb-1", requested_at=at(f"09:00:0{i}.000"),
            resource_address="bidi.corp.internal", user_id="uid-d", username="d@example.com",
            method="DELETE" if i == 0 else "GET", url=url, api_kind="web", user_agent=None,
            downstream_tls="tls13", upstream_tls="verify_full",
        ))
    for i, url in enumerate((f"/api/v1/namespaces/x/pods/a{RLO}b\tc{ZWSP}d", "/api/v1/pods")):
        asyncio.run(add_request(
            app.state.db, f"kb-r{i}", conn_id="kb-1", requested_at=at(f"10:00:0{i}.000"),
            resource_address="kbidi.example.internal", user_id="uid-d", username="d@example.com",
            method="DELETE" if i == 0 else "GET", url=url, kubectl_session="ks-bidi",
            kubectl_command="kubectl delete",
        ))


def _no_raw_format_chars(text: str) -> bool:
    return RLO not in text and ZWSP not in text


def test_search_percent_encodes_control_and_format_characters_in_displayed_urls(tmp_path: Path) -> None:
    """D: U+202E, a tab and a zero-width space in a stored URL render percent-encoded (web and kubectl rows)."""
    with _fresh_client(tmp_path) as (app, client):
        _seed_bidi_rows(app)
        web = _get(client, "/search?type=web")
        kube = _get(client, "/search?type=kubectl")
    assert web.status_code == 200 and kube.status_code == 200
    assert _no_raw_format_chars(web.text) and _no_raw_format_chars(kube.text)
    (wblock,) = _blocks(web.text)
    assert f'<span class="mono request-url">{BIDI_SHOWN}</span>' in wblock  # primary request
    assert f'<td class="mono request-url">{BIDI_SHOWN}</td>' in wblock  # request table
    assert "\t" not in re.search(r'<span class="mono request-url">(.*?)</span>', wblock).group(1)
    (kblock,) = _blocks(kube.text)
    shown = "/api/v1/namespaces/x/pods/a%E2%80%AEb%09c%E2%80%8Bd"
    assert f'<span class="mono request-url">{shown}</span>' in kblock
    assert f'<td class="mono request-url">{shown}' in kblock


def test_dashboard_feed_percent_encodes_the_displayed_url(tmp_path: Path) -> None:
    with _fresh_client(tmp_path) as (app, client):
        _seed_bidi_rows(app)
        resp = _get(client, "/dashboard?window=all")
    assert resp.status_code == 200
    assert _no_raw_format_chars(resp.text)
    assert BIDI_SHOWN in resp.text


def test_csv_keeps_the_stored_value_of_a_url_with_control_and_format_characters(tmp_path: Path) -> None:
    """D: the export is not display-escaped: it carries the stored path, passed through ``_csv_safe``."""
    from gatorcast.web.routes import _csv_safe

    with _fresh_client(tmp_path) as (app, client):
        _seed_bidi_rows(app)
        resp = _get(client, "/search/export.csv?type=web")
    (row,) = _csv_rows(resp)[1:]
    assert row[13] == _csv_safe(BIDI_PATH) == BIDI_PATH
    assert "%E2%80%AE" not in resp.text and "%09" not in resp.text


def test_display_url_helper_encodes_only_control_format_and_separator_categories() -> None:
    from gatorcast.web.routes import _display_url

    assert _display_url(None) is None
    assert _display_url("/plain/%41?a=b&c=d") == "/plain/%41?a=b&c=d"  # '%' and ordinary text untouched
    assert _display_url("/é日本\U0001f600") == "/é日本\U0001f600"
    assert _display_url("/a\nb\rc\x00d\x7fe") == "/a%0Ab%0Dc%00d%7Fe"  # Cc
    assert _display_url("/a​b‏c‮d⁦e﻿") == (
        "/a%E2%80%8Bb%E2%80%8Fc%E2%80%AEd%E2%81%A6e%EF%BB%BF"  # Cf
    )
    assert _display_url("/a b c") == "/a%E2%80%A8b%E2%80%A9c"  # Zl, Zp
    assert _display_url("/a\u0085b") == "/a%C2%85b"  # NEL is Cc


def test_css_isolates_the_stored_text_classes() -> None:
    """D: the classes that wrap stored text carry ``unicode-bidi: isolate`` in app.css."""
    css = (Path(__file__).parent.parent / "src" / "gatorcast" / "web" / "static" / "app.css").read_text(
        encoding="utf-8"
    )
    match = re.search(r"((?:\.[a-z-]+,\s*)+\.[a-z-]+)\s*\{[^}]*unicode-bidi:\s*isolate", css)
    assert match is not None
    selectors = {s.strip() for s in match.group(1).split(",")}
    assert {".request-url", ".app-name", ".method", ".user-link", ".command-label", ".bar-label"} <= selectors


# --- R: fixed maps for status and severity classes --------------------------------------------------

HOSTILE_STATUS = 'x" onmouseover="alert(1)" data-x="'
HOSTILE_SEVERITY = 'high" onclick="alert(2)" class="'


def _seed_hostile_session(app) -> None:
    async def run() -> None:
        db = app.state.db
        await db.execute(
            "INSERT INTO sessions (conn_id, username, resource_address, started_at, duration_seconds, "
            "chunk_count, cast_path, status, finding_count, max_severity, created_at) "
            "VALUES ('hostile-1', 'h@example.com', 'hostile.corp.internal', '2026-10-01T09:00:00.000Z', 5, 1, "
            "'/data/casts/hostile-1.cast', ?, 1, ?, datetime('now'))",
            (HOSTILE_STATUS, HOSTILE_SEVERITY),
        )
        await db.execute(
            "INSERT INTO findings (conn_id, rule_id, category, severity, label, offset_seconds) "
            "VALUES ('hostile-1', 'r1', 'dangerous-command', ?, 'Hostile severity finding', 0.5)",
            (HOSTILE_SEVERITY,),
        )
        await db.commit()

    asyncio.run(run())


def test_hostile_stored_status_and_severity_never_reach_a_class_or_label(tmp_path: Path) -> None:
    """R: an unknown stored status reads ``unknown`` with ``pill-unknown``; an unknown severity is ``sev-none``."""
    with _fresh_client(tmp_path) as (app, client):
        _seed_hostile_session(app)
        pages = {
            "search": _get(client, "/search?type=recordings"),
            "session": _get(client, "/sessions/hostile-1"),
            "system": _get(client, "/systems/hostile.corp.internal"),
        }
    for name, resp in pages.items():
        assert resp.status_code == 200, name
        body = resp.text
        assert 'onmouseover="alert(1)"' not in body, name  # never an attribute of its own
        assert 'onclick="alert(2)"' not in body, name
        assert re.search(r'class="pill pill-unknown">unknown</span>', body), name
        assert 'class="pill pill-complete"' not in body, name
    assert 'class="sev sev-none"' in pages["session"].text
    assert 'class="sev sev-none"' in pages["system"].text
    assert "sev-high" not in pages["session"].text + pages["system"].text
    # The search row never shows an unknown severity at all (``_safe_severity``).
    assert "sev-high" not in pages["search"].text and "sev-none" not in pages["search"].text


# --- I: CSV maps an unrecognised stored TLS mode to ``unknown`` -------------------------------------


def test_csv_maps_unrecognised_tls_modes_to_unknown(tmp_path: Path) -> None:
    """I: a stored mode outside the vocabulary exports as ``unknown`` (never the raw text)."""
    from tests.fixtures.timeline import add_connection, add_request, at

    with _fresh_client(tmp_path) as (app, client):
        asyncio.run(add_connection(
            app.state.db, "wt-1", user_id="uid-t", username="t@example.com", resource_address="tls.corp.internal",
            state="api", resource_type="WEB_APP", gwops_match="exact", gwops_gateway_id="gw-t", gwops_app="T",
            gwops_managed=True, downstream_tls="SENTINEL-DOWN", upstream_tls="SENTINEL-UP",
        ))
        asyncio.run(add_request(
            app.state.db, "wt-r0", conn_id="wt-1", requested_at=at("09:00:00.000"),
            resource_address="tls.corp.internal", user_id="uid-t", username="t@example.com", api_kind="web",
            user_agent=None, downstream_tls="SENTINEL-DOWN", upstream_tls="SENTINEL-UP",
        ))
        resp = _get(client, "/search/export.csv?type=web")
    (row,) = _csv_rows(resp)[1:]
    assert row[15] == "WEB_APP"
    assert (row[16], row[17]) == ("unknown", "unknown")
    assert "SENTINEL" not in resp.text


# --- coverage gaps: a primary 101 (WebSocket) and a primary failed row ------------------------------


def _seed_special_primary_rows(app) -> None:
    from tests.fixtures.timeline import add_connection, add_request, at

    for conn, address, status, outcome in (
        ("w101", "ws.corp.internal", 101, "completed"),
        ("wfail", "fail.corp.internal", None, "failed"),
    ):
        asyncio.run(add_connection(
            app.state.db, conn, user_id="uid-s", username="s@example.com", resource_address=address,
            state="api", resource_type="WEB_APP", downstream_tls="tls13", upstream_tls="verify_full",
        ))
        asyncio.run(add_request(
            app.state.db, f"{conn}-r0", conn_id=conn, requested_at=at("09:00:00.000"),
            resource_address=address, user_id="uid-s", username="s@example.com", url="/socket",
            api_kind="web", user_agent=None, status_code=status, outcome=outcome,
            downstream_tls="tls13", upstream_tls="verify_full",
        ))


def test_search_web_row_with_a_101_primary_shows_the_websocket_label(tmp_path: Path) -> None:
    with _fresh_client(tmp_path) as (app, client):
        _seed_special_primary_rows(app)
        resp = _get(client, "/search?type=web&system=ws.corp.internal")
    (block,) = _blocks(resp.text)
    summary = block.partition('<tr class="command-requests result-detail">')[0]
    assert '<span class="status status-1xx">101</span>' in summary
    assert "WebSocket" in _cell_text(summary)
    assert "outcome-failed" not in summary


def test_search_web_row_with_a_failed_primary_is_marked_failed_with_no_status(tmp_path: Path) -> None:
    with _fresh_client(tmp_path) as (app, client):
        _seed_special_primary_rows(app)
        resp = _get(client, "/search?type=web&system=fail.corp.internal")
    (block,) = _blocks(resp.text)
    summary = block.partition('<tr class="command-requests result-detail">')[0]
    assert '<tr class="result-row is-failed">' in summary
    assert '<span class="outcome-failed">' in summary
    assert "status-" not in summary  # no status chip for a failed request with no status
    assert "WebSocket" not in summary


def test_dashboard_feed_renders_a_101_and_a_failed_primary_web_row(tmp_path: Path) -> None:
    with _fresh_client(tmp_path) as (app, client):
        _seed_special_primary_rows(app)
        resp = _get(client, "/dashboard?window=all")
    assert resp.status_code == 200
    assert '<span class="status status-1xx">101</span>' in resp.text and "WebSocket" in resp.text
    assert '<span class="outcome-failed">' in resp.text
    assert '<tr class="result-row is-failed">' in resp.text


def test_search_web_row_marks_unrecognised_stored_tls_modes(tmp_path: Path) -> None:
    """I: the search row (start row's modes) shows the fixed warning markers, never the stored text."""
    from tests.fixtures.timeline import add_connection, add_request, at

    with _fresh_client(tmp_path) as (app, client):
        asyncio.run(add_connection(
            app.state.db, "wu-1", user_id="uid-u", username="u@example.com", resource_address="u.corp.internal",
            state="api", resource_type="WEB_APP", downstream_tls="SENTINEL-DOWN", upstream_tls="SENTINEL-UP",
        ))
        asyncio.run(add_request(
            app.state.db, "wu-r0", conn_id="wu-1", requested_at=at("09:00:00.000"),
            resource_address="u.corp.internal", user_id="uid-u", username="u@example.com", api_kind="web",
            user_agent=None, downstream_tls="SENTINEL-DOWN", upstream_tls="SENTINEL-UP",
        ))
        resp = _get(client, "/search?type=web")
    (block,) = _blocks(resp.text)
    summary = block.partition('<tr class="command-requests result-detail">')[0]
    assert "Unrecognised TLS mode" in _cell_text(summary)
    assert "Unrecognised upstream TLS mode" in _cell_text(summary)
    assert summary.count('class="marker marker-warn"') == 2
    assert "SENTINEL" not in resp.text and "TLS unknown" not in summary
