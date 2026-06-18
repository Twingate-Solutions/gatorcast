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
import re
from pathlib import Path

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
    """Dashboard severity/category/user rows deep-link to search; systems to its page."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_flagged(app, conn_id="d1", username="alice@x", resource_address="prod.host")
        resp = client.get("/dashboard?window=all", headers=_auth_header())
    assert resp.status_code == 200
    body = resp.text
    # Severity drill-down uses the EXACT max_severity filter.
    assert "max_severity=high" in body
    # Category drill-down.
    assert "category=dangerous-command" in body
    # Top-user row links to that user's sessions in search (username is URL-encoded).
    assert "username=alice%40x" in body
    # Top-system row links to the system's session list page.
    assert "/systems/prod.host" in body
    # Window toggle is present.
    assert "window=7" in body and "window=all" in body


def test_dashboard_window_filters_by_time(tmp_path: Path) -> None:
    """A 7-day window excludes an old session that ``window=all`` includes."""
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
        within = client.get("/dashboard?window=7", headers=_auth_header()).text
        everything = client.get("/dashboard?window=all", headers=_auth_header()).text

    # 7-day window: only the recent user appears.
    assert "recent%40x" in within
    assert "old%40x" not in within
    # All-time: both appear.
    assert "recent%40x" in everything and "old%40x" in everything


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
