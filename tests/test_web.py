"""Smoke tests for the Web UI routes (Session 5).

Uses FastAPI TestClient (synchronous) so no pytest-asyncio event loop
entanglement with TestClient's own thread-per-request model. Async store
helpers are driven with asyncio.run() inside the ``with TestClient`` block
(lifespan has already run and wired app.state).

All UI routes are behind HTTP Basic auth (gatorcast.web.auth.require_ui_auth).
Default creds: admin / change-me.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gatorcast.config import Settings
from gatorcast.main import create_app

# ---------------------------------------------------------------------------
# Minimal valid asciicast v2 document used to seed cast files in tests.
# The UNIQUE_MARKER string lets us verify rule 6: the raw recording text must
# never appear verbatim in the rendered HTML.
# ---------------------------------------------------------------------------
UNIQUE_MARKER = "VAULT_ROOT_TOKEN_SECRET_abc123xyz"
SMALL_CAST = (
    '{"version":2,"width":80,"height":24,"timestamp":1700000000,"user":"ubuntu"}\n'
    f'[0.1,"o","hello {UNIQUE_MARKER}"]\n'
)


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
    """Build an Authorization: Basic header."""
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _seed(app, *, conn_id: str, username: str, resource_address: str | None) -> None:
    """Seed one provisional session row + its .cast file into the live app state.

    Must be called INSIDE ``with TestClient(app) as client`` so lifespan has
    already wired app.state.repo and app.state.casts.

    Uses asyncio.run() to drive async store methods from synchronous test code.
    """
    repo = app.state.repo
    casts = app.state.casts

    asyncio.run(
        repo.upsert_start(
            conn_id=conn_id,
            username=username,
            resource_address=resource_address,
            started_at="2026-01-01T10:00:00Z",
        )
    )
    # Finalize so status == complete and cast_path is set.
    cast_path, _ = asyncio.run(casts.write_cast(conn_id, SMALL_CAST))
    asyncio.run(
        repo.finalize(
            conn_id,
            username=username,
            shell_user="ubuntu",
            started_at="2026-01-01T10:00:00Z",
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


# ---------------------------------------------------------------------------
# Test 1 & 2 — Authentication enforcement
# ---------------------------------------------------------------------------


def test_no_credentials_returns_401_with_www_authenticate(tmp_path: Path) -> None:
    """Missing credentials on a UI route returns 401 with WWW-Authenticate: Basic."""
    app = create_app(_settings(tmp_path))
    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.get("/systems", follow_redirects=False)
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers
    assert resp.headers["WWW-Authenticate"] == "Basic"


def test_wrong_credentials_returns_401(tmp_path: Path) -> None:
    """Wrong password returns 401."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/systems", headers=_auth_header("admin", "wrong-password"))
    assert resp.status_code == 401


def test_correct_credentials_returns_200(tmp_path: Path) -> None:
    """Correct credentials on /systems return 200."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/systems", headers=_auth_header())
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Test 3 — Root redirect
# ---------------------------------------------------------------------------


def test_root_redirects_to_dashboard(tmp_path: Path) -> None:
    """GET / → 307 redirect to /dashboard (do not follow)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/", headers=_auth_header(), follow_redirects=False)
    assert resp.status_code == 307
    assert resp.headers["location"] == "/dashboard"


# ---------------------------------------------------------------------------
# Test 4 — /systems lists seeded addresses + unknown bucket
# ---------------------------------------------------------------------------


def test_systems_lists_resource_addresses_and_unknown_bucket(tmp_path: Path) -> None:
    """Systems page shows seeded resource_address values and the (unknown) bucket."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="conn-known", username="alice@x", resource_address="prod.example.com")
        _seed(app, conn_id="conn-unknown", username="bob@x", resource_address=None)

        resp = client.get("/systems", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.text
    assert "prod.example.com" in body
    assert "(unknown)" in body
    # Both systems have session_count ≥ 1 — counts rendered (not an empty table).
    # We can't pin the exact last_seen timestamp (SQLite datetime('now') at upsert),
    # so just confirm the table rendered real rows (addresses present is sufficient).
    assert "/systems/prod.example.com" in body
    assert "/systems/_unknown" in body


def test_systems_page_ssh_row_badge_timestamps_and_links(tmp_path: Path) -> None:
    """Session 10 §8.4: an SSH system shows the SSH badge, Last session, and a count link."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="conn-a", username="alice@x", resource_address="prod.example.com")
        _seed(app, conn_id="conn-b", username="bob@x", resource_address=None)
        resp = client.get("/systems", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.text
    assert '<span class="pill pill-ssh">SSH</span>' in body
    assert "Kubernetes</span>" not in body
    # started_at "…10:00:00Z" renders in the requested_at format.
    assert "2026-01-01T10:00:00.000Z" in body
    assert 'href="/search?type=recordings&amp;system=prod.example.com"' in body
    assert 'href="/search?type=recordings&amp;system=_unknown"' in body
    # No API requests: no kubectl count link.
    assert "type=kubectl" not in body


def test_system_page_has_search_link_and_user_icon_link(tmp_path: Path) -> None:
    """Session 10 §8.5: "Search this system" and a ⌕ user link beside the replay link."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="s1", username="alice@x", resource_address="db.internal")
        known = client.get("/systems/db.internal", headers=_auth_header())
        _seed(app, conn_id="u1", username="dana@x", resource_address=None)
        unknown = client.get("/systems/_unknown", headers=_auth_header())

    assert known.status_code == 200
    body = known.text
    assert '<a href="/search?system=db.internal">Search this system' in body
    assert 'href="/search?type=kubectl&amp;system=db.internal"' in body
    assert 'href="/sessions/s1"' in body  # the name still links to replay
    assert (
        '<a class="user-link user-link-icon" href="/search?user=alice%40x" '
        'aria-label="All activity for alice@x"'
    ) in body

    assert unknown.status_code == 200
    assert '<a href="/search?system=_unknown">Search this system' in unknown.text


def test_session_detail_user_links_to_search_and_ssh_has_no_command_link(
    tmp_path: Path,
) -> None:
    """Session 10 §8.5: the User value links to /search?user=…; SSH has no command link."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="p0", username="eve@x", resource_address="web.internal")
        resp = client.get("/sessions/p0", headers=_auth_header())

    assert resp.status_code == 200
    assert '<a class="user-link" href="/search?user=eve%40x">eve@x</a>' in resp.text
    assert "/search?cmd=" not in resp.text


# ---------------------------------------------------------------------------
# Test 5 — /systems/{addr} lists sessions; unknown bucket via _unknown slug
# ---------------------------------------------------------------------------


def test_system_sessions_page_lists_sessions(tmp_path: Path) -> None:
    """Sessions for a known system are listed with username, status, duration."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="s1", username="alice@x", resource_address="db.internal")
        _seed(app, conn_id="s2", username="charlie@x", resource_address="db.internal")

        # resource_address percent-encoded
        slug = "db.internal"
        resp = client.get(f"/systems/{slug}", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.text
    assert "alice@x" in body
    assert "charlie@x" in body
    assert "complete" in body
    assert "5:00" in body  # duration 300s → 5:00


def test_system_sessions_unknown_bucket_via_sentinel(tmp_path: Path) -> None:
    """The _unknown slug routes to the NULL resource_address bucket."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="u1", username="dana@x", resource_address=None)

        resp = client.get("/systems/_unknown", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.text
    assert "dana@x" in body
    assert "(unknown)" in body


# ---------------------------------------------------------------------------
# Test 6 — /sessions/{conn_id} detail: AsciinemaPlayer.create present; raw
#           recording text absent (rule 6)
# ---------------------------------------------------------------------------


def test_session_detail_has_player_create_and_cast_url(tmp_path: Path) -> None:
    """Detail page contains AsciinemaPlayer.create and the /cast URL."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="p1", username="eve@x", resource_address="web.internal")

        resp = client.get("/sessions/p1", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.text
    assert "AsciinemaPlayer.create" in body
    assert "/sessions/p1/cast" in body


def test_session_detail_does_not_render_raw_recording_text(tmp_path: Path) -> None:
    """Rule 6: raw recording content (UNIQUE_MARKER) must not appear in HTML."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="p2", username="frank@x", resource_address="sec.internal")

        resp = client.get("/sessions/p2", headers=_auth_header())

    assert resp.status_code == 200
    # The marker is in the .cast file body but must not leak into the HTML
    assert UNIQUE_MARKER not in resp.text


# ---------------------------------------------------------------------------
# Test 7 — /sessions/{conn_id}/cast serves the cast file
# ---------------------------------------------------------------------------


def test_cast_endpoint_returns_cast_file(tmp_path: Path) -> None:
    """GET /sessions/{id}/cast → 200, application/x-asciicast, body == seeded cast."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="c1", username="grace@x", resource_address="ssh.internal")

        resp = client.get("/sessions/c1/cast", headers=_auth_header())

    assert resp.status_code == 200
    assert "application/x-asciicast" in resp.headers["content-type"]
    # Normalize line endings: on Windows CastStore._write_atomic uses write_text
    # which emits \r\n; FileResponse serves bytes as-is. Compare LF-normalized.
    assert resp.text.replace("\r\n", "\n") == SMALL_CAST


def _enc_settings(tmp_path: Path) -> Settings:
    """Like _settings but with encryption enabled and a valid master key."""
    key = base64.b64encode(os.urandom(32)).decode("ascii")
    return Settings(
        data_dir=tmp_path,
        syslog_tcp_port=0,
        ui_auth_username="admin",
        ui_auth_password="change-me",
        encryption_enabled=True,
        master_key=key,
    )


def test_cast_endpoint_decrypts_when_encryption_on(tmp_path: Path) -> None:
    """With encryption on: cast file is ciphertext on disk, route serves plaintext."""
    app = create_app(_enc_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="enc1", username="ivy@x", resource_address="ssh.internal")

        # The on-disk file must be ciphertext (no plaintext header), rule 5.
        on_disk = (tmp_path / "casts" / "enc1.cast").read_bytes()
        assert on_disk.startswith(b"GCST\x01\x00")
        assert b'{"version":2' not in on_disk

        resp = client.get("/sessions/enc1/cast", headers=_auth_header())

    assert resp.status_code == 200
    assert "application/x-asciicast" in resp.headers["content-type"]
    assert resp.text.replace("\r\n", "\n") == SMALL_CAST


def test_cast_endpoint_encryption_on_requires_auth(tmp_path: Path) -> None:
    """The decrypting cast route is still behind UI auth (rule 6 unchanged)."""
    app = create_app(_enc_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="enc2", username="ivy@x", resource_address="ssh.internal")
        resp = client.get("/sessions/enc2/cast", follow_redirects=False)
    assert resp.status_code == 401


def test_create_app_fails_closed_without_key(tmp_path: Path) -> None:
    """encryption_enabled=true with no master key refuses to boot (fail-closed)."""
    settings = Settings(
        data_dir=tmp_path,
        syslog_tcp_port=0,
        encryption_enabled=True,
        master_key=None,
    )
    with pytest.raises(RuntimeError):
        create_app(settings)


def test_create_app_fails_closed_with_invalid_key(tmp_path: Path) -> None:
    """encryption_enabled=true with an invalid key refuses to boot (fail-closed)."""
    settings = Settings(
        data_dir=tmp_path,
        syslog_tcp_port=0,
        encryption_enabled=True,
        master_key="not-a-valid-32-byte-base64-key",
    )
    with pytest.raises(RuntimeError):
        create_app(settings)


# ---------------------------------------------------------------------------
# Test 8 — 404 for missing session and missing cast file
# ---------------------------------------------------------------------------


def test_missing_session_returns_404(tmp_path: Path) -> None:
    """GET /sessions/{nonexistent} → 404."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/sessions/does-not-exist", headers=_auth_header())
    assert resp.status_code == 404


def test_missing_cast_file_returns_404(tmp_path: Path) -> None:
    """/sessions/{id}/cast → 404 when the .cast file is absent (row exists)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        # Insert provisional row only — no .cast file written.
        asyncio.run(
            app.state.repo.upsert_start(
                conn_id="no-cast",
                username="henry@x",
                resource_address="host",
                started_at="2026-01-01T00:00:00Z",
            )
        )
        resp = client.get("/sessions/no-cast/cast", headers=_auth_header())
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Test 9 — /healthz and /static/* are accessible WITHOUT UI auth
# ---------------------------------------------------------------------------


def test_healthz_accessible_without_auth(tmp_path: Path) -> None:
    """/healthz returns 200 without credentials."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_static_file_accessible_without_auth(tmp_path: Path) -> None:
    """/static/asciinema-player.min.js is served without auth and is non-empty."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/static/asciinema-player.min.js")
    assert resp.status_code == 200
    assert len(resp.content) > 0


# ---------------------------------------------------------------------------
# Test 10 — Offline: no external CDN/font/JS in rendered HTML
# ---------------------------------------------------------------------------


_EXTERNAL_SRC_HREF = re.compile(
    r'(?:src|href)\s*=\s*["\'](?P<url>https?://[^"\']+)["\']',
    re.IGNORECASE,
)


def _external_urls_in_html(html: str) -> list[str]:
    """Return all http(s):// URLs found in src= or href= attributes."""
    return [m.group("url") for m in _EXTERNAL_SRC_HREF.finditer(html)]


def test_systems_page_has_no_external_asset_urls(tmp_path: Path) -> None:
    """Rule 8: /systems HTML must not reference any external (http/https) assets."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/systems", headers=_auth_header())
    assert resp.status_code == 200
    external = _external_urls_in_html(resp.text)
    assert external == [], f"Found external asset URLs: {external}"


def test_session_detail_page_has_no_external_asset_urls(tmp_path: Path) -> None:
    """Rule 8: session detail HTML must not reference external (http/https) assets."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="offline-1", username="iris@x", resource_address="host")
        resp = client.get("/sessions/offline-1", headers=_auth_header())
    assert resp.status_code == 200
    external = _external_urls_in_html(resp.text)
    assert external == [], f"Found external asset URLs: {external}"


# ---------------------------------------------------------------------------
# Session 12 (web apps): shared-page smoke tests (WEBAPP_SPEC §8.5; CLAUDE.md rule 8)
# ---------------------------------------------------------------------------

_WEB_SYSTEM = "wiki.corp.internal"
_WEB_ASSET_PAGES = (
    "/systems",
    f"/systems/{_WEB_SYSTEM}?activity_before=2026-10-02T00:00:00Z",
    f"/systems/{_WEB_SYSTEM}/web?user=uid-alice&from=2026-10-01T10:00:00Z&to=2026-10-01T10:30:00Z",
    "/search?type=web",
    "/search?type=any&scheme=https",
    "/dashboard?window=all",
)


def _seed_web_pages(app) -> None:
    """Load the web scenario (Alice's wiki connections fall inside the visit bounds above)."""
    from tests.fixtures.timeline import build_web_scenario

    asyncio.run(build_web_scenario(app.state.db))


@pytest.mark.parametrize("path", _WEB_ASSET_PAGES)
def test_web_pages_require_auth(tmp_path: Path, path: str) -> None:
    """Every web-bearing page is behind the UI Basic auth (401 + challenge)."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_web_pages(app)
        resp = client.get(path, follow_redirects=False)
    assert resp.status_code == 401
    assert resp.headers.get("WWW-Authenticate") == "Basic"


@pytest.mark.parametrize("path", _WEB_ASSET_PAGES)
def test_web_pages_render_and_reference_no_external_assets(tmp_path: Path, path: str) -> None:
    """Rule 8: the systems, system, visit, web search, and dashboard pages are offline-only."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed_web_pages(app)
        resp = client.get(path, headers=_auth_header())
    assert resp.status_code == 200
    assert _external_urls_in_html(resp.text) == []
    assert "<script>" not in resp.text.replace('<script src=', "")  # no inline script blocks added
    assert resp.headers["content-type"].startswith("text/html")


def test_systems_page_lists_web_systems_alongside_ssh_systems(tmp_path: Path) -> None:
    """An SSH system and a web system each get their own row, badge set, and request links."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="ssh-1", username="iris@x", resource_address="ssh-host")
        _seed_web_pages(app)
        body = client.get("/systems", headers=_auth_header()).text
    ssh_row = next(c for c in body.split("<tr>") if 'href="/systems/ssh-host"' in c)
    web_row = next(c for c in body.split("<tr>") if f'href="/systems/{_WEB_SYSTEM}"' in c)
    assert "pill-ssh" in ssh_row and "pill-web" not in ssh_row
    assert "pill-web" in web_row and "pill-ssh" not in web_row and "pill-kubectl" not in web_row
    assert "type=web" in web_row and "type=web" not in ssh_row


def test_system_page_for_an_ssh_system_has_no_web_sections(tmp_path: Path) -> None:
    """A recordings-only system keeps its session table and gains no web or TLS section."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _seed(app, conn_id="ssh-2", username="jo@x", resource_address="ssh-only")
        body = client.get("/systems/ssh-only", headers=_auth_header()).text
    assert "jo@x" in body
    assert "Configured web app TLS" not in body and "Web activity" not in body
