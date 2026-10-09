"""End-to-end test: ingest front door → classify → assembler → detect → search UI.

Drives the real pipeline using the HTTP ingest endpoint (no direct store seeding),
assembles and finalizes a session containing both a dangerous command and an AWS key,
then exercises every search/session route and enforces CLAUDE.md rule 6 throughout:
recorded content (including the secret value) must NEVER appear in HTML or CSV
responses — only in the auth-gated, player-only ``/cast`` byte stream.

Concretely the recording carries:
  * ``rm -rf /etc``           → triggers the ``recursive-delete`` rule
  * ``AKIAIOSFODNN7EXAMPLE``  → triggers the ``aws-key`` rule
  * ``ZZUNIQUEMARKER42``      → a unique marker that is NOT itself a detected secret;
                                its presence/absence in each response proves content
                                never leaks from any rendered surface.
"""

from __future__ import annotations

import asyncio
import base64
import csv
import html
import io
import json
import re
import time
from pathlib import Path

from fastapi.testclient import TestClient

from gatorcast.config import Settings
from gatorcast.main import create_app

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INGEST_TOKEN = "e2e-ingest-token"
CONN_ID = "e2e-conn-1"

# A unique string baked into the recording that is NOT a detected secret.
# Used throughout to verify that no rendering surface leaks recorded content.
UNIQUE_MARKER = "ZZUNIQUEMARKER42"

# The full AWS key literal embedded in the recording — also must never leak.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

# One asciicast v2 chunk containing both triggers and the unique marker.
CAST = (
    '{"version":2,"width":80,"height":24,"timestamp":1700000000}\n'
    '[0.5,"o","rm -rf /etc\\r\\n"]\n'
    f'[1.0,"o","export AWS_KEY={AWS_KEY} {UNIQUE_MARKER}\\r\\n"]\n'
)

# The JSON shapes the classifier expects (from classify.py).
_SESSION_START_LINE = json.dumps(
    {
        "logger": "gateway",
        "message": "Authenticated connection",
        "conn_id": CONN_ID,
        "resource_address": "prod-db-01",
        "user": {"username": "auditor@corp", "id": "u1", "groups": []},
    }
)

_RECORDING_CHUNK_LINE = json.dumps(
    {
        "logger": "gateway.audit",
        "message": "session finished",  # final flush → assembler seals on the app loop
        "conn_id": CONN_ID,
        "asciicast": CAST,
        "asciicast_sequence_num": 0,
        "user": {"username": "auditor@corp", "id": "u1", "groups": []},
        "ts": "2026-01-01T10:00:00Z",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _settings(tmp_path: Path) -> Settings:
    """Isolated settings: tmp data dir, syslog disabled, known auth credentials."""
    return Settings(
        data_dir=tmp_path,
        syslog_tcp_port=0,
        ingest_token=INGEST_TOKEN,
        ui_auth_username="admin",
        ui_auth_password="change-me",
    )


def _ingest_header() -> dict[str, str]:
    """Bearer-token auth header for the /ingest endpoint."""
    return {"Authorization": f"Bearer {INGEST_TOKEN}"}


def _ui_header() -> dict[str, str]:
    """HTTP Basic auth header for the UI routes."""
    token = base64.b64encode(b"admin:change-me").decode()
    return {"Authorization": f"Basic {token}"}


def _poll_until(
    condition_fn,
    *,
    timeout: float = 5.0,
    interval: float = 0.05,
    description: str = "condition",
) -> None:
    """Busy-poll ``condition_fn()`` until it returns truthy or the timeout expires.

    Args:
        condition_fn: A zero-argument callable returning a truthy/falsy value.
        timeout: Maximum seconds to wait before raising ``TimeoutError``.
        interval: Sleep between polls in seconds.
        description: Human-readable label shown in the ``TimeoutError`` message.

    Raises:
        TimeoutError: If ``condition_fn`` never returns truthy within ``timeout``.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition_fn():
            return
        time.sleep(interval)
    raise TimeoutError(f"Timed out waiting for: {description}")


# ---------------------------------------------------------------------------
# The E2E test
# ---------------------------------------------------------------------------


def test_e2e_ingest_to_search(tmp_path: Path) -> None:
    """Full pipeline: ingest → assemble → detect → search UI (rule-6 leak checks).

    Steps:
    1. POST session-start + recording-chunk NDJSON to /ingest.
    2. Poll until the provisional session row exists (consumer drained).
    3. Finalize the session deterministically via the assembler.
    4. Poll until status == "complete" (scan also finished).
    5. Assert search/session/cast routes with rule-6 leak enforcement.
    """
    settings = _settings(tmp_path)
    app = create_app(settings)

    with TestClient(app) as client:
        # ------------------------------------------------------------------ #
        # Step 1: POST session-start + recording-chunk as NDJSON              #
        # ------------------------------------------------------------------ #
        ndjson_body = f"{_SESSION_START_LINE}\n{_RECORDING_CHUNK_LINE}\n"
        resp = client.post(
            "/ingest",
            content=ndjson_body,
            headers={
                **_ingest_header(),
                "Content-Type": "application/x-ndjson",
            },
        )
        assert resp.status_code == 204, f"ingest returned {resp.status_code}: {resp.text}"

        # ------------------------------------------------------------------ #
        # Step 2: Poll until the async consumer has created the provisional   #
        # session row (chunk → classify → assembler._on_chunk → upsert_start) #
        # ------------------------------------------------------------------ #
        repo = app.state.repo

        def _provisional_exists() -> bool:
            """Return True once the session row has been inserted."""
            session = asyncio.run(repo.get(CONN_ID))
            return session is not None

        _poll_until(
            _provisional_exists,
            timeout=5.0,
            description=f"provisional row for {CONN_ID}",
        )

        # ------------------------------------------------------------------ #
        # Step 3: The recording chunk carried "session finished", so the      #
        # consumer seals the session on the app loop — no manual finalize.    #
        # Poll until status == "complete" (seal + final scan done).           #
        # ------------------------------------------------------------------ #
        def _session_complete() -> bool:
            """Return True once the session row shows status='complete'."""
            session = asyncio.run(repo.get(CONN_ID))
            return session is not None and session.status == "complete"

        _poll_until(
            _session_complete,
            timeout=5.0,
            description=f"session {CONN_ID} status=complete",
        )

        # ------------------------------------------------------------------ #
        # Step 5a: GET /search?keyword=rm                                     #
        # Expects: 200, conn_id present, recursive-delete label shown,        #
        #          UNIQUE_MARKER and AWS_KEY absent (rule 6).                 #
        # ------------------------------------------------------------------ #
        resp = client.get("/search?keyword=rm", headers=_ui_header())
        assert resp.status_code == 200, f"/search?keyword=rm → {resp.status_code}"
        body = resp.text
        assert CONN_ID in body, f"session {CONN_ID!r} not found in keyword search"
        assert "recursive-delete" in body or "Recursive delete" in body, (
            "recursive-delete finding label not shown in keyword search"
        )
        # Rule 6: recorded content must NEVER appear in rendered HTML.
        assert UNIQUE_MARKER not in body, (
            f"RULE 6 VIOLATION: {UNIQUE_MARKER!r} leaked into /search HTML"
        )
        assert AWS_KEY not in body, (
            f"RULE 6 VIOLATION: {AWS_KEY!r} (AWS secret) leaked into /search HTML"
        )

        # ------------------------------------------------------------------ #
        # Step 5b: GET /search?rule_ids=aws-key                               #
        # Expects: 200, session appears (aws-key detection fired end-to-end). #
        # ------------------------------------------------------------------ #
        resp = client.get("/search?rule_ids=aws-key", headers=_ui_header())
        assert resp.status_code == 200, f"/search?rule_ids=aws-key → {resp.status_code}"
        body = resp.text
        assert CONN_ID in body, (
            f"session {CONN_ID!r} not found in aws-key rule filter — "
            "aws-key detection may not have fired end-to-end"
        )

        # ------------------------------------------------------------------ #
        # Step 5c: GET /sessions/e2e-conn-1                                   #
        # Expects: 200, data-offset attributes present (seek works),          #
        #          cast URL shown, UNIQUE_MARKER and AWS_KEY absent (rule 6). #
        # ------------------------------------------------------------------ #
        resp = client.get(f"/sessions/{CONN_ID}", headers=_ui_header())
        assert resp.status_code == 200, f"/sessions/{CONN_ID} → {resp.status_code}"
        body = resp.text
        assert "data-offset" in body, "session detail: no data-offset attributes (findings not rendered)"
        assert f"/sessions/{CONN_ID}/cast" in body, "session detail: cast URL absent"
        assert UNIQUE_MARKER not in body, (
            f"RULE 6 VIOLATION: {UNIQUE_MARKER!r} leaked into session detail HTML"
        )
        assert AWS_KEY not in body, (
            f"RULE 6 VIOLATION: {AWS_KEY!r} (AWS secret) leaked into session detail HTML"
        )

        # ------------------------------------------------------------------ #
        # Step 5d: GET /search/export.csv                                     #
        # Expects: 200, text/csv, finding label present,                      #
        #          UNIQUE_MARKER and AWS_KEY absent (rule 6).                 #
        # ------------------------------------------------------------------ #
        resp = client.get("/search/export.csv", headers=_ui_header())
        assert resp.status_code == 200, f"/search/export.csv → {resp.status_code}"
        assert resp.headers["content-type"].startswith("text/csv"), (
            f"export.csv wrong content-type: {resp.headers['content-type']!r}"
        )
        csv_body = resp.text
        assert "conn_id" in csv_body, "CSV export: header row missing"
        assert CONN_ID in csv_body, f"CSV export: session {CONN_ID!r} row missing"
        # Finding label(s) must appear in the CSV (metadata, not content).
        assert "recursive-delete" in csv_body.lower() or "Recursive delete" in csv_body, (
            "CSV export: recursive-delete finding label not present"
        )
        # Rule 6: no recorded content in CSV.
        assert UNIQUE_MARKER not in csv_body, (
            f"RULE 6 VIOLATION: {UNIQUE_MARKER!r} leaked into CSV export"
        )
        assert AWS_KEY not in csv_body, (
            f"RULE 6 VIOLATION: {AWS_KEY!r} (AWS secret) leaked into CSV export"
        )

        # ------------------------------------------------------------------ #
        # Step 5e: GET /sessions/e2e-conn-1/cast                              #
        # Expects: 200; body DOES contain UNIQUE_MARKER — proving the content #
        # exists and is only reachable via the player byte stream, not via    #
        # any rendered surface (indirect rule-6 proof).                       #
        # ------------------------------------------------------------------ #
        resp = client.get(f"/sessions/{CONN_ID}/cast", headers=_ui_header())
        assert resp.status_code == 200, f"/sessions/{CONN_ID}/cast → {resp.status_code}"
        assert UNIQUE_MARKER in resp.text, (
            f"Expected {UNIQUE_MARKER!r} in /cast response body (recording content "
            "should be accessible only via the player byte stream)"
        )

        # ------------------------------------------------------------------ #
        # Step 5f: Findings via store — verify offset_seconds on               #
        # recursive-delete (seek functionality proven at the store level).    #
        # ------------------------------------------------------------------ #
        search = app.state.search
        findings = asyncio.run(search.list_findings(CONN_ID))
        recursive_delete_findings = [f for f in findings if f.rule_id == "recursive-delete"]
        assert recursive_delete_findings, (
            "No recursive-delete finding stored — detection did not run end-to-end"
        )
        rd_finding = recursive_delete_findings[0]
        assert rd_finding.offset_seconds is not None, (
            "recursive-delete finding has null offset_seconds — seek will not work"
        )


# ---------------------------------------------------------------------------
# Web apps (Session 12, WEBAPP_SPEC 12.2): start lines with gwops objects, then traffic,
# then search (scheme / upstream), system page, visit view, CSV.
# ---------------------------------------------------------------------------

_E2E_USER = {"id": "e2e-user-id", "username": "e2e.user@corp", "groups": []}
_E2E_AUTHZ = "E2E_SECRET_AUTHZ_9a7c41d0ee"  # credential header value: never stored or shown
_E2E_QUERY = "E2E_SECRET_QUERYVALUE_5b1f33c2aa"  # query value: only its masked form may show
_E2E_UA = "Mozilla/5.0 E2E_SECRET_UA_77de01ff"  # stored on web rows, never rendered
_E2E_UNKNOWN_KEY = "E2E_SECRET_GWOPS_UNKNOWN_c3d2e1f0"  # unknown gwops key: never read
_E2E_PATH_TOKEN = "E2E_PATHTOKEN_0f9e8d7c"  # path token: shown unmasked by design
_E2E_BEFORE = "2026-10-09T00:00:00Z"


def _gwops(app_name: str, managed: bool, down: str, dport: int, up: str, uport: int, gateway: str) -> dict:
    """A valid ``match: exact`` gwops object (plus an unknown key that must be ignored)."""
    return {
        "schema": 1, "gateway_id": gateway, "match": "exact", "app": app_name, "managed": managed,
        "downstream_tls": down, "downstream_port": dport, "upstream_tls": up, "upstream_port": uport,
        "request_headers": {"Authorization": [f"Bearer {_E2E_UNKNOWN_KEY}"]},
    }


# (conn_id, system, gwops object or None, [(request_id, hms, method, url, status), ...])
_E2E_WEB_CONNS: tuple[tuple[str, str, object, list[tuple[str, str, str, str, int]]], ...] = (
    (
        "e2e-web-a", "wiki.e2e.test",
        _gwops("Legacy Wiki (prod)", False, "none", 80, "none", 8080, "gw-e2e-1"),
        [
            ("e2e-req-a1", "12:00:01", "GET", f"/home?month={_E2E_QUERY}", 200),
            ("e2e-req-a2", "12:00:02", "GET", f"/reset/{_E2E_PATH_TOKEN}", 404),
            ("e2e-req-a3", "12:00:03", "POST", "/login", 200),
        ],
    ),
    (
        "e2e-web-b", "portal.e2e.test",
        _gwops("Portal", True, "tls13", 443, "verify_full", 443, "gw-e2e-2"),
        [
            ("e2e-req-b1", "12:10:01", "GET", "/dashboard?tab=main", 200),
            ("e2e-req-b2", "12:10:02", "GET", "/ws", 101),
        ],
    ),
    (
        "e2e-web-c", "grafana.e2e.test",
        {"schema": 1, "gateway_id": "gw-e2e-3", "match": "none"},
        [("e2e-req-c1", "12:20:01", "GET", "/d/home", 200)],
    ),
    ("e2e-web-d", "docs.e2e.test", None, [("e2e-req-d1", "12:30:01", "GET", "/", 200)]),
    (
        "e2e-web-e", "bad.e2e.test",
        {**_gwops("Rejected App", True, "tls13", 443, "verify_full", 443, "gw-e2e-5"), "schema": 2},
        [("e2e-req-e1", "12:40:01", "GET", "/", 200)],
    ),
)


def _web_start_line(conn_id: str, system: str, gwops: object | None) -> str:
    """One ``Authenticated connection`` line for a ``WEB_APP`` resource."""
    line: dict[str, object] = {
        "logger": "gateway", "message": "Authenticated connection", "conn_id": conn_id,
        "user": _E2E_USER, "resource_type": "WEB_APP", "resource_address": system,
        "ts": "2026-10-08T11:59:00Z",
    }
    if gwops is not None:
        line["gwops"] = gwops
    return json.dumps(line)


def _web_request_line(
    conn_id: str, system: str, rid: str, hms: str, method: str, url: str, status: int
) -> str:
    """One ``API request completed`` line carrying a credential header and a User-Agent."""
    return json.dumps(
        {
            "logger": "gateway.audit", "message": "API request completed", "request_id": rid,
            "requested_at": f"2026-10-08T{hms}.000Z", "method": method, "url": url,
            "conn_id": conn_id, "user": _E2E_USER, "remote_addr": "172.20.0.3:50000",
            "request": {"headers": {
                "Authorization": [f"Bearer {_E2E_AUTHZ}"], "User-Agent": [_E2E_UA],
                "X-Twingate-User": ["spoofed@evil"],
            }},
            "response": {"headers": {}, "status_code": status},
        }
    )


def _post(client: TestClient, app, lines: list[str]) -> None:
    """POST NDJSON lines to ``/ingest`` and wait for the consumer to drain them."""
    resp = client.post(
        "/ingest", content="\n".join(lines) + "\n",
        headers={**_ingest_header(), "Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 204, resp.text
    client.portal.call(app.state.ingest_queue.join)


def _text(fragment: str) -> str:
    """Visible text of an HTML fragment."""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


def _web_rows(body: str) -> dict[str, str]:
    """Map system address to its web result block on a search page."""
    out: dict[str, str] = {}
    for block in body.split('<tbody class="result">')[1:]:
        if 'class="pill pill-web"' not in block:
            continue
        system = re.search(r'<td class="mono"><a href="/systems/[^"]*">([^<]*)</a></td>', block)
        assert system is not None
        out[system.group(1)] = block
    return out


def test_e2e_web_apps_ingest_to_search_pages_and_csv(tmp_path: Path) -> None:
    """Ingest gwops start lines, then traffic; check search filters, pages, visit view and CSV."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        # Step 1: the start lines (each WEB_APP resource, with its gwops object) ...
        _post(client, app, [_web_start_line(c, s, g) for c, s, g, _r in _E2E_WEB_CONNS])
        # ... then the traffic on each connection.
        _post(client, app, [
            _web_request_line(conn, system, *req)
            for conn, system, _g, reqs in _E2E_WEB_CONNS
            for req in reqs
        ])

        # The snapshots are stored: exact, none, and (absent / rejected) nothing.
        snaps = asyncio.run(app.state.activity.gwops_for_connections([c[0] for c in _E2E_WEB_CONNS]))
        assert (snaps["e2e-web-a"].gwops_match, snaps["e2e-web-a"].gwops_managed) == ("exact", False)
        assert (snaps["e2e-web-a"].downstream_tls, snaps["e2e-web-a"].upstream_tls) == ("none", "none")
        assert snaps["e2e-web-b"].upstream_tls == "verify_full"
        assert snaps["e2e-web-b"].downstream_port == 443
        assert snaps["e2e-web-c"].gwops_match == "none" and snaps["e2e-web-c"].downstream_tls is None
        assert snaps["e2e-web-d"].gwops_match is None
        assert snaps["e2e-web-e"].gwops_match is None  # rejected object: stored as no object

        ui = _ui_header()
        search = client.get("/search?type=web&page_size=50", headers=ui)
        rows = _web_rows(search.text)
        assert set(rows) == {
            "wiki.e2e.test", "portal.e2e.test", "grafana.e2e.test", "docs.e2e.test", "bad.e2e.test",
        }

        # --- search rows ----------------------------------------------------------------
        wiki = rows["wiki.e2e.test"].partition('<tr class="command-requests')[0]
        assert 'class="pill pill-http"' in wiki and "Plaintext upstream" in wiki
        assert '<span class="app-name">Legacy Wiki (prod)</span>' in wiki
        assert 'class="pill pill-unmanaged"' in wiki and 'title="gateway gw-e2e-1"' in wiki
        assert '<span class="method mono">POST</span>' in wiki  # the first mutating request
        assert "3 requests" in _text(wiki)
        portal = rows["portal.e2e.test"].partition('<tr class="command-requests')[0]
        assert 'class="pill pill-https"' in portal and "marker" not in portal
        assert 'class="pill pill-managed"' in portal and "Portal" in portal
        for system in ("grafana.e2e.test", "docs.e2e.test", "bad.e2e.test"):
            summary = rows[system].partition('<tr class="command-requests')[0]
            assert "TLS unknown" in summary and "web-app" not in summary, system
        # The masked query is stored: at most a quarter of the value (4 characters) plus its length.
        detail = html.unescape(rows["wiki.e2e.test"].partition('<tr class="command-requests')[2])
        masked = re.search(r"/home\?month=([A-Za-z0-9._~-]{0,4})…([A-Za-z0-9._~-]{0,4})\((\d+)\)", detail)
        assert masked is not None and masked.group(3) == str(len(_E2E_QUERY))
        assert len(masked.group(1)) + len(masked.group(2)) <= 4
        assert f"/reset/{_E2E_PATH_TOKEN}" in detail  # path token: unmasked by design

        # --- scheme / upstream filters ---------------------------------------------------
        def systems_for(query: str) -> set[str]:
            resp = client.get(f"/search?type=web&{query}", headers=ui)
            assert resp.status_code == 200, query
            return set(_web_rows(resp.text))

        assert systems_for("scheme=http") == {"wiki.e2e.test"}
        assert systems_for("scheme=https") == {"portal.e2e.test"}
        assert systems_for("scheme=unknown") == {"grafana.e2e.test", "docs.e2e.test", "bad.e2e.test"}
        assert systems_for("upstream=plaintext") == {"wiki.e2e.test"}
        assert systems_for("upstream=verified") == {"portal.e2e.test"}
        assert systems_for("upstream=unknown") == {"grafana.e2e.test", "docs.e2e.test", "bad.e2e.test"}
        assert systems_for("scheme=https&upstream=unverified") == set()
        assert client.get("/search?type=web&scheme=bogus", headers=ui).status_code == 400
        any_http = client.get("/search?scheme=http", headers=ui)
        assert set(_web_rows(any_http.text)) == {"wiki.e2e.test"}
        assert "not searched: the HTTP/HTTPS filter applies to web connections only." in any_http.text

        # --- system page: configuration block, Web activity, visit view -------------------
        wiki_page = client.get(f"/systems/wiki.e2e.test?activity_before={_E2E_BEFORE}", headers=ui)
        assert wiki_page.status_code == 200
        cfg = re.search(r'<section class="config-block".*?</section>', wiki_page.text, re.S)
        assert cfg is not None
        line = re.search(r'<li class="config-line">(.*?)</li>', cfg.group(0), re.S)
        assert line is not None
        assert _text(line.group(1)) == (
            "HTTP :80 → to upstream none :8080 ! Plaintext upstream app: Legacy Wiki (prod) unmanaged "
            "gateway gw-e2e-1 1 connection · 2026-10-08T12:00:01.000Z → 2026-10-08T12:00:03.000Z"
        )
        activity = re.search(
            r'<table class="activity-table web-activity-table">.*?<tbody>(.*?)</tbody>',
            wiki_page.text, re.S,
        )
        assert activity is not None
        cells = [_text(td) for td in re.findall(r"<td[^>]*>(.*?)</td>", activity.group(1), re.S)]
        assert cells[:7] == [
            "e2e.user@corp ⌕", "2026-10-08T12:00:01.000Z", "2026-10-08T12:00:03.000Z", "0:02",
            "1", "3", "1",  # one connection, three requests, one 4xx/5xx (the 404)
        ]
        href = re.search(r'<a href="(/systems/wiki\.e2e\.test/web\?[^"]*)"', activity.group(1))
        assert href is not None
        visit = client.get(html.unescape(href.group(1)), headers=ui)
        assert visit.status_code == 200
        assert "Configured web app TLS (from gwops)" in visit.text
        assert "<dt>Requests</dt><dd>3</dd>" in visit.text and "<dt>4xx/5xx</dt><dd>1</dd>" in visit.text
        assert "HTTP ! Plaintext upstream" in _text(visit.text.split("<tbody>")[-1])
        assert "e2e-web-" in visit.text  # the connection column (first 8 characters)

        portal_visit = client.get(
            "/systems/portal.e2e.test/web?user=e2e-user-id"
            "&from=2026-10-08T12:10:01.000Z&to=2026-10-08T12:10:02.000Z",
            headers=ui,
        )
        assert portal_visit.status_code == 200
        assert (
            '<span class="status status-1xx">101</span> <span class="dim">WebSocket</span>'
            in portal_visit.text
        )

        # --- CSV: 22 columns, WEBAPP_SPEC 8.7 values --------------------------------------
        export = client.get("/search/export.csv?type=web", headers=ui)
        assert export.status_code == 200
        parsed = list(csv.reader(io.StringIO(export.text)))
        assert len(parsed[0]) == 22 and parsed[0][15:] == [
            "resource_type", "configured_scheme", "configured_upstream_tls", "query",
            "gwops_gateway_id", "gwops_app", "gwops_managed",
        ]
        by_system = {r[2]: r for r in parsed[1:]}
        assert set(by_system) == set(rows)
        assert by_system["wiki.e2e.test"][10:] == [
            "web", "", "POST", "/login", "3", "WEB_APP", "http", "plaintext", "", "gw-e2e-1",
            "Legacy Wiki (prod)", "false",
        ]
        portal_row = by_system["portal.e2e.test"]
        assert portal_row[15:18] == ["WEB_APP", "https", "verified"]
        assert portal_row[13] == "/dashboard"  # the query is not part of the path column
        assert re.fullmatch(r"tab=[a-z]{0,1}…\(4\)", portal_row[18])  # masked value, no "?"
        assert portal_row[19:] == ["gw-e2e-2", "Portal", "true"]
        assert by_system["grafana.e2e.test"][15:] == [
            "WEB_APP", "unknown", "unknown", "", "gw-e2e-3", "", "",
        ]
        assert by_system["docs.e2e.test"][15:] == ["WEB_APP", "unknown", "unknown", "", "", "", ""]
        assert by_system["bad.e2e.test"][15:] == by_system["docs.e2e.test"][15:]  # a rejected object = absent
        filtered = client.get(
            "/search/export.csv?type=web&scheme=http&upstream=plaintext", headers=ui
        )
        assert [r[2] for r in list(csv.reader(io.StringIO(filtered.text)))[1:]] == ["wiki.e2e.test"]

        # --- nothing secret on any surface; the path token is the documented exception ----
        dashboard = client.get("/dashboard?window=all", headers=ui).text
        surfaces = {
            "search": search.text, "wiki": wiki_page.text, "visit": visit.text,
            "portal visit": portal_visit.text, "csv": export.text, "dashboard": dashboard,
            "systems": client.get("/systems", headers=ui).text,
        }
        for name, text in surfaces.items():
            for secret in (
                _E2E_AUTHZ, _E2E_QUERY, _E2E_UA, _E2E_UNKNOWN_KEY, "spoofed@evil", "Rejected App",
            ):
                assert secret not in text, f"{secret} leaked on {name}"
        tile = re.search(
            r'<span class="card-value">(\d+)</span>\s*<span class="card-label">Web requests', dashboard
        )
        assert tile is not None and tile.group(1) == "8"  # 3 + 2 + 1 + 1 + 1 web requests
