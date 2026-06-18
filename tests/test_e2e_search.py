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
import json
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
        # Step 3: Finalize the session deterministically via the assembler.   #
        # This is the same pattern test_web_search.py uses for direct async   #
        # calls: asyncio.run() on the already-running lifespan loop.         #
        # ------------------------------------------------------------------ #
        assembler = app.state.assembler
        asyncio.run(assembler.finalize(CONN_ID))

        # ------------------------------------------------------------------ #
        # Step 4: Poll until status == "complete" (finalize + scan done).     #
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
