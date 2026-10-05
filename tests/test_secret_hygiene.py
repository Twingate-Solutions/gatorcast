"""Secret hygiene end-to-end (Session 9, T9; spec §12 / §13).

The synthetic fixture ``tests/fixtures/kubectl_audit_lines.ndjson`` is planted with
three sentinels that must never be stored, logged, or rendered:

  * ``GC_SENTINEL_TOKEN``  -- in the ``Authorization: Bearer`` and ``Cookie`` request
    headers of every audit line;
  * ``GC_SENTINEL_CMD``    -- in the exec ``command=`` query parameter, on the status-101
    audit line and on the k8s recording-chunk lines;
  * ``GC_SENTINEL_PANIC``  -- in the ``panic`` field of the ``API request failed`` line.

The whole fixture is POSTed through the real ``/ingest`` endpoint of a real app
(tmp data dir, detection on, encryption both off and on) and drained by the real
consumer: classify -> Assembler -> SQLite + .cast files. Afterwards the test dumps
every cell of every table, the captured log output, and every reachable UI response,
and asserts no sentinel appears. A positive control proves the sentinels really are in
the input, and scanner controls prove the DB dump and log capture can actually see a
planted value, so the test cannot pass vacuously.

``.cast`` files may legitimately hold terminal output and are not scanned. The
``/cast`` endpoint serves raw recording data, so it is checked only after confirming
the fixture's chunk content itself carries no sentinel.

structlog is configured with ``cache_logger_on_first_use=True``, so its test capture is
unreliable across a whole suite. Instead each module's ``log`` is swapped for a real
structlog logger that renders JSON into a shared buffer (as ``test_retention.py`` swaps
its module logger); stdout/stderr and stdlib ``logging`` are captured as well.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import html
import importlib
import io
import json
import logging
import os
import re
import sqlite3
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit

import pytest
import structlog
from fastapi.testclient import TestClient

from gatorcast.config import Settings
from gatorcast.main import create_app
from gatorcast.web.routes import _system_slug

FIXTURE = Path(__file__).parent / "fixtures" / "kubectl_audit_lines.ndjson"

SENTINEL_TOKEN = "GC_SENTINEL_TOKEN"
SENTINEL_CMD = "GC_SENTINEL_CMD"
SENTINEL_PANIC = "GC_SENTINEL_PANIC"
SENTINELS = (SENTINEL_TOKEN, SENTINEL_CMD, SENTINEL_PANIC)
# The full panic text (not only the marker) must not surface either.
PANIC_TEXT = "invalid memory address"

# Real credentials the test app is configured with; they must not leak either.
INGEST_TOKEN = "GC_HYGIENE_INGEST_SECRET"
UI_USER = "hygiene-admin"
UI_PASSWORD = "GC_HYGIENE_UI_SECRET"

BEFORE = "2026-10-02T00:00:00Z"  # pins the system page window over the fixture

FAILED_REQUEST_ID = "55555555-5555-4555-8555-555555555555"
EXPECTED_API_ROWS = 8  # 3 on A, the exec 101 line on B, 4 on C (502, 200, failed, legacy)

# Modules that hold a module-level structlog ``log``.
_LOG_MODULES = (
    "gatorcast.db",
    "gatorcast.main",
    "gatorcast.ingest.http",
    "gatorcast.ingest.normalize",
    "gatorcast.ingest.syslog_tcp",
    "gatorcast.web.routes",
    "gatorcast.pipeline.assembler",
    "gatorcast.pipeline.backfill",
    "gatorcast.pipeline.classify",
    "gatorcast.pipeline.retention",
    "gatorcast.store.search",
)

_HREF_RE = re.compile(r'href="([^"]+)"')
_MAX_CRAWLED_PAGES = 80


# ---------------------------------------------------------------------------
# Scanning helpers
# ---------------------------------------------------------------------------


def _hits(text: str, needles: tuple[str, ...]) -> list[str]:
    """Return the needles that appear in ``text``."""
    return [n for n in needles if n in text]


def _stringify(value: object) -> str:
    """Render one SQLite cell as text (BLOBs decoded losslessly)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return str(value)


def _db_table_names(db_path: Path) -> list[str]:
    """Enumerate every table in the database from ``sqlite_master``."""
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
    finally:
        conn.close()
    return [r[0] for r in rows]


def _db_cell_hits(db_path: Path, needles: tuple[str, ...]) -> tuple[list[str], int]:
    """Scan every column of every row of every table for ``needles``.

    Tables are enumerated from ``sqlite_master`` (none hardcoded).

    Returns:
        ``(hits, cells_scanned)``. Each hit reads ``table.column: needle (rowid-ish
        row index)`` so a leak is reported by exact location.
    """
    hits: list[str] = []
    cells = 0
    conn = sqlite3.connect(str(db_path))
    try:
        for table in _db_table_names(db_path):
            quoted = '"' + table.replace('"', '""') + '"'
            cur = conn.execute(f"SELECT * FROM {quoted}")  # noqa: S608 - name from sqlite_master
            columns = [d[0] for d in cur.description]
            for row_no, row in enumerate(cur.fetchall()):
                for column, value in zip(columns, row, strict=True):
                    cells += 1
                    text = _stringify(value)
                    for needle in needles:
                        if needle in text:
                            hits.append(f"{table}.{column}: {needle} (row #{row_no})")
    finally:
        conn.close()
    return hits, cells


def _raw_db_file_hits(db_path: Path, needles: tuple[str, ...]) -> list[str]:
    """Scan the raw SQLite file (and WAL, if any) bytes, catching freed pages too."""
    hits: list[str] = []
    for suffix in ("", "-wal", "-journal"):
        path = db_path.with_name(db_path.name + suffix)
        if not path.exists():
            continue
        data = path.read_bytes()
        for needle in needles:
            if needle.encode() in data:
                hits.append(f"{path.name}: {needle}")
    return hits


def _wait_for(condition: Callable[[], bool], *, what: str, timeout: float = 15.0) -> None:
    """Poll ``condition`` until truthy; fail with ``what`` on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if condition():
                return
        except sqlite3.OperationalError:
            pass  # db not yet created / momentarily locked
        time.sleep(0.05)
    raise TimeoutError(f"Timed out waiting for: {what}")


def _scalar(db_path: Path, sql: str, params: tuple = ()) -> object:
    """Run a single-value query through an independent reader connection."""
    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(sql, params).fetchone()
        return row[0] if row is not None else None
    finally:
        conn.close()


def _rows(db_path: Path, sql: str, params: tuple = ()) -> list[tuple]:
    """Run a query through an independent reader connection."""
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Log capture
# ---------------------------------------------------------------------------


class _ListHandler(logging.Handler):
    """Stdlib logging handler that keeps every formatted record and its raw args."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(f"{record.name} {record.getMessage()} {record.args!r}")


@dataclass
class LogCapture:
    """Everything the app wrote while it ran."""

    structlog_buffer: io.StringIO
    stdout: io.StringIO
    stderr: io.StringIO
    stdlib: _ListHandler

    def text(self) -> str:
        """All captured output as one searchable string."""
        return "\n".join(
            [
                self.structlog_buffer.getvalue(),
                self.stdout.getvalue(),
                self.stderr.getvalue(),
                *self.stdlib.lines,
            ]
        )

    def structlog_events(self) -> list[dict]:
        """Parse the captured structlog JSON lines."""
        events: list[dict] = []
        for line in self.structlog_buffer.getvalue().splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events


def _capturing_logger(buffer: io.StringIO) -> object:
    """Build a real structlog logger rendering JSON lines (all levels) into ``buffer``."""
    return structlog.wrap_logger(
        structlog.PrintLogger(file=buffer),
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
    )


# ---------------------------------------------------------------------------
# The end-to-end run (module scoped, once per encryption mode)
# ---------------------------------------------------------------------------


@dataclass
class Page:
    """One fetched UI response."""

    path: str
    status: int
    text: str  # response headers + body, so header leaks are caught too


@dataclass
class HygieneRun:
    """Everything produced by one full ingest + UI sweep."""

    encryption: bool
    db_path: Path
    logs: LogCapture
    pages: dict[str, Page] = field(default_factory=dict)
    explicit_paths: list[str] = field(default_factory=list)
    cast_responses: dict[str, Page] = field(default_factory=dict)
    ingest_status: int = 0


def _ui_headers() -> dict[str, str]:
    """HTTP Basic auth header for the UI routes."""
    token = base64.b64encode(f"{UI_USER}:{UI_PASSWORD}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _fetch(client: TestClient, path: str) -> Page:
    """GET a UI path (authenticated, no redirects) and keep headers + body text."""
    resp = client.get(path, headers=_ui_headers(), follow_redirects=False)
    header_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    return Page(path=path, status=resp.status_code, text=f"{header_text}\n\n{resp.text}")


def _settings(data_dir: Path, *, encryption: bool) -> Settings:
    """Real settings: tmp data dir, detection on, non-default credentials."""
    extra: dict[str, object] = {}
    if encryption:
        extra = {
            "encryption_enabled": True,
            "master_key": base64.b64encode(os.urandom(32)).decode("ascii"),
        }
    return Settings(
        data_dir=data_dir,
        syslog_tcp_port=0,
        ingest_token=INGEST_TOKEN,
        ui_auth_username=UI_USER,
        ui_auth_password=UI_PASSWORD,
        detection_enabled=True,
        **extra,
    )


def _crawl(client: TestClient, run: HygieneRun, seeds: list[str]) -> None:
    """Breadth-first follow same-origin links found in HTML responses.

    ``/static`` assets and ``/cast`` streams are skipped; every other link reachable
    from the seed pages is fetched once (bounded), so UI pages the explicit seeds miss
    are still covered.
    """
    queue = list(seeds)
    while queue and len(run.pages) < _MAX_CRAWLED_PAGES:
        path = queue.pop(0)
        if path not in run.pages:
            run.pages[path] = _fetch(client, path)
        for raw in _HREF_RE.findall(run.pages[path].text):
            href = html.unescape(raw)
            if not href.startswith("/") or href.startswith("//"):
                continue
            if href.startswith("/static") or urlsplit(href).path.endswith("/cast"):
                continue
            if href not in run.pages and href not in queue:
                queue.append(href)


def _run_pipeline(data_dir: Path, *, encryption: bool) -> HygieneRun:
    """Ingest the whole fixture over HTTP, settle, then sweep every UI page."""
    buffer = io.StringIO()
    out, err = io.StringIO(), io.StringIO()
    handler = _ListHandler()
    capture = LogCapture(structlog_buffer=buffer, stdout=out, stderr=err, stdlib=handler)

    settings = _settings(data_dir, encryption=encryption)
    run = HygieneRun(encryption=encryption, db_path=settings.db_path, logs=capture)

    patcher = pytest.MonkeyPatch()
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        for module_name in _LOG_MODULES:
            module = importlib.import_module(module_name)
            patcher.setattr(module, "log", _capturing_logger(buffer))

        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            app = create_app(settings)
            body = FIXTURE.read_text(encoding="utf-8")
            with TestClient(app) as client:
                resp = client.post(
                    "/ingest",
                    content=body,
                    headers={
                        "Authorization": f"Bearer {INGEST_TOKEN}",
                        "Content-Type": "application/x-ndjson",
                    },
                )
                run.ingest_status = resp.status_code

                # Let the consumer drain: every API row stored and the exec recording
                # sealed (its final chunk carries "session finished").
                db = run.db_path
                _wait_for(
                    lambda: _scalar(db, "SELECT COUNT(*) FROM api_requests")
                    == EXPECTED_API_ROWS,
                    what=f"{EXPECTED_API_ROWS} api_requests rows",
                )
                _wait_for(
                    lambda: _scalar(
                        db, "SELECT COUNT(*) FROM sessions WHERE status = 'complete'"
                    )
                    == 1,
                    what="the exec recording sealed to complete",
                )
                # Idle backstop sweep too (nothing should be stale, but run it so any
                # sweep-path logging is captured).
                asyncio.run(app.state.assembler.finalize_idle())

                run.explicit_paths = _explicit_paths(db)
                _crawl(client, run, list(run.explicit_paths))
                # Explicit seeds are always recorded, even if the crawl cap was hit.
                for path in run.explicit_paths:
                    run.pages.setdefault(path, _fetch(client, path))
                for (conn_id,) in _rows(db, "SELECT conn_id FROM sessions"):
                    cast_path = f"/sessions/{conn_id}/cast"
                    run.cast_responses[cast_path] = _fetch(client, cast_path)
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)
        patcher.undo()
    return run


def _explicit_paths(db_path: Path) -> list[str]:
    """Every UI page reachable for the fixture's systems, users, and sessions."""
    paths = [
        "/dashboard",
        "/dashboard?window=all",
        "/systems",
        "/search",
        "/search/export.csv",
    ]
    systems = _rows(
        db_path,
        "SELECT resource_address FROM sessions "
        "UNION SELECT resource_address FROM api_requests",
    )
    for (address,) in systems:
        slug = _system_slug(address)
        paths.append(f"/systems/{slug}")
        paths.append(f"/systems/{slug}?activity_before={BEFORE}")
        users = _rows(
            db_path,
            "SELECT user_key, MIN(requested_at), MAX(requested_at) FROM api_requests "
            "WHERE resource_address IS ? GROUP BY user_key",
            (address,),
        )
        for user_key, first, last in users:
            user = quote(user_key if user_key else "_unknown", safe="")
            base = (
                f"/systems/{slug}/activity?user={user}"
                f"&from={quote(first, safe='')}&to={quote(last, safe='')}"
            )
            paths.append(base)
            paths.append(base + "&discovery=1")
    for (conn_id,) in _rows(db_path, "SELECT conn_id FROM sessions"):
        paths.append(f"/sessions/{conn_id}")
    return paths


@pytest.fixture(
    scope="module",
    params=[False, True],
    ids=["encryption-off", "encryption-on"],
)
def run(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Iterator[HygieneRun]:
    """One full ingest + UI sweep per encryption mode."""
    data_dir = tmp_path_factory.mktemp(f"hygiene_{'enc' if request.param else 'plain'}")
    yield _run_pipeline(data_dir, encryption=request.param)


# ---------------------------------------------------------------------------
# Positive control: the sentinels really are in the input
# ---------------------------------------------------------------------------


def _fixture_objects() -> list[dict]:
    """Parse every fixture line."""
    return [
        json.loads(line)
        for line in FIXTURE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_positive_control_sentinels_are_in_the_fixture() -> None:
    """Each sentinel is present in the exact place it is meant to be planted."""
    objects = _fixture_objects()
    raw = FIXTURE.read_text(encoding="utf-8")
    for sentinel in SENTINELS:
        assert sentinel in raw, f"{sentinel} missing from the fixture (vacuous test)"

    audits = [o for o in objects if o.get("logger") == "gateway.audit"]

    # Token: Authorization Bearer + Cookie on every request audit line.
    request_audits = [o for o in audits if "request" in o]
    assert request_audits, "fixture has no request audit lines"
    for line in request_audits:
        headers = line["request"]["headers"]
        assert headers["Authorization"] == [f"Bearer {SENTINEL_TOKEN}"]
        assert SENTINEL_TOKEN in headers["Cookie"][0]

    # Exec command=: on the 101 audit line and on the recording-chunk lines.
    exec_lines = [o for o in audits if SENTINEL_CMD in o.get("url", "")]
    chunk_lines = [o for o in exec_lines if o.get("asciicast") is not None]
    audit_101 = [
        o for o in exec_lines if o.get("response", {}).get("status_code") == 101
    ]
    assert len(chunk_lines) >= 2 and len(audit_101) == 1
    assert all("command=" in o["url"] for o in exec_lines)

    # Panic: on the "API request failed" line.
    failed = [o for o in audits if o.get("message") == "API request failed"]
    assert len(failed) == 1
    assert SENTINEL_PANIC in failed[0]["panic"]
    assert PANIC_TEXT in failed[0]["panic"]


def test_fixture_chunk_content_carries_no_sentinel() -> None:
    """Gate for scanning ``/cast``: the recorded terminal output has no sentinel."""
    chunks = [o["asciicast"] for o in _fixture_objects() if o.get("asciicast") is not None]
    assert chunks
    for chunk in chunks:
        assert _hits(chunk, SENTINELS) == []


# ---------------------------------------------------------------------------
# Scanner controls: the scanners can really see a planted value
# ---------------------------------------------------------------------------


def test_db_scanner_finds_planted_sentinel_in_unknown_table(tmp_path: Path) -> None:
    """The dump enumerates ``sqlite_master`` and sees text and BLOB cells anywhere."""
    db = tmp_path / "planted.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE zz_surprise (id INTEGER PRIMARY KEY, note TEXT, raw BLOB)")
    conn.execute(
        "INSERT INTO zz_surprise (note, raw) VALUES (?, ?)",
        (f"Bearer {SENTINEL_TOKEN}", SENTINEL_CMD.encode()),
    )
    conn.commit()
    conn.close()

    hits, cells = _db_cell_hits(db, (*SENTINELS, "Bearer"))
    assert cells == 3
    assert "zz_surprise.note: GC_SENTINEL_TOKEN (row #0)" in hits
    assert "zz_surprise.note: Bearer (row #0)" in hits
    assert "zz_surprise.raw: GC_SENTINEL_CMD (row #0)" in hits
    assert _raw_db_file_hits(db, SENTINELS)  # raw-file scan sees it as well


def test_log_capture_is_live_and_sees_planted_values(run: HygieneRun) -> None:
    """The capture recorded real ingest events, and would record a leaked value."""
    events = run.logs.structlog_events()
    names = [e["event"] for e in events]
    assert "ingest.http" in names, f"no ingest log event captured; saw {names}"
    ingest = next(e for e in events if e["event"] == "ingest.http")
    assert ingest["accepted"] == len(_fixture_objects())
    assert ingest["dropped"] == 0

    # Control: the capturing logger renders a leaked value into its buffer, and the
    # text search used on the real capture finds it.
    probe_buffer = io.StringIO()
    probe = _capturing_logger(probe_buffer)
    probe.info("hygiene.probe", leaked=SENTINEL_TOKEN)  # type: ignore[attr-defined]
    probe.warning("hygiene.probe", url=f"/x?command={SENTINEL_CMD}")  # type: ignore[attr-defined]
    assert _hits(probe_buffer.getvalue(), SENTINELS) == [SENTINEL_TOKEN, SENTINEL_CMD]


# ---------------------------------------------------------------------------
# The pipeline really ran
# ---------------------------------------------------------------------------


def test_pipeline_processed_the_fixture(run: HygieneRun) -> None:
    """Ingest accepted the fixture and every table the scan relies on has data."""
    assert run.ingest_status == 204
    db = run.db_path
    assert _scalar(db, "SELECT COUNT(*) FROM api_requests") == EXPECTED_API_ROWS
    assert _scalar(db, "SELECT COUNT(*) FROM sessions") == 1
    assert _scalar(db, "SELECT status FROM sessions") == "complete"
    assert _scalar(db, "SELECT COUNT(*) FROM connections") == 3
    assert _scalar(db, "SELECT COUNT(*) FROM api_findings") >= 1  # kube-exec fired
    tables = _db_table_names(db)
    for expected in ("sessions", "connections", "api_requests", "api_findings", "findings"):
        assert expected in tables
    if run.encryption:
        # Sealed under encryption: the on-disk recording is ciphertext, not plaintext.
        (conn_id,) = _rows(db, "SELECT conn_id FROM sessions")[0]
        cast = (run.db_path.parent / "casts" / f"{conn_id}.cast").read_bytes()
        assert b'"version"' not in cast


# ---------------------------------------------------------------------------
# 1. Database
# ---------------------------------------------------------------------------


def test_no_sentinel_in_any_db_cell(run: HygieneRun) -> None:
    """No sentinel in any column of any row of any table (enumerated, not hardcoded)."""
    hits, cells = _db_cell_hits(run.db_path, (*SENTINELS, PANIC_TEXT))
    assert cells > 100, f"DB dump scanned only {cells} cells (vacuous)"
    assert hits == [], f"secret leaked into the database: {hits}"


def test_no_bearer_or_service_credentials_in_db(run: HygieneRun) -> None:
    """The literal ``Bearer`` and the app's own credentials are never stored."""
    hits, _ = _db_cell_hits(run.db_path, ("Bearer", INGEST_TOKEN, UI_PASSWORD))
    assert hits == [], f"credential material stored in the database: {hits}"


def test_no_sentinel_in_raw_db_files(run: HygieneRun) -> None:
    """Raw SQLite file / WAL bytes (incl. freed pages) hold no sentinel."""
    assert _raw_db_file_hits(run.db_path, (*SENTINELS, PANIC_TEXT)) == []


# ---------------------------------------------------------------------------
# 2. Logs
# ---------------------------------------------------------------------------


def test_no_sentinel_in_captured_logs(run: HygieneRun) -> None:
    """No sentinel, ``Bearer``, or credential in any captured log output."""
    text = run.logs.text()
    assert "ingest.http" in text  # capture is live (see the control test)
    assert _hits(text, (*SENTINELS, PANIC_TEXT)) == [], "secret leaked into log output"
    assert _hits(text, ("Bearer", INGEST_TOKEN, UI_PASSWORD)) == [], (
        "credential material in log output"
    )


# ---------------------------------------------------------------------------
# 3. UI
# ---------------------------------------------------------------------------


def test_ui_pages_were_reached(run: HygieneRun) -> None:
    """Every explicit seed returned 200 and the sweep covered the fixture's pages."""
    for path in run.explicit_paths:
        assert run.pages[path].status == 200, f"{path} -> {run.pages[path].status}"
    paths = list(run.pages)
    assert any(p.startswith("/dashboard") for p in paths)
    assert "/systems" in paths
    assert any("/activity?" in p and "discovery=1" in p for p in paths), (
        "activity page with discovery=1 not fetched"
    )
    assert any("/activity?" in p and "discovery=1" not in p for p in paths)
    assert any(p.startswith("/sessions/") for p in paths)
    assert len(run.pages) >= 8

    # The activity pages are real renders of the fixture, not empty shells.
    discovery_page = next(
        run.pages[p] for p in paths if "/activity?" in p and "discovery=1" in p
    )
    assert "k8s.example.internal" in discovery_page.text
    assert "kubectl exec" in discovery_page.text
    assert "/api?timeout=32s" in discovery_page.text  # discovery requests are shown


def test_no_sentinel_in_any_ui_response(run: HygieneRun) -> None:
    """No sentinel, panic text, ``Bearer``, or credential in any UI response body/header."""
    leaks: list[str] = []
    for path, page in run.pages.items():
        for needle in (*SENTINELS, PANIC_TEXT, "Bearer", INGEST_TOKEN, UI_PASSWORD):
            if needle in page.text:
                leaks.append(f"{path}: {needle}")
    assert leaks == [], f"secret leaked into UI responses: {leaks}"


def test_activity_pages_render_no_command_parameter(run: HygieneRun) -> None:
    """The exec URL renders on the activity page without its ``command=`` params."""
    activity = [p for p in run.pages.values() if "/activity?" in p.path]
    assert activity
    for page in activity:
        assert "command=" not in page.text, f"{page.path} renders a command= parameter"
    exec_pages = [p for p in activity if "/pods/web-1/exec" in p.text]
    assert exec_pages, "no activity page rendered the exec URL (vacuous)"


def test_cast_endpoint_serves_no_sentinel(run: HygieneRun) -> None:
    """``/cast`` (raw recording data) is clean; the fixture chunk content has no sentinel."""
    assert run.cast_responses
    for path, page in run.cast_responses.items():
        assert page.status == 200, f"{path} -> {page.status}"
        # Real recording content from both chunks was served.
        assert '"version":2' in page.text and '"o","# "' in page.text
        assert "echo hi" in page.text
        assert _hits(page.text, (*SENTINELS, PANIC_TEXT)) == []


# ---------------------------------------------------------------------------
# 4. Stored URL shape and failed-line handling
# ---------------------------------------------------------------------------


def test_stored_exec_attach_urls_have_no_command_param(run: HygieneRun) -> None:
    """Every stored exec/attach URL is sanitized: no ``command`` parameter at all."""
    urls = [u for (u,) in _rows(run.db_path, "SELECT url FROM api_requests")]
    exec_urls = [
        u for u in urls if urlsplit(u).path.endswith(("/exec", "/attach"))
    ]
    assert exec_urls, "no exec/attach URL stored (vacuous)"
    for url in exec_urls:
        names = [name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
        assert "command" not in names, f"command param stored in {url!r}"
        assert set(names) <= {"container", "stdin", "stdout", "stderr", "tty"}, (
            f"non-allowlisted exec param stored in {url!r}"
        )
    # And no stored URL anywhere carries the sentinel or a command= fragment.
    for url in urls:
        assert SENTINEL_CMD not in url
        assert "command=" not in url


def test_failed_line_stored_as_failed_with_null_status(run: HygieneRun) -> None:
    """The ``API request failed`` line: outcome='failed', status_code NULL."""
    rows = _rows(
        run.db_path,
        "SELECT outcome, status_code FROM api_requests WHERE request_id = ?",
        (FAILED_REQUEST_ID,),
    )
    assert rows == [("failed", None)]
    # It is the only failed row; the rest completed.
    assert _scalar(run.db_path, "SELECT COUNT(*) FROM api_requests WHERE outcome = 'failed'") == 1
