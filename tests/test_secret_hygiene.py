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

Session 11 (web apps, T9 and T12; WEBAPP_SPEC 3.2 Interim, 10, 12.2) adds a second, lighter
harness at the end of this module (``_run_batch``): a batch of lines is POSTed through the
real ``/ingest`` of a real app (encryption off and on), the ingest queue is drained, and the
DB (every cell of every table, plus the raw file bytes), the data volume and the captured logs
are scanned for the ``tests/samples.py`` sentinels. UI pages and CSV for web rows are Session 12.
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
from tests.samples import (
    WEBAPP_CONNS,
    WEBAPP_DROPPED_REQUEST_KEYS,
    WEBAPP_GATEWAY_ID,
    WEBAPP_GWOPS_CASES,
    WEBAPP_GWOPS_SENTINELS,
    WEBAPP_HEADER_VARIANTS,
    WEBAPP_INTERIM_SECTIONS,
    WEBAPP_INTERIM_SENTINELS,
    WEBAPP_NEVER_LOGGED_SENTINELS,
    WEBAPP_NEVER_STORED_SENTINELS,
    WEBAPP_PATH_TOKENS,
    WEBAPP_QUERY_SENTINELS,
    WEBAPP_REQUESTS,
    WEBAPP_SENTINELS,
    WEBAPP_USER_AGENT_SENTINELS,
    check_webapp_fixture_index,
    webapp_interim_lines,
    webapp_interim_section,
    webapp_lines,
    webapp_lines_for,
    webapp_mixed_batch,
    webapp_objects,
)

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
# Session 10 T9: raised from 80. The explicit seeds now number ~90 (search types, users,
# systems, windows, legacy params, command focus, both CSV exports, the Next-cursor
# walk), which alone exceeded the old cap. Search pages link to each other through
# facets, so the crawl graph is effectively unbounded and always runs to the cap; it
# sits well above the seed count so links followed from the dashboard feed, systems
# list, and search results are still fetched. Seeds are fetched regardless of the cap.
_MAX_CRAWLED_PAGES = 300
# "Next >" / "Continue scanning >" link on a /search results page.
_NEXT_RE = re.compile(
    r'<a class="page-link" href="([^"]+)"[^>]*>\s*(?:Next|Continue scanning)\s*›'
)
_CURSOR_WALK_STEPS = 6  # pages followed through Next per cursor-walk seed

# Fixture values that must never be rendered or exported (spec s10 / s12): the full
# User-Agent string, the Gateway TCP peer (remote_addr), and a response-header value.
FULL_USER_AGENT = "kubectl/v1.33.0 (linux/amd64) kubernetes/abcdef0"
USER_AGENT_FRAGMENTS = (FULL_USER_AGENT, "linux/amd64", "kubernetes/abcdef0")
REMOTE_ADDR_HOST = "10.0.0.5"
RESPONSE_HEADER_VALUE = "no-cache, private"


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
    error_pages: dict[str, Page] = field(default_factory=dict)  # 400 probes (not crawled)
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
                # Next-cursor pages: walk the one-item-per-page results for the mixed
                # list and for kubectl only.
                for start in ("/search?page_size=1", "/search?type=kubectl&page_size=1"):
                    run.explicit_paths += _cursor_walk(client, start, _CURSOR_WALK_STEPS)
                run.explicit_paths.append("/search?type=kubectl&page_size=1")
                run.explicit_paths = list(dict.fromkeys(run.explicit_paths))
                _crawl(client, run, list(run.explicit_paths))
                # Explicit seeds are always recorded, even if the crawl cap was hit.
                for path in run.explicit_paths:
                    run.pages.setdefault(path, _fetch(client, path))
                for path in _BAD_REQUEST_PROBES:
                    run.error_pages[path] = _fetch(client, path)
                for (conn_id,) in _rows(db, "SELECT conn_id FROM sessions"):
                    cast_path = f"/sessions/{conn_id}/cast"
                    run.cast_responses[cast_path] = _fetch(client, cast_path)
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)
        patcher.undo()
    return run


# Rejected requests carrying a marker value: the 400 must not echo it (spec s10). The
# marker is deliberately not one of SENTINELS: the TestClient's own httpx logger prints
# every request URL, which would otherwise trip the app-log scan with a test artifact.
ECHO_PROBE = "GC_PROBE_ECHO"
_BAD_REQUEST_PROBES = (
    f"/search?type={ECHO_PROBE}",
    f"/search?cursor={ECHO_PROBE}",
    f"/search?cmd={ECHO_PROBE}%00",
    f"/search?sort={ECHO_PROBE}",
    f"/search?severity={ECHO_PROBE}",
    f"/search?q=({ECHO_PROBE}&mode=regex",
    f"/search?window={ECHO_PROBE}",
    f"/search?from={ECHO_PROBE}",
    f"/search?user={ECHO_PROBE}&username={ECHO_PROBE}",
    f"/search/export.csv?type={ECHO_PROBE}",
    f"/search/export.csv?cursor={ECHO_PROBE}&page_size={ECHO_PROBE}",
)


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
    paths.extend(_search_paths(db_path))
    return paths


def _q(**params: str) -> str:
    """Build a ``/search``-style query string (values percent-encoded)."""
    return "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())


def _search_paths(db_path: Path) -> list[str]:
    """Every Session 10 search seed (spec s12): unified search, focus, and both exports."""
    paths: list[str] = ["/search?page_size=1"]  # first page of the Next-cursor walk
    # One seed per search type, plus the shapes called out in the spec.
    for type_ in ("any", "recordings", "ssh", "exec", "failed", "kubectl"):
        paths.append(f"/search?type={type_}")
    paths += [
        "/search?type=kubectl&discovery=1",
        "/search?type=any&discovery=1",
        "/search?type=any&sort=risk",
        "/search?type=kubectl&sort=risk",
        "/search?type=kubectl&has_findings=true",
        "/search?type=kubectl&severity=high",
        "/search?type=any&status=complete",
        # Text and regex search (text over kubectl matches path / kubectl_command).
        "/search?type=kubectl&q=pods",
        "/search?type=any&q=exec",
        "/search?type=any&q=echo",
        "/search?type=any&q=echo&mode=regex",
        "/search?type=recordings&q=hi&mode=regex",
        # Windows.
        "/search?window=7",
        "/search?window=30",
        "/search?window=90",
        "/search?window=all",
        "/search?type=kubectl&window=all&discovery=1",
        # Absolute bounds that pin the fixture day.
        "/search?" + _q(**{"from": "2026-10-01T00:00:00Z", "to": BEFORE}),
        # Legacy (Session 8) params, which still resolve to type=any.
        "/search?" + _q(keyword="echo"),
        "/search?" + _q(regex="echo|hi"),
        "/search?" + _q(started_after="2026-10-01T00:00:00Z"),
        "/search?" + _q(started_before=BEFORE),
        "/search?page=1",
    ]

    addresses = [a for (a,) in _rows(db_path, "SELECT resource_address FROM sessions "
                                              "UNION SELECT resource_address FROM api_requests")]
    for address in addresses:
        system = address if address else "_unknown"
        paths.append("/search?" + _q(system=system))
        paths.append("/search?" + _q(type="kubectl", system=system))
        paths.append("/search?" + _q(type="exec", system=system, window="all"))
        if address:
            paths.append("/search?" + _q(resource_address=address))  # legacy alias
    paths.append("/search?system=_unknown")

    # Users: every username and user_id the fixture produced, from all three tables.
    identities = _rows(
        db_path,
        "SELECT username FROM api_requests UNION SELECT user_id FROM api_requests "
        "UNION SELECT username FROM sessions "
        "UNION SELECT username FROM connections UNION SELECT user_id FROM connections",
    )
    for (identity,) in identities:
        if not identity:
            continue
        paths.append("/search?" + _q(user=identity))  # username or user_id
        paths.append("/search?" + _q(type="kubectl", user=identity))
        paths.append("/search?" + _q(type="any", user=identity, sort="risk"))
        paths.append("/search?" + _q(type="failed", user=identity))
        paths.append("/search?" + _q(username=identity))  # legacy alias
    paths.append("/search?" + _q(user="user@example.com", system="k8s.example.internal",
                                 window="all", type="any"))

    # Command focus: every stored request id (non-start ids resolve to their command).
    for (request_id,) in _rows(db_path, "SELECT request_id FROM api_requests"):
        paths.append("/search?" + _q(cmd=request_id))
        paths.append("/search?" + _q(type="kubectl", cmd=request_id, discovery="1"))

    # Both CSV exports, the type-restricted variants, and a legacy-params export.
    paths += [
        "/search/export.csv",
        "/search/export.csv?type=kubectl",
        "/search/export.csv?type=any",
        "/search/export.csv?type=recordings",
        "/search/export.csv?type=exec",
        "/search/export.csv?type=failed",
        "/search/export.csv?type=kubectl&discovery=1",
        "/search/export.csv?type=any&sort=risk",
        "/search/export.csv?" + _q(type="kubectl", q="pods"),
        "/search/export.csv?" + _q(keyword="echo", username="user@example.com"),  # legacy
        "/search/export.csv?" + _q(regex="echo", resource_address="k8s.example.internal"),
        "/search/export.csv?" + _q(started_after="2026-10-01T00:00:00Z"),
    ]
    return paths


def _cursor_walk(client: TestClient, start: str, steps: int) -> list[str]:
    """Follow a results page's Next / Continue link up to ``steps`` times.

    Returns the cursor-bearing paths visited (the Next-cursor pages of spec s12), so they
    become explicit seeds that are scanned like any other page.
    """
    visited: list[str] = []
    path = start
    for _ in range(steps):
        match = _NEXT_RE.search(_fetch(client, path).text)
        if match is None:
            break
        path = html.unescape(match.group(1))
        assert "cursor=" in path, f"Next link without a cursor: {path}"
        visited.append(path)
    return visited


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


def _split(page: Page) -> tuple[str, str]:
    """Split a fetched page into ``(header_text, body)`` at the first blank line."""
    head, _, body = page.text.partition("\n\n")
    return head, body


def _csv_pages(run: HygieneRun) -> dict[str, Page]:
    """Every fetched CSV export."""
    return {p: pg for p, pg in run.pages.items() if urlsplit(p).path == "/search/export.csv"}


def _search_pages(run: HygieneRun) -> dict[str, Page]:
    """Every fetched ``/search`` HTML page."""
    return {p: pg for p, pg in run.pages.items() if urlsplit(p).path == "/search"}


def test_positive_control_forbidden_values_are_in_the_fixture() -> None:
    """The UA, remote_addr, and response-header values really are in the input."""
    audits = [o for o in _fixture_objects() if o.get("logger") == "gateway.audit"]
    with_headers = [o for o in audits if "request" in o]
    assert with_headers
    for line in with_headers:
        assert line["request"]["headers"]["User-Agent"] == [FULL_USER_AGENT]
        assert line["remote_addr"].startswith(REMOTE_ADDR_HOST)
    responses = [o["response"]["headers"] for o in audits if o.get("response", {}).get("headers")]
    assert responses
    assert all(RESPONSE_HEADER_VALUE in h["Cache-Control"] for h in responses)


def test_search_surface_was_seeded_and_fetched(run: HygieneRun) -> None:
    """Every Session 10 seed is present, fetched with 200, and not lost to the crawl cap."""
    paths = set(run.explicit_paths)
    for type_ in ("any", "recordings", "ssh", "exec", "failed", "kubectl"):
        assert f"/search?type={type_}" in paths
    assert any("user=VXNlcjox" in p for p in paths), "no user=<user_id> seed"
    assert any("user=user%40example.com" in p for p in paths), "no user=<username> seed"
    assert any("type=failed" in p and "user=" in p for p in paths)
    assert any("cmd=" in p for p in paths)
    assert any("system=" in p for p in paths)
    assert any("window=" in p for p in paths)
    assert any("q=pods" in p for p in paths) and any("mode=regex" in p for p in paths)
    assert any("cursor=" in p for p in paths), "no Next-cursor page was reached"
    assert {"/search/export.csv", "/search/export.csv?type=kubectl"} <= paths
    assert any(p.startswith("/search/export.csv?") and "username=" in p for p in paths), (
        "no legacy-params export seed"
    )
    assert len(paths) <= _MAX_CRAWLED_PAGES // 2, "seeds leave no room for crawled links"
    for path in paths:
        assert path in run.pages, f"{path} was not fetched"
        assert run.pages[path].status == 200, f"{path} -> {run.pages[path].status}"


def test_search_pages_render_real_content(run: HygieneRun) -> None:
    """The new surface is not empty shells, so the leak scans below are not vacuous."""
    pages = run.pages
    # Mixed list: the kubectl command label and the exec recording's own row.
    any_page = pages["/search?type=any"].text
    assert "kubectl exec" in any_page
    assert any(
        f"/sessions/{c}" in any_page for (c,) in _rows(run.db_path, "SELECT conn_id FROM sessions")
    )
    # kubectl-only list has the command and no recording-only rows.
    assert "kubectl exec" in pages["/search?type=kubectl"].text
    assert "kubectl get" in pages["/search?type=kubectl"].text
    # user=<user_id> and user=<username> resolve to the same user's activity.
    by_id = pages["/search?user=VXNlcjox"].text
    by_name = pages["/search?user=user%40example.com"].text
    assert "kubectl exec" in by_id and "kubectl exec" in by_name
    # Focus on a command by request id renders that command.
    focus = next(
        pg for p, pg in pages.items() if p.startswith("/search?cmd=11111111-1111-4111-8111-111111111111")
    )
    assert "kubectl exec" in focus.text
    # Next-cursor pages came from real result pages.
    cursor_pages = [pg for p, pg in pages.items() if p.startswith("/search?") and "cursor=" in p]
    assert cursor_pages and all(pg.status == 200 for pg in cursor_pages)
    # Dashboard and systems list link into search (crawl feed).
    assert "/search?" in pages["/dashboard"].text
    assert "/search?" in pages["/systems"].text


def test_csv_exports_have_rows_and_are_clean(run: HygieneRun) -> None:
    """Each CSV has a header and data rows (positive control), and carries no secret."""
    import csv as csvmod

    csvs = _csv_pages(run)
    assert {"/search/export.csv", "/search/export.csv?type=kubectl",
            "/search/export.csv?type=any"} <= set(csvs)
    forbidden = (
        *SENTINELS, PANIC_TEXT, "Bearer", INGEST_TOKEN, UI_PASSWORD, "command=",
        *USER_AGENT_FRAGMENTS, REMOTE_ADDR_HOST, RESPONSE_HEADER_VALUE, "Authorization",
        "Cookie", "remote_addr",
    )
    for path, page in csvs.items():
        head, body = _split(page)
        assert "text/csv" in head.lower(), f"{path} is not served as CSV"
        rows = list(csvmod.reader(io.StringIO(body)))
        assert rows and rows[0][0] == "conn_id" and len(rows[0]) == 22, f"{path}: bad header"
        assert rows[0][15:] == [
            "resource_type", "configured_scheme", "configured_upstream_tls", "query",
            "gwops_gateway_id", "gwops_app", "gwops_managed",
        ], f"{path}: bad Session 12 columns"
        # Every row is 22 cells wide; kubectl rows carry KUBERNETES in column 16 and
        # leave the six web-only columns empty (this run has no web rows).
        assert all(len(r) == 22 for r in rows), f"{path}: ragged rows"
        assert all(r[15:] == ["KUBERNETES", "", "", "", "", "", ""] for r in rows[1:] if r[10] == "kubectl")
        assert _hits(page.text, forbidden) == [], f"{path} leaks {_hits(page.text, forbidden)}"
    # Default and type=kubectl/any exports are not empty shells.
    for path in ("/search/export.csv", "/search/export.csv?type=kubectl",
                 "/search/export.csv?type=any"):
        rows = list(csvmod.reader(io.StringIO(_split(csvs[path])[1])))
        assert len(rows) >= 2, f"{path} has no data rows (vacuous)"
    kube_rows = list(csvmod.reader(io.StringIO(_split(csvs["/search/export.csv?type=kubectl"])[1])))
    assert any("kubectl exec" in cell for row in kube_rows[1:] for cell in row)
    # The legacy-params export is served and parsed (200 asserted above), as CSV.
    legacy = [p for p in csvs if "username=" in p]
    assert legacy


def test_no_command_param_in_any_search_page_or_export(run: HygieneRun) -> None:
    """No rendered or exported URL carries a ``command=`` parameter, on any page."""
    leaks = [
        p
        for p, page in run.pages.items()
        if "command=" in page.text
    ]
    assert leaks == [], f"command= rendered on: {leaks}"
    # Seeds that the sentinel could hide behind were actually fetched.
    assert any("/pods/web-1/exec" in pg.text for pg in _search_pages(run).values()), (
        "no search page rendered the exec URL (vacuous)"
    )


def test_no_user_agent_remote_addr_or_response_header_in_any_response(run: HygieneRun) -> None:
    """No full User-Agent, remote_addr, response-header value, or request header
    name/value pair appears in any page, header block, or CSV (spec s10)."""
    forbidden = (*USER_AGENT_FRAGMENTS, REMOTE_ADDR_HOST, RESPONSE_HEADER_VALUE)
    leaks = [
        f"{path}: {needle}"
        for path, page in run.pages.items()
        for needle in forbidden
        if needle in page.text
    ]
    assert leaks == [], f"gateway-only values rendered: {leaks}"
    # Cookie and Authorization values are covered by the sentinel/Bearer scan; the
    # request-header names themselves must not be echoed as stored data either.
    for path, page in run.pages.items():
        assert "session=GC_SENTINEL" not in page.text, path
        assert "Authorization: Bearer" not in page.text, path


def test_search_400_pages_do_not_echo_submitted_values(run: HygieneRun) -> None:
    """A rejected search or export is a 400 that never echoes the submitted value (s10)."""
    assert run.error_pages, "no 400 probes were fetched (vacuous)"
    for path, page in run.error_pages.items():
        assert page.status == 400, f"{path} -> {page.status}"
        assert ECHO_PROBE not in page.text, f"{path} echoed a submitted value"
        assert _hits(page.text, SENTINELS) == []
        assert "command=" not in page.text


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


# ===========================================================================
# Session 11: web apps (T9 and T12 hygiene). DB, data volume and logs.
# ===========================================================================

# Modules holding a module-level ``log``; ``store.timeline`` is not in the Session 9 list.
_WEB_LOG_MODULES = (*_LOG_MODULES, "gatorcast.store.timeline")

_WEB_IDENTITY = "PLACEHOLDER-KEY-ID-1"  # user.username == user.id on every fixture line
_DATA_TABLES = ("sessions", "connections", "api_requests", "api_findings", "findings")
_GWOPS_COLUMNS = (
    "gwops_match",
    "gwops_gateway_id",
    "gwops_app",
    "gwops_managed",
    "downstream_tls",
    "downstream_port",
    "upstream_tls",
    "upstream_port",
)

_REJECTED_CASES = [c for c in WEBAPP_GWOPS_CASES if c.outcome == "rejected"]
_APP_IGNORED_CASES = [c for c in WEBAPP_GWOPS_CASES if c.outcome == "accepted_app_ignored"]
_NOT_READ_CASES = [c for c in WEBAPP_GWOPS_CASES if c.outcome == "not_read"]
_UNKNOWN_KEY_CONN_KEYS = (
    "gw_unknown_key_exact",
    "gw_match_none_unknown_key",
    "gw_match_none_app_fields",
)


@dataclass
class BatchRun:
    """One ``/ingest`` batch run through a real app, drained and swept."""

    encryption: bool
    data_dir: Path
    db_path: Path
    logs: LogCapture
    lines: list[str]
    ingest_status: int = 0
    pages: dict[str, Page] = field(default_factory=dict)  # filled by a Session 12 UI sweep
    explicit_paths: list[str] = field(default_factory=list)  # the sweep's explicit seeds
    error_pages: dict[str, Page] = field(default_factory=dict)  # the sweep's 400 probes


@dataclass
class WebRuns:
    """The two batches every web-app test shares: valid lines only, and valid + interim."""

    valid: BatchRun
    mixed: BatchRun


async def _drain_queue(app: object) -> None:
    """Wait until the consumer has processed everything ``/ingest`` queued."""
    await asyncio.wait_for(app.state.ingest_queue.join(), timeout=60)  # type: ignore[attr-defined]


def _run_batch(
    data_dir: Path,
    lines: list[str],
    *,
    encryption: bool,
    sweep: Callable[[TestClient, BatchRun], None] | None = None,
) -> BatchRun:
    """POST ``lines`` (NDJSON) to ``/ingest`` of a real app and drain the pipeline.

    ``sweep`` (Session 12) runs inside the ``with TestClient`` block after the drain and
    the idle sweep, with the live client, to fetch UI pages into ``batch.pages``.

    Same log capture as ``_run_pipeline`` (every module ``log`` swapped for a DEBUG-level
    JSON logger, plus stdout, stderr and stdlib logging). The idle sweep runs once so any
    sweep-path logging is captured too.
    """
    buffer = io.StringIO()
    out, err = io.StringIO(), io.StringIO()
    handler = _ListHandler()
    capture = LogCapture(structlog_buffer=buffer, stdout=out, stderr=err, stdlib=handler)

    settings = _settings(data_dir, encryption=encryption)
    batch = BatchRun(
        encryption=encryption,
        data_dir=data_dir,
        db_path=settings.db_path,
        logs=capture,
        lines=list(lines),
    )

    patcher = pytest.MonkeyPatch()
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(handler)
    # INFO is the production default (``Settings.log_level``). The Session 9 harness uses
    # DEBUG, at which stdlib ``aiosqlite`` echoes every bound SQL parameter, so values the
    # app stores (path tokens, User-Agent) or merely binds (a repeated start line's ``gwops``
    # ``app``) show up in the capture. That is the ``aiosqlite`` library's own debug output,
    # not application logging; the app's structlog events are captured at DEBUG regardless.
    root.setLevel(logging.INFO)
    try:
        for module_name in _WEB_LOG_MODULES:
            module = importlib.import_module(module_name)
            patcher.setattr(module, "log", _capturing_logger(buffer))

        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.post(
                    "/ingest",
                    content="\n".join(lines) + "\n",
                    headers={
                        "Authorization": f"Bearer {INGEST_TOKEN}",
                        "Content-Type": "application/x-ndjson",
                    },
                )
                batch.ingest_status = resp.status_code
                client.portal.call(_drain_queue, app)
                client.portal.call(app.state.assembler.finalize_idle)
                if sweep is not None:
                    sweep(client, batch)
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)
        patcher.undo()
    return batch


@pytest.fixture(
    scope="module",
    params=[False, True],
    ids=["encryption-off", "encryption-on"],
)
def web_runs(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> WebRuns:
    """Both batches for one encryption mode (one pairing, so tests compare like with like)."""
    tag = "enc" if request.param else "plain"
    valid = _run_batch(
        tmp_path_factory.mktemp(f"web_valid_{tag}"), webapp_lines(), encryption=request.param
    )
    mixed = _run_batch(
        tmp_path_factory.mktemp(f"web_mixed_{tag}"), webapp_mixed_batch(), encryption=request.param
    )
    return WebRuns(valid=valid, mixed=mixed)


@pytest.fixture
def web_run(web_runs: WebRuns) -> BatchRun:
    """The valid-only web fixture run."""
    return web_runs.valid


@pytest.fixture
def mixed_run(web_runs: WebRuns) -> BatchRun:
    """The run whose batch interleaves interim lines with the valid ones."""
    return web_runs.mixed


# ---------------------------------------------------------------------------
# Scanning helpers (web)
# ---------------------------------------------------------------------------


def _volume_hits(data_dir: Path, db_path: Path, needles: tuple[str, ...]) -> list[str]:
    """Scan every file under the data dir except the SQLite files (``.cast``, ``.txt.enc``...)."""
    hits: list[str] = []
    for path in sorted(data_dir.rglob("*")):
        if not path.is_file() or path.name.startswith(db_path.name):
            continue
        data = path.read_bytes()
        for needle in needles:
            if needle.encode() in data:
                hits.append(f"{path.relative_to(data_dir).as_posix()}: {needle}")
    return hits


def _all_hits(batch: BatchRun, needles: tuple[str, ...]) -> dict[str, list[str]]:
    """Every place ``needles`` appear: DB cells, raw DB bytes, volume files, captured logs."""
    cells, _ = _db_cell_hits(batch.db_path, needles)
    found = {
        "db_cells": cells,
        "raw_db_files": _raw_db_file_hits(batch.db_path, needles),
        "volume": _volume_hits(batch.data_dir, batch.db_path, needles),
        "logs": [f"log: {n}" for n in _hits(batch.logs.text(), needles)],
    }
    return {where: hits for where, hits in found.items() if hits}


def _sentinels_in(lines: list[str], pool: tuple[str, ...]) -> tuple[str, ...]:
    """The members of ``pool`` that appear in ``lines``."""
    text = "\n".join(lines)
    return tuple(s for s in pool if s in text)


def _table_rows(
    db_path: Path, table: str, drop: tuple[str, ...] = ()
) -> list[tuple]:
    """All rows of ``table`` without the ``drop`` columns, in a deterministic order."""
    conn = sqlite3.connect(str(db_path))
    try:
        quoted = '"' + table.replace('"', '""') + '"'
        cur = conn.execute(f"SELECT * FROM {quoted}")  # noqa: S608 - fixed table names
        columns = [d[0] for d in cur.description]
        keep = [i for i, c in enumerate(columns) if c not in drop]
        rows = [tuple(row[i] for i in keep) for row in cur.fetchall()]
    finally:
        conn.close()
    return sorted(rows, key=repr)


def _request_row(db_path: Path, request_id: str, drop: tuple[str, ...] = ()) -> dict:
    """One ``api_requests`` row as a dict (minus ``drop``); fails if the row is missing."""
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute("SELECT * FROM api_requests WHERE request_id = ?", (request_id,))
        columns = [d[0] for d in cur.description]
        row = cur.fetchone()
    finally:
        conn.close()
    assert row is not None, f"no api_requests row for {request_id}"
    return {c: v for c, v in zip(columns, row, strict=True) if c not in drop}


def _connection_row(db_path: Path, conn_id: str) -> dict:
    """One ``connections`` row as a dict; fails if the row is missing."""
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute("SELECT * FROM connections WHERE conn_id = ?", (conn_id,))
        columns = [d[0] for d in cur.description]
        row = cur.fetchone()
    finally:
        conn.close()
    assert row is not None, f"no connections row for {conn_id}"
    return dict(zip(columns, row, strict=True))


def _conn_id(key: str) -> str:
    """``conn_id`` of a fixture connection key."""
    return WEBAPP_CONNS[key].conn_id


def _gwops_log_events(batch: BatchRun) -> dict[str, list[dict]]:
    """Captured ``classify.gwops*`` events grouped by their ``conn_id``."""
    grouped: dict[str, list[dict]] = {}
    for event in batch.logs.structlog_events():
        if str(event.get("event", "")).startswith("classify.gwops"):
            grouped.setdefault(event.get("conn_id", "<no conn_id>"), []).append(event)
    return grouped


# ---------------------------------------------------------------------------
# Positive controls and scanner controls
# ---------------------------------------------------------------------------


def test_webapp_fixture_index_matches_the_fixture_files() -> None:
    """The ``tests/samples.py`` registries agree with both NDJSON files (no drift)."""
    check_webapp_fixture_index()


def test_every_web_sentinel_is_in_the_posted_input() -> None:
    """Each sentinel is really in the fixture it is documented for, so no scan is vacuous."""
    web_text = "\n".join(webapp_lines())
    interim_text = "\n".join(webapp_interim_lines())
    for group, values in WEBAPP_SENTINELS.items():
        assert values, f"sentinel group {group} is empty"
        for value in values:
            if group in ("NONJSON", "SVC", "SSH"):
                assert value in interim_text and value not in web_text, value
            else:
                assert value in web_text and value not in interim_text, value
    assert set(WEBAPP_NEVER_STORED_SENTINELS) | set(WEBAPP_PATH_TOKENS) <= set(
        WEBAPP_NEVER_LOGGED_SENTINELS
    )


def test_credential_sentinels_sit_in_request_headers_of_the_posted_lines() -> None:
    """Authorization / Cookie / X-Api-Key / spoofed identity values are planted as headers."""
    header_values: set[str] = set()
    for obj in webapp_objects():
        request = obj.get("request")
        response = obj.get("response")
        headers = request.get("headers") if isinstance(request, dict) else None
        response_headers = response.get("headers") if isinstance(response, dict) else None
        for block in (headers, response_headers):
            if not isinstance(block, dict):
                continue
            for values in block.values():
                if isinstance(values, list):
                    header_values.update(v for v in values if isinstance(v, str))
    planted = {
        s
        for group in (
            "AUTHZ", "COOKIE", "APIKEY", "PROXYAUTH", "XAUTHTOKEN", "CSRF", "SETCOOKIE", "SPOOF",
        )
        for s in WEBAPP_SENTINELS[group]
        if any(s in v for v in header_values)
    }
    assert planted, "no credential sentinel is carried by a header (vacuous)"


def test_volume_scanner_finds_a_planted_value_in_a_nested_file(tmp_path: Path) -> None:
    """The volume scan walks subdirectories, skips the SQLite files, and sees raw bytes."""
    (tmp_path / "casts").mkdir()
    (tmp_path / "casts" / "x.cast").write_bytes(b"\x00junk" + SENTINEL_TOKEN.encode())
    db = tmp_path / "gatorcast.db"
    db.write_bytes(SENTINEL_CMD.encode())  # skipped here; _raw_db_file_hits covers it
    assert _volume_hits(tmp_path, db, SENTINELS) == [f"casts/x.cast: {SENTINEL_TOKEN}"]


# ---------------------------------------------------------------------------
# T9: the web fixture, DB and logs
# ---------------------------------------------------------------------------


def test_web_batch_was_accepted_and_every_line_processed(web_run: BatchRun) -> None:
    """204, every line queued, no pipeline error, and the control events are live."""
    assert web_run.ingest_status == 204
    events = web_run.logs.structlog_events()
    ingest = next(e for e in events if e["event"] == "ingest.http")
    assert ingest["accepted"] == len(web_run.lines)
    assert ingest["dropped"] == 0
    assert [e for e in events if e["event"] == "pipeline.error"] == []

    # Control: DEBUG-level classify events are captured (the method gate drops four lines).
    gate_drops = [
        e for e in events if e["event"] == "classify.drop" and e.get("reason") == "api_bad_method"
    ]
    assert len(gate_drops) == len(WEBAPP_DROPPED_REQUEST_KEYS)

    # Every request line the gate accepts has a row; the dropped four have none.
    dropped_ids = {WEBAPP_REQUESTS[k].request_id for k in WEBAPP_DROPPED_REQUEST_KEYS}
    expected_ids = {
        o["request_id"]
        for o in webapp_objects()
        if o.get("logger") == "gateway.audit" and o.get("asciicast") is None and "request_id" in o
    } - dropped_ids
    stored_ids = {
        r[0] for r in _rows(web_run.db_path, "SELECT request_id FROM api_requests")
    }
    assert stored_ids == expected_ids
    assert _scalar(web_run.db_path, "SELECT COUNT(*) FROM connections") > 50


def test_no_never_stored_sentinel_in_db_volume_or_logs(web_run: BatchRun) -> None:
    """Credential headers, spoofed identity, unmasked query values, panic and gwops content.

    Scans every cell of every table, the raw SQLite file and WAL, every file on the data
    volume, and all captured log output, for the whole sentinel (masked output may reveal
    only the first and last two characters, so a full match is a leak).
    """
    _, cells = _db_cell_hits(web_run.db_path, WEBAPP_NEVER_STORED_SENTINELS)
    assert cells > 1000, f"DB dump scanned only {cells} cells (vacuous)"
    leaks = _all_hits(web_run, WEBAPP_NEVER_STORED_SENTINELS)
    assert leaks == {}, f"never-stored sentinel found: {leaks}"


def test_no_never_logged_sentinel_in_logs(web_run: BatchRun) -> None:
    """Never-stored sentinels, path tokens and the User-Agent sentinel never reach a log."""
    text = web_run.logs.text()
    assert "ingest.http" in text  # capture is live
    assert _hits(text, WEBAPP_NEVER_LOGGED_SENTINELS) == []
    assert _hits(text, WEBAPP_USER_AGENT_SENTINELS) == []
    assert _hits(text, ("Bearer", INGEST_TOKEN, UI_PASSWORD)) == []


def test_path_token_sentinels_are_stored_unmasked_in_api_request_urls(web_run: BatchRun) -> None:
    """By design (WEBAPP_SPEC 5.3 withdrawn, 10): path-embedded tokens are kept as-is."""
    for token in WEBAPP_PATH_TOKENS:
        hits, _ = _db_cell_hits(web_run.db_path, (token,))
        assert any(h.startswith("api_requests.url:") for h in hits), (
            f"path token {token} not stored unmasked in api_requests.url; found: {hits}"
        )
    # And the same URLs show their query values masked, so masking ran on this input.
    masked = [u for (u,) in _rows(web_run.db_path, "SELECT url FROM api_requests") if "…(" in u]
    assert masked, "no stored URL carries a masked query value (vacuous)"


def test_path_token_sentinels_are_absent_from_logs_and_the_volume(web_run: BatchRun) -> None:
    """Path tokens may sit in the DB, never in logs or on the recording volume."""
    assert _hits(web_run.logs.text(), WEBAPP_PATH_TOKENS) == []
    assert _volume_hits(web_run.data_dir, web_run.db_path, WEBAPP_PATH_TOKENS) == []


@pytest.mark.parametrize("group", sorted(WEBAPP_HEADER_VARIANTS))
def test_header_present_placeholdered_and_stripped_variants_store_identical_rows(
    web_run: BatchRun, group: str
) -> None:
    """The same request with credential values present, placeholdered and removed."""
    volatile = ("request_id", "conn_id", "requested_at", "created_at")
    variants = WEBAPP_HEADER_VARIANTS[group]
    assert set(variants) == {"present", "placeholder", "removed"}
    rows = {
        name: _request_row(web_run.db_path, WEBAPP_REQUESTS[key].request_id, drop=volatile)
        for name, key in variants.items()
    }
    assert rows["present"]["method"] == "POST"  # a real stored row, not an empty comparison
    assert rows["placeholder"] == rows["present"]
    assert rows["removed"] == rows["present"]

    def findings(key: str) -> list[tuple]:
        return _rows(
            web_run.db_path,
            "SELECT rule_id, category, severity, label FROM api_findings "
            "WHERE request_id = ? ORDER BY rule_id",
            (WEBAPP_REQUESTS[key].request_id,),
        )

    assert findings(variants["placeholder"]) == findings(variants["present"])
    assert findings(variants["removed"]) == findings(variants["present"])

    # The placeholder text is header content that is never read, so it is never stored on
    # these rows (``ht_ua_placeholder`` stores it, by design, as a User-Agent: not these).
    assert all("[REDACTED]" not in str(v) for v in rows["placeholder"].values())


def test_spoofed_identity_headers_never_change_the_stored_username(web_run: BatchRun) -> None:
    """``X-Twingate-User`` / ``X_twingate_user`` (any case) are never identity (rule 4)."""
    for key in ("spoof_four_spellings", "cap_spoofed_identity"):
        row = _request_row(web_run.db_path, WEBAPP_REQUESTS[key].request_id)
        assert row["username"] == _WEB_IDENTITY, key
        assert row["user_id"] == _WEB_IDENTITY, key
        assert row["user_key"] == _WEB_IDENTITY, key
    assert {r[0] for r in _rows(web_run.db_path, "SELECT username FROM api_requests")} == {
        _WEB_IDENTITY
    }
    # Connections: one identity, apart from the minimal row of the connection whose start
    # line never arrives (``no_start``), which has none to store.
    nameless = {r[0] for r in _rows(web_run.db_path, "SELECT conn_id FROM connections WHERE username IS NULL")}
    assert nameless == {_conn_id("no_start")}
    assert {
        r[0] for r in _rows(web_run.db_path, "SELECT username FROM connections WHERE username IS NOT NULL")
    } == {_WEB_IDENTITY}
    assert _hits(web_run.logs.text(), WEBAPP_SENTINELS["SPOOF"]) == []


# ---------------------------------------------------------------------------
# T12: gwops content (unknown keys, non-WEB_APP lines, invalid variants)
# ---------------------------------------------------------------------------


def test_gwops_unknown_key_and_ignored_app_field_sentinels_reach_nothing(
    web_run: BatchRun,
) -> None:
    """An unknown ``gwops`` key (scalar or header-shaped) and app fields on ``match: none``."""
    planted: list[str] = []
    for key in _UNKNOWN_KEY_CONN_KEYS:
        lines = webapp_lines_for(key)
        found = _sentinels_in(lines, WEBAPP_GWOPS_SENTINELS)
        assert found, f"{key} carries no gwops sentinel (vacuous)"
        planted.extend(found)
        # The connection is stored as usual: the object is accepted, the extras are ignored.
        case = next(c for c in WEBAPP_GWOPS_CASES if c.key == key)
        row = _connection_row(web_run.db_path, _conn_id(key))
        assert row["gwops_match"] == case.expected["match"], key
        assert row["gwops_app"] == case.expected["app"], key
    assert _all_hits(web_run, tuple(planted)) == {}


@pytest.mark.parametrize("case", _NOT_READ_CASES, ids=lambda c: c.key)
def test_gwops_object_on_a_non_web_app_line_is_never_read_stored_or_logged(
    web_run: BatchRun, case
) -> None:
    """KUBERNETES, lowercase kubernetes, SSH and every other non-WEB_APP type."""
    conn_id = _conn_id(case.key)
    lines = webapp_lines_for(case.key)
    planted = _sentinels_in(lines, WEBAPP_GWOPS_SENTINELS)
    assert planted, f"{case.key} carries no gwops sentinel (vacuous)"

    row = _connection_row(web_run.db_path, conn_id)  # stored as usual
    assert row["resource_type"] == case.resource_type
    assert {c: row[c] for c in _GWOPS_COLUMNS} == dict.fromkeys(_GWOPS_COLUMNS)
    for (request_tls,) in _rows(
        web_run.db_path,
        "SELECT downstream_tls || upstream_tls FROM api_requests WHERE conn_id = ?",
        (conn_id,),
    ):
        assert request_tls is None  # nothing from the object copied onto request rows

    assert _all_hits(web_run, planted) == {}
    assert conn_id not in _gwops_log_events(web_run), "a gwops log event names this connection"


def test_gwops_rejection_set_is_not_vacuous() -> None:
    """The invalid-variant cases carry sentinels, so the leak checks below can fail."""
    planted = {
        s for c in _REJECTED_CASES for s in _sentinels_in(webapp_lines_for(c.key), WEBAPP_GWOPS_SENTINELS)
    }
    assert len(_REJECTED_CASES) >= 30
    assert len(planted) >= 25


@pytest.mark.parametrize("case", _REJECTED_CASES, ids=lambda c: c.key)
def test_each_invalid_gwops_variant_logs_one_warning_with_reason_and_conn_id_only(
    web_run: BatchRun, case
) -> None:
    """Exactly one ``classify.gwops_rejected``: ``reason`` and ``conn_id``, no value, no key name."""
    conn_id = _conn_id(case.key)
    events = _gwops_log_events(web_run).get(conn_id, [])
    assert len(events) == 1, f"{case.key}: expected exactly one gwops log event, got {events}"
    event = events[0]
    assert event["event"] == "classify.gwops_rejected"
    assert event["level"] == "warning"
    assert event["reason"] == case.reason
    assert event["conn_id"] == conn_id
    assert set(event) == {"event", "level", "reason", "conn_id"}, (
        f"{case.key}: warning carries extra fields: {sorted(set(event) - {'event', 'level', 'reason', 'conn_id'})}"
    )

    # The sentinels this variant planted reach neither the DB, the volume nor any log line.
    planted = _sentinels_in(webapp_lines_for(case.key), WEBAPP_GWOPS_SENTINELS)
    assert _all_hits(web_run, planted) == {}

    # The connection is stored exactly as the same line without the object (TLS unknown).
    row = _connection_row(web_run.db_path, conn_id)
    assert {c: row[c] for c in _GWOPS_COLUMNS} == dict.fromkeys(_GWOPS_COLUMNS)
    absent = _connection_row(web_run.db_path, _conn_id("gw_absent"))
    same = ("user_id", "username", "resource_type", "state", "has_api")
    assert {c: row[c] for c in same} == {c: absent[c] for c in same}


@pytest.mark.parametrize("case", _APP_IGNORED_CASES, ids=lambda c: c.key)
def test_a_bad_gwops_app_is_ignored_with_one_warning_and_never_stored_or_logged(
    web_run: BatchRun, case
) -> None:
    """``app`` rejected (control char, bidi, too long, empty, not a string, missing)."""
    conn_id = _conn_id(case.key)
    events = _gwops_log_events(web_run).get(conn_id, [])
    assert len(events) == 1, f"{case.key}: expected exactly one gwops log event, got {events}"
    event = events[0]
    assert event["event"] == "classify.gwops_field_ignored"
    assert event["level"] == "warning"
    assert event["reason"] == case.reason == "gwops_bad_app"
    assert set(event) == {"event", "level", "reason", "conn_id"}
    assert event["conn_id"] == conn_id

    row = _connection_row(web_run.db_path, conn_id)
    assert row["gwops_match"] == "exact" and row["gwops_app"] is None  # rest accepted

    planted = _sentinels_in(webapp_lines_for(case.key), WEBAPP_GWOPS_SENTINELS)
    assert _all_hits(web_run, planted) == {}


def test_gwops_log_events_name_exactly_the_invalid_variants(web_run: BatchRun) -> None:
    """No gwops log for valid, absent, redelivered or non-WEB_APP objects; one per invalid one."""
    expected = {
        _conn_id(c.key): [("classify.gwops_rejected", c.reason)] for c in _REJECTED_CASES
    }
    expected.update(
        {_conn_id(c.key): [("classify.gwops_field_ignored", c.reason)] for c in _APP_IGNORED_CASES}
    )
    actual = {
        conn: [(e["event"], e.get("reason")) for e in events]
        for conn, events in _gwops_log_events(web_run).items()
    }
    assert actual == expected


def test_conflicting_and_late_gwops_objects_are_neither_stored_nor_logged(
    web_run: BatchRun,
) -> None:
    """A repeated start line with another object (or one added later) never rewrites the snapshot."""
    for key in ("redeliver", "redeliver_noobj_then_obj"):
        planted = _sentinels_in(webapp_lines_for(key), WEBAPP_GWOPS_SENTINELS)
        assert planted, f"{key} carries no gwops sentinel (vacuous)"
        assert _all_hits(web_run, planted) == {}
    row = _connection_row(web_run.db_path, _conn_id("redeliver_noobj_then_obj"))
    assert {c: row[c] for c in _GWOPS_COLUMNS} == dict.fromkeys(_GWOPS_COLUMNS)


# ---------------------------------------------------------------------------
# T9: the interim case (WEBAPP_SPEC 3.2 Interim)
# ---------------------------------------------------------------------------


def _interim_conn_ids() -> tuple[str, ...]:
    """Every ``conn_id`` carried by a JSON interim line."""
    ids: set[str] = set()
    for line in webapp_interim_lines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("conn_id"), str):
            ids.add(obj["conn_id"])
    return tuple(sorted(ids))


def test_interim_fixture_is_not_vacuous() -> None:
    """Interim lines of every shape exist, and JSON ones carry connection ids to check."""
    assert set(WEBAPP_INTERIM_SECTIONS) == {
        "nonjson_capture", "nonjson_synthetic", "service_capture",
        "service_synthetic", "ssh_audit", "ssh_operational",
    }
    assert len(_interim_conn_ids()) >= 3
    interim_text = "\n".join(webapp_interim_lines())
    assert all(s in interim_text for s in WEBAPP_INTERIM_SENTINELS)
    # The batch interleaves: interim lines sit between valid ones, in a single batch.
    batch = webapp_mixed_batch()
    assert len(batch) == len(webapp_lines()) + len(webapp_interim_lines())
    first_interim = batch.index(webapp_interim_lines()[0])
    assert 0 < first_interim < len(webapp_lines())


def test_mixed_batch_returns_204_and_drops_the_non_json_lines_with_a_reason_only(
    mixed_run: BatchRun,
) -> None:
    """204; non-JSON lines are dropped, each logged as ``reason`` and ``length`` only."""
    assert mixed_run.ingest_status == 204
    events = mixed_run.logs.structlog_events()
    ingest = next(e for e in events if e["event"] == "ingest.http")
    assert ingest["accepted"] + ingest["dropped"] == len(mixed_run.lines)
    assert ingest["dropped"] >= 7  # the capture's seven non-JSON lines at least
    drops = [e for e in events if e["event"] == "normalize.drop"]
    assert len(drops) == ingest["dropped"]
    for drop in drops:
        assert set(drop) == {"event", "level", "reason", "length"}, drop
        assert drop["level"] == "warning"
    assert [e for e in events if e["event"] == "pipeline.error"] == []


def test_mixed_batch_stores_exactly_the_valid_lines(web_runs: WebRuns) -> None:
    """Valid lines are stored as if the interim lines were absent; no row appears or changes."""
    valid, mixed = web_runs.valid, web_runs.mixed
    for table, drop in (
        ("connections", ("created_at", "last_seen_at")),
        ("api_requests", ("created_at",)),
        ("api_findings", ("id", "created_at")),
    ):
        stored = _table_rows(mixed.db_path, table, drop)
        assert stored, f"{table} is empty in the mixed run (vacuous)"
        assert stored == _table_rows(valid.db_path, table, drop), table
    for table in ("sessions", "findings"):
        assert _table_rows(mixed.db_path, table, ("created_at",)) == _table_rows(
            valid.db_path, table, ("created_at",)
        ), table


def test_mixed_batch_creates_no_row_for_any_interim_connection(mixed_run: BatchRun) -> None:
    """No table holds a ``conn_id`` that only interim lines carry."""
    conn_ids = _interim_conn_ids()
    hits, _ = _db_cell_hits(mixed_run.db_path, conn_ids)
    assert hits == [], f"interim connection stored: {hits}"
    assert _raw_db_file_hits(mixed_run.db_path, conn_ids) == []


def test_no_interim_sentinel_in_db_volume_or_logs_of_the_mixed_batch(mixed_run: BatchRun) -> None:
    """Non-JSON, service, SSH ``env``/``exec`` and SSH operational sentinels reach nothing."""
    leaks = _all_hits(mixed_run, WEBAPP_INTERIM_SENTINELS)
    assert leaks == {}, f"interim sentinel found: {leaks}"
    # The valid lines in the same batch still keep every never-stored sentinel out.
    leaks = _all_hits(mixed_run, WEBAPP_NEVER_STORED_SENTINELS)
    assert leaks == {}, f"never-stored sentinel found: {leaks}"
    assert _hits(mixed_run.logs.text(), WEBAPP_PATH_TOKENS) == []


@pytest.mark.parametrize("section", list(WEBAPP_INTERIM_SECTIONS))
def test_interim_section_alone_creates_no_row_and_leaks_nothing(
    tmp_path: Path, section: str
) -> None:
    """Each interim section posted by itself: 204, zero rows anywhere, no sentinel anywhere."""
    lines = webapp_interim_section(section)
    assert lines
    batch = _run_batch(tmp_path, lines, encryption=False)
    assert batch.ingest_status == 204
    for table in _DATA_TABLES:
        count = _scalar(batch.db_path, f"SELECT COUNT(*) FROM {table}")  # noqa: S608
        assert count == 0, f"{section}: {count} row(s) in {table}"
    assert _all_hits(batch, WEBAPP_INTERIM_SENTINELS) == {}
    # The capture's own non-JSON and service lines carry no planted sentinel, so also assert
    # that no line's content (>= 20 characters) reaches the DB, the volume or a log.
    contents = tuple(dict.fromkeys(l.strip() for l in lines if len(l.strip()) >= 20))
    assert contents
    assert _all_hits(batch, contents) == {}
    if section not in ("nonjson_capture", "service_capture"):
        assert _sentinels_in(lines, WEBAPP_INTERIM_SENTINELS), f"{section}: no sentinel (vacuous)"
    assert [e for e in batch.logs.structlog_events() if e["event"] == "pipeline.error"] == []


# ===========================================================================
# Session 12: web apps (T12 hygiene). UI pages, cursor pages, visit views, system
# pages and CSV exports (WEBAPP_SPEC 10, 12.2, 12.3).
# ===========================================================================
#
# The same ``webapp_lines.ndjson`` batch the Session 11 tests post is ingested again, and
# the app's UI is then swept through the live client (encryption off and on). Credential
# headers, spoofed identity headers, unmasked query values, ``gwops`` content that is never
# read, and the User-Agent must not appear on ANY page, cursor page, visit view, system
# page or CSV. Path tokens are expected unmasked (accepted risk, WEBAPP_SPEC 5.3 withdrawn,
# 10): the test documents that by asserting they ARE there.
#
# The sweep's own captured logs are not scanned: the TestClient's httpx logger prints every
# request URL (a test artifact), and the log guarantees are asserted on the Session 11 batch.

_WEB_UI_BEFORE = "2026-10-09T00:00:00Z"  # pins the system-page window over the 2026-10-08 fixture

# gwops sentinels that sit in unknown keys, in ignored ``app`` fields, or in objects on
# KUBERNETES / SSH / other-typed start lines (never read).
_GWOPS_UNKNOWN_KEY_SENTINELS = tuple(
    s for s in WEBAPP_GWOPS_SENTINELS if any(t in s for t in ("UNKNOWN_SCALAR", "UNKNOWN_HDRS", "NONE_APP"))
)
_GWOPS_NON_WEB_SENTINELS = tuple(
    s for s in WEBAPP_GWOPS_SENTINELS
    if any(t in s for t in ("_K8S_", "_K8SLOWER_", "_SSH_", "_NORT_", "_JUNKRT_", "_INTRT_", "_DBRT_"))
)
_GWOPS_REJECTED_SENTINELS = tuple(s for s in WEBAPP_GWOPS_SENTINELS if "_REJ_" in s)
_GWOPS_IGNORED_SENTINELS = tuple(
    s for s in WEBAPP_GWOPS_SENTINELS
    if any(t in s for t in ("_APP_CTRL_", "_APP_BIDI_", "_APP_LSEP_", "_APP_LONG_", "_CONFLICT_APP_",
                            "_RETROFILL_APP_", "_GWID_SPACE_"))
)
_WEB_ECHO = "GC_WEB_PROBE_ECHO"


def _web_ui_paths(db_path: Path) -> list[str]:
    """Every UI page the web sweep fetches (seeds are fetched whatever the crawl cap)."""
    paths = [
        "/dashboard", "/dashboard?window=all", "/dashboard?window=7", "/systems", "/search",
        "/search?window=all", "/search?type=any&window=all", "/search?type=web",
        "/search?type=web&window=all", "/search?type=web&sort=risk",
        "/search?type=kubectl&window=all", "/search?type=recordings&window=all",
    ]
    for value in ("https", "http", "unknown"):
        paths.append(f"/search?type=web&scheme={value}")
        paths.append(f"/search?type=any&scheme={value}")
    for value in ("verified", "ca_only", "unverified", "plaintext", "unknown"):
        paths.append(f"/search?type=web&upstream={value}")
    paths += [
        "/search?type=web&scheme=https&upstream=verified",
        "/search?type=web&scheme=http&upstream=plaintext",
        "/search?type=web&has_findings=true",
        "/search?type=web&discovery=1",
        "/search?" + _q(type="web", q="report"),
        "/search?" + _q(type="web", q="login"),
        "/search?" + _q(type="web", q="reset"),
        "/search?" + _q(type="web", q="/"),
        "/search?" + _q(type="web", user=_WEB_IDENTITY),
        "/search?" + _q(user=_WEB_IDENTITY, window="all"),
    ]
    addresses = [
        a for (a,) in _rows(
            db_path,
            "SELECT resource_address FROM sessions UNION SELECT resource_address FROM api_requests "
            "UNION SELECT resource_address FROM connections",
        )
    ]
    for address in addresses:
        slug = _system_slug(address)
        system = address if address else "_unknown"
        paths += [
            f"/systems/{slug}",
            f"/systems/{slug}?activity_before={_WEB_UI_BEFORE}",
            "/search?" + _q(system=system, window="all"),
            "/search?" + _q(type="web", system=system),
        ]
    # Visit views: one per system+user (the system page's rows) and one per connection (the
    # search rows' Visit links), plus the kubectl activity route for the same keys.
    for kind, route in (("web", "web"), ("kubectl", "activity")):
        groups = _rows(
            db_path,
            "SELECT resource_address, user_key, conn_id, MIN(requested_at), MAX(requested_at) "
            "FROM api_requests WHERE api_kind = ? GROUP BY resource_address, user_key, conn_id",
            (kind,),
        )
        for address, user_key, _conn, first, last in groups:
            slug = _system_slug(address)
            user = quote(user_key if user_key else "_unknown", safe="")
            paths.append(
                f"/systems/{slug}/{route}?user={user}&from={quote(first, safe='')}&to={quote(last, safe='')}"
            )
        spans = _rows(
            db_path,
            "SELECT resource_address, user_key, MIN(requested_at), MAX(requested_at) "
            "FROM api_requests WHERE api_kind = ? GROUP BY resource_address, user_key",
            (kind,),
        )
        for address, user_key, first, last in spans:
            slug = _system_slug(address)
            user = quote(user_key if user_key else "_unknown", safe="")
            paths.append(
                f"/systems/{slug}/{route}?user={user}&from={quote(first, safe='')}&to={quote(last, safe='')}"
            )
    for (request_id,) in _rows(db_path, "SELECT request_id FROM api_requests"):
        paths.append("/search?" + _q(cmd=request_id))
    for (conn_id,) in _rows(db_path, "SELECT conn_id FROM sessions"):
        paths.append(f"/sessions/{conn_id}")
    paths += [
        "/search/export.csv",
        "/search/export.csv?type=any",
        "/search/export.csv?type=web",
        "/search/export.csv?type=web&scheme=https",
        "/search/export.csv?type=web&scheme=http&upstream=plaintext",
        "/search/export.csv?type=web&upstream=unknown",
        "/search/export.csv?type=kubectl",
        "/search/export.csv?type=recordings",
        "/search/export.csv?scheme=unknown",
    ]
    return list(dict.fromkeys(paths))


_WEB_UI_PROBES = (
    f"/search?type=web&scheme={_WEB_ECHO}",
    f"/search?type=web&upstream={_WEB_ECHO}",
    f"/search?type=web&scheme=https&scheme={_WEB_ECHO}",
    f"/search?scheme=HTTPS&cursor={_WEB_ECHO}",
    f"/search/export.csv?type=web&scheme={_WEB_ECHO}",
    f"/search/export.csv?type=web&upstream={_WEB_ECHO}&upstream={_WEB_ECHO}",
    f"/systems/wiki.example.test/web?user={_WEB_ECHO}%00&from=2026-10-08T00:00:00Z&to=2026-10-09T00:00:00Z",
    f"/systems/wiki.example.test/web?user=u&from={_WEB_ECHO}&to=2026-10-09T00:00:00Z",
    f"/systems/wiki.example.test/web?user=u&from=2026-10-08T00:00:00Z&to={_WEB_ECHO}",
    f"/systems/wiki.example.test/web?user=u&user={_WEB_ECHO}&from=2026-10-08T00:00:00Z&to=2026-10-09T00:00:00Z",
    f"/systems/wiki.example.test/web?user={_WEB_ECHO}&from=2026-10-09T00:00:00Z&to=2026-10-08T00:00:00Z",
)


def _sweep_web_ui(client: TestClient, batch: BatchRun) -> None:
    """Fetch every web UI surface into ``batch.pages`` (explicit seeds, cursor walks, crawl)."""
    explicit = _web_ui_paths(batch.db_path)
    for start in (
        "/search?type=web&page_size=1",
        "/search?type=any&page_size=1",
        "/search?type=web&scheme=https&page_size=1",
        "/search?type=web&upstream=plaintext&page_size=1",
        "/search?window=all&page_size=1",
    ):
        explicit += _cursor_walk(client, start, 8)
    explicit = list(dict.fromkeys(explicit))
    _crawl(client, batch, list(explicit))  # type: ignore[arg-type]  # duck-typed: only ``pages`` is used
    for path in explicit:
        batch.pages.setdefault(path, _fetch(client, path))
    batch.explicit_paths = explicit
    batch.error_pages = {p: _fetch(client, p) for p in _WEB_UI_PROBES}


@pytest.fixture(
    scope="module",
    params=[False, True],
    ids=["encryption-off", "encryption-on"],
)
def web_ui_run(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> BatchRun:
    """The full web fixture ingested, then every web UI surface swept (one run per mode)."""
    tag = "enc" if request.param else "plain"
    return _run_batch(
        tmp_path_factory.mktemp(f"web_ui_{tag}"),
        webapp_lines(),
        encryption=request.param,
        sweep=_sweep_web_ui,
    )


def _ui_pages(batch: BatchRun) -> dict[str, Page]:
    """Every fetched page of the sweep (the 400 probes are kept apart)."""
    return batch.pages


def _html_pages(batch: BatchRun) -> dict[str, Page]:
    """The sweep's HTML pages (everything that is not a CSV export)."""
    return {p: pg for p, pg in batch.pages.items() if urlsplit(p).path != "/search/export.csv"}


def _csv_page_map(batch: BatchRun) -> dict[str, Page]:
    """The sweep's CSV exports."""
    return {p: pg for p, pg in batch.pages.items() if urlsplit(p).path == "/search/export.csv"}


def _all_text(pages: dict[str, Page]) -> str:
    """Every page's headers + body as one string."""
    return "\n".join(pg.text for pg in pages.values())


def test_web_ui_sweep_reached_every_web_surface(web_ui_run: BatchRun) -> None:
    """Positive controls: the sweep fetched real web pages, so the scans below are not vacuous."""
    assert web_ui_run.ingest_status == 204
    pages = web_ui_run.pages
    explicit = web_ui_run.explicit_paths
    assert len(explicit) > 60
    for path in explicit:
        assert pages[path].status == 200, f"{path} -> {pages[path].status}"
    html_pages = _html_pages(web_ui_run)
    # Web search rows, in the full page and on cursor pages.
    assert 'class="pill pill-web"' in pages["/search?type=web"].text
    cursor_pages = [
        pg for p, pg in html_pages.items() if "cursor=" in p and "type=web" in p
    ]
    assert len(cursor_pages) >= 3, "no web cursor pages were walked"
    assert all('class="pill pill-web"' in pg.text for pg in cursor_pages)
    # Visit views and system pages with the configuration block.
    visits = {p: pg for p, pg in html_pages.items() if urlsplit(p).path.endswith("/web")}
    assert len(visits) >= 3, "no visit views were fetched"
    assert all("Configured web app TLS (from gwops)" in pg.text for pg in visits.values())
    system_pages = {
        p: pg for p, pg in html_pages.items()
        if re.fullmatch(r"/systems/[^/?]+(\?.*)?", p) and "Configured web app TLS" in pg.text
    }
    assert system_pages, "no system page rendered the configuration block"
    # Dashboard and systems list render the web tile, feed rows and badges.
    assert "Web requests" in pages["/dashboard?window=all"].text
    assert 'class="pill pill-web"' in pages["/dashboard?window=all"].text
    assert ">Web</span>" in pages["/systems"].text
    # CSV exports carry web rows with 22 columns.
    web_csv = pages["/search/export.csv?type=web"].text
    assert ",web," in web_csv and ",WEB_APP," in web_csv
    # The 400 probes were rejected.
    assert web_ui_run.error_pages
    assert all(pg.status == 400 for pg in web_ui_run.error_pages.values())


def test_web_ui_pages_render_gwops_derived_and_stored_content(web_ui_run: BatchRun) -> None:
    """The pages do show what is meant to be shown (so a missing sentinel proves something)."""
    text = _all_text(_html_pages(web_ui_run))
    for shown in (
        "Legacy Wiki (prod)",  # unmanaged app name (a tenant resource name)
        "mode-b-app",  # exact object with a NULL gateway id
        "gateway id not yet assigned",
        "TLS unknown",
        "No gwops data on these connections",
        "gwops matched no web app at this address on gateway",
        "(or had not yet read the tenant",  # the none line's trailing clause (apostrophe is escaped)
        "gwops found more than one web app at this address on gateway",
        "Unverified upstream",
        "Plaintext upstream",
        "CA-only upstream",
        "pill-https",
        "pill-http",
        "pill-unmanaged",
        "pill-managed",
        '<span class="dim">WebSocket</span>',  # a 101 row in the visit view
        "…(",  # a masked query value
    ):
        assert shown in text, f"nothing rendered {shown!r} (vacuous)"
    assert WEBAPP_GATEWAY_ID in text  # the example gateway id from the synthetic objects


def test_no_credential_spoof_query_or_gwops_sentinel_on_any_page_or_export(web_ui_run: BatchRun) -> None:
    """Credential headers, spoofed identity headers, unmasked query values, the panic text and
    every never-read ``gwops`` value appear on no page, cursor page, visit view, system page or CSV."""
    needles = WEBAPP_NEVER_STORED_SENTINELS
    assert _sentinels_in(webapp_lines(), needles), "no sentinel in the posted input (vacuous)"
    leaks = {
        path: found
        for path, page in web_ui_run.pages.items()
        if (found := _hits(page.text, needles))
    }
    assert leaks == {}, f"never-stored sentinel rendered: {leaks}"


def test_no_service_credential_or_header_name_on_any_page_or_export(web_ui_run: BatchRun) -> None:
    """The UI/ingest secrets and request-header lines never appear on any page or export."""
    forbidden = ("Bearer", INGEST_TOKEN, UI_PASSWORD, "Authorization:", "Cookie:", "X-Api-Key")
    leaks = {p: found for p, pg in web_ui_run.pages.items() if (found := _hits(pg.text, forbidden))}
    assert leaks == {}, f"forbidden text rendered: {leaks}"


def test_command_parameter_is_masked_on_web_rows_and_absent_from_kubectl_pages(
    web_ui_run: BatchRun,
) -> None:
    """``command=`` may appear only as a masked web query key; a kubectl exec URL never carries it.

    A web request can legitimately have a ``command`` query KEY (keys are kept, values
    masked, WEBAPP_SPEC 5.4), so the Session 9 rule "no ``command=`` anywhere" now reads:
    every occurrence is followed by a masked value (``…(N)``), and no kubectl-kind page
    or kubectl export row contains it at all.
    """
    pages = web_ui_run.pages
    occurrences = [
        (path, m.group(1))
        for path, pg in pages.items()
        for m in re.finditer(r"command=([^&\s<\"]*)", pg.text)
    ]
    assert occurrences, "no web page rendered a command= key (vacuous)"
    assert all("…" in value for _path, value in occurrences), occurrences[:3]
    for path in ("/search?type=kubectl&window=all", "/search/export.csv?type=kubectl"):
        assert "command=" not in pages[path].text, path
    activity = [pg for p, pg in pages.items() if "/activity?" in p]
    assert activity and all("command=" not in pg.text for pg in activity)


@pytest.mark.parametrize(
    ("group", "sentinels"),
    [
        ("unknown-key", _GWOPS_UNKNOWN_KEY_SENTINELS),
        ("non-web-object", _GWOPS_NON_WEB_SENTINELS),
        ("rejected-object", _GWOPS_REJECTED_SENTINELS),
        ("ignored-or-conflicting", _GWOPS_IGNORED_SENTINELS),
    ],
    ids=["unknown-key", "non-web-object", "rejected-object", "ignored-or-conflicting"],
)
def test_gwops_sentinel_groups_never_reach_a_page(
    web_ui_run: BatchRun, group: str, sentinels: tuple[str, ...]
) -> None:
    """Unknown ``gwops`` keys, objects on KUBERNETES/SSH/other lines, and rejected objects: nowhere."""
    assert sentinels, f"{group}: empty sentinel group"
    posted = _sentinels_in(webapp_lines(), sentinels)
    assert posted == sentinels, f"{group}: not every sentinel is in the input (vacuous)"
    text = _all_text(web_ui_run.pages)
    assert _hits(text, sentinels) == [], f"{group}: rendered"


def test_kubernetes_and_ssh_system_pages_were_swept_for_gwops_leaks(web_ui_run: BatchRun) -> None:
    """The KUBERNETES / SSH systems that carried a ``gwops`` object were actually fetched."""
    pages = web_ui_run.pages
    k8s = [p for p in pages if p.startswith("/systems/k8s.riglabel.rig.test")]
    assert any(p.endswith("?activity_before=" + _WEB_UI_BEFORE) for p in k8s)
    assert any("/activity?" in p for p in k8s), "no kubectl activity page for the k8s system"
    assert any(p.startswith("/search?cmd=") for p in pages)
    ssh = [p for p in pages if p.startswith("/systems/ssh-target.riglabel.rig.test")]
    assert ssh, "the SSH system page was not fetched"


def test_user_agent_sentinel_is_stored_but_never_rendered_or_exported(web_ui_run: BatchRun) -> None:
    """The full User-Agent is stored on web rows by design (control) and rendered nowhere."""
    assert _sentinels_in(webapp_lines(), WEBAPP_USER_AGENT_SENTINELS), "not in the input (vacuous)"
    cells, _ = _db_cell_hits(web_ui_run.db_path, WEBAPP_USER_AGENT_SENTINELS)
    assert cells, "the User-Agent sentinel was not stored (the control is vacuous)"
    assert any(c.startswith("api_requests.user_agent") for c in cells)
    leaks = {
        p: found
        for p, pg in web_ui_run.pages.items()
        if (found := _hits(pg.text, WEBAPP_USER_AGENT_SENTINELS))
    }
    assert leaks == {}, f"User-Agent rendered: {leaks}"


def test_path_token_sentinels_are_rendered_unmasked_by_design(web_ui_run: BatchRun) -> None:
    """Accepted risk (WEBAPP_SPEC 5.3 withdrawn, 10): path tokens show in full in the UI and CSV.

    Documents the behaviour rather than hiding it: every path-token sentinel is on at
    least one HTML page (search rows, focus pages, visit views). The CSV ``path`` column
    carries only a connection's primary request, and no fixture connection has a token in
    its primary path, so the CSV side is pinned in ``test_web_search.py``
    (``test_csv_web_path_is_exported_unmasked_by_design``). Masked query values are never
    complete (separate test).
    """
    html_text = _all_text(_html_pages(web_ui_run))
    missing = [t for t in WEBAPP_PATH_TOKENS if t not in html_text]
    assert missing == [], f"path tokens expected unmasked on a page but absent: {missing}"


def test_masked_query_values_are_never_complete_but_keys_and_lengths_show(web_ui_run: BatchRun) -> None:
    """Query values appear only masked (``…(N)``); the full sentinel never does (positive control)."""
    text = _all_text(web_ui_run.pages)
    assert re.search(r"[A-Za-z0-9_.\[\]-]+=[A-Za-z0-9._~-]{0,4}…[A-Za-z0-9._~-]{0,4}\(\d+\)", text)
    for sentinel in WEBAPP_QUERY_SENTINELS:
        assert sentinel not in text


def test_csv_exports_of_web_rows_have_22_columns_and_valid_web_cells(web_ui_run: BatchRun) -> None:
    """Every export parses, is 22 columns wide, and its web rows use the fixed vocabularies."""
    import csv as csvmod

    csvs = _csv_page_map(web_ui_run)
    assert {"/search/export.csv", "/search/export.csv?type=web", "/search/export.csv?type=any"} <= set(csvs)
    web_rows = 0
    for path, page in csvs.items():
        head, body = _split(page)
        assert "text/csv" in head.lower(), path
        rows = list(csvmod.reader(io.StringIO(body)))
        assert rows[0][0] == "conn_id" and len(rows[0]) == 22, path
        assert all(len(r) == 22 for r in rows), f"{path}: ragged rows"
        for row in rows[1:]:
            if row[10] == "web":
                web_rows += 1
                assert row[15] == "WEB_APP" and row[16] in {"https", "http", "unknown"}, (path, row)
                assert row[17] in {"verified", "ca_only", "unverified", "plaintext", "unknown"}, (path, row)
                assert row[13] and "?" not in row[13] and "?" not in row[18], (path, row)
                assert row[7] == "0" and row[3] == "" and row[11] == "", (path, row)
                assert row[21] in {"", "true", "false"}, (path, row)
            elif row[10] == "kubectl":
                assert row[15:] == ["KUBERNETES", "", "", "", "", "", ""], (path, row)
            else:
                assert row[16:] == [""] * 6, (path, row)
    assert web_rows >= 10, "the CSV sweep held too few web rows (vacuous)"


def test_web_ui_400_pages_do_not_echo_submitted_values(web_ui_run: BatchRun) -> None:
    """Invalid web filters and visit parameters are 400s that name the parameter, never the value."""
    errors = web_ui_run.error_pages
    assert errors, "no 400 probes were fetched (vacuous)"
    for path, page in errors.items():
        assert page.status == 400, f"{path} -> {page.status}"
        assert _WEB_ECHO not in page.text, f"{path} echoed a submitted value"
        assert "command=" not in page.text


# ---------------------------------------------------------------------------
# Session 12 fix loop (B): requests that beat, or never meet, their start line
# ---------------------------------------------------------------------------
#
# A request stored before its start line is a provisional kubectl row whose URL is the stricter of
# the Kubernetes and web forms (``webmask.store_provisional_url``). An exec ``command=`` value and a
# service-proxy path/query value must reach nothing: not the DB, the volume, the logs, any kubectl
# or web page, nor the CSV, whether the start line never comes, comes as KUBERNETES, or as WEB_APP.

_PROV_CMD = "QJxCMDsentinelValue7f3aKZ"
_PROV_PROXY = "QJxPROXYsentinelPath9c1dKZ"
_PROV_QUERY = "QJxQUERYsentinelValue4b2eKZ"
_PROV_FRAGMENTS = tuple(s[:2] for s in (_PROV_CMD, _PROV_PROXY, _PROV_QUERY)) + tuple(
    s[-2:] for s in (_PROV_CMD, _PROV_PROXY, _PROV_QUERY)
)
_PROV_NEEDLES = (_PROV_CMD, _PROV_PROXY, _PROV_QUERY, *_PROV_FRAGMENTS)
_PROV_SCENARIOS = (  # (tag, address, start resource_type or None for "no start line ever")
    ("none", None, None),
    ("k8s", "prov-k8s.example.test", "KUBERNETES"),
    ("web", "prov-web.example.test", "WEB_APP"),
)


def _provisional_lines() -> list[str]:
    """Two sentinel-bearing requests per scenario connection, then (if any) its start line."""
    lines: list[str] = []
    for i, (tag, address, resource_type) in enumerate(_PROV_SCENARIOS):
        conn = f"5b0b0000-0000-4000-8000-00000000000{i}"
        urls = (
            f"/api/v1/namespaces/x/pods/y/exec?command={_PROV_CMD}&stdin=true",
            f"/api/v1/namespaces/x/services/s/proxy/{_PROV_PROXY}?a={_PROV_QUERY}",
        )
        for j, url in enumerate(urls):
            at = f"2026-10-08T12:0{i}:0{j + 1}.000Z"
            lines.append(json.dumps({
                "logger": "gateway.audit", "message": "API request completed", "ts": at,
                "requested_at": at, "request_id": f"5b0b1111-0000-4000-8000-0000000000{i}{j}",
                "conn_id": conn, "method": "GET", "url": url,
                "user": {"id": "prov-user", "username": "prov@example.test"},
                "request": {"headers": {
                    "User-Agent": ["kubectl/v1.33.0"], "Kubectl-Command": ["kubectl exec"],
                    "Kubectl-Session": [f"5e55e55e-0000-4000-8000-00000000009{i}"],
                }},
                "response": {"status_code": 101},
            }))
        if resource_type is not None:
            lines.append(json.dumps({
                "logger": "gateway", "message": "Authenticated connection", "conn_id": conn,
                "ts": f"2026-10-08T12:0{i}:09.000Z", "user": {"id": "prov-user", "username": "prov@example.test"},
                "resource_address": address, "resource_type": resource_type,
            }))
    return lines


@pytest.fixture(scope="module")
def provisional_run(tmp_path_factory: pytest.TempPathFactory) -> BatchRun:
    """The provisional-URL scenarios ingested over ``/ingest`` and every UI surface swept."""
    return _run_batch(
        tmp_path_factory.mktemp("prov_hygiene"), _provisional_lines(), encryption=False, sweep=_sweep_web_ui
    )


def test_provisional_hygiene_positive_controls(provisional_run: BatchRun) -> None:
    """The sentinels are in the posted input, every line was processed, and the sweep reached the pages."""
    assert _sentinels_in(provisional_run.lines, (_PROV_CMD, _PROV_PROXY, _PROV_QUERY)) == (
        _PROV_CMD, _PROV_PROXY, _PROV_QUERY,
    )
    assert provisional_run.ingest_status == 204
    assert _scalar(provisional_run.db_path, "SELECT COUNT(*) FROM api_requests") == 6
    urls = sorted(u for (u,) in _rows(provisional_run.db_path, "SELECT url FROM api_requests"))
    assert urls == sorted(
        ["/api/v1/namespaces/x/pods/y/exec?stdin=t…(4)", "/api/v1/namespaces/x/services/s/proxy"] * 3
    )
    for prefix in ("/systems/_unknown", "/systems/prov-k8s.example.test", "/systems/prov-web.example.test"):
        assert any(p.startswith(prefix) and pg.status == 200 for p, pg in provisional_run.pages.items()), prefix
    assert any(urlsplit(p).path == "/search/export.csv" and pg.status == 200 for p, pg in provisional_run.pages.items())
    text = _all_text(provisional_run.pages)
    assert "stdin=t…(4)" in text  # the provisional form is what the pages show


def test_provisional_rows_follow_their_start_line_but_keep_the_provisional_url(provisional_run: BatchRun) -> None:
    """None stays kubectl, a late KUBERNETES start stays kubectl, a late WEB_APP start converts to web."""
    rows = _rows(
        provisional_run.db_path,
        "SELECT r.api_kind, r.kubectl_command, c.resource_type FROM api_requests r "
        "JOIN connections c ON c.conn_id = r.conn_id ORDER BY r.conn_id, r.request_id",
    )
    assert [(k, cmd, rt) for k, cmd, rt in rows] == [
        ("kubectl", "kubectl exec", None), ("kubectl", "kubectl exec", None),
        ("kubectl", "kubectl exec", "KUBERNETES"), ("kubectl", "kubectl exec", "KUBERNETES"),
        ("web", None, "WEB_APP"), ("web", None, "WEB_APP"),
    ]


def test_no_provisional_sentinel_or_fragment_in_db_volume_or_logs(provisional_run: BatchRun) -> None:
    """Whole values and 2-character prefix/suffix fragments reach neither tables, files nor logs."""
    assert _all_hits(provisional_run, _PROV_NEEDLES) == {}


def test_no_provisional_sentinel_or_fragment_on_any_page_or_export(provisional_run: BatchRun) -> None:
    """Kubectl pages, web pages (system, visit view, search rows, dashboard feed) and CSV carry none of it."""
    leaks = {
        path: found
        for path, page in provisional_run.pages.items()
        if (found := _hits(page.text, _PROV_NEEDLES))
    }
    assert leaks == {}, f"provisional-row sentinel rendered: {leaks}"
    csv_pages = _csv_page_map(provisional_run)
    assert csv_pages and all(pg.status == 200 for pg in csv_pages.values())
