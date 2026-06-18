# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.3.0] - 2026-06-18

### Added

- **Content search + metadata filtering** over recorded sessions (`GET /search`): filter by
  user, system, status, date range, duration range, severity (at-or-above), finding
  category, dangerous-command rule multiselect, free-text keyword, and custom regex.
  HTMX-driven results with pagination and shareable query-string URLs; all behind UI auth.
- **Automated detection at finalize**: a built-in rule set (~21 rules across
  dangerous-command and secret-exposure categories) scans each reassembled recording and
  stores **findings** (rule label + severity + replay offset only — never the matched
  text, CLAUDE.md rule 6). Alert *dispatch* is deferred; the findings it would consume are
  produced now.
- **Encrypted plaintext sidecars** (`<conn_id>.txt.enc`): finalize writes an ANSI-stripped
  plaintext rendering of each recording, encrypted with an independent key derived from the
  master key (distinct HKDF `info`) when encryption is enabled, plaintext otherwise. This
  feeds **scan-on-demand** content search — metadata + precomputed findings narrow the
  candidate set, then the sidecars for those candidates are decrypted and scanned in a
  worker thread, bounded by `SEARCH_REGEX_MAX_CANDIDATES`. **No FTS5, no SQLCipher**; the
  metadata database stays plaintext.
- **Seek-to-finding replay**: clicking a finding on the session detail page seeks the
  vendored asciinema player to that moment (`player.seek(offset)`). A `?t=<seconds>`
  (or `#t=`) **deep link also works on initial page load / refresh** — the offset is
  passed to the player as `startAt` + `poster` (and autoplays), so a "jump" from the
  search results lands at the right timestamp even before the player has loaded.
- **CSV export** of a filtered/search result set (`GET /search/export.csv`): session
  metadata + a finding-summary column (`label@offset`s) — never recorded text.
- **Auditor dashboard** (`GET /dashboard`, now the site root): total/flagged counts,
  severity and category breakdowns, and top users/systems as server-rendered CSS bars
  (no new JS — offline preserved, rule 8). `/` now redirects here.
  - **Time-windowed** with a 7 / 30 / 90 / All-time toggle (default 30 days); every
    figure and drill-down link is scoped to the selected window.
  - **Drill-down links**: each severity badge → search filtered by that exact highest
    severity; each category → search filtered by that category; each top user → that
    user's sessions in search; each top system → the system's session list. Links carry
    the active window via `started_after` so counts and results stay consistent.
- **Exact `max_severity` search filter** (query param + hidden form field): matches a
  session by its single highest severity. Distinct from the existing `severity` filter,
  which is at-or-above; the dashboard severity drill-down uses the exact match so its
  links return exactly the counted sessions.
- **Risk badges** on the systems' session list and search results, from the denormalized
  `sessions.finding_count` / `max_severity` columns.
- **Findings column on the systems index**: each system shows its highest-severity badge
  with a total finding count (or `—` if clean), so an admin can spot at a glance which
  systems warrant a closer look. `SessionRepository.list_systems` now aggregates
  `SUM(finding_count)` and the max severity across each system's sessions.
- **Startup backfill** (`BACKFILL_ON_STARTUP`, default on): a throttled, idempotent
  background pass that builds sidecars + findings for finalized recordings that predate the
  feature (or were recovered by the crash sweep).
- **Retention now purges findings + the `.txt.enc` sidecar** alongside the row and `.cast`
  file (one logical operation).
- **Schema**: new `findings` table (+ indexes) and denormalized `sessions.finding_count` /
  `max_severity` columns, added via an idempotent `PRAGMA`-guarded migration so existing
  databases upgrade in place.
- **Configuration**: `DETECTION_ENABLED`, `BACKFILL_ON_STARTUP`, `SEARCH_PAGE_SIZE`,
  `SEARCH_REGEX_MAX_CANDIDATES` (all defaulted).
- **New tests**: extraction, detection (per-rule positive/negative), search store (every
  filter, regex cap + `truncated`, pagination, sort, dashboard), finalize-scan integration,
  retention purge of sidecar+findings, backfill idempotency, web search/dashboard/export
  routes, and an end-to-end ingest→finalize→search test asserting no recorded content
  (incl. a real AWS-key pattern) leaks into any HTML or CSV.

### Changed

- **Site root `/` now redirects to `/dashboard`** (was `/systems`).
- **Trimmed the header**: removed the "Twingate Gateway session recordings" tagline so the
  nav (Dashboard / Systems / Search) reads cleanly.

### Notes

- The `.txt.enc` sidecars are **secret-grade** (they hold on-screen plaintext, which can
  include typed secrets). They live on the same auth-gated volume as the `.cast` files,
  are encrypted under the same master key when encryption is on, and are removed by
  retention — same trust level as the recordings themselves.

## [0.2.0] - 2026-06-18

### Changed

- **Project renamed Reel → Gatorcast** across the package (`src/reel` → `src/gatorcast`),
  imports, packaging (`pyproject.toml`), Docker image (`ghcr.io/twingate-solutions/gatorcast`),
  `container_name`, volume (`gatorcast-data`), CI workflow, FastAPI title, UI copy, and
  docs. No behavior change; the full test suite stays green across the rename.

### Added

- **Optional encryption at rest for `.cast` recordings** (AES-256-GCM): off by default
  (`ENCRYPTION_ENABLED=false`). When enabled, recordings are encrypted on the volume with
  a per-file random nonce and the connection id bound in as additional authenticated data;
  decrypted in memory only for playback. The metadata database stays plaintext (documented
  limitation; encrypting it would require SQLCipher, deliberately avoided).
- **`crypto.py` (`Cryptor`)**: validates a base64 32-byte master key, derives the AES key
  via HKDF-SHA256 (purpose-bound `info`), and frames blobs as `GCST` magic + nonce +
  ciphertext+tag. Never logs the key or any plaintext/ciphertext content.
- **`GATORCAST_MASTER_KEY` + `ENCRYPTION_ENABLED` configuration**: the master key is read
  from the environment (suitable for `.env` or injection from a cloud secrets vault).
- **Fail-closed startup**: with encryption enabled and a missing or invalid key, the app
  refuses to boot rather than storing recordings in the clear.
- **Decrypting cast route**: when encryption is on, `GET /sessions/{conn_id}/cast`
  decrypts in memory and serves `application/x-asciicast`; UI auth and cast-path
  confinement are unchanged, and recording content is still only loaded by the vendored
  player.
- **`cryptography` dependency** added to `pyproject.toml`.
- **New tests**: `test_crypto.py` (round-trip, tamper/wrong-key/AAD-mismatch failures,
  invalid-key construction) plus CastStore encryption and web-route fail-closed/decrypt
  coverage.

### Notes

- **Fresh-start only**: enabling encryption does not migrate existing unencrypted
  recordings. Losing the master key makes encrypted recordings unrecoverable; key rotation
  is not yet supported.

## [0.1.0] - 2026-06-17

### Added

- **Push ingestion via HTTP POST** (`POST /ingest`): accepts NDJSON, JSON array, single
  JSON object, or newline-delimited text; bearer-token auth (`INGEST_TOKEN`); returns
  204; per-line tolerant so one bad line never fails a batch.
- **Push ingestion via syslog TCP** (`SYSLOG_TCP_PORT`, default 6514): asyncio TCP
  server supporting RFC 6587 octet-counting and newline-delimited framing; strips syslog
  envelope (`<PRI>` header) to recover the inner JSON payload; no UDP (asciicast lines
  are multi-KB and must not be truncated).
- **Normalization pipeline**: syslog-envelope stripping, Docker collector-envelope
  unwrapping (`{"log":"...","stream":"stdout"}`), and tolerant `json.loads` — all in one
  step shared by both front doors.
- **Two-stage recording filter** (`pipeline/classify`): an event is a recording chunk
  only when `logger == "gateway.audit"` AND `asciicast` is non-null. `gateway.audit`
  also carries API-request audits with no recording; those are dropped by design.
- **Session-start classification**: `logger == "gateway"` with `"Authenticated
  connection"` is captured as a session-start event, carrying `resource_address` (the
  target system) and the envelope SSO identity (`user.username`).
- **Per-`conn_id` assembler** (`pipeline/assembler`): in-memory buffers keyed by
  `conn_id`; fragments keyed by `asciicast_sequence_num` (last-write-wins for
  redelivery safety); lazy buffer creation so chunks arriving before their start event
  are handled correctly.
- **Concat-then-parse reassembly**: all fragments are sorted by sequence number,
  concatenated into one string, and only then parsed as an asciicast v2 document — a
  Gateway flush may split a single event tuple across two log lines.
- **Idle-timeout finalization** (APScheduler interval job): sessions silent for
  `IDLE_TIMEOUT_SECONDS` are finalized even without a close event.
- **Close-event hook** in classify: wires a `SessionEnd` event for candidate Gateway
  close messages; idle timeout remains the authoritative finalize path.
- **Startup sweep**: on restart, provisional rows orphaned by a crash are either
  recovered from an existing on-disk `.cast` file or swept if stale and empty.
- **SQLite metadata store** (`store/sessions`): WAL mode, `synchronous=NORMAL`; raw
  parameterized SQL; full repository (`upsert_start`, `add_chunk_meta`, `finalize`,
  `finalize_from_disk`, `find_provisional`, `delete_provisional`, `list_systems`,
  `list_sessions`, `get`, `purge_before`, `purge_over_bytes`).
- **`.cast` file store** (`store/casts`): atomic write (temp + replace) using bytes
  (UTF-8) so newline translation never mutates `.cast` files on Windows hosts; read,
  delete (missing-file tolerant), size accounting.
- **Retention purge** (`pipeline/retention`): daily APScheduler job; age-based
  (`RETENTION_DAYS`, 0 = keep forever) and size-based (`RETENTION_MAX_GB`, 0 = off);
  row and file deletion are one logical operation.
- **Web UI** (`web/routes`, `web/templates`): FastAPI + Jinja2 + HTMX; browse systems
  index → sessions list → session detail/replay; `GET /sessions/{conn_id}/cast` serves
  the `.cast` file with media type `application/x-asciicast`; all routes require UI
  auth; recording content is never rendered as HTML.
- **Vendored frontend assets** (offline, no CDN): asciinema-player 3.8.0, htmx 2.0.4,
  Alpine.js 3.14.8, hand-written `app.css`; all served from `/static/`.
- **Asciinema player integration**: the session detail page mounts the vendored player
  pointed at `/sessions/{conn_id}/cast`; ANSI/escape content is never rendered as HTML.
- **UI HTTP Basic auth** (`web/auth`): `require_ui_auth` FastAPI dependency applies to
  every UI and cast route; constant-time credential comparison; `WWW-Authenticate:
  Basic` challenge on failure.
- **Docker image** published to `ghcr.io/twingate-solutions/gatorcast` via GitHub Actions on push to
  `main` and version tags; multi-tag strategy (`latest`, semver tag, SHA).
- **Non-root container**: dedicated `gatorcast` system user (uid/gid 10001); `/data` and
  `/app` pre-created and owned before `USER gatorcast`.
- **Syslog DoS bounds**: `MAX_FRAME_BYTES` (16 MiB), `MAX_LENGTH_DIGITS` (10),
  `MAX_CONNECTIONS` (128), and `IDLE_READ_TIMEOUT_SECONDS` (300) cap resource use from
  a hostile or misbehaving syslog peer.
- **Insecure-default warnings**: startup checks `INGEST_TOKEN`, `UI_AUTH_PASSWORD`, and
  `UI_AUTH_USERNAME` against known placeholder values and logs a warning for each match;
  the service still boots so tests and local runs work without extra configuration.
- **Cast-path confinement** in both the web route and the cast store: `conn_id`-derived
  paths are validated with `is_relative_to(casts_dir)` before serving or reading,
  providing defense in depth against traversal even though `conn_id` is already
  validated in `classify`.
- **`/healthz` endpoint**: returns `{"status": "ok"}`; reachable without UI auth for
  liveness probes.
- **pytest suite** (103 tests): normalization, HTTP ingest, syslog TCP, classify,
  assembler (including multi-chunk, out-of-order, duplicate, interleaved sessions, idle
  finalize, crash recovery), repository CRUD, retention policies, and web route smoke
  tests.
- **GitHub Actions CI** (`publish.yml`): `pytest` gate must pass before the image is
  built and pushed; installs the package with `[dev]` extras.

[0.3.0]: https://github.com/Twingate-Solutions/gatorcast/releases/tag/v0.3.0
[0.2.0]: https://github.com/Twingate-Solutions/gatorcast/releases/tag/v0.2.0
[0.1.0]: https://github.com/Twingate-Solutions/gatorcast/releases/tag/v0.1.0
