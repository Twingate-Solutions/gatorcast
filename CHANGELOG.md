# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.4.0] - 2026-10-05

This release also ships the kubectl activity work that was previously listed under Unreleased.

### Changed

- **`/search` is now a unified search over every event kind.** It lists SSH recordings, kubectl
  exec recordings, failed connections and kubectl commands in one interleaved timeline, selected
  with `type=any|recordings|ssh|exec|failed|kubectl`. A missing `type` means `any`, even on a link
  that carries only old parameters. A kubectl result is one command (grouped as on the activity
  page), expandable to its requests. A filter a kind cannot evaluate (`status`, a duration,
  `mode=regex`, `sort=duration`) excludes that kind and the page says so.
- **Old `/search` links can show more results, never fewer.** The previous parameter names
  (`username`, `resource_address`, `started_after`, `started_before`, `keyword`, `regex`, `page`)
  are still accepted. A link that carried only recording filters still lists every recording it
  listed before, plus any kubectl commands and failed connections that satisfy the same filters.
  Three exceptions:
  1. A value that used to be silently ignored now returns `400`: an unknown `sort`, a non-numeric
     `min_duration` or `max_duration`, and an uncompilable `regex` (which used to return an empty
     result).
  2. `page=N` lands on the first page. The same results are reachable with **Next ›**.
  3. A hand-typed `started_after` or `started_before` with a fractional second can differ at that
     one boundary second, because bounds are now compared in a normalized format. Links built by
     the dashboard never carried fractions.
- **Search paging is keyset-based and forward-only.** The result total, page numbers and **Prev**
  link are gone. **Next ›** carries an opaque cursor and **First page** returns to the start.
  Each page is bounded: at most 20,000 kubectl request rows are examined, and at most
  `SEARCH_REGEX_MAX_CANDIDATES` sidecars are read, per page. When a budget stops a page,
  **Continue scanning ›** resumes without skipping or repeating results. `SEARCH_REGEX_MAX_CANDIDATES`
  is now a per-page limit; it used to cap the whole candidate set. The `search.truncated` log line
  is replaced by `timeline.content_budget_hit`, which carries counters only.
- **Search parameters are validated strictly.** An invalid or repeated value, `window` combined
  with `from`/`to`, `from` later than `to`, an uncompilable regex, or a bad cursor returns `400`
  with a message that names the parameter and never echoes the value. HTMX requests swap the
  message into the results area.
- **CSV export follows the page.** `/search/export.csv` takes the same filters and kinds as the
  page and writes recordings and kubectl commands mixed, in page order. It now has 15 columns:
  the first ten are unchanged for recordings, and `kind`, `command`, `method`, `path` and
  `request_count` are appended. The response sets `X-Gatorcast-Truncated: true` when the export
  stopped early (10,000-row cap, a scan budget, the sidecar limit, or the flagged-command cap).
- **Dashboard figures are links.** Every tile, severity chip and top user opens search with an
  explicit `type` and the selected window, so a figure and its list agree. The kubectl card's
  flagged figure and severity chips now count **commands**, not requests; its total still counts
  requests (discovery included). `DashboardStats.api_flagged_requests` and `api_by_severity` are
  replaced by `api_flagged_commands`, `api_commands_by_severity` and `api_flagged_truncated`.
  Session figures are windowed on the recording start (the Gateway start time, else the time
  Gatorcast first saw the session), the same rule search uses, so a session with no `started_at`
  now falls inside the windows by its first-seen time instead of appearing only under All time.
  An invalid dashboard `window` still falls back to 30 days.
- **Systems list.** "Last seen" is replaced by **Last session** and **Last API request**. Rows
  carry SSH and Kubernetes type badges, sort by the newer of the two timestamps, and the session
  and API request counts link into search. "Last session" is now the newest recording start
  rather than `updated_at`. The SSH badge's `ssh_count` also counts rows that have a `.cast` path
  but zero chunks (recordings rebuilt from disk).
- **Usernames link to search.** A username on the search, dashboard, session, system and activity
  pages links to `/search?user=<username>`. A user known only by id links with that id. The
  `user` filter matches the username or an exact Gateway user id.
- **`SearchStore.search` and `SearchFilters` are deprecated.** They are kept for one release and
  no route calls them.
- **Start-only connections are now pending, not provisional.** An `Authenticated connection`
  line no longer creates a visible session. It writes a hidden *pending connection*
  (`connections` table); the first recording chunk promotes it to a `provisional` session. An
  API-only connection never becomes a session. A connection that delivers neither chunks nor
  API audits within `SESSION_MAX_IDLE_SECONDS` becomes a visible `error` session.
- **One-time database migration (`PRAGMA user_version` 0 to 1).** Historical start-only
  `sessions` rows (`provisional`/`error`, zero chunks, no `.cast` path, zero bytes) are moved
  into `connections`, so empty sessions left by API-only kubectl connections and SSH transport
  failures disappear from the sessions list. Old SSH transport-failure rows cannot be told apart
  from API-only rows and are moved too. Session counts can drop after the upgrade; this is
  expected. A row whose `<conn_id>.cast` or `.txt.enc` file exists on disk is kept. Back up the
  `/data` volume before upgrading.
- **Retention covers kubectl activity.** The `RETENTION_DAYS` purge now also deletes
  `api_requests` (with their findings) and `connections` on the same cutoff. There is no new
  setting. `RETENTION_MAX_GB` still counts `.cast` bytes only and never touches API rows.
- **The two-stage recording filter no longer drops API audits.** `gateway.audit` lines with no
  `asciicast` and the message `API request completed` or `API request failed` are classified as
  API requests instead of being dropped. They are still never treated as recording chunks.
- **File-first session assembly.** Recordings are no longer buffered in memory and written
  once at finalize. Each `conn_id`'s `.cast` is now reassembled and written to disk
  (plaintext) on **every append** — durable across a mid-session restart — and scanned for
  findings **live**. A session is **sealed** to `complete` (encrypted if enabled) either
  terminally on the Gateway's `"session finished"` flush / close event, or reopenably on the
  idle backstop; a late chunk after a backstop seal decrypts, appends, and re-seals, so a
  long interactive pause never loses or splits a recording.
- **Correct multi-chunk reassembly.** Confirmed against the Gateway source
  (`internal/sessionrecorder`) that each chunk is a self-contained `header + new-events`
  document (the header repeats per flush; events are whole lines). Reassembly is now
  line-based — keep the header once, concatenate event lines in `seq` order
  (`reassemble_asciicast`), discriminating header vs event by JSON shape so it survives
  Gateway header/version/event-type changes. Previous raw concatenation corrupted any
  recording that spanned more than one chunk.
- **Detection runs live** on every append (and again at seal) instead of once at finalize,
  so risk shows on in-progress sessions. The content-search sidecar is still written only at
  seal.
- **In-progress recordings are playable** in the UI (served as plaintext; sealed recordings
  are decrypted), shown with an "in progress" badge.
- `IDLE_TIMEOUT_SECONDS` is no longer a finalize trigger — it only sets the idle-sweep cadence
  (the value clamped to 5–30 seconds) and the startup-sweep cutoff.
- **Unparseable ingest lines now log at `warning`** (was `debug`) with the line length (never
  content), so a transport that mangles chunks — e.g. journald splitting large asciicast lines
  at `LineMax` — is a one-glance `event=normalize.drop reason=unparseable length=49152` signal.

### Added

- **Unified search.** Event kinds `ssh`, `exec`, `failed` and `kubectl` in one timeline, with a
  type badge per row. `type=failed` lists failed connections: a connection that delivered neither
  chunks nor API audits before `SESSION_MAX_IDLE_SECONDS`. They have no recording, so the row
  links to the session page (**Details ›**) instead of replay. Under `type=any`, a kubectl exec
  recording appears twice by design: as its own `exec` row and as the **Replay** link inside its
  command row.
- **Per-user view.** `/search?user=<username>` lists that user's SSH, exec and kubectl activity on
  every system.
- **kubectl command focus.** `/search?cmd=<request_id>` shows the one command that request
  belongs to, expanded, or "Command not found". An exec recording's session page links to its
  command, and dashboard feed rows open it.
- **kubectl commands in search.** Filters: `system`, `user`, `window`/`from`/`to`, `severity`,
  `max_severity`, `has_findings`, `category=kube-api`, `rule_ids`, `sort=newest|risk`, and text
  over request URL paths (query strings excluded) and `Kubectl-Command`. `discovery=1` shows
  discovery-only commands. Each command row lists its first 200 requests.
- **Recent-activity feed** on the dashboard: the newest 15 items of every kind, discovery-only
  commands hidden.
- **Cross-links.** "Search this system" and "kubectl commands in search" on the system page, a
  ⌕ link beside usernames there, and links from the systems list into search.
- **Event-kind registry.** `web/kinds.py` (`EventKind`, `KINDS`, the six `TYPE_GROUPS`,
  `resolve_kinds`) gives future event families a slot without changing the merge, the URL scheme or
  the cursor format.
- **New modules.** `store/timeline.py` (the query engine: `UnifiedQuery`, `Cursor`,
  `build_sources`, `run_timeline`, keyset paging with a frontier rule), `web/params.py`
  (`parse_unified_query`, `search_url`, cursor encoding), `web/kinds.py`, and the templates
  `_macros.html`, `_rows.html` and `_search_error.html`.
- **Four indexes** (`CREATE INDEX IF NOT EXISTS`, no `user_version` bump): `idx_api_req_cmd`
  (command key, time, id), `idx_api_req_user_time`, `idx_api_req_userid_time` and
  `idx_sessions_at` (recording start). The first boot after upgrade builds them. A deterministic
  SQL function `gc_is_discovery(method, url)` is registered on each connection so SQL and Python
  share one discovery test.
- **Tests.** `test_timeline.py`, `test_search_params.py`, `test_query_plans.py` and
  `tests/fixtures/timeline.py`; the secret-hygiene suite now seeds every search type, user, `cmd`
  and cursor walk. The full suite is 1,379 tests.
- **kubectl activity.** The stock Gateway's per-request API audit lines are stored as
  allowlisted metadata (method, sanitized URL, status, user, outcome, and the `User-Agent`,
  `Kubectl-Command` and `Kubectl-Session` headers), deduplicated by `request_id`. Requests are
  grouped per user and cluster into **activity sessions** (split by gap and max window), and
  within a session into **commands** by `Kubectl-Session` (falling back to the connection).
  Exec/attach recordings link to their command by `request_id`, never by `conn_id`. Grouping
  is computed on view; nothing is cached. API-discovery `GET`s are hidden by default.
- **Activity UI.** The systems list now includes clusters with only API activity and shows a
  kubectl request count. The system page has a paged kubectl activity table (7 days per page).
  New `GET /systems/{slug}/activity` page shows one activity session's commands, requests,
  findings and recording links. The dashboard has a kubectl API requests card (total, flagged,
  severity breakdown).
- **API findings.** Six built-in rules run on each stored request's method and normalized
  path, category `kube-api`: `kube-delete` (high), `kube-secrets` (high), `kube-evict` (high),
  `kube-cordon` (medium), `kube-exec` (medium) and `kube-node-proxy-exec` (high). Findings
  store the rule, severity and label only, never the URL. They are not produced when
  `DETECTION_ENABLED=false`.
- **`KUBECTL_ACTIVITY_GAP_SECONDS`** (default `900`) and **`KUBECTL_ACTIVITY_MAX_SECONDS`**
  (default `14400`): the activity-session split gap and the hard cap on one session's span.
  Startup fails if `0 < gap <= max` does not hold. Both are listed in `.env.example`.
- **Schema**: new `connections`, `api_requests` and `api_findings` tables, plus a
  `sessions.request_id` column linking exec recordings to their API audit line.
- **`SESSION_MAX_IDLE_SECONDS`** (default `3600`): idle backstop. After this much silence a
  data-bearing recording is sealed reopenably (Gateway died without its final flush), and a
  session that **started but never recorded a valid chunk** is marked `error` so it no longer
  sits "in progress" forever (a genuinely-late chunk still recovers it). Must exceed the
  Gateway's flush interval; also bounds the plaintext-at-rest window under encryption.
- **`"session finished"` end signal** (`is_final` on the recording chunk) — the Gateway's
  reliable end-of-session marker, used to seal immediately.
- **Envelope wire format accepted by `classify`.** Self-describing records with a `type` of
  `session_start`, `recording_chunk` or `session_end` and no `logger` are mapped onto the
  existing start, chunk and end events. Retained for compatibility with the former
  Gateway-fork recording sink; legacy log-line classification is unchanged and the envelope
  path is not being extended.

### Fixed

- **A late chunk after a restart could overwrite a sealed recording (data loss).** The set of
  sealed `conn_id` values lived only in memory (and was cleared after 10,000 entries), so after a
  restart, or after eviction, a chunk for an already sealed recording found no buffer and was
  treated as a new connection. Its fragment replaced the sealed `.cast`. The seal mode is now
  persisted on the session row (`sessions.sealed_terminal`, added by an idempotent column
  migration with no `user_version` bump), and the row decides what a chunk with no buffer may do:
  - Sealed terminally (the `session finished` flush or a close event), or sealed before the
    column existed (`NULL`, treated as terminal): the chunk is ignored and the `.cast` is
    byte-identical afterward.
  - Sealed reopenably (idle backstop): the recording is reopened, appended to and re-sealed.
  - Orphan `.cast` with no row, or a sealed row whose `.cast` is missing: the chunk is ignored
    and a warning is logged (`assembler.orphan_cast_skip`, `assembler.sealed_cast_missing`). Nothing
    is written.
  - An `error` row that has a `.cast` now reopens on a late chunk; it used to stay stuck. A failed
    connection (`error`, no `.cast`) still recovers as before.
  - Provisional rows with a `.cast` are adopted as the baseline (`assembler.adopt`).
- Sessions that outlived the old 120 s idle window (or whose recording shipped late) were
  finalized prematurely as `error` and their eventual recording discarded. Recordings now
  seal on the real end signal and recombine correctly by `conn_id`.
- A session whose recording chunks were all dropped (e.g. journald `LineMax` splitting) no
  longer stays "in progress" indefinitely: the backstop marks it `error`, and it recovers if
  valid data arrives late.

### Security

- **CSV formula guard.** Any text cell in a search export that starts with `=`, `+`, `-`, `@`,
  tab or carriage return is written with a leading `'`, because usernames and `Kubectl-Command`
  values are client-influenced.
- **Search input never reaches SQL or a response unchecked.** The search cursor is unsigned,
  length-capped, strictly validated and used only as bound parameters. A `4xx` never echoes the
  submitted value. Every new `/search` link is built by one function (`search_url`). The
  secret-hygiene suite now asserts that no planted secret, `command=` value or full `User-Agent`
  appears in any search page or export.
- **Request-header allowlist.** Only `User-Agent`, `Kubectl-Command` and `Kubectl-Session` are
  read from a request, matched case-insensitively, first value only, capped at 256 characters.
  `Authorization` (present on every request), cookies, all other request headers, all response
  headers, `remote_addr` and panic content are never stored or logged, and raw audit lines are
  never logged.
- **URL normalization and query allowlist.** Every stored URL is normalized first (fragment
  dropped, path unquoted once, repeated `/` collapsed, trailing `/` stripped). Only allowlisted
  query keys survive, and only with a value that passes validation (at most 256 characters, no
  `;`, no control characters). Every other key is dropped, not kept blank. Detection matches on
  the same normalized path, so encoded variants such as `%73ecrets` still produce findings.
- **Exec/attach parameters are validated.** `…/pods/<name>/exec` and `…/attach` keep only
  `container`, `stdin`, `stdout`, `stderr` and `tty`. Flags must be `true`, `false`, `1` or
  `0`, and `container` must be a valid name. `command=`, which can hold secrets, is always
  dropped.
- **Proxy paths are truncated.** Everything after a `/proxy` segment, and the whole query, is
  dropped because it is forwarded to a backend. `/nodes/<n>/proxy/exec|run|attach` keeps that
  one segment so `kube-node-proxy-exec` still matches.
- **Fail-closed on encoded `?` and `#`.** If the unquoted path contains `?` or `#` (from `%3F`
  or `%23`), the path is cut there and the query is discarded. A path that is still
  percent-encoded after one decode also has its query discarded.
- **Atomic request and findings insert.** A request row and its findings are written in one
  transaction, so a redelivered line cannot leave a request without its findings or duplicate
  findings.
- **Retention purges on ingest time too.** An API request is purged when either its
  Gateway-supplied `requested_at` or the server-assigned insert time is past the cutoff, so a
  forged future timestamp cannot keep a row forever. Connections are purged on server time only.
- **The migration keeps rows with on-disk recordings.** A start-only-looking `sessions` row is
  never moved if its `.cast` or sidecar file exists, which would otherwise orphan a
  secret-grade file. Rows with an unsafe `conn_id` are skipped without building a path.
- With encryption enabled, in-progress recordings are **plaintext at rest** until sealed
  (accepted tradeoff for durability + live playback). Lower `SESSION_MAX_IDLE_SECONDS` to
  shorten that window for abandoned sessions. See ARCHITECTURE.md → Encryption at Rest.

### Notes

- **Known limitation, unchanged:** a chunk redelivered to a recording that was reopened is
  appended after the existing document rather than deduplicated, so a reopen can duplicate events.
- **Known limitation, not fixed here:** if the process dies after a recording is encrypted at seal
  but before its row is marked sealed, the row stays `provisional` with an encrypted `.cast`. The
  startup sweep and the adopt path read it as plaintext and fail.
- Dashboard flagged figures above 5,000 commands are lower bounds, shown as `5000+`.
- `idx_api_req_session` and `idx_api_req_conn` are now likely redundant with the new indexes.
  They are kept.

### Documentation

- README, ARCHITECTURE.md, SEARCH_AND_DETECTION.md and TESTING.md describe the unified search,
  the dashboard and systems changes, the persisted seal mode, and the new test modules. The README
  has a new Unified Search section and an upgrade note for 0.4.0.
- Documented a journald ingestion pitfall: `LineMax` (default 48 KB) splits large asciicast
  lines and rate limiting drops them, so high-volume / full-screen-TUI sessions (`btop`,
  `top`, `watch`) silently fail to record. INGESTION_RECIPES.md §2.1 now has a caveat + fix
  (raise `LineMax`/relax rate limiting, or use the §2.4 file-tail transport), §2.4 is
  flagged as the sturdiest transport for chunky sessions, and the README troubleshooting
  guide has a matching callout.
- README now has Ingestion, Web UI, Search and Detection, Encryption at Rest and Retention
  sections, a startup-failure troubleshooting entry, and a note that variables set in the
  `environment:` block of `docker-compose.yml` take precedence over `.env`. The configuration
  table lists the placeholder defaults for `INGEST_TOKEN` and `UI_AUTH_PASSWORD`.

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

[Unreleased]: https://github.com/Twingate-Solutions/gatorcast/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Twingate-Solutions/gatorcast/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Twingate-Solutions/gatorcast/releases/tag/v0.3.0
[0.2.0]: https://github.com/Twingate-Solutions/gatorcast/releases/tag/v0.2.0
[0.1.0]: https://github.com/Twingate-Solutions/gatorcast/releases/tag/v0.1.0
