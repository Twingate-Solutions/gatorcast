# Gatorcast — Architecture & Operations

Design and operational reference for Gatorcast: how data flows through the
service, how recordings are protected at rest, the data model, the background
jobs, the security model, and how retention works. For setup and day-to-day use,
see the [README](README.md); for forwarding Gateway logs in, see
[INGESTION_RECIPES.md](INGESTION_RECIPES.md); for search and detection, see
[SEARCH_AND_DETECTION.md](SEARCH_AND_DETECTION.md).

---

## Architecture

```text
  Twingate Gateway host (k8s pod OR SSH/VM)
  emits gateway / gateway.audit JSON (asciicast v2 chunks + API-request audits)
  to stdout/stderr
        │  push (operator's choice of shipper)
        │   • rsyslog omhttp  → HTTP POST /ingest
        │   • Docker syslog driver / rsyslog omfwd → syslog TCP
        │   • curl (testing)  → HTTP POST /ingest
        ▼
┌──────────────────────── Gatorcast (single FastAPI container) ────────────────────────────┐
│  Ingest front doors (ingest/)                                                            │
│    • POST /ingest        (NDJSON / JSON over HTTP, bearer-token auth, returns 204)       │
│    • syslog TCP listener (octet-counted or newline framing; strips <PRI> header)         │
│        │  raw line → normalize (syslog / Docker {"log":…} unwrap) → JSON object          │
│        ▼  in-memory asyncio.Queue → one consumer task                                    │
│  Classify & filter (pipeline/classify.py)                                                │
│    • logger=="gateway.audit" AND asciicast!=null → recording chunk                       │
│      (message=="session finished" → final chunk / end signal)                            │
│    • gateway.audit, no asciicast, "API request completed"/"failed"                       │
│      → API request (allowlisted metadata; URL via pipeline/urlnorm.py)                   │
│    • logger=="gateway" "Authenticated connection" → pending connection + target          │
│    • (close event if present) → finalize signal                                          │
│    • envelope-format records ("type", no "logger") → same events (legacy, kept)          │
│        ▼                                                                                 │
│  Per-conn_id assembler (pipeline/assembler.py, file-first) + connection lifecycle        │
│    • pending → recording on first chunk; pending → api on first audit;                   │
│        pending → visible error after SESSION_MAX_IDLE_SECONDS with neither               │
│    • each chunk → reassemble (header once, events in seq order) →                        │
│        write PLAINTEXT .cast to disk + scan live (durable per append)                    │
│    • seal (sidecar + final scan, encrypt if enabled → complete): on                      │
│        "session finished"/close (terminal) OR idle backstop (reopenable)                 │
│    • API request → dedup by request_id → row + API findings, one transaction             │
│        ▼                                                                                 │
│  Storage (store/)                                                                        │
│    • SQLite (WAL) /data/gatorcast.db: sessions, findings, connections,                   │
│        api_requests, api_findings                                                        │
│    • Volume /data/casts: <conn_id>.cast (plaintext while recording, encrypted at         │
│        seal) and <conn_id>.txt.enc (search sidecar, written at seal)                     │
│  Scheduler (APScheduler): idle_finalize every 5–30 s · retention_purge every 24 h        │
│  Startup: migrations → startup sweep → background backfill                               │
│        ▲                                                                                 │
│  Web UI (web/: FastAPI + Jinja2 + HTMX + Alpine, vendored asciinema player, Basic auth)  │
│    /dashboard · /search (+ /search/export.csv) · figures link to search                  │
│    /search: one keyset-paged timeline (store/timeline.py, web/params.py, web/kinds.py)   │
│    /systems → /systems/{addr} → /sessions/{id} → /sessions/{id}/cast                     │
│                              └→ /systems/{addr}/activity (kubectl, no player)            │
│    (activity grouping computed per page view by pipeline/activity.py)                    │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

**Key points:**

- Single FastAPI process: ingestion, assembly, storage, scheduler, and UI all in one container.
- State: SQLite (WAL mode) for metadata; a named Docker volume for `.cast` files and their search sidecars (`.txt.enc`).
- APScheduler drives two background jobs: the idle backstop sweep (seals data-bearing sessions reopenably; expires pending connections that delivered neither chunks nor API audits to a visible `error` session) and the retention purge, which runs every 24 hours. See [Background Jobs](#background-jobs).
- Two wire formats are classified. The stock Gateway's log lines (`logger` field) are the supported path. Envelope-format records from the retired Gateway fork (a `type` field and no `logger`) are still mapped onto the same events for compatibility; that code is kept but not extended.
- kubectl activity: the Gateway's API-request audits are stored as allowlisted metadata (`store/activity.py`), their URLs normalized and sanitized by `pipeline/urlnorm.py` and `pipeline/classify.py`, and grouped per user and cluster into activity sessions and commands on each page view by `pipeline/activity.py`. Nothing is cached. See the [README](README.md#kubectl-activity).
- Search: `/search` is one query engine over every event kind (`store/timeline.py`), not a recordings-only filter. Recordings, failed connections and kubectl commands are merged into one keyset-paged timeline. See [Unified search engine](#unified-search-engine).
- Push-based: Gatorcast exposes endpoints and waits. It never reaches back into the Gateway, Docker, or Kubernetes.
- All frontend assets (HTMX, Alpine.js, asciinema player, CSS) are vendored under `web/static/`. No CDN or external JS at runtime.

### Data flow

1. **Front door.** `POST /ingest` takes a bearer token. An `application/json` body is parsed as one object or an array; any other content type is split into lines. The syslog TCP listener accepts RFC 6587 octet-counted frames and newline-delimited lines, auto-detected per message. Both paths hand each raw line to `normalize`.
2. **Normalize** (`ingest/normalize.py`). A syslog `<PRI>` header is stripped by parsing from the first `{`. A collector wrapper such as Docker's `{"log": "...", "stream": "stdout"}` is unwrapped. A line that does not reduce to a JSON object is dropped with a `normalize.drop` warning that logs the length only. A length near 49152 means journald's `LineMax` split a large chunk; see the [README troubleshooting](README.md#troubleshooting).
3. **Queue.** Accepted objects go onto one in-memory, unbounded `asyncio.Queue`. `/ingest` returns `204` whether or not lines were dropped. Objects still queued when the process dies are lost.
4. **Classify** (`pipeline/classify.py`). One consumer task drains the queue and turns each object into an event or drops it:

   | Input | Event |
   | --- | --- |
   | `gateway.audit` with a string `asciicast` and an integer `asciicast_sequence_num` | `RecordingChunk` (`is_final` when `message == "session finished"`; carries `request_id` on k8s exec/attach lines) |
   | `gateway.audit`, no `asciicast`, `message` of `API request completed` or `API request failed` | `ApiRequest` (allowlisted fields only) |
   | `gateway`, `Authenticated connection` | `SessionStart` (user, target `resource_address`) |
   | `gateway`, `Connection closed` or `Closed connection` | `SessionEnd` |
   | Anything else | Dropped |

   `conn_id` names the `.cast` file, so it must `fullmatch` `[A-Za-z0-9_.-]{1,128}`; anything else is dropped here. An exception in the consumer is logged by type only and never stops it.
5. **Assemble** (`pipeline/assembler.py`). The assembler demuxes by `conn_id` under one lock, so every state transition is serialized with chunk handling. See the lifecycle below.
6. **Store.** Metadata goes to SQLite through `SessionRepository`, `ActivityStore` and `SearchStore`; the UI reads it back through those and the `store/timeline.py` query engine. Recording bytes go to the volume through `CastStore`. Recording content is never written to SQLite or to application logs.

### Session lifecycle: provisional → complete (file-first)

Gatorcast is **file-first**: as each chunk arrives it is reassembled (the header kept once, event lines concatenated in `asciicast_sequence_num` order — the Gateway repeats the header in every chunk) and the growing document is written to `<conn_id>.cast` **as plaintext on every append**. So the recording is durable on disk from the first chunk, playable while in progress, and scanned for findings live. A connection starts as a hidden **pending connection** (the Gateway's `Authenticated connection` line creates only that); its first recording chunk creates the session row, and the session is **provisional** while it is still recording. A connection that only makes API requests never becomes a session.

The recording is **sealed** to **complete** in one of two ways. Sealing writes the search sidecar, runs a final detection pass over the plaintext, encrypts the `.cast` (if enabled), and marks the row `complete`:

- **Terminal seal**, on the Gateway's final flush (`message == "session finished"`, emitted by the recorder's `Stop()`) or a connection-close event. This is the normal, immediate path: the final flush is appended and scanned first, then the recording is sealed the moment that line is processed. Late or redelivered chunks for a terminally sealed `conn_id` are ignored, including after a restart (see [Sealed sessions and late chunks](#sealed-sessions-and-late-chunks)).
- **Reopenable seal**, on the idle backstop: an in-progress recording silent for `SESSION_MAX_IDLE_SECONDS` (default 3600 s) is sealed anyway, assuming the Gateway died without its final flush. If a later chunk *does* arrive for that `conn_id`, the sealed file is decrypted back to plaintext, appended to, and re-sealed — so a long interactive pause never loses or splits the recording.

`IDLE_TIMEOUT_SECONDS` (default 120 s) is not a finalize trigger — it only sets the idle-sweep cadence (`max(5, min(IDLE_TIMEOUT_SECONDS, 30))` seconds) and the startup-sweep cutoff. A pending connection that delivers neither a recording chunk nor an API audit within `SESSION_MAX_IDLE_SECONDS` becomes a visible `error` session at the backstop; a genuinely-late chunk reverts it and records, and a late API audit removes the error row. `SESSION_MAX_IDLE_SECONDS` must therefore exceed the Gateway's flush interval, since a quiet-but-active session is legitimately chunkless until its first flush.

On restart, Gatorcast re-adopts each provisional row from its on-disk plaintext `.cast` as an in-progress session (so continuation chunks keep appending and it seals normally) with a fresh idle clock; a provisional row with no `.cast` older than the idle timeout is an abandoned start and is swept away. A clean shutdown does not seal in-progress sessions. They stay provisional and are re-adopted the same way on the next start.

**Encryption note:** because recordings are written plaintext while in progress and only encrypted at seal, an in-progress recording is plaintext at rest until it seals (see [Encryption at Rest](#encryption-at-rest)).

#### Connection and session states

Two tables track a connection. `connections.state` is the hidden lifecycle. `sessions.status` is what the UI shows.

| `connections.state` | Meaning | Moves to |
| --- | --- | --- |
| `pending` | `Authenticated connection` seen. No session row. | `recording` on the first chunk; `api` on the first API audit; `error` when `last_seen_at` is older than `SESSION_MAX_IDLE_SECONDS` |
| `recording` | A chunk arrived and a `sessions` row exists. `has_api` is also set if audits arrive on the same connection. | Stays |
| `api` | API audits only. No session row, ever. Never expired. | `recording` if a chunk arrives later |
| `error` | Expired while pending. A visible `error` session row was created. | `recording` on a late chunk (the row reverts to `provisional`); `api` on a late API audit (the phantom row is deleted) |

| `sessions.status` | UI label | Meaning |
| --- | --- | --- |
| `provisional` | in progress | Chunks are arriving. The plaintext `.cast` is playable and scanned live. |
| `complete` | complete | Sealed. The `.cast` is encrypted when encryption is enabled. |
| `error` | error | Either a connection that never delivered a chunk or audit (backstop), or a sealed document with no valid asciicast v2 header (the raw `.cast` is kept for inspection). |

A chunk that arrives before its start line creates a minimal `recording` connection, and a start line arriving later never leaves it `pending`. The expiry of pending connections uses SQLite wall-clock time (`last_seen_at`), so it holds across restarts. The silence timer for in-progress recordings uses a monotonic clock in memory.

#### Sealed sessions and late chunks

The seal mode is stored on the session row in `sessions.sealed_terminal`: `1` for a terminal seal, `0` for a reopenable (idle backstop) seal, and `NULL` for an unsealed row or one sealed before the column existed. An in-memory map of sealed `conn_id` values is only a cache. It holds at most 10,000 entries, is cleared when it overflows, and is empty after a restart.

When a chunk arrives for a `conn_id` with no in-memory buffer and no cache entry, the session row decides what it may do (one primary-key lookup per session, not per chunk). A chunk never reaches the "new connection" path for a row that already exists, so it can never replace a sealed `.cast`:

| Row | `.cast` on disk | Action |
| --- | --- | --- |
| None | None | Promote: a new connection's first chunk |
| None | Non-empty | Ignore with a warning (`assembler.orphan_cast_skip`). An orphan file is never overwritten. |
| `provisional` | Non-empty | Adopt the file as the baseline and keep appending (`assembler.adopt`) |
| `provisional` | None | Promote |
| `error`, no `cast_path` (a failed connection) | None | Promote, which recovers it through `revert_error_to_provisional` |
| `complete`, or `error` with a `cast_path`, sealed reopenably (`0`) | Present | Reopen: decrypt, append, re-seal |
| `complete`, or `error` with a `cast_path`, sealed terminally (`1`) or `NULL` | Present | Ignore. The file is left byte-identical. `NULL` is treated as terminal because the likely cause is a shipper redelivering its buffer, and reopening would append duplicate events. |
| `complete`, or `error` with a `cast_path` | Missing | Ignore with a warning (`assembler.sealed_cast_missing`). Nothing is written. |
| Any other status | Any | Ignore with a warning (`assembler.unknown_status_skip`) |

A sealed `error` row that has a `.cast` (a document with no valid header) now reopens on a late chunk when it was sealed reopenably. Before this fix such a row stayed stuck.

#### Reassembly

Each Gateway flush is self-contained: the recorder prepends the asciicast header to every flush and resets its event buffer, so a chunk is the header plus only the events since the previous flush. `reassemble_asciicast` splits every chunk into lines and classifies each by JSON shape. The first object line is the header and is kept once. Every array line is an event and is kept. Blank lines, non-JSON fragments and scalars are dropped. Raw string concatenation would repeat the header mid-stream and fuse chunk boundaries, since chunks carry no trailing newline.

Chunks are held per `conn_id` in a map keyed by `asciicast_sequence_num` and reassembled in ascending order on every append, so arrival order does not matter and a redelivered `seq` overwrites itself. Two limits follow from that design:

- The per-`seq` map exists only while the session is in memory. After a restart or a reopen, the prior document is held as a single baseline, and a redelivered chunk is appended after it rather than deduplicated.
- Event offsets are absolute seconds, so concatenation preserves playback timing.

After each reassembly the session row is refreshed from the document: dimensions from the header, the header `user` as `shell_user` (secondary detail, never identity), `started_at` from the header timestamp only when the row has none, `duration_seconds` as the largest event offset, `ended_at` from the latest chunk timestamp, `chunk_count` and `size_bytes`. Identity is the envelope `user.username`; the system is the start line's `resource_address`. The `request_id` of the first k8s exec/attach chunk is stored on the session and is the only link to its API audit line.

---

## Data Model

SQLite holds metadata only. Recording payloads live on the volume and are never stored in the database. The connection runs in WAL mode with `synchronous=NORMAL` and `foreign_keys=ON`. All SQL is raw and parameterized (`aiosqlite`, no ORM).

### On the volume (`DATA_DIR`, default `/data`)

| Path | Contents |
| --- | --- |
| `gatorcast.db` (plus `-wal` and `-shm`) | The SQLite database |
| `casts/<conn_id>.cast` | The recording. Plaintext while in progress, encrypted at seal when encryption is on. |
| `casts/<conn_id>.txt.enc` | The ANSI-stripped plaintext sidecar and offset index for content search, written at seal |

Files are written atomically (temp file, then replace), as raw bytes so a Windows host never rewrites newlines.

### Tables

| Table | Key | Holds |
| --- | --- | --- |
| `sessions` | `conn_id` | One row per recording, visible in the UI: `username` (envelope identity), `resource_address` (the system), `shell_user`, `started_at`, `ended_at`, `duration_seconds`, `width`, `height`, `chunk_count`, `size_bytes`, `cast_path`, `status` (`provisional`, `complete`, `error`), `finding_count` and `max_severity` (denormalized from `findings`), `request_id` (k8s exec/attach only), `sealed_terminal` (seal mode, see [Sealed sessions and late chunks](#sealed-sessions-and-late-chunks)), `created_at`, `updated_at` |
| `findings` | `id` | Recording findings: `conn_id`, `rule_id`, `category`, `severity`, `label`, `offset_seconds`, `created_at`. No matched text. Deleted explicitly with the session; there is no foreign key. |
| `connections` | `conn_id` | Hidden per-connection state: `user_id`, `username`, `resource_address`, `started_at`, `state` (`pending`, `recording`, `api`, `error`), `has_api`, `created_at`, `last_seen_at` |
| `api_requests` | `request_id` | Allowlisted kubectl API metadata, deduplicated by `request_id`: `conn_id`, `resource_address` (joined from the connection), `user_key` (user id, else username), `user_id`, `username`, `requested_at`, `method`, `url` (sanitized), `status_code`, `outcome` (`completed` or `failed`), `kubectl_command`, `kubectl_session`, `user_agent`, `created_at` |
| `api_findings` | `id` | API rule findings: `request_id` (foreign key, `ON DELETE CASCADE`), `rule_id`, `category` (`kube-api`), `severity`, `label`, `created_at` |

Indexes cover the lookups the UI and retention use (20 in total): `sessions` on `resource_address`, `started_at`, `status`, `request_id`, and the recording start expression (`idx_sessions_at`); `findings` on `conn_id`, `category` and `severity`; `connections` on `(state, last_seen_at)` and `created_at`; `api_requests` on system and time, system and user and time, `conn_id`, `kubectl_session` and `requested_at`, plus three added for search; `api_findings` on `request_id` and `severity`. The four search indexes are:

| Index | On | Serves |
| --- | --- | --- |
| `idx_api_req_cmd` | the command key expression, `requested_at`, `request_id` | Grouping requests into a command: start-row probes, aggregates and the expanded request list |
| `idx_api_req_user_time` | `username`, `requested_at`, `request_id` | The `username` arm of the `user` filter, in time order |
| `idx_api_req_userid_time` | `user_id`, `requested_at`, `request_id` | The `user_id` arm of the `user` filter, in time order |
| `idx_sessions_at` | the recording start expression, `conn_id` | Newest-first keyset paging over `sessions` |

The two expression indexes reproduce the SQL fragments in `db.py` exactly (`CMD_KEY_SQL`, `SESSION_AT_SQL`), which the query engine imports, so SQLite can match them. The command key is `s:<Kubectl-Session>` when the header is non-empty, else `c:<conn_id>`. The recording start is `strftime('%Y-%m-%dT%H:%M:%fZ', COALESCE(started_at, created_at))`. `idx_api_req_session` and `idx_api_req_conn` are probably redundant now; they are kept.

Timestamps use three stored formats. `created_at`, `updated_at` and `last_seen_at` are SQLite UTC (`YYYY-MM-DD HH:MM:SS`). `sessions.started_at` is the Gateway's start timestamp or the asciicast header time, in ISO 8601. `api_requests.requested_at` is always `YYYY-MM-DDTHH:MM:SS.mmmZ`, and every bound compared against it is normalized to that format first. Search compares recordings and commands in one format by rendering the recording start through `SESSION_AT_SQL` into the `requested_at` shape.

A SQL function, `gc_is_discovery(method, url)`, is registered on every connection opened through `db.connect()`. It calls `pipeline.activity.is_discovery`, so SQL filters and the Python grouping share one discovery test. It is used in queries only, never in the schema, so the database stays readable by any SQLite client.

### Schema evolution

The schema is created with `CREATE TABLE IF NOT EXISTS` on every boot. Columns added to `sessions` after its first release (`finding_count`, `max_severity`, `request_id`, `sealed_terminal`) are added with a guarded `ALTER`. The `sessions` indexes are created afterward, and only for columns that exist (`idx_sessions_at` needs `started_at`). The search indexes are plain `CREATE INDEX IF NOT EXISTS` and need no data migration, so `PRAGMA user_version` stays at 1; the first boot after an upgrade builds them in one pass per table. `PRAGMA user_version` gates one-time data migrations. Version 1 moves start-only `sessions` rows (no chunks, no `.cast` path, no size, status `provisional` or `error`) into `connections` as `error`, in one transaction. It skips any row whose `.cast` or `.txt.enc` is on disk, so a crash between a file write and its metadata update never orphans a recording.

---

## Unified search engine

`/search`, the CSV export and the dashboard's recent-activity feed all run through one engine. It answers "what happened, across every kind of event" with a single keyset-paged timeline. For the user-facing parameters, see the [README](README.md#unified-search); for rules and content-search internals, see [SEARCH_AND_DETECTION.md](SEARCH_AND_DETECTION.md).

### Layering

| Module | Role |
| --- | --- |
| `store/timeline.py` | The engine. Holds `UnifiedQuery` (validated parameters), `Cursor`, the kind, source and sort constants, `session_kind(row)`, the two sources, `build_sources`, `run_timeline` and `TimelinePage`. It reads no request. |
| `web/params.py` | `parse_unified_query(request)` returns a `ParsedSearch` (the `UnifiedQuery`, its resolved kinds and exclusions, the decoded cursor and the page size). It also holds the legacy-name aliases, `encode_cursor` / `decode_cursor`, and `search_url(**params)`, the only way the UI builds a `/search` link. |
| `web/kinds.py` | The event-kind registry: `EventKind`, `KINDS` (`ssh`, `exec`, `failed`, `kubectl`), the six `TYPE_GROUPS` (`any`, `recordings`, `ssh`, `exec`, `failed`, `kubectl`), `TYPE_LABELS`, and `resolve_kinds(query)`. |

The dependency runs one way: `web/params.py` and `web/kinds.py` import from `store/timeline.py`. The store never imports `gatorcast.web`, and a test enforces it. The route calls `resolve_kinds`, then passes the kinds and exclusions into `run_timeline`.

### Kinds

A kind is data: a key, a label, a badge class, the source that serves it, the row template macro, and the filters and sorts it can evaluate. Adding an event family means one new kind, one new source and one row macro; the merge, the URL scheme and the cursor format do not change.

A `sessions` row's kind is derived when it is queried, never stored, and the SQL predicate (`FAILED_SQL` in `db.py`) and `session_kind()` use the same definition, evaluated in this order:

| Kind | Predicate |
| --- | --- |
| `failed` | `status = 'error'` and `chunk_count` is zero or NULL and `cast_path` is NULL (the pending-backstop row for a connection that delivered neither chunks nor audits) |
| `exec` | `request_id` is set, and not `failed` |
| `ssh` | `request_id` is NULL, and not `failed` |

`kubectl` comes from the second source, not from `sessions`.

`resolve_kinds` turns a `UnifiedQuery` into the kinds to query plus an exclusion map. A kind that cannot evaluate an active filter (or the chosen sort) is excluded, and the page shows a notice naming the filter. If every selected kind is excluded the result is empty and the response is still `200`.

### Sources and merge

Each source implements `page(query, kinds, after, limit)` and returns up to `limit + 1` items in its own order, whether it is exhausted, and a frontier when its work budget ran out.

- **Sessions source** serves `ssh`, `exec` and `failed`. Without content search it is one indexed query. With `q` it reads the page's candidates in batches of 100, reads and matches their sidecars off the event loop, and stops at `SEARCH_REGEX_MAX_CANDIDATES` sidecars per page.
- **API commands source** serves `kubectl`. A command is the set of `api_requests` rows that share a resource address, a user key and the command key, and its id is the `request_id` of its earliest row (its *start row*). Two modes find start rows. *Scan mode* walks `api_requests` newest first by keyset, examining at most 20,000 rows per page, and keeps the rows that are their command's start row and pass the command-level filters. *Flagged mode* starts from `api_findings` (small, since only rule hits are stored), so cost scales with the number of flagged commands rather than traffic, capped at 5,000 commands. `sort=risk` without a finding filter runs flagged commands first, then scan mode for unflagged ones; the cursor records the phase. A command belongs to the window that contains its first request, so it is never split across a page or a window edge.

`run_timeline` merges the sources:

1. Call each selected source for one page.
2. Set a bound per source that is not exhausted: the merge key of its last returned item, or its frontier if its budget ran out.
3. Merge by sort key, descending, and emit only items at or above every bound. Take the first `page_size`.
4. Set each source's next position. If everything it returned was emitted and it is exhausted, the position is `done`. If everything was emitted but its budget ran out, the position is its frontier, so the scanned stretch is not scanned again. Otherwise the position is its last emitted item, or unchanged when none of its items were reached.
5. Hydrate the page: findings for the page's recordings in one query, and for each command its aggregates, findings, linked recordings and first 200 requests. Aggregates cover all of a command's rows, so the count, end time and severity are right even when only 200 requests are listed.

No item is emitted while another source could still produce one that sorts before it, and none is skipped or repeated across pages. When a source hits its budget the page can be short or empty, and the next link reads **Continue scanning ›**. Ties break by a fixed source rank (`sessions` 0, `api_commands` 1), then by id.

### Cursor

The cursor is base64url JSON, at most 2,048 characters, and carries a version, the sort, the sorted kinds queried, and one position per source (or `done`). It must match the request's sort and kinds, or the request is a `400`. It is unsigned on purpose: it selects which rows an already authenticated user sees next, and every value in it reaches SQL only as a bound parameter. Decoding rejects unknown fields, malformed timestamps, ids that fail the same patterns as ingest, out-of-range ranks and durations, and a position for a source the search does not use.

### Budgets

All are module constants except the sidecar count, which is a setting.

| Limit | Value | Bounds |
| --- | --- | --- |
| Page size | 50 default (`SEARCH_PAGE_SIZE`), 200 maximum | Items per page |
| `_API_SCAN_BUDGET` | 20,000 | API request rows examined per page in scan mode |
| `SEARCH_REGEX_MAX_CANDIDATES` | 2,000 | Sidecars read per page of a content search, and per CSV export |
| `_FLAGGED_CMD_CAP` | 5,000 | Flagged commands considered per query, and per dashboard figure |
| `_CMD_MAX_REQUESTS` | 200 | Requests listed per expanded command |
| Dashboard feed | 15 | Items in the recent-activity feed |
| CSV export | 10,000 | Rows per export |

The index choice for each hot query is steered in SQL, and `tests/test_query_plans.py` pins it by asserting the index names that appear in `EXPLAIN QUERY PLAN`, not the plan text, so a different SQLite version cannot break the test over wording.

### Dashboard and systems list

`SearchStore.dashboard_stats` windows session figures on the recording start (the same expression search uses) and counts flagged kubectl commands, not requests: `api_flagged_commands`, `api_commands_by_severity` and `api_flagged_truncated`. `api_requests_total` counts requests and is the one figure that is not the length of its linked list. Over the 5,000-command cap the flagged figures are lower bounds.

`SessionRepository.list_systems` returns a `SystemSummary` per `resource_address` with `session_count`, `ssh_count`, `exec_count`, `api_request_count`, `last_session_at` and `last_api_at` (both in the `requested_at` format), and the findings summary. `last_seen` is the newer of the two timestamps and drives the sort. The SSH badge needs `ssh_count > 0`, and the Kubernetes badge needs `exec_count > 0` or API requests, so a start-only `error` row earns neither.

---

## Encryption at Rest

Gatorcast can encrypt the sensitive bulk of the data — the `.cast` recordings — on the volume. Recordings capture full on-screen content, including typed tokens and passwords, so encrypting them protects against a stolen disk, a leaked backup, or a volume snapshot.

**What is and isn't protected:**

| Scenario | Protected? |
| --- | --- |
| Stolen disk / laptop / leaked backup / volume snapshot | **Yes for sealed recordings** — completed `.cast` content is ciphertext. In-progress recordings are plaintext until they seal (see note below). |
| Another process reading the live `/data` volume | **Yes for sealed recordings** (ciphertext); **no for in-progress recordings** (plaintext until sealed) and **no for metadata** (the DB is plaintext). |
| Compromise of the running app process | **No** — the key is in memory so the app can decrypt for replay. Inherent. |
| Metadata (usernames, system addresses, shell user) | **No** — the metadata database stays plaintext. |

This is the honest meaning of "at rest" for a service that must decrypt to replay. Encrypting the metadata DB would require SQLCipher, which this project deliberately avoids.

**How it works:** `.cast` files are encrypted with AES-256-GCM (per-file random nonce, the connection id bound in as additional authenticated data). The key on disk is HKDF-derived from `GATORCAST_MASTER_KEY` — the raw env value is never used directly. The metadata database is unchanged. The search/detection plaintext sidecars (`<conn_id>.txt.enc`) are encrypted with an independent key derived from the same master key via a distinct HKDF context (see [SEARCH_AND_DETECTION.md](SEARCH_AND_DETECTION.md)).

Details:

- **Key derivation.** `GATORCAST_MASTER_KEY` must be base64 and decode to exactly 32 bytes. HKDF-SHA256 (no salt) derives a 32-byte key per purpose. The `.cast` key uses the context `gatorcast/cast/v1`; the sidecar key uses `gatorcast/sidecar/v1`. The same master key therefore yields two unrelated keys, and a blob from one artifact fails authentication if presented as the other.
- **Blob format.** `GCST\x01\x00` (6-byte magic and version) `||` 12-byte random nonce `||` ciphertext and GCM tag. A wrong key, a flipped byte, a truncated file or a mismatched connection id (the AAD) fails the tag check.
- **File names.** A recording is always `<conn_id>.cast` and its sidecar always `<conn_id>.txt.enc`, whether or not encryption is on. With encryption off, both hold plaintext bytes under those same names.
- **When encryption happens.** Only at seal. While a session is recording, the `.cast` on disk is plaintext (see the limitation below). The sidecar is first written at seal, so with encryption on it is never on disk as plaintext. A reopened session is decrypted back to plaintext on disk until it seals again.
- **Replay.** The cast route streams a provisional recording's plaintext file as is. For a sealed row under encryption it decrypts in memory and serves the bytes to the player. A decrypt failure returns `404` and logs `cast.decrypt_failed` with the `conn_id` only.

**Enabling it:**

1. Generate a master key:

   ```bash
   openssl rand -base64 32
   ```

2. Set `ENCRYPTION_ENABLED` by editing it in `docker-compose.yml`. It is already listed under `environment:`, which takes precedence over `env_file`, so a value in `.env` has no effect:

   ```yaml
   ENCRYPTION_ENABLED: "true"
   ```

   Set `GATORCAST_MASTER_KEY` in `.env` (or inject it from a secrets manager):

   ```bash
   GATORCAST_MASTER_KEY=<the base64 value from step 1>
   ```

3. Start the service. If encryption is enabled but the key is missing or invalid, Gatorcast **refuses to boot** (fail-closed) rather than silently storing recordings in the clear.

**Pulling the key from a cloud vault → env:** The app only ever reads the key from the environment, so any vault that can inject an env var works:

- **AWS Secrets Manager / Parameter Store** — reference the secret in an ECS task definition `secrets:` block so it lands as `GATORCAST_MASTER_KEY`.
- **HashiCorp Vault** — use a Vault agent or an entrypoint wrapper that exports `GATORCAST_MASTER_KEY` before launching the process.
- **Docker Compose secrets** — mount the secret and export it to the env in your entrypoint.

**Important limitations:**

- **In-progress recordings are plaintext at rest.** A `.cast` is written plaintext on every append and only encrypted when the session seals (on "session finished" or the idle backstop). So a session that is still recording — or one held open and idle below the backstop — sits unencrypted on the volume until it seals. This is the accepted tradeoff for durability and live/in-progress playback; lower `SESSION_MAX_IDLE_SECONDS` to shorten the plaintext window for abandoned sessions.
- **Fresh-start only.** Enabling encryption does **not** migrate existing unencrypted recordings. Start with a clean `/data`. Sealed plaintext recordings written before encryption was enabled stay plaintext on disk, and they cannot be replayed afterward, because a sealed row under encryption is always decrypted and a plaintext file fails the format check (the UI returns `404`). The reverse also holds: turning encryption off on a volume that holds encrypted recordings leaves them unreadable.
- **Losing the key means losing the recordings.** There is no recovery path and no key rotation in this version. Changing `GATORCAST_MASTER_KEY` makes every existing sealed recording and sidecar fail authentication.
- **The metadata database is not encrypted.**

---

## Security Model

| Layer | Mechanism |
| --- | --- |
| `/ingest` endpoint | `Authorization: Bearer <INGEST_TOKEN>` checked with constant-time comparison. Missing or mismatched token → 401. The body size is not limited (asciicast lines are large), and the response never echoes content. |
| Web UI (all routes) | HTTP Basic auth on every UI and cast route. Credentials checked with constant-time comparison; both fields are always compared. No route is reachable unauthenticated (except `/healthz` and `/static/*`). |
| `.cast` file serving | The path is built from the session's `conn_id`, never from the stored `cast_path`, and must resolve inside `casts_dir` (`is_relative_to`) before serving. `CastStore` applies the same confinement to every read. `conn_id` is also validated upstream in `classify`. |
| Recording replay | Recording content is only ever loaded by the vendored asciinema player. It is never rendered as HTML, because it is full of attacker-influenced escape sequences. Jinja autoescaping is on everywhere. |
| Container privileges | Runs as a dedicated non-root system user (`uid 10001`). |
| Recording payloads | Never written to application logs, and neither are search sidecars or extracted text. Session recordings may contain on-screen secrets (terminals, typed tokens). Treat all stored `.cast` and `.txt.enc` files as secret-grade. |
| Findings | Carry the rule label, category, severity and replay offset only, never the matched text. |
| kubectl API metadata | Only `User-Agent`, `Kubectl-Command` and `Kubectl-Session` request headers are stored (first value, 256 characters at most). `Authorization`, cookies, other headers, response headers, `remote_addr` and panic content are never stored or logged. URLs are normalized and keep only allowlisted query keys with validated values; `command=` is always dropped, proxy URLs keep only their path up to `proxy`, and exec/attach URLs keep the path plus `container`, `stdin`, `stdout`, `stderr` and `tty`. See the [README](README.md#what-is-stored-and-what-is-never-stored). |
| Activity page parameters | `user`, `from`, `to`, `activity_before` and `discovery` are validated strictly (400 on bad or repeated input) and used only as bound SQL parameters. |
| Search parameters | All search SQL is parameterized; the only dynamic SQL text is fixed fragments and placeholder lists sized by validated counts. Parameters are validated strictly (`400` on an invalid, repeated or conflicting value), and a `4xx` never echoes the submitted value or logs it. The cursor is unsigned, length-capped and strictly decoded, and reaches SQL only as bound parameters. Content search decrypts only the sidecars of a metadata-narrowed candidate set, capped at `SEARCH_REGEX_MAX_CANDIDATES` per page. The regex filter never runs over API rows. |
| Search output | Kind badges come from the registry, severity classes from fixed keys, and status classes from integers; no stored value becomes a class name. Stored URLs, `Kubectl-Command` values, usernames and system addresses render through autoescape. CSV cells starting with `=`, `+`, `-`, `@`, tab or carriage return get a leading `'`. Rows carry metadata and finding labels only, never recording text, and `User-Agent` appears only as the command-label product token. |
| Syslog TCP | No per-message auth. The container listens on all interfaces, and the shipped `docker-compose.yml` publishes the port on `127.0.0.1` only. Caps: 128 concurrent connections (extras are closed at once), a 5-minute idle read timeout, a 16 MiB frame limit and a 10-digit length-prefix limit; a frame that breaks a limit closes its connection. TCP only; UDP is never accepted. `SYSLOG_TCP_PORT=0` disables the listener. |
| Insecure defaults | At startup, Gatorcast logs a warning for each secret still equal to a placeholder default (`INGEST_TOKEN`, `UI_AUTH_PASSWORD`) and when `UI_AUTH_USERNAME` is still `admin`. The service still boots, but the warning is prominent. The value itself is never logged. |
| Encryption config | If `ENCRYPTION_ENABLED=true` and the master key is missing or invalid, the app refuses to start (fail-closed). See [Encryption at Rest](#encryption-at-rest). |

**Access control summary:** Set strong, unique values for `INGEST_TOKEN`, `UI_AUTH_USERNAME`, and `UI_AUTH_PASSWORD`. Put Gatorcast behind a TLS-terminating reverse proxy. Do not expose the syslog port on a public interface. See [Deployment Behind a Reverse Proxy](README.md#deployment-behind-a-reverse-proxy) in the README for the intended production layout.

---

## Background Jobs

Two APScheduler jobs run on the in-process asyncio scheduler. Both use `max_instances=1` and `coalesce=True`, so a slow run never overlaps itself and missed runs collapse into one.

| Job id | Trigger | What it does |
| --- | --- | --- |
| `idle_finalize` | Every `max(5, min(IDLE_TIMEOUT_SECONDS, 30))` seconds | Seals reopenably every in-progress recording silent for at least `SESSION_MAX_IDLE_SECONDS`. Then expires `pending` connections whose `last_seen_at` is older than `SESSION_MAX_IDLE_SECONDS` into visible `error` session rows. |
| `retention_purge` | Every 24 hours | Runs the age and size policies below. The first run is 24 hours after the process starts, not at startup, and the schedule is not persisted, so each restart resets the timer. |

Startup runs, in order: schema creation and migrations, the startup sweep (re-adopt or remove provisional rows), then the ingest queue and consumer, the scheduler, and the syslog listener. The backfill is a one-off background task, not a scheduled job. It is started after the startup sweep and runs only when both `BACKFILL_ON_STARTUP` and `DETECTION_ENABLED` are true (see [SEARCH_AND_DETECTION.md](SEARCH_AND_DETECTION.md#detecting-on-pre-existing-recordings)). Shutdown stops the syslog listener, the backfill, the consumer and the scheduler, then closes the database.

---

## Retention

Two independent policies run every 24 hours (the `retention_purge` job):

1. **Age-based:** Sessions with a `started_at` older than `RETENTION_DAYS` days (default `90`) are deleted whatever their status (row, `.cast` file, search sidecar and findings). Sessions with no `started_at` are not age-purged (their age is unknown).
2. **Size-based:** If `RETENTION_MAX_GB > 0`, the oldest `complete` sessions (by `started_at`, else `created_at`) are deleted until the total is under the cap. The total is the sum of the recorded `size_bytes` of all session rows, in-progress ones included, but only `complete` sessions are eligible for deletion. Sidecar sizes are not counted.

Both policies are no-ops when disabled (`0`). Deleting a row and its `.cast` file is one logical operation; a missing file is tolerated and does not cause an error. A purged session's plaintext search sidecar and findings are removed alongside it.

The age-based purge also deletes kubectl activity on the same `RETENTION_DAYS` cutoff, with no separate setting: `api_requests` (with their `api_findings`) and `connections`. An API request is purged when either its Gateway `requested_at` or the time Gatorcast stored it is past the cutoff; connections are purged on Gatorcast's own timestamps. The size cap counts `.cast` bytes only and never deletes API rows or connections.

To keep recordings indefinitely, set `RETENTION_DAYS=0` and `RETENTION_MAX_GB=0` (the default for size is already `0`). Both are listed under `environment:` in `docker-compose.yml`, so edit them there; a value in `.env` has no effect.

---

## Module Map

All code is under `src/gatorcast/`.

| Module | Role |
| --- | --- |
| `main.py` | FastAPI app, lifespan (startup and shutdown order), queue consumer, scheduler wiring, `/healthz` |
| `config.py` | `pydantic-settings` `Settings` (all environment variables and their defaults) |
| `logging.py` | structlog setup (JSON to stdout) |
| `db.py` | SQLite connection (WAL), schema, column additions, `user_version` migrations, the shared SQL fragments (`CMD_KEY_SQL`, `SESSION_AT_SQL`, `FAILED_SQL`) and the `gc_is_discovery` SQL function |
| `models.py` | Pydantic models: `Session` and the events `RecordingChunk`, `SessionStart`, `SessionEnd`, `ApiRequest` |
| `crypto.py` | `Cryptor`: AES-256-GCM with HKDF-derived keys (cast and sidecar contexts) |
| `ingest/http.py` | `POST /ingest` (bearer auth, JSON or line-delimited bodies) |
| `ingest/syslog_tcp.py` | Syslog TCP listener: octet-counted and newline framing, connection and frame limits |
| `ingest/normalize.py` | Raw line to JSON object: syslog header strip, collector unwrap |
| `pipeline/classify.py` | Line to event; `conn_id` validation; allowlisted headers; stored-URL sanitizing |
| `pipeline/urlnorm.py` | Shared URL normalization used by `classify` and `detect` |
| `pipeline/assembler.py` | Per-`conn_id` buffers, connection lifecycle, reassembly, sealing, idle sweep, startup sweep |
| `pipeline/extract.py` | ANSI-stripped plaintext and character-to-time offset index |
| `pipeline/detect.py` | Built-in cast rules and kubectl API rules |
| `pipeline/activity.py` | Pure kubectl grouping: discovery, activity sessions, commands |
| `pipeline/backfill.py` | Startup pass that builds sidecars and findings for older sessions |
| `pipeline/retention.py` | Age and size purge, including API rows and connections |
| `store/sessions.py` | `sessions` repository (including the persisted seal mode), systems index query, retention queries |
| `store/casts.py` | `.cast` and `.txt.enc` read, write, reopen, delete; encryption at the file layer |
| `store/search.py` | `findings` store, dashboard stats. `SearchStore.search` and `SearchFilters` are deprecated and unused by the routes. |
| `store/timeline.py` | The unified search engine: `UnifiedQuery`, `Cursor`, the sessions and API-command sources, `run_timeline`, keyset paging |
| `store/activity.py` | `connections`, `api_requests`, `api_findings` |
| `web/routes.py` | Dashboard, search, CSV export, systems, sessions, activity, cast stream |
| `web/params.py` | Strict search parameter parsing (canonical and legacy names), cursor encoding, `search_url` |
| `web/kinds.py` | Event-kind registry, type groups, filter and sort applicability (`resolve_kinds`) |
| `web/auth.py` | HTTP Basic auth dependency for the UI routes |
| `web/templates/`, `web/static/` | Jinja2 templates (shared `_macros.html` and `_rows.html` for search and dashboard rows, `_search_error.html` for HTMX `400`s); vendored asciinema player, HTMX, Alpine.js and CSS |

`scripts/seed_demo.py` is a throwaway helper that posts synthetic sessions for UI and detection testing. It is not part of the app.
