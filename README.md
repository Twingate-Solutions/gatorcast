# Gatorcast

> **⚠️ Example project — provided as-is, with no support or warranty.** Gatorcast is published as a reference example to build from, not a supported product. Nothing here is guaranteed and no support is attached to it. It was developed with help from an LLM-based coding assistant. **Review the code and test it yourself before using it in any critical or production environment.** Your use is governed by the [Apache License 2.0](LICENSE), including its "AS IS", no-warranty (Section 7), and limitation-of-liability (Section 8) terms.

Self-hosted, single-container service for **Twingate Identity Firewall Gateway session recordings**. The Twingate Gateway records interactive privileged sessions (`kubectl exec`, SSH shells) as asciicast v2 fragments and emits them via structured JSON audit logs. Twingate's reference pipeline ships those fragments to object storage but does not reassemble them into sessions or provide a browse/replay UI. Gatorcast fills that gap: it receives the Gateway's log lines via push (HTTP POST or syslog TCP), demultiplexes concurrent sessions by `conn_id`, reassembles each into a complete asciicast v2 document, stores it, and serves a lightweight web UI to browse **systems → sessions → replay** in a locally vendored asciinema player. All recordings stay on your infrastructure.

Gatorcast also stores the Gateway's per-request Kubernetes API audit lines as allowlisted **kubectl activity** metadata (method, sanitized URL, status, user, and three request headers), grouped per user and cluster and shown next to the recordings. No recording or request body is ever involved. See [kubectl Activity](#kubectl-activity).

It does the same for **web apps** that users reach through the Gateway acting as a Layer 7 reverse proxy: each request's method, path, status and `User-Agent` is stored, grouped per connection, and shown with the app's **configured** TLS posture when gwops reports it. Web traffic has no recording and is not evaluated by detection rules. See [Web Apps](#web-apps).

![Session replay — full session metadata, in-browser playback, and detection findings with jump-to-timestamp links](images/session_replay.png)

---

## A Quick Tour

**Dashboard** — session volume, flagged sessions, findings by severity and category, the most active users and systems, and a recent-activity feed. Every tile, severity chip and top user links into [search](#unified-search) with the selected time window:

![Dashboard with session totals, severity breakdown, findings by category, and top users/systems](images/dashboard.png)

**Systems → sessions** — recordings are grouped by target system (`resource_address`), with per-system findings badges; drill into a system to see every session with its user, duration, status, and risk:

![Systems list with session counts, findings badges, and last-seen timestamps](images/systems_list.png)

![Sessions for one system showing user, shell user, duration, status, and risk badges](images/sessions_list_one_system.png)

**kubectl activity** — the systems list also includes clusters that only have kubectl API activity, with type badges and separate "Last session" and "Last API request" columns. A system page adds a per-user kubectl activity table, and each row opens a page of that activity session's commands, with findings and links to any exec recordings. The dashboard has a kubectl API requests card. See [kubectl Activity](#kubectl-activity).

**Web apps** — the systems list badges web apps `Web` with their configured TLS. A system page adds a **Configured web app TLS (from gwops)** block and a **Web activity** table of per-user visits, and each visit opens a page of its requests. The dashboard has a **Web requests** tile. See [Web Apps](#web-apps).

**Search** — one timeline over SSH recordings, kubectl exec recordings, failed connections, kubectl commands and web connections. Filter by type, user, system, time, duration, status, finding severity/category or specific detection rules, plus full-content keyword/regex search over recordings. Recording results link straight to each finding's timestamp in the replay, kubectl commands expand to their requests, and any result set exports to CSV. See [Unified Search](#unified-search):

![Search with metadata filters, detection-rule filters, content search, and findings with jump links](images/search_results.png)

**Detection** — built-in dangerous-command and secret-exposure rules run live on every session; each finding jumps the player to the exact moment it happened:

![Replay of a session where an inline secret was detected, with the finding's jump-to-timestamp link](images/findings.png)

---

## Documentation

This README covers install, configuration, and day-to-day operation. The deeper topics live in their own docs:

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — how data flows through the service, the session lifecycle, encryption at rest, the security model, and retention.
- **[SEARCH_AND_DETECTION.md](SEARCH_AND_DETECTION.md)** — the dashboard, search/filtering, content-search internals, and the full built-in detection rule set.
- **[INGESTION_RECIPES.md](INGESTION_RECIPES.md)** — a cookbook for forwarding Gateway logs into Gatorcast from any deployment: systemd VMs, Terraform-provisioned cloud instances (AWS/GCP/Azure), Docker, and Kubernetes.
- **[TESTING.md](TESTING.md)** — running the test suite, seeding demo data, and the exact text to paste into a session to trigger each built-in detection rule (plus negative controls).

---

## Quickstart

**Prerequisites:** Docker and Docker Compose.

### 1. Get the files

```bash
git clone https://github.com/Twingate-Solutions/gatorcast.git
cd gatorcast
```

The `docker-compose.yml` pulls the image from GHCR — it never builds locally.

### 2. Create your `.env`

```bash
cp .env.example .env
```

Edit `.env` and set strong values for all three secrets:

```bash
INGEST_TOKEN=<long-random-string>    # Bearer token your shipper presents to /ingest
UI_AUTH_USERNAME=<your-username>     # Web UI login
UI_AUTH_PASSWORD=<strong-password>   # Web UI password
```

> **Important:** Gatorcast logs a warning at startup (`config.insecure_default`) if any of these values are still equal to the placeholder defaults (`change-me-long-random`, `admin`, `change-me`). The service will still start, but do not run it on a network with those defaults in place.

### 3. Start the service

```bash
docker compose pull
docker compose up -d
```

### 4. Browse the UI

Open `http://<your-host>:8080` in a browser. You will be prompted for the `UI_AUTH_USERNAME` and `UI_AUTH_PASSWORD` you set above.

Sessions appear as soon as the shipper begins forwarding Gateway logs — a recording shows up (in progress, and playable) on its first chunk and flips to complete when the Gateway sends its "session finished" flush. To forward logs in, see [INGESTION_RECIPES.md](INGESTION_RECIPES.md).

---

## Configuration

All settings are environment variables. Secrets (`INGEST_TOKEN`, `UI_AUTH_*`, `GATORCAST_MASTER_KEY`) should live in `.env` (which is in `.gitignore`).

The shipped `docker-compose.yml` already sets nine variables in its `environment:` block: `HTTP_PORT`, `SYSLOG_TCP_PORT`, `DATA_DIR`, `IDLE_TIMEOUT_SECONDS`, `SESSION_MAX_IDLE_SECONDS`, `RETENTION_DAYS`, `RETENTION_MAX_GB`, `LOG_LEVEL` and `ENCRYPTION_ENABLED`. Docker Compose gives `environment:` precedence over `env_file`, so change those nine in `docker-compose.yml`; the same names in `.env` are ignored. Every other variable can go in `.env`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HTTP_PORT` | `8080` | FastAPI HTTP port (UI + `POST /ingest`). The shipped compose file publishes `8080:8080`, so change that mapping too if you change this. |
| `SYSLOG_TCP_PORT` | `6514` | Syslog TCP listener port. `0` disables the listener. |
| `DATA_DIR` | `/data` | Volume root for the SQLite database (`gatorcast.db`), `.cast` files and search sidecars |
| `IDLE_TIMEOUT_SECONDS` | `120` | Sets how often the idle-backstop sweep runs (this value clamped to 5–30 seconds) and, on restart, the age past which a provisional row with no `.cast` is swept as an abandoned start. **Not** a finalize trigger (recordings seal on the Gateway's "session finished" flush). |
| `SESSION_MAX_IDLE_SECONDS` | `3600` | Idle backstop after this much silence: a recording **with data** is sealed (reopenable — a later chunk resumes it); a session that started but **never recorded** a valid chunk is marked `error`. **Must exceed the Gateway's flush interval** (a quiet-but-active session is chunkless until its first flush). Under encryption, also bounds how long a recording stays plaintext at rest. |
| `RETENTION_DAYS` | `90` | Purge sessions older than this many days. Also purges kubectl API requests (with their findings) and connections on the same cutoff. `0` keeps everything forever. See [Retention](#retention). |
| `RETENTION_MAX_GB` | `0` | Optional total recording (`.cast`) size cap in GB. When over the cap, the oldest completed sessions are deleted. `0` disables size-based purge. Counts recording bytes only; API rows and connections are never touched by it. |
| `LOG_LEVEL` | `info` | structlog level (`debug`, `info`, `warning`, `error`) |
| `INGEST_TOKEN` | `change-me-long-random` | Bearer token the shipper presents to `POST /ingest`. The default is a placeholder; set your own. |
| `UI_AUTH_USERNAME` | `admin` | Username for web UI HTTP Basic auth |
| `UI_AUTH_PASSWORD` | `change-me` | Password for web UI HTTP Basic auth. The default is a placeholder; set your own. |
| `ENCRYPTION_ENABLED` | `false` | Encrypt `.cast` recordings at rest (AES-256-GCM). Opt-in. Set it in `docker-compose.yml`, not `.env` (see above). See [Encryption at Rest](#encryption-at-rest). |
| `GATORCAST_MASTER_KEY` | *(unset)* | Base64 32-byte key (`openssl rand -base64 32`). **Required** when encryption is enabled; startup fails without a valid key. Also keys the search sidecars. |
| `DETECTION_ENABLED` | `true` | Master switch for detection: scans each recording live on every append and again at seal, and applies the kubectl API rules to each stored request. `false` produces no findings and skips the startup backfill. See [SEARCH_AND_DETECTION.md](SEARCH_AND_DETECTION.md). |
| `BACKFILL_ON_STARTUP` | `true` | On startup, index and scan completed recordings that lack a search sidecar. Has no effect when `DETECTION_ENABLED=false`. |
| `SEARCH_PAGE_SIZE` | `50` | Default number of search results per page. A `page_size` query parameter (1 to 200) overrides it. |
| `SEARCH_REGEX_MAX_CANDIDATES` | `2000` | Max sidecars read per page of a keyword/regex content search, and per CSV export (cost / ReDoS bound). When a page hits it, search offers **Continue scanning**. |
| `KUBECTL_ACTIVITY_GAP_SECONDS` | `900` | Inactivity gap that splits one user's kubectl activity on a cluster, or one user's web visits to a web app, into separate activity sessions or visits. Must be greater than `0`. |
| `KUBECTL_ACTIVITY_MAX_SECONDS` | `14400` | Hard cap on the span of one activity session or web visit. Bounds long-lived clients (`k9s`, `kubectl get -w`, CI polling, a page that polls) that never leave a gap. Must be greater than or equal to `KUBECTL_ACTIVITY_GAP_SECONDS`. |

There are no web-specific settings. `KUBECTL_ACTIVITY_GAP_SECONDS` and `KUBECTL_ACTIVITY_MAX_SECONDS` also govern web visits, and the name is historical. They must satisfy `0 < gap <= max`. If they do not, the service refuses to start and the error names both values. Both are listed in `.env.example`.

---

## Ingestion

Gatorcast is push-only: it exposes two front doors and waits. Both feed the same pipeline, and the Gateway's log lines are the same on either.

| Door | Where | Auth |
| --- | --- | --- |
| HTTP | `POST /ingest` on `HTTP_PORT` | `Authorization: Bearer <INGEST_TOKEN>` |
| Syslog TCP | `SYSLOG_TCP_PORT` (`6514`) | None. Bind it to an internal interface only. |

**HTTP.** An `application/json` body is parsed as one document, either a single object or an array of objects. Any other content type (`application/x-ndjson`, `text/plain`) is read as newline-delimited, one JSON object per line. Lines are split on `\n` only (one trailing `\r` is dropped), so a Unicode line separator such as U+2028 inside a header value or terminal output cannot tear a line apart. A line that cannot be parsed, including a non-JSON line such as a Go `http: proxy error` message, is dropped without failing the batch or its other lines. The response is `204 No Content` even when some lines were dropped, and `401` when the token is missing or wrong. The app sets no body-size limit; set one at your proxy (see [Deployment Behind a Reverse Proxy](#deployment-behind-a-reverse-proxy)).

**Syslog TCP.** TCP only; UDP is never accepted, because asciicast lines are multi-KB and must not be truncated. Octet-counted (RFC 6587) and newline-delimited framing are both accepted and detected per message. A frame over 16 MiB closes the connection, at most 128 connections are served at once, and a connection idle for 5 minutes is closed.

**Both doors** strip a syslog `<PRI>` header and unwrap a Docker `{"log": "...", "stream": "..."}` envelope before parsing. After that, only three kinds of line are kept: recording chunks, `Authenticated connection` lines, and API request audits (Kubernetes and web-app requests alike). Everything else is dropped by design.

For a copy-paste test and shipper recipes (journald, rsyslog, Vector, Docker, Kubernetes), see [INGESTION_RECIPES.md](INGESTION_RECIPES.md); the curl test is in §8.

---

## Web UI

Every page and the `.cast` stream require HTTP Basic auth (`UI_AUTH_USERNAME` / `UI_AUTH_PASSWORD`). Only `/healthz` and `/static/*` are open.

| Route | What it shows |
| --- | --- |
| `/` | Redirects to `/dashboard`. |
| `/dashboard` | Totals, severity and category breakdowns, top users and systems, the kubectl API requests card, the Web requests tile, and a recent-activity feed. `?window=7`, `30` (default), `90` or `all` sets the time window; an invalid value falls back to 30. See [Dashboard](#dashboard). |
| `/systems` | One row per target system, with SSH / Kubernetes / Web type badges (and the configured TLS of a web app), session count and last session, a request count per kind and last request, and a findings badge. Sessions with no target system appear as `(unknown)`. |
| `/systems/{slug}` | The system's recordings (newest first), its kubectl activity table, and for a web app the configured-TLS block and Web activity table, with links into search for the system. `{slug}` is the URL-encoded `resource_address` (which may contain `/`), or `_unknown`. |
| `/systems/{slug}/activity` | One kubectl activity session. Takes `user`, `from` and `to`, plus optional `discovery=1`; the links on the system page fill these in. |
| `/systems/{slug}/web` | One web visit: the requests of one user on one web app between `from` and `to`, with per-request configured TLS. Takes `user`, `from` and `to`; the links in the Web activity table fill these in. |
| `/sessions/{conn_id}` | Session metadata, the asciinema player, and the findings list. `?t=<seconds>` opens the player at that offset. The user links to their activity in search; an exec recording links to its kubectl command. |
| `/sessions/{conn_id}/cast` | The `.cast` bytes, consumed only by the player. Decrypted in memory for sealed recordings when encryption is on. |
| `/search`, `/search/export.csv` | One search over every event kind; CSV export of the current result set. See [Unified Search](#unified-search). |
| `/healthz` | Liveness probe. Returns `{"status": "ok"}` with no auth. |

Session status shows as **in progress** (still recording, playable now), **complete**, or **error** (the recording had no valid asciicast header when it sealed, or the connection never delivered a recording chunk or API audit before the backstop).

Recording content is never rendered as HTML. It is only ever loaded by the vendored asciinema player.

---

## Search and Detection

**Detection.** 21 built-in rules (14 dangerous-command, 7 secret-exposure) scan each recording live on every append and again when it seals. A finding stores the rule, severity, label and replay offset only, never the matched text. Rules are fixed in code; there is no rule configuration. Disable detection with `DETECTION_ENABLED=false`. The six kubectl API rules run on Kubernetes requests only. Web-app traffic is not evaluated by any rule.

**Search.** `/search` is one search over every event kind. See [Unified Search](#unified-search) below.

The full rule list, filter reference and search internals are in [SEARCH_AND_DETECTION.md](SEARCH_AND_DETECTION.md).

---

## Unified Search

`/search` lists SSH recordings, kubectl exec recordings, failed connections, kubectl commands and web connections in one interleaved timeline. Each row carries a type badge. There is no result total, because a total would need every kubectl command grouped. Paging is forward-only: **Next ›** moves on, **First page** returns to the start, and the browser's Back button returns to earlier pages.

### Types

The `type` parameter (the form's Type select) chooses which kinds are searched.

| `type` | Lists |
| --- | --- |
| `any` (default) | Every kind below |
| `recordings` ("All sessions") | SSH recordings, kubectl exec recordings and failed connections. This is every row the dashboard's "Total sessions" counts. |
| `ssh` | SSH recordings |
| `exec` | kubectl exec/attach recordings |
| `failed` | Failed connections: a connection that delivered neither recording chunks nor API audits before `SESSION_MAX_IDLE_SECONDS`. These have no recording, so the row shows **Details ›** (the session metadata page) instead of **Replay**. |
| `kubectl` | kubectl commands |
| `web` ("Web requests") | Web connections |

A kubectl result is one **command**, grouped the same way as the activity page (by `Kubectl-Session`, else by connection, within one user and one cluster). Each row expands inline to its requests (the first 200, with a link to the activity view for the rest). A command appears in the window that contains its first request, and it always shows all of its requests.

Under `any`, a kubectl exec recording appears twice by design: as its own `exec` row, and as the **Replay** link inside its kubectl command row.

A web result is one **connection** (one `conn_id`), placed by its first request. The row shows the configured-TLS badge and upstream marker, the user, the system and, when gwops matched the app, its name with a `managed` or `unmanaged` marker (the gateway id is in the marker's tooltip). It also shows the primary request (the first `POST`, `PUT`, `PATCH` or `DELETE`, else the first request), the request count and span, a **Visit ›** link to the visit view, and a **Focus ›** link. It expands inline to its requests (the first 200). A browser can open several connections for one page load, so one visit can appear as several interleaved rows; the visit view shows them together. See [Web Apps](#web-apps).

### Filters

| Parameter | Meaning |
| --- | --- |
| `type` | See above. |
| `system` | Exact `resource_address`. `_unknown` selects sessions with no system. |
| `user` | Exact match on the username or on the Gateway user id. Usernames across the UI link to `/search?user=<username>`, which is the per-user view: that user's SSH, exec and kubectl activity on every system. |
| `window`, `from`, `to` | `window` is `7`, `30`, `90` or `all` (days back from now). `from` and `to` are inclusive ISO 8601 times (naive means UTC). Do not combine `window` with `from` or `to`. |
| `severity`, `max_severity` | At-or-above, or exact highest severity. |
| `has_findings`, `category`, `rule_ids` | Finding filters. They apply to recording findings and to kubectl API findings (`category=kube-api`, `kube-*` rule ids). |
| `status`, `min_duration`, `max_duration` | Recordings only. |
| `scheme` | Web connections only: the configured client-facing TLS. `https`, `http` or `unknown`. |
| `upstream` | Web connections only: the configured app-facing TLS. `verified`, `ca_only`, `unverified`, `plaintext` or `unknown`. |
| `q`, `mode` | Text (default) or regex. Text matches recording content case-insensitively, matches a kubectl command's URL paths (query strings excluded) and `Kubectl-Command` values, and matches a web connection's stored URLs (the unmasked path and the masked query) case-insensitively for ASCII letters. Regex runs over recordings only. |
| `sort` | `newest` (default), `risk`, or `duration` (recordings only). |
| `discovery` | `1` shows discovery-only kubectl commands, which are hidden by default. Web connections ignore it. |
| `cmd` | A request id. Shows the one kubectl command or web connection that request belongs to, expanded, and ignores the other filters (except `discovery`). An unknown id shows "Command or web connection not found. It may have been removed by retention." Linked from an exec recording's session page, a web row's **Focus ›** link and the dashboard feed. |
| `page_size`, `cursor` | Page size (1 to 200) and the opaque position that **Next ›** carries. |

**A filter a kind cannot evaluate excludes that kind.** The page shows a notice, for example "kubectl commands not searched: the Status filter applies to recordings only." `status`, `min_duration`, `max_duration`, `mode=regex` and `sort=duration` exclude kubectl commands and web connections; `cmd` excludes recordings; `scheme` and `upstream` exclude every kind except web. A kind that can evaluate the filter but has no match simply returns no rows.

**Findings filters and web connections.** Web connections carry no findings, because no detection rule evaluates them. `has_findings=true`, `severity`, `max_severity`, `category` and `rule_ids` return no web rows, and the page says "Web connections are not evaluated by detection rules." `has_findings=false` matches every web connection. The `scheme` and `upstream` values filter on configured TLS, which is not proof of what was negotiated (see [Web Apps](#configured-tls)). `unknown` matches every connection with no TLS data, whatever the reason.

**Invalid input is a `400`.** An unknown `sort`, a non-numeric duration, a repeated parameter, `window` combined with `from`, `from` later than `to`, an uncompilable regex and a bad `cursor` are all rejected with a message that names the parameter. Search forms swap the message into the results area.

### Old `/search` links

The earlier parameter names still work: `username`, `resource_address`, `started_after`, `started_before`, `keyword`, `regex` and `page`. The UI now builds only the new names.

**Old `/search` links can show more results, never fewer.** A link with no `type` now means `any`, so it lists every recording it listed before, plus any kubectl commands and failed connections that satisfy the same filters. A `username=` link also matches the Gateway user id. A link that carries a recordings-only filter (`status`, a duration, `regex`) still lists recordings only.

Three exceptions to that guarantee:

1. **Values that used to be ignored now fail.** An unknown `sort`, a non-numeric `min_duration` and an uncompilable `regex` used to be silently dropped. They now return `400`.
2. **`page=N` lands on the first page.** The same results are reachable with **Next ›**.
3. **Fractional-second bounds can differ at one boundary second.** A hand-typed `started_after` or `started_before` with a fractional second is now compared in a normalized format. Links generated by the dashboard never carried fractions.

### Paging and budgets

Each page costs in proportion to its size, not its depth. Three limits bound the work for one page. The scan and flagged limits are fixed in code; the sidecar limit is the `SEARCH_REGEX_MAX_CANDIDATES` setting:

- **kubectl commands and web connections:** at most 20,000 request rows of each kind are examined per page. A search that matches rarely (for example a text search on a busy cluster or web app) can stop early with a short page and the notice "Scanned 20,000 kubectl requests without filling the page." (or "web requests", or both).
- **Recording content search:** at most `SEARCH_REGEX_MAX_CANDIDATES` sidecars are read per page.
- **Flagged commands:** at most 5,000 flagged commands are considered per query. Past that the page says so and asks you to narrow by system, user or time.

When a budget stops a page, **Continue scanning ›** replaces **Next ›** and resumes without skipping or repeating results. A short or empty page with **Continue scanning ›** does not mean the search is finished.

### CSV export

**Export CSV** (`/search/export.csv`) follows the page: the same filters and kinds, one row per recording, kubectl command or web connection, mixed. It ignores `cursor` and `page_size` and writes up to 10,000 rows. The response header `X-Gatorcast-Truncated: true` is set when the export stopped early (row cap, a scan budget, the sidecar limit, or the flagged-command cap).

There are 22 columns. The first 15 are unchanged from 0.4.0.

| # | Columns | Meaning |
| --- | --- | --- |
| 1–10 | `conn_id`, `username`, `resource_address`, `status`, `started_at`, `ended_at`, `duration_seconds`, `finding_count`, `max_severity`, `findings` | Unchanged for recordings. |
| 11–15 | `kind`, `command`, `method`, `path`, `request_count` | `kind` is `ssh`, `exec`, `failed`, `kubectl` or `web`. kubectl rows fill the last four; `path` has no query string and `command` is the kubectl command label, never the full `User-Agent`. Web rows fill `method`, `path` and `request_count` and leave `command` empty. |
| 16 | `resource_type` | `KUBERNETES` for kubectl rows, `WEB_APP` for web rows, and the session's stored type (or empty) for recordings and failed connections. |
| 17 | `configured_scheme` | Web rows: `https`, `http` or `unknown`. Otherwise empty. |
| 18 | `configured_upstream_tls` | Web rows: `verified`, `ca_only`, `unverified`, `plaintext` or `unknown`. Otherwise empty. |
| 19 | `query` | Web rows: the stored query of the primary request, values masked, without the `?`. Otherwise empty. |
| 20 | `gwops_gateway_id` | Web rows: the gateway id gwops reported, when it reported a `match` of any kind. Otherwise empty. |
| 21 | `gwops_app` | Web rows: the app name, when gwops matched the app exactly. Otherwise empty. |
| 22 | `gwops_managed` | Web rows: `true` or `false`, when gwops matched the app exactly. Otherwise empty. |

Columns 17 and 18 carry the `configured_` prefix because a CSV has no tooltips: they are configured state, not proof of what was negotiated. A rejected `gwops` object exports exactly like an absent one (`unknown` and empty). A text cell starting with `=`, `+`, `-`, `@`, tab or carriage return is written with a leading `'` so a spreadsheet does not treat it as a formula; this includes `gwops_app`, which is free text for apps gwops does not manage. The export never contains recorded text. For web rows it contains the primary request's path unmasked, so a token embedded in a path appears in the export (see [what is stored](#what-is-stored-and-what-is-never-stored-web)).

### Dashboard

The dashboard's figures link into search with an explicit `type` and the selected window, so a figure and its list agree:

| Dashboard element | Opens |
| --- | --- |
| Total sessions | `type=recordings` |
| Flagged sessions, session severity chips, category chips | `type=recordings` with `has_findings=true`, `max_severity=` or `category=` |
| kubectl API requests | `type=kubectl` |
| Web requests | `type=web` |
| Flagged commands, API severity chips | `type=kubectl` with `has_findings=true` or `max_severity=` |
| Top users | `user=<username>` |
| Top systems | The system page |
| Recent activity | The newest 15 items of every kind (discovery-only commands hidden, not windowed). Rows open the replay, the session page, or `cmd=`. |

The kubectl card counts **commands** for its flagged figure and severity chips, and **requests** for its total (discovery included), so the total is the one figure that is not the length of its list. The kubectl card counts kubectl requests only; the Web requests tile counts web requests, and its list shows connections, so it is likewise not the length of its list. Two other figures differ from their lists by design: category chips count findings while the list shows sessions, and top users count sessions while the user link also lists kubectl commands. If more than 5,000 flagged commands match, the flagged figures are lower bounds and show as `5000+`.

Session figures are windowed on the recording start (the Gateway start time, else the time Gatorcast first saw the session), the same rule search uses.

---

## kubectl Activity

Besides recordings, the stock Gateway emits one `gateway.audit` line per Kubernetes API request (`"API request completed"` or `"API request failed"`). Gatorcast stores these as allowlisted metadata and shows them per user and cluster. It uses the same ingest paths (`POST /ingest`, syslog TCP) as recordings, so no extra shipper configuration is needed.

### How activity is grouped

- **API-only connections are not sessions.** An `Authenticated connection` line creates a hidden *pending connection*. A connection that only makes API requests never appears as a recording session. A connection that delivers neither recording chunks nor API audits within `SESSION_MAX_IDLE_SECONDS` becomes a visible `error` session.
- **Activity sessions.** Requests are grouped by user and cluster, then split when the gap since the previous request exceeds `KUBECTL_ACTIVITY_GAP_SECONDS`, or when one session's span reaches `KUBECTL_ACTIVITY_MAX_SECONDS`. Grouping is computed when a page is viewed. Nothing is cached.
- **Commands.** Within an activity session, requests are grouped into commands by the `Kubectl-Session` header (one UUID per `kubectl` run). A request with no `Kubectl-Session` is grouped by its connection instead. API-discovery `GET`s (`/api`, `/apis/…`, `/openapi/…`, `/version`) count toward timing but are hidden by default; the activity page has a toggle to show them.
- **Exec recordings.** An exec/attach recording links to its command by `request_id`, never by connection, because one `kubectl exec` can use two connections. The activity page links each command to its recording; recordings still replay on the normal session page.

### Where it appears in the UI

| Page | What it shows |
| --- | --- |
| `/systems` | Systems with recordings **and** clusters that only have kubectl activity. A **Type** column badges each system SSH and/or Kubernetes (a start-only `error` row earns neither). **Last session** and **Last API request** are separate columns, and rows sort by the newer of the two. The session and API request counts link into search. The Findings column counts recording findings only. |
| `/systems/{slug}` | The system's recordings, plus a **kubectl activity** table of per-user activity sessions. It shows 7 days at a time; use the "Older" and "Latest" links to page. At most 20,000 requests are read per page, and a notice appears if the cap is hit. "Search this system" and "kubectl commands in search" link into search, and each username has a trailing ⌕ link to that user's activity. |
| `/systems/{slug}/activity` | One activity session: its commands, each command's requests and findings, and links to exec recordings. No player is used. The user in the header links to search. |
| `/dashboard` | A **kubectl API requests** card: total requests, flagged commands, and a severity breakdown of those commands, within the selected time window. Each figure links to search. |
| `/search` | kubectl commands, one row per command, expandable to their requests, mixed with recordings. See [Unified Search](#unified-search). |

kubectl commands are searchable and included in the CSV export. Individual requests are not search rows: they appear only inside their command.

### API findings

Each stored request is checked against built-in rules on its method and normalized path. A finding stores the rule, category (`kube-api`), severity and label only, never the URL. Findings show on the activity page and in search, and feed the dashboard card. They are not produced when `DETECTION_ENABLED=false`.

| Rule | Severity | Matches |
| --- | --- | --- |
| `kube-delete` | high | Any `DELETE` request |
| `kube-secrets` | high | Any request to a `…/secrets` path |
| `kube-evict` | high | `POST …/pods/<name>/eviction` (drain) |
| `kube-cordon` | medium | `PATCH /api/v1/nodes/<name>` (cordon/uncordon) |
| `kube-exec` | medium | `…/pods/<name>/exec` or `…/attach` |
| `kube-node-proxy-exec` | high | `…/nodes/<name>/proxy/exec`, `run` or `attach` (kubelet exec through the API server) |

Rules match on the normalized path, so encoded or oddly shaped variants (`%73ecrets`, a trailing `/`, doubled `//`) still match. Query strings are never matched.

### What is stored, and what is never stored

Stored per request: `request_id`, `conn_id`, cluster (`resource_address`), user id and username, `requested_at`, method, a sanitized URL, status code, outcome (`completed` or `failed`), and these three request headers only:

- `User-Agent`
- `Kubectl-Command`
- `Kubectl-Session`

Header names are matched case-insensitively. Only the first value is kept, capped at 256 characters.

**Never stored, and never logged:** `Authorization` (present on every request), cookies, every other request header, all response headers, `remote_addr`, and panic content. Raw audit lines are never logged.

**URLs are normalized before storage:**

- The fragment is dropped. The path is percent-decoded once, repeated `/` are collapsed, and a trailing `/` is removed.
- If the decoded path contains an encoded `?` or `#` (`%3F`, `%23`), the path is cut at that character and the whole query is dropped. If the path is still percent-encoded after one decode, the query is dropped as ambiguous.
- Only allowlisted query keys are kept, and a key with a rejected value is dropped. Every other key is dropped outright, not kept blank. The allowlist is `labelSelector`, `fieldSelector`, `limit`, `continue`, `watch`, `timeout`, `timeoutSeconds`, `resourceVersion`, `resourceVersionMatch`, `allowWatchBookmarks`, `propagationPolicy`, `gracePeriodSeconds`, `dryRun`, `fieldManager`, `fieldValidation`, `force`, `follow`, `tailLines`, `sinceSeconds`, `previous`, `timestamps`, `pretty` and `orphanDependents`. Values must be at most 256 characters with no `;` and no control characters.
- **Exec/attach** URLs (`…/pods/<name>/exec` and `…/attach`) additionally keep only `container`, `stdin`, `stdout`, `stderr` and `tty`. Flags must be `true`, `false`, `1` or `0`, and `container` must be a valid DNS-label-style name. `command=` and every other parameter is always dropped, because it can hold secrets.
- Anything after a `/proxy` segment is dropped, along with the whole query, because the rest of the URL is forwarded to a backend. The one exception is `/nodes/<name>/proxy/exec`, `run` or `attach`, where that single segment is kept so `kube-node-proxy-exec` can still fire.

A request and its findings are written in one transaction, so a redelivered line never produces duplicate or partial rows. API rows are deduplicated by `request_id`.

Activity data is purged on the same cutoff as sessions. See [Retention](#retention).

---

## Web Apps

When the Twingate Gateway acts as a Layer 7 reverse proxy for a web app (resource type `WEB_APP`, HTTP or HTTPS), it writes the same `gateway.audit` / `"API request completed"` line per HTTP request that it writes for Kubernetes. Those request lines carry no resource fields, so Gatorcast joins each one to its connection's `Authenticated connection` line by `conn_id` to tell web requests from kubectl requests. Web requests are stored and shown separately from kubectl activity. They use the same ingest paths (`POST /ingest`, syslog TCP) as everything else.

There is no recording and no request or response body: the Gateway logs neither. Gatorcast never sees the end user's IP address, because the Gateway's `remote_addr` is the connector side. What a user did inside the app is visible only as method, path, query and status per request.

### Requirements

- The `Authenticated connection` line must reach Gatorcast. It is the only line that names the resource type and address. A shipper that filters lines must keep it (see [INGESTION_RECIPES.md](INGESTION_RECIPES.md) §1.4).
- **Configured-TLS badges need gwops.** The Gateway puts no scheme, port or TLS mode on any log line. The badges come from an optional `gwops` object that gwops adds to the `WEB_APP` `Authenticated connection` line. That requires a gwops release that adds the object (backlog item B-20) with Gatorcast delivery configured on it. From any other shipper, or from a gwops without Gatorcast delivery, web traffic is stored and shown normally and every connection reads **TLS unknown**. Whether a given gwops build adds the object is for you to confirm: Gatorcast has been checked against fixtures and demo data only.

### How web traffic is grouped

- **Connections.** Each `conn_id` is one search row. One connection can carry many keep-alive requests, and a browser can open several connections for one page load.
- **Visits.** The system page and the visit view group one user's requests to one web app into visits, split when the gap since the previous request exceeds `KUBECTL_ACTIVITY_GAP_SECONDS` or when a visit's span reaches `KUBECTL_ACTIVITY_MAX_SECONDS`. Grouping is computed when a page is viewed. Nothing is cached. Discovery hiding is a kubectl feature and does not apply to web.
- **Empty connections.** A `WEB_APP` connection starts hidden. If it delivers no request within `SESSION_MAX_IDLE_SECONDS` (a browser pre-connect, a refused `CONNECT` tunnel, a client that gave up), it expires hidden and never becomes a visible `error` session. A later request on it still records normally.
- **Requests before their start line.** gwops ships the start line first, but other shippers can deliver out of order. A request that arrives before its connection's start line is stored fail-closed: its URL gets the stricter of the web and Kubernetes policies (Kubernetes path cut at `proxy`, allowlisted query keys only, values masked). If the start line then says `WEB_APP`, the request becomes a web request but keeps that stricter URL. If it says `KUBERNETES`, it stays a kubectl request.
- **First write wins.** A connection's resource type and its TLS snapshot are fixed when its start line is first processed. A repeated, redelivered or forged start line cannot change or fill them.
- **WebSocket.** The Gateway logs one status 101 line when an upgrade completes and never logs frames. It shows as `101 WebSocket`.
- **Not logged by the Gateway:** a refused `CONNECT` tunnel to another host, a downstream TLS handshake failure and a rejected token. None of them produce a request line, so they are not visible here.

### Where web apps appear in the UI

| Page | What it shows |
| --- | --- |
| `/systems` | A `Web` badge, plus the configured-TLS badge and upstream marker of the app's newest web request. The **Requests** column links each kind present (`N kubectl ›`, `N web ›`) to its own search. A web-only system never gets the Kubernetes badge. |
| `/systems/{slug}` | The **Configured web app TLS (from gwops)** block and a **Web activity** table of per-user visits (start, end, duration, connections, requests, and a `4xx/5xx` count of statuses 400 to 599), over the same 7-day window as the kubectl table. The Web activity table appears only when the system has web requests. |
| `/systems/{slug}/web` | One visit's requests (at most 2,000, with a notice beyond that): time, method, stored URL, status, configured TLS, and connection. The configuration block above the table covers that visit's connections. |
| `/dashboard` | A **Web requests** tile (requests in the window) linking to `type=web`. The recent-activity feed includes web connections. |
| `/search` | The `web` kind and the `scheme` and `upstream` filters. See [Unified Search](#unified-search). |

### Configured TLS

Each web connection gets a client-facing badge and, when the upstream leg is not fully verified, a marker. Every badge and marker carries a tooltip saying the value is configured, not proof.

| Badge or marker | Means (as configured) |
| --- | --- |
| `HTTPS` | The client-facing leg uses TLS 1.3. |
| `HTTP` | The client-facing leg is plaintext. This is neutral, not a warning: that hop runs inside the Twingate tunnel. |
| `TLS unknown` | No TLS data for the connection (see below). |
| `Plaintext upstream` | The Gateway-to-app leg is plain HTTP. |
| `Unverified upstream` | The Gateway-to-app leg uses TLS with no certificate checks. |
| `CA-only upstream` | The certificate chain is checked, the hostname is not. |
| no marker | The upstream certificate chain and hostname are verified, or the connection is `TLS unknown`. |

The system page's **Configured web app TLS (from gwops)** block lists each distinct configuration seen in the window, newest first (at most 10), with connection counts and first and last request times. A line reads, for example, `HTTPS :443 → upstream verify_full :443`, with the app name, `managed` or `unmanaged`, and the gateway id (or "gateway id not yet assigned" when gwops has not created or adopted the Gateway yet). Several lines appear when the configuration changed inside the window. Other lines say gwops matched no web app at that address (or had not yet read the tenant's web apps), found more than one, or sent no data.

**The values are configured, not proof.** They are what gwops read as configured when it shipped the start line, not an observation of the handshake. TLS modes travel in each connection's token, so after a mode change a connection authenticated with an older token (up to about 55 minutes) can run the old mode while labelled with the new one. Do not treat `HTTPS` or `Verified` as evidence that a given connection was encrypted or verified.

**A connection shows `TLS unknown` when:**

- its start line had no `gwops` object (another shipper, gwops without Gatorcast delivery, a gwops that does not add the object yet, or a line gwops shipped without it after an enrichment failure);
- the `gwops` object was invalid. Gatorcast ignores it, logs one `classify.gwops_rejected` warning with a reason code and the `conn_id` (never a value), and the UI shows it exactly as an absent object ("No gwops data");
- gwops matched no web app at that address on its gateway, or had not yet read the tenant's web apps (`match: none`);
- gwops found more than one web app at that address (`match: ambiguous`).

The `scheme=unknown` and `upstream=unknown` filters match all four cases. The system page's block tells them apart, except that a rejected object reads as "No gwops data". There is no retroactive fill: connections that arrived without TLS data stay unknown, and a later start line cannot fill them.

The app name, managed marker and gateway id are display and export detail only. The system stays the `resource_address`, which is always the resource's address and never an alias a client used.

### What is stored, and what is never stored (web)

Stored per web request: `request_id`, `conn_id`, the system (`resource_address`, joined from the connection), user id and username, `requested_at`, method, the stored URL, status code, outcome (`completed` or `failed`), and `User-Agent` (stored, never displayed). Per connection: the resource type and, when present and valid, the `gwops` snapshot (match, gateway id, app name, managed flag, both TLS modes and ports).

**Never stored, and never logged:** `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, every other request header, all response headers, `remote_addr`, request and response bodies, and client-sent identity headers such as `X-Twingate-User`. Identity is the envelope `user.username`. `Kubectl-Command` and `Kubectl-Session` headers are discarded on web requests, so a web client cannot steer grouping. Raw audit lines are never logged, and no URL, masked or not, is logged.

**The stored URL:**

- The URL is normalized as for kubectl: fragment dropped, path percent-decoded once, repeated `/` collapsed, trailing `/` removed, and an encoded `?` or `#` cuts the path and drops the query.
- **The path is stored as is.** There is no `proxy` truncation, no query allowlist and no path masking.
- Query keys are kept in plaintext when they are at most 64 characters of letters, digits, `_`, `.`, `[`, `]` and `-`; other keys are masked.
- **Every query value is masked.** At most a quarter of the characters (never more than four) are kept from the start and end, followed by the length: `token=ab…6(12)`. A value of 1 to 3 characters reveals only its length. A query item with no `=` (`/callback?<token>`) is masked whole, and so is a padded base64 token such as `?dGVzdA==`. Revealed characters outside letters, digits, `.`, `_`, `~` and `-` show as `*`.
- The stored URL is capped at 4,096 characters, after masking.

| Request URL | Stored |
| --- | --- |
| `/report?month=09` | `/report?month=…(2)` |
| `/login?token=abc123def456` | `/login?token=ab…6(12)` |
| `/search?q=quarterly+report&page=2` | `/search?q=qu…rt(16)&page=…(1)` |
| `/items/42` | `/items/42` |
| `/reset/<token>` | `/reset/<token>` (path not masked) |

The HTTP method is recorded for any token that starts with a letter, continues with letters, digits, `_` or `-`, and is at most 24 characters, with its case preserved, so WebDAV and lowercase methods produce rows.

### Accepted risks and limits

- **Paths are not masked.** A token embedded in a path is stored in full in the plaintext database and shown to every UI user in search results, the visit view and CSV exports, and `q` search matches it. This includes password-reset and invite links (`/reset/<token>`), share and download capability URLs, magic-login JWTs, `;jsessionid=` values and UUID capability ids. The database stays plaintext even when `ENCRYPTION_ENABLED` is on, so anyone who can read the volume reads them. If that is not acceptable, keep tokens out of paths in the app, or shorten `RETENTION_DAYS`.
- **Masking is not encryption.** Masked values reveal up to a quarter of each value plus its length. A single-padded base64 token (`?dGVzdDE=`) looks like a key with an empty value and is not masked, and a token that fits the key pattern in key position (`?<token>=x`) is kept as a key.
- **Web traffic is not evaluated by detection rules.** No finding is ever produced for a web request. Searches that filter on findings return no web rows and say so.
- **Web requests stored before 0.5.0 stay kubectl.** They keep their old URLs and any `kube-api` findings until retention removes them.

### Securing the gwops hop

- **Use TLS between gwops and Gatorcast.** gwops forwards the Gateway's request lines byte for byte and redacts nothing. Those lines hold the client's `Authorization`, `Cookie` and `X-Api-Key` values, the response's `Set-Cookie` values and the full URL including any query string (an OAuth `?code=`, for example), and gwops keeps them at rest in its spool. Gatorcast reads and stores none of them, but they cross the wire on the way to `/ingest`. The gwops demo compose network uses plain HTTP; do not copy that. Point gwops at an `https://` URL on your reverse proxy (see [Deployment Behind a Reverse Proxy](#deployment-behind-a-reverse-proxy)).
- **Forged lines.** Anyone holding `INGEST_TOKEN`, or with network access to the syslog port, can forge a start line carrying a `gwops` object and mislabel a connection as `HTTPS` or `Verified`. Separately, the Gateway logs upstream TLS errors without escaping them, so an upstream certificate whose DNS name contains `\n{...}` produces a standalone line that gwops cannot tell from a Gateway line and ships if it matches. Anyone who controls an upstream app's certificate can therefore forge ingest lines. First-write-wins protects an existing connection from being retyped or relabelled; forged request or recording lines on other connection ids cannot be told apart from real ones. Fixing this needs a change in the Gateway or gwops.
- **Keep `LOG_LEVEL` at `info` in production.** At `debug`, the SQLite driver's own log lines include bound parameters, which can include stored URLs and usernames.

---

## Encryption at Rest

Opt-in. When enabled, `.cast` recordings are encrypted on the volume with AES-256-GCM, using a key derived from `GATORCAST_MASTER_KEY`. The search sidecars (`<conn_id>.txt.enc`) are encrypted under an independent key derived from the same master key. Sealed recordings are decrypted in memory for playback.

To enable it:

1. Generate a key: `openssl rand -base64 32`
2. Put `GATORCAST_MASTER_KEY=<that value>` in `.env`.
3. In `docker-compose.yml`, change `ENCRYPTION_ENABLED: "false"` to `"true"`. A value in `.env` does not override it.
4. Run `docker compose up -d`.

If encryption is enabled and the key is missing or invalid, the service refuses to start.

Limits to know before you rely on it:

- **In-progress recordings are plaintext on disk** until they seal. Lower `SESSION_MAX_IDLE_SECONDS` to shorten that window for abandoned sessions.
- **The metadata database is not encrypted** (usernames, system addresses, finding labels).
- **Fresh-start only.** Enabling it does not encrypt existing recordings.
- **Losing the key loses the recordings.** There is no key rotation.

Details: [ARCHITECTURE.md](ARCHITECTURE.md#encryption-at-rest).

---

## Retention

A purge runs every 24 hours with two independent policies:

- **Age (`RETENTION_DAYS`, default 90).** Deletes sessions whose start time is older than the cutoff, along with their `.cast` file, search sidecar and findings. Sessions with no start time are not age-purged. The same cutoff deletes kubectl `api_requests` (with their findings) and `connections`. An API request is purged when either its Gateway timestamp or the time Gatorcast stored it is older than the cutoff, so a forged future timestamp cannot keep a row forever. Connections are purged on Gatorcast's own timestamps only, by last activity: a connection is removed only when its last start line or newly stored request is past the cutoff and no stored request still refers to it, so a long-lived keep-alive connection is not purged while it is active. Web requests are purged like kubectl requests, and their configured-TLS data goes with their rows. There is no separate setting for API or web activity.
- **Size (`RETENTION_MAX_GB`, default off).** When total recording size is over the cap, deletes the oldest completed sessions until it is under. It counts recording bytes only and never deletes API rows or connections.

`0` disables a policy. To keep everything, set `RETENTION_DAYS=0` and leave `RETENTION_MAX_GB=0`. See [ARCHITECTURE.md](ARCHITECTURE.md#retention).

---

## Deployment Behind a Reverse Proxy

The intended production layout is Gatorcast behind **NPMplus + CrowdSec** (or any reverse proxy):

- The proxy terminates TLS and forwards HTTP traffic to Gatorcast on port `8080`.
- The syslog TCP port (`6514`) is **not** published through the proxy; it is for direct internal access only.

**Body-size limit at the proxy:** Gatorcast's `/ingest` endpoint intentionally accepts large request bodies (asciicast lines are multi-KB; a batch of many lines can be several MB). Configure a generous but bounded `client_max_body_size` (or equivalent) at the proxy level — for example, `64m` or `128m` — to cap potential abuse while allowing legitimate batched payloads. Do not set a tight limit (e.g. 1m) that would truncate real batches.

**Syslog TCP interface binding:** In `docker-compose.yml` the syslog port is bound to loopback by default:

```yaml
ports:
  - "127.0.0.1:6514:6514"   # syslog TCP (internal interface only)
```

If your shipper runs on a different host, change `127.0.0.1` to the host's internal/VPN interface IP so only authorized shippers on that network can reach it. Never bind it to `0.0.0.0` in a production environment.

---

## Updating

Gatorcast uses a floating `latest` tag in docker-compose. To update:

```bash
docker compose pull
docker compose up -d
```

The `gatorcast-data` named volume (SQLite database + `.cast` files) persists across container replacements. Schema changes are applied automatically on start; there is no manual migration step.

### Upgrading to the kubectl activity release

**Back up the `/data` volume before upgrading** (see [Where is my data?](#where-is-my-data)). On first start the service runs a one-time database migration (`PRAGMA user_version` 0 to 1). Once applied, it never runs again. There is no down-migration: to roll back, restore your backup.

The migration removes historical *start-only* session rows from the sessions list. These are rows that never received a recording chunk: `provisional` or `error` status, zero chunks, no `.cast` path, and zero bytes. Before this release, every `Authenticated connection` line created a visible session, so API-only kubectl connections and SSH transport failures showed up as empty `provisional` or `error` sessions. Those rows are moved into the hidden `connections` table. Old SSH transport-failure rows cannot be told apart from API-only rows, so they are moved too. **This is expected.** Session counts on the dashboard and systems list can drop after the upgrade.

A row is **kept** if a `<conn_id>.cast` file or `<conn_id>.txt.enc` sidecar exists for it on disk, even when its metadata looks empty. Such a row stays in the sessions list, is re-adopted at startup, and is purged by retention as normal.

The migration only covers sessions. Past API requests were not stored before this release, so kubectl activity starts from the upgrade.

### Upgrading to 0.4.0 (unified search)

There is no manual step and no `PRAGMA user_version` change. On first start the service:

- builds four new indexes (three on `api_requests`, one on `sessions`). On a large `api_requests` table the first boot takes longer while they build.
- adds a `sessions.sealed_terminal` column. Sessions sealed before the upgrade have no value there and are treated as terminally sealed, so a late chunk never overwrites them.

Back up the `/data` volume first, as for any upgrade. Old `/search` links keep working; see [Old `/search` links](#old-search-links) for the exceptions.

### Upgrading to 0.5.0 (web apps)

There is no manual step and no `PRAGMA user_version` change. On first start the service adds the new columns in place and replaces five `api_requests` indexes with ones that lead with the request kind, so the first boot takes longer on a large `api_requests` table while they build. Back up the `/data` volume first, as for any upgrade.

What to expect afterwards:

- **Existing `api_requests` rows stay `kubectl`.** That includes any web traffic Gatorcast stored before the upgrade. Those rows keep their old URLs (the Kubernetes query allowlist, the `proxy` cut) and any `kube-api` findings, and they show as kubectl activity until retention removes them. New web traffic is stored as web.
- **No TLS badges until gwops sends the `gwops` object.** Web connections read `TLS unknown` until a gwops that adds the object, with Gatorcast delivery configured, authenticates them. Earlier connections stay unknown.
- **The CSV has 22 columns.** The first 15 are unchanged; a script that reads the export by position keeps working, and one that reads by header sees seven new columns on the right.
- **The systems list columns changed.** "API requests" and "Last API request" are now **Requests** and **Last request**.
- **Use TLS between gwops and Gatorcast** before you start shipping web traffic. See [Securing the gwops hop](#securing-the-gwops-hop).

To pin to a specific version, change the image tag in `docker-compose.yml`:

```yaml
image: ghcr.io/twingate-solutions/gatorcast:v0.5.0
```

---

## Troubleshooting

### Container exits at startup

Check `docker compose logs gatorcast`. Two configurations stop the service on purpose:

- `ENCRYPTION_ENABLED=true` with `GATORCAST_MASTER_KEY` missing or not a base64 32-byte value. It refuses to boot rather than store recordings in the clear. Generate a key with `openssl rand -base64 32`.
- `KUBECTL_ACTIVITY_GAP_SECONDS` and `KUBECTL_ACTIVITY_MAX_SECONDS` not satisfying `0 < gap <= max`. The error names both values.

### Sessions stuck in "provisional" (in-progress) status

A recording is provisional (shown as "in progress") while it is still recording; its `.cast` is on disk and playable throughout. It seals to complete when the Gateway sends its final flush (`message == "session finished"`), or — as a backstop — after `SESSION_MAX_IDLE_SECONDS` of silence. If sessions remain provisional indefinitely:

- Verify your shipper is forwarding log lines during active sessions (check rsyslog/Docker syslog driver stats). A recording that is provisional but *playable* just hasn't received its "session finished" flush yet.
- Confirm the Gateway actually ends the session (its recorder emits "session finished" on `Stop()`). If the shipper drops that line, the recording seals via the backstop after `SESSION_MAX_IDLE_SECONDS`; lower that value to seal sooner, or raise it if you hold sessions idle for very long.
- **Connected but no recording?** A connection that authenticated but never delivered a recording chunk or an API audit (e.g. its chunks were all dropped — see the big/chatty-session note below) is a hidden pending connection, not an "in progress" session. At the `SESSION_MAX_IDLE_SECONDS` backstop it becomes a visible `error` session. A connection that only makes API requests never becomes a session; its requests appear under kubectl activity. Watch for `event=normalize.drop reason=unparseable length=…` in the logs — a `length` at/near 49152 means the transport is splitting your chunks (journald `LineMax`). If a real recording does arrive late, the errored row automatically recovers.
- On restart, Gatorcast re-adopts provisional rows that have an on-disk `.cast` as in-progress (continuation chunks keep appending); a provisional row with no `.cast` older than `IDLE_TIMEOUT_SECONDS` is an abandoned start and is removed.

### Big or "chatty" sessions not recording (`btop`, `top`, `watch`, verbose output)

If ordinary sessions record fine but a session that ran a **full-screen TUI or produced a firehose of output** stays "in progress" with no recording, the culprit is almost always your **log transport**, not Gatorcast — most commonly **systemd-journald limits** when shipping via journald (INGESTION_RECIPES.md §2.1):

- **`LineMax` (default 48 KB):** journald splits any log line longer than this, so a large asciicast chunk arrives as unparseable fragments and is dropped (`event=normalize.drop reason=unparseable`). The recording never assembles.
- **Rate limiting:** a rapidly repainting TUI can exceed journald's `RateLimitBurst`, so entries are dropped outright (`Suppressed N messages`), leaving gaps.

Quick fixes: raise `LineMax` (e.g. `LineMax=4M`) and relax rate limiting (`RateLimitBurst=0`) in `/etc/systemd/journald.conf`, then restart `systemd-journald` **and** your shipper. For recording TUIs routinely, prefer the **file-tail transport (§2.4)** — it has neither limit. Full detail and a diagnosis command are in [INGESTION_RECIPES.md](INGESTION_RECIPES.md) §2.1. (UDP syslog has the same truncation problem — always ship over TCP or HTTP.)

### Nothing showing up in the UI

1. **Check `INGEST_TOKEN`:** Send a test `curl` request (see [INGESTION_RECIPES.md](INGESTION_RECIPES.md) §8). A 401 response means the token does not match.
2. **Two-stage recording filter:** A line is a recording chunk only when `logger == "gateway.audit"` AND the `asciicast` field is non-null. `gateway.audit` lines without an `asciicast` field and with the message `API request completed` or `API request failed` are stored as kubectl activity metadata, not recordings. They appear under the system's kubectl activity table and as kubectl commands in search (`type=kubectl`), or, for a web-app connection, in the Web activity table and as web connections in search (`type=web`). They never appear in the session list. Other `gateway.audit` messages are dropped by design.
3. **Check the shipper connection:** For syslog TCP, confirm the shipper's IP/port settings match the binding. For HTTP, check that the shipper sends a valid `Authorization: Bearer` header and a body of one JSON object per line (any content type other than `application/json` is read that way), or a JSON object/array with `Content-Type: application/json`.
4. **Session-start event:** The UI groups sessions by target system (`resource_address`). If the Gateway does not emit an `"Authenticated connection"` line for a session, the session will appear in an "unknown" bucket.
5. **kubectl or web activity missing for a cluster or app:** API audit lines carry no `resource_address`. The system is joined from the `"Authenticated connection"` line by `conn_id`, so that line must reach Gatorcast too. Requests whose connection start was never seen appear under the "unknown" system.
6. **A web app shows no requests:** a `WEB_APP` connection with no requests expires hidden (it is a browser pre-connect or a refused tunnel), and the Gateway writes no line for a downstream TLS handshake failure or a rejected token. Check that real requests reach the Gateway and that its request lines reach Gatorcast.
7. **A web app shows `TLS unknown`:** this is the normal state unless gwops adds its `gwops` object to the start line with Gatorcast delivery configured. Check the logs for `classify.gwops_rejected` (the object was malformed; the warning carries a reason code), and on gwops check `/status` `shipper.enrich_failed` and `shipper.enrichment`. See [Configured TLS](#configured-tls).
8. **Web requests under the Kubernetes badge, or kubectl rows that look like web traffic:** requests stored before the 0.5.0 upgrade stay `kubectl` until retention removes them. See [Upgrading to 0.5.0](#upgrading-to-050-web-apps).

### Syslog framing issues

Gatorcast supports both RFC 6587 octet-counting (`<length> <msg>`) and newline-delimited framing, auto-detected per message. If you see log lines arriving garbled:

- Ensure your shipper is configured for TCP (not UDP). UDP will truncate multi-KB asciicast lines.
- The Docker syslog driver uses octet-counting by default with TCP; no extra configuration is needed.
- rsyslog `omfwd` over TCP can be configured with `TCP_Framing="octet-counted"` in the output action.

### Where is my data?

All data lives in the `gatorcast-data` named Docker volume, mounted at `/data` inside the container:

- SQLite database: `/data/gatorcast.db` (sessions, connections, findings, and kubectl and web request metadata)
- Recording files: `/data/casts/<conn_id>.cast`
- Search sidecars: `/data/casts/<conn_id>.txt.enc`

Back up the whole volume, not just one file: the database and the `.cast` files belong together, and the database runs in WAL mode. Stop the container first (`docker compose stop`) for a consistent copy. Back up before every upgrade.

To inspect or back up:

```bash
# List volume location on the host. The prefix is your compose project name
# (normally the directory name); `docker volume ls` shows the exact name.
docker volume inspect gatorcast_gatorcast-data

# Open a shell to browse
docker run --rm -it -v gatorcast_gatorcast-data:/data alpine sh
```

---

## Offline Note

All frontend assets are vendored locally under `src/gatorcast/web/static/`:

- asciinema-player 3.8.0 (Apache-2.0 / MIT)
- htmx 2.0.4 (0BSD)
- Alpine.js 3.14.8 (MIT)

Gatorcast makes zero external network requests at runtime. There are no CDN dependencies, no web fonts loaded from external origins, and no external JavaScript. It operates fully air-gapped once the image is pulled.

---

## Out of Scope (v1)

The following are explicitly out of scope for this release and will not be added without a design discussion:

- Auto-following (live-tailing) replay of an in-progress session — in-progress recordings **are** playable, but the player shows a snapshot; reload to see output appended since. True streaming/auto-append is out of scope.
- Per-request search rows for kubectl or web activity — search returns commands and web connections, and requests appear only inside them
- Detection rules for web traffic, and an HTTP-status filter for web search
- A stored command rollup, result totals, and a "previous page" link in search
- Alert dispatch (email/webhook/Slack) for findings — detection runs live (on every append) and findings are surfaced immediately, but push/alert delivery is a later consumer
- SSO or multi-user RBAC (the current auth is single-operator HTTP Basic)
- Encryption key rotation, and encryption of the metadata database
- Object-storage offload for cold recordings
- SSH/VM gateway journald tailing (Gatorcast is push-only)

---

## License

Gatorcast is licensed under the [Apache License 2.0](LICENSE). It is provided on an "AS IS" basis, without warranties or conditions of any kind — see the disclaimer at the top of this README and Sections 7 and 8 of the license.
