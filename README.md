# Gatorcast

> **⚠️ Example project — provided as-is, with no support or warranty.** Gatorcast is published as a reference example to build from, not a supported product. Nothing here is guaranteed and no support is attached to it. It was developed with help from an LLM-based coding assistant. **Review the code and test it yourself before using it in any critical or production environment.** Your use is governed by the [Apache License 2.0](LICENSE), including its "AS IS", no-warranty (Section 7), and limitation-of-liability (Section 8) terms.

Self-hosted, single-container service for **Twingate Identity Firewall Gateway session recordings**. The Twingate Gateway records interactive privileged sessions (`kubectl exec`, SSH shells) as asciicast v2 fragments and emits them via structured JSON audit logs. Twingate's reference pipeline ships those fragments to object storage but does not reassemble them into sessions or provide a browse/replay UI. Gatorcast fills that gap: it receives the Gateway's log lines via push (HTTP POST or syslog TCP), demultiplexes concurrent sessions by `conn_id`, reassembles each into a complete asciicast v2 document, stores it, and serves a lightweight web UI to browse **systems → sessions → replay** in a locally vendored asciinema player. All recordings stay on your infrastructure.

Gatorcast also stores the Gateway's per-request Kubernetes API audit lines as allowlisted **kubectl activity** metadata (method, sanitized URL, status, user, and three request headers), grouped per user and cluster and shown next to the recordings. No recording or request body is ever involved. See [kubectl Activity](#kubectl-activity).

![Session replay — full session metadata, in-browser playback, and detection findings with jump-to-timestamp links](images/session_replay.png)

---

## A Quick Tour

**Dashboard** — session volume, flagged sessions, findings by severity and category, and the most active users and systems over a selectable time window:

![Dashboard with session totals, severity breakdown, findings by category, and top users/systems](images/dashboard.png)

**Systems → sessions** — recordings are grouped by target system (`resource_address`), with per-system findings badges; drill into a system to see every session with its user, duration, status, and risk:

![Systems list with session counts, findings badges, and last-seen timestamps](images/systems_list.png)

![Sessions for one system showing user, shell user, duration, status, and risk badges](images/sessions_list_one_system.png)

**kubectl activity** — the systems list also includes clusters that only have kubectl API activity. A system page adds a per-user kubectl activity table, and each row opens a page of that activity session's commands, with findings and links to any exec recordings. The dashboard has a kubectl API requests card. See [kubectl Activity](#kubectl-activity).

**Search** — filter by user, system, time, duration, status, finding severity/category or specific detection rules, plus full-content keyword/regex search; results link straight to each finding's timestamp in the replay, and any result set exports to CSV:

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
# Clone or download the repository, then enter the project directory.
# The docker-compose.yml pulls from GHCR — it never builds locally.
```

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

> **Important:** Gatorcast logs a warning at startup if any of these values are still equal to the placeholder defaults (`change-me-long-random`, `admin`, `change-me`). The service will still start, but do not run it on a network with those defaults in place.

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

All settings are environment variables. Secrets (`INGEST_TOKEN`, `UI_AUTH_*`) should live in `.env` (which is in `.gitignore`). Operational settings can be set directly in the `environment:` block of `docker-compose.yml`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HTTP_PORT` | `8080` | FastAPI HTTP port (UI + `POST /ingest`) |
| `SYSLOG_TCP_PORT` | `6514` | Syslog TCP listener port. `0` disables the listener. |
| `DATA_DIR` | `/data` | Volume root for the SQLite database and `.cast` files |
| `IDLE_TIMEOUT_SECONDS` | `120` | Idle-sweep cadence + startup-sweep cutoff. **Not** a finalize trigger (recordings seal on the Gateway's "session finished" flush). |
| `SESSION_MAX_IDLE_SECONDS` | `3600` | Idle backstop after this much silence: a recording **with data** is sealed (reopenable — a later chunk resumes it); a session that started but **never recorded** a valid chunk is marked `error`. **Must exceed the Gateway's flush interval** (a quiet-but-active session is chunkless until its first flush). Under encryption, also bounds how long a recording stays plaintext at rest. |
| `RETENTION_DAYS` | `90` | Purge sessions older than this many days. Also purges kubectl API requests (with their findings) and connections on the same cutoff. `0` keeps everything forever. |
| `RETENTION_MAX_GB` | `0` | Optional total `.cast` size cap in GB. `0` disables size-based purge. Counts `.cast` bytes only; API rows and connections are never touched by it. |
| `LOG_LEVEL` | `info` | structlog level (`debug`, `info`, `warning`, `error`) |
| `INGEST_TOKEN` | *(see .env.example)* | Bearer token the shipper presents to `POST /ingest` |
| `UI_AUTH_USERNAME` | `admin` | Username for web UI HTTP Basic auth |
| `UI_AUTH_PASSWORD` | *(see .env.example)* | Password for web UI HTTP Basic auth |
| `ENCRYPTION_ENABLED` | `false` | Encrypt `.cast` recordings at rest (AES-256-GCM). Opt-in. See [ARCHITECTURE.md](ARCHITECTURE.md#encryption-at-rest). |
| `GATORCAST_MASTER_KEY` | *(unset)* | Base64 32-byte key. **Required** when encryption is enabled. Also keys the search sidecars. |
| `DETECTION_ENABLED` | `true` | Run dangerous-command + secret-exposure detection live on every append and at seal (produces findings). See [SEARCH_AND_DETECTION.md](SEARCH_AND_DETECTION.md). |
| `BACKFILL_ON_STARTUP` | `true` | On startup, index + detect existing finalized recordings that lack a search sidecar. |
| `SEARCH_PAGE_SIZE` | `50` | Default number of search results per page. |
| `SEARCH_REGEX_MAX_CANDIDATES` | `2000` | Max sidecars scanned per keyword/regex content search (cost / ReDoS bound). |
| `KUBECTL_ACTIVITY_GAP_SECONDS` | `900` | Inactivity gap that splits one user's kubectl activity on a cluster into separate activity sessions. Must be greater than `0`. |
| `KUBECTL_ACTIVITY_MAX_SECONDS` | `14400` | Hard cap on the span of one activity session. Bounds long-lived clients (`k9s`, `kubectl get -w`, CI polling) that never leave a gap. Must be greater than or equal to `KUBECTL_ACTIVITY_GAP_SECONDS`. |

`KUBECTL_ACTIVITY_GAP_SECONDS` and `KUBECTL_ACTIVITY_MAX_SECONDS` must satisfy `0 < gap <= max`. If they do not, the service refuses to start and the error names both values. Both are listed in `.env.example`.

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
| `/systems` | Systems with recordings **and** clusters that only have kubectl activity, with a kubectl request count per system. |
| `/systems/{slug}` | The system's recordings, plus a **kubectl activity** table of per-user activity sessions. It shows 7 days at a time; use the "Older" and "Latest" links to page. At most 20,000 requests are read per page, and a notice appears if the cap is hit. |
| `/systems/{slug}/activity` | One activity session: its commands, each command's requests and findings, and links to exec recordings. No player is used. |
| `/dashboard` | A **kubectl API requests** card: total requests, flagged requests, and a severity breakdown, within the selected time window. |

kubectl activity is not part of search or CSV export.

### API findings

Each stored request is checked against built-in rules on its method and normalized path. A finding stores the rule, category (`kube-api`), severity and label only, never the URL. Findings show on the activity page and feed the dashboard card.

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
- If the decoded path contains an encoded `?` or `#` (`%3F`, `%23`), or is still percent-encoded after one decode, the URL is treated as ambiguous: the path is cut at that point and the whole query is dropped.
- Only allowlisted query keys are kept, and a key with a rejected value is dropped. Every other key is dropped outright, not kept blank. The allowlist is `labelSelector`, `fieldSelector`, `limit`, `continue`, `watch`, `timeout`, `timeoutSeconds`, `resourceVersion`, `resourceVersionMatch`, `allowWatchBookmarks`, `propagationPolicy`, `gracePeriodSeconds`, `dryRun`, `fieldManager`, `fieldValidation`, `force`, `follow`, `tailLines`, `sinceSeconds`, `previous`, `timestamps`, `pretty` and `orphanDependents`. Values must be at most 256 characters with no `;` and no control characters.
- **Exec/attach** URLs (`…/pods/<name>/exec` and `…/attach`) additionally keep only `container`, `stdin`, `stdout`, `stderr` and `tty`. Flags must be `true`, `false`, `1` or `0`, and `container` must be a valid DNS-label-style name. `command=` and every other parameter is always dropped, because it can hold secrets.
- Anything after a `/proxy` segment is dropped, along with the whole query, because the rest of the URL is forwarded to a backend. The one exception is `/nodes/<name>/proxy/exec`, `run` or `attach`, where that single segment is kept so `kube-node-proxy-exec` can still fire.

A request and its findings are written in one transaction, so a redelivered line never produces duplicate or partial rows. API rows are deduplicated by `request_id`.

### Retention

API requests, their findings and connections are purged on the same `RETENTION_DAYS` cutoff as sessions. There is no separate setting. A request row is purged when either its Gateway timestamp or the time Gatorcast stored it is older than the cutoff, so a forged future timestamp cannot keep a row forever. Connections are purged on Gatorcast's own timestamps only. `RETENTION_MAX_GB` counts `.cast` bytes only and never deletes API rows.

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

The `gatorcast-data` named volume (SQLite database + `.cast` files) persists across container replacements. No manual migration step is required.

### Upgrading to the kubectl activity release

**Back up the `/data` volume before upgrading** (see [Where is my data?](#where-is-my-data)). On first start the service runs a one-time database migration (`PRAGMA user_version` 0 to 1). Once applied, it never runs again.

The migration removes historical *start-only* session rows from the sessions list. These are rows that never received a recording chunk: `provisional` or `error` status, zero chunks, no `.cast` path, and zero bytes. Before this release, every `Authenticated connection` line created a visible session, so API-only kubectl connections and SSH transport failures showed up as empty `provisional` or `error` sessions. Those rows are moved into the hidden `connections` table. Old SSH transport-failure rows cannot be told apart from API-only rows, so they are moved too. **This is expected.** Session counts on the dashboard and systems list can drop after the upgrade.

A row is **kept** if a `<conn_id>.cast` file or `<conn_id>.txt.enc` sidecar exists for it on disk, even when its metadata looks empty. Such a row stays in the sessions list, is re-adopted at startup, and is purged by retention as normal.

The migration only covers sessions. Past API requests were not stored before this release, so kubectl activity starts from the upgrade.

To pin to a specific version, change the image tag in `docker-compose.yml`:

```yaml
image: ghcr.io/twingate-solutions/gatorcast:v0.1.0
```

---

## Troubleshooting

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

1. **Check `INGEST_TOKEN`:** Send a test `curl` request (see [INGESTION_RECIPES.md](INGESTION_RECIPES.md)). A 401 response means the token does not match.
2. **Two-stage recording filter:** A line is a recording chunk only when `logger == "gateway.audit"` AND the `asciicast` field is non-null. `gateway.audit` lines without an `asciicast` field and with the message `API request completed` or `API request failed` are stored as kubectl activity metadata, not recordings. They appear under the system's kubectl activity table, not in its session list. Other `gateway.audit` messages are dropped by design.
3. **Check the shipper connection:** For syslog TCP, confirm the shipper's IP/port settings match the binding. For HTTP, check that the shipper sends `Content-Type: application/x-ndjson` or `text/plain` and a valid `Authorization: Bearer` header.
4. **Session-start event:** The UI groups sessions by target system (`resource_address`). If the Gateway does not emit an `"Authenticated connection"` line for a session, the session will appear in an "unknown" bucket.
5. **kubectl activity missing for a cluster:** API audit lines carry no `resource_address`. The cluster is joined from the `"Authenticated connection"` line by `conn_id`, so that line must reach Gatorcast too. Requests whose connection start was never seen appear under the "unknown" system.

### Syslog framing issues

Gatorcast supports both RFC 6587 octet-counting (`<length> <msg>`) and newline-delimited framing, auto-detected per message. If you see log lines arriving garbled:

- Ensure your shipper is configured for TCP (not UDP). UDP will truncate multi-KB asciicast lines.
- The Docker syslog driver uses octet-counting by default with TCP; no extra configuration is needed.
- rsyslog `omfwd` over TCP can be configured with `TCP_Framing="octet-counted"` in the output action.

### Where is my data?

All data lives in the `gatorcast-data` named Docker volume, mounted at `/data` inside the container:

- SQLite database: `/data/gatorcast.db` (sessions, connections, findings, and kubectl API request metadata)
- Recording files: `/data/casts/<conn_id>.cast`

Back up the whole volume, not just one file: the database and the `.cast` files belong together, and the database runs in WAL mode. Stop the container first (`docker compose stop`) for a consistent copy. Back up before every upgrade.

To inspect or back up:

```bash
# List volume location on the host
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
- Search, CSV export, or alerting over kubectl activity — it is browsable per system and shown on the dashboard only
- Alert dispatch (email/webhook/Slack) for findings — detection runs live (on every append) and findings are surfaced immediately, but push/alert delivery is a later consumer
- SSO or multi-user RBAC (the current auth is single-operator HTTP Basic)
- Object-storage offload for cold recordings
- SSH/VM gateway journald tailing (Gatorcast is push-only)

---

## License

Gatorcast is licensed under the [Apache License 2.0](LICENSE). It is provided on an "AS IS" basis, without warranties or conditions of any kind — see the disclaimer at the top of this README and Sections 7 and 8 of the license.
