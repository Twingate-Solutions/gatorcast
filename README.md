# Gatorcast

> **⚠️ Example project — provided as-is, with no support or warranty.** Gatorcast is published as a reference example to build from, not a supported product. Nothing here is guaranteed and no support is attached to it. It was developed with help from an LLM-based coding assistant. **Review the code and test it yourself before using it in any critical or production environment.** Your use is governed by the [Apache License 2.0](LICENSE), including its "AS IS", no-warranty (Section 7), and limitation-of-liability (Section 8) terms.

Self-hosted, single-container service for **Twingate Identity Firewall Gateway session recordings**. The Twingate Gateway records interactive privileged sessions (`kubectl exec`, SSH shells) as asciicast v2 fragments and emits them via structured JSON audit logs. Twingate's reference pipeline ships those fragments to object storage but does not reassemble them into sessions or provide a browse/replay UI. Gatorcast fills that gap: it receives the Gateway's log lines via push (HTTP POST or syslog TCP), demultiplexes concurrent sessions by `conn_id`, reassembles each into a complete asciicast v2 document, stores it, and serves a lightweight web UI to browse **systems → sessions → replay** in a locally vendored asciinema player. All recordings stay on your infrastructure.

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
| `RETENTION_DAYS` | `90` | Purge sessions older than this many days. `0` keeps forever. |
| `RETENTION_MAX_GB` | `0` | Optional total `.cast` size cap in GB. `0` disables size-based purge. |
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

The `gatorcast-data` named volume (SQLite database + `.cast` files) persists across container replacements. No migration step is required for patch and minor releases.

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
- **Provisional forever with no recording?** A session that authenticated but never delivered a single valid chunk (e.g. its chunks were all dropped — see the big/chatty-session note below) is marked `error` at the `SESSION_MAX_IDLE_SECONDS` backstop, so it won't sit "in progress" indefinitely. Watch for `event=normalize.drop reason=unparseable length=…` in the logs — a `length` at/near 49152 means the transport is splitting your chunks (journald `LineMax`). If a real recording does arrive late, the errored row automatically recovers.
- On restart, Gatorcast re-adopts provisional rows that have an on-disk `.cast` as in-progress (continuation chunks keep appending); a provisional row with no `.cast` older than `IDLE_TIMEOUT_SECONDS` is an abandoned start and is removed.

### Big or "chatty" sessions not recording (`btop`, `top`, `watch`, verbose output)

If ordinary sessions record fine but a session that ran a **full-screen TUI or produced a firehose of output** stays "in progress" with no recording, the culprit is almost always your **log transport**, not Gatorcast — most commonly **systemd-journald limits** when shipping via journald (INGESTION_RECIPES.md §2.1):

- **`LineMax` (default 48 KB):** journald splits any log line longer than this, so a large asciicast chunk arrives as unparseable fragments and is dropped (`event=normalize.drop reason=unparseable`). The recording never assembles.
- **Rate limiting:** a rapidly repainting TUI can exceed journald's `RateLimitBurst`, so entries are dropped outright (`Suppressed N messages`), leaving gaps.

Quick fixes: raise `LineMax` (e.g. `LineMax=4M`) and relax rate limiting (`RateLimitBurst=0`) in `/etc/systemd/journald.conf`, then restart `systemd-journald` **and** your shipper. For recording TUIs routinely, prefer the **file-tail transport (§2.4)** — it has neither limit. Full detail and a diagnosis command are in [INGESTION_RECIPES.md](INGESTION_RECIPES.md) §2.1. (UDP syslog has the same truncation problem — always ship over TCP or HTTP.)

### Nothing showing up in the UI

1. **Check `INGEST_TOKEN`:** Send a test `curl` request (see [INGESTION_RECIPES.md](INGESTION_RECIPES.md)). A 401 response means the token does not match.
2. **Two-stage recording filter:** Gatorcast only processes lines where `logger == "gateway.audit"` AND the `asciicast` field is non-null. API-audit lines (e.g. `kubectl logs` completions) emit `gateway.audit` lines without an `asciicast` field and are dropped by design. This is expected behavior.
3. **Check the shipper connection:** For syslog TCP, confirm the shipper's IP/port settings match the binding. For HTTP, check that the shipper sends `Content-Type: application/x-ndjson` or `text/plain` and a valid `Authorization: Bearer` header.
4. **Session-start event:** The UI groups sessions by target system (`resource_address`). If the Gateway does not emit an `"Authenticated connection"` line for a session, the session will appear in an "unknown" bucket.

### Syslog framing issues

Gatorcast supports both RFC 6587 octet-counting (`<length> <msg>`) and newline-delimited framing, auto-detected per message. If you see log lines arriving garbled:

- Ensure your shipper is configured for TCP (not UDP). UDP will truncate multi-KB asciicast lines.
- The Docker syslog driver uses octet-counting by default with TCP; no extra configuration is needed.
- rsyslog `omfwd` over TCP can be configured with `TCP_Framing="octet-counted"` in the output action.

### Where is my data?

All data lives in the `gatorcast-data` named Docker volume, mounted at `/data` inside the container:

- SQLite database: `/data/gatorcast.db`
- Recording files: `/data/casts/<conn_id>.cast`

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
- Alert dispatch (email/webhook/Slack) for findings — detection runs live (on every append) and findings are surfaced immediately, but push/alert delivery is a later consumer
- SSO or multi-user RBAC (the current auth is single-operator HTTP Basic)
- Object-storage offload for cold recordings
- SSH/VM gateway journald tailing (Gatorcast is push-only)

---

## License

Gatorcast is licensed under the [Apache License 2.0](LICENSE). It is provided on an "AS IS" basis, without warranties or conditions of any kind — see the disclaimer at the top of this README and Sections 7 and 8 of the license.
