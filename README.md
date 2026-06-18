# Gatorcast

Self-hosted, single-container service for **Twingate Identity Firewall Gateway session recordings**. The Twingate Gateway records interactive privileged sessions (`kubectl exec`, SSH shells) as asciicast v2 fragments and emits them via structured JSON audit logs. Twingate's reference pipeline ships those fragments to object storage but does not reassemble them into sessions or provide a browse/replay UI. Gatorcast fills that gap: it receives the Gateway's log lines via push (HTTP POST or syslog TCP), demultiplexes concurrent sessions by `conn_id`, reassembles each into a complete asciicast v2 document, stores it, and serves a lightweight web UI to browse **systems → sessions → replay** in a locally vendored asciinema player. All recordings stay on your infrastructure.

---

## Architecture

```text
  Twingate Gateway host (k8s pod OR SSH/VM)
  emits gateway.audit JSON (asciicast v2 chunks) to stdout/stderr
        │  push (operator's choice of shipper)
        │   • rsyslog omhttp  → HTTP POST /ingest
        │   • Docker syslog driver / rsyslog omfwd → syslog TCP
        │   • curl (testing)  → HTTP POST /ingest
        ▼
┌──────────────────────── Gatorcast (single FastAPI container) ───────────────────────┐
│  Ingest front doors                                                            │
│    • POST /ingest        (NDJSON over HTTP, bearer-token auth)                  │
│    • syslog TCP listener (octet-framed; strips <PRI> envelope)                  │
│        │  raw line → normalize → JSON object                                    │
│        ▼                                                                        │
│  Classify & filter                                                              │
│    • logger=="gateway.audit" AND asciicast!=null → recording chunk              │
│    • logger=="gateway" "Authenticated connection" → session start + target      │
│    • (close event if present) → finalize signal                                 │
│        ▼                                                                        │
│  Per-conn_id assembler (in-memory buffers)                                      │
│    • append asciicast chunks, ordered by asciicast_sequence_num                 │
│    • finalize on close-event OR idle timeout (APScheduler):                     │
│        concat ALL chunks → parse asciicast → write .cast → complete row         │
│        ▼                                                                        │
│  Storage:  SQLite (WAL) metadata  +  /data/casts/<conn_id>.cast (named volume) │
│  Retention purge (APScheduler, age/size)                                        │
│        ▲                                                                        │
│  Web UI (FastAPI + Jinja2 + HTMX, vendored asciinema player, UI auth)          │
│    /systems → /systems/{addr} → /sessions/{id} → /sessions/{id}/cast           │
└────────────────────────────────────────────────────────────────────────────────┘
```

**Key points:**

- Single FastAPI process: ingestion, assembly, storage, scheduler, and UI all in one container.
- State: SQLite (WAL mode) for metadata; a named Docker volume for `.cast` files.
- APScheduler drives two background jobs: idle-timeout finalizer and daily retention purge.
- Push-based: Gatorcast exposes endpoints and waits. It never reaches back into the Gateway, Docker, or Kubernetes.
- All frontend assets are vendored locally. No CDN or external JS at runtime.

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

Sessions appear once the shipper begins forwarding Gateway logs and at least one session completes (or the idle timeout fires).

---

## Configuration

All settings are environment variables. Secrets (`INGEST_TOKEN`, `UI_AUTH_*`) should live in `.env` (which is in `.gitignore`). Operational settings can be set directly in the `environment:` block of `docker-compose.yml`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HTTP_PORT` | `8080` | FastAPI HTTP port (UI + `POST /ingest`) |
| `SYSLOG_TCP_PORT` | `6514` | Syslog TCP listener port. `0` disables the listener. |
| `DATA_DIR` | `/data` | Volume root for the SQLite database and `.cast` files |
| `IDLE_TIMEOUT_SECONDS` | `120` | Finalize a session after this many seconds of silence from the shipper |
| `RETENTION_DAYS` | `90` | Purge sessions older than this many days. `0` keeps forever. |
| `RETENTION_MAX_GB` | `0` | Optional total `.cast` size cap in GB. `0` disables size-based purge. |
| `LOG_LEVEL` | `info` | structlog level (`debug`, `info`, `warning`, `error`) |
| `INGEST_TOKEN` | *(see .env.example)* | Bearer token the shipper presents to `POST /ingest` |
| `UI_AUTH_USERNAME` | `admin` | Username for web UI HTTP Basic auth |
| `UI_AUTH_PASSWORD` | *(see .env.example)* | Password for web UI HTTP Basic auth |
| `ENCRYPTION_ENABLED` | `false` | Encrypt `.cast` recordings at rest (AES-256-GCM). Opt-in. |
| `GATORCAST_MASTER_KEY` | *(unset)* | Base64 32-byte key. **Required** when encryption is enabled. Also keys the search sidecars. |
| `DETECTION_ENABLED` | `true` | Run dangerous-command + secret-exposure detection at finalize (produces findings). |
| `BACKFILL_ON_STARTUP` | `true` | On startup, index + detect existing finalized recordings that lack a search sidecar. |
| `SEARCH_PAGE_SIZE` | `50` | Default number of search results per page. |
| `SEARCH_REGEX_MAX_CANDIDATES` | `2000` | Max sidecars scanned per keyword/regex content search (cost / ReDoS bound). |

---

## Search & Automated Detection

Beyond browsing systems → sessions → replay, Gatorcast indexes and scans every recording at finalize so auditors can find sessions fast and have dangerous activity flagged automatically.

- **Dashboard** (`/dashboard`, the site root) — total and flagged session counts, severity/category breakdowns, and top users/systems, all server-rendered (offline, no external JS). It is **time-windowed** with a 7 / 30 / 90 / All-time toggle (default 30 days). Every breakdown is a **drill-down link**: a severity badge opens search filtered to that exact highest severity, a category opens search for that category, a top user opens that user's sessions, and a top system opens its session list — each carrying the active window so the figures and results line up.
- **Search** (`/search`) — filter by user, system, status, date range, duration, severity (at-or-above), finding category, a dangerous-command rule multiselect, a free-text **keyword**, and a custom **regex**. Results paginate and the filters live in the URL (shareable). **CSV export** (`/search/export.csv`) writes session metadata plus a finding summary.
- **Systems index** (`/systems`) — a **Findings column** flags each system with its highest-severity badge and total finding count (or `—` if clean), so you can see at a glance which systems to look into.
- **Findings** — a built-in rule set scans each reassembled recording for **dangerous commands** (e.g. `rm -rf`, pipe-to-shell, `dd of=/dev/…`, `mkfs`, fork bombs, `kubectl delete`, reverse shells, history clearing, privilege changes) and **on-screen secrets** (AWS keys, private-key blocks, GitHub/Slack/Vault tokens, JWTs, inline `PASSWORD=`/`TOKEN=` assignments). Findings expose only the **rule label, severity, and replay offset** — never the matched text.
- **Seek-to-finding** — clicking a finding on the session page jumps the asciinema player to that moment. The jump also works as a **deep link** (`/sessions/{id}?t=<seconds>`): opening or refreshing that URL loads the player already positioned at the timestamp (and autoplaying), so a "jump" from the search results lands in the right place.

**How content search works (no full-text index).** At finalize, Gatorcast writes an ANSI-stripped plaintext rendering of the recording to a per-session **sidecar** file (`<conn_id>.txt.enc`). When `ENCRYPTION_ENABLED=true`, the sidecar is encrypted with a key derived independently from `GATORCAST_MASTER_KEY` (distinct HKDF context) — losing the key makes sidecars unrecoverable too. Keyword/regex search is **scan-on-demand**: metadata filters and precomputed findings narrow the candidate set, then only those sidecars are decrypted and scanned in a worker thread, bounded by `SEARCH_REGEX_MAX_CANDIDATES`. There is **no FTS5 and no SQLCipher**; the metadata database stays plaintext.

> **The `.txt.enc` sidecars are secret-grade.** They hold on-screen plaintext, which can include typed secrets. They live on the same auth-gated volume as the `.cast` files, are encrypted under the same master key when encryption is on, and are deleted by retention alongside the recording — treat them at the same trust level as the recordings.

**Detecting on pre-existing recordings.** With `BACKFILL_ON_STARTUP=true` (default), a throttled background pass on startup builds sidecars + findings for finalized recordings that predate this feature, so search and flags work on your whole history. It is idempotent — already-indexed sessions are skipped.

---

## Encryption at Rest

Gatorcast can encrypt the sensitive bulk of the data — the `.cast` recordings — on the volume. Recordings capture full on-screen content, including typed tokens and passwords, so encrypting them protects against a stolen disk, a leaked backup, or a volume snapshot.

**What is and isn't protected:**

| Scenario | Protected? |
| --- | --- |
| Stolen disk / laptop / leaked backup / volume snapshot | **Yes** — `.cast` content is ciphertext. |
| Another process reading the live `/data` volume | **Yes for recordings** (ciphertext); **no for metadata** (the DB is plaintext). |
| Compromise of the running app process | **No** — the key is in memory so the app can decrypt for replay. Inherent. |
| Metadata (usernames, system addresses, shell user) | **No** — the metadata database stays plaintext. |

This is the honest meaning of "at rest" for a service that must decrypt to replay. Encrypting the metadata DB would require SQLCipher, which this project deliberately avoids.

**How it works:** `.cast` files are encrypted with AES-256-GCM (per-file random nonce, the connection id bound in as additional authenticated data). The key on disk is HKDF-derived from `GATORCAST_MASTER_KEY` — the raw env value is never used directly. The metadata database is unchanged.

**Enabling it:**

1. Generate a master key:

   ```bash
   openssl rand -base64 32
   ```

2. Set both variables (in `.env`, or inject `GATORCAST_MASTER_KEY` from a secrets manager):

   ```bash
   ENCRYPTION_ENABLED=true
   GATORCAST_MASTER_KEY=<the base64 value from step 1>
   ```

3. Start the service. If encryption is enabled but the key is missing or invalid, Gatorcast **refuses to boot** (fail-closed) rather than silently storing recordings in the clear.

**Pulling the key from a cloud vault → env:** The app only ever reads the key from the environment, so any vault that can inject an env var works:

- **AWS Secrets Manager / Parameter Store** — reference the secret in an ECS task definition `secrets:` block so it lands as `GATORCAST_MASTER_KEY`.
- **HashiCorp Vault** — use a Vault agent or an entrypoint wrapper that exports `GATORCAST_MASTER_KEY` before launching the process.
- **Docker Compose secrets** — mount the secret and export it to the env in your entrypoint.

**Important limitations:**

- **Fresh-start only.** Enabling encryption does **not** migrate existing unencrypted recordings. Start with a clean `/data` (or expect previously-written plaintext files to remain plaintext).
- **Losing the key means losing the recordings.** There is no recovery path and no key rotation in this version.
- **The metadata database is not encrypted.**

---

## Shipper Recipes

Gatorcast is push-based. You configure your existing log-shipping infrastructure to forward the Gateway's stdout/stderr to Gatorcast. Three common patterns follow.

### rsyslog omhttp (HTTP POST)

On the host running rsyslog, add a configuration file to batch and POST the Gateway's log lines to `/ingest` with a bearer token:

```conf
# /etc/rsyslog.d/60-gatorcast.conf
module(load="imjournal" StateFile="/var/lib/rsyslog/imjournal.state")
module(load="omhttp")

# Match only the Gateway container's journal unit (adjust as appropriate).
if $programname == "gateway" then {
    action(
        type="omhttp"
        server="gatorcast.example.internal"
        serverport="8080"
        httpcontenttype="application/x-ndjson"
        restpath="ingest"
        usehttps="off"
        action.sendResendOnError="off"
        action.execOnlyWhenPreviousIsSuspended="off"
        template="RSYSLOG_FileFormat"
        httpHeaders="Authorization: Bearer YOUR_INGEST_TOKEN_HERE"
        batch="on"
        batch.maxsize="100"
        batch.timeout="5000"
    )
}
```

Replace `gatorcast.example.internal`, `8080`, and `YOUR_INGEST_TOKEN_HERE` with your actual values. Restart rsyslog after editing.

### Docker syslog driver (syslog TCP)

Run the Twingate Gateway container with the Docker syslog log driver pointed at Gatorcast's syslog TCP port. Docker uses octet-framed TCP by default, which is the framing Gatorcast expects.

```bash
docker run \
  --log-driver=syslog \
  --log-opt syslog-address=tcp://<gatorcast-host>:6514 \
  --log-opt syslog-format=rfc5424 \
  <gateway-image>
```

Or in a Compose file:

```yaml
services:
  gateway:
    image: <gateway-image>
    logging:
      driver: syslog
      options:
        syslog-address: "tcp://<gatorcast-host>:6514"
        syslog-format: rfc5424
```

The syslog port carries no per-message authentication; keep it bound to an internal interface (see the Deployment section below).

### curl (smoke testing)

For a quick one-shot test from a file of Gateway log lines:

```bash
curl -s -X POST http://localhost:8080/ingest \
  -H "Authorization: Bearer $INGEST_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @gateway.log
```

Or to stream a live file:

```bash
tail -F gateway.log | while IFS= read -r line; do
  curl -s -X POST http://localhost:8080/ingest \
    -H "Authorization: Bearer $INGEST_TOKEN" \
    -H "Content-Type: text/plain" \
    --data-binary "$line"
done
```

This is for smoke testing only; use rsyslog or the Docker syslog driver for production.

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

## Security Model

| Layer | Mechanism |
| --- | --- |
| `/ingest` endpoint | `Authorization: Bearer <INGEST_TOKEN>` checked with constant-time comparison. Missing or mismatched token → 401. |
| Web UI (all routes) | HTTP Basic auth on every UI and cast route. Credentials checked with constant-time comparison. No route is reachable unauthenticated (except `/healthz` and `/static/*`). |
| `.cast` file serving | Paths are confined to `casts_dir` with a `is_relative_to` check before serving, even though `conn_id` is already validated upstream. |
| Container privileges | Runs as a dedicated non-root system user (`uid 10001`). |
| Recording payloads | Never written to application logs. Session recordings may contain on-screen secrets (terminals, typed tokens). Treat all stored `.cast` files as secret-grade. |
| Syslog TCP | No per-message auth. Bound to loopback by default. Cap on concurrent connections (128) and idle connections (5-minute timeout) to limit resource exhaustion. |
| Insecure defaults | At startup, Gatorcast logs a warning for each secret still equal to a placeholder default. The service still boots, but the warning is prominent. |

**Access control summary:** Set strong, unique values for `INGEST_TOKEN`, `UI_AUTH_USERNAME`, and `UI_AUTH_PASSWORD`. Put Gatorcast behind a TLS-terminating reverse proxy. Do not expose the syslog port on a public interface.

---

## Retention

Two independent policies run daily (APScheduler):

1. **Age-based:** Sessions with a `started_at` older than `RETENTION_DAYS` days are deleted (row + `.cast` file). Sessions with no `started_at` are not age-purged (their age is unknown).
2. **Size-based:** If `RETENTION_MAX_GB > 0`, the oldest complete sessions are deleted until the total `.cast` size is under the cap.

Both policies are no-ops when disabled (`0`). Deleting a row and its `.cast` file is one logical operation; a missing file is tolerated and does not cause an error.

To keep recordings indefinitely, set `RETENTION_DAYS=0` and `RETENTION_MAX_GB=0` (the defaults for size are already `0`).

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

### Sessions stuck in "provisional" status

A session is provisional while its chunks are buffering in memory. It becomes complete when a close event arrives or `IDLE_TIMEOUT_SECONDS` of silence elapses. If sessions remain provisional indefinitely:

- Verify your shipper is forwarding log lines continuously during active sessions (check rsyslog/Docker syslog driver stats).
- Check whether the Gateway emits a connection-close log line. If it does not, the idle timeout is the only finalize signal; increase `IDLE_TIMEOUT_SECONDS` if sessions are very long.
- On restart, Gatorcast sweeps orphaned provisional rows: if a `.cast` file already exists it is recovered; otherwise stale empty rows are removed.

### Nothing showing up in the UI

1. **Check `INGEST_TOKEN`:** Send a test `curl` request (see Shipper Recipes). A 401 response means the token does not match.
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

- Live/streaming replay of in-progress sessions
- Per-keystroke live detection during ingestion (detection runs at finalize)
- Alert dispatch (email/webhook/Slack) for findings — findings are produced and surfaced; dispatch is a later consumer
- SSO or multi-user RBAC (the current auth is single-operator HTTP Basic)
- Object-storage offload for cold recordings
- SSH/VM gateway journald tailing (Gatorcast is push-only)
