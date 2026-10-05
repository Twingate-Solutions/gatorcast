# Gatorcast — Architecture & Operations

Design and operational reference for Gatorcast: how data flows through the
service, how recordings are protected at rest, the security model, and how
retention works. For setup and day-to-day use, see the [README](README.md); for
forwarding Gateway logs in, see [INGESTION_RECIPES.md](INGESTION_RECIPES.md).

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
┌──────────────────────── Gatorcast (single FastAPI container) ───────────────────────┐
│  Ingest front doors                                                            │
│    • POST /ingest        (NDJSON over HTTP, bearer-token auth)                  │
│    • syslog TCP listener (octet-framed; strips <PRI> envelope)                  │
│        │  raw line → normalize → JSON object                                    │
│        ▼                                                                        │
│  Classify & filter                                                              │
│    • logger=="gateway.audit" AND asciicast!=null → recording chunk              │
│      (message=="session finished" → final chunk / end signal)                   │
│    • gateway.audit, no asciicast, "API request completed"/"failed"              │
│      → API request (allowlisted metadata; URL via pipeline/urlnorm.py)          │
│    • logger=="gateway" "Authenticated connection" → pending connection + target │
│    • (close event if present) → finalize signal                                 │
│        ▼                                                                        │
│  Per-conn_id assembler (file-first) + connection lifecycle                      │
│    • pending → recording on first chunk; pending → api on first audit;          │
│        pending → visible error after SESSION_MAX_IDLE_SECONDS with neither      │
│    • each chunk → reassemble (header once, events in seq order) →               │
│        write PLAINTEXT .cast to disk + scan live (durable per append)           │
│    • seal (encrypt if enabled → complete): on "session finished"/close          │
│        (terminal) OR idle backstop (reopenable → late chunk resumes it)         │
│    • API request → dedup by request_id → row + API findings, one transaction    │
│        ▼                                                                        │
│  Storage:  SQLite (WAL) metadata (sessions, connections, api_requests,          │
│            api_findings, findings)  +  /data/casts/<conn_id>.cast (named volume)│
│            (store/activity.py holds connections + API rows)                     │
│  Retention purge (APScheduler, age/size)                                        │
│        ▲                                                                        │
│  Web UI (FastAPI + Jinja2 + HTMX, vendored asciinema player, UI auth)          │
│    /systems → /systems/{addr} → /sessions/{id} → /sessions/{id}/cast           │
│                              └→ /systems/{addr}/activity (kubectl, no player)  │
│    (activity grouping computed on view by pipeline/activity.py)                 │
└────────────────────────────────────────────────────────────────────────────────┘
```

**Key points:**

- Single FastAPI process: ingestion, assembly, storage, scheduler, and UI all in one container.
- State: SQLite (WAL mode) for metadata; a named Docker volume for `.cast` files.
- APScheduler drives two background jobs: the idle backstop sweep (seals data-bearing sessions reopenably; expires pending connections that delivered neither chunks nor API audits to a visible `error` session) and the daily retention purge.
- kubectl activity: the Gateway's API-request audits are stored as allowlisted metadata (`store/activity.py`), their URLs normalized and sanitized by `pipeline/urlnorm.py` and `pipeline/classify.py`, and grouped per user and cluster into activity sessions and commands on each page view by `pipeline/activity.py`. Nothing is cached. See the [README](README.md#kubectl-activity).
- Push-based: Gatorcast exposes endpoints and waits. It never reaches back into the Gateway, Docker, or Kubernetes.
- All frontend assets are vendored locally. No CDN or external JS at runtime.

### Session lifecycle: provisional → complete (file-first)

Gatorcast is **file-first**: as each chunk arrives it is reassembled (the header kept once, event lines concatenated in `asciicast_sequence_num` order — the Gateway repeats the header in every chunk) and the growing document is written to `<conn_id>.cast` **as plaintext on every append**. So the recording is durable on disk from the first chunk, playable while in progress, and scanned for findings live. A connection starts as a hidden **pending connection** (the Gateway's `Authenticated connection` line creates only that); its first recording chunk creates the session row, and the session is **provisional** while it is still recording. A connection that only makes API requests never becomes a session.

The recording is **sealed** to **complete** — encrypted (if enabled) and finalized — in one of two ways:

- **Terminal seal**, on the Gateway's final flush (`message == "session finished"`, emitted by the recorder's `Stop()`) or a connection-close event. This is the normal, immediate path: the recording is complete the moment that line is processed.
- **Reopenable seal**, on the idle backstop: an in-progress recording silent for `SESSION_MAX_IDLE_SECONDS` (default 3600 s) is sealed anyway, assuming the Gateway died without its final flush. If a later chunk *does* arrive for that `conn_id`, the sealed file is decrypted, appended to, and re-sealed — so a long interactive pause never loses or splits the recording.

`IDLE_TIMEOUT_SECONDS` (default 120 s) is not a finalize trigger — it only sets the idle-sweep cadence (`max(5, min(IDLE_TIMEOUT_SECONDS, 30))` seconds) and the startup-sweep cutoff. A pending connection that delivers neither a recording chunk nor an API audit within `SESSION_MAX_IDLE_SECONDS` becomes a visible `error` session at the backstop; a genuinely-late chunk reverts it and records, and a late API audit removes the error row. `SESSION_MAX_IDLE_SECONDS` must therefore exceed the Gateway's flush interval, since a quiet-but-active session is legitimately chunkless until its first flush.

On restart, Gatorcast re-adopts each provisional row from its on-disk plaintext `.cast` as an in-progress session (so continuation chunks keep appending and it seals normally); a provisional row with no `.cast` older than the idle timeout is an abandoned start and is swept away.

**Encryption note:** because recordings are written plaintext while in progress and only encrypted at seal, an in-progress recording is plaintext at rest until it seals (see [Encryption at Rest](#encryption-at-rest)).

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

- **In-progress recordings are plaintext at rest.** A `.cast` is written plaintext on every append and only encrypted when the session seals (on "session finished" or the idle backstop). So a session that is still recording — or one held open and idle below the backstop — sits unencrypted on the volume until it seals. This is the accepted tradeoff for durability and live/in-progress playback; lower `SESSION_MAX_IDLE_SECONDS` to shorten the plaintext window for abandoned sessions.
- **Fresh-start only.** Enabling encryption does **not** migrate existing unencrypted recordings. Start with a clean `/data` (or expect previously-written plaintext files to remain plaintext).
- **Losing the key means losing the recordings.** There is no recovery path and no key rotation in this version.
- **The metadata database is not encrypted.**

---

## Security Model

| Layer | Mechanism |
| --- | --- |
| `/ingest` endpoint | `Authorization: Bearer <INGEST_TOKEN>` checked with constant-time comparison. Missing or mismatched token → 401. |
| Web UI (all routes) | HTTP Basic auth on every UI and cast route. Credentials checked with constant-time comparison. No route is reachable unauthenticated (except `/healthz` and `/static/*`). |
| `.cast` file serving | Paths are confined to `casts_dir` with a `is_relative_to` check before serving, even though `conn_id` is already validated upstream. |
| Container privileges | Runs as a dedicated non-root system user (`uid 10001`). |
| Recording payloads | Never written to application logs. Session recordings may contain on-screen secrets (terminals, typed tokens). Treat all stored `.cast` files as secret-grade. |
| kubectl API metadata | Only `User-Agent`, `Kubectl-Command` and `Kubectl-Session` request headers are stored. `Authorization`, cookies, other headers, response headers, `remote_addr` and panic content are never stored or logged. URLs are normalized and keep only allowlisted query keys; `command=` is always dropped. See the [README](README.md#what-is-stored-and-what-is-never-stored). |
| Syslog TCP | No per-message auth. Bound to loopback by default. Cap on concurrent connections (128) and idle connections (5-minute timeout) to limit resource exhaustion. |
| Insecure defaults | At startup, Gatorcast logs a warning for each secret still equal to a placeholder default. The service still boots, but the warning is prominent. |

**Access control summary:** Set strong, unique values for `INGEST_TOKEN`, `UI_AUTH_USERNAME`, and `UI_AUTH_PASSWORD`. Put Gatorcast behind a TLS-terminating reverse proxy. Do not expose the syslog port on a public interface. See [Deployment Behind a Reverse Proxy](README.md#deployment-behind-a-reverse-proxy) in the README for the intended production layout.

---

## Retention

Two independent policies run daily (APScheduler):

1. **Age-based:** Sessions with a `started_at` older than `RETENTION_DAYS` days are deleted (row + `.cast` file). Sessions with no `started_at` are not age-purged (their age is unknown).
2. **Size-based:** If `RETENTION_MAX_GB > 0`, the oldest complete sessions are deleted until the total `.cast` size is under the cap.

Both policies are no-ops when disabled (`0`). Deleting a row and its `.cast` file is one logical operation; a missing file is tolerated and does not cause an error. A purged session's plaintext search sidecar and findings are removed alongside it.

The age-based purge also deletes kubectl activity on the same `RETENTION_DAYS` cutoff, with no separate setting: `api_requests` (with their `api_findings`) and `connections`. An API request is purged when either its Gateway `requested_at` or the time Gatorcast stored it is past the cutoff; connections are purged on Gatorcast's own timestamps. The size cap counts `.cast` bytes only and never deletes API rows or connections.

To keep recordings indefinitely, set `RETENTION_DAYS=0` and `RETENTION_MAX_GB=0` (the defaults for size are already `0`).
