# Gatorcast — Architecture & Operations

Design and operational reference for Gatorcast: how data flows through the
service, how recordings are protected at rest, the security model, and how
retention works. For setup and day-to-day use, see the [README](README.md); for
forwarding Gateway logs in, see [INGESTION_RECIPES.md](INGESTION_RECIPES.md).

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

### Session lifecycle: provisional → complete

A session is **provisional** while its chunks are buffering in memory, and becomes **complete** when it finalizes. Finalize fires on whichever comes first:

- A connection-close event, if the Gateway emits one, or
- `IDLE_TIMEOUT_SECONDS` of silence for that `conn_id`, caught by the idle-finalizer job (which runs every `max(5, min(IDLE_TIMEOUT_SECONDS, 30))` seconds).

With the default 120-second timeout, a session finalizes roughly **2–2.5 minutes after its last output chunk** — and because the idle timer resets on every chunk, that clock counts from the *last* byte of output, not the first. On finalize, all chunks are concatenated in `asciicast_sequence_num` order, parsed as one asciicast v2 document, written to `<conn_id>.cast`, and the metadata row is flipped to complete. Partial buffers are always flushed, so an interrupted session still produces a playable file.

On restart, Gatorcast sweeps provisional rows orphaned by a crash: if a `.cast` file already exists it is recovered and finalized from disk; otherwise stale empty rows are removed.

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
| Syslog TCP | No per-message auth. Bound to loopback by default. Cap on concurrent connections (128) and idle connections (5-minute timeout) to limit resource exhaustion. |
| Insecure defaults | At startup, Gatorcast logs a warning for each secret still equal to a placeholder default. The service still boots, but the warning is prominent. |

**Access control summary:** Set strong, unique values for `INGEST_TOKEN`, `UI_AUTH_USERNAME`, and `UI_AUTH_PASSWORD`. Put Gatorcast behind a TLS-terminating reverse proxy. Do not expose the syslog port on a public interface. See [Deployment Behind a Reverse Proxy](README.md#deployment-behind-a-reverse-proxy) in the README for the intended production layout.

---

## Retention

Two independent policies run daily (APScheduler):

1. **Age-based:** Sessions with a `started_at` older than `RETENTION_DAYS` days are deleted (row + `.cast` file). Sessions with no `started_at` are not age-purged (their age is unknown).
2. **Size-based:** If `RETENTION_MAX_GB > 0`, the oldest complete sessions are deleted until the total `.cast` size is under the cap.

Both policies are no-ops when disabled (`0`). Deleting a row and its `.cast` file is one logical operation; a missing file is tolerated and does not cause an error. A purged session's plaintext search sidecar and findings are removed alongside it.

To keep recordings indefinitely, set `RETENTION_DAYS=0` and `RETENTION_MAX_GB=0` (the defaults for size are already `0`).
