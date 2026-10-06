# Gatorcast — Search & Automated Detection

Beyond browsing **systems → sessions → replay**, Gatorcast scans every recording
**live as it is received** and indexes it for content search at seal, so auditors
can find sessions fast and have dangerous activity flagged while a session is still
in progress. This document covers the dashboard, search, the built-in detection
rule set, and how content search and indexing work under the hood.

For the overall design and how recordings are stored/encrypted, see
[ARCHITECTURE.md](ARCHITECTURE.md).

---

## Features at a glance

- **Dashboard** (`/dashboard`; the site root `/` redirects to it) — total and flagged session counts, severity/category breakdowns, and top users/systems, a **kubectl API requests** card (total requests, flagged commands, severity breakdown of those commands), and a **recent activity** feed, all server-rendered (offline, no external JS). It is **time-windowed** with a 7 / 30 / 90 / All-time toggle (default 30 days). Every tile, chip and top user is a **drill-down link** into search with an explicit `type` and the active window, so each figure lines up with its list. See [Dashboard and systems index](#dashboard-and-systems-index).
- **Search** (`/search`) — one timeline over SSH recordings, kubectl exec recordings, failed connections and kubectl commands. Filter by type, user, system, date range, duration, status, severity, finding category, has-findings, a dangerous-command rule multiselect, a free-text **keyword** and a custom **regex** (recordings only), and sort by newest, longest or highest risk. Filters live in the URL (shareable), paging is forward-only with a keyset cursor, and `/search?user=<name>` is the per-user view. **CSV export** (`/search/export.csv`) follows the page and writes recordings and kubectl commands with a finding summary. See [Search in detail](#search-in-detail).
- **Systems index** (`/systems`) — SSH / Kubernetes type badges, separate **Last session** and **Last API request** columns, and a **Findings column** that flags each system with its highest-severity badge and total finding count (or `—` if clean). The column counts recording findings only; clusters with only kubectl activity are listed too.
- **Findings** — a built-in rule set scans each reassembled recording for **dangerous commands** and **on-screen secrets** (full list below). Findings expose only the **rule label, category, severity, and replay offset** — never the matched text. A separate small rule set flags risky **kubectl API requests** (see [kubectl API rules](#kubectl-api-rules)).
- **Seek-to-finding** — clicking a finding on the session page jumps the asciinema player to that moment. The jump also works as a **deep link** (`/sessions/{id}?t=<seconds>`): opening or refreshing that URL loads the player already positioned at the timestamp (and autoplaying), so a "jump" from the search results lands in the right place.

---

## When detection runs

Detection runs **live** — on **every append** as chunks arrive, and once more at
seal — so findings and a session's risk appear while it is still in progress (see
the file-first session lifecycle in
[ARCHITECTURE.md](ARCHITECTURE.md#session-lifecycle-provisional--complete-file-first)).
Each pass re-scans the recording-so-far and replaces that session's findings
(idempotent), so there are never duplicates. Granularity is per Gateway flush, not
per keystroke; a command split across a not-yet-received chunk is flagged as soon
as the chunk carrying the rest of it arrives.

Detection is gated by `DETECTION_ENABLED` (default `true`) and any scan failure is
swallowed — the `.cast` is already on disk, so a failed pass only forfeits findings
for that pass, never a playable recording (only the exception type is logged). The
**content-search sidecar** (`<conn_id>.txt.enc`) is written only at seal, so
keyword/regex content search covers sealed sessions; findings and risk badges are
available live. The sidecar is written by the same scan, so with
`DETECTION_ENABLED=false` no sidecar is written for new sessions and content
search finds nothing in them. A session reopened by a late chunk keeps the sidecar
from its earlier seal until it seals again.

Each rule is evaluated against the ANSI-stripped plaintext rendering of the
recording: only output (`"o"`) events, with escape sequences, carriage returns and
other control characters removed. A rule that matches produces exactly one
finding, carrying the replay offset of its **earliest** match, so seek-to-finding
lands on the first occurrence. Rules run in declaration order, and findings are
stored in that order.

---

## Built-in detection rules

The rule set is built in for v1. Recordings are scanned against two categories —
**dangerous-command** (what the operator did) and **secret-exposure** (what appeared
on screen). Kubectl API requests have their own rules, listed [below](#kubectl-api-rules).
Severity ranks `critical > high > medium > low`; a session's headline severity is
the highest among its findings. No built-in rule currently uses `low`.

Command rules are matched case-insensitively. Secret-token rules are
case-sensitive so token fidelity (`AKIA…`, `ghp_…`, `eyJ…`, `hvs.…`) is preserved
(the exception is `generic-secret-assign`, which is case-insensitive). There are 21
built-in recording rules: 14 in `dangerous-command` and 7 in `secret-exposure`. The
**Label** is what the UI, the rule multiselect and the CSV export show; the **Rule**
id is what `rule_ids` filters and the `findings` table store.

### Dangerous commands

Category `dangerous-command`.

| Rule | Severity | Label | Flags |
| --- | --- | --- | --- |
| `recursive-delete` | high | Recursive delete (rm -rf) | `rm` with `r` and `f` in one short-flag group (`-rf`, `-fr`, `-Rf`, `-rfv`) |
| `pipe-to-shell` | critical | Pipe download to shell | `curl`/`wget … \| sh`, `bash`, or `sudo sh`/`sudo bash` (download piped to a shell) |
| `chmod-777` | medium | World-writable chmod 777 | `chmod 777` (world-writable) |
| `raw-disk-write` | high | Raw disk write (dd) | `dd … of=/dev/…` (raw write to a block device) |
| `mkfs` | high | Filesystem format (mkfs) | `mkfs`/`mkfs.<fs>` (formatting a filesystem) |
| `fork-bomb` | critical | Fork bomb | the classic `:(){ :\|:& };:` fork bomb |
| `reverse-shell` | critical | Reverse shell | `nc … -e …` or any `/dev/tcp/…` redirection |
| `base64-pipe-shell` | critical | base64 decode to shell | `base64 -d … \| sh` (decode-and-run) |
| `kubectl-delete` | high | kubectl delete | `kubectl … delete …` |
| `kubectl-drain` | high | kubectl drain/cordon | `kubectl … drain`/`cordon` |
| `kubectl-secret` | high | kubectl access secret | `kubectl … secret…` (reading/handling secrets) |
| `iptables-flush` | medium | Firewall flush (iptables -F) | `iptables … -F` (flushing firewall rules) |
| `history-clear` | medium | Shell history cleared | `history -c` or redirecting over `~/.bash_history` |
| `privilege-change` | high | Account/privilege change | `useradd`/`usermod`/`passwd`/`visudo`/`sudo su` |

### On-screen secrets

Category `secret-exposure`.

| Rule | Severity | Label | Flags |
| --- | --- | --- | --- |
| `aws-key` | critical | AWS access key on screen | AWS access key id (`AKIA` + 16 chars) |
| `private-key` | critical | Private key block | a PEM private-key header (`-----BEGIN … PRIVATE KEY-----`, optionally `RSA`/`EC`/`OPENSSH`/`DSA`/`PGP`) |
| `github-token` | critical | GitHub token | GitHub PAT (`ghp_` + 36 chars) |
| `slack-token` | high | Slack token | Slack token (`xox[baprs]-…`) |
| `jwt` | medium | JWT on screen | a JWT (`eyJ…` three dot-separated base64url segments) |
| `vault-token` | critical | Vault token | HashiCorp Vault token (`hvs.…`) or `VAULT_TOKEN=…` |
| `generic-secret-assign` | medium | Secret assigned inline | an inline assignment like `password=`/`passwd=`/`secret=`/`api_key=`/`token=` followed by at least 6 non-space characters |

**Matching notes.** These follow from the patterns in
[`detect.py`](src/gatorcast/pipeline/detect.py); the cases below were checked
against the compiled patterns.

- `recursive-delete` does not match separate flags (`rm -r -f`) or long options
  (`rm --recursive --force`).
- `pipe-to-shell` matches `sh` and `bash` only, not other shells such as `zsh`.
- `chmod-777` does not match `0777`.
- `privilege-change` matches the word `passwd` anywhere, so `cat /etc/passwd` is
  flagged.
- `generic-secret-assign` requires `=` with no space before it, so `token: abc123456`
  does not match.
- Rules that pair a command with a later argument or pipe (`pipe-to-shell`,
  `raw-disk-write`, the `nc -e` form of `reverse-shell`, `base64-pipe-shell`,
  `iptables-flush` and the `kubectl-*` rules) match within a single line and do not
  span a line break.

> **Findings never carry the matched text.** A finding records only the rule id,
> category, severity, and replay offset. To see the actual content, an authorized
> operator scrubs to that offset in the player. This keeps the findings index
> (and any CSV export) free of the very secrets it points at.

### kubectl API rules

Each stored kubectl API request is checked on its method and URL path when it is
ingested (gated by `DETECTION_ENABLED`). The path is normalized (fragment dropped,
unquoted once, repeated `/` collapsed, trailing `/` stripped) and lower-cased before
matching, so encoded or oddly shaped variants such as `%73ecrets` or `exec/` still
match. The query string is never matched. The method is compared case-insensitively.
Findings use the category `kube-api`, carry no replay offset, and, like recording
findings, never carry the URL. Each matching rule yields one finding per request.

| Rule | Severity | Label | Flags |
| --- | --- | --- | --- |
| `kube-delete` | high | Kubernetes resource delete | any `DELETE` request |
| `kube-secrets` | high | Kubernetes secret access | any request, of any method including `GET`, to a `…/secrets` or `…/secrets/<name>` path |
| `kube-evict` | high | Pod eviction (drain) | `POST …/pods/<name>/eviction` (drain) |
| `kube-cordon` | medium | Node patched (cordon/uncordon) | `PATCH /api/v1/nodes/<name>` (cordon/uncordon; any patch to the node object, not only cordon) |
| `kube-exec` | medium | Pod exec/attach | `…/pods/<name>/exec` or `…/attach` |
| `kube-node-proxy-exec` | high | Node proxy exec/run/attach | `…/nodes/<name>/proxy/exec`, `run` or `attach` |

The node-proxy rule works on stored URLs because `classify` keeps
`/nodes/<name>/proxy/<exec|run|attach>` as the stored path prefix and drops the
rest of a proxy path and its query.

API findings are stored in `api_findings` and appear on the system's kubectl
activity page, in the dashboard card, and on kubectl command rows in search and the
CSV export. A command's findings are those of all its requests; its severity is the
highest among them. Search filters `severity`, `max_severity`, `has_findings`,
`category=kube-api` and `rule_ids` (the `kube-*` ids) evaluate them.

### Testing the rules

The repo includes [`scripts/seed_demo.py`](scripts/seed_demo.py), which posts a
set of synthetic sessions that, between them, trip **every** one of the 21 built-in
recording rules, plus a clean session and a negative-control session of
look-alike-but-safe commands (e.g. `rm` without `-rf`, `chmod 755`, `kubectl get`)
that must produce zero findings. It is the quickest way to populate the dashboard
and confirm both detection and the absence of false positives. Because the detector
scans on-screen output, simply `echo`-ing a dangerous string is enough to trip a
rule — nothing destructive ever runs.

The script posts to `http://127.0.0.1:8080/ingest` with the bearer token
`test-ingest-token`, so run the service with `INGEST_TOKEN=test-ingest-token` (or
edit `BASE` and `TOKEN` at the top of the script). Each session ends with a close
event, so it seals immediately and is also searchable by content. The script does
not send any kubectl API-request audit lines, so it does not exercise the
[kubectl API rules](#kubectl-api-rules). Those are covered by
[`tests/test_detect.py`](tests/test_detect.py), which has a positive and a
negative case for each of the six API rules (including encoded, fragment and
query-string variants) and for a subset of the recording rules:

```bash
pytest tests/test_detect.py
```

For a full walkthrough — running the test suite, seeding demo data, and the exact
paste-ready text to trip each rule by hand — see [TESTING.md](TESTING.md).

---

## Findings model

Findings are rows, not stored text. Two tables hold them:

| Table | For | Columns |
| --- | --- | --- |
| `findings` | Recordings | `id`, `conn_id`, `rule_id`, `category`, `severity`, `label`, `offset_seconds`, `created_at` |
| `api_findings` | kubectl API requests | `id`, `request_id` (foreign key, `ON DELETE CASCADE`), `rule_id`, `category` (always `kube-api`), `severity`, `label`, `created_at` |

- **Categories:** `dangerous-command`, `secret-exposure` (recordings) and `kube-api` (API requests).
- **Severity:** `critical`, `high`, `medium`, `low`, ranked 4 to 1.
- **Offset:** a recording finding's `offset_seconds` is the replay time of the rule's earliest match. It is `NULL` for API findings, and for a recording with no output events.
- **Replace, not append.** Each scan deletes the session's rows and inserts the current set, so re-running a scan, a live pass and the seal pass never produce duplicates. A purge deletes a session's findings with it.
- **Session summary.** After each scan the session row is updated with `finding_count` and `max_severity` (the highest severity, or `NULL` with no findings). Lists, the dashboard, the search filters and the risk sort read these columns instead of joining.
- **Read order.** A session's findings are listed by offset ascending, `NULL` offsets last.
- **API findings** are written in the same transaction as their request, so a redelivered audit line can never leave a request without the findings it should have had. They have no per-request summary column; the activity page and the dashboard aggregate them on read.
- **No matched text, ever.** A finding stores the rule id, label, category, severity and offset. Nothing from the recording or the URL is copied into it.

---

## Dashboard and systems index

### Dashboard

- **Window.** `?window=7|30|90|all`; any other value falls back to 30 days (the dashboard is lenient where `/search` returns `400`). Session figures count sessions whose recording start is at or after the cutoff. The recording start is the Gateway start time (`started_at`), else the time Gatorcast first saw the session (`created_at`), rendered in one fixed format. This is the same rule `/search` uses, so a figure equals the length of its linked list. A session with no `started_at` now falls inside the windows by its first-seen time; it used to appear only under **All time**.
- **Total sessions** counts every status, in-progress and `error` included, and failed connections. **Flagged sessions** counts sessions with at least one finding.
- **Sessions by highest severity** counts each session once, under its highest severity.
- **Findings by category** counts finding rows, so a session with two findings in a category counts twice. Its link lists sessions, so the count and the list length can differ.
- **Top users** and **Top systems** list the ten with the most sessions. A top user links to every kind of activity for that user, including kubectl commands, so the list can be longer than the session count.
- **kubectl API requests card.** The total counts stored **requests** (discovery included), windowed on `requested_at`. The flagged figure and the severity chips count **commands**, each flagged command once at its highest finding severity, windowed on the command's first request. Because the total counts requests, it is the one figure that is not the length of its linked list. Over 5,000 flagged commands the flagged figures are lower bounds, shown as `5000+`.
- **Recent activity.** The newest 15 items across every kind, discovery-only commands hidden, not windowed. A recording row links to its replay, a failed connection to its session page, and a command to `/search?cmd=<request id>`.
- **Drill-down links** carry an explicit `type` and the active window (`window=<7|30|90|all>`, emitted as given):

  | Element | Link |
  | --- | --- |
  | Total sessions | `/search?type=recordings` |
  | Flagged sessions | `/search?type=recordings&has_findings=true` |
  | Session severity badge | `/search?type=recordings&max_severity=<severity>` |
  | Category | `/search?type=recordings&category=<category>` |
  | kubectl API requests | `/search?type=kubectl` |
  | Flagged commands | `/search?type=kubectl&has_findings=true` |
  | API severity badge | `/search?type=kubectl&max_severity=<severity>` |
  | Top user | `/search?user=<user>` |
  | Top system | `/systems/<address>` (no window) |
  | View all (recent activity) | `/search` |

### Systems index

`/systems` lists one row per distinct `resource_address`, including clusters that have only kubectl API activity. Sessions with no known system are grouped as `(unknown)`. Columns:

| Column | Meaning |
| --- | --- |
| System | The address, linked to the system page |
| Type | `SSH` when the system has an SSH recording that holds recording data, `Kubernetes` when it has an exec recording or any API request. A system with only start-only `error` rows gets no badge. |
| Sessions | Number of sessions, in-progress, `error` and failed connections included, linked to `/search?type=recordings&system=<address>` |
| Last session | The newest recording start (`started_at`, else `created_at`) |
| API requests | Number of stored kubectl API requests, linked to `/search?type=kubectl&system=<address>`, or `—` |
| Last API request | The newest `requested_at`, linked to the same search, or `—` |
| Findings | Highest severity across the system's sessions and the total of their `finding_count`, or `—` when clean. Recording findings only. |

Both timestamps use the `requested_at` format (`YYYY-MM-DDTHH:MM:SS.mmmZ`), so they compare directly. Rows are ordered by the newer of the two, newest first, then by address. The system page adds "Search this system" and "kubectl commands in search" links and a trailing ⌕ link beside each username.

---

## Search in detail

`/search` is one query over every event kind. Four kinds exist, derived when queried and never stored:

| Kind | `type` value | What it is |
| --- | --- | --- |
| SSH session | `ssh` | A `sessions` row with no `request_id` that is not a failed connection |
| kubectl exec | `exec` | A `sessions` row with a `request_id` (an exec/attach recording) |
| Failed connection | `failed` | A `sessions` row with status `error`, no chunks and no `.cast`: a connection that delivered neither chunks nor API audits before the backstop |
| kubectl command | `kubectl` | A group of API requests sharing a cluster, a user and a command key (`Kubectl-Session`, else the connection) |

`type=recordings` ("All sessions") selects the first three, which is every `sessions` row. `type=any` (the default, also for a link that carries only legacy parameters) selects all four.

Every filter is an optional query parameter. A blank value is ignored. Filters combine with AND, and a repeated parameter is a `400` (except `rule_ids`). Canonical names:

| Parameter | Recordings and failed connections | kubectl commands |
| --- | --- | --- |
| `type` | Chooses the kinds (above). | |
| `system` | Exact `resource_address`; `_unknown` is the no-system bucket. | Same. |
| `user` | `username` equals the value, or the connection's `user_id` does. | `username` or `user_id` equals the value. |
| `window` | `7`, `30`, `90` or `all`: days back from now. Do not combine with `from` or `to`. | Same. |
| `from`, `to` | Inclusive ISO 8601 bounds on the recording start (`started_at`, else first-seen time). A naive time is UTC. `from` later than `to` is a `400`. | Inclusive bounds on the command's **first** request. A command that starts inside the window shows all its requests, even those after `to`. |
| `status` | `complete`, `provisional` or `error`. | **Excludes the kind.** |
| `min_duration`, `max_duration` | Duration in seconds, inclusive; finite number at least 0. | **Excludes the kind.** |
| `severity` | At-or-above: at least one finding at that severity or higher. | The command has a finding at or above it. |
| `max_severity` | Exact: the highest severity equals the value. The dashboard's chips use it. | The command's highest finding severity equals the value. |
| `category` | A finding in that category. The form offers `dangerous-command` and `secret-exposure`. | A finding in that category (`kube-api` is the only one). |
| `rule_ids` | Repeatable (at most 50). A finding from any selected rule. The form lists the dangerous-command rules only. | A finding from any selected `kube-*` rule. |
| `has_findings` | `true` for `finding_count > 0`, `false` for none (failed connections have none, so they match `false`). | `true` for any API finding, `false` for none. |
| `q`, `mode` | `mode=text` (default): case-insensitive substring over the sidecar. `mode=regex`: `re.search` over the sidecar. See [How content search works](#how-content-search-works-no-full-text-index). | `mode=text`: case-insensitive substring over any request's URL path (query string excluded) or `Kubectl-Command`. `mode=regex` **excludes the kind**. |
| `sort` | `newest` (default), `duration` (longest first, unknown last), `risk` (highest `max_severity`, then newest). | `newest`, `risk`. `sort=duration` **excludes the kind**. |
| `discovery` | Ignored. | `0` (default) hides discovery-only commands and discovery requests; `1` shows them. |
| `cmd` | **Excludes the kind.** | Focus on the one command this request id belongs to. |
| `page_size`, `cursor` | Page size 1 to 200 (default `SEARCH_PAGE_SIZE`, 50) and the paging cursor. | Same. |

A kind that cannot evaluate an active filter is **excluded**, not shown unfiltered, and the page names the filter ("kubectl commands not searched: the Status filter applies to recordings only."). A kind that can evaluate a filter and finds no match just returns no rows, with no notice. If every selected kind is excluded the page is empty and still `200`. `status=error` therefore never lists kubectl commands.

For recordings, `category`, `severity` and `rule_ids` each test for a matching finding separately, so one session can satisfy them with different findings. For kubectl commands, every finding filter must hold on one finding.

**Legacy names** are still accepted and never emitted: `username` (`user`), `resource_address` (`system`), `started_after` (`from`), `started_before` (`to`), `keyword` (`q` with `mode=text`), `regex`, and `page`. Combining a legacy name with its canonical name, or `keyword` or `regex` with `q`, is a `400`. `keyword` together with `regex` keeps the old AND behavior. **Old links can show more results, never fewer**, with three exceptions: a value that used to be silently ignored (an unknown `sort`, a non-numeric duration, an uncompilable `regex`) now returns `400`; `page=N` lands on the first page; and a hand-typed `started_after` or `started_before` with a fractional second can differ at that one boundary second.

**Validation.** Every failure is a `400` whose detail names the parameter only (for example `'sort' is not a valid value`), and the submitted value is never echoed or logged. Unknown parameters are ignored. For an HTMX request the `400` is rendered into the results area.

**Per-user view and command focus.** `/search?user=<name>` lists that user's SSH, exec and kubectl activity on every system. `/search?cmd=<request_id>` resolves any request of a command to the whole command, shows it expanded, and ignores every other filter except `discovery`. An unknown id shows "Command not found. It may have been removed by retention."

**Result rows.** Recording rows show the status, duration, shell user, risk and finding badges with jump links, and **Replay**. A failed connection shows **Details ›** (its session page) instead. A kubectl row shows the command label, the primary request, the request count (with the hidden discovery count), the risk badge with finding labels, and any linked recordings. It expands to a request table of its first 200 requests, with a link to the activity view. Under `type=any` a kubectl exec recording appears both as its own row and as the **Replay** link inside its command row.

**Paging.** Paging is keyset-based and forward-only. Each source (recordings; kubectl commands) keeps its own position, and `run_timeline` merges them (see [ARCHITECTURE.md](ARCHITECTURE.md#unified-search-engine)). There is no result total and no page number, because a total would need every command grouped. The page shows **Next ›** with an opaque `cursor`, and **First page**. The cursor must match the request's sort and kinds, or the request is a `400`. The page swaps only the results region (HTMX) and pushes the new URL, so every page is shareable. A content hit returns the session and its findings, not the match position.

**Budgets.** Each page does bounded work:

| Limit | Value | When it is hit |
| --- | --- | --- |
| kubectl rows examined | 20,000 per page | A selective command-level filter (text, `has_findings=false`) on a busy cluster. The page says "Scanned 20,000 kubectl requests without filling the page." |
| Recording sidecars read | `SEARCH_REGEX_MAX_CANDIDATES` (2,000) per page | A content search that matches rarely. The page says "Scanned 2,000 recordings without filling the page." |
| Flagged commands considered | 5,000 per query | The page says "More than 5,000 flagged kubectl commands match. Narrow by system, user, or time." Commands beyond the cap are not listed. |
| Requests listed per command | 200 | The expanded row says it is showing the first 200; counts and severity still cover every request. |

When a budget stops a page, the page can be short or empty and **Continue scanning ›** replaces **Next ›**. Continuing resumes after the stretch already examined, without skipping or repeating results. A text search that matches rarely can need several clicks; that is the cost of having no full-text index.

**CSV export.** `/search/export.csv` follows the page: the same filters and kinds, one row per recording or kubectl command, mixed in page order. It ignores `cursor` and `page_size`, returns up to 10,000 rows in one file named `gatorcast-search.csv`, and stops at the first page a budget cut short. Sidecar reads for the whole export are capped at `SEARCH_REGEX_MAX_CANDIDATES`. When the export stops early (the row cap, a scan budget, the sidecar limit, or more flagged commands than the cap), the response carries `X-Gatorcast-Truncated: true`; the log line `search.export_truncated` carries counters only.

There are 15 columns. The first ten keep their names and order:

| # | Column | Recording | kubectl command |
| --- | --- | --- | --- |
| 1 | `conn_id` | the session's `conn_id` | the start row's `conn_id` |
| 2 | `username` | `username` | `username` |
| 3 | `resource_address` | `resource_address` | `resource_address` |
| 4 | `status` | `status` | empty |
| 5 | `started_at` | `started_at` as stored | first request time |
| 6 | `ended_at` | `ended_at` | last request time |
| 7 | `duration_seconds` | `duration_seconds` | last minus first, in seconds |
| 8 | `finding_count` | `finding_count` | API findings over the whole command |
| 9 | `max_severity` | `max_severity` | the command's highest severity |
| 10 | `findings` | `<label>@<offset>s` entries joined by a semicolon and a space, `?` when a finding has no offset | the distinct finding labels joined by a semicolon and a space (API findings have no offset) |
| 11 | `kind` | `ssh`, `exec` or `failed` | `kubectl` |
| 12 | `command` | empty | the command label (`Kubectl-Command`, else the `User-Agent` product token, else `(unknown client)`) |
| 13 | `method` | empty | the primary request's method |
| 14 | `path` | empty | the primary request's path, query string removed |
| 15 | `request_count` | empty | requests in the command, discovery included |

The export never contains recorded text, a query string, or a header value outside the allowlist. **Formula guard:** any text cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return is written with a leading `'`, in every column.

---

## How content search works (no full-text index)

At seal (when a session completes), Gatorcast writes an ANSI-stripped plaintext
rendering of the recording to a per-session **sidecar** file (`<conn_id>.txt.enc`),
along with a character-offset → replay-time index so a keyword hit can be mapped back to a
moment in the recording. When `ENCRYPTION_ENABLED=true`, the sidecar is encrypted
with a key derived independently from `GATORCAST_MASTER_KEY` (distinct HKDF
context) — losing the key makes sidecars unrecoverable too.

Keyword/regex search is **scan-on-demand**: metadata filters and precomputed
findings narrow the candidate set first, then only those sidecars are decrypted
and scanned in a worker thread, in batches of 100, until the page is full or
`SEARCH_REGEX_MAX_CANDIDATES` (default 2000) sidecars have been read for that
page (a cost / ReDoS guard). Content search applies to recordings only; kubectl
commands have no recorded content, and `mode=regex` excludes them. There is **no FTS5 and no SQLCipher**; the metadata
database stays plaintext. This trades the storage and write-amplification cost of
a full-text index for a bounded on-demand scan — a good fit for an
interactive-session corpus where queries are infrequent and ad hoc.

Matching rules:

- **Text (`q` with `mode=text`, or the legacy `keyword`):** a case-insensitive substring match against the sidecar text.
- **Regex (`q` with `mode=regex`, or the legacy `regex`):** Python `re.search` against the sidecar text, with default flags, so it is case-sensitive. Use `(?i)` for case-insensitive matching. The pattern is capped at 256 characters.
- **Both together:** only the legacy `keyword` and `regex` parameters can be combined, and a session must satisfy both.
- **Invalid regex:** a `400` that names the parameter. It used to return an empty result with no message. The pattern is compiled once per request.
- **Text searched:** the ANSI-stripped output of the recording. Escape sequences, carriage returns and other control characters are gone, so match what a user would read on screen.

Limits:

- **Per-page budget.** The candidates are the sessions that pass the metadata and finding filters, in the chosen sort order, read from the position the cursor names. At most `SEARCH_REGEX_MAX_CANDIDATES` sidecars are read **per page** (it used to cap the whole candidate set). If the budget runs out before the page is full, the page shows "Scanned N recordings without filling the page." with **Continue scanning ›**, which resumes after the last candidate examined. The log records `timeline.content_budget_hit` with `scanned` and `matched` counters (never text). Kubectl commands are not emitted past an unscanned stretch of recordings, so a short page is possible.
- **Missing sidecars.** A candidate with no sidecar is skipped without a message, but it still counts toward the budget. Sessions still recording, sessions never sealed, and sessions recorded with `DETECTION_ENABLED=false` have none.
- **No per-pattern timeout.** The cap bounds how many sidecars are scanned, not how long one pattern takes. The scan runs off the event loop, so the UI stays responsive, but a pathological regex can still run long.

> **The `.txt.enc` sidecars are secret-grade.** They hold on-screen plaintext,
> which can include typed secrets. They live on the same auth-gated volume as the
> `.cast` files, are encrypted under the same master key when encryption is on,
> and are deleted by retention alongside the recording — treat them at the same
> trust level as the recordings.

---

## Detecting on pre-existing recordings

With `BACKFILL_ON_STARTUP=true` (default) **and** `DETECTION_ENABLED=true`, a
throttled background pass on startup builds sidecars + findings for sealed
recordings (`complete` or `error`) that have no sidecar, such as recordings that
predate this feature, or that were stored while `DETECTION_ENABLED` was off, so
search and flags work across your whole history. If `DETECTION_ENABLED=false`, the
backfill does not run, whatever `BACKFILL_ON_STARTUP` says.

For each such session the pass reads the `.cast` (decrypting if needed), writes the
sidecar, runs the recording rules, and stores the findings and the session's
`finding_count` and `max_severity`. Details:

- **Idempotent.** A session that already has a sidecar is skipped, so a second run processes nothing.
- **Resilient.** A missing `.cast` is skipped. Any other failure on one recording is logged by exception type and the pass continues.
- **Throttled.** It yields to the event loop after every session and logs progress every 50 sessions, so it does not contend with live ingestion.
- **Not for API requests.** kubectl API findings are written when each request is ingested, so the backfill does not touch them.
- **After enabling encryption.** A backfill read of a plaintext recording fails the encryption format check and is logged and skipped (see the fresh-start note in [ARCHITECTURE.md](ARCHITECTURE.md#encryption-at-rest)).

The pass runs once per startup, in the background, and is cancelled on shutdown.

---

## Configuration

These settings (all defaulted; see the [README configuration table](README.md#configuration)) control search and detection:

| Variable | Default | Meaning |
| --- | --- | --- |
| `DETECTION_ENABLED` | `true` | Run dangerous-command + secret-exposure detection live (every append) and at seal, and the kubectl API rules as each request is ingested. Also gates writing the content-search sidecar and the startup backfill. |
| `BACKFILL_ON_STARTUP` | `true` | On startup, index + detect existing sealed recordings that lack a sidecar. Runs only when `DETECTION_ENABLED` is also `true`. |
| `SEARCH_PAGE_SIZE` | `50` | Default number of search results per page. A `page_size` query parameter (1 to 200) overrides it. |
| `SEARCH_REGEX_MAX_CANDIDATES` | `2000` | Max sidecars read per page of a keyword/regex content search, and per CSV export (cost / ReDoS bound). |

Related settings from the rest of the service affect when findings and sidecars appear:

| Variable | Default | Effect here |
| --- | --- | --- |
| `SESSION_MAX_IDLE_SECONDS` | `3600` | Idle time before a recording with no end signal is sealed. The sidecar and the final scan happen at that seal, so this is how long an abandoned session waits to become content-searchable. |
| `IDLE_TIMEOUT_SECONDS` | `120` | Sets how often the idle sweep runs (bounded to 5–30 s). Not a seal trigger. |
| `ENCRYPTION_ENABLED` | `false` | When `true`, sidecars are encrypted under their own HKDF-derived key (see [ARCHITECTURE.md](ARCHITECTURE.md#encryption-at-rest)). With it off, sidecars are plaintext under the same `.txt.enc` name. |
| `GATORCAST_MASTER_KEY` | unset | Base64 32-byte master key. Required when encryption is enabled. Losing it makes sidecars unrecoverable. |
| `RETENTION_DAYS` | `90` | A purged session's sidecar and findings are deleted with it; API requests and their findings are purged on the same cutoff. |

`ENCRYPTION_ENABLED`, `SESSION_MAX_IDLE_SECONDS`, `IDLE_TIMEOUT_SECONDS` and
`RETENTION_DAYS` are set under `environment:` in `docker-compose.yml`, which takes
precedence over `.env`; edit them there. The four search and detection settings
above are not in the compose file, so set them in `.env`.

The dashboard windows (7 / 30 / 90 days, all time), the CSV export cap (10,000 rows),
the top-N size (10), the dashboard feed size (15), the kubectl scan budget (20,000
rows per page), the flagged-command cap (5,000) and the per-command request list
(200) are fixed in code, not configurable.
