# Gatorcast — Search & Automated Detection

Beyond browsing **systems → sessions → replay**, Gatorcast indexes and scans
every recording at finalize so auditors can find sessions fast and have dangerous
activity flagged automatically. This document covers the dashboard, search, the
built-in detection rule set, and how content search and indexing work under the
hood.

For the overall design and how recordings are stored/encrypted, see
[ARCHITECTURE.md](ARCHITECTURE.md).

---

## Features at a glance

- **Dashboard** (`/dashboard`, the site root) — total and flagged session counts, severity/category breakdowns, and top users/systems, all server-rendered (offline, no external JS). It is **time-windowed** with a 7 / 30 / 90 / All-time toggle (default 30 days). Every breakdown is a **drill-down link**: a severity badge opens search filtered to that exact highest severity, a category opens search for that category, a top user opens that user's sessions, and a top system opens its session list — each carrying the active window so the figures and results line up.
- **Search** (`/search`) — filter by user, system, status, date range, duration, severity (at-or-above), finding category, a dangerous-command rule multiselect, a free-text **keyword**, and a custom **regex**. Results paginate and the filters live in the URL (shareable). **CSV export** (`/search/export.csv`) writes session metadata plus a finding summary.
- **Systems index** (`/systems`) — a **Findings column** flags each system with its highest-severity badge and total finding count (or `—` if clean), so you can see at a glance which systems to look into.
- **Findings** — a built-in rule set scans each reassembled recording for **dangerous commands** and **on-screen secrets** (full list below). Findings expose only the **rule label, category, severity, and replay offset** — never the matched text.
- **Seek-to-finding** — clicking a finding on the session page jumps the asciinema player to that moment. The jump also works as a **deep link** (`/sessions/{id}?t=<seconds>`): opening or refreshing that URL loads the player already positioned at the timestamp (and autoplaying), so a "jump" from the search results lands in the right place.

---

## When detection runs

Detection runs **once per session, at finalize** — the moment the recording is
reassembled and written to disk (see the session lifecycle in
[ARCHITECTURE.md](ARCHITECTURE.md#architecture)). It is not per-keystroke and not
live during ingestion. The scan is gated by `DETECTION_ENABLED` (default `true`)
and runs *after* the `.cast` file and metadata row are committed, so a scan
failure can never prevent a session from being playable — it only forfeits search
and findings for that one session.

Each rule is evaluated against the ANSI-stripped plaintext rendering of the
recording. A rule that matches produces exactly one finding, carrying the replay
offset of its **earliest** match, so seek-to-finding lands on the first
occurrence.

---

## Built-in detection rules

The rule set is built in for v1. There are two categories — **dangerous-command**
(what the operator did) and **secret-exposure** (what appeared on screen).
Severity ranks `critical > high > medium > low`; a session's headline severity is
the highest among its findings.

Command rules are matched case-insensitively. Secret-token rules are
case-sensitive so token fidelity (`AKIA…`, `ghp_…`, `eyJ…`, `hvs.…`) is preserved.

### Dangerous commands

| Rule | Severity | Flags |
| --- | --- | --- |
| `recursive-delete` | high | `rm -rf` and its flag permutations |
| `pipe-to-shell` | critical | `curl`/`wget … \| sh` (download piped to a shell) |
| `chmod-777` | medium | `chmod 777` (world-writable) |
| `raw-disk-write` | high | `dd … of=/dev/…` (raw write to a block device) |
| `mkfs` | high | `mkfs`/`mkfs.<fs>` (formatting a filesystem) |
| `fork-bomb` | critical | the classic `:(){ :\|:& };:` fork bomb |
| `reverse-shell` | critical | `nc … -e …` or any `/dev/tcp/…` redirection |
| `base64-pipe-shell` | critical | `base64 -d … \| sh` (decode-and-run) |
| `kubectl-delete` | high | `kubectl … delete …` |
| `kubectl-drain` | high | `kubectl … drain`/`cordon` |
| `kubectl-secret` | high | `kubectl … secret…` (reading/handling secrets) |
| `iptables-flush` | medium | `iptables … -F` (flushing firewall rules) |
| `history-clear` | medium | `history -c` or redirecting over `~/.bash_history` |
| `privilege-change` | high | `useradd`/`usermod`/`passwd`/`visudo`/`sudo su` |

### On-screen secrets

| Rule | Severity | Flags |
| --- | --- | --- |
| `aws-key` | critical | AWS access key id (`AKIA` + 16 chars) |
| `private-key` | critical | a PEM private-key header (`-----BEGIN … PRIVATE KEY-----`) |
| `github-token` | critical | GitHub PAT (`ghp_` + 36 chars) |
| `slack-token` | high | Slack token (`xox[baprs]-…`) |
| `jwt` | medium | a JWT (`eyJ…` three dot-separated base64url segments) |
| `vault-token` | critical | HashiCorp Vault token (`hvs.…`) or `VAULT_TOKEN=…` |
| `generic-secret-assign` | medium | an inline assignment like `password=`/`secret=`/`api_key=`/`token=` |

> **Findings never carry the matched text.** A finding records only the rule id,
> category, severity, and replay offset. To see the actual content, an authorized
> operator scrubs to that offset in the player. This keeps the findings index
> (and any CSV export) free of the very secrets it points at.

### Testing the rules

The repo includes [`scripts/seed_demo.py`](scripts/seed_demo.py), which posts a
set of synthetic sessions that, between them, trip **every** built-in rule, plus a
negative-control session of look-alike-but-safe commands (e.g. `rm` without
`-rf`, `chmod 755`, `kubectl get`) that must produce zero findings. It is the
quickest way to populate the dashboard and confirm both detection and the absence
of false positives. Because the detector scans on-screen output, simply `echo`-ing
a dangerous string is enough to trip a rule — nothing destructive ever runs.

---

## How content search works (no full-text index)

At finalize, Gatorcast writes an ANSI-stripped plaintext rendering of the
recording to a per-session **sidecar** file (`<conn_id>.txt.enc`), along with a
character-offset → replay-time index so a keyword hit can be mapped back to a
moment in the recording. When `ENCRYPTION_ENABLED=true`, the sidecar is encrypted
with a key derived independently from `GATORCAST_MASTER_KEY` (distinct HKDF
context) — losing the key makes sidecars unrecoverable too.

Keyword/regex search is **scan-on-demand**: metadata filters and precomputed
findings narrow the candidate set first, then only those sidecars are decrypted
and scanned in a worker thread, bounded by `SEARCH_REGEX_MAX_CANDIDATES` (default
2000) as a cost / ReDoS guard. There is **no FTS5 and no SQLCipher**; the metadata
database stays plaintext. This trades the storage and write-amplification cost of
a full-text index for a bounded on-demand scan — a good fit for an
interactive-session corpus where queries are infrequent and ad hoc.

> **The `.txt.enc` sidecars are secret-grade.** They hold on-screen plaintext,
> which can include typed secrets. They live on the same auth-gated volume as the
> `.cast` files, are encrypted under the same master key when encryption is on,
> and are deleted by retention alongside the recording — treat them at the same
> trust level as the recordings.

---

## Detecting on pre-existing recordings

With `BACKFILL_ON_STARTUP=true` (default), a throttled background pass on startup
builds sidecars + findings for finalized recordings that predate this feature (or
were recovered by the crash sweep), so search and flags work across your whole
history. It is idempotent — already-indexed sessions are skipped — and throttled
so it does not contend with live ingestion.

---

## Configuration

These settings (all defaulted; see the [README configuration table](README.md#configuration)) control search and detection:

| Variable | Default | Meaning |
| --- | --- | --- |
| `DETECTION_ENABLED` | `true` | Run dangerous-command + secret-exposure detection at finalize. |
| `BACKFILL_ON_STARTUP` | `true` | On startup, index + detect existing finalized recordings that lack a sidecar. |
| `SEARCH_PAGE_SIZE` | `50` | Default number of search results per page. |
| `SEARCH_REGEX_MAX_CANDIDATES` | `2000` | Max sidecars scanned per keyword/regex content search (cost / ReDoS bound). |
