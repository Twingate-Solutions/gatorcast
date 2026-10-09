# Ingestion Recipes — Getting Session Data from the Gateway to Gatorcast

This document is a cookbook. It collects worked examples of how to forward
Twingate Gateway session recordings to Gatorcast across the deployment shapes we
actually see in the field: bare systemd VMs, Terraform-provisioned cloud
instances (AWS / GCP / Azure), Docker, and Kubernetes.

It is intentionally separate from the project README — the README explains *what
Gatorcast is*; this explains *how to feed it* from whatever your Gateway happens
to be running on.

> **Scope note.** Gatorcast is push-based and transport-agnostic. It never
> reaches back into the Gateway. Every recipe below is some variation on the same
> job: **capture the Gateway's stdout/stderr JSON and ship each line to one of
> Gatorcast's two front doors.** What changes between recipes is only *how the
> logs are captured* on that particular platform.

---

## 1. Background — what you are actually shipping

### 1.1 What the Gateway emits

The Twingate L7 Gateway writes structured JSON audit logs to **stdout/stderr**.
Among those lines are the session-recording chunks:

```json
{"logger":"gateway.audit","message":"session recording","ts":"…Z","user":{"username":"alice@corp"},"conn_id":"<uuid>","asciicast":"<v2 chunk>","asciicast_sequence_num":1}
```

plus the session-start line that carries the target system:

```json
{"logger":"gateway","message":"Authenticated connection","conn_id":"<uuid>","resource_address":"prod-db-01","user":{"username":"alice@corp"}}
```

The Gateway's last chunk for a connection has `"message":"session finished"`. Gatorcast
treats it as the end of the recording and seals it immediately.

For Kubernetes access, the Gateway also emits one `gateway.audit` line per API
request (`"message":"API request completed"` or `"API request failed"`, with no
`asciicast`). Gatorcast stores these as allowlisted kubectl activity metadata (see
the README's [kubectl Activity](README.md#kubectl-activity) section). The audit line
carries no `resource_address`, so Gatorcast joins each request to its cluster through
the start line's `conn_id`. **Ship both.** If the start line never arrives, the request
is stored with an unknown cluster; a start line that arrives later fills it in.

For web apps, the Gateway acts as a Layer 7 reverse proxy and emits the **same** `API request
completed` line for every HTTP request, on the same `conn_id` as its start line. The start line
for a web app carries `"resource_type":"WEB_APP"`, and it is the only line that does: the request
line has no resource fields. Gatorcast joins them by `conn_id` and stores web requests separately
from kubectl ones (see the README's [Web Apps](README.md#web-apps) section). **Ship the start
line**: without it a web request cannot be told from a kubectl request and is stored under the
stricter provisional policy. The Gateway puts no TLS information on any line; the configured TLS
badges come from the `gwops` object described in [§1.4](#14-gwops-filtering-and-the-gwops-object).

You do **not** need to filter these out of the Gateway's other output — Gatorcast
classifies and drops everything it does not recognize. **Ship the Gateway's whole log
stream; Gatorcast sorts it out.** The only hard requirement is that **whole lines arrive
intact and untruncated** — asciicast chunks are multi-KB.

What Gatorcast does with each line, as decided by `classify`:

| Line | Match | Result |
| --- | --- | --- |
| Recording chunk | `logger` is `gateway.audit` **and** `asciicast` is a non-null string, with an integer `asciicast_sequence_num` | Chunk for that `conn_id`; `message` of `session finished` also seals the recording. A chunk with a missing or non-integer sequence number is dropped. |
| Start line | `logger` is `gateway`, `message` is `Authenticated connection` | Hidden pending connection, with the normalized `resource_type` (and, for `WEB_APP`, the optional `gwops` object). Needs a recording chunk (becomes a session) or an API audit line (becomes kubectl or web activity) within `SESSION_MAX_IDLE_SECONDS`, or it becomes a visible `error` session. A `WEB_APP` connection with neither expires hidden instead and never becomes an `error` session. |
| API audit line | `logger` is `gateway.audit`, no `asciicast`, `message` is `API request completed` or `API request failed` | Allowlisted metadata, deduplicated by `request_id`: kubectl activity or web activity, chosen from the connection's `resource_type`. |
| Close line | `logger` is `gateway`, `message` is `Connection closed` or `Closed connection` | Seals the recording. A defensive fallback; the stock Gateway does not log a close event. |
| Envelope record | No `logger`; `type` is `session_start`, `recording_chunk` or `session_end` | Same events as above, from the Gateway fork's recording sink. Additive; the recipes below do not need it. |
| Anything else | | Dropped as noise. |

Every recognized line must also carry a `conn_id` made only of letters, digits, `_`, `.` and `-`
(at most 128 characters), because it names the `.cast` file. A line with any other
`conn_id` is dropped.

Under systemd, the Gateway logs to journald under the identifier `gateway`
(`SYSLOG_IDENTIFIER=gateway`). Confirm on any host with:

```bash
journalctl -t gateway -n 1 -o cat
```

### 1.2 The two front doors

| Door | Default | Auth | Body | Use when |
| --- | --- | --- | --- | --- |
| **HTTP** `POST /ingest` | `:8080` (`HTTP_PORT`), the same port as the UI | `Authorization: Bearer $INGEST_TOKEN` (missing or wrong token: `401`) | NDJSON, single JSON object, JSON array, or newline-delimited text | Default. Works over any routed network; auth lets you expose it more safely. |
| **Syslog TCP** | `:6514` (`SYSLOG_TCP_PORT`; `0` disables the listener) | **None** (rely on network position) | Syslog frames (octet-counted **or** newline-delimited); the `<PRI>` header is skipped automatically | Your shipper already speaks syslog (rsyslog `omfwd`, Docker syslog driver). Bind it to an internal interface only. |

Key behaviors that make the recipes simple:

- **The HTTP door is tolerant.** One malformed line never fails the batch. A successful
  request returns `204 No Content` even if some lines were dropped. The body is split by
  `Content-Type`: `application/json` is parsed as **one** JSON document (an object or an
  array of objects); any other type (`application/x-ndjson`, `text/plain`, none) is read
  line by line. Do not send multi-line NDJSON as `application/json` — it is not one valid
  JSON document, so the whole body is dropped. The recipes below use
  `application/x-ndjson`.
- **Collector envelopes are unwrapped automatically.** If a shipper wraps each
  line as `{"log":"<original>","stream":"stdout"}` (Docker's and many log
  collectors' default), Gatorcast recovers the inner Gateway line for you, on both the
  line-by-line and the `application/json` paths. Only a top-level string field named
  `log` on an object with no `logger` is unwrapped; other wrapper shapes (for example
  `{"message":"…"}`) are dropped. This is what makes the Docker and Kubernetes recipes
  nearly config-free.
- **Syslog TCP is TCP-only and unauthenticated.** Never publish `6514` on a
  public interface. UDP is never accepted (it would truncate multi-KB chunks). The
  framing is detected per message: RFC 6587 octet-counting (`<len> <msg>`) or a
  newline-delimited line (LF or CRLF). Gatorcast reads the JSON from the first `{`
  in each message, so the `<PRI>` header of both RFC 5424 and BSD syslog is skipped. Gatorcast
  closes a connection that declares a frame over 16 MiB or a length prefix of more than 10
  digits, refuses connections beyond 128 concurrent, and reaps one that is silent for
  300 s. The shipped `docker-compose.yml` publishes the port as `127.0.0.1:6514`; change
  `127.0.0.1` to your internal interface address before pointing a remote shipper at it.
- **Lines are split on `\n` only.** On the line-by-line path, a body is split on the line feed
  alone (one trailing `\r` is dropped). Unicode line separators (U+0085, U+2028, U+2029) inside a
  JSON string, such as a header value or terminal output, do not split a line, so a user
  cannot tear their own audit line into unparseable fragments.
- **Non-JSON lines in a batch are dropped without failing it.** A line such as Go's
  `http: proxy error: tls: failed to verify certificate: …` (emitted just before the audit line
  for the 502 it caused) is dropped with a `normalize.drop` warning. The batch still returns
  `204` and its other lines are kept.
- **An unparseable line is logged, not stored.** Gatorcast logs `normalize.drop` with the
  line length (never the content) and drops the line. A length at or near `49152` is the
  tell for journald splitting (see the warning in §2.1).

### 1.3 Reachability — a caveat that bites everyone

The Gateway is a **server-side component, not a Twingate Client**, so it has **no
overlay connectivity**. Reaching Gatorcast is ordinary network egress from the
Gateway host. If your Gatorcast is only reachable *through* Twingate (e.g.
self-hosted at home behind a connector), the Gateway cannot reach it on the
overlay. Options, covered in [§9](#9-reaching-a-self-hosted-or-private-gatorcast).

Throughout this doc the placeholders are:

- `GATORCAST_HTTP` → e.g. `https://gatorcast.internal.example.com:8080`
- `GATORCAST_HOST` / `6514` → the syslog TCP listener
- `INGEST_TOKEN` → the value from Gatorcast's `.env`

> **TLS.** Gatorcast itself serves plain HTTP (it has no TLS settings). The `https://`
> URLs in this doc assume a TLS-terminating reverse proxy in front of it, and `:8080` in
> the examples stands for whatever port that proxy listens on. Without a proxy, use
> `http://` and Gatorcast's own port, and keep it on a trusted network, because the bearer
> token and the recordings then cross the wire in the clear. The Fluent Bit recipe in §7.3
> sets `tls On` for the same reason; turn it off if you point it at Gatorcast directly.

### 1.4 gwops filtering and the `gwops` object

**gwops** is a wrapper that runs the Twingate Gateway as a child process, spools the stderr
lines it keeps, and batch-POSTs them to Gatorcast's `POST /ingest` as `application/x-ndjson`
(up to 500 lines or 16 MiB per POST, at least once, so lines can be redelivered byte-identical).
Gatorcast tolerates that redelivery: request lines are deduplicated by `request_id`, and a
repeated start line never rewrites what its first processing stored. The rest of this section
describes gwops as of its backlog item B-20 and the live behaviour notes in
[`docs/gateway-webapp-http-behaviour.md`](docs/gateway-webapp-http-behaviour.md). Check what your
gwops build does before relying on any of it.

**What gwops ships (the B-20 allowlist).** gwops decides on the parsed line, before it spools,
so `/ingest` receives only audit and session data. A line is shipped only if it is at most
16 MiB, starts with `{`, is valid UTF-8, parses as one JSON object, and matches one of:

| Kept line | Rule | Covers |
| --- | --- | --- |
| Session recording | `logger == "gateway.audit"` and `asciicast` is a string | SSH and Kubernetes `session recording` / `session finished` |
| HTTP audit | `logger == "gateway.audit"`, no `asciicast`, `message` is `API request completed` or `API request failed` | Kubernetes requests and web-app requests |
| Connection start | `logger == "gateway"` and `message == "Authenticated connection"` | Every resource type. Gatorcast's only source of `resource_type` and `resource_address`. |

Everything else is dropped and counted by gwops without logging its content: non-JSON lines
(Go `http: proxy error`, klog, panics), token and listener errors, every other `gateway`
service line, the operational error lines the SSH backend logs under the `gateway.audit` name,
and SSH audit events (which log `env` values and full `exec` commands). A line over 16 MiB is
dropped whole, and that recording is lost. gwops reports the counts in its `/status` under
`shipper.dropped_lines`. Gatorcast still drops the same lines itself, as defence in depth and
for shippers that do not filter, so an unfiltered stream is safe to send. If a gwops build does
not filter yet, expect those extra lines in `/ingest` batches and `normalize.drop` warnings in
Gatorcast's log.

**What a kept line contains.** Kept lines are forwarded byte for byte; nothing is redacted. A
web-app request line therefore holds the client's `Authorization`, `Cookie` and `X-Api-Key`
values, the response's `Set-Cookie` values and the full URL including any query string. gwops
keeps these at rest in its spool and sends them to Gatorcast. Gatorcast reads only `User-Agent`
from web requests (and `Kubectl-*` from Kubernetes ones) and stores none of the rest, but the
values still cross the wire. **Use TLS between gwops and Gatorcast**: point gwops at an
`https://` URL on a TLS-terminating reverse proxy in front of Gatorcast (see the TLS note in
§1.3). The gwops demo compose network uses plain HTTP, which is not appropriate beyond a lab.

**The `gwops` object on `WEB_APP` start lines.** When Gatorcast delivery is configured on gwops
(`recording.enabled` with a `gatorcast_url`), gwops adds one `gwops` object to the Gateway's own
`Authenticated connection` line for every `WEB_APP` connection. It is spliced in before the
line's closing brace, so every Gateway byte is unchanged. No other line type is changed, and
there is no separate record.

```json
{"logger":"gateway","message":"Authenticated connection","conn_id":"<uuid>","resource_type":"WEB_APP","resource_address":"wiki.example.test","user":{"id":"u-1","username":"you@corp"},
 "gwops":{"schema":1,"gateway_id":"R2F0ZXdheToxMjk0","match":"exact","app":"wiki","managed":true,
          "downstream_tls":"tls13","downstream_port":443,"upstream_tls":"verify_full","upstream_port":443}}
```

| Field | Notes |
| --- | --- |
| `schema` | Must be `1`. A newer schema reads as TLS unknown until Gatorcast is upgraded. |
| `gateway_id` | Opaque Twingate gateway id, or `null` before gwops has created or adopted the Gateway. |
| `match` | `exact`, `none` (no web app at that address on this gateway, or gwops had not yet read the tenant) or `ambiguous` (more than one). The fields below are present for `exact` only. |
| `app`, `managed` | gwops' name for the app (the tenant resource name for an app gwops does not declare), and whether gwops declares it. |
| `downstream_tls` | `tls13` or `none`: the client-facing leg. |
| `upstream_tls` | `verify_full`, `verify_ca`, `insecure` or `none`: the app-facing leg. |
| `downstream_port`, `upstream_port` | Integers from 1 to 65535. |

Gatorcast reads the object only on `WEB_APP` start lines, only these keys, and ignores every
other key. An invalid object (wrong type, unknown value, bad port, wrong schema) is ignored
and logged as one `classify.gwops_rejected` warning with a reason code and the `conn_id`, and
the connection is stored with TLS unknown; the connection itself is never dropped. A line with
no object is normal and logs nothing. The values are written once, when the start line is first
processed, and are the configuration gwops read at that moment, not proof of the negotiated TLS
mode. Other shippers (rsyslog, Vector, the Docker syslog driver) never add the object, so their
web connections show TLS unknown.

---

## 2. systemd on a VM

**Setup.** The Gateway runs as a native **systemd** service on a Linux VM —
however you installed it (commonly as a unit named `twingate-gateway`). Its
stdout/stderr is captured by **journald** under the identifier `gateway`. Nothing
forwards it off-box yet — that's this section.

> The single gotcha: to forward you must **read journald**. Pointing rsyslog at
> the journal with `imjournal` fails on some hosts (notably LXC containers) where
> rsyslog drops privileges and can no longer read the journal — it silently ships
> nothing. The robust options below either read the journal **as root** or avoid
> the journal entirely.

### 2.1 journald → HTTP shipper (recommended; self-contained)

A small, dependency-free shipper that follows the Gateway's journald output and
POSTs each line to Gatorcast. This is the simplest reliable path. It reads the
journal **as root** (via the unit below), which is what makes it work even on
hosts where rsyslog's privilege-drop cannot read the journal (notably LXC).

The three files below are all you need — copy them onto the VM.

**`/usr/local/bin/journald-http-shipper.sh`** (`chmod 755`):

```bash
#!/usr/bin/env bash
# Follow the Twingate gateway's journald output and POST each line to Gatorcast.
# Config comes from the EnvironmentFile in the unit below.
set -euo pipefail

: "${LOG_ENDPOINT:?set LOG_ENDPOINT (e.g. https://gatorcast.internal:8080/ingest)}"
JOURNAL_ID="${JOURNAL_ID:-gateway}"
CONTENT_TYPE="${CONTENT_TYPE:-application/x-ndjson}"
AUTH_TOKEN="${AUTH_TOKEN:-}"

post_line() {
    local line="$1"
    if [[ -n "$AUTH_TOKEN" ]]; then
        curl -sS -m 10 -X POST "$LOG_ENDPOINT" \
            -H "Authorization: Bearer ${AUTH_TOKEN}" \
            -H "Content-Type: ${CONTENT_TYPE}" \
            --data-binary "$line" >/dev/null
    else
        curl -sS -m 10 -X POST "$LOG_ENDPOINT" \
            -H "Content-Type: ${CONTENT_TYPE}" \
            --data-binary "$line" >/dev/null
    fi
}

# -o cat = emit only the raw MESSAGE (the gateway's JSON); -f = follow;
# --since now = forward only new lines. For gap-free delivery across restarts,
# replace "--since now" with "--cursor-file=/var/lib/journald-http-shipper/cursor"
# (create that directory first).
journalctl -t "$JOURNAL_ID" -o cat -f --since now | while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if ! post_line "$line"; then
        printf '%s: POST to %s failed, dropped one line\n' "${0##*/}" "$LOG_ENDPOINT" >&2
    fi
done
```

**`/etc/journald-http-shipper.env`** (`chmod 600` — it holds the token):

```ini
LOG_ENDPOINT=https://gatorcast.internal.example.com:8080/ingest
AUTH_TOKEN=<your INGEST_TOKEN>
JOURNAL_ID=gateway
CONTENT_TYPE=application/x-ndjson
```

**`/etc/systemd/system/journald-http-shipper.service`**:

```ini
[Unit]
Description=Ship Twingate gateway journald logs to Gatorcast
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/journald-http-shipper.env
ExecStart=/usr/local/bin/journald-http-shipper.sh
Restart=always
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now journald-http-shipper
```

Start the shipper **before** driving a test session — it forwards only new lines
(`--since now`). Verify:

```bash
systemctl status journald-http-shipper --no-pager
journalctl -u journald-http-shipper -f   # quiet unless a POST fails
```

> **⚠️ journald has two limits that silently break large recordings.** This path routes recordings through journald, and asciicast chunks can be big — a busy shell, and especially a full-screen TUI (`btop`, `top`, `htop`, `watch`, `vim`), emits large, rapid frames. Two journald defaults bite:
>
> 1. **`LineMax` (default 48 KB)** — journald splits any single log line longer than this into multiple entries. Each fragment is only a piece of a JSON object, so it fails to parse: Gatorcast drops it (`event=normalize.drop reason=unparseable`) and the recording never assembles. The recording never appears: the connection stays a hidden pending connection and, after `SESSION_MAX_IDLE_SECONDS` with no valid chunks (and no API audit lines), becomes a visible **`error`** session with no recording.
> 2. **Rate limiting (`RateLimitIntervalSec` / `RateLimitBurst`)** — under a firehose (a repainting TUI), journald *drops* entries entirely once the burst is exceeded. You'll see `Suppressed N messages` in the journal and gaps in `asciicast_sequence_num`.
>
> **Quick check on the Gateway host** (as root) — reproduce a heavy session, then look for lines pinned at exactly the 48 KB cap:
>
> ```bash
> sudo journalctl -t gateway -o cat --since -3min \
>   | python3 -c 'import sys; [print("len", len(l)) for l in sys.stdin.buffer.read().split(b"\n") if l.strip()]' \
>   | sort | uniq -c | sort -rn | head
> ```
>
> Any cluster at **49152** = journald truncating. Also grep for drops: `sudo journalctl --since -20min | grep -iE "suppressed|rate.?limit"`.
>
> **Fix — raise both in `/etc/systemd/journald.conf`:**
>
> ```ini
> LineMax=4M              # comfortably exceed the Gateway's largest flush
> RateLimitBurst=0        # disable rate limiting (or set a high value)
> ```
>
> then `sudo systemctl restart systemd-journald && sudo systemctl restart journald-http-shipper` (restarting journald drops the shipper's `-f` follow, so bounce the shipper too).
>
> **Better for high-volume / TUI recording:** don't route recordings through journald at all — use **[§2.4](#24-lxc--privilege-drop-fallback--redirect-stderr-to-a-file-tail-with-imfile)** (stderr → file → `imfile`), which has neither a line cap nor a rate limit. If you expect people to run `btop`-class tools over recorded sessions, prefer §2.4 regardless of host type.

### 2.2 rsyslog `imjournal` → `omhttp` (HTTP, where rsyslog *can* read the journal)

Use this if you already standardize on rsyslog and the host is **not** an LXC
container with privilege-drop. Drop into `/etc/rsyslog.d/50-gatorcast.conf`:

```rsyslog
module(load="imjournal" StateFile="imjournal.state")
module(load="omhttp")

# Forward only the Gateway's own lines; ship the raw MESSAGE (the JSON) verbatim.
template(name="gw_raw" type="string" string="%msg%\n")

if ($programname == "gateway") then {
    action(
        type="omhttp"
        server="gatorcast.internal.example.com"
        serverport="8080"
        restpath="ingest"
        template="gw_raw"
        httpheaderkey="Authorization"
        httpheadervalue="Bearer <your INGEST_TOKEN>"
        httpcontenttype="application/x-ndjson"
        action.resumeRetryCount="-1"
        queue.type="LinkedList"
        queue.saveOnShutdown="on"
        batch="on"
        batch.maxsize="100"
        batch.timeout="5000"
    )
    stop
}
```

```bash
sudo systemctl restart rsyslog
```

The `queue.*` settings give you durable buffering and retry — a real advantage of
the rsyslog path over the simple shipper. The `batch.*` settings post up to 100
lines (or every 5 s) in one NDJSON request rather than one request per line;
Gatorcast's `/ingest` accepts the batch and processes it line-by-line. Exact
`omhttp` parameter names vary by rsyslog version; verify with `rsyslogd -v` and
the `omhttp` docs if it doesn't start.

### 2.3 rsyslog `imjournal` → `omfwd` (Syslog TCP door)

If you'd rather use Gatorcast's syslog TCP listener (no token to manage; gate by
network position):

```rsyslog
module(load="imjournal" StateFile="imjournal.state")

if ($programname == "gateway") then {
    action(
        type="omfwd"
        target="gatorcast.internal.example.com"
        port="6514"
        protocol="tcp"
        template="RSYSLOG_SyslogProtocol23Format"
        TCP_Framing="octet-counted"
        action.resumeRetryCount="-1"
        queue.type="LinkedList"
        queue.saveOnShutdown="on"
    )
    stop
}
```

`octet-counted` framing is preferred — it cannot be confused by any byte in the
payload. Gatorcast also accepts newline-delimited frames (`TCP_Framing="traditional"`),
detecting the framing per message. It skips the `<PRI>…` syslog header automatically by
parsing the JSON from the first `{`. Set `port` to the published syslog port, and note that the
shipped `docker-compose.yml` binds it to `127.0.0.1` only (see §1.2).

### 2.4 LXC / privilege-drop fallback — redirect stderr to a file, tail with `imfile`

Use this when the host is an LXC container and rsyslog can't read the journal —
**or whenever you expect large / high-rate recordings** (full-screen TUIs like
`btop`, verbose build output). Tailing a file sidesteps both journald limits
called out in §2.1 (the 48 KB `LineMax` line cap and rate-limit drops), so it is
the sturdiest transport for chunky sessions. Add a drop-in to the Gateway unit so
its output also lands in a plain file:

```bash
sudo systemctl edit twingate-gateway
```

```ini
[Service]
StandardError=append:/var/log/twingate-gateway.log
StandardOutput=append:/var/log/twingate-gateway.log
```

Then tail that file with rsyslog `imfile` and forward via `omhttp` (§2.2) or
`omfwd` (§2.3):

```rsyslog
module(load="imfile")
input(type="imfile"
      File="/var/log/twingate-gateway.log"
      Tag="gateway"
      Severity="info"
      Facility="local0")
```

Trade-off: you lose clean `journalctl -u twingate-gateway` for the unit's stdout.

### 2.5 Vector (durable buffering, multi-destination)

Use Vector (or Fluent Bit) when you also ship these logs elsewhere or need
on-disk buffering with retry. Vector reads journald natively and runs as root.

`/etc/vector/vector.yaml`:

```yaml
sources:
  gateway_journal:
    type: journald
    include_units: ["twingate-gateway.service"]

transforms:
  gateway_only:
    type: filter
    inputs: ["gateway_journal"]
    condition: '.SYSLOG_IDENTIFIER == "gateway"'

sinks:
  gatorcast:
    type: http
    inputs: ["gateway_only"]
    uri: "https://gatorcast.internal.example.com:8080/ingest"
    method: post
    encoding:
      codec: text          # forward the raw Gateway JSON line as-is
    framing:
      method: newline_delimited
    request:
      headers:
        Authorization: "Bearer <your INGEST_TOKEN>"
        Content-Type: "application/x-ndjson"
    buffer:
      type: disk
      max_size: 268435488
```

> Vector's journald `message` field is the Gateway's JSON line. The `text` codec
> forwards it verbatim, which is what Gatorcast wants. Do not switch to the `json`
> codec: Vector then wraps the line as `{"message":"<line>",…}`, and Gatorcast only
> unwraps a `{"log":"<line>"}` envelope, so every line would be dropped as noise.

---

## 3. Terraform — AWS EC2

**Setup.** A small EC2 instance (t3.micro/small) in the same VPC as your SSH
targets runs the Gateway under systemd. We provision it with Terraform and use
**`user_data` (cloud-init)** to install the Gateway under systemd and lay down
the journald → HTTP shipper from §2.1. Forwarding to Gatorcast is then automatic
on every boot.

`forwarder.tftpl` (a reusable cloud-init fragment — the forwarding half). It
templates the `.env` (which carries the endpoint + token) and enables the
service; the static `journald-http-shipper.sh` and `.service` from §2.1 are
expected to already be on the instance — bake them into your golden image, or
deliver them via cloud-init `write_files`:

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- journald -> HTTP shipper config (script + unit come from §2.1) ---
install -m 600 /dev/stdin /etc/journald-http-shipper.env <<EOF
LOG_ENDPOINT=${gatorcast_url}/ingest
AUTH_TOKEN=${ingest_token}
JOURNAL_ID=gateway
CONTENT_TYPE=application/x-ndjson
EOF

systemctl daemon-reload
systemctl enable --now journald-http-shipper
```

`main.tf`:

```hcl
locals {
  forwarder = templatefile("${path.module}/forwarder.tftpl", {
    gatorcast_url = "https://gatorcast.internal.example.com:8080"
    ingest_token  = var.ingest_token            # pass via TF_VAR / secrets, never hardcode
  })
}

resource "aws_instance" "gateway" {
  ami                    = var.gateway_ami       # current Ubuntu/Debian/RHEL LTS
  instance_type          = "t3.small"
  subnet_id              = var.private_subnet_id
  vpc_security_group_ids = [aws_security_group.gateway.id]

  # Real deployments concatenate the Gateway install + this forwarder via
  # cloud-init's multipart user_data or a templated bootstrap script.
  user_data = local.forwarder
}

resource "aws_security_group" "gateway" {
  name_prefix = "twingate-gateway-"
  vpc_id      = var.vpc_id

  # Egress to Gatorcast (HTTP door) + Twingate control plane (443).
  egress {
    description = "Gatorcast ingest"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.gatorcast_cidr]
  }
  egress {
    description = "Twingate / outbound HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "ingest_token" {
  type      = string
  sensitive = true
}
```

> **Secrets.** Pull `ingest_token` from AWS Secrets Manager / SSM Parameter Store
> (`data "aws_secretsmanager_secret_version"`) rather than a plaintext variable.
> If you front Gatorcast with TLS and a public hostname, the security group can
> egress `443` to it instead of `8080`.

**Alternative — CloudWatch path.** If your org standardizes on the CloudWatch
agent, you can run a tiny Lambda/subscription that re-POSTs the Gateway log
group's events to `/ingest`. The direct shipper above is simpler and avoids the
round-trip; prefer it unless you already centralize on CloudWatch.

---

## 4. Terraform — GCP Compute Engine

**Setup.** An `e2-micro`/`e2-small` Compute Engine instance in the same VPC runs
the Gateway under systemd. GCP's equivalent of `user_data` is the
**`startup-script` metadata key**. The same `forwarder.tftpl` from §3 is reused
verbatim.

```hcl
locals {
  forwarder = templatefile("${path.module}/forwarder.tftpl", {
    gatorcast_url = "https://gatorcast.internal.example.com:8080"
    ingest_token  = var.ingest_token
  })
}

resource "google_compute_instance" "gateway" {
  name         = "twingate-gateway"
  machine_type = "e2-small"
  zone         = var.zone

  boot_disk {
    initialize_params { image = "ubuntu-os-cloud/ubuntu-2404-lts" }
  }

  network_interface {
    subnetwork = var.subnet         # private; no public IP needed if egress via Cloud NAT
  }

  metadata = {
    startup-script = local.forwarder
  }
}

# Egress firewall: allow the Gateway out to Gatorcast's HTTP door.
resource "google_compute_firewall" "gateway_egress" {
  name      = "twingate-gateway-egress"
  network   = var.network
  direction = "EGRESS"
  allow {
    protocol = "tcp"
    ports    = ["8080", "443"]
  }
  destination_ranges = [var.gatorcast_cidr, "0.0.0.0/0"]
  target_tags        = ["twingate-gateway"]
}
```

> Outbound from a private instance needs **Cloud NAT** (or a route) to reach an
> off-VPC Gatorcast and the Twingate control plane. Source `ingest_token` from
> Secret Manager (`google_secret_manager_secret_version`).

---

## 5. Terraform — Azure Linux VM

**Setup.** A `Standard_B1s` Linux VM in the same VNet runs the Gateway under
systemd. Azure's `user_data` mechanism is **`custom_data`** (base64-encoded
cloud-init). Same `forwarder.tftpl` from §3.

```hcl
locals {
  forwarder = templatefile("${path.module}/forwarder.tftpl", {
    gatorcast_url = "https://gatorcast.internal.example.com:8080"
    ingest_token  = var.ingest_token
  })
}

resource "azurerm_linux_virtual_machine" "gateway" {
  name                = "twingate-gateway"
  resource_group_name = var.resource_group
  location            = var.location
  size                = "Standard_B1s"
  admin_username      = "azureuser"
  network_interface_ids = [azurerm_network_interface.gateway.id]

  custom_data = base64encode(local.forwarder)

  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_public_key
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
}

# NSG egress rule: allow the Gateway out to Gatorcast.
resource "azurerm_network_security_rule" "gateway_to_gatorcast" {
  name                        = "egress-gatorcast"
  resource_group_name         = var.resource_group
  network_security_group_name = azurerm_network_security_group.gateway.name
  priority                    = 200
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["8080", "443"]
  source_address_prefix       = "*"
  destination_address_prefix  = var.gatorcast_cidr
}

variable "ingest_token" {
  type      = string
  sensitive = true
}
```

> Source `ingest_token` from Azure Key Vault (`azurerm_key_vault_secret`). If the
> VM has no public IP, ensure outbound via NAT Gateway or a default route.

---

## 6. Docker / docker-compose Gateway

**Setup.** The Gateway runs as a container (not systemd). Its logs are the
container's stdout. The cleanest path is Docker's built-in **syslog log driver**
pointed straight at Gatorcast's syslog TCP door — no extra shipper process.

`docker-compose.yml` (Gateway side):

```yaml
services:
  twingate-gateway:
    image: twingate/gateway:latest
    # ...gateway config, volumes, etc...
    logging:
      driver: syslog
      options:
        syslog-address: "tcp://gatorcast.internal.example.com:6514"
        syslog-format: "rfc5424"
        tag: "gateway"
```

Or as a plain `docker run` (same options):

```bash
docker run \
  --log-driver=syslog \
  --log-opt syslog-address=tcp://gatorcast.internal.example.com:6514 \
  --log-opt syslog-format=rfc5424 \
  --log-opt tag=gateway \
  twingate/gateway:latest
```

Each stdout line is wrapped in a syslog frame and sent over TCP; Gatorcast skips
the `<PRI>` header and parses the Gateway JSON. Gatorcast accepts both octet-counted and
newline-delimited TCP framing, so it does not matter which one the driver uses. **TCP
only** — never `udp://` (asciicast chunks would be truncated). Point `syslog-address` at
the syslog port you publish (the shipped `docker-compose.yml` binds it to `127.0.0.1`; see
§1.2).

**Alternative — HTTP via Fluent Bit/Vector sidecar.** If you'd rather use the
authenticated HTTP door, run a Fluent Bit container with a `forward`/`docker`
input and the `http` output from §7.3. Note Gatorcast auto-unwraps the Docker
`{"log":"…","stream":"stdout"}` envelope, so a collector that forwards the raw
Docker log record still works without a parser step.

---

## 7. Kubernetes (EKS / AKS / GKE)

**Setup.** The Gateway runs as a pod (e.g. via the Twingate Helm chart) and logs
to stdout, which the kubelet writes to the node's container log files. A node-
level log agent (Fluent Bit as a DaemonSet here) tails those files, keeps only
the Gateway pod's lines, and POSTs them to Gatorcast's HTTP door.

### 7.1 Why this is low-friction

Kubernetes/CRI log records arrive wrapped (`{"log":"<line>","stream":"stdout",…}`).
For CRI-format container logs, the `log` value can also start with a CRI prefix
(`<timestamp> stdout F`, then the line). **Gatorcast unwraps the `{"log":…}` collector envelope
automatically**, and parses the inner line from its first `{`, so you do not need a JSON
parser/decoder filter just to expose the inner Gateway line — forward the record and
Gatorcast recovers it. The unwrap applies only to a top-level `log` string, so do not
rename or nest that field in a Fluent Bit filter.

### 7.2 Scope the agent to the Gateway pod

Match only the Gateway's logs (adjust namespace/labels to your install):

```ini
[INPUT]
    Name              tail
    Tag               gateway.*
    Path              /var/log/containers/*twingate-gateway*_*.log
    Refresh_Interval  5
    Skip_Long_Lines   Off          # asciicast chunks are large — do NOT skip them
    Buffer_Max_Size   2MB
    Mem_Buf_Limit     16MB
```

> `Skip_Long_Lines Off` (and a generous `Buffer_Max_Size`) matters: recording
> chunks are multi-KB and the default would silently drop them.

### 7.3 Output to Gatorcast

```ini
[OUTPUT]
    Name    http
    Match   gateway.*
    Host    gatorcast.internal.example.com
    Port    8080
    URI     /ingest
    Format  json_lines
    Header  Authorization Bearer ${INGEST_TOKEN}
    tls     On
    Retry_Limit  False              # retry forever rather than drop on a blip
```

Wire `INGEST_TOKEN` in as a Kubernetes Secret mounted as an env var on the
DaemonSet. The DaemonSet's pods need network egress to Gatorcast (a
NetworkPolicy/egress rule), and — as always — the cluster nodes must have a real
route to Gatorcast since the Gateway pod is not on the Twingate overlay.

**Alternative — Vector aggregator.** For a single chokepoint with disk buffering,
run a Vector `kubernetes_logs` source filtered to the Gateway pod and the same
`http` sink shape as §2.5.

---

## 8. Quick manual test (curl)

Before wiring any shipper, confirm the door works end-to-end. This is also how
you smoke-test connectivity from the Gateway host itself.

```bash
# A minimal valid session: start event, one recording chunk, close event.
curl -sS -X POST "https://gatorcast.internal.example.com:8080/ingest" \
  -H "Authorization: Bearer <your INGEST_TOKEN>" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary $'{"logger":"gateway","message":"Authenticated connection","conn_id":"test-001","resource_address":"demo-host","user":{"username":"you@corp"}}\n{"logger":"gateway.audit","conn_id":"test-001","asciicast_sequence_num":0,"asciicast":"{\\"version\\":2,\\"width\\":80,\\"height\\":24,\\"timestamp\\":1718700000}\\n[0.5,\\"o\\",\\"hello from gatorcast\\\\r\\\\n\\"]\\n","user":{"username":"you@corp"}}\n{"logger":"gateway","message":"Connection closed","conn_id":"test-001"}'
```

A `204 No Content` means the request was accepted; it does not mean every line was
kept. A `401` means the bearer token is missing or wrong. If the session does not
appear, check Gatorcast's logs for `normalize.drop` (a line that is not a JSON object).

The start line creates a hidden pending connection, and the chunk promotes it to a
session. The recording is written to disk and playable as soon as its chunk is
processed. The trailing close event seals it to *complete* immediately. The stock
Gateway does not log a close event; its real end signal is a recording chunk whose
`message` is `"session finished"` (emitted by the recorder on session stop), which
also seals the recording. With neither, the recording still seals via the idle
backstop after `SESSION_MAX_IDLE_SECONDS` (default 1 h), and a later chunk reopens it.

To smoke-test web-app ingestion, send a `WEB_APP` start line (with a `gwops` object) and one
request on the same `conn_id`. The system `wiki.example.test` then appears in `/systems` with a
`Web` badge and a configured `HTTPS` badge, and `/search?type=web` lists the connection:

```bash
curl -sS -X POST "https://gatorcast.internal.example.com:8080/ingest" \
  -H "Authorization: Bearer <your INGEST_TOKEN>" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary $'{"logger":"gateway","message":"Authenticated connection","conn_id":"web-test-001","ts":"2026-10-08T12:00:00.000Z","resource_type":"WEB_APP","resource_address":"wiki.example.test","user":{"id":"u-1","username":"you@corp"},"gwops":{"schema":1,"gateway_id":"R2F0ZXdheToxMjk0","match":"exact","app":"wiki","managed":true,"downstream_tls":"tls13","downstream_port":443,"upstream_tls":"verify_full","upstream_port":443}}\n{"logger":"gateway.audit","message":"API request completed","conn_id":"web-test-001","request_id":"3f2b8c1e-9d4a-4c7b-8e2f-6a1b0c9d8e7f","ts":"2026-10-08T12:00:00.250Z","requested_at":"2026-10-08T12:00:00.200Z","method":"GET","url":"/report?month=09","user":{"id":"u-1","username":"you@corp"},"request":{"headers":{"User-Agent":["curl/8.0"]}},"response":{"status_code":200}}'
```

The stored URL is `/report?month=…(2)`: the query value is masked and the path is not.
Use a current `ts` (or `?window=all` on the dashboard) so the connection falls inside the
default 30-day window. For a fuller data set, `scripts/seed_demo.py` posts seven demo web apps
(see [TESTING.md](TESTING.md#2-seeding-demo-data)).

To replay actual Gateway journald output through the door for a realistic test:

```bash
journalctl -t gateway -o cat --since "10 min ago" \
  | curl -sS -X POST "https://gatorcast.internal.example.com:8080/ingest" \
      -H "Authorization: Bearer <your INGEST_TOKEN>" \
      -H "Content-Type: application/x-ndjson" \
      --data-binary @-
```

Or stream a growing file line-by-line (one POST per line — testing only, no
batching or retry):

```bash
tail -F gateway.log | while IFS= read -r line; do
  curl -sS -X POST "https://gatorcast.internal.example.com:8080/ingest" \
    -H "Authorization: Bearer <your INGEST_TOKEN>" \
    -H "Content-Type: text/plain" \
    --data-binary "$line"
done
```

For anything beyond a smoke test, use one of the shipper recipes above — they
give you batching, buffering, and retry that a bare `curl` loop does not.

---

## 9. Reaching a self-hosted or private Gatorcast

Because the Gateway has **no Twingate overlay connectivity**, a Gatorcast that
only lives behind Twingate (e.g. self-hosted at home) is not directly reachable.
Pick one:

| Option | How | Notes |
| --- | --- | --- |
| **Public ingress + TLS** | Front Gatorcast's `:8080` with a reverse proxy (e.g. NPMplus / Caddy / nginx) on a public hostname with a cert | The `INGEST_TOKEN` bearer auth is what makes the HTTP door safe to expose. The same port also serves the UI (HTTP Basic auth), so if you only want intake public, have the proxy forward just `/ingest`. Don't expose syslog `6514` this way. |
| **Site-to-site / VPN route** | Give the Gateway host a network route to Gatorcast's network (WireGuard, IPsec, cloud peering) | Keeps everything private; use the syslog TCP door over the tunnel. |
| **Reverse SSH tunnel** | From the Gatorcast host, `ssh -R 8080:localhost:8080 gateway-host` (or autossh) | Quick for labs/testing; fragile for production. |
| **Connector beside the sink** | Run a Twingate connector on Gatorcast's network and a *separate* forwarding hop that is overlay-connected | Heavier; only if policy forbids any direct route. The Gateway itself still can't use the overlay. |

For internal/cloud deployments where the Gateway and Gatorcast share a VPC/VNet,
none of this applies — just allow the egress rule (see the Terraform sections)
and point the shipper at the private address.

---

## 10. Picking a recipe

| Your Gateway runs as… | Start with |
| --- | --- |
| systemd on a VM (however installed) | §2.1 journald → HTTP shipper |
| systemd, org standardizes on rsyslog | §2.2 (HTTP) or §2.3 (syslog TCP) |
| systemd on LXC / privilege-drop host | §2.4 stderr-to-file → `imfile` |
| systemd, also shipping logs elsewhere | §2.5 Vector |
| Terraform-provisioned cloud VM | §3 / §4 / §5 (bakes §2.1 into boot) |
| a Docker container | §6 syslog driver (or Fluent Bit for HTTP) |
| a Kubernetes pod | §7 Fluent Bit DaemonSet → HTTP |
| wrapped by gwops (web apps, recordings) | §1.4 (gwops ships to `/ingest` itself; give it an `https://` URL) |
| anything — just testing | §8 curl |

Whatever the platform, the contract is identical: **forward the Gateway's
stdout/stderr JSON, line-intact, to `/ingest` or the syslog TCP listener.**
Gatorcast does the rest.
