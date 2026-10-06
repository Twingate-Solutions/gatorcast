"""Synthetic fixture builder for the unified timeline tests (Session 10, spec §12).

Inserts ``sessions``, ``findings``, ``connections``, ``api_requests`` and
``api_findings`` rows directly with controlled timestamps. Nothing here comes from a
real capture. Imported as ``tests.fixtures.timeline`` (same convention as
``tests.samples``).

:func:`build_scenario` covers every case listed in spec §12: two clusters and two
users; a kubectl run spanning two connections under one ``Kubectl-Session``; a
k9s-style connection with 250 requests and no session header; a discovery-only
command; an exec command linked to its recording by ``request_id``; commands that
start before / end after a window; a ``Kubectl-Session`` of ``c:<conn_id>``; hostile
``kubectl_command`` values; flagged commands at each severity (one high + medium);
a failed connection and an SSH ``error`` row with chunks; API requests carrying only
``user.id``; and recordings whose ``connections`` row carries a ``user_id``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import aiosqlite

from gatorcast.pipeline.detect import SEVERITY_RANK

DAY = "2026-10-01"

ALICE = "alice@example.com"
ALICE_ID = "uid-alice"
BOB = "bob@example.com"
BOB_ID = "uid-bob"
CAROL = "carol@example.com"
CAROL_ID = "uid-carol"
DAVE_ID = "uid-dave"  # API requests with user.id only (no username)

WEB = "web-01"
PROD = "prod-k8s"
DEV = "dev-k8s"

K9S_REQUESTS = 250

# (rule_id, category, severity, label, offset_seconds)
RecFinding = tuple[str, str, str, str, float | None]
# (rule_id, severity, label); category is always kube-api
ApiFindingSpec = tuple[str, str, str]


def at(hms: str) -> str:
    """Return ``DAY`` + ``hms`` in the stored ``YYYY-MM-DDTHH:MM:SS.mmmZ`` format.

    Args:
        hms: ``HH:MM:SS`` or ``HH:MM:SS.mmm``.
    """
    if "." not in hms:
        hms = f"{hms}.000"
    return f"{DAY}T{hms}Z"


async def add_session(
    db: aiosqlite.Connection,
    conn_id: str,
    *,
    started_at: str | None,
    username: str | None = None,
    resource_address: str | None = WEB,
    status: str = "complete",
    chunk_count: int = 2,
    cast_path: str | None = "auto",
    request_id: str | None = None,
    duration: float | None = None,
    created_at: str | None = None,
    findings: Sequence[RecFinding] = (),
) -> None:
    """Insert one ``sessions`` row and its ``findings`` (summary columns derived).

    Args:
        db: The database.
        conn_id: Primary key.
        started_at: Stored ``started_at`` (any shape), or ``None``.
        username: Envelope username.
        resource_address: System.
        status: ``complete`` / ``provisional`` / ``error``.
        chunk_count: Chunks received.
        cast_path: ``"auto"`` for ``<conn_id>.cast``, or a value / ``None``.
        request_id: exec request id (``None`` for SSH).
        duration: ``duration_seconds``.
        created_at: ``created_at`` override (``YYYY-MM-DD HH:MM:SS``).
        findings: Finding tuples.
    """
    path = f"/data/casts/{conn_id}.cast" if cast_path == "auto" else cast_path
    max_sev = None
    for f in findings:
        if max_sev is None or SEVERITY_RANK[f[2]] > SEVERITY_RANK[max_sev]:
            max_sev = f[2]
    await db.execute(
        """
        INSERT INTO sessions (conn_id, username, resource_address, started_at,
            duration_seconds, chunk_count, cast_path, status, finding_count,
            max_severity, request_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now')))
        """,
        (
            conn_id,
            username,
            resource_address,
            started_at,
            duration,
            chunk_count,
            path,
            status,
            len(findings),
            max_sev,
            request_id,
            created_at,
        ),
    )
    for rule_id, category, severity, label, offset in findings:
        await db.execute(
            "INSERT INTO findings (conn_id, rule_id, category, severity, label, offset_seconds) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (conn_id, rule_id, category, severity, label, offset),
        )
    await db.commit()


async def add_connection(
    db: aiosqlite.Connection,
    conn_id: str,
    *,
    user_id: str | None,
    username: str | None,
    resource_address: str | None,
    state: str = "recording",
) -> None:
    """Insert one ``connections`` row."""
    await db.execute(
        "INSERT INTO connections (conn_id, user_id, username, resource_address, state) "
        "VALUES (?, ?, ?, ?, ?)",
        (conn_id, user_id, username, resource_address, state),
    )
    await db.commit()


async def add_request(
    db: aiosqlite.Connection,
    request_id: str,
    *,
    conn_id: str,
    requested_at: str,
    resource_address: str | None = PROD,
    user_id: str | None = None,
    username: str | None = None,
    method: str = "GET",
    url: str = "/api/v1/namespaces/default/pods",
    status_code: int = 200,
    kubectl_command: str | None = None,
    kubectl_session: str | None = None,
    user_agent: str | None = "kubectl/v1.30.0 (linux/amd64) kubernetes/abc",
    findings: Sequence[ApiFindingSpec] = (),
    commit: bool = True,
) -> None:
    """Insert one ``api_requests`` row (``user_key`` = user id, else username)."""
    await db.execute(
        """
        INSERT INTO api_requests (request_id, conn_id, resource_address, user_key,
            user_id, username, requested_at, method, url, status_code, outcome,
            kubectl_command, kubectl_session, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?)
        """,
        (
            request_id,
            conn_id,
            resource_address,
            user_id or username,
            user_id,
            username,
            requested_at,
            method,
            url,
            status_code,
            kubectl_command,
            kubectl_session,
            user_agent,
        ),
    )
    for rule_id, severity, label in findings:
        await db.execute(
            "INSERT INTO api_findings (request_id, rule_id, category, severity, label) "
            "VALUES (?, ?, 'kube-api', ?, ?)",
            (request_id, rule_id, severity, label),
        )
    if commit:
        await db.commit()


@dataclass
class Scenario:
    """Ids of the rows :func:`build_scenario` inserted, for assertions."""

    sessions: list[str] = field(default_factory=list)
    requests: list[str] = field(default_factory=list)


async def build_scenario(db: aiosqlite.Connection) -> Scenario:
    """Insert the full spec §12 scenario and return the ids.

    Recordings (system ``web-01`` unless noted)::

        s-ssh-alice   10:00:00.000  alice  high+medium findings, 120 s
        s-ssh-bob     10:05:00.000  bob    no findings, 30 s
        s-exec-bob    10:10:00.000  bob    prod-k8s exec (request_id req-exec-101)
        s-failed      10:15:00.000  alice  failed connection (error, 0 chunks, no cast)
        s-ssh-error   10:20:00.000  bob    error WITH chunks and a cast (stays ssh)
        s-carol       10:25:00.000  carol  connections.user_id = uid-carol
        s-tie-a/-b    10:30:00.000  alice  equal start and duration
        s-created     (NULL)        bob    created_at 09:30:00 fallback
        s-low         10:40:00.000  alice  low finding
        s-crit        10:45:00.000  bob    critical finding
        s-prov        10:50:00.000  alice  provisional (in progress)
        s-same-at     11:00:00.000  alice  same instant as command ks-1's start

    kubectl commands (``prod-k8s`` unless noted), by start row::

        r-dave-1   09:45:00.000  ks-dave (dev-k8s, user.id only)
        r-dev-1    09:50:00.000  ks-dev-1 (dev-k8s, alice, "kubectl get pods")
        r-early-1  08:59:59.000  ks-early (second request inside a 09:00 window)
        r-exec-get 10:09:59.000  ks-exec (high; links s-exec-bob via req-exec-101)
        r-c1-1     11:00:00.000  ks-1 (conn-a + conn-b, 3 requests)
        r-disc-1   11:30:00.000  ks-disc (discovery only)
        r-sh-a/b   11:40/11:41   ks-shared under alice and under bob (two commands)
        r-empty-1  11:50:00.000  conn-empty ('' header, then NULL header: one command)
        r-k9s-000  12:00:00.000  conn-k9s, 250 requests, no header
        r-cx-1     12:30:00.000  header "c:conn-k9s" (must not merge with conn-k9s)
        r-xss/r-eq 12:40:00.000  "<script>" and "=" commands, equal start
        r-qs       12:50:00.000  "zebrafish" only in the query string
        r-low      13:00:00.000  low
        r-med      13:05:00.000  medium (secrets path)
        r-high     13:10:00.000  high
        r-crit     13:15:00.000  critical
        r-hm-1     13:20:00.000  ks-hm: medium then high (max high)
        r-late-1   13:59:59.000  ks-late, second request at 14:00:10
    """
    sc = Scenario()

    async def sess(conn_id: str, **kw: object) -> None:
        await add_session(db, conn_id, **kw)  # type: ignore[arg-type]
        sc.sessions.append(conn_id)

    async def req(request_id: str, **kw: object) -> None:
        await add_request(db, request_id, **kw)  # type: ignore[arg-type]
        sc.requests.append(request_id)

    # --- recordings -----------------------------------------------------------------
    await sess(
        "s-ssh-alice",
        started_at=at("10:00:00.000"),
        username=ALICE,
        duration=120.0,
        findings=[
            ("rm-rf", "dangerous-command", "high", "Recursive delete", 62.0),
            ("aws-access-key", "secret-exposure", "medium", "AWS access key", 220.0),
        ],
    )
    await sess("s-ssh-bob", started_at=at("10:05:00.000"), username=BOB, duration=30.0)
    await sess(
        "s-exec-bob",
        started_at=at("10:10:00.000"),
        username=BOB,
        resource_address=PROD,
        request_id="req-exec-101",
        duration=41.0,
        findings=[("shell-spawn", "dangerous-command", "medium", "Interactive shell", 3.0)],
    )
    await sess(
        "s-failed",
        started_at=at("10:15:00.000"),
        username=ALICE,
        status="error",
        chunk_count=0,
        cast_path=None,
    )
    await sess(
        "s-ssh-error",
        started_at=at("10:20:00.000"),
        username=BOB,
        status="error",
        chunk_count=3,
    )
    await sess("s-carol", started_at=at("10:25:00.000"), username=CAROL, duration=10.0)
    await sess("s-tie-a", started_at=at("10:30:00.000"), username=ALICE, duration=5.0)
    await sess("s-tie-b", started_at=at("10:30:00.000"), username=ALICE, duration=5.0)
    await sess(
        "s-created",
        started_at=None,
        created_at=f"{DAY} 09:30:00",
        username=BOB,
        duration=60.0,
    )
    await sess(
        "s-low",
        started_at=at("10:40:00.000"),
        username=ALICE,
        duration=7.0,
        findings=[("curl-pipe-sh", "dangerous-command", "low", "Pipe to shell", 1.0)],
    )
    await sess(
        "s-crit",
        started_at=at("10:45:00.000"),
        username=BOB,
        duration=8.0,
        findings=[("private-key", "secret-exposure", "critical", "Private key", 2.0)],
    )
    await sess(
        "s-prov",
        started_at=at("10:50:00.000"),
        username=ALICE,
        status="provisional",
        chunk_count=1,
    )
    await sess("s-same-at", started_at=at("11:00:00.000"), username=ALICE, duration=1.0)

    # connections: every alice/bob recording carries its user_id; carol's too.
    owners = {
        "s-ssh-alice": (ALICE_ID, ALICE, WEB),
        "s-ssh-bob": (BOB_ID, BOB, WEB),
        "s-exec-bob": (BOB_ID, BOB, PROD),
        "s-failed": (ALICE_ID, ALICE, WEB),
        "s-ssh-error": (BOB_ID, BOB, WEB),
        "s-carol": (CAROL_ID, CAROL, WEB),
        "s-tie-a": (ALICE_ID, ALICE, WEB),
        "s-tie-b": (ALICE_ID, ALICE, WEB),
        "s-created": (BOB_ID, BOB, WEB),
        "s-low": (ALICE_ID, ALICE, WEB),
        "s-crit": (BOB_ID, BOB, WEB),
        "s-prov": (ALICE_ID, ALICE, WEB),
        "s-same-at": (ALICE_ID, ALICE, WEB),
    }
    for conn_id, (uid, name, system) in owners.items():
        await add_connection(db, conn_id, user_id=uid, username=name, resource_address=system)

    # --- kubectl commands -------------------------------------------------------------
    bob = {"user_id": BOB_ID, "username": BOB}
    alice = {"user_id": ALICE_ID, "username": ALICE}

    # ks-1: one kubectl run over two connections.
    await req("r-c1-1", conn_id="conn-a", requested_at=at("11:00:00.000"), url="/api?timeout=32s",
              kubectl_session="ks-1", kubectl_command="kubectl get", **bob)
    await req("r-c1-2", conn_id="conn-b", requested_at=at("11:00:00.500"),
              url="/api/v1/namespaces/default/pods?limit=500",
              kubectl_session="ks-1", kubectl_command="kubectl get", **bob)
    await req("r-c1-3", conn_id="conn-b", requested_at=at("11:00:01.000"),
              url="/api/v1/namespaces/default/pods/web-1",
              kubectl_session="ks-1", kubectl_command="kubectl get", **bob)

    # k9s: 250 requests on one connection, no Kubectl-Session.
    for i in range(K9S_REQUESTS):
        ms = i * 100
        await req(
            f"r-k9s-{i:03d}",
            conn_id="conn-k9s",
            requested_at=at(f"12:00:{ms // 1000:02d}.{ms % 1000:03d}"),
            url="/api/v1/pods?limit=500",
            user_agent="k9s/v0.32.5 (linux/amd64)",
            commit=False,
            **alice,
        )
    await db.commit()

    # discovery-only command
    await req("r-disc-1", conn_id="conn-disc", requested_at=at("11:30:00.000"), url="/api",
              kubectl_session="ks-disc", kubectl_command="kubectl api-resources", **bob)
    await req("r-disc-2", conn_id="conn-disc", requested_at=at("11:30:00.100"),
              url="/apis/apps/v1", kubectl_session="ks-disc",
              kubectl_command="kubectl api-resources", **bob)

    # exec command linked to s-exec-bob through request_id req-exec-101
    await req("r-exec-get", conn_id="conn-exec-1", requested_at=at("10:09:59.000"),
              url="/api/v1/namespaces/default/pods/web-1",
              kubectl_session="ks-exec", kubectl_command="kubectl exec", **bob)
    await req("req-exec-101", conn_id="conn-exec-2", requested_at=at("10:10:00.000"),
              url="/api/v1/namespaces/default/pods/web-1/exec?container=web&stdin=true&tty=true",
              status_code=101, kubectl_session="ks-exec", kubectl_command="kubectl exec",
              findings=[("kube-exec", "high", "Pod exec")], **bob)

    # window edges
    await req("r-early-1", conn_id="conn-early", requested_at=at("08:59:59.000"),
              kubectl_session="ks-early", kubectl_command="kubectl get", **alice)
    await req("r-early-2", conn_id="conn-early", requested_at=at("09:00:05.000"),
              kubectl_session="ks-early", kubectl_command="kubectl get", **alice)
    await req("r-late-1", conn_id="conn-late", requested_at=at("13:59:59.000"),
              kubectl_session="ks-late", kubectl_command="kubectl logs", **alice)
    await req("r-late-2", conn_id="conn-late", requested_at=at("14:00:10.000"),
              kubectl_session="ks-late", kubectl_command="kubectl logs", **alice)

    # a header value that looks like a connection fallback key
    await req("r-cx-1", conn_id="conn-x", requested_at=at("12:30:00.000"), url="/api/v1/nodes",
              kubectl_session="c:conn-k9s", kubectl_command="kubectl get", **alice)

    # hostile command values, equal start instant
    await req("r-xss", conn_id="conn-xss", requested_at=at("12:40:00.000"),
              url="/api/v1/namespaces", kubectl_session="ks-xss",
              kubectl_command="<script>alert(1)</script>", **bob)
    await req("r-eq", conn_id="conn-eq", requested_at=at("12:40:00.000"),
              url="/api/v1/namespaces", kubectl_session="ks-eq",
              kubectl_command="=cmd|calc", **bob)

    # a value present only in the query string
    await req("r-qs", conn_id="conn-qs", requested_at=at("12:50:00.000"),
              url="/api/v1/namespaces/default/pods?labelSelector=zebrafish",
              kubectl_session="ks-qs", kubectl_command="kubectl get", **bob)

    # flagged commands at each severity, and one high + medium
    await req("r-low", conn_id="conn-low", requested_at=at("13:00:00.000"), method="PATCH",
              url="/api/v1/nodes/n1", kubectl_session="ks-low", kubectl_command="kubectl cordon",
              findings=[("kube-cordon", "low", "Node cordon")], **alice)
    await req("r-med", conn_id="conn-med", requested_at=at("13:05:00.000"),
              url="/api/v1/namespaces/default/secrets/db", kubectl_session="ks-med",
              kubectl_command="kubectl get", findings=[("kube-secrets", "medium", "Secret read")],
              **bob)
    await req("r-high", conn_id="conn-high", requested_at=at("13:10:00.000"), method="DELETE",
              url="/api/v1/namespaces/default/pods/web-2", kubectl_session="ks-high",
              kubectl_command="kubectl delete",
              findings=[("kube-delete", "high", "Resource delete")], **alice)
    await req("r-crit", conn_id="conn-crit", requested_at=at("13:15:00.000"),
              url="/api/v1/nodes/n1/proxy/exec", kubectl_session="ks-crit",
              kubectl_command="kubectl get --raw",
              findings=[("kube-node-proxy-exec", "critical", "Node proxy exec")], **bob)
    await req("r-hm-1", conn_id="conn-hm", requested_at=at("13:20:00.000"),
              url="/api/v1/namespaces/default/secrets/token", kubectl_session="ks-hm",
              kubectl_command="kubectl delete",
              findings=[("kube-secrets", "medium", "Secret read")], **alice)
    await req("r-hm-2", conn_id="conn-hm", requested_at=at("13:20:01.000"), method="DELETE",
              url="/api/v1/namespaces/default/secrets/token", kubectl_session="ks-hm",
              kubectl_command="kubectl delete",
              findings=[("kube-delete", "high", "Resource delete")], **alice)

    # the same session id under two users → two commands
    await req("r-sh-a", conn_id="conn-sh-a", requested_at=at("11:40:00.000"),
              kubectl_session="ks-shared", kubectl_command="kubectl get", **alice)
    await req("r-sh-b", conn_id="conn-sh-b", requested_at=at("11:41:00.000"),
              kubectl_session="ks-shared", kubectl_command="kubectl get", **bob)

    # an empty header is absent: '' and NULL on one connection are one command
    await req("r-empty-1", conn_id="conn-empty", requested_at=at("11:50:00.000"),
              kubectl_session="", kubectl_command="kubectl get", **bob)
    await req("r-empty-2", conn_id="conn-empty", requested_at=at("11:50:01.000"),
              kubectl_session=None, kubectl_command="kubectl get", **bob)

    # second cluster: user.id-only requests, and alice
    await req("r-dave-1", conn_id="conn-dave", requested_at=at("09:45:00.000"),
              resource_address=DEV, user_id=DAVE_ID, username=None,
              kubectl_session="ks-dave", kubectl_command="kubectl get")
    await req("r-dave-2", conn_id="conn-dave", requested_at=at("09:45:01.000"),
              resource_address=DEV, user_id=DAVE_ID, username=None,
              kubectl_session="ks-dave", kubectl_command="kubectl get")
    await req("r-dev-1", conn_id="conn-dev", requested_at=at("09:50:00.000"),
              resource_address=DEV, url="/api/v1/namespaces/kube-system/pods",
              kubectl_session="ks-dev-1", kubectl_command="kubectl get pods", **alice)
    return sc
