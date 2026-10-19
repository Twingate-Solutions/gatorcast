"""Session 13 secret hygiene: Gateway 2.0.0 content Gatorcast does not read never reaches anything.

Sentinels are planted in the 2.0.0 shapes that carry content Gatorcast must not store:

* the ``ssh`` object of ``audit`` SSH connection events (``username``, ``client_version``,
  ``server_version``, ``id``, and invented ``env`` / ``exec`` style fields, as the preview SSH audit
  lines carried);
* the ``ssh`` object of ``session_recording`` chunks (everything except ``channel.id``);
* ``system`` service lines and JSON proxy-error lines (message text and extra fields).

The batch is ingested through a real app, the UI is crawled, both CSV exports are fetched, and
the DB cells, raw DB files, volume files, captured logs, rendered pages and CSV are scanned for every
sentinel. Runs with encryption off and on, reusing the Session 9 harness in ``test_secret_hygiene``.
"""

from __future__ import annotations

import json
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from tests.samples import GA_EXEC_REQUEST_ID, GA_K8S_CONN, GA_SSH_CONN, ga_recording_lines
from tests.test_secret_hygiene import BatchRun, _all_hits, _crawl, _run_batch, _scalar

SENT = {
    "ssh_audit_username": "SENTINEL_GA_SSHAUDIT_USER_6c1e90ab",
    "ssh_audit_client": "SENTINEL_GA_SSHAUDIT_CLIENT_2d7f43e8",
    "ssh_audit_server": "SENTINEL_GA_SSHAUDIT_SERVER_b05a19c4",
    "ssh_audit_id": "SENTINEL_GA_SSHAUDIT_ID_91e3d7f0",
    "ssh_audit_env": "SENTINEL_GA_SSHAUDIT_ENV_f4a82b6d",
    "ssh_audit_exec": "SENTINEL_GA_SSHAUDIT_EXEC_07c9e5a1",
    "chunk_ssh_username": "SENTINEL_GA_CHUNKSSH_USER_3b8d6f21",
    "chunk_ssh_client": "SENTINEL_GA_CHUNKSSH_CLIENT_e6a07c93",
    "chunk_ssh_server": "SENTINEL_GA_CHUNKSSH_SERVER_58d1b4fa",
    "chunk_ssh_id": "SENTINEL_GA_CHUNKSSH_ID_a29c7e05",
    "chunk_ssh_type": "SENTINEL_GA_CHUNKSSH_CHTYPE_c71f3a8e",
    "system_message": "SENTINEL_GA_SYSTEM_MSG_4e0b92d7",
    "system_field": "SENTINEL_GA_SYSTEM_FIELD_d83a61c5",
    "proxy_error": "SENTINEL_GA_PROXYERR_9a5c2f18",
    "proxy_error_field": "SENTINEL_GA_PROXYERR_FIELD_1f7e84b3",
}
SENTINELS = tuple(SENT.values())

_BASE = ga_recording_lines()


def _audit_ssh_line(message: str, tag: str) -> str:
    """A 2.0.0 ``audit`` SSH connection event whose ``ssh`` object carries sentinels."""
    obj = json.loads(_BASE[2])
    obj["message"] = message
    obj["ssh"] = {
        "id": SENT["ssh_audit_id"] + tag,
        "username": SENT["ssh_audit_username"] + tag,
        "client_version": SENT["ssh_audit_client"] + tag,
        "server_version": SENT["ssh_audit_server"] + tag,
        "env": {"AWS_SESSION": SENT["ssh_audit_env"] + tag},
        "exec": {"command": "cat /etc/shadow " + SENT["ssh_audit_exec"] + tag},
        "channels_opened": 1,
    }
    return json.dumps(obj)


def _chunk_with_sentinel_ssh(index: int) -> str:
    """A fixture SSH chunk whose ``ssh`` fields (all but ``channel.id``) carry sentinels."""
    obj = json.loads(_BASE[index])
    obj["ssh"].update(
        id=SENT["chunk_ssh_id"],
        username=SENT["chunk_ssh_username"],
        client_version=SENT["chunk_ssh_client"],
        server_version=SENT["chunk_ssh_server"],
    )
    obj["ssh"]["channel"]["type"] = SENT["chunk_ssh_type"]
    return json.dumps(obj)


def _batch_lines() -> list[str]:
    """The GA fixture with sentinels added; order keeps each start line ahead of its other lines."""
    service = json.loads(_BASE[0])
    service["message"] = "Using local CA for SSH authentication " + SENT["system_message"]
    service["ssh_ca_public_key"] = SENT["system_field"]
    proxy_error = {
        "levelname": "error",
        "ts": "2026-10-15T09:20:00.000Z",
        "logger": "system",
        "caller": "httputil/reverseproxy.go:700",
        "message": "http: proxy error: tls: failed to verify certificate: x509: certificate is valid"
        f" for {SENT['proxy_error']}",
        "version": "2.0.0",
        "tenant_host": SENT["proxy_error_field"],
    }
    return [
        json.dumps(service),
        _BASE[1],
        _audit_ssh_line("SSH connection established", "_a"),
        _chunk_with_sentinel_ssh(3),
        json.dumps(proxy_error),
        _chunk_with_sentinel_ssh(4),
        _chunk_with_sentinel_ssh(5),
        _audit_ssh_line("SSH connection closed", "_b"),
        *_BASE[7:],
    ]


def _sweep(client: TestClient, batch: BatchRun) -> None:
    """Fetch the surfaces that could carry a stored value: pages, a crawl, and both CSV exports."""
    batch.pages = {}
    seeds = [
        "/dashboard",
        "/search",
        "/search?type=any",
        "/search?type=ssh",
        "/search?type=exec",
        "/search?type=kubectl",
        "/search?type=web",
        "/search?keyword=file-b",
        "/search/export.csv",
        "/search/export.csv?type=any",
        "/search/export.csv?type=kubectl",
        "/systems",
        "/systems/ssh-target.example.test:22",
        "/systems/kubernetes.default.svc.cluster.local",
        f"/sessions/{GA_SSH_CONN}",
        f"/sessions/{GA_K8S_CONN}",
    ]
    batch.explicit_paths = list(seeds)
    _crawl(client, batch, seeds)  # type: ignore[arg-type]  # BatchRun has the same page fields


@pytest.fixture(scope="module", params=[False, True], ids=["encryption-off", "encryption-on"])
def ga_hygiene_run(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> BatchRun:
    """One ingest + UI sweep of the sentinel-bearing GA batch per encryption mode."""
    tag = "enc" if request.param else "plain"
    return _run_batch(
        tmp_path_factory.mktemp(f"ga_hygiene_{tag}"),
        _batch_lines(),
        encryption=request.param,
        sweep=_sweep,
    )


# --------------------------------------------------------------------------- controls


def test_every_sentinel_is_planted_in_the_input() -> None:
    """Non-vacuous: each sentinel really is on a line of the posted batch."""
    text = "\n".join(_batch_lines())
    for name, sentinel in SENT.items():
        assert sentinel in text, name
    assert len(set(SENTINELS)) == len(SENTINELS) and all(len(s) >= 16 for s in SENTINELS)


def test_the_pipeline_ran_and_the_sweep_fetched_real_pages(ga_hygiene_run: BatchRun) -> None:
    """The batch was accepted and stored, and the crawl reached the session pages and both CSVs."""
    run = ga_hygiene_run
    assert run.ingest_status == 200
    events = run.logs.structlog_events()
    ingest = next(e for e in events if e["event"] == "ingest.http")
    assert ingest["accepted_by_kind"] == {"ApiRequest": 1, "RecordingChunk": 5, "SessionStart": 2}
    # service line + proxy error (system) and the two SSH audit events (audit) are noise.
    assert ingest["dropped_by_reason"] == {"noise": 4}
    assert ingest["noise_by_logger"] == {"audit": 2, "system": 2}
    assert [e for e in events if e["event"] == "pipeline.error"] == []
    assert _scalar(run.db_path, "SELECT COUNT(*) FROM sessions WHERE status = 'complete'") == 2
    assert _scalar(run.db_path, "SELECT COUNT(*) FROM api_requests") == 1
    assert _scalar(run.db_path, "SELECT COUNT(*) FROM connections") == 2
    for path in run.explicit_paths:
        assert run.pages[path].status == 200, f"{path} -> {run.pages[path].status}"
    assert GA_SSH_CONN in run.pages[f"/sessions/{GA_SSH_CONN}"].text
    csv_pages = [pg for p, pg in run.pages.items() if p.startswith("/search/export.csv")]
    assert len(csv_pages) >= 3 and all(GA_SSH_CONN in pg.text for pg in csv_pages[:1])
    assert run.logs.text().strip(), "log capture recorded nothing (vacuous)"


# --------------------------------------------------------------------------- scans


def test_no_sentinel_reaches_db_volume_or_logs(ga_hygiene_run: BatchRun) -> None:
    """DB cells, raw SQLite files, ``.cast`` / sidecar files and every captured log are clean."""
    leaks = _all_hits(ga_hygiene_run, SENTINELS)
    assert leaks == {}, f"sentinel found: {leaks}"


def test_no_sentinel_in_any_rendered_page_or_csv(ga_hygiene_run: BatchRun) -> None:
    """Every crawled HTML page and CSV export is free of every sentinel."""
    hits = {
        path: [s for s in SENTINELS if s in page.text]
        for path, page in ga_hygiene_run.pages.items()
    }
    assert {p: h for p, h in hits.items() if h} == {}
    assert len(ga_hygiene_run.pages) >= 16


def test_identity_is_the_envelope_user_never_the_ssh_username(ga_hygiene_run: BatchRun) -> None:
    """Stored identity is ``user.username``; the ``ssh.username`` sentinel appears nowhere stored."""
    conn = sqlite3.connect(str(ga_hygiene_run.db_path))
    try:
        rows = {
            r[0]: r[1:]
            for r in conn.execute("SELECT conn_id, username, shell_user FROM sessions")
        }
    finally:
        conn.close()
    assert rows[GA_SSH_CONN] == ("placeholder-user", "placeholder")  # shell account: header, not ssh
    assert rows[GA_K8S_CONN][0] == "placeholder-user"


def test_exec_request_id_link_survives_the_sentinel_batch(ga_hygiene_run: BatchRun) -> None:
    """The unrelated k8s exec recording still links to its 101 request."""
    assert (
        _scalar(
            ga_hygiene_run.db_path,
            "SELECT request_id FROM sessions WHERE conn_id = ?",
            (GA_K8S_CONN,),
        )
        == GA_EXEC_REQUEST_ID
    )


def test_ssh_chunk_sentinels_are_not_in_the_cast_files(ga_hygiene_run: BatchRun) -> None:
    """Only recorded terminal text is in a ``.cast``; none of the ``ssh`` metadata is."""
    casts = list((ga_hygiene_run.data_dir / "casts").glob("*"))
    assert casts
    blob = b"".join(p.read_bytes() for p in casts)
    for sentinel in SENTINELS:
        assert sentinel.encode() not in blob
    # The ssh object's keys are not copied either.
    assert not re.search(rb"client_version|server_version", blob)
