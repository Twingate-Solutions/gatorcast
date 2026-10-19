"""Session 13 end to end: Gateway 2.0.0 fixtures through ``POST /ingest`` into the stores and UI.

Uses the two gwops fixtures (``tests/fixtures/ga_recording_lines.ndjson``,
``ga_webapp_lines.ndjson``) and the preview ``sample_log_lines.ndjson``. Rows are read through
an independent ``sqlite3`` connection; the queue is drained with ``ingest_queue.join`` so every
event has been through the assembler before anything is asserted.

Per-channel (``ssh.channel.id``) behaviour is deliberately not covered here: those semantics
are changing and their tests are pending.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from gatorcast.config import Settings
from gatorcast.main import create_app
from gatorcast.pipeline.assembler import session_id_for
from tests.samples import (
    GA_CHANNEL_ID,
    GA_EXEC_REQUEST_ID,
    GA_K8S_CONN,
    GA_SSH_CONN,
    ga_recording_lines,
    ga_webapp_json_objects,
    ga_webapp_lines,
    sample_lines,
)

INGEST_TOKEN = "ga-e2e-ingest-token"
GA_CHANNEL_B = "00000000-0000-4000-8000-0000000000b2"  # a second channel on the same connection


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        syslog_tcp_port=0,
        ingest_token=INGEST_TOKEN,
        ui_auth_username="admin",
        ui_auth_password="change-me",
    )


def _ui() -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(b"admin:change-me").decode()}


def _ingest(client: TestClient, app, lines: list[str]):
    """POST ``lines`` as NDJSON and wait until the consumer has processed every event."""
    resp = client.post(
        "/ingest",
        content="\n".join(lines) + "\n",
        headers={"Authorization": f"Bearer {INGEST_TOKEN}", "Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 200, resp.text
    client.portal.call(app.state.ingest_queue.join)
    return resp


def _rows(db_path: Path, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def _cast(tmp_path: Path, conn_id: str) -> str:
    """Plaintext ``.cast`` (encryption is off in these tests)."""
    return (tmp_path / "casts" / f"{conn_id}.cast").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- GA recording fixture


def test_ga_recording_fixture_response_counts(tmp_path: Path) -> None:
    """8 of the 11 lines are events; the service line and both SSH audit events are noise."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = _ingest(client, app, ga_recording_lines())
    assert resp.json() == {
        "accepted": 8,
        "dropped": 3,
        "accepted_by_kind": {"ApiRequest": 1, "RecordingChunk": 5, "SessionStart": 2},
        "dropped_by_reason": {"noise": 3},
        "noise_by_logger": {"audit": 2, "system": 1},
    }


def test_ga_ssh_recording_is_one_complete_session_with_one_header(tmp_path: Path) -> None:
    """3 chunks (seq 1, 2, 3 final) reassemble into one sealed ``.cast``: one header, events in order."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    with TestClient(app) as client:
        _ingest(client, app, ga_recording_lines())
        rows = _rows(settings.db_path, "SELECT * FROM sessions WHERE conn_id = ?", (GA_SSH_CONN,))
        assert len(rows) == 1
        row = rows[0]
        assert row["status"] == "complete"
        assert row["sealed_terminal"] == 1  # terminal seal on "session finished"
        assert row["chunk_count"] == 3
        assert row["resource_type"] == "SSH"
        assert row["resource_address"] == "ssh-target.example.test:22"
        assert row["username"] == "placeholder-user"  # envelope identity
        assert row["shell_user"] == "placeholder"  # asciicast header user, secondary only
        assert row["width"] == 120 and row["height"] == 40
        assert row["parent_conn_id"] is None  # the first stream keeps conn_id
        assert row["stream"] == GA_CHANNEL_ID  # the claim is persisted
        assert row["duration_seconds"] == 330.0

        text = _cast(tmp_path, GA_SSH_CONN)
        lines = [ln for ln in text.split("\n") if ln]
        assert sum(1 for ln in lines if ln.startswith("{")) == 1
        assert lines[0].startswith('{"version":2')
        events = [json.loads(ln) for ln in lines if ln.startswith("[")]
        assert [e[2] for e in events] == [
            "Welcome\r\n", "$ ", "ls\r\n", "file-a  file-b\r\n", "$ ", "exit\r\n",
        ]
        assert [e[0] for e in events] == sorted(e[0] for e in events)

        connection = _rows(
            settings.db_path, "SELECT state, resource_type FROM connections WHERE conn_id = ?",
            (GA_SSH_CONN,),
        )[0]
        assert (connection["state"], connection["resource_type"]) == ("recording", "SSH")


def test_ga_ssh_recording_plaintext_is_searchable_without_leaking_into_html(tmp_path: Path) -> None:
    """Keyword search finds the SSH session through its sidecar; the page never shows the text."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        _ingest(client, app, ga_recording_lines())
        hit = client.get("/search?keyword=file-b", headers=_ui())
        miss = client.get("/search?keyword=zzz-not-recorded", headers=_ui())
        page = client.get(f"/sessions/{GA_SSH_CONN}", headers=_ui())
    assert hit.status_code == 200 and GA_SSH_CONN in hit.text
    assert GA_SSH_CONN not in miss.text
    assert page.status_code == 200
    # Rule 6: recorded text is never rendered. (The search form echoes the query, so check a
    # recorded string that was not queried, and the session page, which has no query.)
    assert "file-a" not in hit.text and "file-a" not in page.text
    assert "file-b" not in page.text and "Welcome" not in page.text
    # The fixture's channel id is a UUID string. The first stream on a connection keeps
    # conn_id as its session id, so there is no separate "Recording id".
    assert "<dt>SSH channel</dt>" in page.text
    assert GA_CHANNEL_ID in page.text  # (HTML-escaped; a UUID has no characters to escape)
    assert "<dt>Connection id</dt>" in page.text
    assert "Recording id" not in page.text


def test_ga_k8s_exec_session_is_complete_and_linked_to_its_101_request(tmp_path: Path) -> None:
    """The exec recording seals on its final chunk and its ``request_id`` matches the 101 audit row."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    with TestClient(app) as client:
        _ingest(client, app, ga_recording_lines())
        session = _rows(settings.db_path, "SELECT * FROM sessions WHERE conn_id = ?", (GA_K8S_CONN,))
        assert len(session) == 1
        assert session[0]["status"] == "complete"
        assert session[0]["sealed_terminal"] == 1
        assert session[0]["request_id"] == GA_EXEC_REQUEST_ID
        assert session[0]["chunk_count"] == 2
        assert session[0]["resource_type"] == "KUBERNETES"
        assert session[0]["resource_address"] == "kubernetes.default.svc.cluster.local"

        api = _rows(settings.db_path, "SELECT * FROM api_requests")
        assert len(api) == 1  # only the 101 line; SSH audit events never become API rows
        assert api[0]["request_id"] == GA_EXEC_REQUEST_ID
        assert api[0]["status_code"] == 101
        assert api[0]["api_kind"] == "kubectl"
        assert api[0]["conn_id"] == GA_K8S_CONN
        assert api[0]["user_agent"] == "kubectl/v1.30.0"
        # Exec URL: ``command`` is never stored.
        assert "command" not in api[0]["url"]

        text = _cast(tmp_path, GA_K8S_CONN)
        assert sum(1 for ln in text.split("\n") if ln.startswith("{")) == 1
        assert [json.loads(ln)[2] for ln in text.split("\n") if ln.startswith("[")] == [
            "# ", "exit\r\n",
        ]
        # The cluster's system page and the exec session page render.
        for path in (
            "/systems/kubernetes.default.svc.cluster.local",
            f"/sessions/{GA_K8S_CONN}",
        ):
            assert client.get(path, headers=_ui()).status_code == 200, path


def test_ga_recording_fixture_creates_no_session_for_dropped_lines(tmp_path: Path) -> None:
    """Exactly two sessions, two connections and one API row exist after the fixture."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    with TestClient(app) as client:
        _ingest(client, app, ga_recording_lines())
    assert {r["conn_id"] for r in _rows(settings.db_path, "SELECT conn_id FROM sessions")} == {
        GA_SSH_CONN, GA_K8S_CONN,
    }
    assert len(_rows(settings.db_path, "SELECT 1 FROM connections")) == 2
    assert len(_rows(settings.db_path, "SELECT 1 FROM api_requests")) == 1


# --------------------------------------------------------------------------- GA web fixture


def test_ga_webapp_fixture_response_counts(tmp_path: Path) -> None:
    """113 events (58 starts, 55 requests); 38 ``system`` noise lines; 6 non-JSON lines."""
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        resp = _ingest(client, app, ga_webapp_lines())
    objs = ga_webapp_json_objects()
    assert len(ga_webapp_lines()) - len(objs) == 6
    body = resp.json()
    assert body["accepted"] == 113
    assert body["accepted_by_kind"] == {"ApiRequest": 55, "SessionStart": 58}
    assert body["dropped_by_reason"] == {"noise": 38, "not_json": 6}
    assert body["noise_by_logger"] == {"system": 38}
    assert body["accepted"] + body["dropped"] == len(ga_webapp_lines())


def test_ga_webapp_fixture_stores_web_connections_and_web_rows(tmp_path: Path) -> None:
    """Every connection is ``WEB_APP``, every request a ``web`` row, and nothing becomes a session."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    with TestClient(app) as client:
        _ingest(client, app, ga_webapp_lines())
        db = settings.db_path
        conns = _rows(db, "SELECT conn_id, resource_type, state FROM connections")
        assert len(conns) == 58
        assert {c["resource_type"] for c in conns} == {"WEB_APP"}
        reqs = _rows(db, "SELECT request_id, conn_id, api_kind, user_agent FROM api_requests")
        assert len(reqs) == 55
        assert {r["api_kind"] for r in reqs} == {"web"}
        assert len({r["request_id"] for r in reqs}) == 55
        # 55 connections carried a request; the other 3 are still pending (hidden).
        assert sorted(c["state"] for c in conns).count("api") == 55
        assert sorted(c["state"] for c in conns).count("pending") == 3
        assert _rows(db, "SELECT 1 FROM sessions") == []
        assert _rows(db, "SELECT 1 FROM api_findings") == []  # no rules on web rows
        # The configured-TLS snapshot is unknown: this capture carries no gwops object.
        assert {r["downstream_tls"] for r in _rows(db, "SELECT downstream_tls FROM api_requests")} == {None}
        # Proxy-error and service lines stored nothing: no table holds their text.
        assert _rows(db, "SELECT 1 FROM api_requests WHERE url LIKE '%proxy error%'") == []
        search = client.get("/search?type=web", headers=_ui())
        assert search.status_code == 200


def test_ga_webapp_fixture_redelivery_is_idempotent(tmp_path: Path) -> None:
    """Posting the whole web capture twice stores the same rows (at-least-once delivery)."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    with TestClient(app) as client:
        _ingest(client, app, ga_webapp_lines())
        first = (
            len(_rows(settings.db_path, "SELECT 1 FROM connections")),
            len(_rows(settings.db_path, "SELECT 1 FROM api_requests")),
        )
        resp = _ingest(client, app, ga_webapp_lines())
    assert resp.json()["accepted"] == 113  # still classified; the stores deduplicate
    assert first == (58, 55)
    assert len(_rows(settings.db_path, "SELECT 1 FROM connections")) == 58
    assert len(_rows(settings.db_path, "SELECT 1 FROM api_requests")) == 55


# --------------------------------------------------------------------------- mixed generations


def test_mixed_preview_and_ga_batch_stores_both(tmp_path: Path) -> None:
    """A preview batch and the GA recording fixture in ONE post both land."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    with TestClient(app) as client:
        resp = _ingest(client, app, [*sample_lines(), *ga_recording_lines()])
    assert resp.json()["accepted"] == 11
    sessions = {r["conn_id"]: r["status"] for r in _rows(settings.db_path, "SELECT conn_id, status FROM sessions")}
    assert sessions[GA_SSH_CONN] == "complete" and sessions[GA_K8S_CONN] == "complete"
    assert len(sessions) == 3  # + the preview recording chunk (still provisional)
    assert len(_rows(settings.db_path, "SELECT 1 FROM api_requests")) == 2
    assert len(_rows(settings.db_path, "SELECT 1 FROM connections")) >= 3


_RENAMES = {"session_recording": "gateway.audit", "system": "gateway", "audit": "gateway.audit"}


def _as_preview(lines: list[str]) -> list[str]:
    """The same fixture lines with their 2.0.0 logger names mapped to the preview names."""
    out = []
    for line in lines:
        obj = json.loads(line)
        obj["logger"] = _RENAMES[obj["logger"]]
        out.append(json.dumps(obj))
    return out


_VOLATILE = {"created_at", "updated_at", "last_seen_at", "id"}


def _stable_rows(db_path: Path, table: str, order: str) -> list[dict]:
    rows = _rows(db_path, f"SELECT * FROM {table} ORDER BY {order}")  # noqa: S608
    out = []
    for r in rows:
        row = {k: r[k] for k in r.keys() if k not in _VOLATILE}
        if row.get("cast_path"):  # differs only by the per-run data directory
            row["cast_path"] = Path(row["cast_path"]).name
        out.append(row)
    return out


def test_ga_lines_and_their_preview_renames_store_identical_rows(tmp_path: Path) -> None:
    """Acceptance: GA and preview logger names produce the same stored data, cast included."""
    results = []
    for tag, lines in (("ga", ga_recording_lines()), ("preview", _as_preview(ga_recording_lines()))):
        data = tmp_path / tag
        data.mkdir()
        settings = _settings(data)
        app = create_app(settings)
        with TestClient(app) as client:
            _ingest(client, app, lines)
        results.append(
            (
                _stable_rows(settings.db_path, "sessions", "conn_id"),
                _stable_rows(settings.db_path, "connections", "conn_id"),
                _stable_rows(settings.db_path, "api_requests", "request_id"),
                {c: _cast(data, c) for c in (GA_SSH_CONN, GA_K8S_CONN)},
            )
        )
    ga, preview = results
    for index, name in enumerate(("sessions", "connections", "api_requests", "casts")):
        assert ga[index] == preview[index], name
    assert ga[0], "no session rows compared (vacuous)"


# --------------------------------------------------------------------------- two channels end to end


def _two_channel_lines() -> list[str]:
    """The fixture's SSH connection with a second channel (own UUID id) interleaved with the first."""
    base = ga_recording_lines()
    first = [json.loads(line) for line in base[3:6]]
    lines = [base[1]]
    for index, obj_a in enumerate(first):
        obj_b = json.loads(json.dumps(obj_a))
        obj_b["ssh"]["channel"]["id"] = GA_CHANNEL_B
        header, _, _events = obj_b["asciicast"].partition("\n")
        obj_b["asciicast"] = header + "\n" + json.dumps([float(index + 1), "o", f"chan-b-{index + 1}"])
        lines += [json.dumps(obj_a), json.dumps(obj_b)]
    return lines


def test_two_ssh_channels_are_two_recordings_with_their_own_pages(tmp_path: Path) -> None:
    """Channel A keeps ``conn_id``, channel B is derived; pages, system page, search and CSV list both."""
    settings = _settings(tmp_path)
    app = create_app(settings)
    derived = session_id_for(GA_SSH_CONN, GA_CHANNEL_B)
    with TestClient(app) as client:
        resp = _ingest(client, app, _two_channel_lines())
        assert resp.json()["accepted"] == 7 and resp.json()["dropped"] == 0
        rows = {
            r["conn_id"]: r
            for r in _rows(settings.db_path, "SELECT * FROM sessions")
        }
        assert set(rows) == {GA_SSH_CONN, derived}
        assert (rows[GA_SSH_CONN]["stream"], rows[GA_SSH_CONN]["parent_conn_id"]) == (GA_CHANNEL_ID, None)
        assert (rows[derived]["stream"], rows[derived]["parent_conn_id"]) == (GA_CHANNEL_B, GA_SSH_CONN)
        assert {r["status"] for r in rows.values()} == {"complete"}  # each channel's own final sealed it
        assert [json.loads(ln)[2] for ln in _cast(tmp_path, derived).split("\n") if ln.startswith("[")] == [
            "chan-b-1", "chan-b-2", "chan-b-3",
        ]
        assert "chan-b" not in _cast(tmp_path, GA_SSH_CONN)

        first = client.get(f"/sessions/{GA_SSH_CONN}", headers=_ui()).text
        assert "<dt>Connection id</dt>" in first and GA_CHANNEL_ID in first
        assert "Recording id" not in first and GA_CHANNEL_B not in first

        second = client.get(f"/sessions/{derived}", headers=_ui()).text
        assert "<dt>Connection id</dt>" in second
        assert f'<dd class="mono dim">{GA_SSH_CONN}</dd>' in second  # the REAL connection id
        assert "<dt>SSH channel</dt>" in second and GA_CHANNEL_B in second
        assert "<dt>Recording id</dt>" in second
        assert f'<dd class="mono dim">{derived}</dd>' in second

        system = client.get("/systems/ssh-target.example.test:22", headers=_ui()).text
        for sid in (GA_SSH_CONN, derived):
            assert f"/sessions/{sid}" in system, sid
        search = client.get("/search?type=ssh", headers=_ui()).text
        for sid in (GA_SSH_CONN, derived):
            assert sid in search, sid
        export = client.get("/search/export.csv?type=ssh", headers=_ui())
        assert export.status_code == 200
        for sid in (GA_SSH_CONN, derived):
            assert sid in export.text, sid
        assert client.get(f"/sessions/{derived}/cast", headers=_ui()).status_code == 200
        # Recorded text never reaches a page.
        assert "chan-b" not in second + system + search + export.text
