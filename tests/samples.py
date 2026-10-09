"""Shared access to the Gateway sample log lines used across tests.

``sample_lines`` returns the real Gateway sample lines (``fixtures/sample_log_lines.ndjson``).

Web-app fixtures (Session 11, T1; WEBAPP_SPEC 12.1)
===================================================

NDJSON cannot carry comments, so this module is the documentation for two fixture files:

* ``fixtures/webapp_lines.ndjson`` (``webapp_lines()``): lines Gatorcast classifies. ``WEB_APP``
  traffic seeded from the Session 25 live capture, plus synthetic additions. 332 lines.
* ``fixtures/webapp_interim_lines.ndjson`` (``webapp_interim_lines()``): lines gwops ships today
  and B-20 will drop (non-JSON, gateway service lines, SSH audit and SSH operational lines).
  None of them may ever create a row or reach the logs. 67 lines.

Origin and sanitization
-----------------------
The capture is ``twingate-gateway-custom-container-image/docs/sessions/25-livetest/
webapp-gateway-lines.ndjson`` (gateway ``2.0.0-dev-5ed8e12``, one service-account client, 2026-10-08).
Sanitized before commit, consistently per original value so joins still hold:

* user id and username (identical in the capture) -> ``PLACEHOLDER-KEY-ID-1``; service-account id group ->
  ``PLACEHOLDER-SA-ID-1``; the capture's 8-hex rig/tenant label -> ``riglabel`` in every address and in the group name
  (``gwops-it-riglabel-client``); the tenant host in a service line ->
  ``tenant-placeholder.example.test``; the SSH CA public key in a service line -> a sentinel.
* Credential and secret-bearing values -> unique sentinels (below). The capture's ``conn_id`` and
  ``request_id`` UUIDs are random and kept. ``remote_addr`` (a docker-internal address) is kept;
  it is never read.
* Lines are re-serialized compactly with the same field order; Go's ``\\u003c``-style escapes are
  not reproduced.

Everything in ``webapp_lines.ndjson`` at index ``< WEBAPP_CAPTURE_LINE_COUNT`` is capture-derived
(start lines and ``API request completed`` lines only; its service lines and non-JSON lines are in
the interim file). A capture connection that is not in ``WEBAPP_CONNS`` is an unmodified (sanitized
only) capture connection; the ones that are registered carry a note when a sentinel was
substituted. Every line at index ``>= WEBAPP_CAPTURE_LINE_COUNT`` is **synthetic**: shapes the
capture lacks, built from the capture's own field set and order. Synthetic ids: ``conn_id``
``c0ffee00-0000-4000-8000-<n>``, ``request_id`` ``5eed0000-0000-4000-8000-<n>``, ``Kubectl-Session``
``6b0b0000-0000-4000-8000-<n>``; timestamps from ``2026-10-08T19:00:00Z`` (capture: 18:28-18:56).

Ordering: a start line precedes its requests in file order, except the deliberate exceptions
``late_start_web``, ``late_start_k8s`` and ``no_start`` (requests first or no start at all), and
the redelivery block, which is last (``webapp_redelivery()``). Every request line is
``API request completed`` unless noted (``hy_failed_panic`` is ``API request failed``). All
lines use one identity (``user.username == user.id == PLACEHOLDER-KEY-ID-1``).

Looking things up
-----------------
Each scenario has its own ``conn_id``: ``WEBAPP_CONNS[key]`` -> ``ConnInfo``,
``webapp_lines_for(key)`` -> its lines in file order. Notable single requests are in
``WEBAPP_REQUESTS[key]`` (``webapp_request_line(key)``). ``gw_*`` connections are one start line
plus one ``GET`` request (``webapp_lines_for(key)[1]``) and are described by ``WEBAPP_GWOPS_CASES``.
``check_webapp_fixture_index()`` verifies this index against the files; run it from one test.

Sentinels
---------
``WEBAPP_SENTINELS`` maps a group to its values; every value is ``SENTINEL_<GROUP>_<NAME>_<hex8>``
(>= 16 characters, unique, greppable). Where each may appear:

* ``WEBAPP_NEVER_STORED_SENTINELS``: credential header values (``AUTHZ``, ``COOKIE``, ``APIKEY``,
  ``PROXYAUTH``, ``XAUTHTOKEN``, ``CSRF``, ``SETCOOKIE`` response header), spoofed identity headers
  (``SPOOF``), query values and query keys (``QUERY``; stored only masked, so the full value must
  not appear), the ``panic`` text (``PANIC``) and ``gwops`` content that is never read or stored
  (``GWOPS``). Absent from the DB, logs, UI and CSV. Masked output may reveal at most the first two
  and last two characters, so always search for the whole sentinel.
* ``WEBAPP_PATH_TOKENS``: path-embedded tokens. Stored **unmasked** in the stored path by design
  (WEBAPP_SPEC 5.3 withdrawn, 10), so they are expected in the DB, UI and CSV and must be absent
  from logs. Includes the three literal 5.7 values (JWT-shaped, UUID, ``jsessionid``).
* ``WEBAPP_USER_AGENT_SENTINELS``: a User-Agent. Stored in ``user_agent`` (<= 256 chars) but never
  rendered and never logged.
* ``WEBAPP_INTERIM_SENTINELS`` (``webapp_interim_lines.ndjson`` only): non-JSON, service and SSH
  content. Absent from the DB and logs.

Header variants
---------------
``WEBAPP_HEADER_VARIANTS``: the same credential-bearing request with credential values present
(sentinels), replaced by ``[REDACTED]``, and the header names removed. The variants of one group
have identical method, URL (the ``orders`` variants share one query sentinel on purpose), status
and User-Agent, so their stored rows must be identical apart from ids and times.

``gwops`` variants (WEBAPP_SPEC 3.3 / 12.1)
-------------------------------------------
``WEBAPP_GWOPS_CASES`` lists every variant with its outcome:

* ``accepted``: parsed to ``expected`` (the ``GwopsWebApp`` fields), nothing logged.
* ``accepted_app_ignored``: parsed with ``app=None``; one ``classify.gwops_field_ignored`` warning
  with reason ``gwops_bad_app``.
* ``rejected``: ``gwops=None``; one ``classify.gwops_rejected`` warning with ``reason``. Each rejected
  object carries a sentinel ``app`` that must reach neither the DB nor the logs.
* ``not_read``: object on a start line that is not ``WEB_APP`` (``KUBERNETES``, lowercase
  ``kubernetes``, ``SSH``, missing/junk/non-string/other ``resource_type``): never read, stored or
  logged. ``resource_type`` is the expected *normalized* value (``None`` when the key is missing,
  the ``invalid`` marker for junk and non-string values, ``models.RESOURCE_TYPE_INVALID``).
* ``absent``: no ``gwops`` key; nothing logged.

The capture's own start lines have no ``gwops`` object (it predates B-20); only synthetic start
lines carry one. **The app-to-mode mapping is inferred** from the rig app names (see
``WEBAPP_APP_MODE_MAPPING``): ``echo-plain`` plaintext upstream, ``echo-vca`` ``verify_ca``,
``echo-wrongfull`` ``verify_full`` (answered 502 against a wrong-host certificate), ``echo-tls``
``insecure`` (its first capture request failed ``unknown authority``, later ones succeeded),
``verifier-a`` ``tls13``/``verify_full`` (the WEBAPP_SPEC 3.1 example), ``verifier-b`` plain HTTP.
Confirm against the Session 25 rig config before relying on it. Ports and the ``gateway_id`` value
``'R2F0ZXdheToxMjk0'`` (the spec's example id) are illustrative.

Interim fixture: what is approximate
------------------------------------
``WEBAPP_INTERIM_SECTIONS`` gives each section's ``[start, stop)`` index range (sections are
contiguous) and ``WEBAPP_INTERIM_DOCS[i]`` describes line ``i`` as ``(section, origin, doc)``.
``origin == "capture"``: the 7 non-JSON lines and the 29 gateway service lines are verbatim
(sanitized only). ``origin == "approximate"``: **every other line is synthetic and its shape is
approximate**: the gateway source at ``5ed8e12`` (``internal/backend/ssh``) was not available, so
the SSH audit and SSH operational lines are built representatively from the message names known
from the gwops filter tests and BACKLOG B-20 (``Connection established``, ``Channel opened``,
channel / global requests with ``env`` and ``exec`` payloads) and the logger name ``gateway.audit``.
Field names beyond ``logger``, ``message``, ``conn_id``, ``user``, ``levelname``, ``ts``,
``caller`` and ``version`` are guesses. The synthetic non-JSON and service lines (panic, klog,
cobra, over-long-line fragments, rejected-connection and config errors) are likewise
representative, not captured. The tests that use them assert that *no line of any shape* creates a
row or leaks, so exact shapes matter less than the logger/message/sentinel placement.
"""

from __future__ import annotations

import json
from functools import lru_cache
from itertools import chain
from pathlib import Path
from typing import NamedTuple

FIXTURES = Path(__file__).parent / "fixtures"


def sample_lines() -> list[str]:
    """The real Gateway sample log lines, one per list entry."""
    text = (FIXTURES / "sample_log_lines.ndjson").read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line.strip()]


# --------------------------------------------------------------------------- web-app fixtures

WEBAPP_LINES_FILE = FIXTURES / "webapp_lines.ndjson"
WEBAPP_INTERIM_FILE = FIXTURES / "webapp_interim_lines.ndjson"

WEBAPP_LINE_COUNT = 332
WEBAPP_CAPTURE_LINE_COUNT = 113  # lines [0, N) are capture-derived, the rest synthetic
WEBAPP_GATEWAY_ID = 'R2F0ZXdheToxMjk0'  # example `gateway_id` used by the synthetic gwops objects


class ConnInfo(NamedTuple):
    """One fixture connection (a ``conn_id`` and the lines that share it)."""

    conn_id: str
    origin: str  # "capture" (sanitized capture, possibly with sentinels) or "synthetic"
    doc: str


class RequestInfo(NamedTuple):
    """One notable fixture request line."""

    request_id: str
    conn: str  # key into WEBAPP_CONNS
    origin: str
    doc: str


class GwopsCase(NamedTuple):
    """One ``gwops`` start-line variant and what the parser must do with it."""

    key: str  # key into WEBAPP_CONNS (start line + one GET request)
    outcome: str  # accepted | accepted_app_ignored | rejected | not_read | absent
    reason: str | None  # reason code for rejected / accepted_app_ignored, else None
    resource_type: str | None  # expected NORMALIZED resource_type on the SessionStart ('invalid' = marker)
    expected: dict | None  # expected GwopsWebApp fields for accepted outcomes, else None


def _exact(app, managed, downstream_tls, downstream_port, upstream_tls, upstream_port,
           gateway_id=WEBAPP_GATEWAY_ID) -> dict:
    """Expected ``GwopsWebApp`` fields for a ``match: exact`` object."""
    return {"match": "exact", "gateway_id": gateway_id, "app": app, "managed": managed,
            "downstream_tls": downstream_tls, "downstream_port": downstream_port,
            "upstream_tls": upstream_tls, "upstream_port": upstream_port}


def _no_app(match, gateway_id=WEBAPP_GATEWAY_ID) -> dict:
    """Expected ``GwopsWebApp`` fields for ``match: none`` / ``ambiguous``."""
    return {"match": match, "gateway_id": gateway_id, "app": None, "managed": None,
            "downstream_tls": None, "downstream_port": None, "upstream_tls": None,
            "upstream_port": None}


# Inferred (WEBAPP_SPEC 12.1): app name -> (downstream_tls, downstream_port, upstream_tls, upstream_port).
WEBAPP_APP_MODE_MAPPING = {
    "echo-plain": ("none", 80, "none", 80),
    "echo-tls": ("tls13", 443, "insecure", 443),
    "echo-vca": ("tls13", 443, "verify_ca", 443),
    "echo-wrongfull": ("tls13", 443, "verify_full", 443),
    "verifier-a": ("tls13", 443, "verify_full", 443),
    "verifier-b": ("none", 80, "none", 8080),
}

# Connection key -> what it is. Capture connections not listed here are unmodified capture traffic.
WEBAPP_CONNS: dict[str, ConnInfo] = {
    'cap_plain_get_root': ConnInfo('686adfd9-5e8e-4d45-b732-a056a29a2692', 'capture', 'echo-plain GET / 200 (plaintext upstream baseline).'),
    'cap_spoofed_identity': ConnInfo('35d2fce0-49bf-462c-9cce-753202aa31e7', 'capture', 'echo-plain GET / whose request.headers carry client-spoofed X-Twingate-User and X_twingate_user (sentinel values substituted).'),
    'cap_tls_502_unknown_ca': ConnInfo('90ef41ee-aa43-4bbc-8070-6f26d7ffaa91', 'capture', 'echo-tls GET / answered 502 with EMPTY response headers (upstream verification failure); its `http: proxy error` line is in the interim fixture.'),
    'cap_tls_empty': ConnInfo('2c4cb8c1-5bfc-4271-8bb4-8b9a8034e445', 'capture', 'echo-tls start line with no request at all (browser pre-connect style): expires `empty`.'),
    'cap_wrongfull_502': ConnInfo('59c3fb17-1d32-46e7-a72a-c0336fc2bce1', 'capture', 'echo-wrongfull GET / 502 (verify_full vs wrong-host cert), empty response headers.'),
    'cap_wrongfull_502_x': ConnInfo('3d8fb07d-7eb4-43de-b8ae-ffdcc1bfc54d', 'capture', 'echo-wrongfull GET /x 502, empty response headers.'),
    'cap_verifier_b_401': ConnInfo('6d9fc1d1-d4ca-43ef-9ed0-d578cb060633', 'capture', 'verifier-b GET / 401.'),
    'cap_post_submit_query': ConnInfo('07fbf84b-afb5-47d4-bc45-68c4f60e5f58', 'capture', "echo-plain POST /submit?q=<query sentinel> 200 (query-value sentinel substituted for the capture's QUERY-MARKER)."),
    'cap_post_login_creds': ConnInfo('3d3dd42d-e723-4498-8f82-d3a749880e40', 'capture', 'echo-plain POST /login 501 with Authorization, Cookie and X-Api-Key header values PRESENT (sentinels). Header-variant group `login`: present variant.'),
    'cap_post_orders_cookie': ConnInfo('c181e0b2-1fcf-420c-b78a-b311b7a31b8a', 'capture', 'verifier-a POST /orders?id=<query sentinel> 200 with Cookie value PRESENT (sentinel). Header-variant group `orders`: present variant.'),
    'cap_post_chunk': ConnInfo('2beecc12-a402-447a-85a6-0415697a7481', 'capture', "echo-plain POST /chunk 200 (chunked body); the capture's `Unsolicited response` non-JSON line belongs to this connection (interim fixture)."),
    'cap_post_big': ConnInfo('acd25ebc-5f98-4d5e-83b5-fb4dc1629f6f', 'capture', 'echo-plain POST /big (5 MiB, Expect: 100-continue) 200.'),
    'cap_post_big50': ConnInfo('c15daaff-8f59-4725-912e-5d253a0054ff', 'capture', 'echo-plain POST /big50 (50 MiB) 200.'),
    'cap_ws_a': ConnInfo('eda9edf3-2a16-44b5-a604-3da7770b1c75', 'capture', 'verifier-a GET /ws with Connection: Upgrade headers; the upstream answered 200, not 101 (as captured).'),
    'cap_ws_b': ConnInfo('25b9debf-23e1-415e-98bd-817546ef7249', 'capture', 'verifier-a second GET /ws (Upgrade headers), 200.'),
    'cap_empty_a': ConnInfo('8cb27cd5-d358-478b-92d9-648febef0d48', 'capture', 'verifier-a start line with no request (empty WEB_APP connection).'),
    'cap_empty_b': ConnInfo('50c73420-931a-415e-b9c1-0ae477d2762b', 'capture', 'verifier-a start line with no request (empty WEB_APP connection).'),
    'cap_report_month': ConnInfo('d1489ad5-e33d-4166-b173-2a22d02799f9', 'capture', 'echo-tls GET /report?month=09 200 (WEBAPP_SPEC 5.7 row 1).'),
    'cap_delete_items_42': ConnInfo('8026911c-841e-4477-8802-18f601a1d8e7', 'capture', 'verifier-a DELETE /items/42 200 (WEBAPP_SPEC 5.7 row 4).'),
    'cap_method_get': ConnInfo('8ea91146-1b53-431d-8ae4-ce8b15cb41b5', 'capture', 'verifier-a GET /m/GET 200.'),
    'cap_method_head': ConnInfo('1af61e5b-3f27-48d0-8a84-e82766739a01', 'capture', 'verifier-a HEAD /m/HEAD 200.'),
    'cap_method_post': ConnInfo('09b27caf-b0a9-42f0-ae18-cfb4415d0993', 'capture', 'verifier-a POST /m/POST 200.'),
    'cap_method_put': ConnInfo('063a4c75-e439-4783-b27a-25382c2d0b7a', 'capture', 'verifier-a PUT /m/PUT 200.'),
    'cap_method_patch': ConnInfo('a5e4303f-96a2-489a-9d78-364ecea2af8b', 'capture', 'verifier-a PATCH /m/PATCH 200.'),
    'cap_method_delete': ConnInfo('5a8cf261-d5cb-471d-a095-421acbbf966c', 'capture', 'verifier-a DELETE /m/DELETE 200.'),
    'cap_method_options': ConnInfo('f8411c4e-4129-4f09-9410-b058a0ad86e6', 'capture', 'verifier-a OPTIONS /m/OPTIONS 200.'),
    'cap_method_trace': ConnInfo('e4d22de0-9f5c-4bec-aa9b-e7fce2b96bae', 'capture', 'verifier-a TRACE /m/TRACE 405.'),
    'cap_method_propfind': ConnInfo('96b641b4-3d5f-4b60-b4cf-9a4eef603d2a', 'capture', 'verifier-a PROPFIND /m/PROPFIND 405 (WebDAV method; 8 chars).'),
    'cap_method_purge': ConnInfo('8bee74d4-d96b-4a92-a886-e29a4e30b31a', 'capture', 'verifier-a PURGE /m/PURGE 405.'),
    'cap_method_connect': ConnInfo('81c35839-c1cd-4a9a-a488-85aec2c7c06c', 'capture', 'verifier-a `CONNECT /` sent as a request, 405.'),
    'worked_examples': ConnInfo('c0ffee00-0000-4000-8000-000000000001', 'synthetic', 'portal.* WEB_APP connection (no gwops object) carrying every WEBAPP_SPEC 5.7 worked-example URL verbatim; expected stored values are in WORKED_EXAMPLES.'),
    'hygiene_requests': ConnInfo('c0ffee00-0000-4000-8000-000000000002', 'synthetic', 'portal.* WEB_APP connection (no gwops object) carrying sentinel-bearing URLs, credential headers, method variants, a 101, a failed line and a long URL.'),
    'bad_methods': ConnInfo('c0ffee00-0000-4000-8000-000000000003', 'synthetic', 'WEB_APP connection whose only requests have methods the widened gate (`[A-Za-z][A-Za-z0-9_-]{0,23}`) still rejects: every line is dropped (`api_bad_method`), so the connection ends up with no rows (`empty`).'),
    'web_rule_lookalikes': ConnInfo('c0ffee00-0000-4000-8000-000000000004', 'synthetic', 'portal.* WEB_APP connection whose requests would trip Kubernetes API rules / discovery on a kubectl connection; on web they must produce no findings.'),
    'hv_login_placeholder': ConnInfo('c0ffee00-0000-4000-8000-000000000005', 'synthetic', 'Header-variant group `login`: same request as cap_post_login_creds with Authorization, Cookie and X-Api-Key VALUES replaced by `[REDACTED]`.'),
    'hv_login_removed': ConnInfo('c0ffee00-0000-4000-8000-000000000006', 'synthetic', 'Header-variant group `login`: same request with the Authorization, Cookie and X-Api-Key header NAMES removed.'),
    'hv_orders_placeholder': ConnInfo('c0ffee00-0000-4000-8000-000000000007', 'synthetic', 'Header-variant group `orders`: same request as cap_post_orders_cookie with the Cookie value replaced by `[REDACTED]` (shares the query sentinel, so the stored URL is identical).'),
    'hv_orders_removed': ConnInfo('c0ffee00-0000-4000-8000-000000000008', 'synthetic', 'Header-variant group `orders`: same request with the Cookie header name removed.'),
    'spoof_variants': ConnInfo('c0ffee00-0000-4000-8000-000000000009', 'synthetic', 'WEB_APP connection; one request carries four spellings/cases of the client-spoofed identity header, each with its own sentinel. Identity must stay user.username.'),
    'hdr_tolerance': ConnInfo('c0ffee00-0000-4000-8000-000000000010', 'synthetic', 'WEB_APP connection exercising WEBAPP_SPEC 5.5 allowlisted-header tolerance: every request is still stored; the unusable User-Agent is stored as absent (NULL).'),
    'k8s_upper': ConnInfo('c0ffee00-0000-4000-8000-000000000011', 'synthetic', 'KUBERNETES (uppercase, as the real gateway emits) connection with a kubectl run: discovery, list, delete (kube-delete) and secret read (kube-secrets); no gwops key.'),
    'k8s_empty': ConnInfo('c0ffee00-0000-4000-8000-000000000012', 'synthetic', 'KUBERNETES start line with no request and no chunk: becomes a visible `error` session after SESSION_MAX_IDLE_SECONDS (unlike WEB_APP).'),
    'ssh_upper': ConnInfo('c0ffee00-0000-4000-8000-000000000013', 'synthetic', 'SSH start line (uppercase), no chunk, no gwops key: visible `error` after the idle timeout.'),
    'k8s_hdr_tolerance': ConnInfo('c0ffee00-0000-4000-8000-000000000014', 'synthetic', 'KUBERNETES connection: kubectl allowlisted headers absent / empty list; rows stored with NULL command/session (grouping falls back to the connection).'),
    'gw_exact_upstream_none': ConnInfo('c0ffee00-0000-4000-8000-000000000015', 'synthetic', 'gwops exact, upstream `none` (echo-plain), downstream none:80.'),
    'gw_exact_upstream_verify_ca': ConnInfo('c0ffee00-0000-4000-8000-000000000016', 'synthetic', 'gwops exact, upstream `verify_ca` (echo-vca).'),
    'gw_exact_upstream_verify_full': ConnInfo('c0ffee00-0000-4000-8000-000000000017', 'synthetic', 'gwops exact, upstream `verify_full` (echo-wrongfull; its request is the 502 with empty response headers).'),
    'gw_exact_upstream_insecure': ConnInfo('c0ffee00-0000-4000-8000-000000000018', 'synthetic', 'gwops exact, upstream `insecure` (echo-tls).'),
    'gw_exact_downstream_tls13': ConnInfo('c0ffee00-0000-4000-8000-000000000019', 'synthetic', 'gwops exact, downstream `tls13` port 443 (verifier-a; the spec 3.1 example object).'),
    'gw_exact_downstream_none': ConnInfo('c0ffee00-0000-4000-8000-000000000020', 'synthetic', 'gwops exact, downstream `none` port 80, upstream none:8080 (verifier-b).'),
    'gw_exact_unmanaged': ConnInfo('c0ffee00-0000-4000-8000-000000000021', 'synthetic', 'gwops exact, `managed: false`, free-text tenant-style app name with spaces and parentheses.'),
    'gw_gateway_id_null': ConnInfo('c0ffee00-0000-4000-8000-000000000022', 'synthetic', 'gwops exact with `gateway_id: null` (gwops Mode B before first reconcile): accepted.'),
    'gw_gateway_id_128': ConnInfo('c0ffee00-0000-4000-8000-000000000023', 'synthetic', 'gwops exact with a 128-character gateway_id (upper bound of `[A-Za-z0-9+/=_-]{1,128}`): accepted.'),
    'gw_app_len_200': ConnInfo('c0ffee00-0000-4000-8000-000000000024', 'synthetic', 'gwops exact with an app of exactly 200 code points: accepted, app stored.'),
    'gw_match_none': ConnInfo('c0ffee00-0000-4000-8000-000000000025', 'synthetic', 'gwops `match: none` (no app fields): accepted; only match and gateway_id stored; TLS unknown.'),
    'gw_match_ambiguous': ConnInfo('c0ffee00-0000-4000-8000-000000000026', 'synthetic', 'gwops `match: ambiguous` (no app fields): accepted; TLS unknown.'),
    'gw_match_none_app_fields': ConnInfo('c0ffee00-0000-4000-8000-000000000027', 'synthetic', 'gwops `match: none` that nevertheless carries app fields (sentinel app): the app fields are not read and never stored.'),
    'gw_match_none_unknown_key': ConnInfo('c0ffee00-0000-4000-8000-000000000028', 'synthetic', 'gwops `match: none` plus an unknown scalar key holding a sentinel: unknown keys never read, stored or logged.'),
    'gw_unknown_key_exact': ConnInfo('c0ffee00-0000-4000-8000-000000000029', 'synthetic', 'otherwise valid exact object plus an unknown `request_headers` key holding a sentinel: accepted, the key is ignored (never read, stored or logged).'),
    'gw_rej_not_object_string': ConnInfo('c0ffee00-0000-4000-8000-000000000030', 'synthetic', '`gwops` is a string (sentinel text).'),
    'gw_rej_not_object_null': ConnInfo('c0ffee00-0000-4000-8000-000000000031', 'synthetic', '`gwops: null` (key present, value null).'),
    'gw_rej_not_object_array': ConnInfo('c0ffee00-0000-4000-8000-000000000032', 'synthetic', '`gwops` is an array.'),
    'gw_rej_not_object_number': ConnInfo('c0ffee00-0000-4000-8000-000000000033', 'synthetic', '`gwops` is a number.'),
    'gw_rej_schema_2': ConnInfo('c0ffee00-0000-4000-8000-000000000034', 'synthetic', '`schema: 2`.'),
    'gw_rej_schema_string': ConnInfo('c0ffee00-0000-4000-8000-000000000035', 'synthetic', '`schema: "1"` (string).'),
    'gw_rej_schema_bool': ConnInfo('c0ffee00-0000-4000-8000-000000000036', 'synthetic', '`schema: true` (bool).'),
    'gw_rej_schema_missing': ConnInfo('c0ffee00-0000-4000-8000-000000000037', 'synthetic', '`schema` missing.'),
    'gw_rej_match_missing': ConnInfo('c0ffee00-0000-4000-8000-000000000038', 'synthetic', '`match` missing.'),
    'gw_rej_match_case': ConnInfo('c0ffee00-0000-4000-8000-000000000039', 'synthetic', '`match: "EXACT"` (case-sensitive).'),
    'gw_rej_match_unknown': ConnInfo('c0ffee00-0000-4000-8000-000000000040', 'synthetic', '`match: "partial"`.'),
    'gw_rej_gateway_id_space': ConnInfo('c0ffee00-0000-4000-8000-000000000041', 'synthetic', '`gateway_id` contains a space.'),
    'gw_rej_gateway_id_missing': ConnInfo('c0ffee00-0000-4000-8000-000000000042', 'synthetic', '`gateway_id` key missing.'),
    'gw_rej_gateway_id_int': ConnInfo('c0ffee00-0000-4000-8000-000000000043', 'synthetic', '`gateway_id` is an int.'),
    'gw_rej_gateway_id_empty': ConnInfo('c0ffee00-0000-4000-8000-000000000044', 'synthetic', '`gateway_id` is the empty string.'),
    'gw_rej_gateway_id_129': ConnInfo('c0ffee00-0000-4000-8000-000000000045', 'synthetic', '`gateway_id` is 129 characters.'),
    'gw_rej_managed_missing': ConnInfo('c0ffee00-0000-4000-8000-000000000046', 'synthetic', 'exact without `managed`.'),
    'gw_rej_managed_string': ConnInfo('c0ffee00-0000-4000-8000-000000000047', 'synthetic', '`managed: "true"` (string).'),
    'gw_rej_managed_int': ConnInfo('c0ffee00-0000-4000-8000-000000000048', 'synthetic', '`managed: 1` (int, not bool).'),
    'gw_rej_mode_downstream_upper': ConnInfo('c0ffee00-0000-4000-8000-000000000049', 'synthetic', '`downstream_tls: "TLS13"` (upper case).'),
    'gw_rej_mode_downstream_tls12': ConnInfo('c0ffee00-0000-4000-8000-000000000050', 'synthetic', '`downstream_tls: "tls12"`.'),
    'gw_rej_mode_downstream_missing': ConnInfo('c0ffee00-0000-4000-8000-000000000051', 'synthetic', '`downstream_tls` missing.'),
    'gw_rej_mode_upstream_upper': ConnInfo('c0ffee00-0000-4000-8000-000000000052', 'synthetic', '`upstream_tls: "VERIFY_FULL"` (upper case).'),
    'gw_rej_mode_upstream_unknown': ConnInfo('c0ffee00-0000-4000-8000-000000000053', 'synthetic', '`upstream_tls: "verify_none"`.'),
    'gw_rej_mode_upstream_missing': ConnInfo('c0ffee00-0000-4000-8000-000000000054', 'synthetic', '`upstream_tls` missing.'),
    'gw_rej_port_downstream_zero': ConnInfo('c0ffee00-0000-4000-8000-000000000055', 'synthetic', '`downstream_port: 0`.'),
    'gw_rej_port_upstream_65536': ConnInfo('c0ffee00-0000-4000-8000-000000000056', 'synthetic', '`upstream_port: 65536`.'),
    'gw_rej_port_string': ConnInfo('c0ffee00-0000-4000-8000-000000000057', 'synthetic', '`downstream_port: "443"` (string).'),
    'gw_rej_port_bool': ConnInfo('c0ffee00-0000-4000-8000-000000000058', 'synthetic', '`upstream_port: true` (bool).'),
    'gw_rej_port_float': ConnInfo('c0ffee00-0000-4000-8000-000000000059', 'synthetic', '`downstream_port: 443.0` (float).'),
    'gw_rej_port_missing': ConnInfo('c0ffee00-0000-4000-8000-000000000060', 'synthetic', '`upstream_port` missing.'),
    'gw_app_control_char': ConnInfo('c0ffee00-0000-4000-8000-000000000061', 'synthetic', 'exact; `app` contains a control character (U+0007, category Cc).'),
    'gw_app_bidi_char': ConnInfo('c0ffee00-0000-4000-8000-000000000062', 'synthetic', 'exact; `app` contains U+202E (category Cf).'),
    'gw_app_line_separator': ConnInfo('c0ffee00-0000-4000-8000-000000000063', 'synthetic', 'exact; `app` contains U+2028 (category Zl).'),
    'gw_app_too_long': ConnInfo('c0ffee00-0000-4000-8000-000000000064', 'synthetic', 'exact; `app` is 201 code points.'),
    'gw_app_empty': ConnInfo('c0ffee00-0000-4000-8000-000000000065', 'synthetic', 'exact; `app` is the empty string.'),
    'gw_app_not_string': ConnInfo('c0ffee00-0000-4000-8000-000000000066', 'synthetic', 'exact; `app` is an int.'),
    'gw_app_missing': ConnInfo('c0ffee00-0000-4000-8000-000000000067', 'synthetic', 'exact; `app` key missing.'),
    'gw_on_kubernetes_upper': ConnInfo('c0ffee00-0000-4000-8000-000000000068', 'synthetic', '`gwops` object (sentinel app) on a KUBERNETES start line: ignored. One kubectl request follows.'),
    'gw_on_kubernetes_lower': ConnInfo('c0ffee00-0000-4000-8000-000000000069', 'synthetic', '`gwops` object (sentinel app) on a lowercase `kubernetes` start line: normalized to KUBERNETES, object ignored.'),
    'gw_on_ssh_upper': ConnInfo('c0ffee00-0000-4000-8000-000000000070', 'synthetic', '`gwops` object (sentinel app) on an SSH start line: ignored. No request line follows (an SSH connection that stays empty).'),
    'gw_on_missing_resource_type': ConnInfo('c0ffee00-0000-4000-8000-000000000071', 'synthetic', 'start line with NO resource_type key but a `gwops` object (sentinel app): resource_type None, object ignored.'),
    'gw_on_junk_resource_type': ConnInfo('c0ffee00-0000-4000-8000-000000000072', 'synthetic', 'resource_type `WEB APP` (space; fails the `[A-Z][A-Z0-9_]{0,31}` check): resource_type is the `invalid` marker (models.RESOURCE_TYPE_INVALID), gwops ignored.'),
    'gw_on_non_string_resource_type': ConnInfo('c0ffee00-0000-4000-8000-000000000073', 'synthetic', 'resource_type is the integer 123: resource_type is the `invalid` marker (models.RESOURCE_TYPE_INVALID), gwops ignored.'),
    'gw_on_other_resource_type': ConnInfo('c0ffee00-0000-4000-8000-000000000074', 'synthetic', 'resource_type `DATABASE` (valid pattern, not WEB_APP): resource_type stored as DATABASE, gwops never read; its request is stored under the web policy (any non-null non-KUBERNETES type).'),
    'gw_resource_type_padded_lower': ConnInfo('c0ffee00-0000-4000-8000-000000000075', 'synthetic', 'resource_type ` web_app ` (lowercase, padded): normalizes to WEB_APP, so the valid exact object is read and accepted.'),
    'gw_absent': ConnInfo('c0ffee00-0000-4000-8000-000000000076', 'synthetic', 'WEB_APP start line with no `gwops` key (non-gwops sender or delivery not configured): TLS unknown, nothing logged.'),
    'late_start_web': ConnInfo('c0ffee00-0000-4000-8000-000000000077', 'synthetic', 'Requests delivered BEFORE their WEB_APP start line (shipper reordering). The start line carries a valid exact gwops object; the web backfill must convert the earlier rows to web with its modes.'),
    'late_start_k8s': ConnInfo('c0ffee00-0000-4000-8000-000000000078', 'synthetic', 'Requests delivered BEFORE their KUBERNETES start line: stored provisionally with the web-policy (masked) URL, then the start line says KUBERNETES so the rows stay kubectl with a masked query.'),
    'no_start': ConnInfo('c0ffee00-0000-4000-8000-000000000079', 'synthetic', 'Request whose start line never arrives (lost or truncated): stays a provisional kubectl row with the fail-closed web-policy URL.'),
    'redeliver': ConnInfo('c0ffee00-0000-4000-8000-000000000080', 'synthetic', 'Redelivery: lines for this conn_id appear 8 times in order: [start, req1, req2] originals, the same three lines byte-identical (replay), a start line with a DIFFERENT exact gwops object, and a start line with NO gwops object. First write must win.'),
    'redeliver_noobj_then_obj': ConnInfo('c0ffee00-0000-4000-8000-000000000081', 'synthetic', 'Redelivery: lines appear in order [start WITHOUT gwops, req] then a repeated start line WITH a valid exact object (sentinel app). The snapshot stays unknown.'),
}

# Notable single requests. Capture connections with exactly one request reuse the connection key.
WEBAPP_REQUESTS: dict[str, RequestInfo] = {
    'cap_plain_get_root': RequestInfo('ab2db8a1-0f3f-4458-9613-e66547890dad', 'cap_plain_get_root', 'capture', 'echo-plain GET / 200 (plaintext upstream baseline).'),
    'cap_spoofed_identity': RequestInfo('7954ca08-f701-4917-b069-d1617caf352f', 'cap_spoofed_identity', 'capture', 'echo-plain GET / whose request.headers carry client-spoofed X-Twingate-User and X_twingate_user (sentinel values substituted).'),
    'cap_tls_502_unknown_ca': RequestInfo('09a974e0-1cfc-4854-87dd-0c2ab7e8674e', 'cap_tls_502_unknown_ca', 'capture', 'echo-tls GET / answered 502 with EMPTY response headers (upstream verification failure); its `http: proxy error` line is in the interim fixture.'),
    'cap_wrongfull_502': RequestInfo('b282c830-354b-4ca5-8625-c5ed0ce95af9', 'cap_wrongfull_502', 'capture', 'echo-wrongfull GET / 502 (verify_full vs wrong-host cert), empty response headers.'),
    'cap_wrongfull_502_x': RequestInfo('ea7f7f09-edc5-4b32-ad77-170a5cfa6eef', 'cap_wrongfull_502_x', 'capture', 'echo-wrongfull GET /x 502, empty response headers.'),
    'cap_verifier_b_401': RequestInfo('c6311465-14cd-4b72-98f4-8552d807af97', 'cap_verifier_b_401', 'capture', 'verifier-b GET / 401.'),
    'cap_post_submit_query': RequestInfo('8293e7e4-21e2-4055-aab1-a3bda85e4634', 'cap_post_submit_query', 'capture', "echo-plain POST /submit?q=<query sentinel> 200 (query-value sentinel substituted for the capture's QUERY-MARKER)."),
    'cap_post_login_creds': RequestInfo('2d49b3b1-8118-408a-bab4-c7b38fd563e4', 'cap_post_login_creds', 'capture', 'echo-plain POST /login 501 with Authorization, Cookie and X-Api-Key header values PRESENT (sentinels). Header-variant group `login`: present variant.'),
    'cap_post_orders_cookie': RequestInfo('d0f417a1-63f8-485b-929f-aceb7aec4eaa', 'cap_post_orders_cookie', 'capture', 'verifier-a POST /orders?id=<query sentinel> 200 with Cookie value PRESENT (sentinel). Header-variant group `orders`: present variant.'),
    'cap_post_chunk': RequestInfo('1d95230e-4fbd-47ce-ba3b-45f8ff3595d8', 'cap_post_chunk', 'capture', "echo-plain POST /chunk 200 (chunked body); the capture's `Unsolicited response` non-JSON line belongs to this connection (interim fixture)."),
    'cap_post_big': RequestInfo('94143ad4-4872-4c45-9258-fbfcaebd1578', 'cap_post_big', 'capture', 'echo-plain POST /big (5 MiB, Expect: 100-continue) 200.'),
    'cap_post_big50': RequestInfo('624cbace-9336-49d7-b480-5b46c1c4ebab', 'cap_post_big50', 'capture', 'echo-plain POST /big50 (50 MiB) 200.'),
    'cap_ws_a': RequestInfo('9d9e3f24-2555-469e-b154-4c4e0e235bda', 'cap_ws_a', 'capture', 'verifier-a GET /ws with Connection: Upgrade headers; the upstream answered 200, not 101 (as captured).'),
    'cap_ws_b': RequestInfo('f78ea5ab-c049-4160-a124-45bd56cff0a7', 'cap_ws_b', 'capture', 'verifier-a second GET /ws (Upgrade headers), 200.'),
    'cap_report_month': RequestInfo('fa94bbe3-c9c0-44df-8dff-12802e15dbce', 'cap_report_month', 'capture', 'echo-tls GET /report?month=09 200 (WEBAPP_SPEC 5.7 row 1).'),
    'cap_delete_items_42': RequestInfo('31e676ef-4ef1-4f92-9bfb-a2acfd99993f', 'cap_delete_items_42', 'capture', 'verifier-a DELETE /items/42 200 (WEBAPP_SPEC 5.7 row 4).'),
    'cap_method_get': RequestInfo('94cc4e33-e37a-4a7c-a86d-65afd754630e', 'cap_method_get', 'capture', 'verifier-a GET /m/GET 200.'),
    'cap_method_head': RequestInfo('7382571b-0fed-4e7d-ab0a-752aeadb7ae1', 'cap_method_head', 'capture', 'verifier-a HEAD /m/HEAD 200.'),
    'cap_method_post': RequestInfo('b1c402ce-1b8a-4ef1-b115-a7b40d3c343e', 'cap_method_post', 'capture', 'verifier-a POST /m/POST 200.'),
    'cap_method_put': RequestInfo('719c07c0-d99e-4080-b7da-6e35a591e09d', 'cap_method_put', 'capture', 'verifier-a PUT /m/PUT 200.'),
    'cap_method_patch': RequestInfo('a04b3291-5def-4c64-94dc-521bd39d3b4c', 'cap_method_patch', 'capture', 'verifier-a PATCH /m/PATCH 200.'),
    'cap_method_delete': RequestInfo('669bd907-1e7d-41fb-8bc6-bd7c469967d4', 'cap_method_delete', 'capture', 'verifier-a DELETE /m/DELETE 200.'),
    'cap_method_options': RequestInfo('bd867023-7f89-41ae-86f6-27add876b79e', 'cap_method_options', 'capture', 'verifier-a OPTIONS /m/OPTIONS 200.'),
    'cap_method_trace': RequestInfo('aec32722-22b1-4426-80e0-a8175e35b4a3', 'cap_method_trace', 'capture', 'verifier-a TRACE /m/TRACE 405.'),
    'cap_method_propfind': RequestInfo('f742eedd-9334-43d5-b88a-56bdeea1edac', 'cap_method_propfind', 'capture', 'verifier-a PROPFIND /m/PROPFIND 405 (WebDAV method; 8 chars).'),
    'cap_method_purge': RequestInfo('bde7a4d7-4417-4efa-a2eb-8dda8dbaf9d2', 'cap_method_purge', 'capture', 'verifier-a PURGE /m/PURGE 405.'),
    'cap_method_connect': RequestInfo('4c4c0c43-2358-4140-baa8-046424f5102b', 'cap_method_connect', 'capture', 'verifier-a `CONNECT /` sent as a request, 405.'),
    'ex_report_month': RequestInfo('5eed0000-0000-4000-8000-000000000001', 'worked_examples', 'synthetic', '5.7 worked example: /report?month=09'),
    'ex_login_token': RequestInfo('5eed0000-0000-4000-8000-000000000002', 'worked_examples', 'synthetic', '5.7 worked example: /login?token=abc123def456'),
    'ex_reset_jwt': RequestInfo('5eed0000-0000-4000-8000-000000000003', 'worked_examples', 'synthetic', '5.7 worked example: /reset/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl'),
    'ex_items_42': RequestInfo('5eed0000-0000-4000-8000-000000000004', 'worked_examples', 'synthetic', '5.7 worked example: /items/42'),
    'ex_items_uuid': RequestInfo('5eed0000-0000-4000-8000-000000000005', 'worked_examples', 'synthetic', '5.7 worked example: /items/3f2b8c1e-9d4a-4c7b-8e2f-6a1b0c9d8e7f'),
    'ex_proxy_settings': RequestInfo('5eed0000-0000-4000-8000-000000000006', 'worked_examples', 'synthetic', '5.7 worked example: /proxy/settings?tab=general'),
    'ex_search_q': RequestInfo('5eed0000-0000-4000-8000-000000000007', 'worked_examples', 'synthetic', '5.7 worked example: /search?q=quarterly+report&page=2'),
    'ex_callback_bare': RequestInfo('5eed0000-0000-4000-8000-000000000008', 'worked_examples', 'synthetic', '5.7 worked example: /callback?Zm9vYmFyYmF6cXV4'),
    'ex_jsessionid': RequestInfo('5eed0000-0000-4000-8000-000000000009', 'worked_examples', 'synthetic', '5.7 worked example: /app;jsessionid=0A1B2C3D4E5F6A7B8C9D/home'),
    'ex_go_next': RequestInfo('5eed0000-0000-4000-8000-000000000010', 'worked_examples', 'synthetic', '5.7 worked example: /go?next=%2Fhome%3Fx%3D1'),
    'ex_api_v1_users': RequestInfo('5eed0000-0000-4000-8000-000000000011', 'worked_examples', 'synthetic', '5.7 worked example: /api/v1/users?limit=50&continue=abc'),
    'ex_blog_trailing_slash': RequestInfo('5eed0000-0000-4000-8000-000000000012', 'worked_examples', 'synthetic', '5.7 worked example: /blog/release-notes-2024/'),
    'ex_double_encoded': RequestInfo('5eed0000-0000-4000-8000-000000000013', 'worked_examples', 'synthetic', '5.7 worked example: /a%252Fb?x=1'),
    'hy_query_login': RequestInfo('5eed0000-0000-4000-8000-000000000014', 'hygiene_requests', 'synthetic', 'Query value sentinel (key `token`): stored masked.'),
    'hy_query_search': RequestInfo('5eed0000-0000-4000-8000-000000000015', 'hygiene_requests', 'synthetic', 'Query value sentinel plus a second param.'),
    'hy_query_bare': RequestInfo('5eed0000-0000-4000-8000-000000000016', 'hygiene_requests', 'synthetic', 'Bare query item (no `=`) holding a sentinel: masked whole.'),
    'hy_query_nested': RequestInfo('5eed0000-0000-4000-8000-000000000017', 'hygiene_requests', 'synthetic', 'Percent-encoded nested query holding a sentinel: decoded once, then masked.'),
    'hy_query_badkey': RequestInfo('5eed0000-0000-4000-8000-000000000018', 'hygiene_requests', 'synthetic', 'Query KEY holding a sentinel plus an encoded `$` (fails the key pattern): the key itself is masked.'),
    'hy_query_repeat': RequestInfo('5eed0000-0000-4000-8000-000000000019', 'hygiene_requests', 'synthetic', 'Repeated key, two sentinels: order and repeats preserved, both masked.'),
    'hy_path_reset': RequestInfo('5eed0000-0000-4000-8000-000000000020', 'hygiene_requests', 'synthetic', 'Opaque path token sentinel: stored UNMASKED by design (5.3 withdrawn); never in logs.'),
    'hy_path_invite': RequestInfo('5eed0000-0000-4000-8000-000000000021', 'hygiene_requests', 'synthetic', 'Path-token sentinel (unmasked) and a query-value sentinel (masked) on one URL.'),
    'hy_path_matrix': RequestInfo('5eed0000-0000-4000-8000-000000000022', 'hygiene_requests', 'synthetic', 'Matrix parameter holding a sentinel: part of the path, stored unmasked.'),
    'hy_long_url': RequestInfo('5eed0000-0000-4000-8000-000000000023', 'hygiene_requests', 'synthetic', 'URL over 4096 chars after masking: stored value is capped at 4096; the query sentinel must not survive the cap.'),
    'hy_ua_sentinel': RequestInfo('5eed0000-0000-4000-8000-000000000024', 'hygiene_requests', 'synthetic', 'User-Agent carrying a sentinel: stored (<=256 chars, column user_agent) but never rendered anywhere.'),
    'hy_credential_headers': RequestInfo('5eed0000-0000-4000-8000-000000000025', 'hygiene_requests', 'synthetic', 'Extra credential-bearing request headers (Authorization, Cookie, Proxy-Authorization, X-Auth-Token, X-Csrf-Token) and a Set-Cookie response header, all sentinels; none may be read.'),
    'hy_upgrade_101': RequestInfo('5eed0000-0000-4000-8000-000000000026', 'hygiene_requests', 'synthetic', "WebSocket upgrade completed with status 101 (synthetic: the capture's /ws requests were answered 200)."),
    'hy_failed_panic': RequestInfo('5eed0000-0000-4000-8000-000000000027', 'hygiene_requests', 'synthetic', '`API request failed` line with a `panic` field (sentinel): outcome failed, no status, panic never stored or logged.'),
    'hy_method_lower_delete': RequestInfo('5eed0000-0000-4000-8000-000000000028', 'hygiene_requests', 'synthetic', 'Lowercase method `delete` (must produce a row; stored as received).'),
    'hy_method_mkworkspace': RequestInfo('5eed0000-0000-4000-8000-000000000029', 'hygiene_requests', 'synthetic', '11-character method (over the old [A-Z]{3,10} gate).'),
    'hy_method_mixed_case': RequestInfo('5eed0000-0000-4000-8000-000000000030', 'hygiene_requests', 'synthetic', 'Mixed-case method.'),
    'hy_status_204': RequestInfo('5eed0000-0000-4000-8000-000000000031', 'hygiene_requests', 'synthetic', '204 with no response headers.'),
    'bm_space': RequestInfo('5eed0000-0000-4000-8000-000000000032', 'bad_methods', 'synthetic', 'Method containing a space: dropped.'),
    'bm_too_long': RequestInfo('5eed0000-0000-4000-8000-000000000033', 'bad_methods', 'synthetic', '25-character method: dropped.'),
    'bm_digit_first': RequestInfo('5eed0000-0000-4000-8000-000000000034', 'bad_methods', 'synthetic', 'Method starting with a digit: dropped.'),
    'bm_empty': RequestInfo('5eed0000-0000-4000-8000-000000000035', 'bad_methods', 'synthetic', 'Empty method: dropped.'),
    'rl_delete': RequestInfo('5eed0000-0000-4000-8000-000000000036', 'web_rule_lookalikes', 'synthetic', 'Kubernetes kube-delete look-alike (any DELETE).'),
    'rl_secrets_plain': RequestInfo('5eed0000-0000-4000-8000-000000000037', 'web_rule_lookalikes', 'synthetic', '`/secrets` path (kube-secrets look-alike).'),
    'rl_secrets_kube_path': RequestInfo('5eed0000-0000-4000-8000-000000000038', 'web_rule_lookalikes', 'synthetic', 'Kubernetes-shaped secrets path.'),
    'rl_evict': RequestInfo('5eed0000-0000-4000-8000-000000000039', 'web_rule_lookalikes', 'synthetic', 'kube-evict look-alike.'),
    'rl_cordon': RequestInfo('5eed0000-0000-4000-8000-000000000040', 'web_rule_lookalikes', 'synthetic', 'kube-cordon look-alike.'),
    'rl_exec': RequestInfo('5eed0000-0000-4000-8000-000000000041', 'web_rule_lookalikes', 'synthetic', 'kube-exec look-alike with a `command=` query sentinel (masked on web).'),
    'rl_node_proxy_exec': RequestInfo('5eed0000-0000-4000-8000-000000000042', 'web_rule_lookalikes', 'synthetic', 'kube-node-proxy-exec look-alike.'),
    'rl_discovery_api': RequestInfo('5eed0000-0000-4000-8000-000000000043', 'web_rule_lookalikes', 'synthetic', 'Discovery look-alike `GET /api`: counted, not hidden, on web.'),
    'rl_discovery_api_q': RequestInfo('5eed0000-0000-4000-8000-000000000044', 'web_rule_lookalikes', 'synthetic', 'Discovery look-alike with a query.'),
    'rl_discovery_apis': RequestInfo('5eed0000-0000-4000-8000-000000000045', 'web_rule_lookalikes', 'synthetic', 'Discovery look-alike `GET /apis`.'),
    'hv_login_placeholder': RequestInfo('5eed0000-0000-4000-8000-000000000046', 'hv_login_placeholder', 'synthetic', 'login, credential values replaced by a placeholder'),
    'hv_login_removed': RequestInfo('5eed0000-0000-4000-8000-000000000047', 'hv_login_removed', 'synthetic', 'login, credential headers removed'),
    'hv_orders_placeholder': RequestInfo('5eed0000-0000-4000-8000-000000000048', 'hv_orders_placeholder', 'synthetic', 'orders, cookie value replaced by a placeholder'),
    'hv_orders_removed': RequestInfo('5eed0000-0000-4000-8000-000000000049', 'hv_orders_removed', 'synthetic', 'orders, cookie header removed'),
    'spoof_four_spellings': RequestInfo('5eed0000-0000-4000-8000-000000000050', 'spoof_variants', 'synthetic', 'Five spoofed identity header spellings with sentinels.'),
    'ht_ua_missing': RequestInfo('5eed0000-0000-4000-8000-000000000051', 'hdr_tolerance', 'synthetic', 'No User-Agent header: absent.'),
    'ht_ua_empty_list': RequestInfo('5eed0000-0000-4000-8000-000000000052', 'hdr_tolerance', 'synthetic', 'User-Agent is an empty list: absent.'),
    'ht_ua_int_first': RequestInfo('5eed0000-0000-4000-8000-000000000053', 'hdr_tolerance', 'synthetic', 'First element is not a string: absent.'),
    'ht_ua_int_value': RequestInfo('5eed0000-0000-4000-8000-000000000054', 'hdr_tolerance', 'synthetic', 'Value is neither list nor string: absent.'),
    'ht_ua_empty_string': RequestInfo('5eed0000-0000-4000-8000-000000000055', 'hdr_tolerance', 'synthetic', 'First element is an empty string: absent.'),
    'ht_ua_placeholder': RequestInfo('5eed0000-0000-4000-8000-000000000056', 'hdr_tolerance', 'synthetic', 'User-Agent replaced by a placeholder string: a normal non-empty string, stored as-is (Gatorcast cannot recognise placeholders).'),
    'ht_ua_plain_string': RequestInfo('5eed0000-0000-4000-8000-000000000057', 'hdr_tolerance', 'synthetic', 'Plain non-empty string instead of a list: accepted.'),
    'ht_no_request_key': RequestInfo('5eed0000-0000-4000-8000-000000000058', 'hdr_tolerance', 'synthetic', 'No `request` object at all: User-Agent absent, line kept.'),
    'ht_headers_not_dict': RequestInfo('5eed0000-0000-4000-8000-000000000059', 'hdr_tolerance', 'synthetic', '`request.headers` is a list: User-Agent absent, line kept.'),
    'k8s_discovery': RequestInfo('5eed0000-0000-4000-8000-000000000060', 'k8s_upper', 'synthetic', 'Discovery request.'),
    'k8s_list_pods': RequestInfo('5eed0000-0000-4000-8000-000000000061', 'k8s_upper', 'synthetic', 'List with allowlisted query keys.'),
    'k8s_delete_pod': RequestInfo('5eed0000-0000-4000-8000-000000000062', 'k8s_upper', 'synthetic', 'kube-delete finding.'),
    'k8s_get_secret': RequestInfo('5eed0000-0000-4000-8000-000000000063', 'k8s_upper', 'synthetic', 'kube-secrets finding; non-allowlisted query key `access_token` (sentinel) is dropped by the Kubernetes policy.'),
    'k8s_ht_no_kubectl_headers': RequestInfo('5eed0000-0000-4000-8000-000000000064', 'k8s_hdr_tolerance', 'synthetic', 'No Kubectl-* headers.'),
    'k8s_ht_empty_lists': RequestInfo('5eed0000-0000-4000-8000-000000000065', 'k8s_hdr_tolerance', 'synthetic', 'Empty-list Kubectl-* headers.'),
    'late_web_get': RequestInfo('5eed0000-0000-4000-8000-000000000127', 'late_start_web', 'synthetic', 'Arrives first; stored provisionally (masked URL) then converted.'),
    'late_web_delete': RequestInfo('5eed0000-0000-4000-8000-000000000128', 'late_start_web', 'synthetic', 'Arrives first; would trip kube-delete if left provisional: its findings must be removed on conversion.'),
    'late_k8s_list': RequestInfo('5eed0000-0000-4000-8000-000000000129', 'late_start_k8s', 'synthetic', 'Arrives first.'),
    'no_start_get': RequestInfo('5eed0000-0000-4000-8000-000000000130', 'no_start', 'synthetic', 'Query sentinel masked even though no start line exists.'),
    'redeliver_req1': RequestInfo('5eed0000-0000-4000-8000-000000000131', 'redeliver', 'synthetic', 'GET /orders?id=<query sentinel> (redelivered).'),
    'redeliver_req2': RequestInfo('5eed0000-0000-4000-8000-000000000132', 'redeliver', 'synthetic', 'POST /login with credential header sentinels (redelivered).'),
    'redeliver_noobj_req': RequestInfo('5eed0000-0000-4000-8000-000000000133', 'redeliver_noobj_then_obj', 'synthetic', 'GET /redeliver-noobj.'),
}

# Same credential-bearing request, three header forms (see module docs).
WEBAPP_HEADER_VARIANTS = {
    "login": {"present": "cap_post_login_creds", "placeholder": "hv_login_placeholder",
              "removed": "hv_login_removed"},
    "orders": {"present": "cap_post_orders_cookie", "placeholder": "hv_orders_placeholder",
               "removed": "hv_orders_removed"},
}

# Connection keys by lifecycle / resource type.
WEBAPP_EMPTY_CONN_KEYS = {  # start line, no request and no chunk
    "WEB_APP": ("cap_tls_empty", "cap_empty_a", "cap_empty_b", "bad_methods"),  # bad_methods: every request dropped
    "KUBERNETES": ("k8s_empty",),
    "SSH": ("ssh_upper", "gw_on_ssh_upper"),
}
WEBAPP_KUBERNETES_CONN_KEYS = ("k8s_upper", "k8s_empty", "k8s_hdr_tolerance", "late_start_k8s",
                               "gw_on_kubernetes_upper", "gw_on_kubernetes_lower")
WEBAPP_ORDERING_EXCEPTION_CONN_KEYS = ("late_start_web", "late_start_k8s", "no_start")
# Request lines the method gate still rejects (`api_bad_method`): no row, no error.
WEBAPP_DROPPED_REQUEST_KEYS = ("bm_space", "bm_too_long", "bm_digit_first", "bm_empty")

# Every WEBAPP_SPEC 5.7 row, verbatim: (request key, raw url, expected stored url).
WEBAPP_WORKED_EXAMPLES = (
    ('ex_report_month', '/report?month=09', '/report?month=\u2026(2)'),
    ('ex_login_token', '/login?token=abc123def456', '/login?token=ab\u20266(12)'),
    ('ex_reset_jwt', '/reset/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl', '/reset/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl'),
    ('ex_items_42', '/items/42', '/items/42'),
    ('ex_items_uuid', '/items/3f2b8c1e-9d4a-4c7b-8e2f-6a1b0c9d8e7f', '/items/3f2b8c1e-9d4a-4c7b-8e2f-6a1b0c9d8e7f'),
    ('ex_proxy_settings', '/proxy/settings?tab=general', '/proxy/settings?tab=g\u2026(7)'),
    ('ex_search_q', '/search?q=quarterly+report&page=2', '/search?q=qu\u2026rt(16)&page=\u2026(1)'),
    ('ex_callback_bare', '/callback?Zm9vYmFyYmF6cXV4', '/callback?Zm\u2026V4(16)'),
    ('ex_jsessionid', '/app;jsessionid=0A1B2C3D4E5F6A7B8C9D/home', '/app;jsessionid=0A1B2C3D4E5F6A7B8C9D/home'),
    ('ex_go_next', '/go?next=%2Fhome%3Fx%3D1', '/go?next=*h\u2026(9)'),
    ('ex_api_v1_users', '/api/v1/users?limit=50&continue=abc', '/api/v1/users?limit=\u2026(2)&continue=\u2026(3)'),
    ('ex_blog_trailing_slash', '/blog/release-notes-2024/', '/blog/release-notes-2024'),
    ('ex_double_encoded', '/a%252Fb?x=1', '/a%2Fb'),
)

# `gwops` variants; see module docs for the outcome vocabulary.
WEBAPP_GWOPS_CASES: tuple[GwopsCase, ...] = (
    GwopsCase('gw_exact_upstream_none', 'accepted', None, 'WEB_APP', _exact('echo-plain', True, 'none', 80, 'none', 80, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_exact_upstream_verify_ca', 'accepted', None, 'WEB_APP', _exact('echo-vca', True, 'tls13', 443, 'verify_ca', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_exact_upstream_verify_full', 'accepted', None, 'WEB_APP', _exact('echo-wrongfull', True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_exact_upstream_insecure', 'accepted', None, 'WEB_APP', _exact('echo-tls', True, 'tls13', 443, 'insecure', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_exact_downstream_tls13', 'accepted', None, 'WEB_APP', _exact('verifier-a', True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_exact_downstream_none', 'accepted', None, 'WEB_APP', _exact('verifier-b', True, 'none', 80, 'none', 8080, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_exact_unmanaged', 'accepted', None, 'WEB_APP', _exact('Legacy Wiki (prod)', False, 'none', 80, 'none', 8080, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_gateway_id_null', 'accepted', None, 'WEB_APP', _exact('mode-b-app', True, 'tls13', 443, 'verify_full', 443, gateway_id=None)),
    GwopsCase('gw_gateway_id_128', 'accepted', None, 'WEB_APP', _exact('verifier-a', True, 'tls13', 443, 'verify_full', 443, gateway_id='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')),
    GwopsCase('gw_app_len_200', 'accepted', None, 'WEB_APP', _exact('Long-App-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_match_none', 'accepted', None, 'WEB_APP', _no_app('none')),
    GwopsCase('gw_match_ambiguous', 'accepted', None, 'WEB_APP', _no_app('ambiguous')),
    GwopsCase('gw_match_none_app_fields', 'accepted', None, 'WEB_APP', _no_app('none')),
    GwopsCase('gw_match_none_unknown_key', 'accepted', None, 'WEB_APP', _no_app('none')),
    GwopsCase('gw_unknown_key_exact', 'accepted', None, 'WEB_APP', _exact('verifier-a', True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_rej_not_object_string', 'rejected', 'gwops_not_object', 'WEB_APP', None),
    GwopsCase('gw_rej_not_object_null', 'rejected', 'gwops_not_object', 'WEB_APP', None),
    GwopsCase('gw_rej_not_object_array', 'rejected', 'gwops_not_object', 'WEB_APP', None),
    GwopsCase('gw_rej_not_object_number', 'rejected', 'gwops_not_object', 'WEB_APP', None),
    GwopsCase('gw_rej_schema_2', 'rejected', 'gwops_bad_schema', 'WEB_APP', None),
    GwopsCase('gw_rej_schema_string', 'rejected', 'gwops_bad_schema', 'WEB_APP', None),
    GwopsCase('gw_rej_schema_bool', 'rejected', 'gwops_bad_schema', 'WEB_APP', None),
    GwopsCase('gw_rej_schema_missing', 'rejected', 'gwops_bad_schema', 'WEB_APP', None),
    GwopsCase('gw_rej_match_missing', 'rejected', 'gwops_bad_match', 'WEB_APP', None),
    GwopsCase('gw_rej_match_case', 'rejected', 'gwops_bad_match', 'WEB_APP', None),
    GwopsCase('gw_rej_match_unknown', 'rejected', 'gwops_bad_match', 'WEB_APP', None),
    GwopsCase('gw_rej_gateway_id_space', 'rejected', 'gwops_bad_gateway_id', 'WEB_APP', None),
    GwopsCase('gw_rej_gateway_id_missing', 'rejected', 'gwops_bad_gateway_id', 'WEB_APP', None),
    GwopsCase('gw_rej_gateway_id_int', 'rejected', 'gwops_bad_gateway_id', 'WEB_APP', None),
    GwopsCase('gw_rej_gateway_id_empty', 'rejected', 'gwops_bad_gateway_id', 'WEB_APP', None),
    GwopsCase('gw_rej_gateway_id_129', 'rejected', 'gwops_bad_gateway_id', 'WEB_APP', None),
    GwopsCase('gw_rej_managed_missing', 'rejected', 'gwops_bad_managed', 'WEB_APP', None),
    GwopsCase('gw_rej_managed_string', 'rejected', 'gwops_bad_managed', 'WEB_APP', None),
    GwopsCase('gw_rej_managed_int', 'rejected', 'gwops_bad_managed', 'WEB_APP', None),
    GwopsCase('gw_rej_mode_downstream_upper', 'rejected', 'gwops_bad_mode', 'WEB_APP', None),
    GwopsCase('gw_rej_mode_downstream_tls12', 'rejected', 'gwops_bad_mode', 'WEB_APP', None),
    GwopsCase('gw_rej_mode_downstream_missing', 'rejected', 'gwops_bad_mode', 'WEB_APP', None),
    GwopsCase('gw_rej_mode_upstream_upper', 'rejected', 'gwops_bad_mode', 'WEB_APP', None),
    GwopsCase('gw_rej_mode_upstream_unknown', 'rejected', 'gwops_bad_mode', 'WEB_APP', None),
    GwopsCase('gw_rej_mode_upstream_missing', 'rejected', 'gwops_bad_mode', 'WEB_APP', None),
    GwopsCase('gw_rej_port_downstream_zero', 'rejected', 'gwops_bad_port', 'WEB_APP', None),
    GwopsCase('gw_rej_port_upstream_65536', 'rejected', 'gwops_bad_port', 'WEB_APP', None),
    GwopsCase('gw_rej_port_string', 'rejected', 'gwops_bad_port', 'WEB_APP', None),
    GwopsCase('gw_rej_port_bool', 'rejected', 'gwops_bad_port', 'WEB_APP', None),
    GwopsCase('gw_rej_port_float', 'rejected', 'gwops_bad_port', 'WEB_APP', None),
    GwopsCase('gw_rej_port_missing', 'rejected', 'gwops_bad_port', 'WEB_APP', None),
    GwopsCase('gw_app_control_char', 'accepted_app_ignored', 'gwops_bad_app', 'WEB_APP', _exact(None, True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_app_bidi_char', 'accepted_app_ignored', 'gwops_bad_app', 'WEB_APP', _exact(None, True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_app_line_separator', 'accepted_app_ignored', 'gwops_bad_app', 'WEB_APP', _exact(None, True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_app_too_long', 'accepted_app_ignored', 'gwops_bad_app', 'WEB_APP', _exact(None, True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_app_empty', 'accepted_app_ignored', 'gwops_bad_app', 'WEB_APP', _exact(None, True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_app_not_string', 'accepted_app_ignored', 'gwops_bad_app', 'WEB_APP', _exact(None, True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_app_missing', 'accepted_app_ignored', 'gwops_bad_app', 'WEB_APP', _exact(None, True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_on_kubernetes_upper', 'not_read', None, 'KUBERNETES', None),
    GwopsCase('gw_on_kubernetes_lower', 'not_read', None, 'KUBERNETES', None),
    GwopsCase('gw_on_ssh_upper', 'not_read', None, 'SSH', None),
    GwopsCase('gw_on_missing_resource_type', 'not_read', None, None, None),
    GwopsCase('gw_on_junk_resource_type', 'not_read', None, 'invalid', None),
    GwopsCase('gw_on_non_string_resource_type', 'not_read', None, 'invalid', None),
    GwopsCase('gw_on_other_resource_type', 'not_read', None, 'DATABASE', None),
    GwopsCase('gw_resource_type_padded_lower', 'accepted', None, 'WEB_APP', _exact('padded-lower', True, 'tls13', 443, 'verify_full', 443, gateway_id='R2F0ZXdheToxMjk0')),
    GwopsCase('gw_absent', 'absent', None, 'WEB_APP', None),
)

WEBAPP_SENTINELS: dict[str, tuple[str, ...]] = {
    'SPOOF': (
        'SENTINEL_SPOOF_XTU_HYPHEN_def0fbf5',
        'SENTINEL_SPOOF_XTU_UNDERSCORE_c03d937f',
        'SENTINEL_SPOOF_A_X_TWINGATE_USER_529da8d6',
        'SENTINEL_SPOOF_B_UPPER_0e001f21',
        'SENTINEL_SPOOF_C_LOWER_3bd0343c',
        'SENTINEL_SPOOF_D_UNDERSCORE_09883e75',
        'SENTINEL_SPOOF_E_LOWER_UNDERSCORE_49c570f5',
    ),
    'QUERY': (
        'SENTINEL_QUERY_SUBMIT_8e36e743',
        'SENTINEL_QUERY_ORDERS_98f1e13a',
        'SENTINEL_QUERY_LOGIN_195be9c4',
        'SENTINEL_QUERY_SEARCH_ddf4ac14',
        'SENTINEL_QUERY_BARE_7efa4c71',
        'SENTINEL_QUERY_NESTED_8a6ba5c7',
        'SENTINEL_QUERY_KEY_65690ff5',
        'SENTINEL_QUERY_REPEAT_ONE_7d3d5b07',
        'SENTINEL_QUERY_REPEAT_TWO_bb228f11',
        'SENTINEL_QUERY_INVITE_e48992b4',
        'SENTINEL_QUERY_CAP_5c7a2d5c',
        'SENTINEL_QUERY_EXECCMD_4e5706eb',
        'SENTINEL_QUERY_K8SDROP_216629bb',
        'SENTINEL_QUERY_LATEWEB_9108c263',
        'SENTINEL_QUERY_LATEK8S_16f36460',
        'SENTINEL_QUERY_ORPHAN_1b15bb3e',
        'SENTINEL_QUERY_REDELIVER_a661d65e',
    ),
    'AUTHZ': (
        'SENTINEL_AUTHZ_LOGIN_eb87d136',
        'SENTINEL_AUTHZ_BEARER_7bafbfb3',
        'SENTINEL_AUTHZ_K8S_f11cd4fb',
        'SENTINEL_AUTHZ_REDELIVER_aafa3fd0',
    ),
    'COOKIE': (
        'SENTINEL_COOKIE_LOGIN_49f0779e',
        'SENTINEL_COOKIE_ORDERS_c560eb10',
        'SENTINEL_COOKIE_SESSION_095379d0',
        'SENTINEL_COOKIE_REDELIVER_3a6f2096',
    ),
    'APIKEY': (
        'SENTINEL_APIKEY_LOGIN_d7a13711',
        'SENTINEL_APIKEY_REDELIVER_526d1881',
    ),
    'PATHTOKEN': (
        'SENTINEL_PATHTOKEN_RESET_bbd64c8a',
        'SENTINEL_PATHTOKEN_INVITE_3f6e9e57',
        'SENTINEL_PATHTOKEN_MATRIX_636f4424',
    ),
    'UA': (
        'SENTINEL_UA_FULL_cd064c5c',
    ),
    'PROXYAUTH': (
        'SENTINEL_PROXYAUTH_BASIC_20f7cfa4',
    ),
    'XAUTHTOKEN': (
        'SENTINEL_XAUTHTOKEN_TOKEN_0d05cd1d',
    ),
    'CSRF': (
        'SENTINEL_CSRF_TOKEN_bc4ddc2c',
    ),
    'SETCOOKIE': (
        'SENTINEL_SETCOOKIE_RESP_cbd7f9e0',
    ),
    'PANIC': (
        'SENTINEL_PANIC_WEB_f81b89d7',
    ),
    'GWOPS': (
        'SENTINEL_GWOPS_NONE_APP_20846bf9',
        'SENTINEL_GWOPS_UNKNOWN_SCALAR_d3df20d3',
        'SENTINEL_GWOPS_UNKNOWN_HDRS_30dacd44',
        'SENTINEL_GWOPS_REJ_STR_a244f725',
        'SENTINEL_GWOPS_REJ_ARR_16ea8ee0',
        'SENTINEL_GWOPS_REJ_SCHEMA2_1887c3f8',
        'SENTINEL_GWOPS_REJ_SCHEMASTR_b5db4ba4',
        'SENTINEL_GWOPS_REJ_SCHEMABOOL_1297deec',
        'SENTINEL_GWOPS_REJ_SCHEMAMISS_bd8ed30f',
        'SENTINEL_GWOPS_REJ_MATCHMISS_d6813789',
        'SENTINEL_GWOPS_REJ_MATCHCASE_3f848dc6',
        'SENTINEL_GWOPS_REJ_MATCHUNK_80f95227',
        'SENTINEL_GWOPS_REJ_GWIDSPACE_ddaafbab',
        'SENTINEL_GWOPS_GWID_SPACE_5f05abed',
        'SENTINEL_GWOPS_REJ_GWIDMISS_7724abb6',
        'SENTINEL_GWOPS_REJ_GWIDINT_4046adec',
        'SENTINEL_GWOPS_REJ_GWIDEMPTY_e2e0027e',
        'SENTINEL_GWOPS_REJ_GWID129_4198e365',
        'SENTINEL_GWOPS_REJ_MANMISS_42b4cc7e',
        'SENTINEL_GWOPS_REJ_MANSTR_522dde42',
        'SENTINEL_GWOPS_REJ_MANINT_dbdc087d',
        'SENTINEL_GWOPS_REJ_DSUPPER_d2490bac',
        'SENTINEL_GWOPS_REJ_DS12_10c07d20',
        'SENTINEL_GWOPS_REJ_DSMISS_99a7167f',
        'SENTINEL_GWOPS_REJ_USUPPER_ad4cc717',
        'SENTINEL_GWOPS_REJ_USUNK_9ac731d7',
        'SENTINEL_GWOPS_REJ_USMISS_2a4c4bc8',
        'SENTINEL_GWOPS_REJ_DPZERO_9506d551',
        'SENTINEL_GWOPS_REJ_UP65536_ef19ad3d',
        'SENTINEL_GWOPS_REJ_DPSTR_ab3f1bdc',
        'SENTINEL_GWOPS_REJ_UPBOOL_da8ea9b5',
        'SENTINEL_GWOPS_REJ_DPFLOAT_b0b57bf6',
        'SENTINEL_GWOPS_REJ_UPMISS_ed11fab9',
        'SENTINEL_GWOPS_APP_CTRL_56af1d7d',
        'SENTINEL_GWOPS_APP_BIDI_c59505f9',
        'SENTINEL_GWOPS_APP_LSEP_a36a8f24',
        'SENTINEL_GWOPS_APP_LONG_c74b6fb8',
        'SENTINEL_GWOPS_K8S_APP_22343478',
        'SENTINEL_GWOPS_K8SLOWER_APP_b09bc970',
        'SENTINEL_GWOPS_SSH_APP_de151086',
        'SENTINEL_GWOPS_NORT_APP_621e99c1',
        'SENTINEL_GWOPS_JUNKRT_APP_c13276b6',
        'SENTINEL_GWOPS_INTRT_APP_12870214',
        'SENTINEL_GWOPS_DBRT_APP_af4ef548',
        'SENTINEL_GWOPS_CONFLICT_APP_59ec7daf',
        'SENTINEL_GWOPS_RETROFILL_APP_8982deb0',
    ),
    'NONJSON': (
        'SENTINEL_NONJSON_PANIC_300c7c5e',
        'SENTINEL_NONJSON_STACK_a8a97a16',
        'SENTINEL_NONJSON_KLOG_12a18519',
        'SENTINEL_NONJSON_COBRA_d8b02780',
        'SENTINEL_NONJSON_FRAGMENT_942ae7b1',
        'SENTINEL_NONJSON_TRUNC_ceb27091',
    ),
    'SVC': (
        'SENTINEL_SVC_CAKEY_9515a8a6',
        'SENTINEL_SVC_TOKENERR_3fa6b6b8',
        'SENTINEL_SVC_AUTHERR_ea7df2e1',
        'SENTINEL_SVC_CFGERR_d2c3f391',
        'SENTINEL_SVC_REJECTED_2d22ddb4',
    ),
    'SSH': (
        'SENTINEL_SSH_ENV_AWS_83838857',
        'SENTINEL_SSH_ENV_GH_057f0871',
        'SENTINEL_SSH_EXEC_CURL_7087db1f',
        'SENTINEL_SSH_GLOBAL_364746d4',
        'SENTINEL_SSH_EXEC_NULLCAST_89b9640d',
        'SENTINEL_SSH_ERR_CHAN_38020e0a',
        'SENTINEL_SSH_ERR_REQ_177698bc',
        'SENTINEL_SSH_ERR_REC_4b3c6213',
        'SENTINEL_SSH_ERR_HS_3748ce55',
    ),
}


def _group(*names: str) -> tuple[str, ...]:
    return tuple(chain.from_iterable(WEBAPP_SENTINELS[n] for n in names))


WEBAPP_HEADER_SENTINELS = _group("AUTHZ", "COOKIE", "APIKEY", "PROXYAUTH", "XAUTHTOKEN", "CSRF", "SETCOOKIE")
WEBAPP_SPOOF_SENTINELS = _group("SPOOF")
WEBAPP_QUERY_SENTINELS = _group("QUERY")
WEBAPP_PANIC_SENTINELS = _group("PANIC")
WEBAPP_GWOPS_SENTINELS = _group("GWOPS")
WEBAPP_USER_AGENT_SENTINELS = _group("UA")
WEBAPP_PATH_TOKENS = _group("PATHTOKEN") + (
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl',  # WEBAPP_SPEC 5.7 /reset/<jwt>
    '3f2b8c1e-9d4a-4c7b-8e2f-6a1b0c9d8e7f',  # 5.7 /items/<uuid>
    '0A1B2C3D4E5F6A7B8C9D',  # 5.7 matrix parameter value
)
WEBAPP_NEVER_STORED_SENTINELS = (
    WEBAPP_HEADER_SENTINELS + WEBAPP_SPOOF_SENTINELS + WEBAPP_QUERY_SENTINELS
    + WEBAPP_PANIC_SENTINELS + WEBAPP_GWOPS_SENTINELS
)
WEBAPP_NEVER_LOGGED_SENTINELS = (
    WEBAPP_NEVER_STORED_SENTINELS + WEBAPP_PATH_TOKENS + WEBAPP_USER_AGENT_SENTINELS
)
WEBAPP_INTERIM_SENTINELS = _group("NONJSON", "SVC", "SSH")

# Interim fixture: section -> [start, stop) index range, and per-line (section, origin, doc).
WEBAPP_INTERIM_SECTIONS: dict[str, tuple[int, int]] = {
    'nonjson_capture': (0, 7),
    'nonjson_synthetic': (7, 17),
    'service_capture': (17, 46),
    'service_synthetic': (46, 50),
    'ssh_audit': (50, 63),
    'ssh_operational': (63, 67),
}
WEBAPP_INTERIM_DOCS: tuple[tuple[str, str, str], ...] = (
    ('nonjson_capture', 'capture', 'capture line 15'),
    ('nonjson_capture', 'capture', 'capture line 39'),
    ('nonjson_capture', 'capture', 'capture line 64'),
    ('nonjson_capture', 'capture', 'capture line 67'),
    ('nonjson_capture', 'capture', 'capture line 70'),
    ('nonjson_capture', 'capture', 'capture line 132'),
    ('nonjson_capture', 'capture', 'capture line 144'),
    ('nonjson_synthetic', 'approximate', 'Go panic header (approximate shape).'),
    ('nonjson_synthetic', 'approximate', 'Go panic continuation.'),
    ('nonjson_synthetic', 'approximate', 'Go panic stack header.'),
    ('nonjson_synthetic', 'approximate', 'Go panic stack frame (tab-indented).'),
    ('nonjson_synthetic', 'approximate', 'klog error line.'),
    ('nonjson_synthetic', 'approximate', 'cobra usage error line.'),
    ('nonjson_synthetic', 'approximate', 'cobra usage block.'),
    ('nonjson_synthetic', 'approximate', 'cobra usage block.'),
    ('nonjson_synthetic', 'approximate', 'Tail fragment of an over-long line (looks JSON-ish, does not parse).'),
    ('nonjson_synthetic', 'approximate', 'Head fragment of an over-long recording line: starts with `{`, truncated, does not parse.'),
    ('service_capture', 'capture', 'capture line 1'),
    ('service_capture', 'capture', 'capture line 2'),
    ('service_capture', 'capture', 'capture line 3'),
    ('service_capture', 'capture', 'capture line 4'),
    ('service_capture', 'capture', 'capture line 5'),
    ('service_capture', 'capture', 'capture line 6'),
    ('service_capture', 'capture', 'capture line 7'),
    ('service_capture', 'capture', 'capture line 8'),
    ('service_capture', 'capture', 'capture line 9'),
    ('service_capture', 'capture', 'capture line 18'),
    ('service_capture', 'capture', 'capture line 19'),
    ('service_capture', 'capture', 'capture line 20'),
    ('service_capture', 'capture', 'capture line 21'),
    ('service_capture', 'capture', 'capture line 22'),
    ('service_capture', 'capture', 'capture line 23'),
    ('service_capture', 'capture', 'capture line 24'),
    ('service_capture', 'capture', 'capture line 25'),
    ('service_capture', 'capture', 'capture line 26'),
    ('service_capture', 'capture', 'capture line 27'),
    ('service_capture', 'capture', 'capture line 28'),
    ('service_capture', 'capture', 'capture line 29'),
    ('service_capture', 'capture', 'capture line 30'),
    ('service_capture', 'capture', 'capture line 31'),
    ('service_capture', 'capture', 'capture line 41'),
    ('service_capture', 'capture', 'capture line 42'),
    ('service_capture', 'capture', 'capture line 43'),
    ('service_capture', 'capture', 'capture line 44'),
    ('service_capture', 'capture', 'capture line 61'),
    ('service_capture', 'capture', 'capture line 62'),
    ('service_synthetic', 'approximate', 'Token rejection line with a sentinel in `error` (approximate).'),
    ('service_synthetic', 'approximate', 'Listener-level auth failure (approximate).'),
    ('service_synthetic', 'approximate', 'Config load failure (approximate).'),
    ('service_synthetic', 'approximate', 'Service line that carries identity and resource fields but is NOT `Authenticated connection`: must never create a connection (approximate shape; real gateway behaviour unobserved).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Connection established` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Channel opened` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Channel request` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Channel request` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Channel request` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Channel request` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Channel request` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Channel request` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Global request` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Global request` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Channel closed` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event `Connection closed` (approximate shape).'),
    ('ssh_audit', 'approximate', 'SSH audit event with an explicit `asciicast: null` (must not be treated as a recording chunk).'),
    ('ssh_operational', 'approximate', 'operational error with conn_id (approximate shape).'),
    ('ssh_operational', 'approximate', 'operational error with conn_id (approximate shape).'),
    ('ssh_operational', 'approximate', 'operational error with conn_id (approximate shape).'),
    ('ssh_operational', 'approximate', 'operational error with no conn_id and no user (approximate shape).'),
)


# ------------------------------------------------------------------------------------ loaders


def _read_lines(path: Path) -> list[str]:
    """Non-empty lines of an NDJSON fixture (split on ``\\n`` only; never ``splitlines``)."""
    return [line for line in path.read_text(encoding="utf-8").split("\n") if line]


@lru_cache(maxsize=1)
def _webapp_pairs() -> tuple[tuple[str, dict], ...]:
    return tuple((line, json.loads(line)) for line in _read_lines(WEBAPP_LINES_FILE))


def webapp_lines() -> list[str]:
    """All lines of ``webapp_lines.ndjson`` in file order (every line is one JSON object)."""
    return [line for line, _ in _webapp_pairs()]


def webapp_objects() -> list[dict]:
    """The parsed objects of :func:`webapp_lines` (fresh copies)."""
    return [json.loads(line) for line, _ in _webapp_pairs()]


def webapp_capture_lines() -> list[str]:
    """The capture-derived prefix of :func:`webapp_lines` (no ``gwops`` objects)."""
    return webapp_lines()[:WEBAPP_CAPTURE_LINE_COUNT]


def webapp_synthetic_lines() -> list[str]:
    """The synthetic suffix of :func:`webapp_lines`."""
    return webapp_lines()[WEBAPP_CAPTURE_LINE_COUNT:]


def webapp_lines_for(conn_key: str) -> list[str]:
    """Every line whose ``conn_id`` is ``WEBAPP_CONNS[conn_key]``, in file order.

    Typically ``[start_line, request, ...]``. For ``redeliver`` it is the 8-line redelivery
    sequence (see :func:`webapp_redelivery`).
    """
    conn_id = WEBAPP_CONNS[conn_key].conn_id
    return [line for line, obj in _webapp_pairs() if obj.get("conn_id") == conn_id]


def webapp_start_line(conn_key: str) -> str:
    """The first ``Authenticated connection`` line of a connection."""
    conn_id = WEBAPP_CONNS[conn_key].conn_id
    for line, obj in _webapp_pairs():
        if obj.get("conn_id") == conn_id and obj.get("message") == "Authenticated connection":
            return line
    raise KeyError(conn_key)


def webapp_request_line(request_key: str) -> str:
    """The audit line for ``WEBAPP_REQUESTS[request_key]``."""
    request_id = WEBAPP_REQUESTS[request_key].request_id
    for line, obj in _webapp_pairs():
        if obj.get("request_id") == request_id:
            return line
    raise KeyError(request_key)


def webapp_batch(*conn_keys: str) -> list[str]:
    """The lines of several connections, concatenated in the order given."""
    return [line for key in conn_keys for line in webapp_lines_for(key)]


class WebappRedelivery(NamedTuple):
    """The redelivery fixtures (at-least-once delivery, WEBAPP_SPEC 3.1 / 4.4)."""

    originals: list[str]  # [start with exact gwops, GET request, POST /login with credential sentinels]
    replay: list[str]  # the same three lines, byte-identical
    conflicting_start: str  # same conn_id, DIFFERENT exact gwops object (sentinel app)
    no_object_start: str  # same conn_id, no gwops object
    noobj_then_obj: list[str]  # other conn: [start WITHOUT gwops, request, repeated start WITH gwops]


def webapp_redelivery() -> WebappRedelivery:
    """Split the redelivery lines (they are the last 11 lines of the fixture)."""
    seq = webapp_lines_for("redeliver")
    assert len(seq) == 8, len(seq)
    return WebappRedelivery(
        originals=seq[:3],
        replay=seq[3:6],
        conflicting_start=seq[6],
        no_object_start=seq[7],
        noobj_then_obj=webapp_lines_for("redeliver_noobj_then_obj"),
    )


def webapp_interim_lines() -> list[str]:
    """All lines of ``webapp_interim_lines.ndjson``. Not all are JSON; none may produce a row."""
    return _read_lines(WEBAPP_INTERIM_FILE)


def webapp_interim_section(name: str) -> list[str]:
    """One section of the interim fixture (``WEBAPP_INTERIM_SECTIONS``)."""
    start, stop = WEBAPP_INTERIM_SECTIONS[name]
    return webapp_interim_lines()[start:stop]


def webapp_mixed_batch(valid: list[str] | None = None, every: int = 3) -> list[str]:
    """Valid lines with one interim line inserted after every ``every`` valid lines.

    The valid lines keep their relative order (starts before requests). Leftover interim lines are
    appended at the end. ``valid`` defaults to the whole of :func:`webapp_lines`.
    """
    valid_lines = webapp_lines() if valid is None else list(valid)
    junk = iter(webapp_interim_lines())
    out: list[str] = []
    for i, line in enumerate(valid_lines, 1):
        out.append(line)
        if i % every == 0:
            nxt = next(junk, None)
            if nxt is not None:
                out.append(nxt)
    out.extend(junk)
    return out


def check_webapp_fixture_index() -> None:
    """Assert that the registries in this module match the two fixture files.

    Raises ``AssertionError`` on drift. Intended to be called from a single test.
    """
    pairs = _webapp_pairs()
    objs = [obj for _, obj in pairs]
    assert len(pairs) == WEBAPP_LINE_COUNT, (len(pairs), WEBAPP_LINE_COUNT)

    conn_ids = {o["conn_id"] for o in objs if "conn_id" in o}
    for key, info in WEBAPP_CONNS.items():
        assert info.conn_id in conn_ids, key
        assert info.origin in ("capture", "synthetic"), key
    owner = {o["request_id"]: o["conn_id"] for o in objs if "request_id" in o}
    for key, info in WEBAPP_REQUESTS.items():
        assert owner.get(info.request_id) == WEBAPP_CONNS[info.conn].conn_id, key
    for key in WEBAPP_DROPPED_REQUEST_KEYS:
        assert key in WEBAPP_REQUESTS, key
    for group in WEBAPP_HEADER_VARIANTS.values():
        for key in group.values():
            assert key in WEBAPP_REQUESTS, key
    for key in (*WEBAPP_KUBERNETES_CONN_KEYS, *WEBAPP_ORDERING_EXCEPTION_CONN_KEYS,
                *chain.from_iterable(WEBAPP_EMPTY_CONN_KEYS.values())):
        assert key in WEBAPP_CONNS, key

    by_request = {o.get("request_id"): o for o in objs if "request_id" in o}
    for key, raw_url, _stored in WEBAPP_WORKED_EXAMPLES:
        assert by_request[WEBAPP_REQUESTS[key].request_id]["url"] == raw_url, key

    for case in WEBAPP_GWOPS_CASES:
        assert case.key in WEBAPP_CONNS, case.key
        start = json.loads(webapp_start_line(case.key))
        assert ("gwops" in start) == (case.outcome != "absent"), case.key
        assert (case.expected is not None) == (case.outcome in ("accepted", "accepted_app_ignored")), case.key

    # Redelivery structure.
    redelivery = webapp_redelivery()
    assert redelivery.originals == redelivery.replay
    assert len(redelivery.noobj_then_obj) == 3
    assert "gwops" not in json.loads(redelivery.no_object_start)
    assert "gwops" not in json.loads(redelivery.noobj_then_obj[0])
    assert "gwops" in json.loads(redelivery.noobj_then_obj[2])

    # Sentinels: unique, long enough, and in exactly the fixture they are documented for.
    web_text = "\n".join(line for line, _ in pairs)
    interim = webapp_interim_lines()
    interim_text = "\n".join(interim)
    seen: set[str] = set()
    for group, values in WEBAPP_SENTINELS.items():
        for value in values:
            assert len(value) >= 16 and value not in seen, value
            seen.add(value)
            in_interim = group in ("NONJSON", "SVC", "SSH")
            assert (value in interim_text) == in_interim, value
            assert (value in web_text) == (not in_interim), value
    for token in WEBAPP_PATH_TOKENS:
        assert token in web_text, token

    # Interim sections are contiguous, cover every line, and each line is documented.
    assert len(WEBAPP_INTERIM_DOCS) == len(interim)
    cursor = 0
    for name, (start, stop) in WEBAPP_INTERIM_SECTIONS.items():
        assert start == cursor and stop > start, name
        assert all(d[0] == name for d in WEBAPP_INTERIM_DOCS[start:stop]), name
        cursor = stop
    assert cursor == len(interim)
