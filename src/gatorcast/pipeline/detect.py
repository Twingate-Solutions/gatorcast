"""Built-in detection rule engine for recorded session content.

Runs a fixed set of regex rules against the plaintext reconstruction produced by
:mod:`gatorcast.pipeline.extract`. Each matching rule yields at most one
:class:`Finding` describing the rule that fired and the earliest replay offset at
which it matched.

Security (CLAUDE.md rules 5 + 6): a :class:`Finding` carries only the rule label,
category, severity, and time offset. It NEVER carries the matched text, and this
module never logs recorded content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from gatorcast.pipeline.extract import ExtractResult, offset_at


@dataclass(frozen=True, slots=True)
class Rule:
    """A single detection rule: identity, classification, and its regex."""

    id: str
    category: str
    severity: str
    label: str
    pattern: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class Finding:
    """A rule hit. Carries rule metadata + offset only, never matched text."""

    rule_id: str
    category: str
    severity: str
    label: str
    offset_seconds: float | None


SEVERITY_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Command rules are case-insensitive; secret-token rules are case-sensitive so
# case fidelity is preserved (AWS AKIA, ghp_, JWT eyJ, vault hvs., private key).
_IC = re.IGNORECASE

BUILTIN_RULES: list[Rule] = [
    Rule(
        "recursive-delete",
        "dangerous-command",
        "high",
        "Recursive delete (rm -rf)",
        re.compile(r"\brm\s+(?:-\w+\s+)*-\w*r\w*f\w*|\brm\s+(?:-\w+\s+)*-\w*f\w*r\w*", _IC),
    ),
    Rule(
        "pipe-to-shell",
        "dangerous-command",
        "critical",
        "Pipe download to shell",
        re.compile(r"(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", _IC),
    ),
    Rule(
        "chmod-777",
        "dangerous-command",
        "medium",
        "World-writable chmod 777",
        re.compile(r"\bchmod\s+(?:-\w+\s+)*777\b", _IC),
    ),
    Rule(
        "raw-disk-write",
        "dangerous-command",
        "high",
        "Raw disk write (dd)",
        re.compile(r"\bdd\s+[^\n]*\bof=/dev/", _IC),
    ),
    Rule(
        "mkfs",
        "dangerous-command",
        "high",
        "Filesystem format (mkfs)",
        re.compile(r"\bmkfs(?:\.\w+)?\s+", _IC),
    ),
    Rule(
        "fork-bomb",
        "dangerous-command",
        "critical",
        "Fork bomb",
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:&\s*\}\s*;\s*:", _IC),
    ),
    Rule(
        "reverse-shell",
        "dangerous-command",
        "critical",
        "Reverse shell",
        re.compile(r"\bnc\b[^\n]*\s-e\b|/dev/tcp/", _IC),
    ),
    Rule(
        "base64-pipe-shell",
        "dangerous-command",
        "critical",
        "base64 decode to shell",
        re.compile(r"base64\s+(?:-\w+\s+)*-d\b[^\n]*\|\s*(?:ba)?sh\b", _IC),
    ),
    Rule(
        "kubectl-delete",
        "dangerous-command",
        "high",
        "kubectl delete",
        re.compile(r"\bkubectl\b[^\n]*\bdelete\b", _IC),
    ),
    Rule(
        "kubectl-drain",
        "dangerous-command",
        "high",
        "kubectl drain/cordon",
        re.compile(r"\bkubectl\b[^\n]*\b(?:drain|cordon)\b", _IC),
    ),
    Rule(
        "kubectl-secret",
        "dangerous-command",
        "high",
        "kubectl access secret",
        re.compile(r"\bkubectl\b[^\n]*\bsecret", _IC),
    ),
    Rule(
        "iptables-flush",
        "dangerous-command",
        "medium",
        "Firewall flush (iptables -F)",
        re.compile(r"\biptables\b[^\n]*\s-F\b", _IC),
    ),
    Rule(
        "history-clear",
        "dangerous-command",
        "medium",
        "Shell history cleared",
        re.compile(r"\bhistory\s+-c\b|>\s*~?/?\.bash_history", _IC),
    ),
    Rule(
        "privilege-change",
        "dangerous-command",
        "high",
        "Account/privilege change",
        re.compile(r"\b(?:useradd|usermod|passwd|visudo)\b|\bsudo\s+su\b", _IC),
    ),
    Rule(
        "aws-key",
        "secret-exposure",
        "critical",
        "AWS access key on screen",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    Rule(
        "private-key",
        "secret-exposure",
        "critical",
        "Private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    Rule(
        "github-token",
        "secret-exposure",
        "critical",
        "GitHub token",
        re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),
    ),
    Rule(
        "slack-token",
        "secret-exposure",
        "high",
        "Slack token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ),
    Rule(
        "jwt",
        "secret-exposure",
        "medium",
        "JWT on screen",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    Rule(
        "vault-token",
        "secret-exposure",
        "critical",
        "Vault token",
        re.compile(r"\bhvs\.[A-Za-z0-9]{20,}\b|VAULT_TOKEN\s*=\s*\S+"),
    ),
    Rule(
        "generic-secret-assign",
        "secret-exposure",
        "medium",
        "Secret assigned inline",
        re.compile(r"\b(?:password|passwd|secret|api[_-]?key|token)\s*=\s*['\"]?\S{6,}", _IC),
    ),
]


def load_rules() -> list[Rule]:
    """Return the active rule set.

    This is the single seam where a future YAML-backed rule loader would plug in;
    for v1 it returns the built-in rules verbatim.

    Returns:
        The list of :class:`Rule` objects to evaluate.
    """
    return BUILTIN_RULES


def detect(extract: ExtractResult, rules: list[Rule] | None = None) -> list[Finding]:
    """Evaluate detection rules against extracted plaintext.

    Each rule's pattern is searched against ``extract.text``. ``re.search`` returns
    the earliest match by position, so a matching rule produces exactly one
    :class:`Finding` carrying the replay offset of that earliest match. Matched
    text is never copied into the finding (CLAUDE.md rule 6).

    Args:
        extract: The plaintext extraction result to scan.
        rules: Optional explicit rule set; defaults to :func:`load_rules`.

    Returns:
        A list of findings, one per matching rule, in rule-declaration order.
    """
    active = load_rules() if rules is None else rules
    findings: list[Finding] = []
    for rule in active:
        match = rule.pattern.search(extract.text)
        if match is None:
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                category=rule.category,
                severity=rule.severity,
                label=rule.label,
                offset_seconds=offset_at(extract, match.start()),
            )
        )
    return findings


def max_severity(findings: list[Finding]) -> str | None:
    """Return the highest-ranked severity among findings, or None if empty.

    Args:
        findings: The findings to reduce.

    Returns:
        The severity string with the greatest :data:`SEVERITY_RANK`, or ``None``.
    """
    if not findings:
        return None
    return max(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0)).severity
