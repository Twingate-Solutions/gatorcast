"""Built-in detection rule engine for recorded session content.

Runs a fixed set of regex rules against the plaintext reconstruction produced by
:mod:`gatorcast.pipeline.extract`. Each matching rule yields at most one
:class:`Finding` describing the rule that fired and the earliest replay offset at
which it matched.

It also runs a second, independent rule set (:class:`ApiRule`) against Kubernetes
API request metadata (method + URL path) from the Gateway's API-request audit
lines. API findings have no replay offset (``offset_seconds`` is always ``None``).

Security (CLAUDE.md rules 5 + 6): a :class:`Finding` carries only the rule label,
category, severity, and time offset. It NEVER carries the matched text, and this
module never logs recorded content, URLs, or header values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from gatorcast.pipeline.extract import ExtractResult, offset_at
from gatorcast.pipeline.urlnorm import match_path


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


# ---------------------------------------------------------------------------
# Kubernetes API request detection (spec §10)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ApiRule:
    """A detection rule over one Kubernetes API request's method and URL path.

    ``methods`` is the set of uppercase HTTP methods the rule applies to, or
    ``None`` to apply to any method. ``path`` is searched against the normalized,
    lower-cased URL path only (see :func:`gatorcast.pipeline.urlnorm.match_path`),
    never the query string, so write patterns in lower case.

    ``resource_types`` is the set of normalized (uppercase) Twingate resource types
    the rule applies to; it defaults to Kubernetes only, so the built-in rules never
    fire on web-app traffic (WEBAPP_SPEC §7.1).
    """

    id: str
    category: str
    severity: str
    label: str
    methods: frozenset[str] | None
    path: re.Pattern[str]
    resource_types: frozenset[str] = frozenset({"KUBERNETES"})


API_CATEGORY = "kube-api"

BUILTIN_API_RULES: list[ApiRule] = [
    ApiRule(
        "kube-delete",
        API_CATEGORY,
        "high",
        "Kubernetes resource delete",
        frozenset({"DELETE"}),
        re.compile(r"^/"),
    ),
    ApiRule(
        "kube-secrets",
        API_CATEGORY,
        "high",
        "Kubernetes secret access",
        None,
        re.compile(r"/secrets(/|$)"),
    ),
    ApiRule(
        "kube-evict",
        API_CATEGORY,
        "high",
        "Pod eviction (drain)",
        frozenset({"POST"}),
        re.compile(r"/pods/[^/]+/eviction$"),
    ),
    ApiRule(
        "kube-cordon",
        API_CATEGORY,
        "medium",
        "Node patched (cordon/uncordon)",
        frozenset({"PATCH"}),
        re.compile(r"^/api/v1/nodes/[^/]+$"),
    ),
    ApiRule(
        "kube-exec",
        API_CATEGORY,
        "medium",
        "Pod exec/attach",
        None,
        re.compile(r"/pods/[^/]+/(exec|attach)$"),
    ),
    # Kubelet exec through the API server's node proxy. classify keeps
    # ``/nodes/<n>/proxy/<exec|run|attach>`` as the stored prefix (and drops the
    # rest of the path and the query), so this rule still sees it on stored URLs.
    ApiRule(
        "kube-node-proxy-exec",
        API_CATEGORY,
        "high",
        "Node proxy exec/run/attach",
        None,
        re.compile(r"/nodes/[^/]+/proxy/(exec|run|attach)(/|$)"),
    ),
]


def load_api_rules() -> list[ApiRule]:
    """Return the active Kubernetes API rule set.

    Same seam as :func:`load_rules`: a future YAML-backed loader would plug in
    here; for v1 it returns the built-in API rules verbatim.

    Returns:
        The list of :class:`ApiRule` objects to evaluate.
    """
    return BUILTIN_API_RULES


def detect_api(
    method: str,
    url: str,
    rules: list[ApiRule] | None = None,
    *,
    resource_type: str | None = None,
) -> list[Finding]:
    """Evaluate API rules against one request's method and URL path.

    The URL is normalized with the same helper classify uses (fragment dropped,
    path unquoted once, repeated ``/`` collapsed, trailing ``/`` stripped) and
    lower-cased, so callers may pass raw or stored URLs and encoded or oddly
    shaped variants (``/%73ecrets/x``, ``/pods/p/exec/``) still match. The query
    string is never matched, so query content (e.g. a ``labelSelector``
    mentioning ``/secrets``) does not affect the result. Stored URLs are
    normalized a second time here; a double-encoded path therefore errs toward a
    finding. ``method`` is compared case-insensitively. Each matching rule yields
    exactly one :class:`Finding` with ``offset_seconds=None``; the URL is never
    copied into the finding.

    Rules whose ``resource_types`` does not contain the request's resource type are
    skipped. ``resource_type=None`` (an unresolved, fail-closed, or NULL connection
    row) is treated as Kubernetes, so the Kubernetes-policy rows keep their
    Kubernetes rules (WEBAPP_SPEC §4.4, §7.1). A non-None value is compared
    upper-cased, so ``"kubernetes"`` and ``"KUBERNETES"`` behave the same.

    Args:
        method: The HTTP method of the request (e.g. ``"DELETE"``).
        url: The raw or stored request URL; only its normalized path is matched.
        rules: Optional explicit rule set; defaults to :func:`load_api_rules`.
        resource_type: The connection's normalized resource type, or ``None`` for
            the Kubernetes default.

    Returns:
        A list of findings, one per matching rule, in rule-declaration order.
    """
    active = load_api_rules() if rules is None else rules
    verb = method.upper()
    path = match_path(url)
    scope = "KUBERNETES" if resource_type is None else resource_type.upper()
    findings: list[Finding] = []
    for rule in active:
        if scope not in rule.resource_types:
            continue
        if rule.methods is not None and verb not in rule.methods:
            continue
        if rule.path.search(path) is None:
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                category=rule.category,
                severity=rule.severity,
                label=rule.label,
                offset_seconds=None,
            )
        )
    return findings
