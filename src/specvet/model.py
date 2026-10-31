"""Data structures shared by the loader, the rules and the reporters.

Everything here is deliberately plain: a finding is a rule plus a pointer plus
a line. The pointer is a JSON Pointer (RFC 6901) so it survives reflows of the
file, and the line is what lets a human jump straight to it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "CRITICAL",
    "HIGH",
    "INFO",
    "LOW",
    "MEDIUM",
    "SEVERITIES",
    "SEVERITY_RANK",
    "WRITE_METHODS",
    "Document",
    "Finding",
    "Operation",
    "Report",
    "Rule",
    "pointer_escape",
]

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITIES = (CRITICAL, HIGH, MEDIUM, LOW, INFO)
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES)}

WRITE_METHODS = ("post", "put", "patch", "delete")
READ_METHODS = ("get", "head", "options")


@dataclass(frozen=True)
class Rule:
    """One deterministic check, mapped to an OWASP API Top 10 2023 category."""

    id: str
    title: str
    severity: str
    owasp: str
    summary: str
    fix: str


def pointer_escape(token: str) -> str:
    """RFC 6901: ``~`` then ``/``, and in that order."""
    return str(token).replace("~", "~0").replace("/", "~1")


def node_line(node: Any) -> int:
    """The source line of a node, 0 when the parser could not record one."""
    return int(getattr(node, "line", 0) or 0)


def key_line(node: Any, key: str) -> int:
    """The line where ``key`` was written inside a mapping node."""
    klines = getattr(node, "klines", None)
    if isinstance(klines, dict):
        return int(klines.get(str(key)) or node_line(node))
    return node_line(node)


def item_line(seq: Any, index: int) -> int:
    """The line of ``seq[index]``."""
    ilines = getattr(seq, "ilines", None)
    if isinstance(ilines, dict):
        return int(ilines.get(index) or node_line(seq))
    return node_line(seq)


@dataclass
class Finding:
    rule: Rule
    pointer: str
    line: int
    snippet: str = ""
    detail: str = ""

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def rule_id(self) -> str:
        return self.rule.id

    def sort_key(self) -> tuple:
        return (SEVERITY_RANK.get(self.rule.severity, 99), self.rule.id, self.line, self.pointer)


@dataclass
class Operation:
    """One ``(path, method)`` pair, with its security already resolved."""

    path: str
    method: str
    node: Any
    line: int = 0
    pointer: str = ""
    # None  -> no `security` anywhere (neither local nor global)
    # []    -> explicitly public (`security: []`)
    # [...] -> requirement objects
    security: Any = None
    security_local: bool = False
    deprecated: bool = False
    operation_id: str = ""

    @property
    def is_write(self) -> bool:
        return self.method in WRITE_METHODS

    @property
    def is_read(self) -> bool:
        return self.method in READ_METHODS

    @property
    def authenticated(self) -> bool:
        return bool(self.security)

    def responses(self) -> dict:
        node = self.node
        if not isinstance(node, dict):
            return {}
        out = node.get("responses")
        return out if isinstance(out, dict) else {}

    def parameters(self) -> list:
        node = self.node
        if not isinstance(node, dict):
            return []
        out = node.get("parameters")
        return list(out) if isinstance(out, list) else []

    def request_body(self) -> Any:
        node = self.node
        return node.get("requestBody") if isinstance(node, dict) else None

    def requirement_names(self) -> list[str]:
        """Scheme names referenced by this operation's security requirements."""
        names: list[str] = []
        if not isinstance(self.security, list):
            return names
        for requirement in self.security:
            if isinstance(requirement, dict):
                names.extend(str(k) for k in requirement)
            elif isinstance(requirement, str):
                names.append(requirement)
        return names


@dataclass
class Document:
    """A parsed spec plus the derived view the rules walk."""

    path: str
    text: str = ""
    root: Any = None
    fmt: str = "yaml"
    version: str = ""
    operations: list[Operation] = field(default_factory=list)
    global_security: Any = None
    schemes: dict = field(default_factory=dict)
    servers: list = field(default_factory=list)

    @property
    def is_swagger2(self) -> bool:
        return self.version.startswith("2")

    def lines(self) -> list[str]:
        return self.text.replace("\r\n", "\n").replace("\r", "\n").splitlines()

    def snippet(self, line: int) -> str:
        if line <= 0:
            return ""
        all_lines = self.lines()
        if line > len(all_lines):
            return ""
        return all_lines[line - 1].strip()[:160]

    def counts_by_severity(self, findings: list[Finding]) -> dict:
        out = dict.fromkeys(SEVERITIES, 0)
        for finding in findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out


@dataclass
class Report:
    document: Document
    findings: list[Finding] = field(default_factory=list)
    rules_run: int = 0
    scanned_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.document.path

    @property
    def operation_count(self) -> int:
        return len(self.document.operations)

    def by_severity(self, name: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == name]

    def counts(self) -> dict:
        return self.document.counts_by_severity(self.findings)

    def rule_ids(self) -> list[str]:
        return sorted({f.rule_id for f in self.findings})

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def risk_score(self) -> int:
        """0-100, weighted by severity. Deterministic, for CI thresholds."""
        weights = {CRITICAL: 25, HIGH: 12, MEDIUM: 5, LOW: 2, INFO: 1}
        score = sum(weights.get(f.severity, 0) for f in self.findings)
        return min(100, score)
