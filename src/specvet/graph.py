"""The second pass: rules that need the whole operation set.

Reading one endpoint at a time answers "is this operation authenticated?".
It cannot answer "why does this one path authenticate GET but not DELETE?" or
"why is this scheme defined but never used?". Both are properties of the graph
of operations, and both are where real reviews find the bug - because each
endpoint looks defensible in isolation.

This is the same observation kubeguard makes about Kubernetes manifests: the
default posture is permissive, so the risk lives in the relationships.
"""

from __future__ import annotations

from .model import HIGH, Document, Finding, Rule, key_line, pointer_escape

__all__ = ["CROSS_RULES", "run"]

SPV005 = Rule(
    "SPV005",
    "Security scheme is defined but never required",
    HIGH,
    "API2:2023",
    "The document declares a scheme that no `security` requirement references. Unreferenced "
    "schemes do not authenticate anything - they only make the contract look authenticated.",
    "Reference the scheme from `security`, or delete it.",
)

SPV021 = Rule(
    "SPV021",
    "Authorization is inconsistent within one path",
    HIGH,
    "API5:2023",
    "Some methods on this path carry a security requirement and others do not. A path that "
    "authenticates reads but not writes has its function-level authorization backwards.",
    "Apply the same security requirement to every method of the path.",
)

CROSS_RULES: dict[str, Rule] = {"SPV005": SPV005, "SPV021": SPV021}


def _finding(rule: Rule, doc: Document, pointer: str, line: int, detail: str) -> Finding:
    return Finding(rule=rule, pointer=pointer, line=line, snippet=doc.snippet(line), detail=detail)


def _unused_schemes(doc: Document) -> list[Finding]:
    if not doc.schemes:
        return []
    used: set[str] = set()

    def collect(requirement: object) -> None:
        if isinstance(requirement, list):
            for entry in requirement:
                collect(entry)
        elif isinstance(requirement, dict):
            used.update(str(k) for k in requirement)

    collect(doc.global_security)
    for op in doc.operations:
        collect(op.security)

    out: list[Finding] = []
    for name in doc.schemes:
        if str(name) in used:
            continue
        pointer = "/components/securitySchemes/" + pointer_escape(str(name))
        if doc.is_swagger2:
            pointer = "/securityDefinitions/" + pointer_escape(str(name))
        out.append(
            _finding(
                SPV005,
                doc,
                pointer,
                key_line(doc.schemes, name),
                f"scheme {str(name)!r} is never referenced by a security requirement",
            )
        )
    return out


def _inconsistent_paths(doc: Document) -> list[Finding]:
    grouped: dict[str, list] = {}
    for op in doc.operations:
        grouped.setdefault(op.path, []).append(op)

    out: list[Finding] = []
    for path, ops in grouped.items():
        if len(ops) < 2:
            continue
        # `security: []` is a decision; `security` absent is an omission. Only
        # the omission is inconsistent - mixing the two silently would flag
        # every intentional public read next to a protected write.
        decided = [op for op in ops if op.security is not None]
        undecided = [op for op in ops if op.security is None]
        if not decided or not undecided:
            continue
        shown = ", ".join(sorted(op.method.upper() for op in undecided))
        out.append(
            _finding(
                SPV021,
                doc,
                "/paths/" + pointer_escape(path),
                min(op.line for op in ops),
                f"{path}: {shown} has no security while other methods do",
            )
        )
    return out


def coverage(doc: Document) -> dict:
    """Share of operations that resolve to a security requirement."""
    total = len(doc.operations)
    authed = sum(1 for op in doc.operations if op.authenticated)
    explicit_public = sum(1 for op in doc.operations if op.security == [])
    return {
        "operations": total,
        "authenticated": authed,
        "explicitly_public": explicit_public,
        "undeclared": total - authed - explicit_public,
        "coverage": round(100.0 * authed / total, 1) if total else 100.0,
    }


def run(doc: Document) -> list[Finding]:
    return _unused_schemes(doc) + _inconsistent_paths(doc)
