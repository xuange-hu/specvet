"""MCP surface — optional extra, imported only when the ``mcp`` package exists.

Kept importable without mcp: the module raises ImportError at server
construction time, never at import time, so ``specvet --version`` and the
whole zero-dependency promise survive on a machine that has no `mcp` installed.
"""

from __future__ import annotations

import json
import os
from typing import Any

from . import demo, graph, rules
from .analyze import Options, scan_path, scan_text
from .model import SEVERITIES

TOOLS = (
    "specvet_scan",
    "specvet_scan_text",
    "specvet_rules",
    "specvet_explain",
    "specvet_coverage",
    "specvet_demo",
)

__all__ = ["TOOLS", "build_server", "main", "tool_manifest"]


def _finding_dict(finding) -> dict[str, Any]:
    return {
        "rule": finding.rule_id,
        "title": finding.rule.title,
        "severity": finding.severity,
        "owasp": finding.rule.owasp,
        "pointer": finding.pointer,
        "line": finding.line,
        "snippet": finding.snippet,
        "detail": finding.detail,
    }


def _report_dict(report, max_findings: int = 60) -> dict[str, Any]:
    doc = report.document
    findings = report.sorted()
    return {
        "tool": "specvet",
        "path": report.path,
        "spec": {"kind": "swagger" if doc.is_swagger2 else "openapi", "version": doc.version, "format": doc.fmt},
        "operations": report.operation_count,
        "coverage": graph.coverage(doc),
        "riskScore": report.risk_score(),
        "rulesRun": report.rules_run,
        "counts": report.counts(),
        "owasp": [{"id": o, "worst": w, "count": c} for o, w, c in _owasp(report)],
        "findings": [_finding_dict(f) for f in findings[: max(1, int(max_findings))]],
        "truncated": len(findings) > max_findings,
    }


def _owasp(report):
    from .render import owasp_table

    return owasp_table(report)


def _clean_severity(value: str) -> str:
    return value if value in SEVERITIES else "info"


def specvet_scan(
    path: str = ".",
    min_severity: str = "info",
    ignore: str = "",
    max_findings: int = 60,
) -> str:
    """Audit an OpenAPI/Swagger file or a directory of specs.

    Returns JSON: counts per severity, an OWASP API Top 10 breakdown, a risk
    score, authentication coverage, and every finding with a JSON Pointer and
    a line number. Use `ignore` for accepted risks (comma-separated rule ids).
    """
    if not os.path.exists(path):
        return json.dumps({"error": f"path not found: {path}", "tool": "specvet"}, ensure_ascii=False)
    options = Options(
        min_severity=_clean_severity(min_severity),
        ignore=tuple(part.strip() for part in ignore.split(",") if part.strip()),
    )
    report = scan_path(path, options=options)
    return json.dumps(_report_dict(report, max_findings), indent=2, ensure_ascii=False)


def specvet_scan_text(
    text: str,
    path: str = "<memory>",
    min_severity: str = "info",
    ignore: str = "",
    max_findings: int = 60,
) -> str:
    """Audit a spec supplied inline instead of on disk.

    For an agent that just generated or edited an OpenAPI document: paste the
    YAML/JSON and get the same findings the CLI would produce, without a
    round trip through the filesystem.
    """
    options = Options(
        min_severity=_clean_severity(min_severity),
        ignore=tuple(part.strip() for part in ignore.split(",") if part.strip()),
    )
    report = scan_text(text, path=path, options=options)
    return json.dumps(_report_dict(report, max_findings), indent=2, ensure_ascii=False)


def specvet_rules(severity: str = "", owasp: str = "") -> str:
    """List the 36 rules, optionally filtered by severity or by OWASP API Top 10 2023 category (e.g. API2:2023)."""
    all_rules = {**rules.RULES, **graph.CROSS_RULES}
    items = sorted(all_rules.values(), key=lambda r: r.id)
    if severity:
        items = [r for r in items if r.severity == severity]
    if owasp:
        items = [r for r in items if r.owasp.lower() == owasp.strip().lower()]
    return json.dumps(
        {
            "count": len(items),
            "total": len(all_rules),
            "rules": [
                {"id": r.id, "title": r.title, "severity": r.severity, "owasp": r.owasp, "summary": r.summary, "fix": r.fix}
                for r in items
            ],
        },
        indent=2,
        ensure_ascii=False,
    )


def specvet_explain(rule_id: str) -> str:
    """Explain one rule: the attack it corresponds to, why it matters, and the fix."""
    all_rules = {**rules.RULES, **graph.CROSS_RULES}
    rule = all_rules.get(str(rule_id).strip().upper())
    if rule is None:
        return json.dumps({"error": f"unknown rule {rule_id}", "known": sorted(all_rules)}, ensure_ascii=False)
    return json.dumps(
        {**rule.__dict__, "narrative": f"{rule.summary}\n\nFix: {rule.fix}"},
        indent=2,
        ensure_ascii=False,
    )


def specvet_coverage(path: str) -> str:
    """Report what share of operations resolve to a security requirement.

    Coverage is the number worth watching in review: a spec can look
    authenticated because it *defines* schemes while no operation requires one.
    """
    if not os.path.exists(path):
        return json.dumps({"error": f"path not found: {path}", "tool": "specvet"}, ensure_ascii=False)
    report = scan_path(path)
    return json.dumps(
        {"path": report.path, "operations": report.operation_count, **graph.coverage(report.document)},
        indent=2,
        ensure_ascii=False,
    )


def specvet_demo(max_findings: int = 40) -> str:
    """Audit the built-in deliberately flawed spec — one-call proof of value, no input needed."""
    report = demo.scan_demo()
    payload = _report_dict(report, max_findings)
    payload["demo"] = True
    return json.dumps(payload, indent=2, ensure_ascii=False)


def build_server():
    """Construct the MCP server. Requires the optional `mcp` extra."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(name="specvet")

    def specvet_scan_tool(
        path: str = ".",
        min_severity: str = "info",
        ignore: str = "",
        max_findings: int = 60,
    ) -> str:
        return specvet_scan(path, min_severity, ignore, max_findings)

    def specvet_scan_text_tool(
        text: str,
        path: str = "<memory>",
        min_severity: str = "info",
        ignore: str = "",
        max_findings: int = 60,
    ) -> str:
        return specvet_scan_text(text, path, min_severity, ignore, max_findings)

    def specvet_rules_tool(severity: str = "", owasp: str = "") -> str:
        return specvet_rules(severity, owasp)

    def specvet_explain_tool(rule_id: str) -> str:
        return specvet_explain(rule_id)

    def specvet_coverage_tool(path: str) -> str:
        return specvet_coverage(path)

    def specvet_demo_tool(max_findings: int = 40) -> str:
        return specvet_demo(max_findings)

    # FastMCP reads fn.__doc__ at registration time, so copy the underlying
    # docstring onto each wrapper *before* mcp.tool() runs - the manifest
    # promises these descriptions and an empty one is useless to an agent.
    for name, wrapper, fn in (
        ("specvet_scan", specvet_scan_tool, specvet_scan),
        ("specvet_scan_text", specvet_scan_text_tool, specvet_scan_text),
        ("specvet_rules", specvet_rules_tool, specvet_rules),
        ("specvet_explain", specvet_explain_tool, specvet_explain),
        ("specvet_coverage", specvet_coverage_tool, specvet_coverage),
        ("specvet_demo", specvet_demo_tool, specvet_demo),
    ):
        wrapper.__doc__ = fn.__doc__
        mcp.tool(name=name)(wrapper)

    return mcp


def tool_manifest() -> list[dict[str, str]]:
    return [
        {"name": "specvet_scan", "description": specvet_scan.__doc__ or ""},
        {"name": "specvet_scan_text", "description": specvet_scan_text.__doc__ or ""},
        {"name": "specvet_rules", "description": specvet_rules.__doc__ or ""},
        {"name": "specvet_explain", "description": specvet_explain.__doc__ or ""},
        {"name": "specvet_coverage", "description": specvet_coverage.__doc__ or ""},
        {"name": "specvet_demo", "description": specvet_demo.__doc__ or ""},
    ]


def main() -> None:
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()
