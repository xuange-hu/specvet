"""Human-facing output.

Every finding carries three coordinates: the severity, the JSON Pointer (which
survives a reflow of the file) and the line (which a human can jump to).
Printing all three is what makes the report checkable instead of trusted.
"""

from __future__ import annotations

import json

from . import graph
from .model import CRITICAL, HIGH, INFO, LOW, MEDIUM, SEVERITIES, SEVERITY_RANK, Report

__all__ = ["json_text", "owasp_table", "summary", "text"]

_BADGE = {
    CRITICAL: "CRITICAL",
    HIGH: "HIGH    ",
    MEDIUM: "MEDIUM  ",
    LOW: "LOW     ",
    INFO: "INFO    ",
}


def _spec_label(report: Report) -> str:
    doc = report.document
    kind = "Swagger" if doc.is_swagger2 else "OpenAPI"
    return f"{kind} {doc.version}"


def summary(report: Report) -> str:
    counts = report.counts()
    parts = ", ".join(f"{counts[name]} {name}" for name in SEVERITIES if counts.get(name))
    doc = report.document
    cover = graph.coverage(doc)
    head = f"{report.path}  {_spec_label(report)} · {report.operation_count} operations"
    if len(report.scanned_files) > 1:
        head += f" · {len(report.scanned_files)} files"
    head += f"\n{len(report.findings)} findings"
    if parts:
        head += f" ({parts})"
    head += f" · risk {report.risk_score()}/100 · auth coverage {cover['coverage']}%"
    return head


def owasp_table(report: Report) -> list[tuple[str, str, int]]:
    """``(owasp_id, worst_severity, count)`` ordered by OWASP category.

    "Worst" means the highest severity in the category, not the severity of
    whichever finding happened to be generated first - the unsorted order put a
    medium ahead of a critical here once, which reads as "this category is
    fine" in a report people skim.
    """
    buckets: dict[str, dict] = {}
    for finding in report.findings:
        entry = buckets.setdefault(finding.rule.owasp, {"count": 0, "rank": 99, "worst": "info"})
        entry["count"] += 1
        rank = SEVERITY_RANK.get(finding.severity, 99)
        if rank < entry["rank"]:
            entry["rank"] = rank
            entry["worst"] = finding.severity
    order = [f"API{i}:2023" for i in range(1, 11)]
    out: list[tuple[str, str, int]] = []
    for key in order:
        if key in buckets:
            out.append((key, buckets[key]["worst"], buckets[key]["count"]))
    for key in sorted(buckets):
        if key not in order:
            out.append((key, buckets[key]["worst"], buckets[key]["count"]))
    return out


def text(report: Report, snippets: bool = True) -> str:
    out: list[str] = [summary(report), ""]
    if not report.findings:
        out.append("no findings")
        return "\n".join(out)

    table = owasp_table(report)
    if table:
        out.append("OWASP API Top 10 coverage")
        for owasp, worst, count in table:
            out.append(f"  {owasp:<12} {count:>3} finding(s), worst {worst}")
        out.append("")

    for finding in report.sorted():
        out.append(f"{_BADGE[finding.severity]}  {finding.rule_id}  {finding.rule.title}  [{finding.rule.owasp}]")
        out.append(f"           {finding.pointer}")
        if finding.line > 0:
            out.append(f"           line {finding.line}")
        if finding.detail:
            out.append(f"           {finding.detail}")
        if snippets and finding.snippet:
            out.append(f"           | {finding.snippet}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def json_text(report: Report) -> str:
    doc = report.document
    payload = {
        "tool": "specvet",
        "version": "0.1.0",
        "path": report.path,
        "spec": {"kind": "swagger" if doc.is_swagger2 else "openapi", "version": doc.version, "format": doc.fmt},
        "operations": report.operation_count,
        "coverage": graph.coverage(doc),
        "risk_score": report.risk_score(),
        "rules_run": report.rules_run,
        "counts": report.counts(),
        "owasp": [{"id": o, "worst": w, "count": c} for o, w, c in owasp_table(report)],
        "findings": [
            {
                "rule": f.rule_id,
                "title": f.rule.title,
                "severity": f.severity,
                "owasp": f.rule.owasp,
                "pointer": f.pointer,
                "line": f.line,
                "snippet": f.snippet,
                "detail": f.detail,
                "fix": f.rule.fix,
            }
            for f in report.sorted()
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
