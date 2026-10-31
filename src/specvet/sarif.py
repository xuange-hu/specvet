"""SARIF 2.1.0 output for `github/codeql-action/upload-sarif`.

Rule metadata is emitted once and referenced by index, so a large scan does
not repeat 36 descriptions per result.
"""

from __future__ import annotations

import json

from .model import CRITICAL, HIGH, INFO, LOW, MEDIUM, Finding, Report

__all__ = ["dump", "dumps"]

# GitHub renders anything below 1.0 as "note"; spacing the values out keeps the
# code-scanning ordering aligned with the CLI's severity ordering.
_SECURITY_SEVERITY = {CRITICAL: "9.5", HIGH: "7.5", MEDIUM: "5.0", LOW: "3.0", INFO: "1.0"}
_SARIF_LEVEL = {CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note", INFO: "note"}


def _rules(report: Report) -> tuple[list[dict], dict[str, int]]:
    seen: dict[str, int] = {}
    out: list[dict] = []
    for finding in report.sorted():
        rule = finding.rule
        if rule.id in seen:
            continue
        seen[rule.id] = len(out)
        out.append(
            {
                "id": rule.id,
                "name": rule.id,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": f"{rule.summary} Fix: {rule.fix}"},
                "help": {
                    "text": f"{rule.summary}\n\nRemediation: {rule.fix}",
                    "markdown": f"**{rule.title}**\n\n{rule.summary}\n\n_Remediation_: {rule.fix}",
                },
                "properties": {
                    "tags": ["security", "api", "openapi", rule.owasp.lower()],
                    "security-severity": _SECURITY_SEVERITY.get(rule.severity, "1.0"),
                    "owasp-api-top10": rule.owasp,
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(rule.severity, "note")},
            }
        )
    return out, seen


def _uri(path: str) -> str:
    """SARIF artifact URIs are forward-slash on every platform.

    Replacing `os.sep` only fixes the separator of the machine that produced
    the report, so a Windows-style path scanned on Linux kept its backslashes
    and GitHub could not resolve the artifact. Normalise both.
    """
    return path.replace("\\", "/")


def _result(report: Report, finding: Finding, index_of: dict[str, int]) -> dict:
    line = finding.line if finding.line > 0 else 1
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": index_of.get(finding.rule_id, 0),
        "level": _SARIF_LEVEL.get(finding.severity, "note"),
        "message": {"text": finding.detail or finding.rule.title},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(report.path), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": line, "snippet": {"text": finding.snippet}},
                },
                "logicalLocations": [{"name": finding.pointer, "kind": "jsonPointer"}],
            }
        ],
        "properties": {"severity": finding.severity, "owasp": finding.rule.owasp, "jsonPointer": finding.pointer},
    }


def dumps(report: Report) -> str:
    rules, index_of = _rules(report)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "specvet",
                        "informationUri": "https://github.com/xuange-hu/specvet",
                        "version": "0.1.0",
                        "semanticVersion": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": [_result(report, f, index_of) for f in report.sorted()],
                "properties": {
                    "specvet.severityCounts": report.counts(),
                    "specvet.riskScore": report.risk_score(),
                    "specvet.operations": report.operation_count,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def dump(report: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dumps(report))
        fh.write("\n")
