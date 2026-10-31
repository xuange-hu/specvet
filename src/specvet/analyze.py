"""Scan orchestration: discover files, run both passes, apply suppressions.

Ordering is part of the contract: single-endpoint rules first, cross-endpoint
rules second, suppression last. A suppression keyed on a line must see the
same line the rule produced, so nothing may rewrite findings afterwards.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from . import graph, rules
from .loader import LoadError, load_file, load_text
from .model import (
    HIGH,
    INFO,
    SEVERITIES,
    SEVERITY_RANK,
    Document,
    Finding,
    Report,
)

__all__ = ["EXIT_FINDINGS", "EXIT_OK", "EXIT_USAGE", "Options", "exit_code", "scan_path", "scan_text"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

SPEC_SUFFIXES = (".yaml", ".yml", ".json")
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "site-packages",
}

IGNORE_RE = re.compile(r"specvet\s*:\s*ignore(?:\s*\[([^\]]*)\])?", re.IGNORECASE)


@dataclass
class Options:
    """Tunables that change which findings are reported, not what is detected."""

    fail_on: str = HIGH
    min_severity: str = INFO
    ignore: tuple[str, ...] = ()
    respect_inline_ignores: bool = True
    max_files: int = 2000
    _: tuple = field(default=(), repr=False, compare=False)

    def threshold(self) -> int:
        return SEVERITY_RANK.get(self.fail_on, len(SEVERITIES))


def _is_ignored(rule_id: str, ignored: Iterable[str]) -> bool:
    return any(rule_id.lower() == str(item).strip().lower() for item in ignored)


def _inline_ignores(doc: Document, line: int) -> set[str]:
    """Rule ids suppressed on ``line`` by a ``specvet: ignore[...]`` comment."""
    if line <= 0:
        return set()
    all_lines = doc.lines()
    if line > len(all_lines):
        return set()
    suppressed: set[str] = set()
    for match in IGNORE_RE.finditer(all_lines[line - 1]):
        inside = match.group(1)
        if inside is None:
            suppressed.add("*")
            continue
        for chunk in inside.replace(";", ",").split(","):
            rule_id = chunk.strip()
            if rule_id:
                suppressed.add(rule_id.upper())
    return suppressed


def _apply_suppressions(doc: Document, findings: list[Finding], options: Options) -> list[Finding]:
    out: list[Finding] = []
    for finding in findings:
        if _is_ignored(finding.rule_id, options.ignore):
            continue
        if SEVERITY_RANK.get(finding.severity, 99) > SEVERITY_RANK.get(options.min_severity, 0):
            continue
        if options.respect_inline_ignores:
            suppressed = _inline_ignores(doc, finding.line)
            if "*" in suppressed or finding.rule_id in suppressed:
                continue
        out.append(finding)
    return out


def scan_text(text: str, path: str = "<memory>", options: Options | None = None) -> Report:
    options = options or Options()
    doc = load_text(text, path=path)
    findings = rules.run(doc) + graph.run(doc)
    findings = _apply_suppressions(doc, findings, options)
    return Report(document=doc, findings=findings, rules_run=len(rules.RULES) + len(graph.CROSS_RULES))


def _iter_spec_files(root: str, max_files: int) -> list[str]:
    out: list[str] = []
    if os.path.isfile(root):
        return [root]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if name.lower().endswith(SPEC_SUFFIXES):
                out.append(os.path.join(dirpath, name))
                if len(out) >= max_files:
                    return out
    return out


def scan_path(path: str, options: Options | None = None) -> Report:
    """Scan a file or a directory tree.

    A file that is not an API description is skipped rather than reported:
    a repository is full of unrelated YAML, and "not a spec" is not a finding.
    """
    options = options or Options()
    files = _iter_spec_files(path, options.max_files)
    if not files:
        raise LoadError(f"{path}: no .yaml/.yml/.json files found")

    merged: list[Finding] = []
    documents: list[Document] = []
    errors: list[str] = []
    for file_path in files:
        try:
            doc = load_file(file_path)
        except (LoadError, OSError, UnicodeError):
            continue
        documents.append(doc)
        merged.extend(_apply_suppressions(doc, rules.run(doc) + graph.run(doc), options))

    if not documents:
        raise LoadError(f"{path}: no OpenAPI or Swagger document found (scanned {len(files)} file(s))")

    primary = documents[0]
    return Report(
        document=primary,
        findings=merged,
        rules_run=len(rules.RULES) + len(graph.CROSS_RULES),
        scanned_files=[d.path for d in documents],
        errors=errors,
    )


def exit_code(report: Report, fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_OK
    threshold = SEVERITY_RANK.get(fail_on)
    if threshold is None:
        return EXIT_USAGE
    for finding in report.findings:
        if SEVERITY_RANK.get(finding.severity, 99) <= threshold:
            return EXIT_FINDINGS
    return EXIT_OK
