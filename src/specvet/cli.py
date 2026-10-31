"""Command line interface.

argparse on purpose: the scanner has no dependencies, and a CLI that needs a
package installed before it will print `--help` is a CLI nobody reaches for
in a slim container. The MCP server (`specvet-mcp`) is the same library with
a different front door.
"""

from __future__ import annotations

import argparse
import contextlib
import sys

from . import __version__, demo, graph, rules
from .analyze import EXIT_OK, EXIT_USAGE, Options, exit_code, scan_path
from .loader import LoadError
from .model import SEVERITIES
from .render import json_text, summary, text
from .sarif import dumps as sarif_dumps

__all__ = ["build_parser", "force_utf8_stdio", "main"]


def force_utf8_stdio() -> None:
    """Make stdout/stderr UTF-8 before the first byte is printed.

    Windows consoles default to cp1252/cp936, which cannot encode the
    characters this tool prints by design (box drawing, CJK in spec
    descriptions). Without this, the first command a new visitor runs dies
    with ``UnicodeEncodeError`` — a failure no Linux machine reproduces.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # a StringIO in a test host
            continue
        if (getattr(stream, "encoding", "") or "").lower().replace("-", "") == "utf8":
            continue
        with contextlib.suppress(ValueError, OSError):  # detached / closed stream
            reconfigure(encoding="utf-8", errors="replace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="specvet",
        description="Deterministic security review for OpenAPI and Swagger documents.",
    )
    parser.add_argument("--version", action="version", version=f"specvet {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="audit a spec file or a directory tree")
    scan.add_argument("path", help="a .yaml/.yml/.json spec, or a directory to walk")
    scan.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument(
        "--fail-on",
        default="high",
        metavar="SEVERITY",
        help=f"exit 1 when a finding at or above SEVERITY exists ({', '.join(SEVERITIES)}, or none)",
    )
    scan.add_argument("--min-severity", default="info", choices=SEVERITIES, help="hide findings below this severity")
    scan.add_argument("--ignore", default="", metavar="IDS", help="comma-separated rule ids to drop")
    scan.add_argument("--no-inline-ignore", action="store_true", help="ignore `specvet: ignore` comments")
    scan.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    scan.add_argument("--no-snippets", action="store_true", help="omit the source line under each finding")
    scan.add_argument("--stats", action="store_true", help="print the OWASP coverage table")

    rule_cmd = sub.add_parser("rules", help="list the rule set")
    rule_cmd.add_argument("--severity", choices=SEVERITIES, help="only this severity")
    rule_cmd.add_argument("--owasp", help="only this OWASP API Top 10 category, e.g. API2:2023")
    rule_cmd.add_argument("--json", action="store_true", help="machine-readable output")

    demo_cmd = sub.add_parser("demo", help="print a deliberately flawed spec")
    demo_cmd.add_argument("--scan", action="store_true", help="audit the demo instead of printing it")
    demo_cmd.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")

    sub.add_parser("coverage", help="authentication coverage of a spec").add_argument("path")

    return parser


def _options(args: argparse.Namespace) -> Options:
    ignored = tuple(part.strip() for part in str(getattr(args, "ignore", "") or "").split(",") if part.strip())
    return Options(
        fail_on=str(getattr(args, "fail_on", "high")),
        min_severity=str(getattr(args, "min_severity", "info")),
        ignore=ignored,
        respect_inline_ignores=not getattr(args, "no_inline_ignore", False),
    )


def _emit(report, fmt: str, snippets: bool = True) -> str:
    if fmt == "json":
        return json_text(report) + "\n"
    if fmt == "sarif":
        return sarif_dumps(report)
    return text(report, snippets=snippets)


def _cmd_rules(args: argparse.Namespace) -> int:
    all_rules = {**rules.RULES, **graph.CROSS_RULES}
    selected = sorted(all_rules.values(), key=lambda r: r.id)
    if args.severity:
        selected = [r for r in selected if r.severity == args.severity]
    if args.owasp:
        wanted = args.owasp.strip().lower()
        selected = [r for r in selected if r.owasp.lower() == wanted]
    if args.json:
        import json

        print(json.dumps([r.__dict__ for r in selected], indent=2, ensure_ascii=False))
        return EXIT_OK
    print(f"{len(selected)} of {len(all_rules)} rules")
    print()
    for rule in selected:
        print(f"{rule.id}  [{rule.severity:<8}] {rule.owasp:<11} {rule.title}")
    return EXIT_OK


def _cmd_coverage(args: argparse.Namespace) -> int:
    report = scan_path(args.path)
    cover = graph.coverage(report.document)
    print(f"{report.path}: {_spec_line(report)}")
    print(f"  operations          {cover['operations']}")
    print(f"  authenticated       {cover['authenticated']}")
    print(f"  explicitly public   {cover['explicitly_public']}")
    print(f"  undeclared          {cover['undeclared']}")
    print(f"  coverage            {cover['coverage']}%")
    return EXIT_OK


def _spec_line(report) -> str:
    doc = report.document
    return f"{'Swagger' if doc.is_swagger2 else 'OpenAPI'} {doc.version}, {report.operation_count} operations"


def main(argv: list[str] | None = None) -> int:
    force_utf8_stdio()
    args = build_parser().parse_args(argv)

    if args.command == "rules":
        return _cmd_rules(args)

    if args.command == "demo":
        if args.scan:
            report = demo.scan_demo()
            print(_emit(report, args.format))
            return EXIT_OK
        print(demo.spec_text(), end="")
        return EXIT_OK

    if args.command == "coverage":
        try:
            return _cmd_coverage(args)
        except LoadError as exc:
            print(f"specvet: {exc}", file=sys.stderr)
            return EXIT_USAGE

    # -- scan ------------------------------------------------------------
    options = _options(args)
    if options.fail_on != "none" and options.fail_on not in SEVERITIES:
        print(f"specvet: --fail-on must be one of {', '.join(SEVERITIES)} or 'none'", file=sys.stderr)
        return EXIT_USAGE

    try:
        report = scan_path(args.path, options=options)
    except LoadError as exc:
        print(f"specvet: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"specvet: {exc}", file=sys.stderr)
        return EXIT_USAGE

    body = _emit(report, args.format, snippets=not args.no_snippets)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"wrote {args.output}")
    else:
        print(body, end="" if body.endswith("\n") else "\n")

    if args.stats:
        print()
        print(summary(report))

    return exit_code(report, options.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
