"""CLI contract: commands, formats and exit codes, driven in-process."""

from __future__ import annotations

import json

import pytest

from specvet.analyze import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE
from specvet.cli import build_parser, main
from specvet.demo import SPEC_TEXT

SPEC = """\
openapi: 3.0.3
info: {title: t, version: '1'}
paths:
  /x:
    get:
      responses:
        '200': {description: ok}
"""


def run(argv, capsys) -> tuple[int, str]:
    code = main(argv)
    out = capsys.readouterr()
    return code, out.out + out.err


def write(tmp_path, text=SPEC, name="openapi.yaml") -> str:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_scan_text_output_mentions_the_rule(capsys, tmp_path):
    code, out = run(["scan", write(tmp_path)], capsys)
    assert code == EXIT_FINDINGS
    assert "SPV004" in out
    assert "/paths/~1x/get" in out


def test_scan_json_output_parses(capsys, tmp_path):
    code, out = run(["scan", write(tmp_path), "--format", "json"], capsys)
    assert code == EXIT_FINDINGS
    payload = json.loads(out)
    assert payload["tool"] == "specvet"
    assert payload["findings"]


def test_scan_sarif_output_parses(capsys, tmp_path):
    code, out = run(["scan", write(tmp_path), "--format", "sarif"], capsys)
    assert code == EXIT_FINDINGS
    payload = json.loads(out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "specvet"


def test_fail_on_none_exits_zero(capsys, tmp_path):
    code, _ = run(["scan", write(tmp_path), "--fail-on", "none"], capsys)
    assert code == EXIT_OK


def test_bad_fail_on_is_a_usage_error(capsys, tmp_path):
    code, out = run(["scan", write(tmp_path), "--fail-on", "catastrophe"], capsys)
    assert code == EXIT_USAGE
    assert "fail-on" in out


def test_missing_path_is_a_usage_error(capsys, tmp_path):
    code, out = run(["scan", str(tmp_path / "nope.yaml")], capsys)
    assert code == EXIT_USAGE
    assert "specvet:" in out


def test_output_file_is_written(capsys, tmp_path):
    target = tmp_path / "report.txt"
    code, _ = run(["scan", write(tmp_path), "-o", str(target), "--fail-on", "none"], capsys)
    assert code == EXIT_OK
    assert target.exists()
    assert "SPV004" in target.read_text(encoding="utf-8")


def test_demo_prints_a_scannable_spec(capsys):
    code, out = run(["demo"], capsys)
    assert code == EXIT_OK
    assert "openapi: 3.0.3" in out


def test_demo_scan_reports_findings(capsys):
    code, out = run(["demo", "--scan"], capsys)
    assert code == EXIT_OK
    assert "SPV001" in out and "SPV036" in out


def test_demo_output_matches_the_shipped_text(capsys):
    _, out = run(["demo"], capsys)
    assert out.strip() == SPEC_TEXT.strip()


def test_rules_lists_the_whole_set(capsys):
    code, out = run(["rules"], capsys)
    assert code == EXIT_OK
    assert "36 of 36 rules" in out
    assert "SPV001" in out and "SPV036" in out


def test_rules_filter_by_severity(capsys):
    code, out = run(["rules", "--severity", "critical"], capsys)
    assert code == EXIT_OK
    assert "SPV002" in out
    assert "SPV035" not in out


def test_rules_filter_by_owasp_category(capsys):
    code, out = run(["rules", "--owasp", "API2:2023"], capsys)
    assert code == EXIT_OK
    assert "SPV004" in out
    assert "SPV001" not in out


def test_rules_json_output(capsys):
    code, out = run(["rules", "--json"], capsys)
    assert code == EXIT_OK
    payload = json.loads(out)
    assert len(payload) == 36


def test_coverage_command(capsys, tmp_path):
    code, out = run(["coverage", write(tmp_path)], capsys)
    assert code == EXIT_OK
    assert "coverage" in out


def test_ignore_flag(capsys, tmp_path):
    # /x has no path parameter, so SPV004 is the only critical finding on it.
    code, out = run(["scan", write(tmp_path), "--ignore", "SPV004", "--fail-on", "critical"], capsys)
    assert code == EXIT_OK
    assert "SPV004" not in out


def test_no_snippets_removes_source_lines(capsys, tmp_path):
    _, with_snip = run(["scan", write(tmp_path)], capsys)
    _, without = run(["scan", write(tmp_path), "--no-snippets"], capsys)
    assert len(without) < len(with_snip)


def test_stats_flag(capsys, tmp_path):
    code, out = run(["scan", write(tmp_path), "--stats"], capsys)
    assert code == EXIT_FINDINGS
    assert "risk" in out


def test_parser_requires_a_subcommand():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_min_severity_flag(capsys, tmp_path):
    code, out = run(["scan", write(tmp_path), "--min-severity", "critical"], capsys)
    assert code == EXIT_FINDINGS
    assert "SPV035" not in out
