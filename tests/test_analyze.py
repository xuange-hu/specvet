"""Scan orchestration: discovery, suppression, exit codes."""

from __future__ import annotations

import os

import pytest

from specvet.analyze import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, Options, exit_code, scan_path, scan_text
from specvet.loader import LoadError

SPEC = """\
openapi: 3.0.3
info: {title: t, version: '1'}
paths:
  /x:
    get:
      responses:
        '200': {description: ok}
"""

OTHER = """\
name: not-an-api
on: push
"""


def _tree(tmp_path):
    (tmp_path / "openapi.yaml").write_text(SPEC, encoding="utf-8")
    (tmp_path / "unrelated.yml").write_text(OTHER, encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "openapi.json").write_text(
        '{"openapi": "3.0.3", "info": {"title": "j", "version": "1"}, "paths": {"/j": {"get": {"responses": {"200": {"description": "ok"}}}}}}',
        encoding="utf-8",
    )
    return tmp_path


def test_scan_path_walks_a_directory_and_skips_non_specs(tmp_path):
    report = scan_path(str(_tree(tmp_path)), options=Options())
    assert len(report.scanned_files) == 2
    assert any(f.endswith(".json") for f in report.scanned_files)


def test_scan_path_on_a_single_file(tmp_path):
    path = tmp_path / "openapi.yaml"
    path.write_text(SPEC, encoding="utf-8")
    report = scan_path(str(path), options=Options())
    assert report.operation_count == 1


def test_a_directory_without_any_spec_raises(tmp_path):
    (tmp_path / "x.txt").write_text("hello", encoding="utf-8")
    with pytest.raises(LoadError):
        scan_path(str(tmp_path), options=Options())


def test_vendor_directories_are_not_walked(tmp_path):
    _tree(tmp_path)
    vendor = tmp_path / "node_modules"
    vendor.mkdir()
    (vendor / "openapi.yaml").write_text(SPEC, encoding="utf-8")
    report = scan_path(str(tmp_path), options=Options())
    assert not any("node_modules" in f for f in report.scanned_files)


def test_ignore_option_drops_a_rule():
    report = scan_text(SPEC, options=Options(ignore=("SPV004",)))
    assert "SPV004" not in report.rule_ids()


def test_min_severity_hides_lower_findings():
    report = scan_text(SPEC, options=Options(min_severity="critical"))
    assert set(report.rule_ids()) <= {"SPV002", "SPV004", "SPV020"}


def test_inline_ignore_suppresses_one_line():
    text = (
        "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    get:  # specvet: ignore[SPV004]\n"
        "      responses:\n        '200': {description: ok}\n"
    )
    assert "SPV004" not in scan_text(text, options=Options()).rule_ids()


def test_bare_inline_ignore_suppresses_everything_on_that_line():
    text = (
        "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    get:  # specvet: ignore\n"
        "      responses:\n        '200': {description: ok}\n"
    )
    assert "SPV004" not in scan_text(text, options=Options()).rule_ids()


def test_inline_ignore_can_be_turned_off():
    text = (
        "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    get:  # specvet: ignore[SPV004]\n"
        "      responses:\n        '200': {description: ok}\n"
    )
    assert "SPV004" in scan_text(text, options=Options(respect_inline_ignores=False)).rule_ids()


def test_exit_code_is_one_when_a_finding_is_at_or_above_the_threshold():
    report = scan_text(SPEC, options=Options())
    assert exit_code(report, "high") == EXIT_FINDINGS
    assert exit_code(report, "critical") == EXIT_FINDINGS


def test_exit_code_is_zero_when_everything_is_below_the_threshold():
    report = scan_text(SPEC, options=Options(ignore=("SPV002", "SPV004")))
    assert exit_code(report, "critical") == EXIT_OK


def test_fail_on_none_always_passes():
    report = scan_text(SPEC, options=Options())
    assert exit_code(report, "none") == EXIT_OK


def test_an_unknown_threshold_is_a_usage_error():
    assert exit_code(scan_text(SPEC, options=Options()), "catastrophic") == EXIT_USAGE


def test_risk_score_is_capped_at_one_hundred():
    from specvet.demo import scan_demo

    assert scan_demo().risk_score() == 100


def test_report_counts_every_severity_bucket():
    counts = scan_text(SPEC, options=Options()).counts()
    assert set(counts) == {"critical", "high", "medium", "low", "info"}


def test_operations_from_both_formats_end_up_in_one_report(tmp_path):
    report = scan_path(str(_tree(tmp_path)), options=Options())
    assert report.operation_count >= 1
    assert os.path.isfile(report.path)
