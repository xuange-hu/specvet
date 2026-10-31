"""The shipped demo is the product's first impression: it must stay honest."""

from __future__ import annotations

import json

from specvet import demo
from specvet.analyze import Options, scan_text
from specvet.graph import CROSS_RULES
from specvet.rules import RULES

ALL_RULES = {**RULES, **CROSS_RULES}


def test_demo_spec_is_valid_openapi():
    doc = scan_text(demo.SPEC_TEXT, path="demo.yaml", options=Options()).document
    assert doc.version.startswith("3.")
    assert doc.operations


def test_demo_swagger_file_is_recognised_as_swagger():
    doc = scan_text(demo.SWAGGER2_TEXT, path="legacy.yaml", options=Options()).document
    assert doc.is_swagger2 is True


def test_between_them_the_demo_files_trigger_every_rule():
    fired = set(scan_demo_ids())
    assert fired == set(ALL_RULES), sorted(set(ALL_RULES) - fired)


def scan_demo_ids() -> list[str]:
    report = demo.scan_demo()
    return report.rule_ids()


def test_demo_scan_reports_both_files():
    assert demo.scan_demo().scanned_files == ["demo/openapi.yaml", "demo/swagger2.yaml"]


def test_demo_has_findings_in_more_than_one_severity():
    counts = demo.scan_demo().counts()
    assert counts["critical"] and counts["high"] and counts["medium"] and counts["low"]


def test_demo_covers_every_owasp_category():
    doc = json.loads(_json())
    owasp = {entry["id"] for entry in doc["owasp"]}
    assert owasp == {f"API{i}:2023" for i in range(1, 11)}


def _json() -> str:
    from specvet.render import json_text

    return json_text(demo.scan_demo())


def test_demo_text_is_not_empty_and_has_lines():
    from specvet.render import text

    out = text(demo.scan_demo())
    assert "SPV001" in out
    assert "line " in out


def test_demo_spec_has_no_trailing_whitespace_that_breaks_yaml():
    for line in demo.SPEC_TEXT.splitlines():
        assert line == line.rstrip() or line.strip().startswith("#")
