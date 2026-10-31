"""SARIF must be valid enough for `github/codeql-action/upload-sarif`."""

from __future__ import annotations

import json

from specvet.analyze import Options, scan_text
from specvet.demo import scan_demo
from specvet.sarif import dumps

SPEC = """\
openapi: 3.0.3
info: {title: t, version: '1'}
paths:
  /x:
    get:
      responses:
        '200': {description: ok}
"""


def payload() -> dict:
    return json.loads(dumps(scan_text(SPEC, options=Options())))


def test_schema_and_version():
    doc = payload()
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")


def test_one_run_with_a_named_driver():
    run = payload()["runs"][0]
    assert run["tool"]["driver"]["name"] == "specvet"
    assert run["tool"]["driver"]["informationUri"]


def test_rule_index_matches_the_rule_id_in_every_result():
    run = payload()["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_rules_are_deduplicated():
    rules = payload()["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))


def test_every_rule_carries_security_severity_and_an_owasp_tag():
    rules = payload()["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        assert float(rule["properties"]["security-severity"]) >= 1.0
        assert rule["properties"]["owasp-api-top10"].startswith("API")


def test_results_have_a_start_line_of_at_least_one():
    for result in payload()["runs"][0]["results"]:
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_results_keep_the_json_pointer_as_a_logical_location():
    for result in payload()["runs"][0]["results"]:
        assert result["locations"][0]["logicalLocations"][0]["name"].startswith("/")


def test_windows_paths_are_emitted_with_forward_slashes():
    report = scan_text(SPEC, path="docs\\api\\openapi.yaml", options=Options())
    out = dumps(report)
    assert "docs/api/openapi.yaml" in out
    assert "\\\\" not in out.split('"uri": ')[1].split(",")[0]


def test_demo_report_produces_valid_sarif():
    doc = json.loads(dumps(scan_demo()))
    assert doc["runs"][0]["results"]
    assert doc["runs"][0]["properties"]["specvet.operations"] >= 1
