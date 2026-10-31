"""The cross-endpoint pass: what one endpoint at a time cannot see."""

from __future__ import annotations

from specvet import graph
from specvet.analyze import Options, scan_text

HEAD = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\n"


def scan(body: str):
    return scan_text(HEAD + body, path="t.yaml", options=Options())


def test_an_unreferenced_scheme_is_reported():
    body = (
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    Unused: {type: http, scheme: bearer}\n"
    )
    assert "SPV005" in scan(body).rule_ids()


def test_a_referenced_scheme_is_not_reported():
    body = (
        "security:\n  - Bearer: []\n"
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    Bearer: {type: http, scheme: bearer, bearerFormat: JWT}\n"
    )
    assert "SPV005" not in scan(body).rule_ids()


def test_a_scheme_referenced_by_one_operation_only_is_used():
    body = (
        "paths:\n  /x:\n    get:\n      security:\n        - Bearer: []\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    Bearer: {type: http, scheme: bearer, bearerFormat: JWT}\n"
    )
    assert "SPV005" not in scan(body).rule_ids()


def test_mixed_authorization_within_one_path_is_reported():
    body = (
        "paths:\n  /x:\n    get:\n      security:\n        - Bearer: []\n      responses:\n        '200': {description: ok}\n"
        "    delete:\n      responses:\n        '204': {description: gone}\n"
        "components:\n  securitySchemes:\n    Bearer: {type: http, scheme: bearer, bearerFormat: JWT}\n"
    )
    report = scan(body)
    assert "SPV021" in report.rule_ids()
    detail = next(f.detail for f in report.findings if f.rule_id == "SPV021")
    assert "DELETE" in detail


def test_uniform_authorization_is_not_reported():
    body = (
        "security:\n  - Bearer: []\n"
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "    delete:\n      responses:\n        '204': {description: gone}\n"
        "components:\n  securitySchemes:\n    Bearer: {type: http, scheme: bearer, bearerFormat: JWT}\n"
    )
    assert "SPV021" not in scan(body).rule_ids()


def test_explicitly_public_alongside_protected_is_a_decision_not_an_omission():
    body = (
        "paths:\n  /x:\n    get:\n      security:\n        - Bearer: []\n      responses:\n        '200': {description: ok}\n"
        "    post:\n      security: []\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    Bearer: {type: http, scheme: bearer, bearerFormat: JWT}\n"
    )
    assert "SPV021" not in scan(body).rule_ids()


def test_a_single_operation_path_is_never_inconsistent():
    body = "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
    assert "SPV021" not in scan(body).rule_ids()


def test_coverage_counts():
    body = (
        "paths:\n  /a:\n    get:\n      security:\n        - Bearer: []\n      responses:\n        '200': {description: ok}\n"
        "  /b:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "  /c:\n    get:\n      security: []\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    Bearer: {type: http, scheme: bearer, bearerFormat: JWT}\n"
    )
    cover = graph.coverage(scan(body).document)
    assert cover["operations"] == 3
    assert cover["authenticated"] == 1
    assert cover["explicitly_public"] == 1
    assert cover["undeclared"] == 1


def test_coverage_is_one_hundred_percent_with_no_operations():
    assert graph.coverage(scan("paths: {}\n").document)["coverage"] == 100.0
