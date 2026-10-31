"""Rule behaviour, including the cases that must *not* fire.

A rule that never fires is invisible; a rule that fires on everything is
ignored. The negative cases below are what keeps this rule set usable in a
pull-request gate.
"""

from __future__ import annotations

from specvet.analyze import Options, scan_text
from specvet.rules import RULES, resolve_ref

HEAD = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\n"


def scan(body: str):
    return scan_text(HEAD + body, path="t.yaml", options=Options())


def ids(body: str) -> set[str]:
    return set(scan(body).rule_ids())


def test_rule_table_is_complete_and_well_formed():
    assert len(RULES) + 2 == 36
    for rule_id, rule in RULES.items():
        assert rule.id == rule_id
        assert rule.severity in ("critical", "high", "medium", "low", "info")
        assert rule.owasp.startswith("API") and rule.owasp.endswith(":2023")
        assert rule.summary and rule.fix and rule.title


def test_every_owasp_category_from_one_to_ten_is_covered():
    from specvet.graph import CROSS_RULES

    all_rules = {**RULES, **CROSS_RULES}
    covered = {r.owasp for r in all_rules.values()}
    assert covered == {f"API{i}:2023" for i in range(1, 11)}, sorted(covered)


def test_sensitive_property_detection_is_case_and_separator_insensitive():
    body = (
        "paths:\n  /x:\n    get:\n      responses:\n        '200':\n          description: ok\n"
        "          content:\n            application/json:\n"
        "              schema: {type: object, properties: {CreditCard: {type: string}}}\n"
    )
    assert "SPV012" in ids(body)


def test_a_harmless_property_does_not_trigger_sensitive_exposure():
    body = (
        "paths:\n  /x:\n    get:\n      responses:\n        '200':\n          description: ok\n"
        "          content:\n            application/json:\n"
        "              schema: {type: object, properties: {nickname: {type: string}}}\n"
    )
    assert "SPV012" not in ids(body)


def test_additional_properties_false_silences_the_mass_assignment_rule():
    ok = (
        "paths:\n  /x:\n    post:\n      requestBody:\n        content:\n          application/json:\n"
        "            schema: {type: object, additionalProperties: false}\n      responses:\n        '200': {description: ok}\n"
    )
    assert "SPV013" not in ids(ok)


def test_declaring_403_silences_the_object_authorization_rule():
    ok = (
        "paths:\n  /x/{id}:\n    put:\n      responses:\n        '200': {description: ok}\n"
        "        '403': {description: no}\n"
    )
    assert "SPV001" not in ids(ok)


def test_bounded_numeric_property_is_accepted():
    ok = (
        "paths:\n  /x:\n    post:\n      requestBody:\n        content:\n          application/json:\n"
        "            schema: {type: object, properties: {qty: {type: integer, minimum: 1, maximum: 10}}}\n"
        "      responses:\n        '200': {description: ok}\n"
    )
    assert "SPV017" not in ids(ok)


def test_enum_string_needs_no_max_length():
    ok = (
        "paths:\n  /x:\n    post:\n      requestBody:\n        content:\n          application/json:\n"
        "            schema: {type: object, properties: {kind: {type: string, enum: [a, b]}}}\n"
        "      responses:\n        '200': {description: ok}\n"
    )
    assert "SPV016" not in ids(ok)


def test_rate_limit_response_silences_the_resource_rule():
    ok = (
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "        '429': {description: slow down}\n"
    )
    assert "SPV018" not in ids(ok)


def test_a_uri_formatted_parameter_is_constrained_enough():
    ok = (
        "paths:\n  /x:\n    post:\n      parameters:\n"
        "        - {name: callback_url, in: query, schema: {type: string, format: uri}}\n"
        "      responses:\n        '200': {description: ok}\n"
    )
    assert "SPV026" not in ids(ok)


def test_localhost_http_server_is_not_flagged():
    ok = (
        "servers: [{url: 'http://localhost:8080'}]\n"
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
    )
    assert "SPV028" not in ids(ok)


def test_https_server_is_not_flagged():
    ok = "servers: [{url: 'https://api.example.com'}]\npaths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
    assert "SPV028" not in ids(ok)


def test_error_responses_silence_the_misconfiguration_rule():
    ok = (
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "        '400': {description: bad}\n"
    )
    assert "SPV029" not in ids(ok)


def test_default_response_also_counts_as_an_error_response():
    ok = (
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "        default: {description: err}\n"
    )
    assert "SPV029" not in ids(ok)


def test_idempotency_key_silences_the_business_flow_rule():
    ok = (
        "paths:\n  /payments/transfer:\n    post:\n      parameters:\n"
        "        - {name: Idempotency-Key, in: header, schema: {type: string}}\n"
        "      responses:\n        '200': {description: ok}\n"
    )
    assert "SPV025" not in ids(ok)


def test_a_clean_minimal_spec_has_no_authentication_findings():
    body = (
        "servers: [{url: 'https://api.example.com'}]\n"
        "security:\n  - Bearer: []\n"
        "paths:\n  /x:\n    get:\n      responses:\n        '200':\n          description: ok\n"
        "          content:\n            application/json:\n              schema: {type: object, additionalProperties: false}\n"
        "        '404': {description: none}\n        '429': {description: slow}\n"
        "components:\n  securitySchemes:\n    Bearer: {type: http, scheme: bearer, bearerFormat: JWT}\n"
    )
    fired = ids(body)
    assert not fired & {"SPV002", "SPV004", "SPV011", "SPV020", "SPV022", "SPV005"}


def test_resolve_ref_follows_local_pointers():
    body = (
        "paths:\n  /x:\n    get:\n      responses:\n        '200':\n          description: ok\n"
        "          content:\n            application/json:\n              schema: {$ref: '#/components/schemas/O'}\n"
        "components:\n  schemas:\n    O: {type: object, properties: {password: {type: string}}}\n"
    )
    report = scan(body)
    assert "SPV012" in report.rule_ids()
    doc = report.document
    node = doc.root["paths"]["/x"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert "properties" in resolve_ref(doc, node)


def test_resolve_ref_does_not_recurse_forever_on_a_self_reference():
    body = (
        "paths:\n  /x:\n    get:\n      responses:\n        '200':\n          description: ok\n"
        "          content:\n            application/json:\n              schema: {$ref: '#/components/schemas/O'}\n"
        "components:\n  schemas:\n    O: {type: object, properties: {child: {$ref: '#/components/schemas/O'}}}\n"
    )
    scan(body)  # must not raise or hang


def test_findings_carry_a_pointer_and_a_line():
    body = "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
    report = scan(body)
    target = next(f for f in report.findings if f.rule_id == "SPV004")
    assert target.pointer == "/paths/~1x/get"
    assert target.line == 5


def test_deduplication_keeps_one_finding_per_rule_pointer_detail():
    body = "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
    report = scan(body)
    keys = [(f.rule_id, f.pointer) for f in report.findings]
    assert len(keys) == len(set(keys))
