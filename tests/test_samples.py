"""Every rule has a spec that triggers it.

A rule library rots silently: nobody notices when a refactor makes a check
unreachable, because the suite still passes. This module is the antidote -
one minimal document per rule, and an assertion that the rule fires under
default options. If a rule cannot be triggered, it does not exist.
"""

from __future__ import annotations

import pytest

from specvet.analyze import Options, scan_text
from specvet.graph import CROSS_RULES
from specvet.rules import RULES

HEAD = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\n"


def _spec(body: str) -> str:
    return HEAD + body


SAMPLES: dict[str, str] = {
    "SPV001": _spec(
        "paths:\n  /x/{id}:\n    put:\n      responses:\n        '200': {description: ok}\n"
    ),
    "SPV002": _spec("paths:\n  /x/{id}:\n    get:\n      responses:\n        '200': {description: ok}\n"),
    "SPV003": _spec(
        "security:\n  - Bearer: []\npaths:\n  /x/{id}:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    Bearer: {type: http, scheme: bearer, bearerFormat: JWT}\n"
    ),
    "SPV004": _spec("paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"),
    "SPV005": _spec(
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    Unused: {type: http, scheme: bearer}\n"
    ),
    "SPV006": _spec(
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    Key: {type: apiKey, in: query, name: k}\n"
    ),
    "SPV007": _spec(
        "servers: [{url: 'http://api.example.com'}]\n"
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    Basic: {type: http, scheme: basic}\n"
    ),
    "SPV008": _spec(
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    O: {type: oauth2, flows: {implicit: {authorizationUrl: 'https://e', scopes: {read: r}}}}\n"
    ),
    "SPV009": _spec(
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    O: {type: oauth2, flows: {authorizationCode: {authorizationUrl: 'https://e', tokenUrl: 'https://t', scopes: {}}}}\n"
    ),
    "SPV010": _spec(
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    B: {type: http, scheme: bearer}\n"
    ),
    "SPV011": _spec("paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"),
    "SPV012": _spec(
        "paths:\n  /x:\n    get:\n      responses:\n        '200':\n          description: ok\n"
        "          content:\n            application/json:\n              schema: {type: object, properties: {password: {type: string}}}\n"
    ),
    "SPV013": _spec(
        "paths:\n  /x:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: {type: object, properties: {a: {type: string}}}\n"
        "      responses:\n        '200': {description: ok}\n"
    ),
    "SPV014": _spec(
        "paths:\n  /x:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/O'}\n"
        "      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: {$ref: '#/components/schemas/O'}\n"
        "components:\n  schemas:\n    O: {type: object, additionalProperties: false}\n"
    ),
    "SPV015": _spec(
        "paths:\n  /x:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: {type: object, properties: {tags: {type: array, items: {type: string}}}}\n"
        "      responses:\n        '200': {description: ok}\n"
    ),
    "SPV016": _spec(
        "paths:\n  /x:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: {type: object, properties: {name: {type: string}}}\n"
        "      responses:\n        '200': {description: ok}\n"
    ),
    "SPV017": _spec(
        "paths:\n  /x:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: {type: object, properties: {qty: {type: integer}}}\n"
        "      responses:\n        '200': {description: ok}\n"
    ),
    "SPV018": _spec("paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"),
    "SPV019": _spec(
        "paths:\n  /x:\n    get:\n      parameters:\n        - {name: limit, in: query, schema: {type: integer}}\n"
        "      responses:\n        '200': {description: ok}\n"
    ),
    "SPV020": _spec("paths:\n  /admin/x:\n    get:\n      responses:\n        '200': {description: ok}\n"),
    "SPV021": _spec(
        "paths:\n  /x:\n    get:\n      security:\n        - B: []\n      responses:\n        '200': {description: ok}\n"
        "    post:\n      responses:\n        '200': {description: ok}\n"
        "components:\n  securitySchemes:\n    B: {type: http, scheme: bearer}\n"
    ),
    "SPV022": _spec("paths:\n  /x:\n    post:\n      responses:\n        '200': {description: ok}\n"),
    "SPV023": _spec(
        "paths:\n  /x:\n    post:\n      security: []\n      responses:\n        '200': {description: ok}\n"
    ),
    "SPV024": _spec(
        "paths:\n  /payments/transfer:\n    post:\n      responses:\n        '200': {description: ok}\n"
    ),
    "SPV025": _spec(
        "paths:\n  /payments/transfer:\n    post:\n      responses:\n        '200': {description: ok}\n"
    ),
    "SPV026": _spec(
        "paths:\n  /x:\n    post:\n      parameters:\n        - {name: callback_url, in: query, schema: {type: string}}\n"
        "      responses:\n        '200': {description: ok}\n"
    ),
    "SPV027": _spec(
        "paths:\n  /x:\n    post:\n      parameters:\n        - {name: callback_url, in: query, schema: {type: string}}\n"
        "      responses:\n        '200': {description: ok}\n"
    ),
    "SPV028": _spec(
        "servers: [{url: 'http://api.example.com'}]\npaths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
    ),
    "SPV029": _spec("paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"),
    "SPV030": _spec("paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"),
    "SPV031": "swagger: '2.0'\ninfo: {title: t, version: '1'}\nhost: e.com\npaths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n",
    "SPV032": _spec("paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"),
    "SPV033": _spec(
        "servers:\n  - url: 'https://{region}.example.com'\n    variables:\n      region: {enum: [eu]}\n"
        "paths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
    ),
    "SPV034": _spec(
        "paths:\n  /x:\n    get:\n      deprecated: true\n      responses:\n        '200': {description: ok}\n"
    ),
    "SPV035": "openapi: 3.0.3\ninfo: {title: t}\npaths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n",
    "SPV036": _spec(
        "paths:\n  /x:\n    get:\n      responses:\n        '200':\n          description: ok\n"
        "          content:\n            application/json:\n              schema: {$ref: 'https://e.example/s.json'}\n"
    ),
}

ALL_RULES = {**RULES, **CROSS_RULES}


def test_every_rule_has_a_sample():
    missing = sorted(set(ALL_RULES) - set(SAMPLES))
    assert missing == [], f"rules without a sample: {missing}"


def test_no_sample_targets_an_unknown_rule():
    assert sorted(set(SAMPLES) - set(ALL_RULES)) == []


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
def test_sample_triggers_its_rule(rule_id):
    report = scan_text(SAMPLES[rule_id], path=f"{rule_id}.yaml", options=Options())
    assert rule_id in report.rule_ids(), f"{rule_id} did not fire on its own sample"


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
def test_sample_is_reproducible(rule_id):
    """The same input must give the same finding set twice - no hidden state."""
    a = scan_text(SAMPLES[rule_id], path=f"{rule_id}.yaml", options=Options()).rule_ids()
    b = scan_text(SAMPLES[rule_id], path=f"{rule_id}.yaml", options=Options()).rule_ids()
    assert a == b
