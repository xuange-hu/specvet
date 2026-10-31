"""The JSON reader is differential-tested against the stdlib.

`json.loads` is the reference: for anything it accepts, this reader must
produce an equal structure. The only thing added on top is position, and
position is the only reason the module exists.
"""

from __future__ import annotations

import json

import pytest

from specvet.jsonloc import JsonError, loads

CASES = [
    "{}",
    "[]",
    "1",
    "-0",
    "1.5e10",
    '"plain"',
    '"tab\\there"',
    '{"a": 1, "b": [1, 2, {"c": null}]}',
    '{"a": true, "b": false, "c": null}',
    '{"nested": {"deep": {"deeper": [1, [2, [3]]]}}}',
    '{"unicode": "\\u00e9\\u4e2d\\u6587"}',
    '{"emoji": "\\ud83d\\ude00"}',
    '{"empty_string": "", "zero": 0, "negative": -12.5e-3}',
    '{\n  "multiline": true,\n  "arr": [\n    1,\n    2\n  ]\n}',
    '{"escapes": "quote\\" back\\\\ slash\\/ bell\\b form\\f nl\\n cr\\r tab\\t"}',
]


@pytest.mark.parametrize("text", CASES)
def test_matches_stdlib(text):
    assert loads(text) == json.loads(text)


@pytest.mark.parametrize("text", CASES)
def test_round_trips_through_stdlib(text):
    assert json.loads(json.dumps(loads(text), ensure_ascii=False)) == json.loads(text)


def test_object_key_lines():
    text = '{\n  "one": 1,\n  "two": 2\n}'
    node = loads(text)
    assert node.klines["one"] == 2
    assert node.klines["two"] == 3


def test_array_item_lines():
    text = '[\n  1,\n  2,\n  3\n]'
    node = loads(text)
    assert [node.ilines[i] for i in range(3)] == [2, 3, 4]


def test_scalar_lines():
    text = '{\n  "a": "x",\n  "b": "y"\n}'
    node = loads(text)
    assert node["a"].line == 2
    assert node["b"].line == 3


def test_duplicate_keys_keep_the_last_value():
    assert loads('{"a": 1, "a": 2}') == {"a": 2}


@pytest.mark.parametrize(
    "text",
    [
        "{",
        '{"a": }',
        '{"a" 1}',
        "[1,]",
        '{"a": 1',
        '"unterminated',
        "{a: 1}",
        "tru",
        '{"a": 1} extra',
        '{"a": "\\q"}',
        '{"a": "\\u12"}',
    ],
)
def test_malformed_input_raises(text):
    with pytest.raises(JsonError):
        loads(text)


def test_empty_text_is_an_empty_mapping():
    assert loads("   ") == {}


def test_surrogate_pair_decodes_to_one_codepoint():
    assert loads('{"e": "\\ud83d\\ude00"}')["e"] == "\U0001f600"


def test_crlf_is_normalised_before_line_numbering():
    node = loads('{\r\n  "a": 1\r\n}')
    assert node.klines["a"] == 2
