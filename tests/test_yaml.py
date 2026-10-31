"""The YAML reader is the foundation — it gets the most tests."""

from __future__ import annotations

import pytest

from specvet.yamlscan import L, M, S, YamlError, load_all, loads


def test_scalars_and_types():
    d = loads("a: 1\nb: 2.5\nc: true\nd: false\ne: ~\nf: 'x'\ng: \"y\"\n")
    assert d["a"] == 1 and isinstance(d["a"], int)
    assert d["b"] == 2.5
    assert d["c"] is True and d["d"] is False
    assert d["e"] is None
    assert d["f"] == "x" and d["g"] == "y"


def test_line_numbers_survive():
    d = loads("name: CI\non:\n  push:\n    branches: [main]\n")
    assert d.klines["name"] == 1
    assert d["on"].klines["push"] == 3


def test_scalar_line_number():
    d = loads("a: 1\nrun: echo hi\n")
    assert d["run"].line == 2


def test_nested_sequence_of_maps():
    y = "jobs:\n  build:\n    steps:\n      - name: A\n        run: echo\n      - name: B\n        uses: x@v1\n"
    steps = loads(y)["jobs"]["build"]["steps"]
    assert isinstance(steps, L) and len(steps) == 2
    assert steps[0]["name"] == "A"
    assert steps[0]["run"] == "echo"
    assert steps[1]["uses"] == "x@v1"


def test_sequence_line_numbers():
    y = "steps:\n  - name: A\n    run: echo\n  - name: B\n"
    steps = loads(y)["steps"]
    assert steps.ilines[0] == 2
    assert steps.ilines[1] == 4


def test_block_scalar_keeps_newlines():
    y = "run: |\n  echo one\n  echo two\n"
    assert loads(y)["run"] == "echo one\necho two\n"


def test_block_scalar_strip_chomp():
    y = "run: |-\n  echo one\n"
    assert loads(y)["run"] == "echo one"


def test_folded_scalar():
    y = "run: >\n  one\n  two\n"
    assert loads(y)["run"] == "one two\n"


def test_block_scalar_preserves_internal_blank_line():
    y = "run: |\n  a\n\n  b\n"
    assert loads(y)["run"] == "a\n\nb\n"


def test_flow_sequence():
    assert list(loads("on: [push, pull_request]")["on"]) == ["push", "pull_request"]


def test_flow_map():
    d = loads("with: {a: 1, b: two}")
    assert d["with"]["a"] == 1 and d["with"]["b"] == "two"


def test_flow_map_with_colon_in_value():
    d = loads('env: {URL: "https://x.dev:443/a"}')
    assert d["env"]["URL"] == "https://x.dev:443/a"


def test_quoted_key_with_colon():
    d = loads('"on:": 1')
    assert d["on:"] == 1


def test_value_containing_colon_is_not_a_key():
    d = loads("run: echo a:b\n")
    assert d["run"] == "echo a:b"


def test_comments_and_blanks_ignored():
    d = loads("# top\na: 1\n\n   # indented comment\nb: 2\n")
    assert list(d.keys()) == ["a", "b"]


def test_empty_document_returns_mapping():
    assert loads("") == {}


def test_document_markers():
    assert loads("---\na: 1\n")["a"] == 1


def test_double_quote_escapes():
    assert loads(r'a: "line\nnext"')["a"] == "line\nnext"
    assert loads(r'a: "tab\there"')["a"] == "tab\there"


def test_single_quote_doubling():
    assert loads("a: 'it''s'")["a"] == "it's"


def test_deep_nesting():
    y = "a:\n  b:\n    c:\n      - d: 1\n        e: 2\n"
    node = loads(y)["a"]["b"]["c"][0]
    assert node["d"] == 1 and node["e"] == 2


def test_crlf_is_normalised():
    assert loads("a: 1\r\nb: 2\r\n")["b"] == 2


def test_tabs_are_expanded_not_fatal():
    assert loads("a:\n\tb: 1\n")["a"]["b"] == 1


def test_empty_key_value_is_none():
    assert loads("a:\nb: 1\n")["a"] is None


def test_malformed_line_raises():
    # a bare scalar at mapping indent is not a key and is not recoverable
    with pytest.raises(YamlError):
        loads("a: 1\nb: 2\noops\n")


def test_load_all_multiple_documents():
    docs = load_all("a: 1\n---\nb: 2\n")
    assert len(docs) == 2 and docs[1]["b"] == 2


def test_types_are_exported():
    assert issubclass(S, str) and issubclass(M, dict) and issubclass(L, list)
