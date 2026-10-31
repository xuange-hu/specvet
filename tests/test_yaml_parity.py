"""Differential test against PyYAML, when it happens to be installed.

PyYAML is NOT a dependency of specvet (that is the whole point), so this module
skips when it is missing. Where it is present, it is the strongest available
check that the hand-written reader is actually correct rather than merely
plausible — it caught the missing inline-comment strip.
"""

from __future__ import annotations

import pytest

from specvet.yamlscan import loads

yaml = pytest.importorskip("yaml", reason="PyYAML not installed (it is not a dependency)")


def _norm(obj):
    """Strip specvet's line-number wrappers and undo YAML 1.1's 'on' -> True."""
    if isinstance(obj, dict):
        return {("on" if k is True else str(k)): _norm(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_norm(v) for v in obj]
    if isinstance(obj, bool) or obj is None or isinstance(obj, (int, float)):
        return obj
    return str(obj)


CASES = {
    "scalars": "a: 1\nb: two\nc: true\nd: ~\n",
    "nested": "a:\n  b:\n    c: 1\n",
    "seq_of_maps": "steps:\n  - name: A\n    run: x\n  - name: B\n",
    "block_scalar": "run: |\n  echo 1\n  echo 2\n",
    "flow": "on: [push, pr]\nwith: {a: 1}\n",
    "quotes": 'a: "x # not a comment"\nb: \'it\'\'s\'\n',
    "inline_comment": "a: 1 # note\nb: two   # another\n",
    "comment_in_quotes": 'run: echo "# hash"\n',
    "empty_values": "a:\nb: 1\nc: {}\nd: []\n",
    "job_shape": (
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5  # minutes\n"
        "    permissions:\n      id-token: write   # required for OIDC\n"
        "    steps:\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"
    ),
    "matrix": "strategy:\n  matrix:\n    python-version: ['3.10', '3.11']\n",
    "multiline_run": "steps:\n  - run: |\n      set -e\n      pytest -q\n",
    "on_block": "on:\n  push:\n    branches: [main]\n  workflow_dispatch:\n    inputs:\n      name:\n        type: string\n",
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_matches_pyyaml(name):
    text = CASES[name]
    assert _norm(yaml.safe_load(text)) == _norm(loads(text)), name


def test_inline_comment_is_stripped():
    """Regression: `key: value  # note` used to keep the whole tail."""
    assert loads("permissions:\n  id-token: write   # required\n")["permissions"]["id-token"] == "write"


def test_hash_inside_quotes_is_kept():
    assert loads('run: echo "# nope"')["run"] == 'echo "# nope"'


def test_on_key_stays_a_string():
    """YAML 1.1 turns `on` into True; a workflow tool needs the string."""
    assert "on" in loads("on: push\n")
    assert yaml.safe_load("on: push\n") == {True: "push"}  # the Norway problem


def test_line_numbers_still_work_after_normalisation():
    # ints/bools are returned as real ints/bools, so use a string scalar here
    d = loads("a: hello # c\nb: 2\n")
    assert d["a"] == "hello" and d["a"].line == 1
    assert d["b"] == 2
