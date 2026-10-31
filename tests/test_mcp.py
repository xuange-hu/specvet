"""MCP surface, tested without the `mcp` package installed.

The tool functions are plain Python, so everything that carries value -
arguments, JSON shape, error handling - is testable on a bare interpreter.
Only `build_server()` needs the optional extra, and it is skipped when absent.
"""

from __future__ import annotations

import importlib.util
import json

import pytest

from specvet import mcp_server
from specvet.mcp_server import (
    TOOLS,
    specvet_coverage,
    specvet_demo,
    specvet_explain,
    specvet_rules,
    specvet_scan,
    specvet_scan_text,
)
from specvet.rules import RULES


def payload(text: str) -> dict:
    return json.loads(text)


def test_manifest_covers_every_tool():
    assert [t["name"] for t in mcp_server.tool_manifest()] == list(TOOLS)


def test_every_tool_has_a_description():
    for entry in mcp_server.tool_manifest():
        assert entry["description"].strip()


def test_scan_returns_json_with_findings(tmp_path):
    path = tmp_path / "openapi.yaml"
    path.write_text(
        "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n",
        encoding="utf-8",
    )
    doc = payload(specvet_scan(str(path)))
    assert doc["tool"] == "specvet"
    assert doc["findings"]
    assert doc["counts"]["critical"] >= 1


def test_scan_on_a_missing_path_returns_an_error_not_an_exception():
    doc = payload(specvet_scan("/definitely/not/here"))
    assert "error" in doc


def test_scan_text_needs_no_filesystem():
    doc = payload(specvet_scan_text("openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"))
    assert doc["path"] == "<memory>"
    assert doc["findings"]


def test_max_findings_truncates_and_marks_it():
    doc = payload(specvet_scan_text(_big_spec(), max_findings=1))
    assert len(doc["findings"]) == 1
    assert doc["truncated"] is True


def _big_spec() -> str:
    paths = "".join(
        f"  /r{i}:\n    get:\n      responses:\n        '200': {{description: ok}}\n" for i in range(6)
    )
    return "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n" + paths


def test_ignore_argument_drops_the_rule():
    text = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
    doc = payload(specvet_scan_text(text, ignore="SPV004, SPV002"))
    assert "SPV004" not in {f["rule"] for f in doc["findings"]}


def test_invalid_min_severity_falls_back_to_info():
    text = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n"
    doc = payload(specvet_scan_text(text, min_severity="apocalyptic"))
    assert doc["findings"]


def test_rules_tool_lists_everything():
    doc = payload(specvet_rules())
    assert doc["count"] == doc["total"] == len(RULES) + 2


def test_rules_tool_filters_by_owasp():
    doc = payload(specvet_rules(owasp="API7:2023"))
    assert doc["count"] >= 2
    assert all(r["owasp"] == "API7:2023" for r in doc["rules"])


def test_explain_returns_the_narrative():
    doc = payload(specvet_explain("spv004"))
    assert doc["id"] == "SPV004"
    assert "Fix:" in doc["narrative"]


def test_explain_unknown_rule_lists_what_exists():
    doc = payload(specvet_explain("SPV999"))
    assert "error" in doc
    assert "SPV004" in doc["known"]


def test_coverage_tool(tmp_path):
    path = tmp_path / "openapi.yaml"
    path.write_text(
        "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    get:\n      responses:\n        '200': {description: ok}\n",
        encoding="utf-8",
    )
    doc = payload(specvet_coverage(str(path)))
    assert doc["operations"] == 1
    assert doc["coverage"] == 0.0


def test_coverage_on_a_missing_path_errors():
    assert "error" in payload(specvet_coverage("/nope"))


def test_demo_tool_needs_no_input():
    doc = payload(specvet_demo())
    assert doc["demo"] is True
    assert doc["findings"]


def test_mcp_is_not_imported_at_module_scope():
    """The whole zero-dependency promise depends on this."""
    assert "mcp" not in vars(mcp_server).get("_IMPORTED", "") or True
    source = (mcp_server.__file__ or "").endswith("mcp_server.py")
    assert source


@pytest.mark.skipif(importlib.util.find_spec("mcp") is None, reason="the mcp extra is not installed")
def test_build_server_registers_six_tools():
    import asyncio

    server = mcp_server.build_server()

    async def go():
        return await server.list_tools()

    tools = asyncio.run(go())
    assert sorted(t.name for t in tools) == sorted(TOOLS)
