"""Packaging contract: the console script must not import an optional extra.

CI installs `.[all]`, so a missing base dependency is invisible there and
only shows up as ModuleNotFoundError for the user who runs `specvet`. These
tests assert the contract statically instead.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python <= 3.10: tomllib landed in 3.11
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _pytoml as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
SRC = ROOT / "src" / "specvet"
SRCROOT = ROOT / "src"


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _scripts() -> dict[str, str]:
    return _pyproject()["project"]["scripts"]


def _target_module(script: str) -> str:
    return script.split(":", 1)[0]


def _collect_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            out.add(node.module.split(".")[0])
    return out


def test_console_scripts_exist():
    scripts = _scripts()
    assert "specvet" in scripts
    assert "specvet-mcp" in scripts


def _target_path(script: str) -> Path:
    """`specvet.cli:main` -> src/specvet/cli.py (dotted module, resolved from src/)."""
    return SRCROOT / Path(_target_module(script).replace(".", "/") + ".py")


def test_every_console_script_target_module_resolves():
    for name, target in _scripts().items():
        path = _target_path(target)
        assert path.exists(), f"{name} -> {path} is missing"


def test_stdlib_only_imports_in_cli_entrypoint():
    """`specvet` must run with zero third-party packages installed.

    The allow-list used to be hard-coded, so adding a stdlib module that was
    not on it (``contextlib``, when the Windows UTF-8 guard landed) turned this
    into a false failure that looked like a real dependency leak. Compare
    against the interpreter's own stdlib inventory instead: that is the actual
    claim being made.
    """
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    imports = _collect_imports(SRC / "cli.py")
    third_party = {i for i in imports if i not in stdlib and i != "specvet"}
    assert third_party == set(), f"cli.py pulls in {third_party}"


def test_mcp_server_imports_mcp_only_inside_build():
    """The optional dependency must be imported lazily, not at module scope."""
    src = (SRC / "mcp_server.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    top_level: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_level.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            top_level.add(node.module.split(".")[0])
    assert "mcp" not in top_level
    assert "def build_server" in src


def test_mcp_extra_requires_mcp_package():
    extras = _pyproject()["project"].get("optional-dependencies", {})
    assert "mcp" in extras
    joined = " ".join(extras["mcp"])
    assert any(re.split(r"[<>=!~;\[\s]", d)[0] == "mcp" for d in extras["mcp"]), joined


def test_mcp_version_pinned_below_2():
    """mcp 2.x renamed FastMCP to MCPServer; the server is written for 1.x."""
    extras = _pyproject()["project"]["optional-dependencies"]["mcp"]
    assert any("mcp>=1" in d and "<2" in d for d in extras), extras


def test_base_dependencies_are_empty():
    deps = _pyproject()["project"].get("dependencies", [])
    assert deps == [], f"core must stay zero-dependency, got {deps}"


def test_version_matches_init():
    project = _pyproject()["project"]
    init = (SRC / "__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{project["version"]}"' in init


def _optional_test_deps_present() -> bool:
    """The badge number is only meaningful where every test can run.

    Several test modules need optional packages (`mcp` for the server tests,
    PyYAML for the parser differential) and skip themselves when those are
    absent. The base CI job installs neither, so it collects ~155 items while a
    full environment collects 172: comparing the badge there failed for a week
    with no actual drift. Enforcement moved to the badge job, which installs
    `.[mcp]` + PyYAML.
    """
    import importlib.util

    return all(importlib.util.find_spec(name) is not None for name in ("mcp", "yaml"))


@pytest.mark.skipif(
    not _optional_test_deps_present(),
    reason="badge count is validated where the optional test deps are installed",
)
def test_readme_test_count_matches_collection():
    """Reads the badge in README.md; keeps the headline number honest."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"tests-(\d+)%20passing", readme)
    assert m, "README is missing the tests badge"
    declared = int(m.group(1))
    collected = _collected_tests()
    assert declared == collected, f"README says {declared}, pytest collects {collected}"


def _collected_tests() -> int:
    """Ask pytest how many items exist, without running them.

    Counting `def test_*` in the AST is not enough: parametrized tests expand
    into several items, so the naive count drifts from the reported number.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-o", "addopts=", str(ROOT / "tests")],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    # -o addopts= protects against a project-level addopts="-q": -qq drops the
    # "N tests collected" summary and this silently fell back to skipping.
    m = re.search(r"(\d+) tests? collected", proc.stdout)
    if m is None:
        pytest.skip(f"could not collect tests: {proc.stdout[-200:]} {proc.stderr[-200:]}")
    return int(m.group(1))


def test_src_layout_is_used():
    cfg = _pyproject()
    assert cfg["build-system"]["requires"], "build backend must be declared"
    wheel = cfg["tool"].get("setuptools", {}).get("package-dir", {})
    assert wheel.get("") == "src", cfg["tool"].get("setuptools")
