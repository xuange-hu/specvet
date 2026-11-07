# specvet

[中文说明 / Chinese README](README_CN.md)

[![tests](https://img.shields.io/badge/tests-307%20passing-brightgreen)](https://github.com/xuange-hu/specvet/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/xuange-hu/specvet/blob/main/pyproject.toml)
[![rules](https://img.shields.io/badge/rules-36%20%2F%20OWASP%20API%20Top%2010-orange)](https://github.com/xuange-hu/specvet/blob/main/src/specvet/rules.py)
[![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/xuange-hu/specvet/blob/main/LICENSE)

**Deterministic security review for OpenAPI and Swagger documents.**

36 rules, each mapped to a category of the OWASP API Security Top 10 2023.
Zero dependencies. SARIF for pull-request gates. MCP server for agent
workflows.

Every finding carries three coordinates — a severity, a JSON Pointer that
survives a reflow of the file, and a line number you can jump to.

```console
$ specvet demo --scan

demo/openapi.yaml  OpenAPI 3.0.3 · 11 operations · 2 files
79 findings (10 critical, 24 high, 36 medium, 9 low) · risk 100/100 · auth coverage 18.2%

OWASP API Top 10 coverage
  API1:2023      5 finding(s), worst critical
  API2:2023     19 finding(s), worst critical
  API3:2023      5 finding(s), worst high
  API4:2023     16 finding(s), worst medium
  API5:2023      9 finding(s), worst critical
  API6:2023      2 finding(s), worst high
  API7:2023      2 finding(s), worst high
  API8:2023     18 finding(s), worst high
  API9:2023      2 finding(s), worst low
  API10:2023     1 finding(s), worst medium

CRITICAL  SPV002  Object path readable without authentication  [API1:2023]
           /paths/~1orders~1{orderId}/get
           line 49
           GET /orders/{orderId} takes ['orderId'] and has no security
           | get:
```

---

## Three steps

```bash
# 1. run it against a spec you already have
uvx --from specvet specvet scan openapi.yaml

# 2. or see what it does, with nothing to install and no file to find
uvx --from specvet specvet demo --scan

# 3. put it in CI and fail the build on high or worse (the default)
specvet scan . --format sarif -o specvet.sarif
```

Exit codes: `0` clean, `1` a finding at or above `--fail-on`, `2` usage error.

## Why another API linter

Spectral, Redocly and vacuum are excellent at *style*. They answer "is this
document well-formed and consistent?". They are also 3k★ JavaScript and Go
projects with plugin systems.

specvet answers a different question: **what can an attacker do with this
contract?** Three consequences follow from taking that seriously:

**1. Rules are organised by threat, not by document shape.**
Every rule is tagged `API1:2023` … `API10:2023`, so the output answers "where
are we exposed to broken object-level authorization?" rather than "you have 47
lint warnings". `specvet rules --owasp API5:2023` lists just those.

**2. The second pass reads relationships, not endpoints.**
Reading one operation at a time cannot see:

* `SPV021` — a path that authenticates `GET` but not `DELETE`. Each endpoint
  looks defensible alone; together they say the authorization is backwards.
* `SPV005` — a `securitySchemes` entry no `security` requirement references.
  The document *looks* authenticated and authenticates nothing.

**3. Absent is not the same as empty.**
`security:` missing is an omission. `security: []` is a decision. The loader
keeps them apart, so `SPV023` (an explicitly public write) is reported as a
decision while `SPV004` (no security anywhere) is reported as a hole.

## Rules

| Rule | Severity | OWASP | What it catches |
|---|---|---|---|
| SPV001 | high | API1 | Object write with no 403/404 — "not yours" and "not there" are indistinguishable |
| SPV002 | critical | API1 | Anonymous read on an identifier path: enumeration *is* the vulnerability |
| SPV003 | medium | API1 | No 404 declared for an identifier-addressed read |
| SPV004 | critical | API2 | Operation with no security requirement anywhere |
| SPV005 | high | API2 | Scheme defined but never required |
| SPV006 | high | API2 | API key in the query string (logs, history, `Referer`) |
| SPV007 | high | API2 | HTTP Basic over a plaintext server |
| SPV008 | high | API2 | OAuth2 implicit flow |
| SPV009 | medium | API2 | OAuth2 flow with no scopes |
| SPV010 | low | API2 | Bearer scheme with no `bearerFormat` |
| SPV011 | high | API2 | No top-level `security`: anonymous by default |
| SPV012 | high | API3 | Sensitive-looking property in a 2xx schema |
| SPV013 | medium | API3 | Request schema accepts unknown properties (mass assignment) |
| SPV014 | medium | API3 | One schema used for both request and 2xx response |
| SPV015 | medium | API4 | Array property with no `maxItems` |
| SPV016 | low | API4 | String property with no `maxLength` |
| SPV017 | medium | API4 | Numeric property with no bounds |
| SPV018 | medium | API4 | No `429` declared |
| SPV019 | low | API4 | Pagination parameter with no `maximum` |
| SPV020 | critical | API5 | Administrative path with no authentication |
| SPV021 | high | API5 | Authorization inconsistent within one path |
| SPV022 | high | API5 | Anonymous write operation |
| SPV023 | medium | API5 | Write operation explicitly public |
| SPV024 | high | API6 | Sensitive flow with neither auth nor `429` |
| SPV025 | medium | API6 | Money-moving POST with no idempotency key |
| SPV026 | high | API7 | Caller-supplied URL parameter with no format constraint |
| SPV027 | medium | API7 | URL-accepting endpoint with no authentication |
| SPV028 | high | API8 | `http://` server URL |
| SPV029 | medium | API8 | No error response declared |
| SPV030 | low | API8 | 2xx response with no content |
| SPV031 | medium | API8 | Swagger 2.0 — a retired format |
| SPV032 | high | API8 | No `securitySchemes` declared at all |
| SPV033 | low | API8 | Wildcard host or unresolved server template |
| SPV034 | low | API9 | Deprecated operation still published |
| SPV035 | low | API9 | No `info.version` |
| SPV036 | medium | API10 | `$ref` resolving to a remote URL |

`specvet explain SPV021` prints the reasoning and the fix for any of them.

## Usage

```bash
specvet scan openapi.yaml                     # text report
specvet scan ./specs --format json            # walk a directory
specvet scan openapi.yaml --fail-on critical  # only block on the worst
specvet scan openapi.yaml --ignore SPV018     # accept a risk, explicitly
specvet rules --owasp API4:2023
specvet coverage openapi.yaml                 # what share of ops are authenticated
specvet demo > openapi.yaml                   # a spec with every mistake in it
```

Output is deterministic: the same document produces byte-identical findings.
There is no LLM in the loop and no confidence score, because a gate that
answers differently on two runs of the same commit is not a gate.

### Suppressions

```yaml
  /health:
    get:                 # specvet: ignore[SPV004] - public by design
      responses: ...
```

`# specvet: ignore[SPV004]` drops that rule on that line; a bare
`# specvet: ignore` drops everything on it. Prefer `--ignore` in CI so the
accepted risk is visible in the command, not buried in a comment.

### CI

```yaml
- name: Audit the API contract
  run: |
    pip install specvet
    specvet scan . --fail-on high --format sarif -o specvet.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: specvet.sarif
```

### MCP

```bash
uvx --from "specvet[mcp]" specvet-mcp
```

Six tools: `specvet_scan`, `specvet_scan_text` (audit a spec an agent just
generated, no filesystem round trip), `specvet_rules`, `specvet_explain`,
`specvet_coverage`, `specvet_demo`.

## Install

```bash
uvx --from specvet specvet --version
pip install specvet
git clone https://github.com/xuange-hu/specvet && cd specvet && pip install -e .
```

Python 3.10+. No runtime dependencies — the YAML and JSON readers are part of
the package, which is why `pip install specvet` adds nothing to your
environment.

> **PyPI status.** The `Publish` job is red for one known reason: PyPI Trusted
> Publishing has to be registered once in the PyPI UI before the first upload
> can succeed, and that step is still pending. The tool itself is unaffected —
> the `git clone` line above works today.

## Design notes

* **Zero dependencies is a feature, not an accident.** A contract gate runs in
  slim containers and on air-gapped runners. Both readers (`yamlscan`,
  `jsonloc`) keep line numbers, which is the only reason they exist instead of
  PyYAML and `json`.
* **Evidence over opinion.** A finding without a pointer and a line is a
  suggestion. `test_samples.py` gives every rule a spec that triggers it, so a
  rule cannot silently become unreachable.
* **Deterministic or useless.** No network, no model, no sampling.

## Contributing

```bash
git clone https://github.com/xuange-hu/specvet && cd specvet
pytest -q                       # 307 tests
ruff check .
```

Adding a rule means: an entry in `RULES` with an OWASP tag, a check function,
a sample in `tests/test_samples.py`, and a row in the table above. The sample
is not optional — it is how the rule proves it still works.

## License

MIT
