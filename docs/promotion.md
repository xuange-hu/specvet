# Promotion copy

Pre-written so publishing is a paste, not a writing session. Nothing here is
posted automatically — every external post needs a human decision.

## One-liner (About / X bio)

> Deterministic security review for OpenAPI and Swagger. 36 rules mapped to the
> OWASP API Top 10 2023, zero dependencies, SARIF for CI, MCP for agents.

## Short description (Awesome lists, 200 chars)

`specvet` — audit an OpenAPI/Swagger document offline: 36 deterministic rules
mapped to the OWASP API Security Top 10 2023, JSON-Pointer evidence, SARIF and
MCP output, zero runtime dependencies.

## Show HN

**Title:** specvet – deterministic security review for OpenAPI and Swagger specs

**Body:**

Most API security tooling either needs a running API or lints style. specvet
reads the contract itself and answers a different question: what can an
attacker do with this document?

36 rules, each tagged with its OWASP API Security Top 10 2023 category
(API1 BOLA through API10). Zero dependencies — the YAML and JSON readers are
part of the package and keep line numbers, so every finding is a severity plus
a JSON Pointer plus a line you can jump to.

The part I think is actually new is the second pass. Reading one endpoint at a
time cannot see that a path authenticates GET but not DELETE, or that a
`securitySchemes` entry is defined but never referenced by any `security`
requirement. Both look defensible in isolation. specvet reports them as
`SPV021` and `SPV005`.

It also refuses to conflate `security:` missing with `security: []`. The first
is an omission, the second is a decision, and they deserve different fixes.

`uvx --from specvet specvet demo --scan` shows the whole corpus with no file
to find.

## Reddit r/carhacking is the wrong room — r/devsecops, r/ExperiencedDevs, r/api

**Title:** I wrote an offline OpenAPI/Swagger security reviewer (36 rules, OWASP
API Top 10 mapping, zero deps)

Points worth raising in the thread:

- Deterministic output, so it can gate a pull request without flake.
- `specvet scan_text` as an MCP tool: an agent generates a spec, audits it, and
  never round-trips the filesystem.
- The rules I am least sure about are `SPV016` (string without `maxLength`) and
  `SPV019` (pagination without `maximum`) — both are noisy on large real specs.
  Feedback welcome.

## X thread

1. Most API security tools need a running API. Your OpenAPI file already says
   whether `/admin/settings` is authenticated. You just have to read 4,000 lines
   of YAML to find out.

2. `uvx --from specvet specvet scan openapi.yaml`

3. 36 rules, each mapped to an OWASP API Top 10 2023 category. Zero
   dependencies. SARIF for CI. MCP for agents.

4. The finding I care about most isn't "no auth". It's `SPV021`: a path that
   authenticates GET but not DELETE. Every endpoint looks fine alone.

5. And `SPV005`: a `securitySchemes` block that looks like authentication and
   authenticates nothing, because no `security` requirement references it.

6. `security:` missing is an omission. `security: []` is a decision. The tool
   reports them differently, because the fixes are different.

## Awesome-list PR blurb

**[specvet](https://github.com/xuange-hu/specvet)** — Deterministic security
review for OpenAPI/Swagger documents: 36 rules mapped to the OWASP API Security
Top 10 2023, cross-endpoint checks (per-path authorization consistency,
unreferenced security schemes), JSON-Pointer evidence, SARIF 2.1.0 and MCP
output. Zero runtime dependencies.

## Topics (20 max)

openapi, swagger, api-security, security, owasp, owasp-api-top10, static-analysis,
devsecops, linter, sarif, api, rest, contract-testing, mcp, model-context-protocol,
python, zero-dependency, ci, shift-left, appsec
