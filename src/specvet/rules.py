"""The deterministic rule set: 34 checks, each mapped to OWASP API Top 10 2023.

Everything here is a pure function of the parsed document. No network, no LLM,
no confidence score - the same spec always produces byte-identical output,
which is the whole point of putting this in a pull-request gate.

The two cross-endpoint rules (SPV005, SPV021) live in :mod:`specvet.graph`:
they need the operation set as a whole, not one operation at a time.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from .loader import server_urls
from .model import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    Document,
    Finding,
    Operation,
    Rule,
    key_line,
    node_line,
    pointer_escape,
)

__all__ = ["RULES", "RULE_ORDER", "resolve_ref", "run", "sensitive_property_names"]

SENSITIVE_NAMES = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "accesstoken",
    "access_token",
    "refreshtoken",
    "refresh_token",
    "privatekey",
    "private_key",
    "secretkey",
    "secret_key",
    "clientsecret",
    "client_secret",
    "ssn",
    "socialsecurity",
    "social_security",
    "creditcard",
    "credit_card",
    "cardnumber",
    "card_number",
    "cvv",
    "cvc",
    "iban",
    "otp",
    "mfa_code",
    "sessionid",
    "session_id",
    "authorization",
)

URLISH_NAMES = (
    "url",
    "uri",
    "link",
    "href",
    "callback",
    "callback_url",
    "webhook",
    "target",
    "target_url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return_url",
    "returnurl",
    "next",
    "endpoint",
    "fetch",
    "fetch_url",
    "download",
    "download_url",
    "proxy",
    "dest",
    "destination",
    "feed",
    "feed_url",
    "src",
    "source_url",
    "avatar_url",
    "image_url",
    "site",
)

ADMIN_PATH_RE = re.compile(r"/(admin|internal|manage|management|debug|ops|sys|system|private|backoffice|console|_)(/|$)")
FLOW_PATH_RE = re.compile(
    r"/(transfer|payment|payout|withdraw|checkout|purchase|order|refund|invoice|reset[-_]?password|password[-_]?reset)(/|$)"
)
PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")
PAGINATION_NAMES = (
    "limit",
    "page_size",
    "pagesize",
    "per_page",
    "perpage",
    "count",
    "size",
    "take",
    "top",
)


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


# The name lists are written for readability (credit_card, callback_url); every
# comparison happens on the squashed form, because `CreditCard`, `credit_card`
# and `creditCard` are the same field and must not be three different rules.
_SENSITIVE = {_norm(n) for n in SENSITIVE_NAMES}
_URLISH = {_norm(n) for n in URLISH_NAMES}
_PAGINATION = {_norm(n) for n in PAGINATION_NAMES}


def sensitive_property_names(names) -> list[str]:
    return [str(n) for n in names if _norm(n) in _SENSITIVE]


# --------------------------------------------------------------------------
# reference resolution
# --------------------------------------------------------------------------


def _pointer_lookup(root: Any, pointer: str) -> Any:
    cur = root
    for raw in pointer.split("/"):
        if not raw:
            continue
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict):
            cur = cur.get(token)
        elif isinstance(cur, list) and token.isdigit():
            cur = cur[int(token)]
        else:
            return None
    return cur


def resolve_ref(doc: Document, node: Any, depth: int = 0) -> Any:
    """Follow local ``#/...`` references. External ones are returned untouched.

    Depth is capped because a self-referential schema (``Node.children`` ->
    ``Node``) is legal and common, and unbounded recursion here would take the
    scanner down with the spec.
    """
    if depth > 6:
        return node
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            return resolve_ref(doc, _pointer_lookup(doc.root, ref[2:]), depth + 1)
    return node


# --------------------------------------------------------------------------
# small spec helpers
# --------------------------------------------------------------------------


def _status_codes(op: Operation) -> set[str]:
    return {str(k) for k in op.responses()}


def _has_status(op: Operation, *codes: str) -> bool:
    return any(code in _status_codes(op) for code in codes)


def _has_any_prefix(op: Operation, prefix: str) -> bool:
    return any(code.startswith(prefix) for code in _status_codes(op))


def _path_params(op: Operation) -> list[str]:
    return PATH_PARAM_RE.findall(op.path)


def _media_schemas(node: Any) -> Iterator[tuple[str, Any]]:
    """Yield ``(pointer_suffix, schema)`` for every ``content`` entry."""
    if not isinstance(node, dict):
        return
    content = node.get("content")
    if isinstance(content, dict):
        for mime, entry in content.items():
            if isinstance(entry, dict) and "schema" in entry:
                yield f"/content/{pointer_escape(mime)}/schema", entry.get("schema")
    elif "schema" in node:  # Swagger 2.0 body parameter / response
        yield "/schema", node.get("schema")


def _request_schemas(doc: Document, op: Operation) -> list[tuple[str, Any, int]]:
    out: list[tuple[str, Any, int]] = []
    body = op.request_body()
    for suffix, schema in _media_schemas(body):
        out.append((op.pointer + "/requestBody" + suffix, schema, node_line(schema) or op.line))
    if doc.is_swagger2:
        for index, param in enumerate(op.parameters()):
            if isinstance(param, dict) and param.get("in") == "body":
                schema = param.get("schema")
                out.append((f"{op.pointer}/parameters/{index}/schema", schema, op.line))
    return out


def _response_schemas(op: Operation, ok_only: bool = True) -> list[tuple[str, Any, int]]:
    out: list[tuple[str, Any, int]] = []
    responses = op.responses()
    for code, entry in responses.items():
        if ok_only and not str(code).startswith("2"):
            continue
        for suffix, schema in _media_schemas(entry):
            out.append((f"{op.pointer}/responses/{pointer_escape(str(code))}{suffix}", schema, node_line(schema) or op.line))
    return out


def _properties(doc: Document, schema: Any, depth: int = 0) -> Iterator[tuple[str, Any, int]]:
    """Yield ``(name, property_schema, line)`` for an object schema's properties."""
    if depth > 4:
        return
    node = resolve_ref(doc, schema)
    if not isinstance(node, dict):
        return
    props = node.get("properties")
    if isinstance(props, dict):
        for name, prop in props.items():
            yield str(name), prop, key_line(props, name) or node_line(node)


def _all_of(doc: Document, schema: Any, depth: int = 0) -> Iterator[tuple[str, Any, int]]:
    node = resolve_ref(doc, schema)
    if not isinstance(node, dict) or depth > 4:
        return
    yield from _properties(doc, node, depth)
    for branch in node.get("allOf") or []:
        yield from _all_of(doc, branch, depth + 1)


def _walk_tree(node: Any, pointer: str = "") -> Iterator[tuple[str, str, Any]]:
    """Yield ``(pointer, key, value)`` for every mapping entry in the tree."""
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{pointer}/{pointer_escape(str(key))}"
            yield child, str(key), value
            yield from _walk_tree(value, child)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            child = f"{pointer}/{index}"
            yield from _walk_tree(value, child)


def _param_schema(doc: Document, param: Any) -> Any:
    """OpenAPI 3 puts constraints under ``schema``; Swagger 2 puts them inline."""
    if not isinstance(param, dict):
        return None
    if "schema" in param:
        return resolve_ref(doc, param.get("schema"))
    return param if "type" in param else None


def _param_names(op: Operation) -> list[tuple[str, Any, int, str]]:
    """Yield ``(name, param_node, line, pointer)`` for the operation's parameters."""
    out: list[tuple[str, Any, int, str]] = []
    for index, param in enumerate(op.parameters()):
        if not isinstance(param, dict):
            continue
        out.append(
            (
                str(param.get("name") or ""),
                param,
                node_line(param) or op.line,
                f"{op.pointer}/parameters/{index}",
            )
        )
    return out


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

R = Rule


def _mk(rule: Rule, doc: Document, pointer: str, line: int, detail: str, snippet: str = "") -> Finding:
    return Finding(
        rule=rule,
        pointer=pointer,
        line=line,
        snippet=snippet or doc.snippet(line),
        detail=detail,
    )


RULES: dict[str, Rule] = {
    # --- API1:2023 Broken Object Level Authorization ----------------------
    "SPV001": R(
        "SPV001",
        "Write operation on an object path declares no authorization-failure response",
        HIGH,
        "API1:2023",
        "A PUT/PATCH/DELETE on /.../{id} without a 403 or 404 response gives a client no way to "
        "distinguish 'not yours' from 'not there', which is how object-level authorization bugs ship.",
        "Declare 403 (and 404) for the operation and enforce ownership server-side.",
    ),
    "SPV002": R(
        "SPV002",
        "Object path readable without authentication",
        CRITICAL,
        "API1:2023",
        "A GET on a path with an identifier parameter and no security requirement means any caller "
        "can enumerate every object: the enumeration is the vulnerability.",
        "Add a security requirement to the operation, and authorize the object server-side.",
    ),
    "SPV003": R(
        "SPV003",
        "Object path response does not declare 404",
        MEDIUM,
        "API1:2023",
        "Without 404 a caller cannot tell an unauthorized object from a nonexistent one, so clients "
        "leak existence and servers skip the ownership check.",
        "Declare 404 alongside 403 for identifier-addressed reads.",
    ),
    # --- API2:2023 Broken Authentication ---------------------------------
    "SPV004": R(
        "SPV004",
        "Operation has no security requirement",
        CRITICAL,
        "API2:2023",
        "Neither the operation nor the document declares `security`, so the endpoint is reachable "
        "anonymously - and no amount of server-side checking can be inferred from the contract.",
        "Attach a security requirement, or mark the operation public explicitly with `security: []`.",
    ),
    "SPV006": R(
        "SPV006",
        "API key carried in the query string",
        HIGH,
        "API2:2023",
        "Query strings end up in access logs, browser history, proxy caches and Referer headers. "
        "A credential in `in: query` leaks on every hop.",
        "Move the key to `in: header` (or a cookie with CSRF protection).",
    ),
    "SPV007": R(
        "SPV007",
        "HTTP Basic over a plaintext server",
        HIGH,
        "API2:2023",
        "Basic authentication sends base64 (not encryption). Paired with an http:// server the "
        "credential is recoverable by anyone on the path.",
        "Serve over https:// only, or move to a bearer/OAuth2 scheme.",
    ),
    "SPV008": R(
        "SPV008",
        "OAuth2 implicit flow",
        HIGH,
        "API2:2023",
        "The implicit flow was deprecated in OAuth 2.1: the access token is returned in the URL "
        "fragment and exposed to the browser and any script running in it.",
        "Use authorization-code with PKCE.",
    ),
    "SPV009": R(
        "SPV009",
        "OAuth2 flow declares no scopes",
        MEDIUM,
        "API2:2023",
        "A flow with an empty or missing `scopes` map grants a token with no stated privilege, so "
        "reviewers cannot tell what the token may do and servers tend to grant everything.",
        "Enumerate the scopes each flow can request.",
    ),
    "SPV010": R(
        "SPV010",
        "Bearer scheme does not declare its token format",
        LOW,
        "API2:2023",
        "Without `bearerFormat` consumers cannot tell whether the token is a JWT, an opaque "
        "reference, or something home-grown - and home-grown is usually the problem.",
        "Set `bearerFormat: JWT` (or the actual format).",
    ),
    "SPV011": R(
        "SPV011",
        "No global security requirement",
        HIGH,
        "API2:2023",
        "The document declares no top-level `security`, so every operation without its own "
        "requirement is anonymous by default. Secure-by-default has to be explicit here.",
        "Declare a top-level `security` and opt operations out with `security: []`.",
    ),
    # --- API3:2023 Broken Object Property Level Authorization -------------
    "SPV012": R(
        "SPV012",
        "Success response exposes a sensitive-looking property",
        HIGH,
        "API3:2023",
        "A 2xx schema carries a property whose name indicates a credential or PII. Names are weak "
        "evidence on their own, which is why this is a high, not a critical - but it is the exact "
        "shape of the mass-exposure bugs in this category.",
        "Remove the property from the response, or split read and write schemas.",
    ),
    "SPV013": R(
        "SPV013",
        "Request schema does not reject unknown properties",
        MEDIUM,
        "API3:2023",
        "Without `additionalProperties: false` a caller can submit properties the schema never "
        "listed - including role, tenant_id or is_admin if the server binds them blindly.",
        "Set `additionalProperties: false` on request schemas.",
    ),
    "SPV014": R(
        "SPV014",
        "The same schema is used for the request body and the success response",
        MEDIUM,
        "API3:2023",
        "Reusing one schema for input and output means every writable field is readable and "
        "vice versa. That is the precondition for mass assignment.",
        "Define separate write and read schemas.",
    ),
    # --- API4:2023 Unrestricted Resource Consumption ----------------------
    "SPV015": R(
        "SPV015",
        "Array property has no maxItems",
        MEDIUM,
        "API4:2023",
        "An unbounded array in a request body lets one call ask for unlimited work: memory, "
        "fan-out, or downstream quota.",
        "Add `maxItems` (and usually `minItems`).",
    ),
    "SPV016": R(
        "SPV016",
        "String property has no maxLength",
        LOW,
        "API4:2023",
        "An unbounded string is the cheapest way to exhaust memory or a downstream buffer.",
        "Add `maxLength`.",
    ),
    "SPV017": R(
        "SPV017",
        "Numeric property has no bounds",
        MEDIUM,
        "API4:2023",
        "A number without `minimum`/`maximum` accepts anything the parser will hold, which is how "
        "pagination and quantity parameters turn into denial-of-service.",
        "Add `minimum` and `maximum`.",
    ),
    "SPV018": R(
        "SPV018",
        "Operation declares no 429 response",
        MEDIUM,
        "API4:2023",
        "No 429 in the contract usually means no rate limit behind it. The contract is where a "
        "limit becomes reviewable.",
        "Declare 429 with a Retry-After header and enforce the limit.",
    ),
    "SPV019": R(
        "SPV019",
        "Pagination parameter has no upper bound",
        LOW,
        "API4:2023",
        "A `limit`/`page_size` parameter without `maximum` lets a caller request the whole table "
        "in one response.",
        "Add `maximum` (and a server-side ceiling).",
    ),
    # --- API5:2023 Broken Function Level Authorization --------------------
    "SPV020": R(
        "SPV020",
        "Administrative path without authentication",
        CRITICAL,
        "API5:2023",
        "The path looks administrative (admin/internal/debug/...) and carries no security "
        "requirement. Function-level authorization is missing where it matters most.",
        "Require an administrative scope on the operation.",
    ),
    "SPV022": R(
        "SPV022",
        "Write operation without authentication",
        HIGH,
        "API5:2023",
        "A POST/PUT/PATCH/DELETE with no security requirement lets anonymous callers mutate state.",
        "Attach a security requirement to the operation.",
    ),
    "SPV023": R(
        "SPV023",
        "Write operation explicitly public",
        MEDIUM,
        "API5:2023",
        "`security: []` on a write operation is a deliberate decision, so it is reported rather "
        "than assumed - but it deserves a second look in review.",
        "Confirm the operation is meant to be anonymous, and document why.",
    ),
    # --- API6:2023 Unrestricted Access to Sensitive Business Flows --------
    "SPV024": R(
        "SPV024",
        "Sensitive business flow neither authenticated nor rate limited",
        HIGH,
        "API6:2023",
        "A payment/transfer-style operation with no security requirement and no 429 is the "
        "canonical automation target: scripted abuse is the attack, not exploration.",
        "Require authentication, add 429, and add bot/flow controls server-side.",
    ),
    "SPV025": R(
        "SPV025",
        "Sensitive POST has no idempotency key",
        MEDIUM,
        "API6:2023",
        "Money-moving POSTs without an idempotency key turn a retried request into a second "
        "transaction.",
        "Accept an `Idempotency-Key` header parameter.",
    ),
    # --- API7:2023 Server Side Request Forgery ----------------------------
    "SPV026": R(
        "SPV026",
        "Caller-supplied URL parameter with no format constraint",
        HIGH,
        "API7:2023",
        "A parameter named url/uri/webhook/callback that accepts an unconstrained string is the "
        "input an SSRF needs. Without `format: uri` plus a pattern there is nothing to validate "
        "against.",
        "Add `format: uri` and constrain the host, or use an allow-list.",
    ),
    "SPV027": R(
        "SPV027",
        "URL-accepting operation without authentication",
        MEDIUM,
        "API7:2023",
        "An anonymous endpoint that fetches a caller-supplied URL is an open proxy: the SSRF is "
        "available to anyone who finds it.",
        "Require authentication before accepting a fetch target.",
    ),
    # --- API8:2023 Security Misconfiguration ------------------------------
    "SPV028": R(
        "SPV028",
        "Server URL uses plain http",
        HIGH,
        "API8:2023",
        "An http:// server URL (outside localhost) puts every request, credential and token on "
        "the wire in the clear.",
        "Use https:// for every non-local server.",
    ),
    "SPV029": R(
        "SPV029",
        "No error response declared",
        MEDIUM,
        "API8:2023",
        "Without 4xx/5xx (or `default`) responses, error shapes are undefined - and undefined "
        "errors are where stack traces and internal identifiers leak.",
        "Declare 4xx/5xx responses, or a `default` response.",
    ),
    "SPV030": R(
        "SPV030",
        "Success response declares no content",
        LOW,
        "API8:2023",
        "A 2xx response with no `content` is unconstrained: reviewers cannot see what the "
        "endpoint returns, and generators will accept anything.",
        "Declare the response content and schema.",
    ),
    "SPV031": R(
        "SPV031",
        "Swagger 2.0 is a retired format",
        MEDIUM,
        "API8:2023",
        "Swagger 2.0 predates OpenAPI 3.x and its tooling is frozen. Security tooling that reads "
        "the contract gets a worse contract.",
        "Migrate to OpenAPI 3.1.",
    ),
    "SPV032": R(
        "SPV032",
        "No security schemes defined",
        HIGH,
        "API8:2023",
        "`components.securitySchemes` is absent, so no operation in the document can express "
        "authentication even if it wants to.",
        "Declare the schemes the API actually uses.",
    ),
    "SPV033": R(
        "SPV033",
        "Server URL is a wildcard or an unresolved template",
        LOW,
        "API8:2023",
        "A `0.0.0.0` host, or a `{variable}` with no default, means the documented deployment "
        "target is not the one being secured.",
        "Give each server variable a `default` and name the real host.",
    ),
    # --- API9:2023 Improper Inventory Management --------------------------
    "SPV034": R(
        "SPV034",
        "Deprecated operation still published",
        LOW,
        "API9:2023",
        "`deprecated: true` documents an endpoint you intend to remove but have not. Old versions "
        "are the ones nobody patches.",
        "Set a removal date and gate the endpoint off before that date.",
    ),
    "SPV035": R(
        "SPV035",
        "Document has no version",
        LOW,
        "API9:2023",
        "Without `info.version` there is no way to say which revision is deployed, which is the "
        "first thing an inventory needs.",
        "Set `info.version`.",
    ),
    # --- API10:2023 Unsafe Consumption of APIs ----------------------------
    "SPV036": R(
        "SPV036",
        "Reference resolves to a remote URL",
        MEDIUM,
        "API10:2023",
        "A `$ref` pointing off-host makes the contract depend on a third party at parse time. "
        "Whoever controls that URL controls part of your API description.",
        "Vendor the referenced document and point the `$ref` at the local copy.",
    ),
}

RULE_ORDER = sorted(RULES)


# --------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------


def _check_schemes(doc: Document) -> list[Finding]:
    out: list[Finding] = []
    schemes = doc.schemes
    if not schemes:
        out.append(_mk(RULES["SPV032"], doc, "/components/securitySchemes", 1, "no securitySchemes declared"))
        return out
    info_root = doc.root.get("components") if isinstance(doc.root, dict) else None
    if doc.is_swagger2:
        info_root = doc.root
    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue
        pointer = "/components/securitySchemes/" + pointer_escape(name)
        line = key_line(schemes, name) or node_line(info_root)
        kind = str(scheme.get("type") or "")
        if kind == "apiKey" and str(scheme.get("in") or "") == "query":
            out.append(
                _mk(
                    RULES["SPV006"],
                    doc,
                    pointer + "/in",
                    key_line(scheme, "in") or line,
                    f"scheme {name!r} puts the key in the query string",
                )
            )
        plaintext = any(
            url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url for url in server_urls(doc)
        )
        if kind == "http" and str(scheme.get("scheme") or "").lower() == "basic" and plaintext:
            out.append(
                _mk(RULES["SPV007"], doc, pointer, line, f"scheme {name!r} is HTTP Basic and a server is plaintext")
            )
        if kind == "http" and str(scheme.get("scheme") or "").lower() == "bearer" and not scheme.get("bearerFormat"):
            out.append(_mk(RULES["SPV010"], doc, pointer, line, f"scheme {name!r} has no bearerFormat"))
        if kind == "oauth2":
            flows = scheme.get("flows")
            if isinstance(flows, dict):
                if "implicit" in flows:
                    out.append(
                        _mk(
                            RULES["SPV008"],
                            doc,
                            pointer + "/flows/implicit",
                            line,
                            f"scheme {name!r} offers the implicit flow",
                        )
                    )
                for flow_name, flow in flows.items():
                    if not isinstance(flow, dict):
                        continue
                    scopes = flow.get("scopes")
                    if not isinstance(scopes, dict) or not scopes:
                        out.append(
                            _mk(
                                RULES["SPV009"],
                                doc,
                                f"{pointer}/flows/{pointer_escape(flow_name)}/scopes",
                                key_line(flow, "scopes") or line,
                                f"flow {flow_name!r} of {name!r} declares no scopes",
                            )
                        )
    return out


def _check_document(doc: Document) -> list[Finding]:
    out: list[Finding] = []
    if doc.global_security is None:
        out.append(_mk(RULES["SPV011"], doc, "/security", 1, "no top-level `security`"))

    if doc.is_swagger2:
        out.append(_mk(RULES["SPV031"], doc, "/swagger", 1, f"swagger {doc.version}"))

    info = doc.root.get("info") if isinstance(doc.root, dict) else None
    if not isinstance(info, dict) or not info.get("version"):
        out.append(_mk(RULES["SPV035"], doc, "/info", key_line(doc.root, "info"), "`info.version` is missing"))

    for index, url in enumerate(server_urls(doc)):
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            out.append(_mk(RULES["SPV028"], doc, f"/servers/{index}/url", 0, f"server {url!r} is plaintext"))
        if "0.0.0.0" in url or "://*" in url:
            out.append(_mk(RULES["SPV033"], doc, f"/servers/{index}/url", 0, f"server {url!r} matches every host"))
        for var in re.findall(r"\{([^}]+)\}", url):
            server = doc.servers[index] if index < len(doc.servers) and isinstance(doc.servers[index], dict) else {}
            variables = server.get("variables") if isinstance(server, dict) else None
            if not isinstance(variables, dict) or not (variables.get(var) or {}).get("default"):
                out.append(
                    _mk(RULES["SPV033"], doc, f"/servers/{index}/variables", 0, f"server variable {{{var}}} has no default")
                )

    for pointer, key, value in _walk_tree(doc.root):
        if key == "$ref" and isinstance(value, str) and not value.startswith("#"):
            out.append(_mk(RULES["SPV036"], doc, pointer, 0, f"$ref -> {value}"))
    return out


def _check_operation(doc: Document, op: Operation) -> list[Finding]:
    out: list[Finding] = []
    params = _path_params(op)
    codes = _status_codes(op)

    label = f"{op.method.upper()} {op.path}"

    # -- API1 -------------------------------------------------------------
    if params:
        if op.is_write and not (_has_status(op, "403") or _has_status(op, "404")):
            out.append(
                _mk(RULES["SPV001"], doc, op.pointer + "/responses", op.line, f"{label}: no 403/404")
            )
        if op.method == "get" and not op.authenticated:
            out.append(
                _mk(RULES["SPV002"], doc, op.pointer, op.line, f"GET {op.path} takes {params} and has no security")
            )
        if op.method == "get" and "404" not in codes:
            out.append(_mk(RULES["SPV003"], doc, op.pointer + "/responses", op.line, f"GET {op.path}: no 404"))

    # -- API2 / API5 ------------------------------------------------------
    if op.security is None:
        out.append(_mk(RULES["SPV004"], doc, op.pointer, op.line, f"{label} declares no security"))
    elif op.security == [] and op.is_write:
        out.append(
            _mk(RULES["SPV023"], doc, op.pointer + "/security", op.line, f"{label} is explicitly public")
        )
    if op.is_write and not op.authenticated:
        out.append(_mk(RULES["SPV022"], doc, op.pointer, op.line, f"{label} can be called anonymously"))
    if ADMIN_PATH_RE.search(op.path) and not op.authenticated:
        out.append(_mk(RULES["SPV020"], doc, op.pointer, op.line, f"{op.path} looks administrative and is anonymous"))

    # -- API3 -------------------------------------------------------------
    response_refs: set[str] = set()
    for pointer, schema, line in _response_schemas(op):
        if isinstance(schema, dict) and isinstance(schema.get("$ref"), str):
            response_refs.add(schema["$ref"])
        for name, _prop_schema, prop_line in _all_of(doc, schema):
            if _norm(name) in _SENSITIVE:
                out.append(
                    _mk(
                        RULES["SPV012"],
                        doc,
                        f"{pointer}/properties/{pointer_escape(name)}",
                        prop_line or line,
                        f"{label} exposes {name!r}",
                    )
                )
    request_refs: set[str] = set()
    for pointer, schema, line in _request_schemas(doc, op):
        node = resolve_ref(doc, schema)
        if isinstance(schema, dict) and isinstance(schema.get("$ref"), str):
            request_refs.add(schema["$ref"])
        if isinstance(node, dict) and node.get("additionalProperties") is not True and "additionalProperties" not in node:
            out.append(
                _mk(
                    RULES["SPV013"],
                    doc,
                    pointer,
                    line,
                    f"{label} request schema accepts unknown properties",
                )
            )
        for name, prop, prop_line in _all_of(doc, node):
            p = resolve_ref(doc, prop)
            if not isinstance(p, dict):
                continue
            if _norm(name) in _SENSITIVE:
                continue
            prop_pointer = f"{pointer}/properties/{pointer_escape(name)}"
            kind = str(p.get("type") or "")
            if kind == "array" and p.get("maxItems") is None:
                out.append(
                    _mk(RULES["SPV015"], doc, prop_pointer, prop_line or line, f"{name!r} has no maxItems")
                )
            elif kind == "string" and p.get("maxLength") is None and p.get("enum") is None:
                out.append(
                    _mk(RULES["SPV016"], doc, prop_pointer, prop_line or line, f"{name!r} has no maxLength")
                )
            elif kind in ("integer", "number") and p.get("minimum") is None and p.get("maximum") is None:
                out.append(
                    _mk(RULES["SPV017"], doc, prop_pointer, prop_line or line, f"{name!r} has no minimum/maximum")
                )

    for shared in sorted(request_refs & response_refs):
        out.append(
            _mk(
                RULES["SPV014"],
                doc,
                op.pointer + "/requestBody",
                op.line,
                f"{label} uses {shared} for both the request and the 2xx response",
            )
        )

    # -- API4 -------------------------------------------------------------
    if "429" not in codes:
        out.append(_mk(RULES["SPV018"], doc, op.pointer + "/responses", op.line, f"{label} declares no 429"))
    for name, param, line, pointer in _param_names(op):
        if _norm(name) not in _PAGINATION:
            continue
        schema = _param_schema(doc, param)
        if isinstance(schema, dict) and schema.get("maximum") is None and schema.get("maxLength") is None:
            out.append(
                _mk(RULES["SPV019"], doc, pointer + "/schema", line, f"pagination parameter {name!r} has no maximum")
            )

    # -- API6 -------------------------------------------------------------
    is_flow = bool(FLOW_PATH_RE.search(op.path))
    if is_flow and not op.authenticated and "429" not in codes:
        out.append(
            _mk(
                RULES["SPV024"],
                doc,
                op.pointer,
                op.line,
                f"{label} is a sensitive flow with neither security nor 429",
            )
        )
    if is_flow and op.method == "post":
        names = [_norm(n) for n, _, _, _ in _param_names(op)]
        if not any("idempotency" in name for name in names):
            out.append(
                _mk(RULES["SPV025"], doc, op.pointer + "/parameters", op.line, f"POST {op.path} accepts no idempotency key")
            )

    # -- API7 -------------------------------------------------------------
    url_params = [entry for entry in _param_names(op) if _norm(entry[0]) in _URLISH]
    for name, param, line, pointer in url_params:
        schema = _param_schema(doc, param)
        constrained = isinstance(schema, dict) and bool(schema.get("format") or schema.get("pattern") or schema.get("enum"))
        if not constrained:
            out.append(
                _mk(
                    RULES["SPV026"],
                    doc,
                    pointer,
                    line,
                    f"parameter {name!r} accepts an unconstrained URL",
                )
            )
            if not op.authenticated:
                out.append(
                    _mk(
                        RULES["SPV027"],
                        doc,
                        op.pointer,
                        op.line,
                        f"{label} fetches a URL anonymously",
                    )
                )

    # -- API8 -------------------------------------------------------------
    if not _has_any_prefix(op, "4") and not _has_any_prefix(op, "5") and "default" not in codes:
        out.append(
            _mk(RULES["SPV029"], doc, op.pointer + "/responses", op.line, f"{label} declares no error response")
        )

    ok_codes = [code for code in codes if code.startswith("2")]
    for code in ok_codes:
        entry = op.responses().get(code)
        if isinstance(entry, dict) and not entry.get("content") and not entry.get("schema") and not entry.get("$ref"):
            out.append(
                _mk(
                    RULES["SPV030"],
                    doc,
                    f"{op.pointer}/responses/{pointer_escape(code)}",
                    op.line,
                    f"{label} {code} has no content",
                )
            )

    # -- API9 -------------------------------------------------------------
    if op.deprecated:
        out.append(
            _mk(
                RULES["SPV034"],
                doc,
                op.pointer + "/deprecated",
                op.line,
                f"{label} is deprecated but still published",
            )
        )

    return out


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.pointer, finding.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def run(doc: Document) -> list[Finding]:
    """Run every single-endpoint rule. Cross-endpoint rules run in `graph`."""
    out: list[Finding] = []
    out.extend(_check_document(doc))
    out.extend(_check_schemes(doc))
    for op in doc.operations:
        out.extend(_check_operation(doc, op))
    return _dedupe(out)
