"""Read an OpenAPI (3.x) or Swagger (2.0) document into a :class:`Document`.

Two details matter more than they look:

* The format is chosen by sniffing the first non-space character, not by the
  file extension. People keep ``openapi.yml`` around with JSON in it, and a
  scanner that answers "no findings" because it guessed wrong is worse than
  one that refuses.
* ``security`` is resolved per operation here, once. Rules that ask
  "is this operation authenticated?" must all see the same answer, and the
  answer has to distinguish *not declared anywhere* from *explicitly public*
  (``security: []``) - those are different facts with different fixes.
"""

from __future__ import annotations

from typing import Any

from .jsonloc import loads as json_loads
from .model import Document, Operation, key_line, node_line, pointer_escape
from .yamlscan import loads as yaml_loads

__all__ = ["PATH_ITEM_METHODS", "LoadError", "load_file", "load_text"]

PATH_ITEM_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


class LoadError(ValueError):
    """The file is not a spec this reader can make sense of."""


def _looks_like_json(text: str) -> bool:
    for ch in text:
        if ch.isspace():
            continue
        return ch in "{["
    return False


def _as_dict(node: Any) -> dict:
    return node if isinstance(node, dict) else {}


def _as_list(node: Any) -> list:
    return list(node) if isinstance(node, list) else []


def load_file(path: str) -> Document:
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return load_text(text, path=path)


def load_text(text: str, path: str = "<memory>") -> Document:
    fmt = "json" if _looks_like_json(text) else "yaml"
    try:
        root = json_loads(text) if fmt == "json" else yaml_loads(text)
    except ValueError as exc:  # both readers raise ValueError subclasses
        raise LoadError(f"{path}: {exc}") from exc

    root_map = _as_dict(root)
    if not root_map:
        raise LoadError(f"{path}: empty document")

    version = str(root_map.get("openapi") or root_map.get("swagger") or "")
    if not version:
        raise LoadError(f"{path}: neither `openapi:` nor `swagger:` is present - not an API description")

    doc = Document(path=path, text=text, root=root_map, fmt=fmt, version=version)
    doc.global_security = root_map.get("security", None)
    doc.servers = _as_list(root_map.get("servers")) if not doc.is_swagger2 else _swagger2_servers(root_map)

    components = _as_dict(root_map.get("components"))
    schemes = components.get("securitySchemes")
    if not isinstance(schemes, dict):
        # Swagger 2.0 keeps them at the top level under a different name.
        schemes = root_map.get("securityDefinitions")
    doc.schemes = _as_dict(schemes)

    doc.operations = list(_iter_operations(doc))
    return doc


def _swagger2_servers(root: dict) -> list:
    """Swagger 2.0 has host/basePath/schemes where 3.x has servers[].url."""
    host = root.get("host")
    if not host:
        return []
    base = root.get("basePath") or ""
    schemes = [s for s in _as_list(root.get("schemes")) if isinstance(s, str)] or ["https"]
    out = []
    for scheme in schemes:
        out.append({"url": f"{scheme}://{host}{base}"})
    return out


def _iter_operations(doc: Document):
    paths = _as_dict(_as_dict(doc.root).get("paths"))
    for path_key in paths:
        item = paths.get(path_key)
        if not isinstance(item, dict):
            continue
        path_line = key_line(paths, path_key)
        path_pointer = "/paths/" + pointer_escape(path_key)
        path_level_security = item.get("security", None)
        path_level_params = _as_list(item.get("parameters"))
        for method in PATH_ITEM_METHODS:
            if method not in item:
                continue
            node = item.get(method)
            if not isinstance(node, dict):
                continue
            has_local = "security" in node
            security = node.get("security", None) if has_local else path_level_security
            if security is None:
                security = doc.global_security
            params = path_level_params + _as_list(node.get("parameters"))
            if params and isinstance(node, dict):
                # Keep the merged view available to rules without mutating the
                # parsed tree: `node["parameters"]` stays what the file said.
                node = dict(node)
                node["parameters"] = params
            yield Operation(
                path=str(path_key),
                method=method,
                node=node,
                line=key_line(item, method) or path_line,
                pointer=f"{path_pointer}/{method}",
                security=security,
                security_local=has_local or path_level_security is not None,
                deprecated=bool(node.get("deprecated")),
                operation_id=str(node.get("operationId") or ""),
            )


def server_urls(doc: Document) -> list[str]:
    out: list[str] = []
    for server in doc.servers:
        if isinstance(server, dict):
            url = server.get("url")
            if isinstance(url, str):
                out.append(url)
        elif isinstance(server, str):
            out.append(server)
    return out


def server_line(doc: Document, index: int) -> int:
    node = doc.root.get("servers") if isinstance(doc.root, dict) else None
    if isinstance(node, list):
        from .model import item_line  # local import: model imports nothing from loader

        return item_line(node, index)
    return node_line(node)
