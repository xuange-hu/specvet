"""The loader decides what a "spec" is, so its judgement calls get pinned.

The two that matter: format is sniffed from content rather than the file name,
and `security` is resolved once, distinguishing *absent* from *empty*.
"""

from __future__ import annotations

import pytest

from specvet.loader import LoadError, load_text, server_urls

MINIMAL = """\
openapi: 3.0.3
info:
  title: t
  version: '1'
paths:
  /ping:
    get:
      responses:
        '200':
          description: ok
"""

MINIMAL_JSON = """{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok"}}}}}
}"""


def test_json_content_in_a_yaml_named_file_is_still_json():
    doc = load_text(MINIMAL_JSON, path="openapi.yaml")
    assert doc.fmt == "json"
    assert len(doc.operations) == 1


def test_yaml_content_is_detected():
    assert load_text(MINIMAL).fmt == "yaml"


def test_openapi_version_is_read():
    assert load_text(MINIMAL).version == "3.0.3"


def test_swagger2_is_recognised_and_flagged():
    doc = load_text("swagger: '2.0'\ninfo: {title: t, version: '1'}\npaths: {}\n")
    assert doc.version == "2.0"
    assert doc.is_swagger2 is True


def test_missing_version_is_rejected():
    with pytest.raises(LoadError):
        load_text("info:\n  title: t\n")


def test_empty_document_is_rejected():
    with pytest.raises(LoadError):
        load_text("# only a comment\n")


def test_broken_yaml_is_rejected():
    """An over-indented line with no `key:` is not something to guess at."""
    with pytest.raises(LoadError):
        load_text("openapi: 3.0.0\n  bad\n")


def test_broken_json_is_rejected():
    with pytest.raises(LoadError):
        load_text('{"openapi": ')


def test_a_sequence_root_is_not_a_spec():
    with pytest.raises(LoadError):
        load_text("- 1\n- 2\n")


def test_operations_are_enumerated_in_document_order():
    doc = load_text(
        """\
openapi: 3.0.3
info: {title: t, version: '1'}
paths:
  /a:
    get: {responses: {'200': {description: ok}}}
    post: {responses: {'200': {description: ok}}}
  /b:
    delete: {responses: {'200': {description: ok}}}
"""
    )
    assert [(o.path, o.method) for o in doc.operations] == [("/a", "get"), ("/a", "post"), ("/b", "delete")]


def test_operation_line_points_at_the_method():
    doc = load_text(MINIMAL)
    op = doc.operations[0]
    assert op.line == 7  # `get:`


def test_unknown_path_item_key_is_not_an_operation():
    doc = load_text(
        "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    summary: nope\n    get: {responses: {}}\n"
    )
    assert [o.method for o in doc.operations] == ["get"]


def test_global_security_is_inherited():
    doc = load_text(
        """\
openapi: 3.0.3
info: {title: t, version: '1'}
security:
  - BearerAuth: []
paths:
  /a:
    get: {responses: {'200': {description: ok}}}
"""
    )
    op = doc.operations[0]
    assert op.authenticated is True
    assert op.security_local is False


def test_absent_security_differs_from_empty_security():
    absent = load_text(MINIMAL).operations[0]
    public = load_text(
        "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      security: []\n      responses: {'200': {description: ok}}\n"
    ).operations[0]
    assert absent.security is None
    assert public.security == []
    assert public.authenticated is False
    assert public.security_local is True


def test_operation_security_overrides_global():
    doc = load_text(
        """\
openapi: 3.0.3
info: {title: t, version: '1'}
security:
  - BearerAuth: []
paths:
  /a:
    get:
      security: []
      responses: {'200': {description: ok}}
"""
    )
    assert doc.operations[0].security == []


def test_path_level_parameters_are_merged_into_every_method():
    doc = load_text(
        """\
openapi: 3.0.3
info: {title: t, version: '1'}
paths:
  /a/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema: {type: string}
    get: {responses: {'200': {description: ok}}}
"""
    )
    assert len(doc.operations[0].parameters()) == 1


def test_requirement_names_are_collected():
    doc = load_text(
        """\
openapi: 3.0.3
info: {title: t, version: '1'}
paths:
  /a:
    get:
      security:
        - BearerAuth: []
        - ApiKey: [read]
      responses: {'200': {description: ok}}
"""
    )
    assert doc.operations[0].requirement_names() == ["BearerAuth", "ApiKey"]


def test_swagger2_synthesizes_servers_from_host_and_base_path():
    doc = load_text(
        "swagger: '2.0'\ninfo: {title: t, version: '1'}\nhost: api.example.com\nbasePath: /v1\nschemes: [http, https]\npaths: {}\n"
    )
    assert server_urls(doc) == ["http://api.example.com/v1", "https://api.example.com/v1"]


def test_swagger2_security_definitions_are_read_as_schemes():
    doc = load_text(
        "swagger: '2.0'\ninfo: {title: t, version: '1'}\nsecurityDefinitions:\n  key:\n    type: apiKey\n    name: k\n    in: header\npaths: {}\n"
    )
    assert "key" in doc.schemes


def test_deprecated_and_operation_id():
    doc = load_text(
        "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      operationId: a\n      deprecated: true\n      responses: {'200': {description: ok}}\n"
    )
    op = doc.operations[0]
    assert op.deprecated is True
    assert op.operation_id == "a"


def test_snippet_reports_the_source_line():
    doc = load_text(MINIMAL)
    assert doc.snippet(1) == "openapi: 3.0.3"
    assert doc.snippet(999) == ""
