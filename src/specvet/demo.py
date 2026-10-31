"""A deliberately flawed API description, shipped inside the package.

`specvet demo > openapi.yaml && specvet scan openapi.yaml` should be the first
thing a visitor runs: it produces a report with real line numbers against a
spec they can read in the same window. Two of the 36 rules (SPV031, SPV032)
need a document of a different shape, so the demo also carries a Swagger 2.0
file - the pair together is what `demo --scan` reports on.
"""

from __future__ import annotations

__all__ = ["SPEC_TEXT", "SWAGGER2_TEXT", "scan_demo", "spec_text", "swagger2_text"]

SPEC_TEXT = """\
# A small API with the mistakes specvet exists to catch.
# Everything below is intentional.
openapi: 3.0.3
info:
  title: Payments sandbox
  description: Demo corpus for specvet
servers:
  - url: http://api.example.com/v1          # SPV028: plaintext
  - url: https://{region}.example.com/v1    # SPV033: template variable, no default
    variables:
      region:
        enum: [eu, us]
paths:
  /users/{id}:
    get:
      operationId: getUser
      security:
        - BearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: the user        # SPV029/SPV030: no errors, no content
    put:
      operationId: replaceUser
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/User'
      responses:
        '200':
          description: replaced        # SPV001: no 403/404 for an object write
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
    delete:
      operationId: deleteUser
      security: []                     # SPV023: an anonymous delete
      responses:
        '204':
          description: gone
  /orders/{orderId}:
    get:
      operationId: getOrder
      parameters:
        - name: orderId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: the order       # SPV002/SPV003: anonymous object read, no 404
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Order'
  /users:
    get:
      operationId: listUsers
      parameters:
        - name: limit                  # SPV019: unbounded page size
          in: query
          schema:
            type: integer
      responses:
        '200':
          description: users
          content:
            application/json:
              schema:
                type: object
                properties:
                  password:            # SPV012: a credential in a success response
                    type: string
                  email:
                    type: string
  /admin/settings:
    get:
      operationId: readSettings
      security:
        - BearerAuth: []
      responses:
        '200':
          description: settings
          content:
            application/json:
              schema:
                type: object
    post:
      operationId: writeSettings       # SPV020/SPV022: anonymous admin write
      requestBody:
        content:
          application/json:
            schema:
              type: object
      responses:
        '200':
          description: saved
          content:
            application/json:
              schema:
                type: object
  /payments/transfer:
    post:
      operationId: transfer
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Transfer'
      responses:
        '200':
          description: done            # SPV024/SPV025: money, no auth, no 429, no idempotency
          content:
            application/json:
              schema:
                type: object
                properties:
                  reference:
                    type: string
  /integrations/preview:
    post:
      operationId: preview
      parameters:
        - name: callback_url           # SPV026/SPV027: unconstrained fetch target
          in: query
          schema:
            type: string
      responses:
        '200':
          description: preview
          content:
            application/json:
              schema:
                type: object
  /legacy/ping:
    get:
      operationId: ping
      deprecated: true                 # SPV034
      responses:
        '200':
          description: pong
          content:
            application/json:
              schema:
                type: object
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer                   # SPV010: no bearerFormat
    BasicAuth:
      type: http
      scheme: basic                    # SPV007: basic over http://
    LegacyKey:
      type: apiKey
      in: query                        # SPV006
      name: api_key
    OAuthImplicit:
      type: oauth2
      flows:
        implicit:                      # SPV008
          authorizationUrl: https://example.com/oauth
          scopes: {}                   # SPV009
    UnusedKey:                         # SPV005: defined, never referenced
      type: apiKey
      in: header
      name: X-Api-Key
  schemas:
    User:
      type: object
      properties:
        name:
          type: string                 # SPV016
        tags:
          type: array                  # SPV015
          items:
            type: string
    Order:
      type: object                     # SPV013: unknown properties accepted
      properties:
        items:
          type: array
          items:
            type: string
        total:
          type: number                 # SPV017
    Transfer:
      type: object
      properties:
        amount:
          type: number
        memo:
          type: string
        remote:
          $ref: 'https://evil.example/schemas/memo.json'   # SPV036
"""

SWAGGER2_TEXT = """\
swagger: '2.0'                          # SPV031
info:
  title: Legacy inventory
  version: '1.0'
host: legacy.example.com
basePath: /api
schemes: [http]                         # SPV028
paths:
  /items:
    get:
      responses:
        '200':
          description: items
          schema:
            type: array
            items:
              type: string
"""


def spec_text() -> str:
    return SPEC_TEXT


def swagger2_text() -> str:
    return SWAGGER2_TEXT


def scan_demo():  # -> Report
    """Scan both demo documents and merge, the way `specvet demo --scan` does."""
    from .analyze import Options, scan_text
    from .model import Report

    a = scan_text(SPEC_TEXT, path="demo/openapi.yaml", options=Options())
    b = scan_text(SWAGGER2_TEXT, path="demo/swagger2.yaml", options=Options())
    # The merged report keeps the first document as its identity so callers see
    # the real operation count, but the findings come from both files.
    primary = a.document
    primary.operations = list(primary.operations) + list(b.document.operations)
    merged = Report(
        document=primary,
        findings=a.findings + b.findings,
        rules_run=a.rules_run,
        scanned_files=["demo/openapi.yaml", "demo/swagger2.yaml"],
    )
    return merged
