"""A JSON reader that keeps line numbers.

`json` gives you the value and throws the position away. That is fine for
configuration and useless for a report: a finding about
``paths./users.post.security`` is only actionable if the reader can jump to
the line where it lives. This module is the JSON twin of :mod:`specvet.yamlscan`
- same contract, same ``S``/``M``/``L`` node types - so the rule engine can
walk a spec without caring which of the two formats it was written in.

Supported: the whole JSON grammar (RFC 8259), with \\u escapes and surrogate
pairs. Duplicated object keys keep the last value, matching `json`.
"""

from __future__ import annotations

from typing import Any

from .yamlscan import L, M, S, YamlError

__all__ = ["JsonError", "loads"]

JsonError = YamlError

_WS = " \t\r\n"

_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


class _Scanner:
    def __init__(self, text: str) -> None:
        self.text = text
        self.i = 0
        self.n = len(text)

    # -- positions -------------------------------------------------------
    def _line(self, pos: int) -> int:
        return self.text.count("\n", 0, pos) + 1

    def _fail(self, msg: str) -> JsonError:
        return JsonError(f"line {self._line(self.i)}: {msg}")

    def _skip_ws(self) -> None:
        while self.i < self.n and self.text[self.i] in _WS:
            self.i += 1

    # -- entry -----------------------------------------------------------
    def parse(self) -> Any:
        self._skip_ws()
        value = self._value()
        self._skip_ws()
        if self.i != self.n:
            raise self._fail("trailing data after the JSON value")
        return value

    def _value(self) -> Any:
        self._skip_ws()
        if self.i >= self.n:
            raise self._fail("unexpected end of input")
        ch = self.text[self.i]
        if ch == "{":
            return self._object()
        if ch == "[":
            return self._array()
        if ch == '"':
            start = self.i
            raw = self._string()
            return S(raw, self._line(start))
        return self._literal()

    def _object(self) -> M:
        out = M(self._line(self.i))
        self.i += 1  # consume '{'
        self._skip_ws()
        if self.i < self.n and self.text[self.i] == "}":
            self.i += 1
            return out
        while True:
            self._skip_ws()
            if self.i >= self.n:
                raise self._fail("unterminated object")
            if self.text[self.i] != '"':
                raise self._fail(f"expected a quoted object key, got {self.text[self.i]!r}")
            kstart = self.i
            key = self._string()
            kline = self._line(kstart)
            self._skip_ws()
            if self.i >= self.n or self.text[self.i] != ":":
                raise self._fail("expected ':' after an object key")
            self.i += 1
            out[key] = self._value()
            out.klines[key] = kline
            self._skip_ws()
            if self.i >= self.n:
                raise self._fail("unterminated object")
            if self.text[self.i] == ",":
                self.i += 1
                continue
            if self.text[self.i] == "}":
                self.i += 1
                return out
            raise self._fail(f"expected ',' or '}}' in object, got {self.text[self.i]!r}")

    def _array(self) -> L:
        out = L(self._line(self.i))
        self.i += 1  # consume '['
        self._skip_ws()
        if self.i < self.n and self.text[self.i] == "]":
            self.i += 1
            return out
        idx = 0
        while True:
            self._skip_ws()
            start = self.i
            out.append(self._value())
            out.ilines[idx] = self._line(start)
            out.line = out.line or out.ilines[idx]
            idx += 1
            self._skip_ws()
            if self.i >= self.n:
                raise self._fail("unterminated array")
            if self.text[self.i] == ",":
                self.i += 1
                continue
            if self.text[self.i] == "]":
                self.i += 1
                return out
            raise self._fail(f"expected ',' or ']' in array, got {self.text[self.i]!r}")

    def _string(self) -> str:
        # self.i points at the opening quote
        self.i += 1
        buf: list[str] = []
        while True:
            if self.i >= self.n:
                raise self._fail("unterminated string")
            ch = self.text[self.i]
            if ch == '"':
                self.i += 1
                return "".join(buf)
            if ch == "\\":
                self.i += 1
                if self.i >= self.n:
                    raise self._fail("unterminated escape")
                esc = self.text[self.i]
                self.i += 1
                if esc == "u":
                    buf.append(self._unicode_escape())
                    continue
                mapping = _ESCAPES.get(esc)
                if mapping is None:
                    raise self._fail(f"invalid escape \\{esc}")
                buf.append(mapping)
                continue
            buf.append(ch)
            self.i += 1

    def _unicode_escape(self) -> str:
        chunk = self.text[self.i : self.i + 4]
        if len(chunk) < 4 or any(c not in "0123456789abcdefABCDEF" for c in chunk):
            raise self._fail("truncated \\u escape")
        self.i += 4
        code = int(chunk, 16)
        # Surrogate pairs: a lone high surrogate is what naive decoders turn
        # into U+FFFD, silently corrupting emoji in descriptions.
        if 0xD800 <= code <= 0xDBFF and self.text[self.i : self.i + 2] == "\\u":
            self.i += 2
            low = self.text[self.i : self.i + 4]
            if len(low) == 4 and all(c in "0123456789abcdefABCDEF" for c in low):
                low_code = int(low, 16)
                if 0xDC00 <= low_code <= 0xDFFF:
                    self.i += 4
                    return chr(0x10000 + ((code - 0xD800) << 10) + (low_code - 0xDC00))
        return chr(code)

    def _literal(self) -> Any:
        start = self.i
        while self.i < self.n and self.text[self.i] not in ",}]" + _WS:
            self.i += 1
        token = self.text[start : self.i].strip()
        if token in ("true", "false", "null", "0", "-0"):
            if token == "true":
                return True
            if token == "false":
                return False
            if token == "null":
                return None
            return 0
        try:
            return int(token)
        except ValueError:
            pass
        try:
            return float(token)
        except ValueError:
            pass
        raise self._fail(f"invalid JSON literal {token!r}")


def loads(text: str) -> Any:
    """Parse ``text`` into S/M/L nodes that remember their source lines."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return M()
    return _Scanner(text).parse()
