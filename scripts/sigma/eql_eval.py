"""Evaluate the small EQL subset emitted by the pySigma Elasticsearch backend.

This is a test oracle for staged Sigma candidates, not a detection engine. It models the
documented EQL semantics for the operators below and raises ``UnsupportedQueryError`` for
anything else, so an unexpected backend change fails closed instead of being guessed at.

Supported grammar::

    query   := "any" "where" expr
    expr    := or_expr
    or_expr := and_expr ("or" and_expr)*
    and_expr:= not_expr ("and" not_expr)*
    not_expr:= ("not" | "!") not_expr | atom
    atom    := "(" expr ")" | field OP literal | field OP "(" literal ("," literal)* ")"
    OP      := ":" | "like~" | "like" | "==" | "!=" | "in~" | "in"

Case rules: ``:``, ``like~`` and ``in~`` are case-insensitive; ``like``, ``==``, ``!=`` and
``in`` are case-sensitive. ``*`` and ``?`` are wildcards for ``:`` and ``like``/``like~``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any


class UnsupportedQueryError(ValueError):
    """The query uses syntax outside the supported, reviewed subset."""


_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<string>"(?:[^"\\]|\\.)*")
      | (?P<op>==|!=|like~|in~|:|\(|\)|,|!)
      | (?P<word>[A-Za-z_][A-Za-z0-9_.\-]*)
      | (?P<number>-?\d+(?:\.\d+)?)
    )""",
    re.VERBOSE,
)
_ESCAPES = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t"}
_KEYWORDS = {"and", "or", "not", "like", "in", "where", "any", "null", "true", "false"}


@dataclass(frozen=True)
class Token:
    kind: str
    value: Any


def _unquote(raw: str) -> str:
    body, out, index = raw[1:-1], [], 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            index += 1
            escape = body[index]
            if escape not in _ESCAPES:
                raise UnsupportedQueryError(f"unsupported string escape \\{escape}")
            out.append(_ESCAPES[escape])
        else:
            out.append(char)
        index += 1
    return "".join(out)


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    position = 0
    stripped = text.rstrip()
    while position < len(stripped):
        match = _TOKEN_RE.match(stripped, position)
        if not match or match.end() == position:
            raise UnsupportedQueryError(f"unsupported syntax near {stripped[position : position + 24]!r}")
        position = match.end()
        if match.group("string") is not None:
            tokens.append(Token("string", _unquote(match.group("string"))))
        elif match.group("op") is not None:
            tokens.append(Token("op", match.group("op")))
        elif match.group("number") is not None:
            tokens.append(Token("number", match.group("number")))
        else:
            word = match.group("word")
            lowered = word.lower()
            if lowered in _KEYWORDS:
                tokens.append(Token("kw", lowered))
            else:
                tokens.append(Token("field", word))
    return tokens


def _wildcard_regex(pattern: str, *, ignore_case: bool) -> re.Pattern[str]:
    parts = []
    for char in pattern:
        parts.append(".*" if char == "*" else "." if char == "?" else re.escape(char))
    return re.compile("".join(parts), re.DOTALL | (re.IGNORECASE if ignore_case else 0))


def _values(event: dict[str, Any], dotted: str) -> list[Any]:
    """Return every scalar at ``dotted`` (arrays flatten; missing -> empty)."""
    current: list[Any] = [event]
    for part in dotted.split("."):
        nxt: list[Any] = []
        for item in current:
            if isinstance(item, dict) and part in item:
                nxt.append(item[part])
        current = nxt
    flat: list[Any] = []
    for item in current:
        if isinstance(item, list):
            flat.extend(item)
        elif item is not None:
            flat.append(item)
    return flat


Predicate = Callable[[dict[str, Any]], bool]


def _comparison(field: str, op: str, literals: list[Any]) -> Predicate:
    def match_one(candidate: Any, literal: Any) -> bool:
        if op in {":", "like~", "like"}:
            if not isinstance(literal, str):
                raise UnsupportedQueryError(f"{op} requires string literals")
            ignore = op != "like"
            return _wildcard_regex(literal, ignore_case=ignore).fullmatch(str(candidate)) is not None
        if op in {"==", "in"}:
            return candidate == literal
        if op == "in~":
            return str(candidate).lower() == str(literal).lower()
        raise UnsupportedQueryError(f"unsupported operator {op}")

    def predicate(event: dict[str, Any]) -> bool:
        values = _values(event, field)
        if op == "!=":
            return not any(value in literals for value in values) if values else True
        if None in literals:  # field == null
            return not values
        return any(match_one(value, literal) for value in values for literal in literals)

    return predicate


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.index = 0
        self.fields: set[str] = set()

    def peek(self) -> Token | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> Token:
        token = self.peek()
        if token is None:
            raise UnsupportedQueryError("unexpected end of query")
        self.index += 1
        return token

    def expect(self, kind: str, value: Any = None) -> Token:
        token = self.take()
        if token.kind != kind or (value is not None and token.value != value):
            raise UnsupportedQueryError(f"expected {value or kind}, found {token.value!r}")
        return token

    def parse(self) -> Predicate:
        self.expect("kw", "any")
        self.expect("kw", "where")
        predicate = self.or_expr()
        if self.peek() is not None:
            raise UnsupportedQueryError(f"trailing tokens after expression: {self.peek()!r}")
        return predicate

    def or_expr(self) -> Predicate:
        parts = [self.and_expr()]
        while (token := self.peek()) and token == Token("kw", "or"):
            self.take()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else (lambda e, p=parts: any(x(e) for x in p))

    def and_expr(self) -> Predicate:
        parts = [self.not_expr()]
        while (token := self.peek()) and token == Token("kw", "and"):
            self.take()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else (lambda e, p=parts: all(x(e) for x in p))

    def not_expr(self) -> Predicate:
        token = self.peek()
        if token in (Token("kw", "not"), Token("op", "!")):
            self.take()
            inner = self.not_expr()
            return lambda e: not inner(e)
        return self.atom()

    def atom(self) -> Predicate:
        token = self.take()
        if token == Token("op", "("):
            inner = self.or_expr()
            self.expect("op", ")")
            return inner
        if token.kind != "field":
            raise UnsupportedQueryError(f"expected field name, found {token.value!r}")
        field = token.value
        self.fields.add(field)
        op_token = self.take()
        if op_token.kind == "kw" and op_token.value in {"like", "in"}:
            op = op_token.value
        elif op_token.kind == "op" and op_token.value in {":", "==", "!=", "like~", "in~"}:
            op = op_token.value
        else:
            raise UnsupportedQueryError(f"unsupported operator {op_token.value!r}")
        return _comparison(field, op, self.literals())

    def literals(self) -> list[Any]:
        if self.peek() == Token("op", "("):
            self.take()
            values = [self.literal()]
            while self.peek() == Token("op", ","):
                self.take()
                values.append(self.literal())
            self.expect("op", ")")
            return values
        return [self.literal()]

    def literal(self) -> Any:
        token = self.take()
        if token.kind == "string":
            return token.value
        if token.kind == "number":
            return float(token.value) if "." in token.value else int(token.value)
        if token == Token("kw", "null"):
            return None
        if token == Token("kw", "true"):
            return True
        if token == Token("kw", "false"):
            return False
        raise UnsupportedQueryError(f"expected literal, found {token.value!r}")


@dataclass(frozen=True)
class CompiledQuery:
    fields: frozenset[str]
    predicate: Predicate

    def matches(self, event: dict[str, Any]) -> bool:
        return self.predicate(event)


def compile_query(text: str) -> CompiledQuery:
    parser = _Parser(tokenize(text))
    predicate = parser.parse()
    return CompiledQuery(frozenset(parser.fields), predicate)


def iter_literals(text: str) -> Iterator[str]:
    """Yield string literals from a query (used by safety checks)."""
    for token in tokenize(text):
        if token.kind == "string":
            yield token.value
