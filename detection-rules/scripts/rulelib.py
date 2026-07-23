"""Shared deterministic helpers for WatchMyAI rule tooling."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
METADATA_DIR = ROOT / "detections" / "metadata"
ELASTIC_DIR = ROOT / "detections" / "elastic"
SIGMA_DIR = ROOT / "detections" / "sigma"


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_metadata() -> list[dict[str, Any]]:
    return [load_yaml(path) for path in sorted(METADATA_DIR.glob("WMAI-*.yml"))]


def elastic_payload(rule: dict[str, Any]) -> dict[str, Any]:
    """Build one Elastic Security import object from canonical metadata."""
    elastic = rule["elastic"]
    investigation = "\n".join(f"{index}. {step}" for index, step in enumerate(rule["investigation_steps"], 1))
    limitations = "\n".join(f"- {item}" for item in rule["limitations"])
    blocked = (
        f"\n\n## Blocked\n\n{rule['blocked_reason']} This artifact is excluded from the deployable package."
        if rule["maturity"] == "blocked"
        else ""
    )
    note = (
        f"## Expected alert\n\n{rule['expected_alert']}\n\n"
        f"## Investigation\n\n{investigation}\n\n"
        f"## Limitations\n\n{limitations}{blocked}"
    )
    tags = (
        [
            "AI Agent",
            rule["category"],
            f"Maturity: {rule['maturity']}",
            f"Custom telemetry: {str(rule['custom_telemetry']).lower()}",
            "WatchMyAI",
            "schema-1.1.0",
            "remediated-2026-07-20",
        ]
        if rule["custom_telemetry"]
        else [
            "WatchMyAI",
            "AI Agent",
            rule["category"],
            f"Maturity: {rule['maturity']}",
            "Custom telemetry: false",
            "Endpoint building block",
        ]
    )
    payload: dict[str, Any] = {
        "author": [rule["author"]],
        "description": rule["description"],
        "enabled": False,
        "false_positives": rule["false_positives"],
        "from": elastic["from"],
        "index": elastic["index_patterns"],
        "interval": elastic["interval"],
        "language": elastic["language"],
        "license": "Apache-2.0",
        "max_signals": 100,
        "name": rule["name"],
        "note": note,
        "query": elastic["query"],
        "references": rule["references"],
        "risk_score": rule["risk_score"],
        "rule_id": rule["rule_id"],
        "rule_source": {"type": "internal"},
        "severity": rule["severity"],
        "tags": tags,
        "to": "now",
        "type": elastic["type"],
        "version": int(rule["version"].split(".", 1)[0]),
    }
    if elastic["type"] == "threshold":
        payload["threshold"] = elastic["threshold"]
    return payload


def dotted_value(event: dict[str, Any], field: str) -> Any:
    value: Any = event
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _normalized(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).casefold()
    return str(value)


def _match_value(actual: Any, expected: str, wildcard: bool) -> bool:
    values = actual if isinstance(actual, list) else [actual]
    for value in values:
        if value is None:
            continue
        candidate = _normalized(value)
        if wildcard and fnmatch.fnmatchcase(candidate.casefold(), expected.casefold()):
            return True
        if not wildcard and candidate.casefold() == expected.casefold():
            return True
    return False


TOKEN_RE = re.compile(
    r"\s*(?:(?P<lparen>\()|(?P<rparen>\))|(?P<colon>:)|"
    r"(?P<string>\"(?:\\.|[^\"\\])*\")|(?P<bare>[^\s():]+))"
)


@dataclass(frozen=True)
class Token:
    kind: str
    value: str


def _tokenize(query: str) -> list[Token]:
    tokens: list[Token] = []
    position = 0
    while position < len(query):
        match = TOKEN_RE.match(query, position)
        if not match or match.end() == position:
            raise ValueError(f"invalid KQL near character {position}")
        kind = match.lastgroup
        if kind is None:
            raise ValueError(f"invalid KQL near character {position}")
        value = match.group(kind)
        if kind == "bare" and value.casefold() in {"and", "or", "not"}:
            kind = value.casefold()
        elif kind == "string":
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid quoted KQL value: {exc}") from exc
        tokens.append(Token(kind, value))
        position = match.end()
    return tokens


class KqlParser:
    """Parser for the deliberate KQL subset used by repository fixtures."""

    def __init__(self, query: str):
        self.tokens = _tokenize(query)
        self.position = 0

    def parse(self) -> tuple[Any, ...]:
        if not self.tokens:
            raise ValueError("KQL query is empty")
        expression = self._parse_or()
        if self.position != len(self.tokens):
            raise ValueError(f"unexpected KQL token {self.tokens[self.position].value!r}")
        return expression

    def _peek(self, kind: str) -> bool:
        return self.position < len(self.tokens) and self.tokens[self.position].kind == kind

    def _take(self, kind: str) -> Token:
        if not self._peek(kind):
            found = self.tokens[self.position].kind if self.position < len(self.tokens) else "end"
            raise ValueError(f"expected KQL token {kind}, found {found}")
        token = self.tokens[self.position]
        self.position += 1
        return token

    def _parse_or(self) -> tuple[Any, ...]:
        node = self._parse_and()
        while self._peek("or"):
            self._take("or")
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self) -> tuple[Any, ...]:
        node = self._parse_unary()
        while self._peek("and"):
            self._take("and")
            node = ("and", node, self._parse_unary())
        return node

    def _parse_unary(self) -> tuple[Any, ...]:
        if self._peek("not"):
            self._take("not")
            return ("not", self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self) -> tuple[Any, ...]:
        if self._peek("lparen"):
            self._take("lparen")
            node = self._parse_or()
            self._take("rparen")
            return node
        field = self._take("bare").value
        self._take("colon")
        return ("condition", field, self._parse_values())

    def _parse_values(self) -> tuple[str, ...]:
        if self._peek("lparen"):
            self._take("lparen")
            values = [self._parse_scalar()]
            while self._peek("or"):
                self._take("or")
                values.append(self._parse_scalar())
            self._take("rparen")
            return tuple(values)
        return (self._parse_scalar(),)

    def _parse_scalar(self) -> str:
        if self._peek("string"):
            return self._take("string").value
        return self._take("bare").value


def parse_kql(query: str) -> tuple[Any, ...]:
    return KqlParser(query).parse()


def kql_fields(node: tuple[Any, ...]) -> set[str]:
    operation = node[0]
    if operation == "condition":
        return {node[1]}
    if operation == "not":
        return kql_fields(node[1])
    return kql_fields(node[1]) | kql_fields(node[2])


def kql_conditions(node: tuple[Any, ...]) -> dict[str, set[str]]:
    """Return all literal values grouped by field from a parsed KQL expression."""
    operation = node[0]
    if operation == "condition":
        return {node[1]: set(node[2])}
    if operation == "not":
        return kql_conditions(node[1])
    result = kql_conditions(node[1])
    for field, values in kql_conditions(node[2]).items():
        result.setdefault(field, set()).update(values)
    return result


def evaluate_kql(node: tuple[Any, ...], event: dict[str, Any]) -> bool:
    operation = node[0]
    if operation == "and":
        return evaluate_kql(node[1], event) and evaluate_kql(node[2], event)
    if operation == "or":
        return evaluate_kql(node[1], event) or evaluate_kql(node[2], event)
    if operation == "not":
        return not evaluate_kql(node[1], event)
    _, field, values = node
    actual = dotted_value(event, field)
    return any(_match_value(actual, value, "*" in value or "?" in value) for value in values)


def fixture_events(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    events = fixture.get("events")
    return events if isinstance(events, list) else [fixture]


def _timestamp(event: dict[str, Any]) -> datetime:
    value = str(event.get("@timestamp", "1970-01-01T00:00:00Z"))
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def evaluate_fixture(rule: dict[str, Any], fixture: dict[str, Any]) -> bool:
    """Evaluate query, threshold, or sequence logic without an LLM."""
    logic = rule["detection_logic"]
    kind = logic["kind"]
    if kind == "query":
        return any(evaluate_kql(parse_kql(logic["query"]), item) for item in fixture_events(fixture))
    if kind == "threshold":
        parsed = parse_kql(logic["query"])
        selected = [item for item in fixture_events(fixture) if evaluate_kql(parsed, item)]
        fields = logic["threshold"]["field"]
        minimum = logic["threshold"]["value"]
        counts: dict[tuple[str, ...], int] = {}
        for item in selected:
            key = tuple(_normalized(dotted_value(item, field)) for field in fields)
            counts[key] = counts.get(key, 0) + 1
        return any(value >= minimum for value in counts.values())
    if kind == "eql":
        sequence = logic["sequence"]
        stages = [parse_kql(stage) for stage in sequence["stages"]]
        events = sorted(fixture_events(fixture), key=_timestamp)
        join_by = sequence["join_by"]
        maxspan = sequence["maxspan_seconds"]
        for start_index, start in enumerate(events):
            if not evaluate_kql(stages[0], start):
                continue
            join_value = dotted_value(start, join_by)
            first_time = _timestamp(start)
            cursor = start_index + 1
            matched = True
            for stage in stages[1:]:
                while cursor < len(events):
                    candidate = events[cursor]
                    cursor += 1
                    if (_timestamp(candidate) - first_time).total_seconds() > maxspan:
                        break
                    if dotted_value(candidate, join_by) == join_value and evaluate_kql(stage, candidate):
                        break
                else:
                    matched = False
                    break
                if cursor > len(events) or not (
                    dotted_value(events[cursor - 1], join_by) == join_value
                    and evaluate_kql(stage, events[cursor - 1])
                ):
                    matched = False
                    break
            if matched:
                return True
        return False
    raise ValueError(f"unsupported fixture logic kind: {kind}")
