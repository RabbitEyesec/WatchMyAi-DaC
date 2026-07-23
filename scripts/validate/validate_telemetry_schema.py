#!/usr/bin/env python3
"""Validate active telemetry, rule fields, and Elastic mappings as one contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "telemetry-gateway"
RULES = ROOT / "detection-rules"
SCHEMA_PATH = ROOT / "src/watchmyai/schema/watchmyai_event.schema.json"
CONTRACT_PATH = ROOT / "src/watchmyai/schema/telemetry_contract.json"
MAPPING_PATH = GATEWAY / "deployment/elastic/component_template.json"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_ndjson import validate_file  # noqa: E402

from watchmyai.normalization.normalizer import Normalizer  # noqa: E402


def _events(value: dict[str, Any]) -> list[dict[str, Any]]:
    events = value.get("events")
    return events if isinstance(events, list) else [value]


def _field(schema: dict[str, Any], dotted: str) -> dict[str, Any] | None:
    node = schema
    for part in dotted.split("."):
        reference = node.get("$ref")
        if reference:
            if not reference.startswith("#/"):
                return None
            node = schema
            for segment in reference[2:].split("/"):
                node = node[segment]
        properties = node.get("properties", {})
        if part not in properties:
            return None
        node = properties[part]
    reference = node.get("$ref")
    if reference and reference.startswith("#/"):
        node = schema
        for segment in reference[2:].split("/"):
            node = node[segment]
    return node


def _mapping_field(mapping: dict[str, Any], dotted: str) -> dict[str, Any] | None:
    node = mapping
    for part in dotted.split("."):
        if node.get("type") == "flattened":
            return {"type": "keyword"}
        properties = node.get("properties", {})
        if part not in properties:
            return None
        node = properties[part]
    return node


def _flatten(value: Any, prefix: str = "") -> set[str]:
    if not isinstance(value, dict):
        return set()
    result: set[str] = set()
    for key, child in value.items():
        dotted = f"{prefix}.{key}" if prefix else key
        result.add(dotted)
        result.update(_flatten(child, dotted))
    return result


def _rule_fields(rule: dict[str, Any]) -> set[str]:
    fields = set(rule.get("required_fields", []))
    query = str(rule.get("elastic", {}).get("query", ""))
    fields.update(re.findall(r"(?<![\w.])([@A-Za-z_][\w.@-]*):", query))
    logic = rule.get("detection_logic", {})
    sequence = logic.get("sequence", {})
    fields.update(sequence.get("join_by", []) if isinstance(sequence.get("join_by"), list) else [])
    if isinstance(sequence.get("join_by"), str):
        fields.add(sequence["join_by"])
    for stage in sequence.get("stages", []):
        fields.update(re.findall(r"(?<![\w.])([@A-Za-z_][\w.@-]*):", stage))
    return fields


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
    contract = json.loads(CONTRACT_PATH.read_text("utf-8"))
    mapping = json.loads(MAPPING_PATH.read_text("utf-8"))["template"]["mappings"]
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    errors: list[str] = []
    fixture_count = 0
    event_count = 0

    if contract.get("schema_version") != "1.1.0":
        errors.append("telemetry contract schema_version must be 1.1.0")
    if contract.get("canonical_dataset_field") != "event.dataset":
        errors.append("telemetry contract canonical field must be event.dataset")
    if contract.get("canonical_dataset_value") != "watchmyai.events":
        errors.append("telemetry contract canonical value must be watchmyai.events")

    fixture_paths = sorted((RULES / "tests/fixtures").glob("*/*.json"))
    for path in fixture_paths:
        fixture_count += 1
        value = json.loads(path.read_text("utf-8"))
        for index, event in enumerate(_events(value)):
            event_count += 1
            location = f"{path.relative_to(ROOT)}:event[{index}]"
            flattened = _flatten(event)
            for deprecated in contract["deprecated_fields"]:
                if deprecated in flattened:
                    errors.append(f"{location}: deprecated field {deprecated}")
            if event.get("event", {}).get("dataset") == "watchmyai.events":
                for error in sorted(
                    validator.iter_errors(event),
                    key=lambda item: list(item.absolute_path),
                ):
                    field = ".".join(str(part) for part in error.absolute_path) or "<root>"
                    actual = error.instance
                    actual_type = type(actual).__name__
                    errors.append(
                        f"{location}: invalid field {field}; expected {error.validator_value!r}; "
                        f"actual {actual_type} {actual!r}: {error.message}"
                    )
            elif not {
                "event.category",
                "event.type",
                "process.entity_id",
            } <= _flatten(event):
                errors.append(f"{location}: endpoint fixture lacks required ECS fields")

    for path in sorted((ROOT / "fixtures/telemetry").glob("*.ndjson")):
        count, ndjson_errors = validate_file(path, telemetry_schema=True)
        event_count += count
        errors.extend(ndjson_errors)

    for path in sorted((RULES / "detections/metadata").glob("WMAI-*.yml")):
        rule = yaml.safe_load(path.read_text("utf-8"))
        rule_id = rule.get("rule_id", path.stem)
        query = str(rule.get("elastic", {}).get("query", ""))
        if rule.get("custom_telemetry") and not re.search(
            r'event\.dataset:(?:"watchmyai\.events"|watchmyai\.events)', query
        ):
            errors.append(f"{rule_id} {path.relative_to(ROOT)}: canonical dataset predicate missing")
        for forbidden in ("event.dataset_name", "event.data_set"):
            if forbidden in query:
                errors.append(f"{rule_id} {path.relative_to(ROOT)}: deprecated field {forbidden}")
        for field in sorted(_rule_fields(rule)):
            definition = _field(schema, field)
            if definition is None:
                errors.append(f"{rule_id} {path.relative_to(ROOT)}: rule references unknown field {field}")
            if field.startswith("watchmyai.") and _mapping_field(mapping, field) is None:
                errors.append(f"{rule_id} {path.relative_to(ROOT)}: Elastic mapping lacks {field}")

    normalizer = Normalizer(
        clock=lambda: "2026-07-21T00:00:00Z",
        id_factory=lambda: "schema-check-event",
        host={"name": "schema-check"},
        user={"name": "schema-check"},
    )
    normalized = normalizer.normalize(
        {
            "event": {
                "category": ["configuration"],
                "type": ["info"],
                "action": "schema.check",
            },
            "watchmyai": {"session": {"id": "schema-check-session"}},
        }
    )
    if normalized["event"].get("dataset") != contract["canonical_dataset_value"]:
        errors.append("gateway normalizer output does not use the canonical dataset")

    if errors:
        print(f"FAIL: {len(errors)} telemetry contract error(s)", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 6
    print(
        f"PASS: schema v{contract['schema_version']}; {fixture_count} fixtures and "
        f"{event_count} events; active rule fields and Elastic mappings are compatible"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
