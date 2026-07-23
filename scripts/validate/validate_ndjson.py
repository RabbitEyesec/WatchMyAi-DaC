#!/usr/bin/env python3
"""Stream-validate newline-delimited JSON with exact line diagnostics."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class NdjsonRecord:
    line_number: int
    value: dict[str, Any]


class NdjsonError(ValueError):
    """One actionable NDJSON validation failure."""


def iter_ndjson(path: Path) -> Iterator[NdjsonRecord]:
    records = 0
    try:
        handle = path.open("r", encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise NdjsonError(f"{path}: invalid UTF-8: {exc}") from exc
    except OSError as exc:
        raise NdjsonError(f"{path}: cannot read file: {exc}") from exc
    try:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                raise NdjsonError(f"{path}: line {line_number}: blank records are not allowed")
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise NdjsonError(
                    f"{path}: line {line_number}: JSON parse error: {exc.msg} at column {exc.colno}"
                ) from exc
            if not isinstance(value, dict):
                kind = "array" if isinstance(value, list) else type(value).__name__
                raise NdjsonError(f"{path}: line {line_number}: expected one JSON object, found {kind}")
            records += 1
            yield NdjsonRecord(line_number, value)
    except UnicodeDecodeError as exc:
        raise NdjsonError(f"{path}: line {line_number}: invalid UTF-8: {exc}") from exc
    finally:
        handle.close()
    if records == 0:
        raise NdjsonError(f"{path}: file contains no JSON objects")


def validate_file(path: Path, *, telemetry_schema: bool = False) -> tuple[int, list[str]]:
    errors: list[str] = []
    count = 0
    validator: Any = None
    if telemetry_schema:
        try:
            from jsonschema import Draft202012Validator, FormatChecker
        except ImportError:
            return 0, ["jsonschema is required for --telemetry-schema"]
        root = Path(__file__).resolve().parents[2]
        schema_path = root / "src" / "watchmyai" / "schema" / "watchmyai_event.schema.json"
        schema = json.loads(schema_path.read_text("utf-8"))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
    try:
        for record in iter_ndjson(path):
            count += 1
            if validator is None:
                continue
            for error in sorted(
                validator.iter_errors(record.value),
                key=lambda item: list(item.absolute_path),
            ):
                location = ".".join(str(part) for part in error.absolute_path) or "<root>"
                errors.append(f"{path}: line {record.line_number}: field {location}: {error.message}")
    except NdjsonError as exc:
        errors.append(str(exc))
    return count, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--telemetry-schema", action="store_true")
    args = parser.parse_args()
    total = 0
    failures: list[str] = []
    for path in args.paths:
        count, errors = validate_file(path, telemetry_schema=args.telemetry_schema)
        total += count
        failures.extend(errors)
    if failures:
        print(f"FAIL: {len(failures)} NDJSON error(s)", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 6
    print(f"PASS: {total} NDJSON object(s) validated across {len(args.paths)} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
