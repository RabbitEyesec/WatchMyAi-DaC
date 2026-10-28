#!/usr/bin/env python3
"""Check staged candidates against positive/negative fixtures.

Every positive event must match its candidate query and every negative event must not.
Fixture files are JSON: {"rule_id": "WMAI-0NN", "events": [{"id": "...", "event": {...}}]}.

Usage:
    python scripts/sigma/compare_semantics.py [--input dist/sigma-candidates]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import candidate_lib as lib  # noqa: E402
from eql_eval import UnsupportedQueryError, compile_query  # noqa: E402


def load_events(path: Path, rule_id: str) -> list[dict]:
    payload = json.loads(path.read_text("utf-8"))
    if payload.get("rule_id") != rule_id or not payload.get("events"):
        raise ValueError(f"{lib.rel(path)} must declare rule_id {rule_id} and at least one event")
    return payload["events"]


def compare(candidate: dict) -> list[str]:
    failures: list[str] = []
    rule_id = candidate["watchmyai_rule_id"]
    try:
        query = compile_query(candidate["query"])
    except UnsupportedQueryError as exc:
        return [f"{rule_id}: query outside reviewed EQL subset: {exc}"]
    for key, expected in (("positive_fixture", True), ("negative_fixture", False)):
        path = lib.ROOT / candidate["semantic_tests"][key]
        try:
            events = load_events(path, rule_id)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failures.append(f"{rule_id}: {exc}")
            continue
        for entry in events:
            if query.matches(entry["event"]) is not expected:
                failures.append(f"{rule_id}: {entry['id']} expected {'match' if expected else 'no match'}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--input", type=Path, default=lib.ROOT / "dist" / "sigma-candidates")
    args = parser.parse_args(argv)
    files = sorted(args.input.glob("*.candidate.json")) if args.input.is_dir() else []
    if not files:
        print(f"FAIL: no candidates in {args.input}; run convert_candidates.py first", file=sys.stderr)
        return 1
    failures: list[str] = []
    total = 0
    for path in files:
        candidate = json.loads(path.read_text("utf-8"))
        failures.extend(compare(candidate))
        total += 1
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print(f"PASS: positive/negative fixtures agree with {total} candidate queries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
