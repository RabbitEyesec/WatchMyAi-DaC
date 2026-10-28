#!/usr/bin/env python3
"""Validate staged Sigma candidates against the conversion contract.

Checks provenance hashes, that sources are unchanged, disabled-by-default drafts, allowed
indexes and fields, and that no candidate collides with the production rule IDs.

Usage:
    python scripts/sigma/validate_candidates.py --strict [--input dist/sigma-candidates]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import candidate_lib as lib  # noqa: E402
from eql_eval import UnsupportedQueryError, compile_query  # noqa: E402

REQUIRED = (
    "candidate_id",
    "watchmyai_rule_id",
    "status",
    "promotion",
    "attribution",
    "source",
    "conversion",
    "query_language",
    "rule_type",
    "index_patterns",
    "query",
    "elastic_rule_draft",
    "semantic_tests",
    "review",
)


def validate_candidate(path: Path, policy: dict, forbidden: set[str]) -> list[str]:
    errors: list[str] = []
    name = path.name
    try:
        candidate = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{name}: unreadable: {exc}"]
    missing = [key for key in REQUIRED if key not in candidate]
    if missing:
        return [f"{name}: missing keys {missing}"]
    rule_id = candidate["watchmyai_rule_id"]
    if rule_id in forbidden:
        errors.append(f"{name}: {rule_id} collides with production/excluded rule IDs")
    if candidate["status"] != "requires_review" and candidate["review"]["decision"] == "pending":
        errors.append(f"{name}: status {candidate['status']} without a recorded review decision")
    if candidate["promotion"] != policy["promotion"]:
        errors.append(f"{name}: promotion must be {policy['promotion']}")
    if candidate["attribution"] != "endpoint-only":
        errors.append(f"{name}: endpoint candidates must be attribution endpoint-only")
    if candidate["query_language"] != "eql" or candidate["elastic_rule_draft"]["language"] != "eql":
        errors.append(f"{name}: only eql candidates are supported (never label another language)")
    draft = candidate["elastic_rule_draft"]
    if draft.get("enabled") is not False:
        errors.append(f"{name}: draft must be disabled")
    category = candidate["source"]["logsource"]["category"]
    allowed_indexes = set(policy["logsources"].get(category, {}).get("index_patterns", []))
    if (
        not allowed_indexes
        or set(candidate["index_patterns"]) - allowed_indexes
        or not candidate["index_patterns"]
    ):
        errors.append(f"{name}: index patterns outside the allowlist for {category}")
    if draft["query"] != candidate["query"] or draft["index"] != candidate["index_patterns"]:
        errors.append(f"{name}: draft does not match the candidate query/index")
    try:
        compiled = compile_query(candidate["query"])
        if not compiled.fields <= set(policy["allowed_target_fields"]):
            errors.append(f"{name}: query uses fields outside the allowlist")
    except UnsupportedQueryError as exc:
        errors.append(f"{name}: query outside reviewed EQL subset: {exc}")
    source = lib.ROOT / candidate["source"]["path"]
    if not source.is_file():
        errors.append(f"{name}: source {candidate['source']['path']} no longer exists")
    elif lib.sha256_file(source) != candidate["source"]["sha256"]:
        errors.append(f"{name}: source changed since conversion; re-run convert_candidates.py")
    for key in ("positive_fixture", "negative_fixture"):
        if not (lib.ROOT / candidate["semantic_tests"][key]).is_file():
            errors.append(f"{name}: missing {key} {candidate['semantic_tests'][key]}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--input", type=Path, default=lib.ROOT / "dist" / "sigma-candidates")
    parser.add_argument("--strict", action="store_true", help="a missing input directory is a failure")
    args = parser.parse_args(argv)

    try:
        policy = lib.load_policy()
        forbidden = lib.forbidden_rule_ids()
    except lib.CandidateError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if not args.input.is_dir():
        message = f"no candidates at {args.input}; run scripts/sigma/convert_candidates.py first"
        print(("FAIL: " if args.strict else "SKIPPED: ") + message, file=sys.stderr)
        return 1 if args.strict else 0
    files = sorted(args.input.glob("*.candidate.json"))
    manifest_path = args.input / "manifest.json"
    errors: list[str] = []
    if not files:
        errors.append("no candidate files found")
    if not manifest_path.is_file():
        errors.append("manifest.json missing")
    else:
        manifest = json.loads(manifest_path.read_text("utf-8"))
        if manifest.get("production_mutation") is not False:
            errors.append("manifest must declare production_mutation false")
        listed = {entry["file"]: entry["sha256"] for entry in manifest.get("candidates", [])}
        if set(listed) != {p.name for p in files}:
            errors.append("manifest candidate list does not match files on disk")
        for path in files:
            if listed.get(path.name) and lib.sha256_file(path) != listed[path.name]:
                errors.append(f"{path.name}: hash differs from manifest")
    for path in files:
        errors.extend(validate_candidate(path, policy, forbidden))
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: {len(files)} Sigma candidates satisfy the conversion contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
