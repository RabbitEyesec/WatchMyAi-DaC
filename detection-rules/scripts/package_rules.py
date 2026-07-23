#!/usr/bin/env python3
"""Build the deterministic 20-rule deployment artifact and manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from rulelib import ELASTIC_DIR, ROOT, load_json, load_metadata

sys.path.insert(0, str(ROOT.parent / "scripts"))
from utilities.release_contract import (  # noqa: E402
    DEFERRED_COUNT,
    EXCLUDED_IDS,
    PROJECT_VERSION,
    SUPPORTED_COUNT,
    SUPPORTED_ELASTIC_VERSION,
    SUPPORTED_IDS,
)

REPOSITORY_ROOT = ROOT.parent
AUTHORITATIVE = REPOSITORY_ROOT / "deployment" / "rules_schema_1.1.0.ndjson"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "dist"


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(content)
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _authoritative_rules() -> tuple[list[dict[str, Any]], bytes]:
    content = AUTHORITATIVE.read_bytes()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("authoritative NDJSON is not UTF-8") from exc
    lines = text.splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise ValueError("authoritative NDJSON contains a blank record")
    try:
        rules = [json.loads(line) for line in lines]
    except json.JSONDecodeError as exc:
        raise ValueError(f"authoritative NDJSON is invalid at line {exc.lineno}: {exc.msg}") from exc
    ids = tuple(str(rule.get("rule_id", "")) for rule in rules)
    if ids != SUPPORTED_IDS or len(ids) != len(set(ids)):
        raise ValueError("authoritative NDJSON does not contain the exact ordered production set")
    if any(rule.get("enabled") is not False for rule in rules):
        raise ValueError("packaged rules must be disabled by default")
    expected = [load_json(ELASTIC_DIR / f"{rule_id}.json") for rule_id in SUPPORTED_IDS]
    if rules != expected:
        raise ValueError("per-rule JSON differs from the authoritative NDJSON")
    packageable = {rule["rule_id"] for rule in load_metadata() if rule["deployment"]["packageable"]}
    if packageable != set(SUPPORTED_IDS):
        raise ValueError("packageable metadata differs from the exact production set")
    return rules, content


def build(output_dir: Path) -> tuple[Path, Path, Path]:
    rules, ndjson = _authoritative_rules()
    ndjson_path = output_dir / "watchmyai-rules.ndjson"
    manifest_path = output_dir / "watchmyai-package-manifest.json"
    checksums_path = output_dir / "SHA256SUMS.txt"
    _atomic_write(ndjson_path, ndjson)
    manifest = {
        "format": 1,
        "project": "WatchMyAI",
        "version": PROJECT_VERSION,
        "package_type": "elastic-detection-rule-deployment",
        "rule_count": SUPPORTED_COUNT,
        "rule_ids": list(SUPPORTED_IDS),
        "excluded_rule_ids": list(EXCLUDED_IDS),
        "deferred_research_rule_count": DEFERRED_COUNT,
        "telemetry_schema_version": "1.1.0",
        "elastic_validated_version": SUPPORTED_ELASTIC_VERSION,
        "files": {
            ndjson_path.name: {
                "sha256": sha256(ndjson),
                "size": len(ndjson),
            }
        },
        "ndjson_sha256": sha256(ndjson),
        "live_validation": "separate; retained laboratory evidence is not a current connected run",
    }
    manifest_content = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(manifest_path, manifest_content)
    checksum_content = "".join(
        f"{sha256(path.read_bytes())}  {path.name}\n"
        for path in sorted((ndjson_path, manifest_path), key=lambda item: item.name)
    ).encode("ascii")
    _atomic_write(checksums_path, checksum_content)
    if len(rules) != SUPPORTED_COUNT:
        raise ValueError(f"expected {SUPPORTED_COUNT} rules, found {len(rules)}")
    return ndjson_path, manifest_path, checksums_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--skip-validation", action="store_true")
    args = parser.parse_args()
    if not args.skip_validation:
        result = subprocess.run([sys.executable, "scripts/validate.py"], cwd=ROOT, check=False)
        if result.returncode:
            return result.returncode
    try:
        paths = build(args.output_dir.resolve())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Refusing rule package: {exc}", file=sys.stderr)
        return 1
    print(f"Built {paths[0]} ({SUPPORTED_COUNT} disabled rules)")
    print(f"Built {paths[1]} (rule IDs, versions, and file hashes)")
    print(f"Built {paths[2]} (SHA-256 checksums)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
