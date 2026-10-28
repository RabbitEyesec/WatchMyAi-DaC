#!/usr/bin/env python3
"""Convert reviewed Sigma sources into staged Elastic candidates (never production).

Usage:
    python scripts/sigma/convert_candidates.py --output dist/sigma-candidates
    python scripts/sigma/convert_candidates.py --check
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import candidate_lib as lib  # noqa: E402

DEFAULT_OUTPUT = lib.ROOT / "dist" / "sigma-candidates"
PRODUCTION_DIR = lib.ROOT / "detection-rules" / "detections"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="staging directory")
    parser.add_argument(
        "--check",
        action="store_true",
        help="convert twice in memory, require identical output, and write nothing",
    )
    parser.add_argument(
        "--allow-rejections",
        action="store_true",
        help="exit 0 even if some sources are rejected (they are still reported)",
    )
    args = parser.parse_args(argv)

    try:
        policy = lib.load_policy()
        candidates, rejected = lib.convert_all(policy)
        if args.check:
            again, _ = lib.convert_all(policy)
            if lib.dumps(candidates) != lib.dumps(again):
                print("FAIL: conversion is not deterministic", file=sys.stderr)
                return 1
    except lib.CandidateError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    for item in rejected:
        print(f"REJECTED {item['source']}: {item['code']}: {item['message']}", file=sys.stderr)

    if args.check:
        print(f"PASS: {len(candidates)} candidates deterministic, {len(rejected)} rejected, nothing written")
        return 0 if (not rejected or args.allow_rejections) else 1

    output = args.output.resolve()
    if output == PRODUCTION_DIR or PRODUCTION_DIR in output.parents:
        print("FAIL: refusing to write candidates into the production detections tree", file=sys.stderr)
        return 1
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    for candidate in candidates:
        (output / f"{candidate['watchmyai_rule_id']}.candidate.json").write_text(
            lib.dumps(candidate), encoding="utf-8"
        )
    (output / "manifest.json").write_text(
        lib.dumps(lib.build_manifest(candidates, rejected)), encoding="utf-8"
    )
    print(f"Wrote {len(candidates)} candidates to {lib.rel(output)} ({len(rejected)} rejected)")
    print("Candidates are disabled, require review, and are not deployable.")
    return 0 if (not rejected or args.allow_rejections) else 1


if __name__ == "__main__":
    raise SystemExit(main())
