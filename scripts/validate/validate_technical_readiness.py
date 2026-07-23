#!/usr/bin/env python3
"""Validate the machine-readable WatchMyAI technical-readiness declaration."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))

from utilities.release_contract import (  # noqa: E402
    EXIT_VALIDATION,
    REPOSITORY_ROOT,
    validate_technical_readiness,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=REPOSITORY_ROOT / "release/technical-readiness.json",
    )
    args = parser.parse_args()
    try:
        payload = json.loads(args.path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: invalid technical readiness file: {exc}", file=sys.stderr)
        return EXIT_VALIDATION
    errors = validate_technical_readiness(payload)
    if errors:
        print("FAIL: inconsistent technical readiness declaration", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return EXIT_VALIDATION
    print(f"PASS: technical readiness declaration is consistent ({args.path})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
