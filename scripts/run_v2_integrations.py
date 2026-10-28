#!/usr/bin/env python3
"""Run the Version 2 detection-integration toolchain end to end.

Steps: Sigma conversion (determinism check, then staging), candidate contract validation,
fixture semantics, and D3FEND mapping validation. Nothing is imported into Elastic and the
production rule pack is never modified. Also checks Sysmon sample documents against the ECS field
contract (or --sysmon-fixture FILE) and runs agent-to-endpoint correlation on sample events. Run
scripts/validate/verify_sysmon_ingest.py and correlate_agent_endpoint.py without arguments to use
them against a live deployment.

Usage:
    python scripts/run_v2_integrations.py [--output dist/sigma-candidates]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--output", default="dist/sigma-candidates")
    parser.add_argument("--sysmon-fixture", help="saved Sysmon documents (JSON list) to validate")
    args = parser.parse_args(argv)

    python = sys.executable
    steps = [
        ("Sigma conversion (determinism)", [python, "scripts/sigma/convert_candidates.py", "--check"]),
        (
            "Sigma conversion (stage)",
            [python, "scripts/sigma/convert_candidates.py", "--output", args.output],
        ),
        (
            "Sigma candidate contract",
            [python, "scripts/sigma/validate_candidates.py", "--strict", "--input", args.output],
        ),
        ("Sigma fixture semantics", [python, "scripts/sigma/compare_semantics.py", "--input", args.output]),
        ("D3FEND mappings", [python, "scripts/validate/validate_d3fend_mappings.py", "--offline"]),
    ]
    sysmon_fixtures = (
        [args.sysmon_fixture]
        if args.sysmon_fixture
        else [
            f"detection-rules/tests/sysmon/fixtures/{name}"
            for name in ("event11_create.json", "event23_delete.json", "event26_delete.json")
        ]
    )
    for fixture in sysmon_fixtures:
        steps.append(
            (
                f"Sysmon ECS field contract ({Path(fixture).name})",
                [python, "scripts/validate/verify_sysmon_ingest.py", "--fixture", fixture],
            )
        )
    steps.append(
        (
            "Agent-to-endpoint correlation",
            [
                python,
                "scripts/validate/correlate_agent_endpoint.py",
                "--agent-events",
                "detection-rules/tests/integration/fixtures/agent_events.json",
                "--endpoint-events",
                "detection-rules/tests/integration/fixtures/endpoint_events.json",
            ],
        )
    )
    failed: list[str] = []
    for title, command in steps:
        print(f"\n== {title}")
        if subprocess.run(command, cwd=ROOT, check=False).returncode != 0:  # noqa: S603
            failed.append(title)
    print()
    if failed:
        print(f"FAIL: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("PASS: Version 2 integration toolchain completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
