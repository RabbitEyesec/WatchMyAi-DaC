#!/usr/bin/env python3
"""Pin a MITRE D3FEND ontology snapshot (explicit maintainer operation, never run by CI).

Downloads the ontology JSON-LD (or ingests a file you downloaded yourself), records its
SHA-256 in detection-rules/detections/mappings/d3fend-ontology.lock.json, and stores the
snapshot next to it so validation is offline and reproducible.

Usage:
    python scripts/utilities/update_d3fend_snapshot.py --version 1.6.0
    python scripts/utilities/update_d3fend_snapshot.py --version 1.6.0 --from-file d3fend.json
    python scripts/utilities/update_d3fend_snapshot.py --version 1.6.0 --expected-sha256 <hex>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAPPINGS = ROOT / "detection-rules" / "detections" / "mappings"
LOCK = MAPPINGS / "d3fend-ontology.lock.json"
DEFAULT_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--version", required=True, help="ontology version being pinned, e.g. 1.6.0")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--from-file", type=Path, help="ingest a file you downloaded and checked yourself")
    parser.add_argument("--expected-sha256", help="refuse the snapshot unless it has this digest")
    args = parser.parse_args(argv)

    try:
        if args.from_file:
            data = args.from_file.read_bytes()
        else:
            with urllib.request.urlopen(args.url, timeout=60) as response:  # noqa: S310
                data = response.read()
        document = json.loads(data)
    except (OSError, ValueError) as exc:
        print(f"FAIL: could not obtain a valid D3FEND JSON document: {exc}", file=sys.stderr)
        return 1
    if not isinstance(document, dict) or "@graph" not in document:
        print("FAIL: document has no @graph; this is not the D3FEND JSON-LD ontology", file=sys.stderr)
        return 1
    digest = hashlib.sha256(data).hexdigest()
    if args.expected_sha256 and digest != args.expected_sha256.lower():
        print(f"FAIL: sha256 {digest} does not match expected {args.expected_sha256}", file=sys.stderr)
        return 1

    lock = json.loads(LOCK.read_text("utf-8"))
    relative = f"detection-rules/detections/mappings/snapshot/d3fend-{args.version}.json"
    target = ROOT / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    lock.update(
        ontology_version=args.version,
        source_url=str(args.from_file) if args.from_file else args.url,
        snapshot_path=relative,
        snapshot_status="PINNED",
        sha256=digest,
        retrieved_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    LOCK.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(f"Pinned D3FEND {args.version}: {relative} sha256={digest}")
    print("Review the licence note in the lock file, then update ontology_version in d3fend.yml if needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
