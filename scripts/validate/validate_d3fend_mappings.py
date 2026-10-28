#!/usr/bin/env python3
"""Validate the reviewed D3FEND sidecar mappings against a pinned, offline ontology snapshot.

Rules (all fail closed):
* the sidecar covers exactly the 20 production rules, once each;
* ``mapped`` items need well-formed D3FEND IDs, a rationale, and ``mapped_by`` / ``mapped_at``;
  ``unmapped`` items need a rationale and no techniques;
* when an ontology snapshot is pinned, every technique must exist in it and not be deprecated, and
  the snapshot must match the SHA-256 recorded in the lock file.

The tool never uses the network and never changes detection rules or policy enforcement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.utilities.release_contract import SUPPORTED_RULES  # noqa: E402

MAPPINGS = ROOT / "detection-rules" / "detections" / "mappings"
SIDECAR = MAPPINGS / "d3fend.yml"
LOCK = MAPPINGS / "d3fend-ontology.lock.json"
STATUSES = {"mapped", "unmapped"}
D3_ID = re.compile(r"^D3-[A-Z0-9]+$")
ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
REQUIRED = {
    "watchmyai_id",
    "kind",
    "mapping_status",
    "defensive_techniques",
    "related_attack_techniques",
    "rationale",
    "evidence_source",
    "mapped_by",
    "mapped_at",
}


def load_snapshot_index(path: Path) -> dict[str, dict[str, Any]]:
    """Index technique IDs from the D3FEND JSON-LD graph: id -> {label, deprecated}."""
    document = json.loads(path.read_text("utf-8"))
    index: dict[str, dict[str, Any]] = {}
    for node in document.get("@graph", []):
        if not isinstance(node, dict):
            continue
        ids = node.get("d3f:d3fend-id")
        for ident in ids if isinstance(ids, list) else [ids]:
            if isinstance(ident, str) and D3_ID.match(ident):
                label = node.get("rdfs:label")
                deprecated = node.get("owl:deprecated")
                index[ident] = {
                    "label": label if isinstance(label, str) else None,
                    "deprecated": deprecated in (True, "true")
                    or (isinstance(deprecated, dict) and deprecated.get("@value") in (True, "true")),
                }
    return index


def validate(sidecar: Path = SIDECAR, lock_path: Path = LOCK) -> tuple[list[str], dict[str, int]]:
    errors: list[str] = []
    counts = {"mapped": 0, "unmapped": 0}
    data = yaml.safe_load(sidecar.read_text("utf-8"))
    lock = json.loads(lock_path.read_text("utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        return ["sidecar schema_version must be 1"], counts
    if data.get("ontology_version") != lock.get("ontology_version"):
        errors.append(
            f"ontology_version {data.get('ontology_version')} differs from lock {lock.get('ontology_version')}"
        )

    index: dict[str, dict[str, Any]] | None = None
    snapshot_path = ROOT / str(lock.get("snapshot_path", ""))
    if lock.get("snapshot_status") == "PINNED":
        if not snapshot_path.is_file():
            errors.append(f"lock says PINNED but {lock.get('snapshot_path')} is missing")
        elif hashlib.sha256(snapshot_path.read_bytes()).hexdigest() != lock.get("sha256"):
            errors.append("snapshot sha256 does not match the lock file")
        else:
            index = load_snapshot_index(snapshot_path)
            if not index:
                errors.append("snapshot contains no D3FEND technique IDs; refusing to trust it")
                index = None

    items = data.get("items") or []
    seen: set[str] = set()
    for item in items:
        rid = str(item.get("watchmyai_id"))
        label = f"{rid}"
        if missing := REQUIRED - set(item):
            errors.append(f"{label}: missing fields {sorted(missing)}")
            continue
        if rid in seen:
            errors.append(f"{label}: duplicate item")
        seen.add(rid)
        status = item["mapping_status"]
        if status not in STATUSES:
            errors.append(f"{label}: unknown mapping_status {status!r}")
            continue
        counts[status] += 1
        evidence = ROOT / str(item["evidence_source"])
        if not evidence.is_file():
            errors.append(f"{label}: evidence_source {item['evidence_source']} does not exist")
        techniques = item["defensive_techniques"] or []
        attack = item["related_attack_techniques"] or []
        if len(set(techniques)) != len(techniques):
            errors.append(f"{label}: duplicate defensive techniques")
        for ident in attack:
            if not ATTACK_ID.match(str(ident)):
                errors.append(f"{label}: malformed ATT&CK ID {ident!r}")
        if len(str(item["rationale"]).strip()) < 20:
            errors.append(f"{label}: {status} requires a rationale of at least 20 characters")
        if status == "unmapped":
            if techniques:
                errors.append(f"{label}: unmapped items cannot list techniques")
            continue
        if not techniques:
            errors.append(f"{label}: mapped items need at least one defensive technique")
        if not item["mapped_by"] or not item["mapped_at"]:
            errors.append(f"{label}: mapped items need mapped_by and mapped_at")
        for ident in techniques:
            if not D3_ID.match(str(ident)):
                errors.append(f"{label}: malformed D3FEND ID {ident!r}")
            elif index is not None and ident not in index:
                errors.append(f"{label}: {ident} does not exist in ontology {lock['ontology_version']}")
            elif index is not None and index[ident]["deprecated"]:
                errors.append(f"{label}: {ident} is deprecated in ontology {lock['ontology_version']}")

    if seen != set(SUPPORTED_RULES):
        errors.append(
            f"items must cover exactly the production rules; missing={sorted(set(SUPPORTED_RULES) - seen)} "
            f"extra={sorted(seen - set(SUPPORTED_RULES))}"
        )
    return errors, counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        "--offline", action="store_true", help="accepted for clarity; this tool is always offline"
    )
    parser.add_argument(
        "--require-snapshot",
        action="store_true",
        help="fail unless a D3FEND ontology snapshot is pinned and every technique resolves in it",
    )
    args = parser.parse_args(argv)
    errors, counts = validate()
    pinned = json.loads(LOCK.read_text("utf-8")).get("snapshot_status") == "PINNED"
    if args.require_snapshot and not pinned:
        errors.append("no ontology snapshot is pinned; run scripts/utilities/update_d3fend_snapshot.py")
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: D3FEND mappings valid (mapped={counts['mapped']}, unmapped={counts['unmapped']})")
    if not pinned:
        print(
            "Tip: pin D3FEND with scripts/utilities/update_d3fend_snapshot.py to also resolve every ID in the ontology."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
