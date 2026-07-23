#!/usr/bin/env python3
"""Recover and synchronize the validated WatchMyAI schema 1.1.0 rule pack.

The committed NDJSON file is authoritative.  ``--recover-alert-export`` exists
only to recover that file from a laboratory alert export containing the rule
parameters that produced each alert.  Normal release work uses ``--sync`` or
``--check`` and does not require access to the laboratory export.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from utilities.release_contract import DEFERRED_IDS, PROJECT_VERSION, SUPPORTED_IDS  # noqa: E402

AUTHORITATIVE = ROOT / "deployment" / "rules_schema_1.1.0.ndjson"
ELASTIC_DIR = ROOT / "detection-rules" / "detections" / "elastic"
METADATA_DIR = ROOT / "detection-rules" / "detections" / "metadata"
RULES_ROOT = ROOT / "detection-rules"
RULE_FIELDS = {
    "author",
    "description",
    "enabled",
    "false_positives",
    "from",
    "index",
    "interval",
    "language",
    "license",
    "max_signals",
    "name",
    "note",
    "query",
    "references",
    "risk_score",
    "rule_id",
    "rule_source",
    "severity",
    "tags",
    "threshold",
    "to",
    "type",
    "version",
}
MANAGED_GLOBS = (
    "detection-rules/detections/elastic/WMAI-*.json",
    "detection-rules/detections/metadata/WMAI-*.yml",
    "detection-rules/playbooks/WMAI-*.md",
    "detection-rules/tests/fixtures/benign/WMAI-*.json",
    "detection-rules/tests/fixtures/malicious/WMAI-*.json",
    "detection-rules/tests/corpus/atomic/WMAI-*.json",
    "detection-rules/tests/corpus/conformance/WMAI-*.json",
    "detection-rules/tests/corpus/evasion/WMAI-*.json",
)
MANAGED_FILES = (
    "detection-rules/detections/manifest.yml",
    "detection-rules/tests/fixtures/manifest.json",
    "scenarios/definitions/supported-rules.json",
)


def load_ndjson(path: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for line_number, raw in enumerate(path.read_text("utf-8").splitlines(), 1):
        if not raw.strip():
            raise ValueError(f"{path}:{line_number}: blank NDJSON line")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: rule must be an object")
        rules.append(value)
    ids = [str(rule.get("rule_id", "")) for rule in rules]
    if tuple(ids) != SUPPORTED_IDS:
        raise ValueError(
            f"authoritative NDJSON must contain the ordered {len(SUPPORTED_IDS)}-rule production set; "
            f"found {ids!r}"
        )
    if any(rule.get("enabled") is not False for rule in rules):
        raise ValueError("authoritative source rules must be disabled by default")
    return rules


def _latest_live_rules(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text("utf-8"))
    alerts = payload.get("alerts")
    if not isinstance(alerts, list):
        raise ValueError("alert export must contain an alerts array")
    latest: dict[str, dict[str, Any]] = {}
    for item in alerts:
        source = item.get("_source", {}) if isinstance(item, dict) else {}
        rule_id = source.get("kibana.alert.rule.rule_id")
        if rule_id not in SUPPORTED_IDS:
            continue
        previous = latest.get(rule_id)
        updated = str(source.get("kibana.alert.rule.updated_at", ""))
        if previous is None or updated >= str(previous.get("kibana.alert.rule.updated_at", "")):
            latest[rule_id] = source
    missing = sorted(set(SUPPORTED_IDS) - set(latest))
    if missing:
        raise ValueError("alert export lacks validated rules: " + ", ".join(missing))
    rules: list[dict[str, Any]] = []
    for rule_id in SUPPORTED_IDS:
        source = latest[rule_id]
        parameters = source.get("kibana.alert.rule.parameters")
        if not isinstance(parameters, dict):
            raise ValueError(f"{rule_id}: alert has no rule parameters")
        rule = {key: value for key, value in parameters.items() if key in RULE_FIELDS}
        rule.update(
            {
                "enabled": False,
                "interval": source["kibana.alert.rule.interval"],
                "name": source["kibana.alert.rule.name"],
                "tags": source["kibana.alert.rule.tags"],
            }
        )
        if rule.get("rule_id") != rule_id:
            raise ValueError(f"{rule_id}: embedded rule_id mismatch")
        if rule_id in {"WMAI-023", "WMAI-024"}:
            rule["references"] = [
                "../docs/DETECTION_RULES.md",
                "https://www.elastic.co/docs/reference/ecs",
            ]
        rules.append(rule)
    return rules


def write_ndjson(path: Path, rules: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(
        json.dumps(rule, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n" for rule in rules
    )
    path.write_text(content, "utf-8", newline="\n")


def _note_sections(note: str) -> tuple[str, list[str], list[str]]:
    match = re.fullmatch(
        r"## Expected alert\n\n(?P<expected>.*?)\n\n"
        r"## Investigation\n\n(?P<investigation>.*?)\n\n"
        r"## Limitations\n\n(?P<limitations>.*)",
        note,
        flags=re.DOTALL,
    )
    if not match:
        raise ValueError("rule note does not use the release note structure")
    investigation = [
        re.sub(r"^\d+\.\s+", "", line) for line in match.group("investigation").splitlines() if line.strip()
    ]
    limitations = [
        re.sub(r"^-\s+", "", line) for line in match.group("limitations").splitlines() if line.strip()
    ]
    return match.group("expected"), investigation, limitations


def _query_fields(rule: dict[str, Any]) -> list[str]:
    fields = set(re.findall(r"(?<![\w.])([@A-Za-z_][\w.@-]*):", rule["query"]))
    threshold = rule.get("threshold", {})
    fields.update(threshold.get("field", []) if isinstance(threshold, dict) else [])
    return sorted(fields)


def sync_metadata(rule: dict[str, Any]) -> None:
    path = METADATA_DIR / f"{rule['rule_id']}.yml"
    metadata = yaml.safe_load(path.read_text("utf-8"))
    expected, investigation, limitations = _note_sections(rule["note"])
    category = next(
        tag
        for tag in rule["tags"]
        if tag not in {"WatchMyAI", "AI Agent", "Endpoint building block"}
        and not tag.startswith(("Maturity:", "Custom telemetry:", "schema-", "remediated-"))
    )
    metadata.update(
        {
            "name": rule["name"],
            "description": rule["description"],
            "category": category,
            "maturity": next(
                tag.split(":", 1)[1].strip() for tag in rule["tags"] if tag.startswith("Maturity:")
            ),
            "version": f"{rule['version']}.0.0",
            "author": rule["author"][0],
            "severity": rule["severity"],
            "risk_score": rule["risk_score"],
            "required_telemetry": [
                "WatchMyAI Telemetry Schema 1.1.0"
                if any(item.startswith("logs-watchmyai.events-") for item in rule["index"])
                else "Elastic Defend or Sysmon file events using ECS"
            ],
            "required_fields": _query_fields(rule),
            "data_sources": list(rule["index"]),
            "custom_telemetry": any(item.startswith("logs-watchmyai.events-") for item in rule["index"]),
            "endpoint_only": not any(item.startswith("logs-watchmyai.events-") for item in rule["index"]),
            "false_positives": rule["false_positives"],
            "investigation_steps": investigation,
            "limitations": limitations,
            "expected_alert": expected,
            "validation_scenario": (
                f"Generate isolated endpoint-native file events for SCN-{rule['rule_id']} "
                "under a run-ID path, confirm the source-event threshold for one "
                "process.entity_id, and require that entity in the resulting threshold alert."
                if rule["rule_id"] in {"WMAI-023", "WMAI-024"}
                else f"Ingest the schema 1.1.0 malicious fixture for SCN-{rule['rule_id']} "
                "and correlate the resulting alert to the fixture session and action IDs."
            ),
            "references": rule["references"],
            "traceability": [
                "../deployment/rules_schema_1.1.0.ndjson",
                "../docs/DETECTION_RULES.md",
            ],
        }
    )
    metadata.pop("efficacy", None)
    logic: dict[str, Any] = {"kind": rule["type"], "query": rule["query"]}
    if "threshold" in rule:
        logic["threshold"] = rule["threshold"]
    metadata["detection_logic"] = logic
    elastic: dict[str, Any] = {
        "type": rule["type"],
        "language": rule["language"],
        "query": rule["query"],
        "index_patterns": rule["index"],
        "interval": rule["interval"],
        "from": rule["from"],
        "enabled": False,
        "target_stack_versions": ["9.4.3"],
        "lab_tested_versions": ["9.4.3"],
    }
    if "threshold" in rule:
        elastic["threshold"] = rule["threshold"]
    metadata["elastic"] = elastic
    metadata["deployment"] = {
        "packageable": True,
        "status": "production_validated",
    }
    metadata["blocked_reason"] = None
    history = metadata.setdefault("history", [])
    reconciliation_entry = {
        "version": "1.1.0",
        "date": "2026-07-20",
        "author": "WatchMyAI release engineering",
        "change": "Reconciled with the rule validated in the Elastic laboratory.",
    }
    history[:] = [
        item for item in history if item.get("version") != "schema-1.1.0" and item != reconciliation_entry
    ]
    history.append(reconciliation_entry)
    path.write_text(
        yaml.safe_dump(metadata, sort_keys=False, width=100),
        "utf-8",
        newline="\n",
    )


def _base_event(rule_id: str, index: int = 0) -> dict[str, Any]:
    return {
        "@timestamp": f"2026-07-20T04:00:{index:02d}.000Z",
        "event": {
            "id": f"fixture-{rule_id}-{index:03d}",
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "tool_request",
            "dataset": "watchmyai.events",
            "provider": "watchmyai",
        },
        "host": {"name": "watchmyai-validation-host"},
        "process": {
            "entity_id": f"fixture-process-{rule_id}",
            "working_directory": "/tmp/watchmyai-validation",
        },
        "watchmyai": {
            "schema": {"version": "1.1.0"},
            "agent": {"id": "fixture-agent", "type": "known_ai_agent"},
            "attribution": {"level": "confirmed"},
            "session": {"id": f"fixture-session-{rule_id}"},
            "action": {"id": f"fixture-action-{rule_id}-{index:03d}"},
            "tool": {
                "name": "Bash",
                "category": "shell",
                "arguments": {"command": "echo safe"},
            },
        },
    }


def _fixture_events(rule: dict[str, Any], malicious: bool) -> list[dict[str, Any]]:
    rule_id = rule["rule_id"]
    if rule_id in {"WMAI-023", "WMAI-024"}:
        count = rule["threshold"]["value"] if malicious else rule["threshold"]["value"] - 1
        event_type = "change" if rule_id == "WMAI-023" else "deletion"
        events = []
        for index in range(count):
            event = _base_event(rule_id, index)
            event["event"].update(
                {
                    "category": ["file"],
                    "type": [event_type],
                    "action": "file_" + event_type,
                    "dataset": "endpoint.events.file",
                    "provider": "elastic_endpoint",
                }
            )
            event.pop("watchmyai")
            event["file"] = {"path": f"/tmp/watchmyai-validation/file-{index:03d}"}
            events.append(event)
        return events

    event = _base_event(rule_id)
    watchmyai = event["watchmyai"]
    tool = watchmyai["tool"]
    if not malicious:
        if rule_id == "WMAI-048":
            events = []
            for index in range(4):
                item = _base_event(rule_id, index)
                item["event"]["action"] = "policy_violation"
                item["watchmyai"]["policy"] = {"violation": {"type": "benign_validation"}}
                events.append(item)
            return events
        return [event]

    values: dict[str, tuple[str, str]] = {
        "WMAI-001": ("violation", "ai_access_outside_approved_workspace"),
        "WMAI-002": ("violation_file", "path_scope"),
        "WMAI-007": ("command", "sudo id"),
        "WMAI-009": ("violation", "approval_missing"),
        "WMAI-022": ("file_path", "/tmp/watchmyai-validation/.ssh/id_rsa"),
        "WMAI-025": ("file_path", "/tmp/watchmyai-validation/tool.exe"),
        "WMAI-030": ("command", "curl https://example.invalid/health"),
        "WMAI-051": ("violation", "unauthorized_shell_execution"),
        "WMAI-053": ("command", "ssh validation@example.invalid"),
        "WMAI-054": ("file_path", "/tmp/watchmyai-validation/.ssh/id_ed25519"),
        "WMAI-055": ("command", "git push origin validation"),
        "WMAI-057": ("file_path", "/tmp/watchmyai-validation/.env"),
        "WMAI-058": ("command", "printenv"),
        "WMAI-059": ("command", "aws configure list"),
        "WMAI-060": ("command", "docker ps"),
        "WMAI-061": ("command", "kubectl get pods"),
        "WMAI-063": ("command", "rm -rf ./disposable-build"),
    }
    if rule_id == "WMAI-048":
        events = []
        for index in range(5):
            item = _base_event(rule_id, index)
            item["event"]["action"] = "policy_violation"
            item["watchmyai"]["policy"] = {"violation": {"type": "validation_violation"}}
            events.append(item)
        return events
    kind, value = values[rule_id]
    if kind.startswith("violation"):
        event["event"]["action"] = "policy_violation"
        watchmyai["policy"] = {"violation": {"type": value}}
        if kind == "violation_file":
            tool["category"] = "file"
    else:
        tool["arguments"] = {kind: value}
        if kind == "command":
            event["process"]["command_line"] = value
        elif kind == "file_path":
            command = f"cat {value}"
            tool["arguments"]["command"] = command
            event["process"]["command_line"] = command
    return [event]


def sync_fixtures(rules: list[dict[str, Any]]) -> None:
    manifest: dict[str, dict[str, str]] = {}
    for rule in rules:
        rule_id = rule["rule_id"]
        manifest[rule_id] = {}
        for fixture_type, malicious in (("malicious", True), ("benign", False)):
            relative = Path("tests") / "fixtures" / fixture_type / f"{rule_id}.json"
            target = RULES_ROOT / relative
            fixture = {
                "case_id": f"{'positive' if malicious else 'negative'}-{rule_id}",
                "case_type": "deterministic_unit_fixture_not_measured_efficacy",
                "rule_id": rule_id,
                "expected_match": malicious,
                "events": _fixture_events(rule, malicious),
            }
            target.write_text(json.dumps(fixture, indent=2) + "\n", "utf-8", newline="\n")
            manifest[rule_id][fixture_type] = str(relative)
    (RULES_ROOT / "tests" / "fixtures" / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", "utf-8", newline="\n"
    )


def sync_playbooks(rules: list[dict[str, Any]]) -> None:
    for rule in rules:
        rule_id = rule["rule_id"]
        fields = _query_fields(rule)
        source = (
            "WatchMyAI schema 1.1.0 telemetry"
            if any(index.startswith("logs-watchmyai.events-") for index in rule["index"])
            else "ECS endpoint file telemetry"
        )
        correlation = (
            "Correlate the session and action IDs with adjacent WatchMyAI records."
            if source.startswith("WatchMyAI")
            else "Trace the run-ID file path to one `process.entity_id`, then match that "
            "entity in `kibana.alert.threshold_result.terms`."
        )
        threshold = ""
        if "threshold" in rule:
            threshold = (
                f"\nThreshold: {rule['threshold']['value']} events grouped by "
                + ", ".join(f"`{field}`" for field in rule["threshold"]["field"])
                + ".\n"
            )
        false_positives = "\n".join(f"- {item}" for item in rule["false_positives"])
        fields_list = "\n".join(f"- `{field}`" for field in fields)
        content = f"""# {rule_id}: {rule["name"]}

## Detection basis

Source: {source}.

```text
{rule["query"]}
```
{threshold}
## Triage

1. Confirm the alert's stable rule ID is `{rule_id}` and record its source event time.
2. Inspect the fields below and preserve the original source events:

{fields_list}

3. {correlation}
4. Determine whether the activity was approved, expected, and confined to its intended scope.

## Containment

If the activity is unauthorized, stop the affected session or process, isolate exposed credentials or resources, and preserve the alert and source telemetry. Do not disable the rule globally to resolve a single expected workflow.

## False-positive handling

{false_positives}

Use a narrowly scoped exception with an owner and expiry only after the activity is verified.

## Validation

Follow the [public verification guide](../../docs/VERIFICATION.md) for `SCN-{rule_id}`. A passing validation requires a current alert from `{rule_id}`; historical or uncorrelated alerts do not count.
"""
        (RULES_ROOT / "playbooks" / f"{rule_id}.md").write_text(content, "utf-8", newline="\n")


def sync_release_catalogs(rules: list[dict[str, Any]]) -> None:
    expected = set(SUPPORTED_IDS)
    rules_by_id = {rule["rule_id"]: rule for rule in rules}
    active_groups = [
        (RULES_ROOT / "playbooks", ".md"),
        (RULES_ROOT / "tests" / "fixtures" / "malicious", ".json"),
        (RULES_ROOT / "tests" / "fixtures" / "benign", ".json"),
        (RULES_ROOT / "tests" / "corpus" / "atomic", ".json"),
        (RULES_ROOT / "tests" / "corpus" / "evasion", ".json"),
        (RULES_ROOT / "tests" / "corpus" / "conformance", ".json"),
    ]
    for directory, suffix in active_groups:
        for path in directory.glob(f"WMAI-*{suffix}"):
            if path.stem not in expected:
                path.unlink()

    manifest = {
        "pack_id": "watchmyai-cli-detection-pack",
        "pack_version": PROJECT_VERSION,
        "telemetry_schema_version": "1.1.0",
        "rule_count": len(rules),
        "selected_rule_ids": list(SUPPORTED_IDS),
        "validation_scope": f"production-validated-v{PROJECT_VERSION}",
        "authoritative_rules": "../../deployment/rules_schema_1.1.0.ndjson",
        "deferred_catalog": "research/deferred-catalog",
    }
    (RULES_ROOT / "detections" / "manifest.yml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), "utf-8", newline="\n"
    )
    scenarios = {
        "version": PROJECT_VERSION,
        "scenarios": [
            {
                "scenario_id": f"SCN-{rule_id}",
                "rule_id": rule_id,
                "platforms": ["neutral"],
                "fixture": f"detection-rules/tests/fixtures/malicious/{rule_id}.json",
                "destructive": rule_id in {"WMAI-023", "WMAI-024", "WMAI-025"},
                "ingest_mode": (
                    "endpoint_native" if rule_id in {"WMAI-023", "WMAI-024"} else "watchmyai_fixture"
                ),
            }
            for rule_id in SUPPORTED_IDS
        ],
    }
    (ROOT / "scenarios" / "definitions" / "supported-rules.json").write_text(
        json.dumps(scenarios, indent=2) + "\n", "utf-8", newline="\n"
    )
    for path in (RULES_ROOT / "tests" / "corpus" / "conformance").glob("WMAI-*.json"):
        value = json.loads(path.read_text("utf-8"))
        rule = rules_by_id[path.stem]
        value["schema_version"] = "1.1.0"
        value["required_fields"] = _query_fields(rule)
        value["required_correlations"] = (
            ["process.entity_id"]
            if path.stem in {"WMAI-023", "WMAI-024"}
            else ["watchmyai.session.id", "watchmyai.action.id"]
        )
        value["prohibited_fields"] = [
            "watchmyai.approval.id",
            "watchmyai.prompt.text",
            "secret.value",
        ]
        value["status"] = "REQUIRES_LIVE_PRODUCER"
        value.pop("result", None)
        path.write_text(json.dumps(value, indent=2) + "\n", "utf-8", newline="\n")

    for rule in rules:
        rule_id = rule["rule_id"]
        events = _fixture_events(rule, malicious=True)
        atomic = {
            "atomic_id": f"ATOMIC-{rule_id.removeprefix('WMAI-')}-BASE",
            "rule_id": rule_id,
            "tier": "T3" if rule_id in {"WMAI-023", "WMAI-024"} else "T1",
            "execution": "real_adapter_required",
            "safety": ("isolated_lab_only; destructive effects must be redirected to disposable resources"),
            "input": events[0],
            "event_count": len(events),
            "expected": {
                "runtime": "schema_1.1.0_event_emitted",
                "elastic_alerts": 1,
            },
        }
        (RULES_ROOT / "tests" / "corpus" / "atomic" / f"{rule_id}.json").write_text(
            json.dumps(atomic, indent=2) + "\n", "utf-8", newline="\n"
        )


def sync(rules: list[dict[str, Any]]) -> None:
    expected = set(SUPPORTED_IDS)
    for path in [*ELASTIC_DIR.glob("WMAI-*.json"), *METADATA_DIR.glob("WMAI-*.yml")]:
        if path.stem not in expected:
            path.unlink()
    for rule in rules:
        target = ELASTIC_DIR / f"{rule['rule_id']}.json"
        target.write_text(
            json.dumps(rule, indent=2, ensure_ascii=False) + "\n",
            "utf-8",
            newline="\n",
        )
        sync_metadata(rule)
    sync_playbooks(rules)
    sync_release_catalogs(rules)
    sync_fixtures(rules)


def check(rules: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    deferred_paths = sorted((RULES_ROOT / "research" / "deferred-catalog" / "metadata").glob("WMAI-*.yml"))
    if tuple(path.stem for path in deferred_paths) != DEFERRED_IDS:
        errors.append("deferred research catalog does not contain exactly the 45 deferred IDs")
    actual_paths = sorted(ELASTIC_DIR.glob("WMAI-*.json"))
    if {path.stem for path in actual_paths} != set(SUPPORTED_IDS):
        errors.append("per-rule Elastic files do not contain exactly the production IDs")
    for rule in rules:
        path = ELASTIC_DIR / f"{rule['rule_id']}.json"
        if not path.is_file() or json.loads(path.read_text("utf-8")) != rule:
            errors.append(f"{rule['rule_id']}: per-rule JSON differs from authoritative NDJSON")
        metadata_path = METADATA_DIR / f"{rule['rule_id']}.yml"
        if not metadata_path.is_file():
            errors.append(f"{rule['rule_id']}: metadata is missing")
            continue
        metadata = yaml.safe_load(metadata_path.read_text("utf-8"))
        elastic = metadata.get("elastic", {})
        comparisons = {
            "name": metadata.get("name"),
            "description": metadata.get("description"),
            "severity": metadata.get("severity"),
            "risk_score": metadata.get("risk_score"),
            "query": elastic.get("query"),
            "type": elastic.get("type"),
            "language": elastic.get("language"),
            "index": elastic.get("index_patterns"),
            "interval": elastic.get("interval"),
            "from": elastic.get("from"),
        }
        expected = {key: rule[key] for key in comparisons}
        for key, actual in comparisons.items():
            if actual != expected[key]:
                errors.append(f"{rule['rule_id']}: metadata {key} differs from NDJSON")
    return errors


def _managed_snapshot(root: Path) -> dict[str, bytes]:
    paths = {root / relative for relative in MANAGED_FILES}
    for pattern in MANAGED_GLOBS:
        paths.update(root.glob(pattern))
    snapshot: dict[str, bytes] = {}
    for path in sorted(paths):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if "/detections/metadata/" in relative:
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            snapshot[relative] = json.dumps(value, sort_keys=True).encode()
        else:
            snapshot[relative] = path.read_bytes()
    return snapshot


def check_reproducible_sync() -> list[str]:
    """Regenerate in an isolated tree and reject stale or non-reproducible outputs."""
    with tempfile.TemporaryDirectory(prefix="watchmyai-rule-sync-") as directory:
        temporary_root = Path(directory) / "repository"
        temporary_root.mkdir()
        (temporary_root / "VERSION").write_bytes((ROOT / "VERSION").read_bytes())
        for relative in (
            "deployment",
            "scripts",
            "detection-rules/detections",
            "detection-rules/deployment",
            "detection-rules/playbooks",
            "detection-rules/research/deferred-catalog",
            "detection-rules/tests",
            "scenarios/definitions",
        ):
            shutil.copytree(ROOT / relative, temporary_root / relative)
        result = subprocess.run(
            [
                sys.executable,
                str(temporary_root / "scripts/rules/reconcile_rules.py"),
                "--sync",
            ],
            cwd=temporary_root,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            return [f"isolated rule regeneration failed: {result.stdout}{result.stderr}"]
        current = _managed_snapshot(ROOT)
        regenerated = _managed_snapshot(temporary_root)
        drift = sorted(
            path for path in set(current) | set(regenerated) if current.get(path) != regenerated.get(path)
        )
        return [f"generated rule artefact is stale: {path}" for path in drift]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=AUTHORITATIVE)
    parser.add_argument("--recover-alert-export", type=Path)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--sync", action="store_true")
    action.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        if args.recover_alert_export:
            recovered = _latest_live_rules(args.recover_alert_export)
            write_ndjson(args.source, recovered)
        rules = load_ndjson(args.source)
        if args.sync:
            sync(rules)
        errors = check(rules)
        if args.check:
            errors.extend(check_reproducible_sync())
    except (KeyError, OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: authoritative schema 1.1.0 pack matches {len(rules)} generated rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
