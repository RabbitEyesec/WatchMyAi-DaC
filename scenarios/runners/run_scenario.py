#!/usr/bin/env python3
"""Generate one safe, correlated supported-rule scenario as telemetry NDJSON."""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts/validate"))

from utilities.release_contract import (  # noqa: E402
    EXIT_SAFETY,
    SUPPORTED_IDS,
    load_dotenv,
    parse_bool,
    require_safe_workspace,
    resolve_repository_path,
)
from validate_ndjson import validate_file  # noqa: E402


def current_platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    return "other"


def load_scenarios() -> dict[str, dict[str, Any]]:
    path = ROOT / "scenarios/definitions/supported-rules.json"
    payload = json.loads(path.read_text("utf-8"))
    return {item["rule_id"]: item for item in payload["scenarios"]}


def platform_supported(scenario: dict[str, Any], actual: str) -> bool:
    platforms = set(scenario["platforms"])
    if "neutral" in platforms:
        return True
    if actual == "linux" and "disposable-linux" in platforms:
        return True
    return actual in platforms


def _load_config(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise ValueError(f"configuration file not found: {path}")
    values = load_dotenv(path)
    return {key: os.environ.get(key, value) for key, value in values.items()}


def _fixture_events(path: Path) -> list[dict[str, Any]]:
    fixture = json.loads(path.read_text("utf-8"))
    events = fixture.get("events")
    return copy.deepcopy(events if isinstance(events, list) else [fixture])


def correlate_events(
    events: list[dict[str, Any]],
    *,
    rule_id: str,
    scenario_id: str,
    run_id: str,
    session_id: str,
    started_at: datetime,
) -> list[dict[str, Any]]:
    for index, event in enumerate(events):
        timestamp = started_at + timedelta(milliseconds=index * 250)
        event["@timestamp"] = timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        event.setdefault("event", {})["id"] = f"{run_id}-event-{index:03d}"
        if event["event"].get("dataset") != "watchmyai.events":
            continue
        watchmyai = event.setdefault("watchmyai", {})
        watchmyai.setdefault("session", {})["id"] = session_id
        watchmyai.setdefault("action", {})["id"] = f"{run_id}-action-{index:03d}"
        context = watchmyai.setdefault("context", {})
        context.update(
            {
                "validation_run_id": run_id,
                "scenario_id": scenario_id,
                "rule_id": rule_id,
            }
        )
    return events


def _safe_side_effects(rule_id: str, workspace: Path, event_count: int) -> Path | None:
    if rule_id not in {"WMAI-023", "WMAI-024", "WMAI-025"}:
        return None
    scratch = workspace / "native-file-events"
    scratch.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    try:
        if rule_id == "WMAI-023":
            for index in range(event_count):
                target = scratch / f"write-{index:03d}.txt"
                target.write_text("synthetic WatchMyAI validation data\n", "utf-8")
                created.append(target)
            # Preserve these harmless files as current-run evidence. Deleting them here
            # would also generate WMAI-024 input from the WMAI-023 scenario.
            return scratch
        elif rule_id == "WMAI-024":
            for index in range(event_count):
                target = scratch / f"delete-{index:03d}.txt"
                target.write_text("disposable\n", "utf-8")
                created.append(target)
            for target in created:
                target.unlink()
            created.clear()
            return scratch
        elif rule_id == "WMAI-025":
            target = scratch / "harmless-validation-executable.txt"
            target.write_text("This file contains no executable payload.\n", "utf-8")
            target.chmod(0o700)
            created.append(target)
        return None
    except Exception:
        for target in created:
            target.unlink(missing_ok=True)
        try:
            scratch.rmdir()
        except OSError:
            pass
        raise
    finally:
        if rule_id == "WMAI-025":
            for target in created:
                target.unlink(missing_ok=True)
            try:
                scratch.rmdir()
            except OSError:
                pass


def write_scenario(
    rule_id: str,
    *,
    config_path: Path,
    platform_name: str | None = None,
) -> dict[str, Any]:
    scenarios = load_scenarios()
    if set(scenarios) != set(SUPPORTED_IDS):
        raise ValueError("scenario catalog does not match the supported rule set")
    scenario = scenarios[rule_id]
    actual_platform = platform_name or current_platform()
    if not platform_supported(scenario, actual_platform):
        return {
            "status": "SKIPPED",
            "rule_id": rule_id,
            "scenario_id": scenario["scenario_id"],
            "reason": (f"requires {scenario['platforms']}; current platform is {actual_platform}"),
        }
    config = _load_config(config_path)
    if not parse_bool(config.get("WATCHMYAI_LAB_MODE", "false"), name="WATCHMYAI_LAB_MODE"):
        raise PermissionError("WATCHMYAI_LAB_MODE=true is required for scenario execution")
    workspace = resolve_repository_path(config["WATCHMYAI_TEST_WORKSPACE"])
    require_safe_workspace(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    run_id = f"wmai-{uuid.uuid4().hex}"
    session_id = f"session-{run_id}"
    started_at = datetime.now(UTC)
    run_dir = workspace / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    events = correlate_events(
        _fixture_events(ROOT / scenario["fixture"]),
        rule_id=rule_id,
        scenario_id=scenario["scenario_id"],
        run_id=run_id,
        session_id=session_id,
        started_at=started_at,
    )
    native_path = _safe_side_effects(rule_id, run_dir, len(events))
    output = run_dir / f"{rule_id}.ndjson"
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n")
    ingest_mode = scenario.get("ingest_mode", "watchmyai_fixture")
    count, errors = validate_file(output, telemetry_schema=ingest_mode == "watchmyai_fixture")
    if errors:
        raise ValueError("; ".join(errors))
    ended_at = datetime.now(UTC)
    return {
        "status": "PASS",
        "run_id": run_id,
        "scenario_id": scenario["scenario_id"],
        "rule_id": rule_id,
        "session_id": session_id,
        "platform": actual_platform,
        "start_timestamp": started_at.isoformat(),
        "end_timestamp": ended_at.isoformat(),
        "record_count": count,
        "ingest_mode": ingest_mode,
        "telemetry_path": str(output),
        "native_path_marker": str(native_path) if native_path else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule-id", required=True, choices=SUPPORTED_IDS)
    parser.add_argument("--config", type=Path, default=ROOT / ".env")
    parser.add_argument("--platform", choices=["windows", "linux", "other"])
    args = parser.parse_args()
    try:
        result = write_scenario(
            args.rule_id,
            config_path=args.config,
            platform_name=args.platform,
        )
    except (KeyError, OSError, PermissionError, ValueError) as exc:
        print(json.dumps({"status": "ERROR", "rule_id": args.rule_id, "error": str(exc)}))
        return EXIT_SAFETY
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
