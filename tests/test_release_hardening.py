from __future__ import annotations

import csv
import importlib
import json
import os
import re
import sys
import tomllib
import urllib.parse
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from watchmyai import onboarding
from watchmyai.adapters.claude_code import installer as claude_installer
from watchmyai.adapters.codex_cli import installer as codex_installer
from watchmyai.schema.event import validate_event

from scenarios.runners.run_scenario import (
    correlate_events,
    load_scenarios,
    platform_supported,
    write_scenario,
)
from scripts.utilities import build_source_archive as source_archive_module
from scripts.utilities.build_release import build as build_release
from scripts.utilities.build_source_archive import build as build_source_archive
from scripts.utilities.build_source_archive import release_files
from scripts.utilities.release_contract import (
    DEFERRED_COUNT,
    DEFERRED_IDS,
    EXCLUDED_COUNT,
    EXCLUDED_RULES,
    SUPPORTED_COUNT,
    SUPPORTED_RULES,
    require_safe_workspace,
    stale_active_scope_lines,
    validate_technical_readiness,
)
from scripts.validate.run_supported_rules import (
    AlertClient,
    _poll_alert,
    _poll_native_source_evidence,
    _run_live,
    alert_is_current,
    native_source_evidence,
    threshold_alert_matches_entity,
)
from scripts.validate.validate_config import validate_config
from scripts.validate.validate_ndjson import validate_file

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "detection-rules"
importer = importlib.import_module("scripts.import.import_rules")


def test_supported_python_version_is_consistent() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
    assert project["project"]["requires-python"] == ">=3.11,<3.13"
    assert project["tool"]["ruff"]["target-version"] == "py311"
    assert project["tool"]["mypy"]["python_version"] == "3.11"

    workflow = (ROOT / ".github/workflows/watchmyai-ci.yml").read_text("utf-8")
    assert 'python: ["3.11", "3.12"]' in workflow
    assert 'python: ["3.10"' not in workflow

    doctor = (ROOT / "telemetry-gateway/src/watchmyai/cli/main.py").read_text("utf-8")
    assert '"Python 3.11 or 3.12"' in doctor


def test_github_actions_are_pinned_to_immutable_commits() -> None:
    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        for number, line in enumerate(workflow.read_text("utf-8").splitlines(), 1):
            match = re.search(r"\buses:\s+([^\s#]+)", line)
            if match and not match.group(1).startswith("./"):
                assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", match.group(1)), (
                    f"{workflow.name}:{number}: {match.group(1)}"
                )


def test_source_archive_is_deterministic_and_excludes_local_state(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    build_source_archive(first)
    build_source_archive(second)

    assert first.read_bytes() == second.read_bytes()
    assert first.stat().st_size < 10 * 1024 * 1024
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert not any(
            ".local-evidence" in name or name.startswith("screenshots/") or ".egg-info/" in name
            for name in names
        )


def test_source_archive_no_git_fallback_is_strict(tmp_path: Path) -> None:
    source = tmp_path / "source"
    required = {
        ".env.example": "SAFE=value\n",
        "LICENSE": "synthetic licence\n",
        "QUICKSTART.md": "# Quick start\n",
        "README.md": "# WatchMyAI\n",
        "VERSION": "1.0.0\n",
        "deployment/rules_schema_1.1.0.ndjson": "{}\n",
        "detection-rules/detections/manifest.yml": "rule_count: 20\n",
        "detection-rules/tests/fixtures/manifest.json": "{}\n",
        "docs/DETECTION_RULES.md": "# Detection rules\n",
        "docs/assets/screenshots/elastic-watchmyai-alerts.png": "reviewed public image",
        "docs/assets/screenshots/elastic-watchmyai-events.png": "reviewed public image",
        "pyproject.toml": "[build-system]\n",
        "scripts/install/install.ps1": "exit 0\n",
        "scripts/install/install.sh": "#!/usr/bin/env bash\n",
        "telemetry-gateway/deployment/elastic/load-assets.sh": "#!/usr/bin/env bash\n",
        "telemetry-gateway/src/watchmyai/__init__.py": "__version__ = '1.0.0'\n",
    }
    for relative, content in required.items():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, "utf-8")
    forbidden = {
        ".local-evidence/report.json": "private",
        ".venv/lib/package.py": "generated",
        "local-reports/internal-validation-report.docx": "private report",
        "screenshots/current.png": "binary-like",
        "tmp-screenshots/current.png": "temporary image",
        "dist/nested.zip": "archive",
        ".env": "SECRET=value",
        "runtime/events.jsonl": "local",
        "WatchMyAI Validation Report working.docx": "private",
    }
    for relative, content in forbidden.items():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, "utf-8")

    archive_path = tmp_path / "source.zip"
    build_source_archive(archive_path, root=source)

    with zipfile.ZipFile(archive_path) as archive:
        names = set(archive.namelist())
    assert set(required) <= names
    assert not (set(forbidden) & names)


def test_source_archive_git_inventory_excludes_arbitrary_untracked_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    tracked: list[str] = []
    for relative in sorted(source_archive_module.REQUIRED_FILES):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
        tracked.append(relative)
    untracked = source / "notes" / "local-observation.txt"
    untracked.parent.mkdir(parents=True)
    untracked.write_text("must not be packaged\n", "utf-8")
    (source / ".git").mkdir()

    monkeypatch.setattr(source_archive_module, "_has_git_head", lambda _root: True)
    monkeypatch.setattr(
        source_archive_module.subprocess,
        "check_output",
        lambda *_args, **_kwargs: b"\0".join(item.encode() for item in tracked) + b"\0",
    )

    archive_path = tmp_path / "tracked-only.zip"
    source_archive_module.build(archive_path, root=source)
    with zipfile.ZipFile(archive_path) as archive:
        names = set(archive.namelist())
    assert set(tracked) <= names
    assert "notes/local-observation.txt" not in names


def test_release_build_does_not_write_generated_metadata_into_source(tmp_path: Path) -> None:
    generated = [ROOT / "build", ROOT / "telemetry-gateway/src/WatchMyAI.egg-info"]
    assert not any(path.exists() for path in generated)
    artifacts = build_release(tmp_path / "release")
    assert {path.name for path in artifacts} == {
        "SHA256SUMS.txt",
        "WatchMyAI-v1.0.0-source.zip",
        "watchmyai-1.0.0-py3-none-any.whl",
        "watchmyai-1.0.0.tar.gz",
        "watchmyai-package-manifest.json",
        "watchmyai-rules.ndjson",
    }
    assert not any(path.exists() for path in generated)


def test_shebang_entry_points_are_executable() -> None:
    required = {
        "detection-rules/deployment/export_rules.sh",
        "detection-rules/scripts/package_rules.py",
        "detection-rules/scripts/smoke_test_elastic.py",
        "detection-rules/scripts/validate.py",
        "scenarios/runners/run_scenario.py",
        "scripts/import/import_rules.py",
        "scripts/install/install.sh",
        "scripts/preflight.py",
        "scripts/validate/preflight.sh",
        "scripts/validate/run_supported_rules.py",
        "scripts/validate/validate_config.py",
        "scripts/validate/validate_ndjson.py",
        "scripts/validate/validate_telemetry_schema.py",
        "telemetry-gateway/deployment/elastic/load-assets.sh",
    }
    for relative in sorted(required):
        path = ROOT / relative
        assert path.read_bytes().startswith(b"#!"), relative
        assert os.access(path, os.X_OK), relative

    for path in release_files(ROOT):
        if path.suffix in {".py", ".sh"} and path.read_bytes().startswith(b"#!"):
            assert os.access(path, os.X_OK), path.relative_to(ROOT)

    rule_library = ROOT / "detection-rules/scripts/rulelib.py"
    assert not rule_library.read_bytes().startswith(b"#!")
    assert not os.access(rule_library, os.X_OK)


def test_exact_supported_and_excluded_release_sets() -> None:
    manifest = yaml.safe_load((RULES / "detections/manifest.yml").read_text("utf-8"))
    excluded = json.loads((ROOT / "release/excluded-rules.json").read_text("utf-8"))
    assert manifest["rule_count"] == SUPPORTED_COUNT
    assert manifest["selected_rule_ids"] == list(SUPPORTED_RULES)
    assert {item["rule_id"] for item in excluded["rules"]} == set(EXCLUDED_RULES)
    assert all(item["status"] == "excluded" for item in excluded["rules"])
    assert all(item["reason"] == "not validated in v1.0.0" for item in excluded["rules"])
    assert all(item["rule_name"] == EXCLUDED_RULES[item["rule_id"]] for item in excluded["rules"])
    assert all(item["future_telemetry_work_required"] is True for item in excluded["rules"])
    deferred = {path.stem for path in (RULES / "research/deferred-catalog/metadata").glob("WMAI-*.yml")}
    assert SUPPORTED_COUNT == 20
    assert EXCLUDED_COUNT == 10
    assert DEFERRED_COUNT == len(deferred) == 45
    assert deferred == set(DEFERRED_IDS)
    assert not (set(SUPPORTED_RULES) & set(EXCLUDED_RULES))
    assert not (set(SUPPORTED_RULES) & deferred)
    assert not (set(EXCLUDED_RULES) & deferred)


def test_retained_lab_summary_reconciles_to_remediation_matrix() -> None:
    summary = json.loads((ROOT / "release/validation/lab-results.json").read_text("utf-8"))
    with (ROOT / "deployment/remediation-matrix.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["rule_id"] for row in rows] == list(SUPPORTED_RULES)
    assert len(rows) == summary["watchmyai_rule_count"] == SUPPORTED_COUNT
    assert sum(int(row["validated_alert_count"]) for row in rows) == summary["watchmyai_alert_count"]
    assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in summary["source_evidence_sha256"].values())


def test_active_rule_files_and_titles_match_authoritative_contract() -> None:
    for directory, suffix in (("elastic", ".json"), ("metadata", ".yml")):
        paths = sorted((RULES / "detections" / directory).glob(f"WMAI-*{suffix}"))
        assert {path.stem for path in paths} == set(SUPPORTED_RULES)
    for rule_id, expected_name in SUPPORTED_RULES.items():
        payload = json.loads((RULES / "detections/elastic" / f"{rule_id}.json").read_text("utf-8"))
        assert payload["name"] == expected_name


def test_excluded_rules_are_absent_from_every_active_catalog() -> None:
    active_roots = [
        RULES / "detections",
        RULES / "playbooks",
        RULES / "tests/fixtures",
        RULES / "tests/corpus",
        ROOT / "scenarios",
    ]
    for active_root in active_roots:
        for path in active_root.rglob("*"):
            if path.is_file() and path.name != "supported-rules.json":
                assert path.stem not in EXCLUDED_RULES


def test_no_active_stale_rule_scope_in_release_text() -> None:
    ignored = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "runtime",
    }
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or set(path.relative_to(ROOT).parts) & ignored:
            continue
        findings.extend(
            f"{path.relative_to(ROOT)}:{line_number}" for line_number in stale_active_scope_lines(path)
        )
    assert findings == []


def test_stale_scope_checker_distinguishes_explicit_history(tmp_path: Path) -> None:
    stale_counts = ("2" + "2", "3" + "0")
    active = tmp_path / "active.md"
    valid = tmp_path / "valid.md"
    historical = tmp_path / "history.yaml"
    active.write_text(
        "".join(f"The active release supports {count} rules.\n" for count in stale_counts),
        "utf-8",
    )
    valid.write_text("The active release supports 20 rules.\n", "utf-8")
    historical.write_text(
        "note: 'Historical: the superseded release selected 30 rules.'\n",
        "utf-8",
    )

    assert stale_active_scope_lines(active) == [1, 2]
    assert stale_active_scope_lines(valid) == []
    assert stale_active_scope_lines(historical) == []


def test_canonical_dataset_in_all_active_fixtures_and_rules() -> None:
    for path in (RULES / "detections/metadata").glob("WMAI-*.yml"):
        rule = yaml.safe_load(path.read_text("utf-8"))
        if rule["custom_telemetry"]:
            assert 'event.dataset:"watchmyai.events"' in rule["elastic"]["query"]
        assert "event.dataset_name" not in rule["elastic"]["query"]
        assert "event.data_set" not in rule["elastic"]["query"]
    for path in (RULES / "tests/fixtures").glob("*/*.json"):
        fixture = json.loads(path.read_text("utf-8"))
        events = fixture.get("events", [fixture])
        assert all(
            event["event"]["dataset"] in {"watchmyai.events", "endpoint.events.file"} for event in events
        )


def test_schema_rejects_unknown_and_deprecated_dataset_fields() -> None:
    event = json.loads((ROOT / "fixtures/telemetry/canonical.ndjson").read_text("utf-8"))
    event["dataset"] = "watchmyai.events"
    assert any("Additional properties" in error for error in validate_event(event))
    event.pop("dataset")
    event["event"]["dataset_name"] = "watchmyai.events"
    assert any("Additional properties" in error for error in validate_event(event))


def test_redacted_tool_arguments_have_bounded_flexible_elastic_mapping() -> None:
    event = json.loads((ROOT / "fixtures/telemetry/canonical.ndjson").read_text("utf-8"))
    event["watchmyai"].setdefault("tool", {})["arguments"] = {
        "command": "echo safe",
        "adapter_specific_option": "synthetic",
    }
    assert validate_event(event) == []
    component = json.loads(
        (ROOT / "telemetry-gateway/deployment/elastic/component_template.json").read_text("utf-8")
    )
    arguments = component["template"]["mappings"]["properties"]["watchmyai"]["properties"]["tool"][
        "properties"
    ]["arguments"]
    assert arguments["type"] == "flattened"
    assert arguments["depth_limit"] == 10


def test_config_rejects_placeholders_and_original_machine_paths(tmp_path: Path) -> None:
    content = (ROOT / ".env.example").read_text("utf-8")
    config = tmp_path / ".env"
    config.write_text(content, "utf-8")
    assert any("placeholder" in error for error in validate_config(config))
    config.write_text(
        content.replace("__SET_ME__", "synthetic-value")
        .replace("repository-only", "windows-endpoint")
        .replace(
            "CLAUDE_SETTINGS_PATH=",
            "CLAUDE_SETTINGS_PATH=/Users/" + "abhinav" + "mac/.claude/settings.json",
        ),
        "utf-8",
    )
    assert any("original-machine" in error for error in validate_config(config))


@pytest.mark.parametrize(
    ("deployment_path", "address"),
    [
        ("/home/operator/watchmyai", "10.24.1.8"),
        (r"C:\Users\operator\WatchMyAI", "172.16.2.9"),
        ("/home/lab/watchmyai", "172.31.255.10"),
        (r"C:\Users\lab\WatchMyAI", "192.168.1.25"),
    ],
)
def test_config_allows_deployment_paths_and_rfc1918_addresses(
    tmp_path: Path, deployment_path: str, address: str
) -> None:
    values: dict[str, str] = {}
    for raw in (ROOT / ".env.example").read_text("utf-8").splitlines():
        if raw and not raw.startswith("#"):
            key, value = raw.split("=", 1)
            values[key] = "" if value == "__SET_ME__" else value
    values.update(
        {
            "ELASTICSEARCH_URL": f"https://{address}:9200",
            "KIBANA_URL": f"https://{address}:5601",
            "FLEET_SERVER_URL": f"https://{address}:8220",
            "FLEET_AGENT_POLICY_ID": "watchmyai-test-policy",
            "CLAUDE_SETTINGS_PATH": deployment_path,
            "TLS_VERIFY": "true",
        }
    )
    config = tmp_path / ".env"
    config.write_text("".join(f"{key}={value}\n" for key, value in values.items()), "utf-8")

    assert validate_config(config) == []


def test_config_rejects_insecure_tls_for_non_loopback_service(tmp_path: Path) -> None:
    values: dict[str, str] = {}
    for raw in (ROOT / ".env.example").read_text("utf-8").splitlines():
        if raw and not raw.startswith("#"):
            key, value = raw.split("=", 1)
            values[key] = "" if value == "__SET_ME__" else value
    values.update(
        {
            "ELASTICSEARCH_URL": "https://10.24.1.8:9200",
            "KIBANA_URL": "https://10.24.1.8:5601",
            "FLEET_SERVER_URL": "https://10.24.1.8:8220",
            "FLEET_AGENT_POLICY_ID": "watchmyai-test-policy",
            "TLS_VERIFY": "false",
        }
    )
    config = tmp_path / ".env"
    config.write_text("".join(f"{key}={value}\n" for key, value in values.items()), "utf-8")

    errors = validate_config(config)
    assert sum("TLS_VERIFY=false" in error for error in errors) == 3


def test_ndjson_validation_cases(tmp_path: Path) -> None:
    cases = {
        "valid.ndjson": ('{"value":1}\n{"value":"café 東京"}\n', True),
        "malformed.ndjson": ('{"value":}\n', False),
        "array.ndjson": ('[{"value":1}]\n', False),
        "blank.ndjson": ('{"value":1}\n\n', False),
        "multiline.ndjson": ('{\n"value":1\n}\n', False),
        "trailing.ndjson": ('{"value":1,}\n', False),
    }
    for name, (content, expected) in cases.items():
        path = tmp_path / name
        path.write_text(content, "utf-8")
        _, errors = validate_file(path)
        assert (not errors) is expected, (name, errors)


def test_importer_duplicate_prevention_and_unchanged_plan() -> None:
    expected = importer.load_active_rules(RULES / "detections/elastic")
    deployed = [dict(item, id=f"object-{index}") for index, item in enumerate(expected)]
    created, updated, unchanged = importer.plan_changes(expected, deployed)
    assert (created, updated) == ([], [])
    assert unchanged == list(SUPPORTED_RULES)
    deployed.append(dict(deployed[0], id="duplicate-object"))
    with pytest.raises(importer.ImportFailure, match="duplicate stable rule IDs"):
        importer.plan_changes(expected, deployed)


def test_importer_rejects_non_authoritative_rule_content(tmp_path: Path) -> None:
    for source in (RULES / "detections/elastic").glob("WMAI-*.json"):
        (tmp_path / source.name).write_bytes(source.read_bytes())
    changed = tmp_path / "WMAI-001.json"
    payload = json.loads(changed.read_text("utf-8"))
    payload["query"] = "event.dataset:tampered"
    changed.write_text(json.dumps(payload), "utf-8")
    with pytest.raises(importer.ImportFailure, match="authoritative NDJSON"):
        importer.load_active_rules(tmp_path)


@pytest.mark.parametrize(("configured", "expected_enabled"), [(None, 0), ("true", SUPPORTED_COUNT)])
def test_importer_requires_explicit_rule_enablement(
    monkeypatch: pytest.MonkeyPatch,
    configured: str | None,
    expected_enabled: int,
) -> None:
    source_rules = importer.load_active_rules(RULES / "detections/elastic")

    class FakeKibanaClient:
        instance: FakeKibanaClient | None = None

        def __init__(self, config: dict[str, str]):
            self.imported = False
            self.enabled = False
            self.enable_calls = 0
            FakeKibanaClient.instance = self

        def find_rules(self) -> list[dict[str, object]]:
            if not self.imported:
                return []
            return [
                dict(rule, id=f"object-{index}", enabled=self.enabled)
                for index, rule in enumerate(source_rules)
            ]

        def import_rules(self, content: bytes) -> dict[str, object]:
            assert content
            self.imported = True
            return {"success": True, "rules_count": SUPPORTED_COUNT, "errors": []}

        def enable(self, object_ids: list[str]) -> None:
            assert len(object_ids) == SUPPORTED_COUNT
            self.enable_calls += 1
            self.enabled = True

    config = {} if configured is None else {"ENABLE_RULES": configured}
    monkeypatch.setattr(importer, "_config", lambda _path: config)
    monkeypatch.setattr(importer, "KibanaClient", FakeKibanaClient)
    monkeypatch.setattr(
        importer.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(sys, "argv", ["import_rules.py"])

    assert importer.main() == 0
    instance = FakeKibanaClient.instance
    assert instance is not None
    assert instance.enable_calls == (1 if configured == "true" else 0)
    assert sum(item["enabled"] is True for item in instance.find_rules()) == expected_enabled


def test_technical_readiness_cannot_hide_failed_preflight() -> None:
    payload = json.loads((ROOT / "release/technical-readiness.json").read_text("utf-8"))
    assert validate_technical_readiness(payload) == []
    assert payload["live_end_to_end_validation"] == "SKIPPED"
    assert payload["rule_import"] == "DRY_RUN_PASS"
    assert payload["repository_controlled_blockers"] == []
    payload["preflight"] = "FAIL"
    errors = validate_technical_readiness(payload, repository_preflight_failed=True)
    assert any("preflight failed" in error for error in errors)


def test_claude_hook_merge_is_idempotent_and_quotes_spaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = tmp_path / "Program Files" / "WatchMyAI" / "watchmyai"
    adapter.parent.mkdir(parents=True)
    adapter.write_text("synthetic adapter", "utf-8")
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"theme": "dark", "hooks": {}}), "utf-8")
    monkeypatch.setenv("WATCHMYAI_ADAPTER_PATH", str(adapter))
    first = claude_installer.install(settings)
    second = claude_installer.install(settings)
    payload = json.loads(settings.read_text("utf-8"))
    assert first["events_added"]
    assert second["events_added"] == []
    assert second["backup"] is None
    assert payload["theme"] == "dark"
    assert claude_installer.status(settings)["duplicate_events"] == []
    commands = [
        hook["command"] for groups in payload["hooks"].values() for group in groups for hook in group["hooks"]
    ]
    assert all("Program Files" in command and command.endswith("hook claude") for command in commands)


def test_codex_hook_merge_is_atomic_idempotent_and_preserves_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = tmp_path / "Program Files" / "WatchMyAI" / "watchmyai"
    adapter.parent.mkdir(parents=True)
    adapter.write_text("synthetic adapter", "utf-8")
    hooks = tmp_path / "hooks.json"
    hooks.write_text(json.dumps({"theme": "dark", "hooks": {}}), "utf-8")
    monkeypatch.setenv("WATCHMYAI_ADAPTER_PATH", str(adapter))

    first = codex_installer.install(hooks)
    second = codex_installer.install(hooks)

    payload = json.loads(hooks.read_text("utf-8"))
    assert first["changed"] is True
    assert first["backup"]
    assert second["changed"] is False
    assert second["backup"] is None
    assert payload["theme"] == "dark"
    assert len(list(tmp_path.glob("hooks.json.wmai-backup-*"))) == 1
    assert all(
        "Program Files" in handler["command"] and handler["command"].endswith("hook codex")
        for groups in payload["hooks"].values()
        for group in groups
        for handler in group["hooks"]
    )


def test_generated_config_is_backed_up_only_when_changed(tmp_path: Path) -> None:
    config = tmp_path / ".env"
    config.write_text("A=old\n", "utf-8")

    onboarding._write_config(config, {"A": ""}, {"A": "new"})
    first_backups = list(tmp_path.glob(".env.wmai-backup-*"))
    assert len(first_backups) == 1
    assert first_backups[0].read_text("utf-8") == "A=old\n"
    assert config.stat().st_mode & 0o777 == 0o600

    onboarding._write_config(config, {"A": ""}, {"A": "new"})
    assert list(tmp_path.glob(".env.wmai-backup-*")) == first_backups


def test_kibana_rule_pagination_reads_every_reported_page() -> None:
    client = object.__new__(importer.KibanaClient)
    calls: list[str] = []

    def request(method: str, path: str, **_kwargs: object) -> tuple[int, dict[str, object]]:
        calls.append(path)
        page = int(urllib.parse.parse_qs(urllib.parse.urlparse(path).query)["page"][0])
        size = 100 if page == 1 else 50
        return 200, {"total": 150, "data": [{"rule_id": f"external-{page}-{i}"} for i in range(size)]}

    client.request = request  # type: ignore[method-assign]
    assert len(client.find_rules()) == 150
    assert calls == [
        "/api/detection_engine/rules/_find?per_page=100&page=1",
        "/api/detection_engine/rules/_find?per_page=100&page=2",
    ]


def test_bulk_scenarios_meet_threshold_with_one_endpoint_process() -> None:
    scenarios = load_scenarios()
    for rule_id, threshold in (("WMAI-023", 50), ("WMAI-024", 20)):
        fixture = json.loads((ROOT / scenarios[rule_id]["fixture"]).read_text("utf-8"))
        events = fixture["events"]
        assert len(events) == threshold
        assert {item["event"]["dataset"] for item in events} == {"endpoint.events.file"}
        assert len({item["process"]["entity_id"] for item in events}) == 1
        timestamps = [datetime.fromisoformat(item["@timestamp"].replace("Z", "+00:00")) for item in events]
        assert max(timestamps) - min(timestamps) < timedelta(minutes=1)


@pytest.mark.parametrize(
    ("rule_id", "expected_files"),
    [("WMAI-023", 50), ("WMAI-024", 0)],
)
def test_native_scenario_path_carries_validation_run_id(
    tmp_path: Path, rule_id: str, expected_files: int
) -> None:
    workspace = tmp_path / "isolated-lab"
    config = tmp_path / ".env"
    config.write_text(
        f"WATCHMYAI_LAB_MODE=true\nWATCHMYAI_TEST_WORKSPACE={workspace}\n",
        "utf-8",
    )

    result = write_scenario(rule_id, config_path=config, platform_name="linux")

    native_path = Path(result["native_path_marker"])
    assert result["run_id"] in str(native_path)
    assert native_path == workspace / result["run_id"] / "native-file-events"
    assert native_path.is_dir()
    assert len(list(native_path.glob("*.txt"))) == expected_files


def test_native_event_query_requires_current_run_path_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = object.__new__(AlertClient)
    captured: dict[str, object] = {}

    def capture(index: str, body: dict[str, object]) -> list[dict[str, object]]:
        captured.update(index=index, body=body)
        return []

    monkeypatch.setattr(client, "_search_index", capture)
    client.search_native_events(
        rule_id="WMAI-023",
        run_id="wmai-current-run",
        started_at="2026-07-22T00:00:00Z",
    )

    encoded = json.dumps(captured["body"])
    assert captured["index"] == ("logs-endpoint.events.file-*,logs-windows.sysmon_operational-*")
    assert "*wmai-current-run*" in encoded
    assert '"gte": "2026-07-22T00:00:00Z"' in encoded


def test_native_source_and_threshold_alert_correlation() -> None:
    hits = [
        {
            "_index": "logs-endpoint.events.file-default",
            "_id": f"native-{index}",
            "_source": {
                "@timestamp": f"2026-07-22T00:00:{index:02d}Z",
                "process": {"entity_id": "process-current-run"},
            },
        }
        for index in range(20)
    ]
    evidence = native_source_evidence(hits, threshold=20)
    assert evidence is not None
    assert evidence["process_entity_id"] == "process-current-run"
    assert evidence["source_event_count"] == 20

    matching_alert = {
        "_source": {
            "kibana.alert.threshold_result": {
                "terms": [{"field": "process.entity_id", "value": "process-current-run"}]
            }
        }
    }
    unrelated_alert = {
        "_source": {
            "kibana.alert.threshold_result.terms": [
                {"field": "process.entity_id", "value": "process-unrelated"}
            ]
        }
    }
    assert threshold_alert_matches_entity(matching_alert, "process-current-run")
    assert not threshold_alert_matches_entity(unrelated_alert, "process-current-run")


def test_native_source_correlation_fails_on_ambiguous_processes() -> None:
    hits = []
    for entity in ("process-one", "process-two"):
        hits.extend(
            {
                "_index": "logs-endpoint.events.file-default",
                "_id": f"{entity}-{index}",
                "_source": {
                    "@timestamp": f"2026-07-22T00:00:{index:02d}Z",
                    "process.entity_id": entity,
                },
            }
            for index in range(20)
        )
    with pytest.raises(RuntimeError, match="ambiguous"):
        native_source_evidence(hits, threshold=20)


def test_native_polling_chain_rejects_unrelated_alert() -> None:
    started_at = "2026-07-22T00:00:00Z"
    source_hits = [
        {
            "_index": "logs-endpoint.events.file-default",
            "_id": f"native-{index}",
            "_source": {
                "@timestamp": f"2026-07-22T00:00:{index:02d}Z",
                "process.entity_id": "process-current-run",
            },
        }
        for index in range(20)
    ]
    alerts = [
        {
            "_id": "unrelated-alert",
            "_source": {
                "@timestamp": "2026-07-22T00:01:00Z",
                "kibana.alert.threshold_result.terms": [
                    {"field": "process.entity_id", "value": "process-unrelated"}
                ],
            },
        },
        {
            "_id": "correlated-alert",
            "_source": {
                "@timestamp": "2026-07-22T00:01:01Z",
                "kibana.alert.threshold_result.terms": [
                    {"field": "process.entity_id", "value": "process-current-run"}
                ],
            },
        },
    ]

    class FakeClient:
        def search_native_events(self, **_kwargs: object) -> list[dict[str, object]]:
            return source_hits

        def search(self, **_kwargs: object) -> list[dict[str, object]]:
            return alerts

    client = FakeClient()
    evidence = _poll_native_source_evidence(
        client,  # type: ignore[arg-type]
        rule_id="WMAI-024",
        run_id="wmai-current-run",
        started_at=started_at,
        timeout=1,
        interval=0,
    )
    alert_id, _ = _poll_alert(
        client,  # type: ignore[arg-type]
        rule_id="WMAI-024",
        run_id="wmai-current-run",
        session_id="session-wmai-current-run",
        started_at=evidence["latest_source_timestamp"],
        timeout=1,
        interval=0,
        correlated=False,
        threshold_entity_id=evidence["process_entity_id"],
    )
    assert alert_id == "correlated-alert"


def test_session_id_preserved_during_scenario_correlation() -> None:
    fixture = json.loads((RULES / "tests/fixtures/malicious/WMAI-048.json").read_text("utf-8"))
    events = correlate_events(
        fixture["events"],
        rule_id="WMAI-048",
        scenario_id="SCN-WMAI-048",
        run_id="run-test",
        session_id="session-run-test",
        started_at=datetime.now(UTC),
    )
    assert {item["watchmyai"]["session"]["id"] for item in events} == {"session-run-test"}
    assert {item["watchmyai"]["context"]["validation_run_id"] for item in events} == {"run-test"}


def test_platform_unavailable_is_skipped_before_execution(tmp_path: Path) -> None:
    assert not platform_supported({"platforms": ["windows"]}, "linux")
    assert platform_supported({"platforms": ["neutral"]}, "linux")


def test_lab_mode_and_destructive_path_safety_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsafe test workspace"):
        require_safe_workspace(Path.home())
    config = tmp_path / ".env"
    config.write_text(
        f"WATCHMYAI_LAB_MODE=false\nWATCHMYAI_TEST_WORKSPACE={tmp_path / 'lab'}\n",
        "utf-8",
    )
    with pytest.raises(PermissionError, match="LAB_MODE"):
        write_scenario("WMAI-001", config_path=config, platform_name="linux")


def test_historical_alerts_are_not_accepted() -> None:
    started = datetime.now(UTC)
    old = started - timedelta(seconds=1)
    new = started + timedelta(seconds=1)
    assert not alert_is_current({"_source": {"@timestamp": old.isoformat()}}, started.isoformat())
    assert alert_is_current({"_source": {"@timestamp": new.isoformat()}}, started.isoformat())


def test_requested_live_validation_cannot_skip_disabled_rules(tmp_path: Path) -> None:
    config = tmp_path / ".env"
    config.write_text("ENABLE_RULES=false\n", "utf-8")
    stage, results = _run_live(config)
    assert stage.status == "FAIL"
    assert results == []


def test_no_obvious_live_secret_is_tracked() -> None:
    patterns = [
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ]
    findings: list[str] = []
    for path in release_files(ROOT):
        if path.suffix not in {".py", ".json", ".yml", ".yaml", ".sh", ".ps1"}:
            continue
        text = path.read_text("utf-8", errors="replace")
        if any(pattern.search(text) for pattern in patterns):
            findings.append(str(path.relative_to(ROOT)))
    assert findings == []


def test_local_markdown_links_resolve() -> None:
    missing: list[str] = []
    pattern = re.compile(r"\[[^\]]*\]\((?P<target>[^)]+)\)")
    for document in release_files(ROOT):
        if document.suffix.casefold() != ".md":
            continue
        for match in pattern.finditer(document.read_text("utf-8")):
            target = match.group("target").strip().split(" ", 1)[0].strip("<>")
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            path_text = urllib.parse.unquote(target.split("#", 1)[0])
            if path_text and not (document.parent / path_text).resolve().exists():
                missing.append(f"{document.relative_to(ROOT)} -> {target}")
    assert missing == []
