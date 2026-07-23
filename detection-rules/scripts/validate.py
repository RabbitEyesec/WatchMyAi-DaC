#!/usr/bin/env python3
"""Validate the exact supported WatchMyAI rule and telemetry contracts."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema
from rulelib import (
    ELASTIC_DIR,
    ROOT,
    SIGMA_DIR,
    dotted_value,
    elastic_payload,
    evaluate_fixture,
    fixture_events,
    kql_fields,
    load_json,
    load_metadata,
    load_yaml,
    parse_kql,
)

GATEWAY_ROOT = ROOT.parent / "telemetry-gateway"
GATEWAY_SCHEMA_PATH = ROOT.parent / "src" / "watchmyai" / "schema" / "watchmyai_event.schema.json"
GATEWAY_MAPPING_PATH = GATEWAY_ROOT / "deployment" / "elastic" / "component_template.json"

sys.path.insert(0, str(ROOT.parent / "scripts"))
from utilities.release_contract import EXCLUDED_IDS, SUPPORTED_COUNT, SUPPORTED_IDS  # noqa: E402

SELECTED_IDS = set(SUPPORTED_IDS)
EXCLUDED_IDS_SET = set(EXCLUDED_IDS)
ALL_IDS = {f"WMAI-{number:03d}" for number in range(1, 76)}
DEFERRED_IDS = ALL_IDS - SELECTED_IDS - EXCLUDED_IDS_SET
SENSITIVE_PATH_VARIANTS = {
    "absolute-path",
    "relative-traversal",
    "symlink",
    "hard-link",
    "alternate-reader",
    "archive-then-read",
    "case-platform-path",
}
REQUIRED_T3_EVASION_CLASSES = {
    "WMAI-007": {
        "sudo",
        "doas",
        "su-c",
        "alias-function",
        "absolute-renamed-binary",
        "runtime-decoding",
        "script",
        "interpreter-indirection",
        "whitespace-quoting",
    },
    "WMAI-022": SENSITIVE_PATH_VARIANTS,
    "WMAI-023": {
        "single-tool-call",
        "loop",
        "xargs",
        "find-exec",
        "script",
        "many-actions",
        "window-bursts",
    },
    "WMAI-024": {
        "single-tool-call",
        "loop",
        "xargs",
        "find-exec",
        "script",
        "many-actions",
        "window-bursts",
    },
    "WMAI-025": {
        "direct-binary",
        "script-extension",
        "chmod-after-write",
        "extensionless-shebang",
        "copied-executable",
        "decoded-payload",
        "archive-extraction",
    },
    "WMAI-030": {
        "curl-wget",
        "language-socket",
        "ip-literal",
        "dns-name",
        "alternate-port",
        "proxy-variable",
        "redirect",
        "script",
    },
    "WMAI-034": {
        "service-manager",
        "config-edit",
        "process-kill",
        "renamed-utility",
        "script-wrapper",
        "indirect-shell",
        "platform-equivalent",
    },
    "WMAI-053": {
        "ssh-family",
        "absolute-binary",
        "config-host",
        "proxy-command",
        "script-wrapper",
        "alternate-client",
        "port-forward",
    },
    "WMAI-054": SENSITIVE_PATH_VARIANTS,
    "WMAI-055": {
        "push-clone",
        "url-variant",
        "remote-alias",
        "credential-helper",
        "shell-script",
        "libgit-client",
        "changed-remote",
    },
    "WMAI-057": SENSITIVE_PATH_VARIANTS,
    "WMAI-058": {
        "env",
        "printenv",
        "set",
        "powershell-env",
        "shell-expansion",
        "proc-environment",
        "script-library",
    },
    "WMAI-059": {
        "cloud-cli-family",
        "profile-flag",
        "environment-credentials",
        "config-file",
        "credential-helper",
        "script-wrapper",
        "alternate-binary",
    },
    "WMAI-060": {
        "docker-podman",
        "compose",
        "remote-context",
        "privileged-flag",
        "socket-access",
        "script-wrapper",
        "api-client",
    },
    "WMAI-061": {
        "client-family",
        "context-flag",
        "namespace",
        "exec",
        "apply",
        "proxy",
        "port-forward",
        "script-library",
    },
    "WMAI-063": {
        "rm-rf",
        "find-delete",
        "xargs-rm",
        "python-shutil",
        "node-fs-rm",
        "script-wrapper",
        "relative-symlink",
        "option-reordering",
    },
}


class Validation:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.checks = 0

    def require(self, condition: bool, message: str) -> None:
        self.checks += 1
        if not condition:
            self.errors.append(message)

    def equal(self, actual: Any, expected: Any, message: str) -> None:
        self.require(actual == expected, f"{message}: expected {expected!r}, found {actual!r}")


def _validator(path: Path) -> jsonschema.Draft202012Validator:
    schema = load_json(path)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )


def _schema_errors(
    validator: jsonschema.Draft202012Validator,
    value: Any,
) -> list[str]:
    errors: list[str] = []
    for error in sorted(validator.iter_errors(value), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "root"
        errors.append(f"{location}: {error.message}")
    return errors


def _resolve(schema: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    reference = node.get("$ref")
    if not reference:
        return node
    if not reference.startswith("#/"):
        raise ValueError(f"unsupported non-local schema reference: {reference}")
    resolved: Any = schema
    for part in reference[2:].split("/"):
        resolved = resolved[part]
    return resolved


def _schema_field(schema: dict[str, Any], dotted: str) -> dict[str, Any] | None:
    node = schema
    for part in dotted.split("."):
        node = _resolve(schema, node)
        properties = node.get("properties", {})
        if part not in properties:
            return None
        node = properties[part]
    return _resolve(schema, node)


def _mapping_field(mapping: dict[str, Any], dotted: str) -> dict[str, Any] | None:
    node = mapping
    for part in dotted.split("."):
        if node.get("type") == "flattened":
            return {"type": "keyword"}
        properties = node.get("properties", {})
        if part not in properties:
            return None
        node = properties[part]
    return node


def validate_gateway_contract(validation: Validation) -> jsonschema.Draft202012Validator:
    validation.require(GATEWAY_SCHEMA_PATH.exists(), "telemetry schema is missing")
    validation.require(GATEWAY_MAPPING_PATH.exists(), "Elastic component template is missing")
    schema = load_json(GATEWAY_SCHEMA_PATH)
    component = load_json(GATEWAY_MAPPING_PATH)
    mapping = component["template"]["mappings"]
    validator = _validator(GATEWAY_SCHEMA_PATH)
    catalog = load_json(ROOT / "detections" / "schema" / "custom_fields.json")
    schema_types = {
        "boolean": "boolean",
        "keyword": "string",
        "keyword[]": "array",
        "long": "integer",
    }
    mapping_types = {
        "boolean": "boolean",
        "keyword": "keyword",
        "keyword[]": "keyword",
        "long": "long",
    }
    for field in catalog["fields"]:
        name = field["name"]
        definition = _schema_field(schema, name)
        mapped = _mapping_field(mapping, name)
        validation.require(definition is not None, f"telemetry schema lacks {name}")
        validation.require(mapped is not None, f"Elastic mapping lacks {name}")
        if definition is not None:
            actual_type = definition.get("type") or ("string" if "enum" in definition else None)
            validation.equal(actual_type, schema_types[field["type"]], f"{name} schema type")
        if mapped is not None:
            validation.equal(mapped.get("type"), mapping_types[field["type"]], f"{name} mapping type")
    validation.equal(
        mapping["properties"]["watchmyai"].get("dynamic"),
        "strict",
        "watchmyai mapping mode",
    )
    return validator


def validate_metadata(validation: Validation) -> dict[str, dict[str, Any]]:
    validator = _validator(ROOT / "detections" / "schema" / "rule.schema.json")
    rules = load_metadata()
    ids = [rule.get("rule_id") for rule in rules]
    validation.equal(len(rules), SUPPORTED_COUNT, "canonical metadata count")
    validation.equal(set(ids), SELECTED_IDS, "selected production rule IDs")
    validation.equal(len(ids), len(set(ids)), "unique production rule IDs")
    validation.equal(
        len({str(rule.get("name", "")).casefold() for rule in rules}),
        SUPPORTED_COUNT,
        "unique production rule names",
    )
    result: dict[str, dict[str, Any]] = {}
    for rule in rules:
        rule_id = rule.get("rule_id", "unknown")
        result[rule_id] = rule
        for error in _schema_errors(validator, rule):
            validation.require(False, f"{rule_id} metadata: {error}")
        validation.equal(rule["elastic"]["enabled"], False, f"{rule_id} disabled by default")
        validation.equal(
            rule["deployment"]["status"],
            "production_validated",
            f"{rule_id} deployment status",
        )
        validation.require(rule["deployment"]["packageable"], f"{rule_id} is not packageable")
        if rule["custom_telemetry"]:
            validation.require(
                "event.dataset" in rule["required_fields"],
                f"{rule_id} does not declare event.dataset",
            )
        if rule["elastic"]["type"] == "eql":
            parsed_stages = [parse_kql(stage) for stage in rule["detection_logic"]["sequence"]["stages"]]
            queried = set().union(*(kql_fields(stage) for stage in parsed_stages))
            queried.add(rule["detection_logic"]["sequence"]["join_by"])
        else:
            queried = kql_fields(parse_kql(rule["elastic"]["query"]))
        validation.require(
            queried <= set(rule["required_fields"]),
            f"{rule_id} query fields missing from required_fields: "
            f"{sorted(queried - set(rule['required_fields']))}",
        )
        for relative in [
            rule["response_playbook"],
            *rule["fixtures"].values(),
            *rule["test_artifacts"].values(),
        ]:
            validation.require((ROOT / relative).is_file(), f"{rule_id} missing artifact {relative}")
        for reference in [*rule["references"], *rule["traceability"]]:
            if reference.startswith(("https://", "http://")):
                continue
            target = ROOT / reference.split("#", 1)[0]
            validation.require(target.is_file(), f"{rule_id} stale reference {reference}")
    return result


def validate_elastic(validation: Validation, rules: dict[str, dict[str, Any]]) -> None:
    validator = _validator(ROOT / "detections" / "schema" / "elastic_rule.schema.json")
    paths = sorted(ELASTIC_DIR.glob("WMAI-*.json"))
    validation.equal(len(paths), SUPPORTED_COUNT, "Elastic rule count")
    validation.equal({path.stem for path in paths}, SELECTED_IDS, "Elastic selected IDs")
    for path in paths:
        payload = load_json(path)
        rule_id = path.stem
        validation.equal(payload, elastic_payload(rules[rule_id]), f"{rule_id} generated Elastic parity")
        for error in _schema_errors(validator, payload):
            validation.require(False, f"{rule_id} Elastic definition: {error}")
        validation.equal(payload.get("enabled"), False, f"{rule_id} import default")


def validate_sigma(validation: Validation, rules: dict[str, dict[str, Any]]) -> None:
    implemented = {rule_id for rule_id, rule in rules.items() if rule["sigma"]["status"] == "implemented"}
    paths = sorted(SIGMA_DIR.glob("WMAI-*.yml"))
    validation.equal({path.stem for path in paths}, implemented, "Sigma implementation set")


def _contains_dotted(value: dict[str, Any], dotted: str) -> bool:
    return dotted_value(value, dotted) is not None


def validate_fixtures(
    validation: Validation,
    rules: dict[str, dict[str, Any]],
    gateway_validator: jsonschema.Draft202012Validator,
) -> None:
    manifest = load_json(ROOT / "tests" / "fixtures" / "manifest.json")
    validation.equal(set(manifest), SELECTED_IDS, "fixture manifest IDs")
    prohibited = load_json(ROOT / "detections" / "schema" / "custom_fields.json")["prohibited_fields"]
    for rule_id, rule in rules.items():
        for fixture_type, expected in (("malicious", True), ("benign", False)):
            fixture = load_json(ROOT / rule["fixtures"][fixture_type])
            validation.equal(
                fixture.get("case_type"),
                "deterministic_unit_fixture_not_measured_efficacy",
                f"{rule_id} {fixture_type} fixture label",
            )
            validation.equal(evaluate_fixture(rule, fixture), expected, f"{rule_id} {fixture_type} result")
            events = fixture_events(fixture)
            for index, event in enumerate(events):
                if rule["custom_telemetry"]:
                    for error in _schema_errors(gateway_validator, event):
                        validation.require(
                            False,
                            f"{rule_id} {fixture_type} event {index}: {error}",
                        )
                for field in prohibited:
                    validation.require(
                        not _contains_dotted(event, field),
                        f"{rule_id} {fixture_type} event contains prohibited {field}",
                    )
            if fixture_type == "malicious":
                for field in rule["required_fields"]:
                    validation.require(
                        any(_contains_dotted(event, field) for event in events),
                        f"{rule_id} malicious corpus lacks {field}",
                    )


def validate_corpora(validation: Validation, rules: dict[str, dict[str, Any]]) -> None:
    for group in ("atomic", "evasion", "conformance"):
        paths = sorted((ROOT / "tests" / "corpus" / group).glob("WMAI-*.json"))
        validation.equal({path.stem for path in paths}, SELECTED_IDS, f"{group} corpus IDs")
    for rule_id, rule in rules.items():
        atomic = load_json(ROOT / rule["test_artifacts"]["atomic"])
        validation.equal(atomic.get("execution"), "real_adapter_required", f"{rule_id} atomic path")
        evasion = load_json(ROOT / rule["test_artifacts"]["evasion"])
        minimum = 7 if rule["test_tier"] == "T3" else 5
        validation.require(len(evasion["variants"]) >= minimum, f"{rule_id} evasion corpus is undersized")
        if rule["test_tier"] == "T3":
            validation.equal(
                {variant.get("class") for variant in evasion["variants"]},
                REQUIRED_T3_EVASION_CLASSES[rule_id],
                f"{rule_id} normative T3 evasion classes",
            )
        conformance = load_json(ROOT / rule["test_artifacts"]["producer_conformance"])
        validation.equal(
            conformance.get("status"),
            "REQUIRES_LIVE_PRODUCER",
            f"{rule_id} conformance status",
        )


def validate_deferred_catalog(validation: Validation) -> None:
    base = ROOT / "research" / "deferred-catalog"
    for group in ("metadata", "elastic", "fixtures/malicious", "fixtures/benign"):
        paths = sorted((base / group).glob("WMAI-*.*"))
        validation.equal({path.stem for path in paths}, DEFERRED_IDS, f"deferred {group} IDs")
    validation.require(not (SELECTED_IDS & DEFERRED_IDS), "selected and deferred catalogs overlap")
    validation.require(
        not (EXCLUDED_IDS_SET & DEFERRED_IDS),
        "excluded rules must not be retained in the deferred catalog",
    )
    sigma_paths = sorted((base / "sigma").glob("WMAI-*.yml"))
    validation.require(bool(sigma_paths), "deferred Sigma research catalog is empty")
    validation.require(
        {path.stem for path in sigma_paths} <= DEFERRED_IDS,
        "deferred Sigma artifacts overlap production or excluded IDs",
    )
    for path in sigma_paths:
        payload = load_yaml(path)
        validation.require(isinstance(payload, dict), f"{path.name} is not a mapping")
        if not isinstance(payload, dict):
            continue
        for field in ("title", "id", "status", "logsource", "detection"):
            validation.require(bool(payload.get(field)), f"{path.name} lacks {field}")


def validate_repository(validation: Validation, rules: dict[str, dict[str, Any]]) -> None:
    required = [
        ROOT / "README.md",
        ROOT.parent / "VERSION",
        ROOT / "detections" / "manifest.yml",
        ROOT / "tests" / "fixtures" / "manifest.json",
        ROOT.parent / "README.md",
        ROOT.parent / "deployment" / "rules_schema_1.1.0.ndjson",
        ROOT.parent / "docs" / "DETECTION_RULES.md",
        ROOT.parent / "docs" / "assets" / "screenshots" / "elastic-watchmyai-alerts.png",
        ROOT.parent / "docs" / "assets" / "screenshots" / "elastic-watchmyai-events.png",
    ]
    for path in required:
        validation.require(path.is_file() and path.stat().st_size > 0, f"missing required file {path}")
    validation.equal(set(rules), SELECTED_IDS, "repository selected IDs")
    validation.require(
        os.access(ROOT.parent / "scripts" / "import" / "import_rules.py", os.X_OK),
        "root rule importer is missing or not executable",
    )
    validation.require(
        os.access(ROOT.parent / "scripts" / "utilities" / "build_release.py", os.X_OK),
        "root release builder is missing or not executable",
    )
    for script in ("deployment/export_rules.sh",):
        validation.require(os.access(ROOT / script, os.X_OK), f"{script} is not executable")


def validate_generated(validation: Validation) -> None:
    command = [sys.executable, "scripts/rules/reconcile_rules.py", "--check"]
    result = subprocess.run(command, cwd=ROOT.parent, capture_output=True, text=True, check=False)
    validation.require(
        result.returncode == 0,
        f"generated Elastic artifacts drifted: {result.stdout}{result.stderr}",
    )


def main() -> int:
    validation = Validation()
    gateway_validator = validate_gateway_contract(validation)
    rules = validate_metadata(validation)
    validate_elastic(validation, rules)
    validate_sigma(validation, rules)
    validate_fixtures(validation, rules, gateway_validator)
    validate_corpora(validation, rules)
    validate_deferred_catalog(validation)
    validate_repository(validation, rules)
    validate_generated(validation)
    if validation.errors:
        print(f"FAILED: {len(validation.errors)} error(s) across {validation.checks} checks")
        for error in validation.errors:
            print(f"- {error}")
        return 1
    print(f"PASS: {validation.checks} deterministic checks across {SUPPORTED_COUNT} supported rules")
    print("LIVE VALIDATION: separate; static validation never claims alert generation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
