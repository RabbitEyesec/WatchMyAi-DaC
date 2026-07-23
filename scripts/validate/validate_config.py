#!/usr/bin/env python3
"""Validate the central WatchMyAI configuration without exposing secrets."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))

from utilities.release_contract import (  # noqa: E402
    CANONICAL_DATASET,
    EXIT_INVALID_CONFIGURATION,
    ORIGINAL_PATH_RE,
    PLACEHOLDER_RE,
    REPOSITORY_ROOT,
    load_dotenv,
    merged_config,
    parse_bool,
    require_safe_workspace,
    resolve_repository_path,
    validate_url,
)

REQUIRED_KEYS = {
    "WATCHMYAI_MACHINE_ROLE",
    "WATCHMYAI_POLICY_MODE",
    "WATCHMYAI_HOME",
    "ELASTICSEARCH_URL",
    "KIBANA_URL",
    "KIBANA_SPACE",
    "FLEET_SERVER_URL",
    "FLEET_AGENT_POLICY_ID",
    "ELASTIC_AUTH_METHOD",
    "TLS_VERIFY",
    "WATCHMYAI_DATASET",
    "SOURCE_DATA_STREAM",
    "ALERT_INDEX_PATTERN",
    "VALIDATION_TIMEOUT_SECONDS",
    "POLL_INTERVAL_SECONDS",
    "WATCHMYAI_TEST_WORKSPACE",
    "WATCHMYAI_LAB_MODE",
    "ENABLE_RULES",
}
ROLES = {"repository-only", "ubuntu-server", "windows-endpoint"}
SECRET_KEYS = {
    "ELASTIC_API_KEY",
    "ELASTIC_PASSWORD",
}


def _integer(config: dict[str, str], name: str, minimum: int, maximum: int) -> int:
    try:
        value = int(config[name])
    except (KeyError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def validate_config(
    path: Path,
    *,
    template: bool = False,
    environ: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    if not path.is_file():
        return [f"configuration file not found: {path}"]
    try:
        template_values = load_dotenv(path)
        config = template_values if template else merged_config(path, environ)
    except (OSError, ValueError) as exc:
        return [str(exc)]

    missing = sorted(key for key in REQUIRED_KEYS if not config.get(key))
    errors.extend(f"missing required value {key}" for key in missing)
    if template:
        missing_keys = sorted(REQUIRED_KEYS - set(template_values))
        errors.extend(f"template is missing required key {key}" for key in missing_keys)
    else:
        for key, value in config.items():
            if value and PLACEHOLDER_RE.search(value):
                errors.append(f"{key} still contains an unresolved placeholder")
            if value and ORIGINAL_PATH_RE.search(value):
                errors.append(f"{key} contains an original-machine address or path")

    role = config.get("WATCHMYAI_MACHINE_ROLE", "")
    if role not in ROLES:
        errors.append("WATCHMYAI_MACHINE_ROLE must be repository-only, ubuntu-server, or windows-endpoint")
    if config.get("WATCHMYAI_DATASET") != CANONICAL_DATASET:
        errors.append(f"WATCHMYAI_DATASET must equal {CANONICAL_DATASET}")
    if config.get("WATCHMYAI_POLICY_MODE") not in {"development", "signed"}:
        errors.append("WATCHMYAI_POLICY_MODE must be development or signed")
    if config.get("ELASTIC_AUTH_METHOD") not in {"api_key", "basic"}:
        errors.append("ELASTIC_AUTH_METHOD must be api_key or basic")

    for name in (
        "ELASTICSEARCH_URL",
        "KIBANA_URL",
        "FLEET_SERVER_URL",
    ):
        value = config.get(name)
        if not value or (template and PLACEHOLDER_RE.search(value)):
            continue
        try:
            validate_url(name, value)
        except ValueError as exc:
            errors.append(str(exc))

    for name in ("TLS_VERIFY", "WATCHMYAI_LAB_MODE", "ENABLE_RULES"):
        if config.get(name):
            try:
                parse_bool(config[name], name=name)
            except ValueError as exc:
                errors.append(str(exc))
    for name, bounds in (
        ("VALIDATION_TIMEOUT_SECONDS", (10, 3600)),
        ("POLL_INTERVAL_SECONDS", (1, 300)),
    ):
        if config.get(name):
            try:
                _integer(config, name, *bounds)
            except ValueError as exc:
                errors.append(str(exc))

    workspace_value = config.get("WATCHMYAI_TEST_WORKSPACE")
    if workspace_value and not PLACEHOLDER_RE.search(workspace_value):
        try:
            workspace = resolve_repository_path(workspace_value)
            require_safe_workspace(workspace)
            lab_mode = parse_bool(config.get("WATCHMYAI_LAB_MODE", "false"), name="WATCHMYAI_LAB_MODE")
            if lab_mode and not workspace.is_dir():
                errors.append(f"WATCHMYAI_TEST_WORKSPACE does not exist in lab mode: {workspace}")
        except ValueError as exc:
            errors.append(str(exc))

    runtime_home_value = config.get("WATCHMYAI_HOME", "")
    if runtime_home_value and not PLACEHOLDER_RE.search(runtime_home_value):
        runtime_home = Path(os.path.expandvars(runtime_home_value)).expanduser()
        if not runtime_home.is_absolute():
            errors.append("WATCHMYAI_HOME must be an absolute path outside the repository")
        else:
            resolved_home = runtime_home.resolve()
            if resolved_home == REPOSITORY_ROOT or resolved_home.is_relative_to(REPOSITORY_ROOT):
                errors.append("WATCHMYAI_HOME must be outside the repository")

    tls_verify = config.get("TLS_VERIFY", "true").lower() == "true"
    if not tls_verify:
        for name in ("ELASTICSEARCH_URL", "KIBANA_URL", "FLEET_SERVER_URL"):
            value = config.get(name, "")
            if value and not PLACEHOLDER_RE.search(value):
                hostname = urlparse(value).hostname
                if hostname not in {"127.0.0.1", "::1", "localhost"}:
                    errors.append(
                        f"TLS_VERIFY=false is allowed only for loopback services; {name} is not loopback"
                    )
    if tls_verify:
        for name in ("ELASTIC_CA_CERT", "FLEET_CA_CERT"):
            value = config.get(name, "")
            if value and not PLACEHOLDER_RE.search(value):
                path_value = Path(value).expanduser()
                if not path_value.is_absolute():
                    errors.append(f"{name} must be an absolute path")
                elif not path_value.is_file():
                    errors.append(f"{name} file does not exist: {path_value}")

    if not template and role != "repository-only":
        if not config.get("FLEET_AGENT_POLICY_ID") or PLACEHOLDER_RE.search(
            config.get("FLEET_AGENT_POLICY_ID", "")
        ):
            errors.append("FLEET_AGENT_POLICY_ID is required for live setup")
        method = config.get("ELASTIC_AUTH_METHOD")
        api_key_file = config.get("ELASTIC_API_KEY_FILE", "")
        if method == "api_key" and not config.get("ELASTIC_API_KEY") and not api_key_file:
            errors.append("api_key authentication requires ELASTIC_API_KEY or ELASTIC_API_KEY_FILE")
        if api_key_file:
            key_path = Path(api_key_file).expanduser()
            if not key_path.is_absolute():
                errors.append("ELASTIC_API_KEY_FILE must be an absolute path")
            elif not key_path.is_file():
                errors.append("ELASTIC_API_KEY_FILE does not exist")
            elif os.name != "nt" and key_path.stat().st_mode & 0o077:
                errors.append("ELASTIC_API_KEY_FILE must be owner-only (mode 0600)")
        if method == "basic" and (not config.get("ELASTIC_USERNAME") or not config.get("ELASTIC_PASSWORD")):
            errors.append("basic authentication requires ELASTIC_USERNAME and ELASTIC_PASSWORD")
        for key in SECRET_KEYS:
            value = config.get(key, "")
            if value and value.lower() in {"password", "changeme", "example", "secret"}:
                errors.append(f"{key} contains an example credential")

    if role in {"ubuntu-server", "windows-endpoint"}:
        for name in ("ELASTIC_AGENT_PATH",):
            value = config.get(name, "")
            if not value or PLACEHOLDER_RE.search(value):
                errors.append(f"{name} is required for {role}")
            elif not resolve_repository_path(value).exists():
                errors.append(f"{name} does not exist: {resolve_repository_path(value)}")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(os.environ.get("WATCHMYAI_CONFIG", REPOSITORY_ROOT / ".env")),
    )
    parser.add_argument(
        "--template",
        action="store_true",
        help="validate template structure while allowing secret placeholders",
    )
    args = parser.parse_args()
    errors = validate_config(args.config, template=args.template)
    if errors:
        print(f"FAIL: invalid configuration {args.config}", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return EXIT_INVALID_CONFIGURATION
    mode = "template" if args.template else "runtime"
    print(f"PASS: {mode} configuration is valid ({args.config})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
