#!/usr/bin/env python3
"""Idempotently import exactly the authoritative supported rules into Kibana."""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from utilities.release_contract import (  # noqa: E402
    DEFERRED_IDS,
    EXCLUDED_IDS,
    EXIT_RULE_IMPORT,
    SUPPORTED_COUNT,
    SUPPORTED_IDS,
    load_dotenv,
    parse_bool,
    resolve_repository_path,
    sanitize_target,
    validate_url,
)

MANAGED_FIELDS = {
    "description",
    "from",
    "index",
    "interval",
    "language",
    "name",
    "query",
    "risk_score",
    "rule_id",
    "severity",
    "threshold",
    "type",
}
AUTHORITATIVE_RULES = ROOT / "deployment/rules_schema_1.1.0.ndjson"


class ImportFailure(RuntimeError):
    pass


def _config(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise ImportFailure(
            f"configuration file not found: {path}; copy .env.example to .env and validate it"
        )
    values = load_dotenv(path)
    return {key: os.environ.get(key, value) for key, value in values.items()}


def rules_enabled(config: dict[str, str]) -> bool:
    """Require an explicit true value; an absent setting keeps rules disabled."""
    return parse_bool(config.get("ENABLE_RULES", "false"), name="ENABLE_RULES")


def _authoritative_rules() -> list[dict[str, Any]]:
    try:
        raw_lines = AUTHORITATIVE_RULES.read_text("utf-8").splitlines()
        if not raw_lines or any(not line.strip() for line in raw_lines):
            raise ImportFailure("authoritative NDJSON contains a blank record")
        rules = [json.loads(line) for line in raw_lines]
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise ImportFailure(f"authoritative rule source is invalid: {exc}") from exc
    ids = [str(item.get("rule_id", "")) for item in rules]
    if tuple(ids) != SUPPORTED_IDS or len(ids) != len(set(ids)):
        raise ImportFailure("authoritative NDJSON does not contain the exact supported rule set")
    if any(item.get("enabled") is not False for item in rules):
        raise ImportFailure("authoritative NDJSON rules must be disabled by default")
    return rules


def _validate_rules(rules: list[dict[str, Any]], *, source: str) -> list[dict[str, Any]]:
    ids = [str(rule.get("rule_id", "")) for rule in rules]
    if len(ids) != len(set(ids)):
        raise ImportFailure(f"{source} contains duplicate stable rule IDs")
    excluded = sorted(set(ids) & set(EXCLUDED_IDS))
    if excluded:
        raise ImportFailure(f"{source} contains excluded IDs: {', '.join(excluded)}")
    deferred = sorted(set(ids) & set(DEFERRED_IDS))
    if deferred:
        raise ImportFailure(f"{source} contains deferred IDs: {', '.join(deferred)}")
    if len(rules) != SUPPORTED_COUNT or tuple(ids) != SUPPORTED_IDS:
        raise ImportFailure(
            f"{source} must contain exactly the ordered supported IDs; found {len(rules)} rules"
        )
    for rule in rules:
        rule_id = rule["rule_id"]
        if not str(rule.get("query", "")).strip():
            raise ImportFailure(f"{rule_id}: query is empty")
        if rule.get("enabled") is not False:
            raise ImportFailure(f"{rule_id}: source rule must be disabled by default")
    authoritative_rules = _authoritative_rules()
    authoritative = {item["rule_id"]: item for item in authoritative_rules}
    for rule in rules:
        if authoritative.get(rule["rule_id"]) != rule:
            raise ImportFailure(f"{rule['rule_id']}: import content differs from the authoritative NDJSON")
    return rules


def load_active_rules(rule_dir: Path) -> list[dict[str, Any]]:
    paths = sorted(rule_dir.glob("WMAI-*.json"))
    rules: list[dict[str, Any]] = []
    for path in paths:
        try:
            rule = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ImportFailure(f"{path}: invalid rule JSON: {exc}") from exc
        if not isinstance(rule, dict):
            raise ImportFailure(f"{path}: rule must be a JSON object")
        if rule.get("rule_id") != path.stem:
            raise ImportFailure(f"{path}: stable rule_id {rule.get('rule_id')!r} does not match filename")
        rules.append(rule)
    return _validate_rules(rules, source="active rule directory")


def load_rule_ndjson(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text("utf-8").splitlines()
        if not lines or any(not line.strip() for line in lines):
            raise ImportFailure(f"{path}: NDJSON contains a blank record")
        rules = [json.loads(line) for line in lines]
    except (OSError, json.JSONDecodeError) as exc:
        raise ImportFailure(f"{path}: invalid rule NDJSON: {exc}") from exc
    if not all(isinstance(rule, dict) for rule in rules):
        raise ImportFailure(f"{path}: every NDJSON record must be an object")
    return _validate_rules(rules, source="rule NDJSON")


def plan_changes(
    expected: list[dict[str, Any]],
    deployed: list[dict[str, Any]],
) -> tuple[list[str], list[str], list[str]]:
    by_id: dict[str, list[dict[str, Any]]] = {}
    for item in deployed:
        rule_id = str(item.get("rule_id", ""))
        if rule_id in SUPPORTED_IDS:
            by_id.setdefault(rule_id, []).append(item)
    duplicates = sorted(rule_id for rule_id, items in by_id.items() if len(items) > 1)
    if duplicates:
        raise ImportFailure("Kibana contains duplicate stable rule IDs: " + ", ".join(duplicates))
    created: list[str] = []
    updated: list[str] = []
    unchanged: list[str] = []
    for rule in expected:
        rule_id = rule["rule_id"]
        current = by_id.get(rule_id)
        if not current:
            created.append(rule_id)
            continue
        before = {key: current[0].get(key) for key in MANAGED_FIELDS}
        after = {key: rule.get(key) for key in MANAGED_FIELDS}
        (unchanged if before == after else updated).append(rule_id)
    return created, updated, unchanged


class KibanaClient:
    def __init__(self, config: dict[str, str]):
        self.base = validate_url("KIBANA_URL", config["KIBANA_URL"])
        space = config.get("KIBANA_SPACE", "default")
        if not space.replace("_", "").replace("-", "").isalnum():
            raise ImportFailure("KIBANA_SPACE contains unsupported characters")
        self.prefix = "" if space == "default" else f"/s/{urllib.parse.quote(space, safe='')}"
        self.headers = {"Accept": "application/json", "kbn-xsrf": "watchmyai-v1"}
        method = config.get("ELASTIC_AUTH_METHOD", "api_key")
        if method == "api_key":
            api_key = config.get("ELASTIC_API_KEY", "")
            api_key_file = config.get("ELASTIC_API_KEY_FILE", "")
            if not api_key and api_key_file:
                api_key = resolve_repository_path(api_key_file).read_text("utf-8").strip()
            if not api_key:
                raise ImportFailure("Kibana authentication requires an API key")
            self.headers["Authorization"] = f"ApiKey {api_key}"
        elif method == "basic":
            username = config.get("ELASTIC_USERNAME", "")
            password = config.get("ELASTIC_PASSWORD", "")
            if not username or not password:
                raise ImportFailure("Kibana basic authentication is incomplete")
            token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
            self.headers["Authorization"] = f"Basic {token}"
        else:
            raise ImportFailure(f"unsupported ELASTIC_AUTH_METHOD {method!r}")
        verify = parse_bool(config.get("TLS_VERIFY", "true"), name="TLS_VERIFY")
        hostname = urllib.parse.urlparse(self.base).hostname
        if not verify and hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise ImportFailure("TLS_VERIFY=false is allowed only for loopback Kibana")
        ca_file = config.get("ELASTIC_CA_CERT", "")
        self.context = (
            ssl.create_default_context(cafile=str(resolve_repository_path(ca_file)))
            if verify and ca_file
            else ssl.create_default_context()
            if verify
            # Insecure contexts are reachable only for explicitly selected loopback URLs.
            else ssl._create_unverified_context()  # nosec B323
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        target = self.base + self.prefix + path
        request = urllib.request.Request(
            target,
            data=data,
            headers={**self.headers, **(headers or {})},
            method=method,
        )
        try:
            # validate_url constrains the base to HTTP(S), with HTTP limited to loopback.
            with urllib.request.urlopen(  # nosec B310
                request, timeout=30, context=self.context
            ) as response:
                body = response.read().decode("utf-8")
                return response.status, json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise ImportFailure(
                f"Kibana request to {sanitize_target(target)} failed with HTTP {exc.code}; "
                f"likely cause: authentication, space, or API readiness; response={detail!r}; "
                f"verify with: curl -I {sanitize_target(self.base)}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ImportFailure(
                f"Kibana request to {sanitize_target(target)} failed: {exc}; likely cause: "
                f"DNS, TLS trust, or service readiness; verify with: curl -I "
                f"{sanitize_target(self.base)}"
            ) from exc

    def find_rules(self) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        page = 1
        per_page = 100
        while True:
            _, payload = self.request(
                "GET",
                f"/api/detection_engine/rules/_find?per_page={per_page}&page={page}",
            )
            data = payload.get("data", [])
            total = payload.get("total")
            if not isinstance(data, list) or not isinstance(total, int) or total < 0:
                raise ImportFailure("Kibana rules API returned invalid pagination data")
            rules.extend(data)
            if len(rules) >= total:
                return rules
            if not data or page > 10000:
                raise ImportFailure("Kibana rules API pagination ended before the reported total")
            page += 1

    def import_rules(self, content: bytes) -> dict[str, Any]:
        boundary = f"watchmyai-{uuid.uuid4().hex}"
        body = (
            (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="file"; filename="watchmyai-rules.ndjson"\r\n'
                "Content-Type: application/x-ndjson\r\n\r\n"
            ).encode()
            + content
            + f"\r\n--{boundary}--\r\n".encode()
        )
        _, payload = self.request(
            "POST",
            "/api/detection_engine/rules/_import?overwrite=true",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        return payload

    def enable(self, object_ids: list[str]) -> None:
        body = json.dumps({"action": "enable", "ids": object_ids}).encode()
        _, payload = self.request(
            "POST",
            "/api/detection_engine/rules/_bulk_action",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        if payload.get("errors"):
            raise ImportFailure(f"Kibana enablement reported errors: {payload['errors']!r}")


def _ndjson(rules: list[dict[str, Any]]) -> bytes:
    return (
        "".join(
            json.dumps(rule, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
            for rule in rules
        )
    ).encode("utf-8")


def _print_summary(
    *,
    validated: int,
    created: int,
    updated: int,
    unchanged: int,
    skipped: int,
    failed: int,
    imported: int,
    enabled: int,
) -> None:
    print(f"Supported rules: {SUPPORTED_COUNT}")
    print(f"Validated: {validated}")
    print(f"Created: {created}")
    print(f"Updated: {updated}")
    print(f"Unchanged: {unchanged}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failed}")
    print(f"Imported supported count: {imported}")
    print(f"Enabled supported count: {enabled}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / ".env")
    parser.add_argument(
        "--rule-dir",
        type=Path,
        default=ROOT / "detection-rules/detections/elastic",
    )
    parser.add_argument(
        "--ndjson",
        type=Path,
        help="import the exact packaged NDJSON instead of generated per-rule JSON files",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        rules = (
            load_rule_ndjson(args.ndjson.resolve())
            if args.ndjson is not None
            else load_active_rules(args.rule_dir.resolve())
        )
        validate = subprocess.run(
            [sys.executable, "scripts/validate.py"],
            cwd=ROOT / "detection-rules",
            capture_output=True,
            text=True,
            check=False,
        )
        if validate.returncode:
            raise ImportFailure(
                "rule validation failed before import: " + (validate.stdout + validate.stderr)[-3000:]
            )
        content = _ndjson(rules)
        # Close before the subprocess opens the path by name; Windows denies a
        # second open while a NamedTemporaryFile is still held open.
        handle = tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False)
        try:
            handle.write(content)
            handle.close()
            ndjson_check = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/validate/validate_ndjson.py"),
                    handle.name,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        finally:
            handle.close()
            os.unlink(handle.name)
        if ndjson_check.returncode:
            raise ImportFailure(ndjson_check.stdout + ndjson_check.stderr)
        if args.dry_run:
            _print_summary(
                validated=SUPPORTED_COUNT,
                created=0,
                updated=0,
                unchanged=0,
                skipped=SUPPORTED_COUNT,
                failed=0,
                imported=0,
                enabled=0,
            )
            print("DRY RUN: active rules are valid; no Kibana request was made")
            return 0

        config = _config(args.config)
        client = KibanaClient(config)
        before = client.find_rules()
        unexpected = sorted(
            {
                str(item.get("rule_id"))
                for item in before
                if str(item.get("rule_id", "")).startswith("WMAI-")
                and item.get("rule_id") not in SUPPORTED_IDS
            }
        )
        if unexpected:
            raise ImportFailure(
                "Kibana contains unexpected WatchMyAI rule IDs; remove them only through an "
                "explicit reviewed cleanup: " + ", ".join(unexpected)
            )
        created, updated, unchanged = plan_changes(rules, before)
        response = client.import_rules(content)
        errors = response.get("errors") or []
        if response.get("success") is not True or errors or response.get("rules_count") != SUPPORTED_COUNT:
            raise ImportFailure(
                "Kibana import was partial: "
                f"success={response.get('success')!r}, "
                f"rules_count={response.get('rules_count')!r}, errors={errors!r}"
            )
        after = client.find_rules()
        unexpected = sorted(
            {
                str(item.get("rule_id"))
                for item in after
                if str(item.get("rule_id", "")).startswith("WMAI-")
                and item.get("rule_id") not in SUPPORTED_IDS
            }
        )
        if unexpected:
            raise ImportFailure(
                "post-import verification found unexpected WatchMyAI rule IDs: " + ", ".join(unexpected)
            )
        supported = [item for item in after if item.get("rule_id") in SUPPORTED_IDS]
        supported_ids = {item.get("rule_id") for item in supported}
        if len(supported) != SUPPORTED_COUNT or supported_ids != set(SUPPORTED_IDS):
            raise ImportFailure(
                f"post-import verification found {len(supported)}/{SUPPORTED_COUNT} supported rules"
            )
        should_enable = rules_enabled(config)
        if should_enable:
            object_ids = [str(item["id"]) for item in supported if not item.get("enabled")]
            if object_ids:
                client.enable(object_ids)
            supported = [item for item in client.find_rules() if item.get("rule_id") in SUPPORTED_IDS]
        enabled = sum(item.get("enabled") is True for item in supported)
        if should_enable and enabled != SUPPORTED_COUNT:
            raise ImportFailure(f"enablement verification found {enabled}/{SUPPORTED_COUNT} enabled rules")
        _print_summary(
            validated=SUPPORTED_COUNT,
            created=len(created),
            updated=len(updated),
            unchanged=len(unchanged),
            skipped=0,
            failed=0,
            imported=len(supported),
            enabled=enabled,
        )
        return 0
    except (ImportFailure, KeyError, ValueError) as exc:
        print(f"FAIL: rule import: {exc}", file=sys.stderr)
        _print_summary(
            validated=0,
            created=0,
            updated=0,
            unchanged=0,
            skipped=0,
            failed=1,
            imported=0,
            enabled=0,
        )
        return EXIT_RULE_IMPORT


if __name__ == "__main__":
    raise SystemExit(main())
