#!/usr/bin/env python3
"""Run static gates and optional live validation for the supported rules."""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scenarios/runners"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "src"))

from utilities.release_contract import (  # noqa: E402
    DEFERRED_IDS,
    EXCLUDED_IDS,
    EXIT_VALIDATION,
    NATIVE_FILE_INDEX_PATTERNS,
    PROJECT_VERSION,
    SUPPORTED_COUNT,
    SUPPORTED_IDS,
    load_dotenv,
    parse_bool,
    resolve_repository_path,
)
from validate_ndjson import iter_ndjson  # noqa: E402

from scenarios.runners.run_scenario import (  # noqa: E402
    load_scenarios,
    write_scenario,
)
from watchmyai.exporters.elastic.exporter import ElasticSink  # noqa: E402

NATIVE_FILE_INDEX_PATTERN = ",".join(NATIVE_FILE_INDEX_PATTERNS)
NATIVE_RULE_REQUIREMENTS = {
    "WMAI-023": ({"change", "creation"}, 50),
    "WMAI-024": ({"deletion"}, 20),
}


@dataclass
class Stage:
    name: str
    status: str
    detail: str


def _command(name: str, command: list[str], *, cwd: Path = ROOT) -> Stage:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    output = (completed.stdout + completed.stderr).strip()
    status = "PASS" if completed.returncode == 0 else "FAIL"
    return Stage(name, status, output[-4000:])


def _config(path: Path) -> dict[str, str]:
    values = load_dotenv(path)
    return {key: os.environ.get(key, value) for key, value in values.items()}


def validate_scenario_contract() -> Stage:
    try:
        scenarios = load_scenarios()
        if set(scenarios) != set(SUPPORTED_IDS):
            raise ValueError("scenario IDs do not match the supported rule set")
        if set(scenarios) & set(EXCLUDED_IDS):
            raise ValueError("excluded IDs appear in the active scenario catalog")
        if set(scenarios) & set(DEFERRED_IDS):
            raise ValueError("deferred IDs appear in the active scenario catalog")
        for rule_id, (_, threshold) in NATIVE_RULE_REQUIREMENTS.items():
            fixture_path = ROOT / scenarios[rule_id]["fixture"]
            fixture = json.loads(fixture_path.read_text("utf-8"))
            events = fixture.get("events", [])
            if len(events) < threshold:
                raise ValueError(
                    f"{rule_id} requires at least {threshold} separate events; found {len(events)}"
                )
            if scenarios[rule_id].get("ingest_mode") != "endpoint_native":
                raise ValueError(f"{rule_id} must use native endpoint telemetry")
        return Stage(
            "scenario contract",
            "PASS",
            f"{SUPPORTED_COUNT} scenarios; endpoint thresholds require run-ID path, source-event, "
            "process-entity, and alert-term correlation",
        )
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
        return Stage("scenario contract", "FAIL", str(exc))


class AlertClient:
    def __init__(self, config: dict[str, str]):
        self.base = config["ELASTICSEARCH_URL"].rstrip("/")
        self.alert_index = config["ALERT_INDEX_PATTERN"]
        self.headers = {"Content-Type": "application/json"}
        method = config.get("ELASTIC_AUTH_METHOD", "api_key")
        if method == "api_key":
            key = config.get("ELASTIC_API_KEY", "")
            key_file = config.get("ELASTIC_API_KEY_FILE", "")
            if not key and key_file:
                key = resolve_repository_path(key_file).read_text("utf-8").strip()
            self.headers["Authorization"] = f"ApiKey {key}"
        else:
            token = base64.b64encode(
                f"{config['ELASTIC_USERNAME']}:{config['ELASTIC_PASSWORD']}".encode()
            ).decode("ascii")
            self.headers["Authorization"] = f"Basic {token}"
        verify = parse_bool(config.get("TLS_VERIFY", "true"), name="TLS_VERIFY")
        hostname = urllib.parse.urlparse(self.base).hostname
        if not verify and hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise RuntimeError("TLS_VERIFY=false is allowed only for loopback Elasticsearch")
        ca_file = config.get("ELASTIC_CA_CERT", "")
        self.context = (
            ssl.create_default_context(cafile=str(resolve_repository_path(ca_file)))
            if verify and ca_file
            else ssl.create_default_context()
            if verify
            # Insecure contexts are reachable only for explicitly selected loopback URLs.
            else ssl._create_unverified_context()  # nosec B323
        )

    def _search_index(self, index_pattern: str, body: dict[str, Any]) -> list[dict[str, Any]]:
        index = urllib.parse.quote(index_pattern, safe="*,-._")
        request = urllib.request.Request(
            f"{self.base}/{index}/_search",
            data=json.dumps(body).encode(),
            headers=self.headers,
            method="POST",
        )
        try:
            # Preflight validates the configured Elasticsearch URL before polling.
            with urllib.request.urlopen(  # nosec B310
                request, timeout=30, context=self.context
            ) as response:
                payload = json.loads(response.read())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            raise RuntimeError(f"Elasticsearch search failed: {exc}") from exc
        return payload.get("hits", {}).get("hits", [])

    def search(
        self,
        *,
        rule_id: str,
        run_id: str,
        session_id: str,
        started_at: str,
        correlated: bool = True,
    ) -> list[dict[str, Any]]:
        filters: list[dict[str, Any]] = [
            {"term": {"kibana.alert.rule.rule_id": rule_id}},
            {"range": {"@timestamp": {"gte": started_at}}},
        ]
        if correlated:
            filters.extend(
                [
                    {"term": {"watchmyai.context.validation_run_id": run_id}},
                    {"term": {"watchmyai.session.id": session_id}},
                ]
            )
        body = {
            "size": 10,
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": filters}},
        }
        return self._search_index(self.alert_index, body)

    def search_native_events(self, *, rule_id: str, run_id: str, started_at: str) -> list[dict[str, Any]]:
        event_types, _ = NATIVE_RULE_REQUIREMENTS[rule_id]
        body = {
            "size": 1000,
            "sort": [{"@timestamp": "asc"}],
            "_source": [
                "@timestamp",
                "event.id",
                "event.type",
                "file.path",
                "process.entity_id",
            ],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"event.category": "file"}},
                        {"terms": {"event.type": sorted(event_types)}},
                        {"range": {"@timestamp": {"gte": started_at}}},
                        {
                            "wildcard": {
                                "file.path": {
                                    "value": f"*{run_id}*",
                                    "case_insensitive": True,
                                }
                            }
                        },
                    ]
                }
            },
        }
        return self._search_index(NATIVE_FILE_INDEX_PATTERN, body)


def alert_is_current(hit: dict[str, Any], started_at: str) -> bool:
    source = hit.get("_source", {})
    alert_time = str(source.get("@timestamp", ""))
    if not alert_time:
        return False
    start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    observed = datetime.fromisoformat(alert_time.replace("Z", "+00:00"))
    return observed >= start


def _source_field(source: dict[str, Any], dotted: str) -> Any:
    if dotted in source:
        return source[dotted]
    value: Any = source
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def threshold_alert_matches_entity(hit: dict[str, Any], entity_id: str) -> bool:
    """Return whether a threshold alert identifies the expected grouped process."""
    source = hit.get("_source", {})
    result = _source_field(source, "kibana.alert.threshold_result")
    terms = result.get("terms", []) if isinstance(result, dict) else []
    if not terms:
        terms = _source_field(source, "kibana.alert.threshold_result.terms") or []
    if not isinstance(terms, list):
        return False
    return any(
        isinstance(term, dict)
        and term.get("field") == "process.entity_id"
        and str(term.get("value")) == entity_id
        for term in terms
    )


def native_source_evidence(hits: list[dict[str, Any]], *, threshold: int) -> dict[str, Any] | None:
    """Select unambiguous run-marked native events from one process entity."""
    grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    for hit in hits:
        source = hit.get("_source", {})
        entity = _source_field(source, "process.entity_id")
        timestamp = str(_source_field(source, "@timestamp") or "")
        document_id = str(hit.get("_id") or _source_field(source, "event.id") or "")
        index = str(hit.get("_index", ""))
        identity = (index, document_id)
        if not isinstance(entity, str) or not entity or not timestamp or not document_id:
            continue
        if identity in seen:
            continue
        seen.add(identity)
        grouped[entity].append((timestamp, document_id))
    eligible = [entity for entity, records in grouped.items() if len(records) >= threshold]
    if len(eligible) > 1:
        raise RuntimeError("run-marked native events are ambiguous across multiple process entities")
    if not eligible:
        return None
    entity = eligible[0]
    records = sorted(grouped[entity])
    return {
        "process_entity_id": entity,
        "source_event_count": len(records),
        "source_event_ids": [document_id for _, document_id in records],
        "latest_source_timestamp": records[-1][0],
    }


def _elastic_sink(config: dict[str, str]) -> ElasticSink:
    api_key = config.get("ELASTIC_API_KEY", "")
    key_file = config.get("ELASTIC_API_KEY_FILE", "")
    if not api_key and key_file:
        api_key = resolve_repository_path(key_file).read_text("utf-8").strip()
    return ElasticSink(
        config["ELASTICSEARCH_URL"],
        index=config["SOURCE_DATA_STREAM"].replace("*", "default"),
        api_key=api_key or None,
        username=config.get("ELASTIC_USERNAME") or None,
        password=config.get("ELASTIC_PASSWORD") or None,
        verify_tls=parse_bool(config.get("TLS_VERIFY", "true"), name="TLS_VERIFY"),
        ca_file=(
            str(resolve_repository_path(config["ELASTIC_CA_CERT"])) if config.get("ELASTIC_CA_CERT") else None
        ),
    )


def _poll_alert(
    client: AlertClient,
    *,
    rule_id: str,
    run_id: str,
    session_id: str,
    started_at: str,
    timeout: int,
    interval: int,
    correlated: bool = True,
    threshold_entity_id: str | None = None,
) -> tuple[str | None, str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hits = client.search(
            rule_id=rule_id,
            run_id=run_id,
            session_id=session_id,
            started_at=started_at,
            correlated=correlated,
        )
        for hit in hits:
            if alert_is_current(hit, started_at) and (
                threshold_entity_id is None or threshold_alert_matches_entity(hit, threshold_entity_id)
            ):
                return str(hit.get("_id", "")), datetime.now(UTC).isoformat()
        time.sleep(interval)
    return None, datetime.now(UTC).isoformat()


def _poll_native_source_evidence(
    client: AlertClient,
    *,
    rule_id: str,
    run_id: str,
    started_at: str,
    timeout: int,
    interval: int,
) -> dict[str, Any]:
    _, threshold = NATIVE_RULE_REQUIREMENTS[rule_id]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        evidence = native_source_evidence(
            client.search_native_events(rule_id=rule_id, run_id=run_id, started_at=started_at),
            threshold=threshold,
        )
        if evidence:
            evidence["validation_run_id"] = run_id
            evidence["confirmed_at"] = datetime.now(UTC).isoformat()
            return evidence
        time.sleep(interval)
    raise RuntimeError(
        f"{rule_id} produced fewer than {threshold} run-marked native file events "
        "from one process entity before the validation timeout"
    )


def verify_current_alert(
    config: dict[str, str],
    *,
    rule_id: str,
    run_id: str,
    session_id: str,
    started_at: str,
) -> str:
    """Return the correlated current-run alert ID or fail with a useful reason."""
    alert_id, _ = _poll_alert(
        AlertClient(config),
        rule_id=rule_id,
        run_id=run_id,
        session_id=session_id,
        started_at=started_at,
        timeout=int(config.get("VALIDATION_TIMEOUT_SECONDS", "180")),
        interval=int(config.get("POLL_INTERVAL_SECONDS", "5")),
    )
    if not alert_id:
        raise RuntimeError(
            f"{rule_id} produced no correlated current-run alert before the validation timeout"
        )
    return alert_id


def _run_live(config_path: Path) -> tuple[Stage, list[dict[str, Any]]]:
    config = _config(config_path)
    if not parse_bool(config.get("ENABLE_RULES", "false"), name="ENABLE_RULES"):
        return (
            Stage(
                "live prerequisites",
                "FAIL",
                "ENABLE_RULES must be explicitly set to true for controlled live alert correlation",
            ),
            [],
        )
    if not parse_bool(config.get("WATCHMYAI_LAB_MODE", "false"), name="WATCHMYAI_LAB_MODE"):
        return (
            Stage(
                "live prerequisites",
                "FAIL",
                "WATCHMYAI_LAB_MODE must be explicitly set to true for controlled live alert correlation",
            ),
            [],
        )
    preflight = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/preflight.py"),
            "--config",
            str(config_path),
            "--json",
            "--allow-dirty",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    try:
        readiness = json.loads(preflight.stdout)
    except json.JSONDecodeError:
        readiness = {}
    if preflight.returncode:
        failures = [
            f"{item.get('name')}: {item.get('detail')}"
            for item in readiness.get("checks", [])
            if item.get("status") == "FAIL"
        ]
        reason = "; ".join(failures) or (preflight.stdout + preflight.stderr)[-2000:]
        return Stage("live prerequisites", "FAIL", reason), []

    imported = _command(
        "rule import and enablement",
        [
            sys.executable,
            str(ROOT / "scripts/import/import_rules.py"),
            "--config",
            str(config_path),
        ],
    )
    if imported.status != "PASS":
        return imported, []

    timeout = int(config["VALIDATION_TIMEOUT_SECONDS"])
    interval = int(config["POLL_INTERVAL_SECONDS"])
    sink = _elastic_sink(config)
    alerts = AlertClient(config)
    results: list[dict[str, Any]] = []
    for rule_id in SUPPORTED_IDS:
        try:
            scenario = write_scenario(rule_id, config_path=config_path)
            if scenario["status"] == "SKIPPED":
                results.append(scenario)
                continue
            if scenario["ingest_mode"] == "watchmyai_fixture":
                records = [record.value for record in iter_ndjson(Path(scenario["telemetry_path"]))]
                sink.send(records)
            native_evidence: dict[str, Any] | None = None
            alert_started_at = scenario["start_timestamp"]
            threshold_entity_id: str | None = None
            if scenario["ingest_mode"] == "endpoint_native":
                native_path = str(scenario.get("native_path_marker") or "")
                if not native_path or scenario["run_id"] not in native_path:
                    raise RuntimeError(f"{rule_id} native path does not carry its validation run ID")
                native_evidence = _poll_native_source_evidence(
                    alerts,
                    rule_id=rule_id,
                    run_id=scenario["run_id"],
                    started_at=scenario["start_timestamp"],
                    timeout=timeout,
                    interval=interval,
                )
                native_evidence["path_marker"] = native_path
                alert_started_at = native_evidence["latest_source_timestamp"]
                threshold_entity_id = native_evidence["process_entity_id"]
            alert_id, ended_at = _poll_alert(
                alerts,
                rule_id=rule_id,
                run_id=scenario["run_id"],
                session_id=scenario["session_id"],
                started_at=alert_started_at,
                timeout=timeout,
                interval=interval,
                correlated=scenario["ingest_mode"] == "watchmyai_fixture",
                threshold_entity_id=threshold_entity_id,
            )
            scenario.update(
                {
                    "status": "PASS" if alert_id else "FAIL",
                    "end_timestamp": ended_at,
                    "polling_interval_seconds": interval,
                    "maximum_timeout_seconds": timeout,
                    "matched_alert_identifier": alert_id,
                    "native_correlation": native_evidence,
                    "reason": "" if alert_id else "no correlated current-run alert before timeout",
                }
            )
            results.append(scenario)
        except Exception as exc:  # noqa: BLE001 - preserve per-rule error reporting
            results.append({"status": "ERROR", "rule_id": rule_id, "error": str(exc)})
    return imported, results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / ".env")
    parser.add_argument("--live", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "runtime/validation-results.json",
    )
    args = parser.parse_args()
    stages: list[Stage] = []

    config_target = args.config if args.config.is_file() else ROOT / ".env.example"
    config_command = [
        sys.executable,
        str(ROOT / "scripts/validate/validate_config.py"),
        "--config",
        str(config_target),
    ]
    if config_target.name == ".env.example":
        config_command.append("--template")
    stages.append(_command("configuration validation", config_command))
    stages.append(
        _command(
            "repository preflight",
            [
                sys.executable,
                str(ROOT / "scripts/preflight.py"),
                "--repository-only",
                "--allow-dirty",
            ],
        )
    )
    stages.append(
        _command(
            "telemetry schema validation",
            [
                sys.executable,
                str(ROOT / "scripts/validate/validate_telemetry_schema.py"),
            ],
        )
    )
    stages.append(
        _command(
            "NDJSON validation",
            [
                sys.executable,
                str(ROOT / "scripts/validate/validate_ndjson.py"),
                "--telemetry-schema",
                str(ROOT / "fixtures/telemetry/canonical.ndjson"),
            ],
        )
    )
    stages.append(
        _command(
            "rule and fixture validation",
            [sys.executable, "scripts/validate.py"],
            cwd=ROOT / "detection-rules",
        )
    )
    stages.append(validate_scenario_contract())
    stages.append(
        _command(
            "importer duplicate-safe dry-run",
            [sys.executable, str(ROOT / "scripts/import/import_rules.py"), "--dry-run"],
        )
    )
    with tempfile.TemporaryDirectory(prefix="watchmyai-package-") as output_dir:
        stages.append(
            _command(
                "release package",
                [
                    sys.executable,
                    "scripts/package_rules.py",
                    "--output-dir",
                    output_dir,
                ],
                cwd=ROOT / "detection-rules",
            )
        )

    live_results: list[dict[str, Any]] = []
    if args.live:
        if not args.config.is_file():
            stages.append(
                Stage(
                    "live prerequisites",
                    "FAIL",
                    f"runtime configuration is unavailable: {args.config}",
                )
            )
        else:
            live_stage, live_results = _run_live(args.config)
            stages.append(live_stage)
        live_complete = len(live_results) == SUPPORTED_COUNT and all(
            item.get("status") == "PASS" for item in live_results
        )
        stages.append(
            Stage(
                "controlled fixture-event alert correlation",
                "PASS" if live_complete else "FAIL",
                (
                    f"{SUPPORTED_COUNT}/{SUPPORTED_COUNT} current-run rule alerts matched"
                    if live_complete
                    else f"{sum(item.get('status') == 'PASS' for item in live_results)}/"
                    f"{SUPPORTED_COUNT} current-run rule alerts matched"
                ),
            )
        )
    else:
        stages.append(
            Stage(
                "controlled fixture-event alert correlation",
                "SKIPPED",
                "not requested; rerun with --live in the configured disposable lab",
            )
        )

    static_failed = any(
        stage.status in {"FAIL", "ERROR"}
        for stage in stages
        if stage.name != "controlled fixture-event alert correlation" and not stage.name.startswith("live ")
    )
    live_failed = args.live and not (
        len(live_results) == SUPPORTED_COUNT and all(item.get("status") == "PASS" for item in live_results)
    )
    result = {
        "release": f"v{PROJECT_VERSION}",
        "supported_rule_count": SUPPORTED_COUNT,
        "supported_rules": list(SUPPORTED_IDS),
        "static_validation": "FAIL" if static_failed else "PASS",
        "live_fixture_alert_correlation": (
            "FAIL" if args.live and live_failed else "PASS" if args.live else "SKIPPED"
        ),
        "stages": [asdict(stage) for stage in stages],
        "rule_results": live_results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf-8")
    for stage in stages:
        print(f"[{stage.status}] {stage.name}: {stage.detail}")
    print(f"Results: {args.output}")
    return EXIT_VALIDATION if static_failed or live_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
