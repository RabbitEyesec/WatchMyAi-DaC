#!/usr/bin/env python3
"""Verify that real Windows Sysmon events reach Elastic with the ECS fields WatchMyAI needs.

Two modes:

* Live (default): query ``logs-windows.sysmon_operational-*`` through the Elasticsearch REST API
  using the same environment variables as the rest of WatchMyAI (ELASTICSEARCH_URL,
  ELASTIC_API_KEY or ELASTIC_USERNAME/ELASTIC_PASSWORD, TLS_VERIFY, ELASTIC_CA_CERT).
* ``--fixture FILE``: validate a saved, sanitised JSON list of documents (golden captures)
  without any network access.

With ``--run-id`` (from scripts/validate/generate-sysmon-load.ps1) the tool also counts the
run's file creations and deletions per ``process.entity_id`` against the WMAI-023 (50) and
WMAI-024 (20) thresholds and reports whether the alert index holds a matching alert.

Exit codes: 0 pass, 1 fail, 2 skipped (no connection settings). Skips are never reported as pass.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

INDEX = "logs-windows.sysmon_operational-*"
EXPECTED_DATASET = "windows.sysmon_operational"
FILE_EVENT_IDS = {"11": "creation", "23": "deletion", "26": "deletion"}
THRESHOLDS = {"WMAI-023": ("creation", 50), "WMAI-024": ("deletion", 20)}


def dig(doc: dict[str, Any], dotted: str) -> Any:
    """Read a field from either nested ({'a': {'b': 1}}) or flat ({'a.b': 1}) documents."""
    if dotted in doc:
        return doc[dotted]
    current: Any = doc
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value is None else [value])


def check_document(doc: dict[str, Any]) -> list[str]:
    """Return ECS acceptance-contract violations for one Sysmon document."""
    problems: list[str] = []
    source = doc.get("_source", doc)
    event_id = str(dig(source, "winlog.event_id") or "")
    if not event_id:
        problems.append("winlog.event_id missing (source Sysmon event ID not preserved)")
    timestamp = dig(source, "@timestamp")
    if not isinstance(timestamp, str):
        problems.append("@timestamp missing")
    else:
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                problems.append("@timestamp has no timezone (expected UTC)")
        except ValueError:
            problems.append(f"@timestamp not ISO-8601: {timestamp!r}")
    if dig(source, "event.dataset") != EXPECTED_DATASET:
        problems.append(f"event.dataset is {dig(source, 'event.dataset')!r}, expected {EXPECTED_DATASET!r}")
    if not (dig(source, "host.id") or dig(source, "host.name")):
        problems.append("host.id and host.name both missing")
    if not (dig(source, "event.id") or dig(source, "winlog.record_id")):
        problems.append("no event.id / winlog.record_id provenance for duplicate suppression")
    if event_id in FILE_EVENT_IDS:
        if "file" not in as_list(dig(source, "event.category")):
            problems.append("file event lacks event.category 'file'")
        if FILE_EVENT_IDS[event_id] not in as_list(dig(source, "event.type")):
            problems.append(f"event {event_id} lacks event.type {FILE_EVENT_IDS[event_id]!r}")
        if not dig(source, "file.path"):
            problems.append("file.path missing on file event")
    if event_id in {"1", *FILE_EVENT_IDS}:
        entity = dig(source, "process.entity_id")
        if not entity:
            problems.append("process.entity_id missing (rules group by it; PID alone is not acceptable)")
    return problems


def summarise(docs: list[dict[str, Any]]) -> dict[str, Any]:
    by_event = Counter(str(dig(d.get("_source", d), "winlog.event_id")) for d in docs)
    failures = {}
    for index, doc in enumerate(docs):
        problems = check_document(doc)
        if problems:
            failures[str(doc.get("_id", index))] = problems
    return {
        "documents": len(docs),
        "by_event_id": dict(sorted(by_event.items())),
        "documents_with_problems": len(failures),
        "problems": dict(list(failures.items())[:20]),
    }


def count_run(docs: list[dict[str, Any]], run_id: str) -> dict[str, Any]:
    counts: dict[str, Counter[str]] = {"creation": Counter(), "deletion": Counter()}
    seen: set[str] = set()
    for doc in docs:
        source = doc.get("_source", doc)
        path = str(dig(source, "file.path") or "")
        if run_id not in path:
            continue
        identity = str(dig(source, "event.id") or dig(source, "winlog.record_id") or doc.get("_id"))
        if identity in seen:  # duplicate delivery of the same record
            continue
        seen.add(identity)
        kind = FILE_EVENT_IDS.get(str(dig(source, "winlog.event_id")))
        if kind:
            key = f"{dig(source, 'host.id') or dig(source, 'host.name')}|{dig(source, 'process.entity_id')}"
            counts[kind][key] += 1
    result = {}
    for rule, (kind, threshold) in THRESHOLDS.items():
        best = counts[kind].most_common(1)
        top = best[0] if best else (None, 0)
        result[rule] = {
            "event_kind": kind,
            "threshold": threshold,
            "max_events_by_one_process_entity": top[1],
            "process_entity": top[0],
            "distinct_process_entities": len(counts[kind]),
            "threshold_met": top[1] >= threshold,
        }
    return result


class Elastic:
    def __init__(self) -> None:
        self.url = os.environ.get("ELASTICSEARCH_URL", "").rstrip("/")
        if not self.url or ".invalid" in self.url:
            raise RuntimeError("ELASTICSEARCH_URL is not configured")
        headers = {"Content-Type": "application/json"}
        key = os.environ.get("ELASTIC_API_KEY", "")
        key_file = os.environ.get("ELASTIC_API_KEY_FILE", "")
        if not key and key_file and Path(key_file).is_file():
            key = Path(key_file).read_text("utf-8").strip()
        if key and key != "__SET_ME__":
            headers["Authorization"] = f"ApiKey {key}"
        elif os.environ.get("ELASTIC_USERNAME"):
            raw = f"{os.environ['ELASTIC_USERNAME']}:{os.environ.get('ELASTIC_PASSWORD', '')}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        else:
            raise RuntimeError("no Elastic credentials configured (ELASTIC_API_KEY or ELASTIC_USERNAME)")
        self.headers = headers
        verify = os.environ.get("TLS_VERIFY", "true").lower() not in {"0", "false", "no"}
        ca = os.environ.get("ELASTIC_CA_CERT", "")
        context = ssl.create_default_context(cafile=ca if ca and Path(ca).is_file() else None)
        if not verify:
            raise RuntimeError(
                "TLS_VERIFY=false is not accepted by this tool; certificate validation is required"
            )
        self.context = context

    def search(self, index: str, body: dict[str, Any]) -> list[dict[str, Any]]:
        request = urllib.request.Request(
            f"{self.url}/{index}/_search", data=json.dumps(body).encode(), headers=self.headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=30) as response:  # noqa: S310
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return []
            raise RuntimeError(f"Elasticsearch returned HTTP {exc.code} for {index}") from exc
        return list(payload.get("hits", {}).get("hits", []))


def live_documents(client: Elastic, minutes: int, run_id: str | None, size: int) -> list[dict[str, Any]]:
    must: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}]
    if run_id:
        must.append({"wildcard": {"file.path": {"value": f"*{run_id}*", "case_insensitive": True}}})
    body = {"size": size, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"must": must}}}
    return client.search(INDEX, body)


def alerts_for(client: Elastic, rule_id: str, minutes: int) -> int:
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "must": [
                    {"term": {"kibana.alert.rule.rule_id": rule_id}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                ]
            }
        },
    }
    request = urllib.request.Request(
        f"{client.url}/.alerts-security.alerts-*/_search",
        data=json.dumps(body).encode(),
        headers=client.headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, context=client.context, timeout=30) as response:  # noqa: S310
            return int(json.load(response)["hits"]["total"]["value"])
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 0
        raise RuntimeError(f"alert index query failed with HTTP {exc.code}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--fixture", type=Path, help="validate saved documents instead of querying Elastic")
    parser.add_argument("--minutes", type=int, default=30, help="look-back window for live queries")
    parser.add_argument("--size", type=int, default=500, help="maximum documents to inspect")
    parser.add_argument("--run-id", help="run ID printed by generate-sysmon-load.ps1")
    parser.add_argument("--output", type=Path, help="write a sanitised JSON report here")
    args = parser.parse_args(argv)

    report: dict[str, Any] = {
        "generated_utc": datetime.now(UTC).isoformat(),
        "index": INDEX,
        "mode": "fixture" if args.fixture else "live",
        "run_id": args.run_id,
    }
    client: Elastic | None = None
    try:
        if args.fixture:
            docs = json.loads(args.fixture.read_text("utf-8"))
            if not isinstance(docs, list):
                raise ValueError("fixture must be a JSON list of documents")
        else:
            try:
                client = Elastic()
            except RuntimeError as exc:
                print(f"SKIPPED: {exc}", file=sys.stderr)
                return 2
            docs = live_documents(client, args.minutes, args.run_id, args.size)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    if not docs:
        print(f"FAIL: no Sysmon documents found in {INDEX}", file=sys.stderr)
        return 1
    report["field_contract"] = summarise(docs)
    ok = report["field_contract"]["documents_with_problems"] == 0

    if args.run_id:
        report["run_counts"] = count_run(docs, args.run_id)
        report["attribution"] = "endpoint-only"
        if client is not None:
            for rule in THRESHOLDS:
                report["run_counts"][rule]["alerts_in_window"] = alerts_for(client, rule, args.minutes)
        for rule, info in report["run_counts"].items():
            alerts = info.get("alerts_in_window")
            detail = "" if alerts is None else f", alerts_in_window={alerts}"
            print(
                f"{rule}: max {info['max_events_by_one_process_entity']} {info['event_kind']} events by one "
                f"process.entity_id (threshold {info['threshold']}, met={info['threshold_met']}{detail})"
            )

    if args.output:
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = report["field_contract"]
    print(f"Inspected {summary['documents']} documents; by Sysmon event ID: {summary['by_event_id']}")
    if not ok:
        for doc_id, problems in summary["problems"].items():
            for problem in problems:
                print(f"FAIL: {doc_id}: {problem}", file=sys.stderr)
        return 1
    print("PASS: Sysmon documents satisfy the ECS field contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
