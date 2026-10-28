#!/usr/bin/env python3
"""Correlate AI-agent actions (watchmyai.events) with endpoint process events (Sysmon / Elastic Defend).

Each endpoint process-start event receives an attribution level and the evidence behind it:

* ``confirmed``     same host, and the endpoint process (or its parent / ancestry) has the same
                    ``process.entity_id`` as the process recorded by the gateway for that action;
* ``strong``        same host, matching process ID (or parent process ID) and matching command line;
* ``probable``      same host and matching command line inside the time window;
* ``endpoint-only`` nothing links the event to an agent action. ``missing_links`` lists what was absent.

Activity is never reported as agent-caused without one of the first three levels.

Usage:
    python scripts/validate/correlate_agent_endpoint.py --agent-events agent.json --endpoint-events endpoint.json
    python scripts/validate/correlate_agent_endpoint.py --minutes 30          # live, uses ELASTICSEARCH_URL etc.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify_sysmon_ingest import Elastic, dig  # noqa: E402

AGENT_INDEX = "logs-watchmyai.events-*"
ENDPOINT_INDEX = "logs-windows.sysmon_operational-*,logs-endpoint.events.process-*"
CLOCK_SKEW = timedelta(seconds=2)
LEVELS = ("confirmed", "strong", "probable", "endpoint-only")


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def normalise_command(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def agent_command(doc: dict[str, Any]) -> str:
    return normalise_command(
        dig(doc, "watchmyai.tool.arguments.command") or dig(doc, "process.command_line") or ""
    )


def commands_match(agent: str, endpoint: str) -> bool:
    if not agent or not endpoint or "[redacted" in agent:
        return False
    return agent == endpoint or agent in endpoint or endpoint in agent


def ancestry_ids(doc: dict[str, Any]) -> set[str]:
    ids = {str(dig(doc, "process.parent.entity_id") or "")}
    for item in dig(doc, "process.ancestry") or []:
        if isinstance(item, dict):
            ids.add(str(item.get("entity_id") or ""))
    ids.discard("")
    return ids


def correlate_event(
    endpoint: dict[str, Any], agents: list[dict[str, Any]], window: timedelta
) -> dict[str, Any]:
    host = str(dig(endpoint, "host.name") or dig(endpoint, "host.id") or "")
    when = parse_time(dig(endpoint, "@timestamp"))
    command = normalise_command(dig(endpoint, "process.command_line"))
    entity = str(dig(endpoint, "process.entity_id") or "")
    pid = dig(endpoint, "process.pid")
    parent_pid = dig(endpoint, "process.parent.pid")
    lineage = ancestry_ids(endpoint) | ({entity} if entity else set())

    result: dict[str, Any] = {
        "endpoint_event_id": dig(endpoint, "event.id") or endpoint.get("_id"),
        "host": host,
        "process_entity_id": entity or None,
        "attribution": "endpoint-only",
        "agent_action_id": None,
        "session_id": None,
        "evidence": [],
        "missing_links": [],
    }
    best_rank = len(LEVELS) - 1
    for agent in agents:
        a_host = str(dig(agent, "host.name") or dig(agent, "host.id") or "")
        a_time = parse_time(dig(agent, "@timestamp"))
        if not host or host != a_host or when is None or a_time is None:
            continue
        if not (a_time - CLOCK_SKEW <= when <= a_time + window):
            continue
        a_entity = str(dig(agent, "process.entity_id") or "")
        a_pid = dig(agent, "process.pid")
        same_command = commands_match(agent_command(agent), command)
        evidence: list[str] = []
        level = "endpoint-only"
        if a_entity and a_entity in lineage:
            level, evidence = (
                "confirmed",
                ["same host", "process.entity_id in endpoint lineage", "inside window"],
            )
        elif a_pid is not None and a_pid in (pid, parent_pid) and same_command:
            level, evidence = (
                "strong",
                ["same host", "process ID match", "command line match", "inside window"],
            )
        elif same_command:
            level, evidence = "probable", ["same host", "command line match", "inside window"]
        rank = LEVELS.index(level)
        if rank < best_rank:
            best_rank = rank
            result.update(
                attribution=level,
                agent_action_id=dig(agent, "watchmyai.action.id"),
                session_id=dig(agent, "watchmyai.session.id"),
                evidence=evidence,
            )
    if result["attribution"] == "endpoint-only":
        missing = []
        if not agents:
            missing.append("no agent events supplied")
        if not entity:
            missing.append("endpoint event lacks process.entity_id")
        if not command:
            missing.append("endpoint event lacks process.command_line")
        if not missing:
            missing.append(
                "no agent action on this host matched entity, process ID, or command inside the window"
            )
        result["missing_links"] = missing
    return result


def correlate(
    agent_events: list[dict[str, Any]], endpoint_events: list[dict[str, Any]], window_seconds: int = 60
) -> dict[str, Any]:
    window = timedelta(seconds=window_seconds)
    rows = [
        correlate_event(event.get("_source", event), [a.get("_source", a) for a in agent_events], window)
        for event in endpoint_events
    ]
    counts = {level: sum(1 for r in rows if r["attribution"] == level) for level in LEVELS}
    return {"window_seconds": window_seconds, "counts": counts, "results": rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--agent-events", type=Path, help="JSON list of watchmyai.events documents")
    parser.add_argument("--endpoint-events", type=Path, help="JSON list of endpoint process documents")
    parser.add_argument("--minutes", type=int, default=30, help="live look-back window")
    parser.add_argument("--window", type=int, default=60, help="seconds after an agent action to correlate")
    parser.add_argument("--output", type=Path, help="write the JSON report here")
    args = parser.parse_args(argv)

    try:
        if args.agent_events and args.endpoint_events:
            agents = json.loads(args.agent_events.read_text("utf-8"))
            endpoints = json.loads(args.endpoint_events.read_text("utf-8"))
        else:
            try:
                client = Elastic()
            except RuntimeError as exc:
                print(f"SKIPPED: {exc}", file=sys.stderr)
                return 2
            query = {"bool": {"must": [{"range": {"@timestamp": {"gte": f"now-{args.minutes}m"}}}]}}
            agents = client.search(AGENT_INDEX, {"size": 1000, "query": query})
            endpoint_query = {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{args.minutes}m"}}},
                        {"term": {"event.category": "process"}},
                    ]
                }
            }
            endpoints = client.search(ENDPOINT_INDEX, {"size": 1000, "query": endpoint_query})
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    report = correlate(agents, endpoints, args.window)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    counts = report["counts"]
    print(
        f"Correlated {len(report['results'])} endpoint events: "
        + ", ".join(f"{level}={counts[level]}" for level in LEVELS)
    )
    for row in report["results"]:
        detail = row["agent_action_id"] or "; ".join(row["missing_links"])
        print(f"  {row['attribution']:<14} {row['host']} {row['process_entity_id'] or '-'} -> {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
