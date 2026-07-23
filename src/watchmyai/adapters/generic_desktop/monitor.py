"""Generic desktop discovery for agents that cannot be wrapped.

Signature-driven: matches a live (or fixture) process snapshot against
the packaged/operator signature catalogue and emits agent_discovered events with
confidence-based attribution. Process proximity alone never yields
"confirmed" — the discovery engine caps signature matches at "strong".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from watchmyai.capture.process import ProcessRecord, ancestry_chain, snapshot_processes
from watchmyai.discovery.engine import AgentMatch, DiscoveryEngine


def _match_partial(match: AgentMatch, action: str) -> dict[str, Any]:
    partial: dict[str, Any] = {
        "event": {"kind": "event", "category": ["process"], "type": ["info"], "action": action},
        "watchmyai": {
            "agent": {
                "id": match.agent_id,
                "name": match.product,
                "vendor": match.vendor,
                "type": match.agent_type,
                "discovery_method": match.discovery_method,
                "discovery_confidence": match.confidence,
            },
            "attribution": {"level": match.attribution_level},
            "visibility": {"mode": "generic"},
        },
    }
    return partial


def discover_running(
    engine: DiscoveryEngine,
    records: list[ProcessRecord] | None = None,
) -> list[dict[str, Any]]:
    """agent_discovered partial events for running processes.

    ``records`` is injectable for deterministic tests; a live psutil
    snapshot is used otherwise (empty when psutil is unavailable).
    """
    records = records if records is not None else snapshot_processes()
    partials = []
    for match in engine.scan(records):
        partial = _match_partial(match, "agent_discovered")
        proc = match.process
        if proc is not None:
            partial["process"] = proc.to_ecs()
            chain = ancestry_chain(records, proc.pid)
            if chain:
                partial["process"]["ancestry"] = chain
            if proc.username:
                partial["user"] = {"name": proc.username}
        partials.append(partial)
    return partials


def discover_installed(engine: DiscoveryEngine, home: Path | None = None) -> list[dict[str, Any]]:
    """agent_installed events from install/config path evidence."""
    return [_match_partial(m, "agent_installed") for m in engine.scan_installed(home)]
