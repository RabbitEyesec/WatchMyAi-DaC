"""Normalizer: completes, redacts, and validates events.

Adapters emit *partial* events — just the fields they can truthfully
populate. The normalizer adds the common envelope (@timestamp, event.id,
host, user, schema version), applies redaction, and validates against the
JSON Schema. Invalid events raise ``InvalidEventError`` so the export
pipeline can route them to the dead-letter file instead of shipping them.

Clock and id factory are injectable for deterministic tests.
"""

from __future__ import annotations

import getpass
import hashlib
import platform
import sys
from collections.abc import Callable
from typing import Any

from watchmyai.privacy.redaction import Redactor
from watchmyai.schema.event import (
    SCHEMA_VERSION,
    canonical_hash,
    deep_merge,
    new_event_id,
    utc_now_iso,
    validate_event,
)


class InvalidEventError(ValueError):
    def __init__(self, errors: list[str], doc: dict[str, Any]):
        super().__init__("; ".join(errors))
        self.errors = errors
        self.doc = doc


def _os_type() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def default_host() -> dict[str, Any]:
    name = platform.node() or "unknown-host"
    return {
        "id": hashlib.sha256(name.encode("utf-8")).hexdigest()[:16],
        "name": name,
        "os": {"type": _os_type(), "name": platform.system(), "version": platform.release()},
    }


def default_user() -> dict[str, Any]:
    try:
        name = getpass.getuser()
    except (KeyError, OSError):  # no passwd entry (containers)
        name = "unknown"
    return {"name": name}


class Normalizer:
    def __init__(
        self,
        redactor: Redactor | None = None,
        clock: Callable[[], str] = utc_now_iso,
        id_factory: Callable[[], str] = new_event_id,
        host: dict[str, Any] | None = None,
        user: dict[str, Any] | None = None,
    ):
        self.redactor = redactor or Redactor()
        self.clock = clock
        self.id_factory = id_factory
        self.host = host or default_host()
        self.user = user or default_user()

    def normalize(self, partial: dict[str, Any]) -> dict[str, Any]:
        base: dict[str, Any] = {
            "@timestamp": self.clock(),
            "event": {
                "id": self.id_factory(),
                "kind": "event",
                "dataset": "watchmyai.events",
                "provider": "watchmyai",
            },
            "host": self.host,
            "user": self.user,
            "watchmyai": {
                "schema": {"version": SCHEMA_VERSION},
                "agent": {"type": "unknown_ai_agent"},
                "attribution": {"level": "unknown"},
            },
        }
        doc = deep_merge(base, partial)
        action = doc["watchmyai"].setdefault("action", {})
        action.setdefault("id", f"action:{doc['event']['id']}")
        event_types = set(doc["event"].get("type", []))
        if event_types & {"access", "change", "creation", "deletion", "end"}:
            action.setdefault("executed_at", doc["@timestamp"])
            action.setdefault("execution_status", "executed")
        elif "start" in event_types:
            action.setdefault("execution_status", "requested")
        command_line = doc.get("process", {}).get("command_line")
        if command_line:
            action.setdefault("command_hash", canonical_hash(command_line))
        target = (
            doc.get("file", {}).get("path")
            or doc.get("destination", {}).get("domain")
            or doc.get("destination", {}).get("ip")
        )
        if target:
            action.setdefault("target_hash", canonical_hash(target))
        doc = self.redactor.redact_event(doc)
        errors = validate_event(doc)
        if errors:
            raise InvalidEventError(errors, doc)
        return doc

    def normalize_all(self, partials: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.normalize(p) for p in partials]
