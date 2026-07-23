"""Schema loading, event validation, and event-construction helpers.

The JSON Schema in ``watchmyai_event.schema.json`` is the single source of
truth for what a valid WatchMyAI telemetry event looks like. Every exporter
validates against it before shipping an event.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from functools import lru_cache
from importlib import resources
from typing import Any

import jsonschema

SCHEMA_VERSION = "1.1.0"
SCHEMA_RESOURCE = "watchmyai_event.schema.json"


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """Load the packaged JSON Schema document."""
    raw = resources.files("watchmyai.schema").joinpath(SCHEMA_RESOURCE).read_text("utf-8")
    return json.loads(raw)


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    schema = load_schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def validate_event(doc: dict[str, Any]) -> list[str]:
    """Return a list of validation error strings; empty means valid."""
    errors = []
    for err in sorted(_validator().iter_errors(doc), key=lambda e: list(e.absolute_path)):
        path = ".".join(str(p) for p in err.absolute_path) or "<root>"
        errors.append(f"{path}: {err.message}")
    return errors


def new_event_id() -> str:
    return str(uuid.uuid4())


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_iso(ts: float) -> str:
    """Convert an epoch timestamp to the schema's ISO-8601 format."""
    dt = datetime.fromtimestamp(ts, tz=UTC)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_hash(payload: Any) -> str:
    """Deterministic sha256 over a canonical JSON encoding, prefixed 'sha256:'."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def put(doc: dict[str, Any], dotted: str, value: Any) -> dict[str, Any]:
    """Set a nested value by dotted path, creating intermediate objects.

    ``put(e, "watchmyai.tool.name", "shell")`` builds the nested dicts. Values
    of ``None`` are skipped so callers can pass through optional fields.
    """
    if value is None:
        return doc
    node = doc
    parts = dotted.split(".")
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = value
    return doc


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``overlay`` into a copy of ``base``; overlay wins."""
    out: dict[str, Any] = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out
