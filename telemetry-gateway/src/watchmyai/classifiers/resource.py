"""Resource allowlist helpers with normalized domain semantics."""

from __future__ import annotations

from fnmatch import fnmatch
from urllib.parse import urlparse


def destination_approved(destination: str | None, allowed: list[str]) -> bool:
    if destination is None:
        return True
    value = destination.lower().rstrip(".")
    for pattern in allowed:
        candidate = pattern.lower().rstrip(".")
        if fnmatch(value, candidate):
            return True
        if "*" not in candidate and value.endswith("." + candidate):
            return True
    return False


def repository_approved(repository_id: str | None, allowed: list[str]) -> bool:
    if repository_id is None:
        return False
    value = repository_id.strip().lower()
    if value.startswith("git@") and ":" in value:
        host, path = value[4:].split(":", 1)
        value = f"{host}/{path}"
    elif "://" in value:
        parsed = urlparse(value)
        value = f"{parsed.hostname or ''}{parsed.path}"
    value = value.removesuffix(".git").strip("/")
    return any(fnmatch(value, pattern.lower().removesuffix(".git").strip("/")) for pattern in allowed)
