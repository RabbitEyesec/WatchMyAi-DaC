"""Claude Code hook installer.

Non-destructive by design:
- the existing settings.json is backed up (timestamped copy) before any change;
- our hook entries are additive and tagged by their command string, so
  uninstall removes exactly what install added and nothing else;
- install is idempotent.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from watchmyai.adapters.claude_code.adapter import HOOK_EVENTS

HOOK_COMMAND = "watchmyai hook claude"
# Tool lifecycle hooks take a matcher; "*" mediates every tool.
MATCHER_EVENTS = {"PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "PermissionDenied"}


def default_settings_path() -> Path:
    configured = os.environ.get("CLAUDE_SETTINGS_PATH", "").strip()
    return Path(configured).expanduser() if configured else Path.home() / ".claude" / "settings.json"


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    backup = path.with_name(f"{path.name}.wmai-backup-{stamp}")
    shutil.copy2(path, backup)
    return backup


def _atomic_write(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(document, indent=2) + "\n", "utf-8")
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _adapter_path() -> Path:
    configured = os.environ.get("WATCHMYAI_ADAPTER_PATH", "").strip()
    located = shutil.which("watchmyai")
    candidates = [
        Path(configured).expanduser() if configured else None,
        Path(sys.executable).with_name("watchmyai"),
        Path(located) if located is not None else None,
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError(
        "WatchMyAI adapter executable not found; set WATCHMYAI_ADAPTER_PATH to "
        "the repository-local watchmyai executable"
    )


def _hook_command() -> str:
    executable = str(_adapter_path())
    arguments = [executable]
    home = os.environ.get("WATCHMYAI_HOME", "").strip()
    if home:
        arguments.extend(["--home", str(Path(home).expanduser().resolve())])
    arguments.extend(["hook", "claude"])
    if os.name == "nt":
        return subprocess.list2cmdline(arguments)
    import shlex

    return shlex.join(arguments)


def _hook_entry() -> dict[str, Any]:
    return {"type": "command", "command": _hook_command(), "timeout": 10}


def _is_ours(hook: dict[str, Any]) -> bool:
    command = str(hook.get("command", "")).strip().replace('"', "").replace("'", "")
    return command == HOOK_COMMAND or command.endswith(" hook claude")


def _validate_settings(settings: Any, path: Path) -> dict[str, Any]:
    if not isinstance(settings, dict):
        raise ValueError(f"{path}: Claude settings must be a JSON object")
    hooks = settings.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"{path}: hooks must be a JSON object")
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            raise ValueError(f"{path}: hooks.{event} must be an array")
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("hooks", []), list):
                raise ValueError(f"{path}: hooks.{event} contains an invalid hook group")
    return settings


def install(settings_path: Path | None = None) -> dict[str, Any]:
    """Add WatchMyAI hooks for every supported event. Returns a report."""
    path = settings_path or default_settings_path()
    settings: dict[str, Any] = {}
    if path.exists():
        settings = _validate_settings(json.loads(path.read_text("utf-8") or "{}"), path)
    hooks = settings.setdefault("hooks", {})
    added: list[str] = []
    for event in HOOK_EVENTS:
        groups: list[dict[str, Any]] = hooks.setdefault(event, [])
        already = any(_is_ours(h) for g in groups for h in g.get("hooks", []))
        if already:
            continue
        group: dict[str, Any] = {"hooks": [_hook_entry()]}
        if event in MATCHER_EVENTS:
            group["matcher"] = "*"
        groups.append(group)
        added.append(event)
    backup = _backup(path) if added else None
    if added:
        _atomic_write(path, settings)
    verification = verify_controlled_hook_event()
    return {
        "settings_path": str(path),
        "backup": str(backup) if backup else None,
        "events_added": added,
        "already_installed": [e for e in HOOK_EVENTS if e not in added],
        "verification": verification,
    }


def verify_controlled_hook_event() -> dict[str, str]:
    """Exercise the registered adapter-to-normalizer telemetry path without side effects."""
    from watchmyai.adapters.claude_code.adapter import parse_hook_payload
    from watchmyai.normalization.normalizer import Normalizer

    session_id = "watchmyai-hook-install-check"
    partial = parse_hook_payload({"hook_event_name": "SessionStart", "session_id": session_id})[0]
    event = Normalizer(
        clock=lambda: "2026-07-21T00:00:00Z",
        id_factory=lambda: "hook-install-check",
        host={"name": "hook-install-check"},
        user={"name": "hook-install-check"},
    ).normalize(partial)
    if event["watchmyai"]["session"]["id"] != session_id:
        raise RuntimeError("controlled Claude hook lost its session ID")
    if event["event"]["dataset"] != "watchmyai.events":
        raise RuntimeError("controlled Claude hook emitted the wrong dataset")
    return {
        "status": "PASS",
        "event_action": event["event"]["action"],
        "session_id": session_id,
    }


def uninstall(settings_path: Path | None = None) -> dict[str, Any]:
    """Remove only the hook entries whose command is ours."""
    path = settings_path or default_settings_path()
    if not path.exists():
        return {"settings_path": str(path), "backup": None, "events_removed": []}
    settings = _validate_settings(json.loads(path.read_text("utf-8") or "{}"), path)
    original = json.dumps(settings, sort_keys=True)
    hooks = settings.get("hooks", {})
    removed: list[str] = []
    for event in list(hooks.keys()):
        groups = hooks[event]
        new_groups = []
        for group in groups:
            kept = [h for h in group.get("hooks", []) if not _is_ours(h)]
            if kept:
                group["hooks"] = kept
                new_groups.append(group)
            elif not group.get("hooks"):
                new_groups.append(group)  # not a hook group we understand; keep it
            else:
                removed.append(event)
        if new_groups:
            hooks[event] = new_groups
        else:
            del hooks[event]
    if not hooks and "hooks" in settings:
        del settings["hooks"]
    changed = json.dumps(settings, sort_keys=True) != original
    backup = _backup(path) if changed else None
    if changed:
        _atomic_write(path, settings)
    return {
        "settings_path": str(path),
        "backup": str(backup) if backup else None,
        "events_removed": sorted(set(removed)),
    }


def status(settings_path: Path | None = None) -> dict[str, Any]:
    path = settings_path or default_settings_path()
    installed: list[str] = []
    if path.exists():
        try:
            settings = json.loads(path.read_text("utf-8") or "{}")
        except json.JSONDecodeError:
            return {"settings_path": str(path), "installed_events": [], "error": "settings.json unparseable"}
        duplicate_events: list[str] = []
        for event, groups in (settings.get("hooks") or {}).items():
            count = sum(_is_ours(h) for g in groups for h in g.get("hooks", []))
            if count:
                installed.append(event)
            if count > 1:
                duplicate_events.append(event)
        return {
            "settings_path": str(path),
            "installed_events": sorted(installed),
            "duplicate_events": sorted(duplicate_events),
        }
    return {
        "settings_path": str(path),
        "installed_events": sorted(installed),
        "duplicate_events": [],
    }
