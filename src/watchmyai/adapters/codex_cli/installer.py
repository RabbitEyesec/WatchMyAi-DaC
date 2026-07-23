"""Non-destructive Codex lifecycle-hook installer for ~/.codex/hooks.json."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HOOK_COMMAND = "watchmyai hook codex"
EVENTS = (
    "SessionStart",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "UserPromptSubmit",
    "SubagentStart",
    "SubagentStop",
    "Stop",
)


def default_hooks_path() -> Path:
    import os

    return Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "hooks.json"


def default_config_path() -> Path:
    """Stable compatibility name; lifecycle hooks live in hooks.json."""
    return default_hooks_path()


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    backup = path.with_name(f"{path.name}.wmai-backup-{stamp}")
    shutil.copy2(path, backup)
    return backup


def _validate_document(document: Any, path: Path) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ValueError(f"{path}: Codex hooks must be a JSON object")
    hooks = document.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"{path}: hooks must be a JSON object")
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            raise ValueError(f"{path}: hooks.{event} must be an array")
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("hooks", []), list):
                raise ValueError(f"{path}: hooks.{event} contains an invalid hook group")
    return document


def _atomic_write(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(document, indent=2) + "\n", "utf-8")
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _ours(hook: dict[str, Any]) -> bool:
    command = str(hook.get("command", "")).strip().replace('"', "").replace("'", "")
    return hook.get("type") == "command" and (command == HOOK_COMMAND or command.endswith(" hook codex"))


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
    arguments = [str(_adapter_path())]
    home = os.environ.get("WATCHMYAI_HOME", "").strip()
    if home:
        arguments.extend(["--home", str(Path(home).expanduser().resolve())])
    arguments.extend(["hook", "codex"])
    if os.name == "nt":
        return subprocess.list2cmdline(arguments)
    import shlex

    return shlex.join(arguments)


def install(config_path: Path | None = None) -> dict[str, Any]:
    path = config_path or default_hooks_path()
    document = _validate_document(json.loads(path.read_text("utf-8")) if path.exists() else {}, path)
    hooks = document.setdefault("hooks", {})
    added: list[str] = []
    for event in EVENTS:
        groups = hooks.setdefault(event, [])
        if any(_ours(handler) for group in groups for handler in group.get("hooks", [])):
            continue
        group: dict[str, Any] = {
            "hooks": [
                {
                    "type": "command",
                    "command": _hook_command(),
                    "timeout": 10,
                    "statusMessage": "Applying WatchMyAI policy",
                }
            ]
        }
        if event in {"PreToolUse", "PermissionRequest", "PostToolUse"}:
            group["matcher"] = "*"
        groups.append(group)
        added.append(event)
    backup = _backup(path) if added else None
    if added:
        _atomic_write(path, document)
    return {
        "config_path": str(path),
        "backup": str(backup) if backup else None,
        "changed": bool(added),
        "events_added": added,
        "note": "Codex lifecycle hooks installed",
    }


def uninstall(config_path: Path | None = None) -> dict[str, Any]:
    path = config_path or default_hooks_path()
    if not path.exists():
        return {"config_path": str(path), "backup": None, "changed": False, "events_removed": []}
    document = _validate_document(json.loads(path.read_text("utf-8")), path)
    removed: list[str] = []
    hooks = document.get("hooks", {})
    for event in list(hooks):
        kept_groups = []
        for group in hooks[event]:
            before = group.get("hooks", [])
            kept = [handler for handler in before if not _ours(handler)]
            if len(kept) != len(before):
                removed.append(event)
            if kept:
                kept_groups.append({**group, "hooks": kept})
        if kept_groups:
            hooks[event] = kept_groups
        else:
            del hooks[event]
    backup = _backup(path) if removed else None
    if removed:
        _atomic_write(path, document)
    return {
        "config_path": str(path),
        "backup": str(backup) if backup else None,
        "changed": bool(removed),
        "events_removed": sorted(set(removed)),
    }


def status(config_path: Path | None = None) -> dict[str, Any]:
    path = config_path or default_hooks_path()
    installed: list[str] = []
    if path.exists():
        document = _validate_document(json.loads(path.read_text("utf-8")), path)
        for event, groups in (document.get("hooks") or {}).items():
            if any(_ours(handler) for group in groups for handler in group.get("hooks", [])):
                installed.append(event)
    return {
        "config_path": str(path),
        "installed_events": sorted(installed),
        "hooks_installed": bool(installed),
    }
