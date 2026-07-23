"""Codex lifecycle-hook adapter using the documented command-hook schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from watchmyai.core.models import AdapterCapability, ToolRequest
from watchmyai.runtime import RuntimeResult, WatchMyAIRuntime
from watchmyai.schema.event import canonical_hash

ADAPTER_ID = "codex_lifecycle_hooks"
AGENT = {
    "id": "codex_cli",
    "name": "Codex CLI",
    "vendor": "OpenAI",
    "type": "known_ai_agent",
    "discovery_method": "deep_adapter",
    "discovery_confidence": 1.0,
}
CAPABILITY = AdapterCapability(
    adapter_id=ADAPTER_ID,
    adapter_version="1.0.0",
    supports_pre_execution=True,
    supports_post_execution=True,
    supports_blocking=True,
    supports_approval=True,
    supports_justification=True,
    supports_argument_redaction=True,
    supports_result_redaction=True,
    supports_hashing=True,
    supports_telemetry_export=True,
    mediated_tool_classes=frozenset({"shell", "file_write", "mcp", "local_function"}),
    source="official_hook_contract",
)


def default_codex_home() -> Path:
    import os

    return Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))


def find_rollout_files(codex_home: Path | None = None) -> list[Path]:
    """Secondary forensic source only; rollout records are not an enforcement contract."""
    sessions = (codex_home or default_codex_home()) / "sessions"
    return sorted(sessions.rglob("rollout-*.jsonl")) if sessions.exists() else []


def _stable_id(prefix: str, *values: Any) -> str:
    return prefix + canonical_hash([str(value) for value in values]).removeprefix("sha256:")[:32]


def _tool_class(tool_name: str) -> str:
    if tool_name == "Bash":
        return "shell"
    if tool_name == "apply_patch":
        return "file_write"
    if tool_name.startswith("mcp__"):
        return "mcp"
    return "local_function"


def tool_request_from_hook(payload: dict[str, Any]) -> ToolRequest:
    if payload.get("hook_event_name") != "PreToolUse":
        raise ValueError("Codex ToolRequest requires a PreToolUse payload")
    session_id = str(payload.get("session_id") or "")
    turn_id = str(payload.get("turn_id") or "")
    tool_use_id = str(payload.get("tool_use_id") or "")
    tool_name = str(payload.get("tool_name") or "")
    if not all((session_id, turn_id, tool_use_id, tool_name)):
        raise ValueError("Codex PreToolUse lacks a required session/turn/tool identifier")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be an object")
    tool_class = _tool_class(tool_name)
    command = tool_input.get("command") if isinstance(tool_input.get("command"), str) else None
    paths: list[str] = []
    for key in ("path", "file_path", "source", "destination"):
        if isinstance(tool_input.get(key), str):
            paths.append(tool_input[key])
    mcp_server = None
    if tool_class == "mcp":
        mcp_server = tool_name[5:].split("__", 1)[0]
    return ToolRequest(
        adapter_id=ADAPTER_ID,
        agent_id="codex_cli",
        session_id=session_id,
        task_id="task-" + turn_id,
        tool_name=tool_name,
        tool_class=tool_class,
        operation={"shell": "execute", "file_write": "write", "mcp": "call"}.get(tool_class, "invoke"),
        arguments=tool_input,
        command=command,
        cwd=str(payload.get("cwd")) if payload.get("cwd") else None,
        requested_paths=paths,
        mcp_server_id=mcp_server,
        mcp_server_fingerprint=canonical_hash({"server": mcp_server}) if mcp_server else None,
        request_id=_stable_id("req-", session_id, turn_id, tool_use_id, tool_name),
        action_id=_stable_id("act-", session_id, turn_id, tool_use_id),
    )


def pre_tool_response(result: RuntimeResult) -> dict[str, Any]:
    decision = "allow" if result.enforcement.permitted else "deny"
    reason = (
        "WatchMyAI policy released this request"
        if result.enforcement.permitted
        else f"WatchMyAI {result.enforcement.outcome.value}: {result.enforcement.reason}"
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def enforce_pre_tool(
    payload: dict[str, Any], runtime: WatchMyAIRuntime, approval_id: str | None = None
) -> tuple[RuntimeResult, dict[str, Any]]:
    result = runtime.process(tool_request_from_hook(payload), approval_id=approval_id)
    return result, pre_tool_response(result)


def parse_hook_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    event_name = str(payload.get("hook_event_name") or "Unknown")
    if event_name == "PreToolUse":
        return [tool_request_from_hook(payload).to_event()]
    session_id = str(payload.get("session_id") or "")
    wm: dict[str, Any] = {
        "agent": dict(AGENT),
        "adapter": {"id": ADAPTER_ID, "version": CAPABILITY.adapter_version, "mode": "pre_tool"},
        "attribution": {"level": "confirmed"},
        "visibility": {"mode": "deep"},
        **({"session": {"id": session_id}} if session_id else {}),
    }
    action = "adapter." + event_name.lower()
    event_type = ["info"]
    if event_name == "SessionStart":
        action, event_type = "session.started", ["start"]
    elif event_name == "PostToolUse":
        action, event_type = "execution.observed", ["end"]
        wm["action"] = {
            "id": _stable_id("act-", session_id, payload.get("turn_id"), payload.get("tool_use_id")),
            "execution_status": "executed",
        }
        wm["execution"] = {
            "id": _stable_id("exec-", session_id, payload.get("turn_id"), payload.get("tool_use_id")),
            "result_hash": canonical_hash(payload.get("tool_response")),
        }
    elif event_name == "PermissionRequest":
        action = "approval.requested"
        wm["approval"] = {"required": True, "status": "pending"}
    return [
        {
            "event": {"kind": "event", "category": ["session"], "type": event_type, "action": action},
            "watchmyai": wm,
            **({"process": {"working_directory": str(payload["cwd"])}} if payload.get("cwd") else {}),
        }
    ]


class RolloutContext:
    """Compatibility container for explicitly secondary forensic import."""

    def __init__(self) -> None:
        self.session_id: str | None = None
        self.cwd: str | None = None
        self.cli_version: str | None = None


def parse_rollout_line(line: str, ctx: RolloutContext, **_: Any) -> list[dict[str, Any]]:
    """Import only session metadata; unstable raw tool records are not trusted as enforcement."""
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return []
    if record.get("type") != "session_meta" or not isinstance(record.get("payload"), dict):
        return []
    payload = record["payload"]
    ctx.session_id = str(payload.get("id") or ctx.session_id or "")
    ctx.cwd = str(payload.get("cwd") or ctx.cwd or "")
    ctx.cli_version = str(payload.get("cli_version") or ctx.cli_version or "")
    return [
        {
            "event": {
                "kind": "event",
                "category": ["session"],
                "type": ["start"],
                "action": "session.started",
            },
            "watchmyai": {
                "agent": {**AGENT, **({"version": ctx.cli_version} if ctx.cli_version else {})},
                "adapter": {"id": "codex_rollout_forensics", "mode": "secondary"},
                "attribution": {"level": "strong"},
                "visibility": {"mode": "deep"},
                "session": {"id": ctx.session_id},
            },
            **({"process": {"working_directory": ctx.cwd}} if ctx.cwd else {}),
        }
    ]
