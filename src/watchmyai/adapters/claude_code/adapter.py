"""Claude Code lifecycle-hook adapter with enforceable PreToolUse decisions."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from watchmyai.core.models import AdapterCapability, ToolRequest
from watchmyai.runtime import RuntimeResult, WatchMyAIRuntime
from watchmyai.schema.event import canonical_hash

ADAPTER_ID = "claude_code_hooks"
AGENT = {
    "id": "claude_code",
    "name": "Claude Code",
    "vendor": "Anthropic",
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
    mediated_tool_classes=frozenset({"*"}),
    source="official_hook_contract",
)

HOOK_EVENTS = [
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "PreToolUse",
    "PermissionRequest",
    "PermissionDenied",
    "PostToolUse",
    "PostToolUseFailure",
    "Notification",
    "Stop",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "CwdChanged",
    "FileChanged",
    "ConfigChange",
]

TOOL_CLASSES = {
    "Bash": "shell",
    "BashOutput": "shell",
    "KillShell": "shell",
    "Read": "file_read",
    "Write": "file_write",
    "Edit": "file_write",
    "MultiEdit": "file_write",
    "NotebookEdit": "file_write",
    "Glob": "file_read",
    "Grep": "file_read",
    "LS": "file_read",
    "WebFetch": "network",
    "WebSearch": "network",
    "Task": "delegation",
    "Agent": "delegation",
}


def _stable_id(prefix: str, payload: dict[str, Any], *names: str) -> str:
    values = [str(payload.get(name, "")) for name in names]
    digest = canonical_hash(values).removeprefix("sha256:")[:32]
    return prefix + digest


def _paths(tool_input: dict[str, Any]) -> list[str]:
    paths = []
    for key in ("file_path", "path", "notebook_path", "destination", "source"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            paths.append(value)
    return list(dict.fromkeys(paths))


def tool_request_from_hook(payload: dict[str, Any]) -> ToolRequest:
    if payload.get("hook_event_name") != "PreToolUse":
        raise ValueError("Claude ToolRequest requires a PreToolUse payload")
    session_id = str(payload.get("session_id") or "")
    if not session_id:
        raise ValueError("PreToolUse payload has no session_id")
    tool_name = str(payload.get("tool_name") or "unknown")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be an object")
    is_mcp = tool_name.startswith("mcp__") and "__" in tool_name[5:]
    mcp_server = tool_name[5:].split("__", 1)[0] if is_mcp else None
    tool_class = "mcp" if is_mcp else TOOL_CLASSES.get(tool_name, "other")
    operation = {
        "file_read": "read",
        "file_write": "write",
        "network": "connect",
        "shell": "execute",
        "mcp": "call",
    }.get(tool_class, "invoke")
    command = tool_input.get("command") if isinstance(tool_input.get("command"), str) else None
    destination = None
    url = tool_input.get("url")
    if isinstance(url, str):
        destination = urlparse(url).hostname
    tool_use_id = str(payload.get("tool_use_id") or canonical_hash(tool_input))
    return ToolRequest(
        adapter_id=ADAPTER_ID,
        agent_id="claude_code",
        session_id=session_id,
        task_id=str(payload.get("task_id") or _stable_id("task-", payload, "session_id")),
        tool_name=tool_name,
        tool_class=tool_class,
        operation=operation,
        arguments=tool_input,
        command=command,
        cwd=str(payload.get("cwd")) if payload.get("cwd") else None,
        requested_paths=_paths(tool_input),
        destination=destination,
        mcp_server_id=mcp_server,
        mcp_server_fingerprint=canonical_hash({"server": mcp_server}) if mcp_server else None,
        request_id=_stable_id("req-", payload, "session_id", "tool_use_id", "tool_name"),
        action_id=_stable_id("act-", {**payload, "tool_use_id": tool_use_id}, "session_id", "tool_use_id"),
    )


def pre_tool_response(result: RuntimeResult) -> dict[str, Any]:
    if result.enforcement.permitted:
        decision = "allow"
        reason = "WatchMyAI policy released this request"
    else:
        decision = "deny"
        reason = f"WatchMyAI {result.enforcement.outcome.value}: {result.enforcement.reason}"
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def enforce_pre_tool(
    payload: dict[str, Any], runtime: WatchMyAIRuntime
) -> tuple[RuntimeResult, dict[str, Any]]:
    request = tool_request_from_hook(payload)
    approval_id = payload.get("watchmyai_approval_id")
    result = runtime.process(request, approval_id=str(approval_id) if approval_id else None)
    return result, pre_tool_response(result)


def parse_hook_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize non-enforcement hook evidence without raw arguments/results."""
    hook_event = str(payload.get("hook_event_name") or "Unknown")
    if hook_event == "PreToolUse":
        return [tool_request_from_hook(payload).to_event()]
    session_id = str(payload.get("session_id") or "")
    wm: dict[str, Any] = {
        "agent": dict(AGENT),
        "adapter": {"id": ADAPTER_ID, "version": CAPABILITY.adapter_version, "mode": "pre_tool"},
        "attribution": {"level": "confirmed"},
        "visibility": {"mode": "deep"},
    }
    if session_id:
        wm["session"] = {"id": session_id}
    event_type = ["info"]
    action = "adapter." + hook_event.lower()
    if hook_event == "SessionStart":
        action, event_type = "session.started", ["start"]
    elif hook_event == "SessionEnd":
        action, event_type = "session.ended", ["end"]
    elif hook_event == "UserPromptSubmit":
        action = "task.submitted"
        prompt_hash = canonical_hash(str(payload.get("prompt", "")))
        wm["task"] = {
            "id": "task-" + prompt_hash.removeprefix("sha256:")[:16],
            "hash": prompt_hash,
        }
    elif hook_event in {"PostToolUse", "PostToolUseFailure"}:
        action, event_type = "execution.observed", ["end"]
        failed = hook_event == "PostToolUseFailure"
        wm["execution"] = {
            "id": _stable_id("exec-", payload, "session_id", "tool_use_id"),
            "result_hash": canonical_hash(payload.get("tool_response")),
            **({"error_class": "tool_failure"} if failed else {}),
        }
        wm["action"] = {
            "id": _stable_id("act-", payload, "session_id", "tool_use_id"),
            "execution_status": "executed",
        }
    elif hook_event == "PermissionRequest":
        action = "approval.requested"
        wm["approval"] = {"required": True, "status": "pending"}
    elif hook_event == "PermissionDenied":
        action, event_type = "approval.rejected", ["denied"]
        wm["approval"] = {"required": True, "status": "rejected"}
    return [
        {
            "event": {"kind": "event", "category": ["session"], "type": event_type, "action": action},
            "watchmyai": wm,
            **({"process": {"working_directory": str(payload["cwd"])}} if payload.get("cwd") else {}),
        }
    ]
