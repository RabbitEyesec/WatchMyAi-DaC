from __future__ import annotations

import json

from watchmyai.adapters.claude_code.adapter import pre_tool_response as claude_response
from watchmyai.adapters.codex_cli.adapter import tool_request_from_hook
from watchmyai.core.models import DecisionEffect
from watchmyai.gateway import Gateway, GatewayConfig


def gateway(tmp_path, policy_file):
    config = GatewayConfig(
        home=tmp_path / "home",
        jsonl_path=tmp_path / "events.jsonl",
        dead_letter_path=tmp_path / "dead.jsonl",
        approvals_store=tmp_path / "approvals.json",
        evidence_database=tmp_path / "evidence.sqlite3",
        unsigned_policy_bundle=policy_file,
        allow_unsigned_policy=True,
    )
    return Gateway(config)


def codex_payload(tmp_path, command="printf ok", tool_use_id="call-1"):
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "session-1",
        "turn_id": "turn-1",
        "tool_use_id": tool_use_id,
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(tmp_path),
    }


def test_real_local_adapter_capability_pdp_pep_evidence_path(tmp_path, policy_file):
    gw = gateway(tmp_path, policy_file)
    runtime = gw.build_runtime()
    first = runtime.process(tool_request_from_hook(codex_payload(tmp_path)))
    assert first.decision.effect == DecisionEffect.REQUIRE_APPROVAL
    assert not first.enforcement.permitted
    assert first.enforcement.outcome.value == "awaiting_approval"

    pending = next(item for item in gw.approvals._approvals.values() if item.status == "pending")
    gw.approvals.grant_ref(pending.approval_ref, justification="test approval")
    second = runtime.process(tool_request_from_hook(codex_payload(tmp_path, tool_use_id="call-2")))
    assert second.enforcement.permitted
    runtime.record_execution(second, "success", result_hash="sha256:" + "a" * 64)
    gw.flush()

    assert gw.evidence.verify("session-1").valid
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text("utf-8").splitlines()]
    actions = [event["event"]["action"] for event in events]
    assert "tool_request" in actions
    assert "capability.checked" in actions
    assert "decision.created" in actions
    assert "approval.consumed" in actions
    assert "pep.enforced" in actions
    assert "execution.observed" in actions
    serialized = json.dumps(events)
    assert "printf ok" in serialized
    assert pending.approval_id not in serialized


def test_recursive_delete_is_denied_before_execution(tmp_path, policy_file):
    gw = gateway(tmp_path, policy_file)
    result = gw.build_runtime().process(tool_request_from_hook(codex_payload(tmp_path, "rm -rf .")))
    assert result.decision.effect == DecisionEffect.DENY
    assert not result.enforcement.permitted
    assert claude_response(result)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_schema_validates_every_chained_runtime_event(tmp_path, policy_file):
    from watchmyai.schema.event import validate_event

    gw = gateway(tmp_path, policy_file)
    gw.build_runtime().process(tool_request_from_hook(codex_payload(tmp_path)))
    gw.flush()
    for line in (tmp_path / "events.jsonl").read_text("utf-8").splitlines():
        assert validate_event(json.loads(line)) == []
