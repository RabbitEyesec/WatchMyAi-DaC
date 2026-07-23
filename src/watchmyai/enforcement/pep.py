"""Policy enforcement point. Decisions are never silently downgraded."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from watchmyai.approval.service import ApprovalService, ConsumeResult
from watchmyai.core.models import DecisionEffect, PolicyDecision, ToolRequest


class EnforcementOutcome(StrEnum):
    RELEASED = "released"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"
    FAILED_CLOSED = "failed_closed"


@dataclass(frozen=True)
class EnforcementResult:
    permitted: bool
    outcome: EnforcementOutcome
    request_id: str
    action_id: str
    decision_id: str
    reason: str
    approval: ConsumeResult | None = None

    def to_event(self) -> dict[str, Any]:
        return {
            "event": {
                "kind": "event",
                "category": ["process"],
                "type": ["info"] if self.permitted else ["denied"],
                "action": "pep.enforced",
                "outcome": "success" if self.permitted else "failure",
            },
            "watchmyai": {
                "request": {"id": self.request_id},
                "action": {
                    "id": self.action_id,
                    "execution_status": "released" if self.permitted else "blocked",
                },
                "decision": {"id": self.decision_id},
                "pep": {"result": self.outcome.value, "reason": self.reason},
                **(
                    {"approval": {"status": "consumed", "id_hash": self.approval.approval.approval_ref}}
                    if self.approval and self.approval.allowed and self.approval.approval
                    else {}
                ),
            },
        }


class PolicyEnforcementPoint:
    def __init__(self, approvals: ApprovalService):
        self.approvals = approvals

    def enforce(
        self,
        request: ToolRequest,
        decision: PolicyDecision,
        *,
        approval_id: str | None = None,
    ) -> EnforcementResult:
        if decision.effect == DecisionEffect.DENY:
            return EnforcementResult(
                False,
                EnforcementOutcome.BLOCKED,
                request.request_id,
                request.action_id,
                decision.decision_id,
                "policy_denied",
            )
        if decision.effect == DecisionEffect.REQUIRE_APPROVAL:
            if not approval_id:
                return EnforcementResult(
                    False,
                    EnforcementOutcome.AWAITING_APPROVAL,
                    request.request_id,
                    request.action_id,
                    decision.decision_id,
                    "approval_required",
                )
            consumed = self.approvals.consume(
                approval_id,
                session_id=request.session_id,
                task_id=request.task_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                payload=request.payload_hash,
                target=request.target_hash,
                action_id=request.action_id,
                request_id=request.request_id,
                decision_id=decision.decision_id,
                policy_bundle_id=decision.evidence.policy_bundle_id,
                policy_sequence=decision.evidence.policy_sequence,
            )
            return EnforcementResult(
                consumed.allowed,
                EnforcementOutcome.RELEASED if consumed.allowed else EnforcementOutcome.BLOCKED,
                request.request_id,
                request.action_id,
                decision.decision_id,
                "approval_consumed" if consumed.allowed else consumed.reason,
                consumed,
            )
        return EnforcementResult(
            True,
            EnforcementOutcome.RELEASED,
            request.request_id,
            request.action_id,
            decision.decision_id,
            "policy_released" if decision.effect == DecisionEffect.ALLOW else "monitor_released",
        )
