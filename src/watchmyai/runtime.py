"""Canonical adapter -> capability -> PDP -> PEP -> evidence orchestration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from watchmyai.approval.service import ApprovalService
from watchmyai.capability.service import CapabilityRegistry
from watchmyai.classifiers.command import classify_command
from watchmyai.classifiers.path import classify_paths, resolve_paths
from watchmyai.classifiers.resource import destination_approved, repository_approved
from watchmyai.core.models import DecisionEffect, PolicyDecision, ToolRequest
from watchmyai.enforcement.pep import EnforcementResult, PolicyEnforcementPoint
from watchmyai.evidence.chain import EvidenceChain
from watchmyai.policy.evaluator import PolicyDecisionPoint
from watchmyai.policy.model import PolicyBundle
from watchmyai.schema.event import canonical_hash

EmitFn = Callable[[dict[str, Any]], Any]
RecordFn = Callable[[dict[str, Any], str], dict[str, Any]]


@dataclass(frozen=True)
class RuntimeResult:
    request: ToolRequest
    decision: PolicyDecision
    enforcement: EnforcementResult


class WatchMyAIRuntime:
    def __init__(
        self,
        bundle: PolicyBundle,
        capabilities: CapabilityRegistry,
        approvals: ApprovalService,
        evidence: EvidenceChain,
        emit: EmitFn | None = None,
        recorder: RecordFn | None = None,
    ):
        self.bundle = bundle
        self.capabilities = capabilities
        self.approvals = approvals
        self.evidence = evidence
        self.emit = emit
        self.recorder = recorder
        self.pdp = PolicyDecisionPoint(bundle, capabilities)
        self.pep = PolicyEnforcementPoint(approvals)

    def activate(self, bundle: PolicyBundle) -> None:
        self.pdp.activate(bundle)
        self.bundle = bundle

    def classify(self, request: ToolRequest) -> ToolRequest:
        metadata = self.bundle.metadata
        if request.requested_paths and not request.resolved_paths:
            request.resolved_paths = resolve_paths(request.requested_paths, request.cwd)
        paths = classify_paths(
            request.requested_paths,
            request.resolved_paths,
            list(metadata.get("approved_workspace_roots", [])),
            list(metadata.get("restricted_paths", [])),
        )
        command = classify_command(request.command)
        request.attributes.update(
            {
                "command_class": command.command_class,
                "command_operation": command.operation,
                "path_outside_approved_workspace": any(not item.approved_workspace for item in paths),
                "path_restricted": any(item.restricted for item in paths),
                "path_classes": sorted({item.sensitivity_class for item in paths}),
                "destination_approved": destination_approved(
                    request.destination, list(metadata.get("allowed_destinations", []))
                ),
                "repository_approved": repository_approved(
                    request.repository_id, list(metadata.get("allowed_repositories", []))
                )
                if request.repository_id is not None
                else True,
                "mcp_approved": request.mcp_server_id in set(metadata.get("allowed_mcp_servers", []))
                if request.mcp_server_id
                else True,
            }
        )
        return request

    def process(self, request: ToolRequest, *, approval_id: str | None = None) -> RuntimeResult:
        request = self.classify(request)
        approved = (
            self.approvals.get(approval_id)
            if approval_id
            else self.approvals.find_approved(
                session_id=request.session_id,
                task_id=request.task_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                payload=request.payload_hash,
                target=request.target_hash,
            )
        )
        if approved is not None:
            # An operator-approved retry resumes the exact held action/decision identifiers.
            request.request_id = approved.request_id
            request.action_id = approved.action_id
            approval_id = approved.approval_id
        capability = self.capabilities.get(request.adapter_id)
        request_event = request.to_event()
        self._record(request_event, request.session_id)
        self._record(
            {
                "event": {
                    "kind": "event",
                    "category": ["configuration"],
                    "type": ["info"],
                    "action": "capability.checked",
                    "outcome": "success" if capability.covers(request.tool_class) else "failure",
                },
                "watchmyai": {
                    "session": {"id": request.session_id},
                    "request": {"id": request.request_id},
                    "action": {"id": request.action_id},
                    "adapter": {"id": request.adapter_id},
                    "capability": {
                        "coverage": capability.covers(request.tool_class),
                        "fingerprint": capability.fingerprint,
                    },
                },
            },
            request.session_id,
        )
        decision = self.pdp.evaluate(request)
        if approved is not None and approved.decision_id:
            decision = PolicyDecision(
                effect=decision.effect,
                evidence=decision.evidence,
                request_id=request.request_id,
                action_id=request.action_id,
                decision_id=approved.decision_id,
            )
        decision_event = decision.to_event()
        request_context = request_event["watchmyai"]
        decision_context = decision_event["watchmyai"]
        for field in (
            "agent",
            "adapter",
            "session",
            "task",
            "tool",
            "command",
            "resource",
            "repository",
            "destination",
            "mcp",
        ):
            if field in request_context:
                decision_context[field] = request_context[field]
        self._record(decision_event, request.session_id)
        violation_type: str | None = None
        if request.attributes.get("path_outside_approved_workspace"):
            violation_type = (
                "execution_outside_approved_workspace"
                if request.tool_class == "file_write"
                else "ai_access_outside_approved_workspace"
            )
        elif request.tool_class == "shell" and decision.effect == DecisionEffect.DENY:
            violation_type = "unauthorized_shell_execution"
        if violation_type:
            self._record(
                {
                    "event": {
                        "kind": "event",
                        "category": ["intrusion_detection"],
                        "type": ["info"],
                        "action": "policy_violation",
                        "outcome": "failure",
                    },
                    "process": request_event.get("process", {}),
                    "watchmyai": {
                        "agent": request_context["agent"],
                        "adapter": request_context.get("adapter", {}),
                        "attribution": {"level": "confirmed"},
                        "session": request_context["session"],
                        "request": request_context["request"],
                        "action": request_context["action"],
                        "tool": request_context["tool"],
                        "policy": {
                            "winning_policy_id": decision.evidence.winning_policy_id,
                            "policy_bundle_id": decision.evidence.policy_bundle_id,
                            "policy_bundle_version": decision.evidence.policy_bundle_version,
                            "policy_sequence": decision.evidence.policy_sequence,
                            "violation": {"detected": True, "type": violation_type},
                        },
                        "decision": {
                            "id": decision.decision_id,
                            "effect": decision.effect.value,
                        },
                    },
                },
                request.session_id,
            )
        if "EMIT_HIGH_SEVERITY_ALERT" in decision.evidence.effective_obligations:
            self._record(
                {
                    "event": {
                        "kind": "alert",
                        "category": ["configuration"],
                        "type": ["denied"],
                        "action": "obligation.high_severity_alert",
                        "outcome": "failure" if decision.effect == DecisionEffect.DENY else "unknown",
                    },
                    "watchmyai": {
                        "agent": {"id": request.agent_id, "type": "known_ai_agent"},
                        "adapter": {"id": request.adapter_id},
                        "session": {"id": request.session_id},
                        "task": {"id": request.task_id},
                        "request": {"id": request.request_id},
                        "action": {"id": request.action_id},
                        "decision": {
                            "id": decision.decision_id,
                            "effect": decision.effect.value,
                        },
                        "policy": {
                            "winning_policy_id": decision.evidence.winning_policy_id,
                            "policy_bundle_id": decision.evidence.policy_bundle_id,
                            "policy_bundle_version": decision.evidence.policy_bundle_version,
                            "policy_sequence": decision.evidence.policy_sequence,
                        },
                        "obligation": {
                            "requested": list(decision.evidence.requested_obligations),
                            "effective": list(decision.evidence.effective_obligations),
                            "status": decision.evidence.obligation_status,
                        },
                    },
                },
                request.session_id,
            )
        if decision.effect == DecisionEffect.REQUIRE_APPROVAL and approval_id is None:
            self.approvals.request(
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
                idempotency_key=canonical_hash(
                    {
                        "session": request.session_id,
                        "task": request.task_id,
                        "tool": request.tool_name,
                        "payload": request.payload_hash,
                        "target": request.target_hash,
                        "policy_sequence": decision.evidence.policy_sequence,
                    }
                ),
                requires_justification=("REQUIRE_JUSTIFICATION" in decision.evidence.effective_obligations),
            )
        enforcement = self.pep.enforce(request, decision, approval_id=approval_id)
        self._record(enforcement.to_event(), request.session_id)
        return RuntimeResult(request, decision, enforcement)

    def execute(
        self,
        request: ToolRequest,
        executor: Callable[[], Any],
        *,
        approval_id: str | None = None,
    ) -> tuple[RuntimeResult, Any | None]:
        result = self.process(request, approval_id=approval_id)
        if not result.enforcement.permitted:
            return result, None
        try:
            output = executor()
        except Exception as exc:
            self.record_execution(result, "failure", error_class=type(exc).__name__)
            raise
        self.record_execution(result, "success", result_hash=canonical_hash(output))
        return result, output

    def record_execution(
        self,
        result: RuntimeResult,
        outcome: str,
        *,
        result_hash: str | None = None,
        error_class: str | None = None,
    ) -> dict[str, Any]:
        event = {
            "event": {
                "kind": "event",
                "category": ["process"],
                "type": ["end"],
                "action": "execution.observed",
                "outcome": outcome,
            },
            "watchmyai": {
                "session": {"id": result.request.session_id},
                "request": {"id": result.request.request_id, "payload_hash": result.request.payload_hash},
                "action": {"id": result.request.action_id, "execution_status": "executed"},
                "decision": {"id": result.decision.decision_id, "effect": result.decision.effect.value},
                **(
                    {
                        "approval": {
                            "status": "consumed",
                            "id_hash": result.enforcement.approval.approval.approval_ref,
                        }
                    }
                    if result.enforcement.approval
                    and result.enforcement.approval.allowed
                    and result.enforcement.approval.approval
                    else {}
                ),
                "execution": {
                    "id": "exec-" + result.request.action_id.removeprefix("act-"),
                    **({"result_hash": result_hash} if result_hash else {}),
                    **({"error_class": error_class} if error_class else {}),
                },
            },
        }
        return self._record(event, result.request.session_id)

    def _record(self, event: dict[str, Any], session_id: str) -> dict[str, Any]:
        if self.recorder is not None:
            return self.recorder(event, session_id)
        chained = self.evidence.append(event, session_id)
        if self.emit is not None:
            self.emit(chained)
        return chained
