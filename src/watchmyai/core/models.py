"""Canonical, vendor-neutral request, decision, capability, and evidence models.

Raw tool arguments and commands exist only in the in-memory request long enough
to classify and hash them. ``to_event`` deliberately emits hashes and derived
classes, never the raw values.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from watchmyai.schema.event import canonical_hash


class DecisionEffect(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    MONITOR = "MONITOR"


class OperatingMode(StrEnum):
    OBSERVE = "observe"
    MONITOR = "monitor"
    RESTRICT = "restrict"
    STRICT = "strict"


class GuaranteeStatus(StrEnum):
    DETERMINISTIC_PRE_EXECUTION = "deterministic_pre_execution"
    DETERMINISTIC_POST_EXECUTION = "deterministic_post_execution"
    COOPERATIVE = "cooperative"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class Obligation(StrEnum):
    AUDIT_FULL = "AUDIT_FULL"
    AUDIT_METADATA_ONLY = "AUDIT_METADATA_ONLY"
    REDACT_ARGUMENTS = "REDACT_ARGUMENTS"
    REDACT_RESULT = "REDACT_RESULT"
    CAPTURE_ARGUMENT_HASH = "CAPTURE_ARGUMENT_HASH"
    REQUIRE_EXECUTION_RECEIPT = "REQUIRE_EXECUTION_RECEIPT"
    REQUIRE_APPROVAL_RECEIPT = "REQUIRE_APPROVAL_RECEIPT"
    REQUIRE_JUSTIFICATION = "REQUIRE_JUSTIFICATION"
    TERMINATE_SESSION_ON_FAILURE = "TERMINATE_SESSION_ON_FAILURE"
    EMIT_HIGH_SEVERITY_ALERT = "EMIT_HIGH_SEVERITY_ALERT"
    NOTIFY_SECURITY = "NOTIFY_SECURITY"


@dataclass(frozen=True)
class AdapterCapability:
    adapter_id: str
    adapter_version: str
    supports_pre_execution: bool = False
    supports_post_execution: bool = False
    supports_blocking: bool = False
    supports_approval: bool = False
    supports_justification: bool = False
    supports_session_termination: bool = False
    supports_argument_redaction: bool = True
    supports_result_redaction: bool = False
    supports_hashing: bool = True
    supports_telemetry_export: bool = True
    supports_notification: bool = False
    mediated_tool_classes: frozenset[str] = frozenset()
    source: str = "declared"

    def covers(self, tool_class: str) -> bool:
        return "*" in self.mediated_tool_classes or tool_class in self.mediated_tool_classes

    @property
    def fingerprint(self) -> str:
        return canonical_hash(
            {
                key: sorted(value) if isinstance(value, frozenset) else value
                for key, value in self.__dict__.items()
            }
        )


@dataclass
class ToolRequest:
    adapter_id: str
    agent_id: str
    session_id: str
    task_id: str
    tool_name: str
    tool_class: str
    operation: str
    arguments: dict[str, Any] = field(default_factory=dict, repr=False)
    command: str | None = field(default=None, repr=False)
    cwd: str | None = None
    requested_paths: list[str] = field(default_factory=list)
    resolved_paths: list[str] = field(default_factory=list)
    destination: str | None = None
    repository_id: str | None = None
    mcp_server_id: str | None = None
    mcp_server_fingerprint: str | None = None
    request_id: str = field(default_factory=lambda: "req-" + uuid.uuid4().hex)
    action_id: str = field(default_factory=lambda: "act-" + uuid.uuid4().hex)
    canonicalizer_version: str = "1"
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        required = {
            "adapter_id": self.adapter_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "tool_name": self.tool_name,
            "tool_class": self.tool_class,
            "operation": self.operation,
        }
        missing = [name for name, value in required.items() if not isinstance(value, str) or not value]
        if missing:
            raise ValueError(f"ToolRequest missing required non-empty fields: {', '.join(missing)}")
        self.requested_paths = [str(p) for p in self.requested_paths if str(p)]
        self.resolved_paths = [str(p) for p in self.resolved_paths if str(p)]

    @property
    def arguments_hash(self) -> str:
        return canonical_hash(self.arguments)

    @property
    def command_hash(self) -> str | None:
        return canonical_hash(self.command) if self.command else None

    @property
    def payload_hash(self) -> str:
        return canonical_hash(
            {
                "canonicalizer_version": self.canonicalizer_version,
                "tool_name": self.tool_name,
                "tool_class": self.tool_class,
                "operation": self.operation,
                "arguments": self.arguments,
                "command": self.command,
                "cwd": self.cwd,
                "resolved_paths": self.resolved_paths,
                "destination": self.destination,
                "repository_id": self.repository_id,
                "mcp_server_id": self.mcp_server_id,
                "mcp_server_fingerprint": self.mcp_server_fingerprint,
            }
        )

    @property
    def target_hash(self) -> str | None:
        targets: list[str] = list(self.resolved_paths)
        if self.destination:
            targets.append(self.destination)
        if self.mcp_server_fingerprint:
            targets.append(self.mcp_server_fingerprint)
        return canonical_hash(targets) if targets else None

    def to_event(self) -> dict[str, Any]:
        """Return the schema 1.1 ``tool_request`` event used by live rules.

        The normalizer applies the configured redactor before validation or
        export.  Retaining redacted command and path values is required by the
        validated schema 1.1.0 detection pack; hashes remain available for
        correlation and integrity checks.
        """
        request: dict[str, Any] = {
            "id": self.request_id,
            "canonicalizer_version": self.canonicalizer_version,
            "payload_hash": self.payload_hash,
            "argument_hash": self.arguments_hash,
        }
        if self.target_hash:
            request["target_hash"] = self.target_hash
        action: dict[str, Any] = {
            "id": self.action_id,
            "operation": self.operation,
            "execution_status": "requested",
        }
        if self.command_hash:
            action["command_hash"] = self.command_hash
        wm: dict[str, Any] = {
            "agent": {"id": self.agent_id, "type": "known_ai_agent"},
            "adapter": {"id": self.adapter_id},
            "session": {"id": self.session_id},
            "task": {"id": self.task_id},
            "request": request,
            "action": action,
            "tool": {
                "name": self.tool_name,
                "class": self.tool_class,
                "category": "file" if self.tool_class.startswith("file_") else self.tool_class,
                "arguments": dict(self.arguments),
                "arguments_hash": self.arguments_hash,
            },
        }
        if self.attributes.get("command_class"):
            wm["command"] = {
                "class": str(self.attributes["command_class"]),
                "operation": str(self.attributes.get("command_operation", self.operation)),
            }
        if self.resolved_paths:
            wm["resource"] = {
                "path": {
                    "requested_count": len(self.requested_paths),
                    "resolved": self.resolved_paths,
                    "classes": list(self.attributes.get("path_classes", [])),
                    "outside_approved_workspace": bool(
                        self.attributes.get("path_outside_approved_workspace", False)
                    ),
                    "restricted": bool(self.attributes.get("path_restricted", False)),
                    "operation": self.operation,
                }
            }
        if self.repository_id:
            wm["repository"] = {
                "id": self.repository_id,
                "approved": bool(self.attributes.get("repository_approved", False)),
            }
        if self.destination:
            wm["destination"] = {
                "hash": canonical_hash(self.destination),
                "approved": bool(self.attributes.get("destination_approved", False)),
            }
        if self.mcp_server_id:
            wm["mcp"] = {
                "server": {
                    "id": self.mcp_server_id,
                    **({"fingerprint": self.mcp_server_fingerprint} if self.mcp_server_fingerprint else {}),
                    "approved": bool(self.attributes.get("mcp_approved", False)),
                }
            }
        return {
            "event": {
                "kind": "event",
                "category": ["process"],
                "type": ["start"],
                "action": "tool_request",
            },
            "process": {
                "working_directory": self.cwd or os.getcwd(),
                **({"command_line": self.command} if self.command else {}),
            },
            "watchmyai": wm,
        }


@dataclass(frozen=True)
class DecisionEvidence:
    winning_policy_id: str
    winning_policy_version: str
    policy_bundle_id: str
    policy_bundle_version: str
    policy_sequence: int
    match_evidence: tuple[dict[str, Any], ...]
    requested_obligations: tuple[str, ...]
    effective_obligations: tuple[str, ...]
    obligation_status: str
    guarantee_status: GuaranteeStatus
    reason_codes: tuple[str, ...]
    capability_fingerprint: str


@dataclass(frozen=True)
class PolicyDecision:
    effect: DecisionEffect
    evidence: DecisionEvidence
    request_id: str
    action_id: str
    decision_id: str = field(default_factory=lambda: "dec-" + uuid.uuid4().hex)

    def to_event(self) -> dict[str, Any]:
        evidence = self.evidence
        return {
            "event": {
                "kind": "event",
                "category": ["configuration"],
                "type": [
                    "info" if self.effect in (DecisionEffect.ALLOW, DecisionEffect.MONITOR) else "denied"
                ],
                "action": "decision.created",
                "outcome": "success",
            },
            "watchmyai": {
                "request": {"id": self.request_id},
                "action": {"id": self.action_id},
                "decision": {
                    "id": self.decision_id,
                    "effect": self.effect.value,
                    "reason_codes": list(evidence.reason_codes),
                },
                "policy": {
                    "winning_policy_id": evidence.winning_policy_id,
                    "winning_policy_version": evidence.winning_policy_version,
                    "policy_bundle_id": evidence.policy_bundle_id,
                    "policy_bundle_version": evidence.policy_bundle_version,
                    "policy_sequence": evidence.policy_sequence,
                    "match_evidence": list(evidence.match_evidence),
                },
                "obligation": {
                    "requested": list(evidence.requested_obligations),
                    "effective": list(evidence.effective_obligations),
                    "status": evidence.obligation_status,
                },
                "guarantee": {"status": evidence.guarantee_status.value},
                "capability": {"fingerprint": evidence.capability_fingerprint},
            },
        }
