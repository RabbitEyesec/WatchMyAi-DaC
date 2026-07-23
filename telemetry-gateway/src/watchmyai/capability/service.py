"""Adapter capability registration and canonical obligation validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from watchmyai.core.models import AdapterCapability, GuaranteeStatus, Obligation, ToolRequest

if TYPE_CHECKING:
    from watchmyai.policy.model import PolicyBundle


@dataclass(frozen=True)
class ObligationSpec:
    capability_field: str
    fallback: str
    mandatory: bool


OBLIGATION_REGISTRY: dict[Obligation, ObligationSpec] = {
    Obligation.AUDIT_FULL: ObligationSpec("supports_telemetry_export", "POLICY_DEFINED", False),
    Obligation.AUDIT_METADATA_ONLY: ObligationSpec("supports_telemetry_export", "REFUSE", False),
    Obligation.REDACT_ARGUMENTS: ObligationSpec("supports_argument_redaction", "REFUSE", False),
    Obligation.REDACT_RESULT: ObligationSpec("supports_result_redaction", "REFUSE", False),
    Obligation.CAPTURE_ARGUMENT_HASH: ObligationSpec("supports_hashing", "IGNORE_OPTIONAL_OBLIGATION", False),
    Obligation.REQUIRE_EXECUTION_RECEIPT: ObligationSpec("supports_post_execution", "REFUSE", True),
    Obligation.REQUIRE_APPROVAL_RECEIPT: ObligationSpec("supports_approval", "REFUSE", True),
    Obligation.REQUIRE_JUSTIFICATION: ObligationSpec("supports_justification", "REFUSE", True),
    Obligation.TERMINATE_SESSION_ON_FAILURE: ObligationSpec("supports_session_termination", "REFUSE", True),
    Obligation.EMIT_HIGH_SEVERITY_ALERT: ObligationSpec(
        "supports_telemetry_export", "QUEUE_OR_REFUSE", False
    ),
    Obligation.NOTIFY_SECURITY: ObligationSpec("supports_notification", "QUEUE_OR_REFUSE", False),
}


@dataclass(frozen=True)
class CapabilityCheck:
    capability: AdapterCapability
    covered: bool
    guarantee_status: GuaranteeStatus
    effective_obligations: tuple[str, ...]
    unavailable_obligations: tuple[str, ...]
    ignored_optional_obligations: tuple[str, ...]

    @property
    def obligations_satisfied(self) -> bool:
        return not self.unavailable_obligations


class CapabilityRegistry:
    def __init__(self) -> None:
        self._capabilities: dict[str, AdapterCapability] = {}
        self._generation = 0

    @property
    def generation(self) -> int:
        return self._generation

    def register(self, capability: AdapterCapability) -> None:
        previous = self._capabilities.get(capability.adapter_id)
        if previous != capability:
            self._capabilities[capability.adapter_id] = capability
            self._generation += 1

    def get(self, adapter_id: str) -> AdapterCapability:
        try:
            return self._capabilities[adapter_id]
        except KeyError as exc:
            raise KeyError(f"adapter {adapter_id!r} has no registered capability") from exc

    def validate_distribution_requirements(
        self,
        bundle: PolicyBundle,
        required: tuple[str, ...],
    ) -> tuple[bool, list[str]]:
        """Validate signed endpoint requirements and policy obligations before activation."""
        gaps: list[str] = []
        capability_fields = set(AdapterCapability.__dataclass_fields__) - {
            "adapter_id",
            "adapter_version",
            "mediated_tool_classes",
            "source",
        }
        for requirement in required:
            if "." in requirement:
                adapter_id, field = requirement.split(".", 1)
                capability = self._capabilities.get(adapter_id)
                if capability is None or field not in capability_fields or not getattr(capability, field):
                    gaps.append(requirement)
            elif requirement not in capability_fields:
                gaps.append(f"unknown:{requirement}")
            elif not self._capabilities or not all(
                getattr(capability, requirement) for capability in self._capabilities.values()
            ):
                gaps.append(requirement)

        for policy in bundle.policies:
            tool_class = policy.match.get("tool_class")
            if tool_class is None and "command_class" in policy.match:
                tool_class = "shell"
            elif tool_class is None and any(key.startswith("path_") for key in policy.match):
                tool_class = ["file_read", "file_write"]
            elif tool_class is None and any(key.startswith("mcp_") for key in policy.match):
                tool_class = "mcp"
            relevant = [
                capability
                for capability in self._capabilities.values()
                if tool_class is None
                or capability.covers(str(tool_class))
                or (isinstance(tool_class, list) and any(capability.covers(str(item)) for item in tool_class))
            ]
            if not relevant:
                gaps.append(f"{policy.policy_id}:no_mediating_adapter")
            for raw in policy.obligations:
                spec = OBLIGATION_REGISTRY[Obligation(raw)]
                if spec.fallback == "IGNORE_OPTIONAL_OBLIGATION" and not spec.mandatory:
                    continue
                for capability in relevant:
                    if not getattr(capability, spec.capability_field):
                        gaps.append(f"{policy.policy_id}:{capability.adapter_id}:{spec.capability_field}")
            if policy.effect.value == "REQUIRE_APPROVAL":
                for capability in relevant:
                    if not capability.supports_approval:
                        gaps.append(f"{policy.policy_id}:{capability.adapter_id}:supports_approval")
        unique = sorted(set(gaps))
        return not unique, unique

    def check(self, request: ToolRequest, obligations: tuple[str, ...]) -> CapabilityCheck:
        capability = self.get(request.adapter_id)
        covered = capability.covers(request.tool_class)
        unavailable: list[str] = []
        ignored: list[str] = []
        effective: list[str] = []
        for raw in obligations:
            try:
                obligation = Obligation(raw)
            except ValueError as exc:
                raise ValueError(f"unknown obligation {raw!r}") from exc
            spec = OBLIGATION_REGISTRY[obligation]
            if getattr(capability, spec.capability_field):
                effective.append(raw)
            elif spec.fallback == "IGNORE_OPTIONAL_OBLIGATION" and not spec.mandatory:
                ignored.append(raw)
            else:
                unavailable.append(raw)
        if not covered or not capability.supports_pre_execution:
            guarantee = GuaranteeStatus.UNAVAILABLE
        elif capability.supports_blocking:
            guarantee = GuaranteeStatus.DETERMINISTIC_PRE_EXECUTION
        else:
            guarantee = GuaranteeStatus.COOPERATIVE
        if unavailable and guarantee != GuaranteeStatus.UNAVAILABLE:
            guarantee = GuaranteeStatus.DEGRADED
        return CapabilityCheck(
            capability=capability,
            covered=covered,
            guarantee_status=guarantee,
            effective_obligations=tuple(effective),
            unavailable_obligations=tuple(unavailable),
            ignored_optional_obligations=tuple(ignored),
        )
