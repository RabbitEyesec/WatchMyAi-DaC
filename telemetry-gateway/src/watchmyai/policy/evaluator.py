"""Deterministic policy decision point with deny-first conflict resolution."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any

from watchmyai.capability.service import CapabilityRegistry
from watchmyai.core.models import (
    DecisionEffect,
    DecisionEvidence,
    GuaranteeStatus,
    OperatingMode,
    PolicyDecision,
    ToolRequest,
)
from watchmyai.policy.model import PolicyBundle, PolicyRule

_EFFECT_ORDER = {
    DecisionEffect.DENY: 0,
    DecisionEffect.REQUIRE_APPROVAL: 1,
    DecisionEffect.MONITOR: 2,
    DecisionEffect.ALLOW: 3,
}


@dataclass(frozen=True)
class RuleMatch:
    policy: PolicyRule
    evidence: dict[str, Any]


def _matches_pattern(value: str, expected: Any) -> bool:
    choices = expected if isinstance(expected, list) else [expected]
    return any(fnmatch(value, str(pattern)) for pattern in choices)


def _match_policy(policy: PolicyRule, request: ToolRequest) -> RuleMatch | None:
    attributes: dict[str, Any] = {
        "adapter_id": request.adapter_id,
        "agent_id": request.agent_id,
        "tool_name": request.tool_name,
        "tool_class": request.tool_class,
        "operation": request.operation,
        "repository_id": request.repository_id,
        "mcp_server_id": request.mcp_server_id,
        **request.attributes,
    }
    evidence: dict[str, Any] = {}
    for field, expected in sorted(policy.match.items()):
        if field not in attributes:
            return None
        actual = attributes[field]
        if isinstance(expected, bool):
            matched = actual is expected
        elif isinstance(actual, (list, tuple, set)):
            matched_values = [str(item) for item in actual if _matches_pattern(str(item), expected)]
            matched = bool(matched_values)
            actual = matched_values
        elif actual is None:
            matched = False
        else:
            matched = _matches_pattern(str(actual), expected)
        if not matched:
            return None
        evidence[field] = actual
    return RuleMatch(policy, evidence)


class PolicyDecisionPoint:
    def __init__(self, bundle: PolicyBundle, capabilities: CapabilityRegistry):
        self.bundle = bundle
        self.capabilities = capabilities
        self._cache: dict[tuple[str, str, str], PolicyDecision] = {}
        self._capability_generation = capabilities.generation

    def activate(self, bundle: PolicyBundle, *, verified_rollback: bool = False) -> None:
        if bundle.policy_sequence < self.bundle.policy_sequence and not verified_rollback:
            raise ValueError("cannot activate a lower policy_sequence")
        if (
            bundle.policy_bundle_version != self.bundle.policy_bundle_version
            or bundle.policy_sequence != self.bundle.policy_sequence
        ):
            self._cache.clear()
        self.bundle = bundle

    def invalidate(self) -> None:
        self._cache.clear()
        self._capability_generation = self.capabilities.generation

    def evaluate(self, request: ToolRequest) -> PolicyDecision:
        if self._capability_generation != self.capabilities.generation:
            self.invalidate()
        capability = self.capabilities.get(request.adapter_id)
        cache_key = (request.payload_hash, self.bundle.policy_bundle_version, capability.fingerprint)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return PolicyDecision(
                effect=cached.effect,
                evidence=cached.evidence,
                request_id=request.request_id,
                action_id=request.action_id,
            )

        matches = [match for rule in self.bundle.policies if (match := _match_policy(rule, request))]
        matches.sort(
            key=lambda item: (
                _EFFECT_ORDER[item.policy.effect],
                -item.policy.priority,
                item.policy.policy_id,
                item.policy.policy_version,
            )
        )
        if matches:
            winner = matches[0].policy
            effect = winner.effect
            obligations = winner.obligations
            reason_codes = [winner.reason_code]
            winning_id = winner.policy_id
            winning_version = winner.policy_version
        else:
            effect = (
                DecisionEffect.DENY
                if self.bundle.mode == OperatingMode.STRICT
                else self.bundle.default_effect
            )
            obligations = ()
            reason_codes = [
                "STRICT_DEFAULT_DENY" if self.bundle.mode == OperatingMode.STRICT else "UNMATCHED_ACTION"
            ]
            winning_id = "__default__"
            winning_version = self.bundle.schema_version

        check = self.capabilities.check(request, obligations)
        if not check.covered or check.guarantee_status == GuaranteeStatus.UNAVAILABLE:
            reason_codes.append("CAPABILITY_GAP")
            if self.bundle.mode in (OperatingMode.RESTRICT, OperatingMode.STRICT):
                effect = DecisionEffect.DENY
            elif effect == DecisionEffect.ALLOW:
                effect = DecisionEffect.MONITOR
        if check.unavailable_obligations:
            reason_codes.append("OBLIGATION_UNAVAILABLE")
            effect = DecisionEffect.DENY
        if effect == DecisionEffect.REQUIRE_APPROVAL and not capability.supports_approval:
            reason_codes.append("APPROVAL_CAPABILITY_UNAVAILABLE")
            effect = DecisionEffect.DENY

        evidence = DecisionEvidence(
            winning_policy_id=winning_id,
            winning_policy_version=winning_version,
            policy_bundle_id=self.bundle.policy_bundle_id,
            policy_bundle_version=self.bundle.policy_bundle_version,
            policy_sequence=self.bundle.policy_sequence,
            match_evidence=tuple(
                {
                    "policy_id": item.policy.policy_id,
                    "policy_version": item.policy.policy_version,
                    "effect": item.policy.effect.value,
                    "priority": item.policy.priority,
                    "matched": item.evidence,
                }
                for item in matches
            ),
            requested_obligations=tuple(obligations),
            effective_obligations=check.effective_obligations,
            obligation_status="unavailable" if check.unavailable_obligations else "satisfied",
            guarantee_status=check.guarantee_status,
            reason_codes=tuple(dict.fromkeys(reason_codes)),
            capability_fingerprint=capability.fingerprint,
        )
        decision = PolicyDecision(effect, evidence, request.request_id, request.action_id)
        self._cache[cache_key] = decision
        return decision


def evaluate_request(
    request: ToolRequest, bundle: PolicyBundle, capabilities: CapabilityRegistry
) -> PolicyDecision:
    return PolicyDecisionPoint(bundle, capabilities).evaluate(request)
