"""Canonical organization policy bundle model (schema v1.2)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from watchmyai.core.models import DecisionEffect, Obligation, OperatingMode


@dataclass(frozen=True)
class PolicyRule:
    policy_id: str
    policy_version: str
    priority: int
    effect: DecisionEffect
    match: dict[str, Any]
    obligations: tuple[str, ...] = ()
    reason_code: str = "POLICY_MATCH"
    description: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PolicyRule:
        required = ("policy_id", "policy_version", "effect", "match")
        missing = [key for key in required if key not in raw]
        if missing:
            raise ValueError(f"policy is missing: {', '.join(missing)}")
        obligations = tuple(str(item) for item in raw.get("obligations", []))
        unknown = sorted(set(obligations) - {item.value for item in Obligation})
        if unknown:
            raise ValueError(f"policy {raw['policy_id']}: unknown obligations: {', '.join(unknown)}")
        if not isinstance(raw["match"], dict) or not raw["match"]:
            raise ValueError(f"policy {raw['policy_id']}: match must be a non-empty object")
        return cls(
            policy_id=str(raw["policy_id"]),
            policy_version=str(raw["policy_version"]),
            priority=int(raw.get("priority", 0)),
            effect=DecisionEffect(str(raw["effect"]).upper()),
            match=dict(raw["match"]),
            obligations=obligations,
            reason_code=str(raw.get("reason_code", "POLICY_MATCH")),
            description=str(raw.get("description", "")),
        )


@dataclass(frozen=True)
class PolicyBundle:
    policy_bundle_id: str
    policy_bundle_version: str
    policy_sequence: int
    organization_id: str
    mode: OperatingMode
    policies: tuple[PolicyRule, ...]
    schema_version: str = "1.2"
    default_effect: DecisionEffect = DecisionEffect.MONITOR
    required_capabilities: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != "1.2":
            raise ValueError(f"unsupported policy schema_version {self.schema_version!r}")
        for name in ("policy_bundle_id", "policy_bundle_version", "organization_id"):
            if not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        if self.policy_sequence < 1:
            raise ValueError("policy_sequence must be a positive monotonic integer")
        if self.mode == OperatingMode.STRICT and self.default_effect != DecisionEffect.DENY:
            raise ValueError("strict mode must be default-deny for unmatched actions")
        identities = [(item.policy_id, item.policy_version) for item in self.policies]
        if len(identities) != len(set(identities)):
            raise ValueError("duplicate policy_id/policy_version in bundle")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PolicyBundle:
        required = (
            "schema_version",
            "policy_bundle_id",
            "policy_bundle_version",
            "policy_sequence",
            "organization_id",
            "mode",
            "policies",
        )
        missing = [key for key in required if key not in raw]
        if missing:
            raise ValueError(f"policy bundle is missing: {', '.join(missing)}")
        if not isinstance(raw["policies"], list):
            raise ValueError("policies must be an array")
        mode = OperatingMode(str(raw["mode"]).lower())
        default = raw.get("default_effect", "DENY" if mode == OperatingMode.STRICT else "MONITOR")
        known = set(required) | {"default_effect", "required_capabilities", "metadata"}
        unknown = sorted(set(raw) - known)
        if unknown:
            raise ValueError(f"unknown policy bundle fields: {', '.join(unknown)}")
        return cls(
            schema_version=str(raw["schema_version"]),
            policy_bundle_id=str(raw["policy_bundle_id"]),
            policy_bundle_version=str(raw["policy_bundle_version"]),
            policy_sequence=int(raw["policy_sequence"]),
            organization_id=str(raw["organization_id"]),
            mode=mode,
            default_effect=DecisionEffect(str(default).upper()),
            required_capabilities=tuple(str(item) for item in raw.get("required_capabilities", [])),
            policies=tuple(PolicyRule.from_dict(item) for item in raw["policies"]),
            metadata=dict(raw.get("metadata", {})),
        )

    @classmethod
    def load(cls, path: str | Path) -> PolicyBundle:
        source = Path(path)
        text = source.read_text("utf-8")
        raw = json.loads(text) if source.suffix == ".json" else yaml.safe_load(text)
        if not isinstance(raw, dict):
            raise ValueError("policy bundle root must be an object")
        return cls.from_dict(raw)


def load_policy_bundle(path: str | Path) -> PolicyBundle:
    return PolicyBundle.load(path)


# This import alias is source-compatible only. It does not carry the former
# observe-first model or accept its wire format.
Policy = PolicyRule


def load_policies(path: str | Path) -> list[PolicyRule]:
    return list(PolicyBundle.load(path).policies)
