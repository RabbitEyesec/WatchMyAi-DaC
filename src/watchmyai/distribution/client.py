"""Ordered signed-metadata verification, rollback control, and activation state."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from watchmyai.distribution.canonical import load_strict_json
from watchmyai.distribution.metadata import (
    MetadataError,
    RoleVerifier,
    VerifiedMetadata,
    exact_bytes,
    parse_time,
)
from watchmyai.distribution.store import TwoSlotStore
from watchmyai.policy.model import PolicyBundle


class OfflineState(StrEnum):
    FRESH = "FRESH"
    STALE_GRACE = "STALE_GRACE"
    STALE_BLOCKED = "STALE_BLOCKED"
    CLOCK_UNTRUSTED = "CLOCK_UNTRUSTED"


@dataclass(frozen=True)
class ActivationResult:
    activated: bool
    policy_bundle_id: str
    policy_bundle_version: str
    policy_sequence: int
    state_path: Path
    rollback: bool = False


CapabilityValidator = Callable[[PolicyBundle, tuple[str, ...]], tuple[bool, list[str]]]
HealthCheck = Callable[[PolicyBundle], bool]
AuditFn = Callable[[dict[str, Any]], Any]
ActivationHook = Callable[[PolicyBundle, bool], Any]
RootPersister = Callable[[bytes], Any]


def _default_capability_validator(_: PolicyBundle, required: tuple[str, ...]) -> tuple[bool, list[str]]:
    return (not required, list(required))


def _default_health_check(bundle: PolicyBundle) -> bool:
    return bool(bundle.policies) or bundle.mode.value in {"observe", "monitor", "restrict", "strict"}


class DistributionClient:
    def __init__(
        self,
        root: str | Path,
        verifier: RoleVerifier,
        *,
        endpoint_id: str,
        agent_version: str,
        grace_period: timedelta = timedelta(hours=72),
        clock_rollback_tolerance: timedelta = timedelta(minutes=5),
        audit: AuditFn | None = None,
        on_activation: ActivationHook | None = None,
        root_persister: RootPersister | None = None,
    ):
        if grace_period < timedelta(0):
            raise ValueError("grace_period cannot be negative")
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.store = TwoSlotStore(self.root / "policy-store")
        self.verifier = verifier
        self.endpoint_id = endpoint_id
        self.agent_version = agent_version
        self.grace_period = grace_period
        self.clock_rollback_tolerance = clock_rollback_tolerance
        self.audit = audit
        self.on_activation = on_activation
        self.root_persister = root_persister
        self.state_path = self.root / "distribution-state.json"
        self.state = self._load_state()

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {
                "format_version": 1,
                "highest_versions": {"timestamp": 0, "snapshot": 0, "targets": 0},
                "accepted_digests": {},
                "highest_seen_policy_sequence": 0,
                "active_policy_sequence": 0,
                "verified_targets": {},
                "offline_state": OfflineState.FRESH.value,
            }
        raw = json.loads(self.state_path.read_text("utf-8"))
        if raw.get("format_version") != 1:
            raise ValueError("unsupported distribution state format")
        return raw

    def _save_state(self) -> None:
        temporary = self.state_path.with_suffix(f".{os.getpid()}.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(self.state, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(self.state_path)
        if os.name != "nt":
            descriptor = os.open(self.state_path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def rotate_root(self, root_chain: list[bytes], *, now: datetime) -> None:
        try:
            self._check_clock(now)
            if not root_chain:
                raise MetadataError("ROOT_VERSION_GAP", "root update chain is empty")
            candidate_verifier = RoleVerifier(
                copy.deepcopy(self.verifier.trusted_root),
                self.verifier.organization_id,
            )
            for raw in root_chain:
                candidate_verifier.rotate_root(raw, now=now)
            if self.root_persister is not None:
                self.root_persister(root_chain[-1])
            self.verifier = candidate_verifier
            self.state["root_version"] = candidate_verifier.trusted_root["root_version"]
            self.state["root_digest"] = hashlib.sha256(
                json.dumps(
                    candidate_verifier.trusted_root,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            self._save_state()
        except MetadataError as exc:
            self._audit("rejected", exc.code, role="root")
            raise
        self._audit("root_rotated", "VERIFIED", role="root")

    def verify_and_activate(
        self,
        *,
        timestamp_bytes: bytes,
        snapshot_bytes: bytes,
        targets_bytes: bytes,
        target_name: str,
        target_bytes: bytes,
        now: datetime,
        capability_validator: CapabilityValidator = _default_capability_validator,
        health_check: HealthCheck = _default_health_check,
        rollback_approval_count: int = 0,
    ) -> ActivationResult:
        try:
            result, bundle = self._verify_and_activate(
                timestamp_bytes=timestamp_bytes,
                snapshot_bytes=snapshot_bytes,
                targets_bytes=targets_bytes,
                target_name=target_name,
                target_bytes=target_bytes,
                now=now,
                capability_validator=capability_validator,
                health_check=health_check,
                rollback_approval_count=rollback_approval_count,
            )
        except MetadataError as exc:
            self._audit("rejected", exc.code, role="distribution")
            raise
        except Exception as exc:
            self._audit("rejected", type(exc).__name__, role="activation")
            raise
        self._audit(
            "activated",
            "ROLLBACK" if result.rollback else "VERIFIED",
            role="targets",
            candidate_bundle_id=result.policy_bundle_id,
            active_bundle_id=result.policy_bundle_id,
        )
        if self.on_activation is not None:
            self.on_activation(bundle, result.rollback)
        return result

    def _verify_and_activate(
        self,
        *,
        timestamp_bytes: bytes,
        snapshot_bytes: bytes,
        targets_bytes: bytes,
        target_name: str,
        target_bytes: bytes,
        now: datetime,
        capability_validator: CapabilityValidator = _default_capability_validator,
        health_check: HealthCheck = _default_health_check,
        rollback_approval_count: int = 0,
    ) -> tuple[ActivationResult, PolicyBundle]:
        self._check_clock(now)
        timestamp = self._verify_role(timestamp_bytes, "timestamp", now)
        snapshot_descriptor = timestamp.signed.get("snapshot")
        if not isinstance(snapshot_descriptor, dict):
            raise MetadataError("INVALID_TIMESTAMP", "timestamp lacks snapshot descriptor")
        exact_bytes(snapshot_descriptor, snapshot_bytes, "snapshot")
        snapshot = self._verify_role(snapshot_bytes, "snapshot", now)
        if snapshot.metadata_version != snapshot_descriptor.get("metadata_version"):
            raise MetadataError("VERSION_MISMATCH", "snapshot version differs from timestamp")

        targets_descriptor = snapshot.signed.get("targets")
        if not isinstance(targets_descriptor, dict):
            raise MetadataError("INVALID_SNAPSHOT", "snapshot lacks targets descriptor")
        exact_bytes(targets_descriptor, targets_bytes, "targets")
        targets = self._verify_role(targets_bytes, "targets", now)
        if targets.metadata_version != targets_descriptor.get("metadata_version"):
            raise MetadataError("VERSION_MISMATCH", "targets version differs from snapshot")

        descriptors = targets.signed.get("targets")
        if not isinstance(descriptors, dict) or not isinstance(descriptors.get(target_name), dict):
            raise MetadataError("TARGET_NOT_AUTHORIZED", f"target {target_name!r} is not authorized")
        descriptor = descriptors[target_name]
        self._validate_descriptor(descriptor, now)
        exact_bytes(descriptor, target_bytes, "policy bundle")

        sequence = int(descriptor["policy_sequence"])
        highest = int(self.state.get("highest_seen_policy_sequence", 0))
        rollback = sequence < highest
        if rollback:
            self._validate_rollback(descriptor, now, rollback_approval_count)
        elif sequence == highest and highest:
            active_id = self.state.get("active_policy_bundle_id")
            if active_id != descriptor["policy_bundle_id"]:
                raise MetadataError("POLICY_SEQUENCE_REUSE", "policy_sequence reused by a different bundle")

        bundle_raw = load_strict_json(target_bytes)
        if not isinstance(bundle_raw, dict):
            raise MetadataError("POLICY_SCHEMA", "policy bundle root must be an object")
        bundle = PolicyBundle.from_dict(bundle_raw)
        self._bind_policy(descriptor, bundle)
        compatible, gaps = capability_validator(bundle, tuple(descriptor.get("required_capabilities", [])))
        if not compatible:
            raise MetadataError("CAPABILITY_MISMATCH", ", ".join(gaps) or "required capability unavailable")

        manifest = {
            "organization_id": self.verifier.organization_id,
            "endpoint_id": self.endpoint_id,
            "policy_bundle_id": bundle.policy_bundle_id,
            "policy_bundle_version": bundle.policy_bundle_version,
            "policy_sequence": bundle.policy_sequence,
            "metadata_versions": {
                "timestamp": timestamp.metadata_version,
                "snapshot": snapshot.metadata_version,
                "targets": targets.metadata_version,
            },
            "target_sha256": hashlib.sha256(target_bytes).hexdigest(),
            "rollback": rollback,
        }
        candidate = self.store.stage(
            {
                "timestamp.json": timestamp_bytes,
                "snapshot.json": snapshot_bytes,
                "targets.json": targets_bytes,
                "policy.json": target_bytes,
            },
            manifest,
        )

        def staged_health_check(path: Path) -> bool:
            loaded = PolicyBundle.from_dict(load_strict_json((path / "policy.json").read_bytes()))
            return health_check(loaded)

        active = self.store.activate(candidate, staged_health_check)
        self._commit_state(timestamp, snapshot, targets, descriptor, bundle, now, rollback)
        return (
            ActivationResult(
                True, bundle.policy_bundle_id, bundle.policy_bundle_version, sequence, active, rollback
            ),
            bundle,
        )

    def _audit(
        self,
        result: str,
        reason_code: str,
        *,
        role: str,
        candidate_bundle_id: str | None = None,
        active_bundle_id: str | None = None,
    ) -> None:
        if self.audit is None:
            return
        versions = self.state.get("highest_versions", {})
        distribution: dict[str, Any] = {
            "state": self.state.get("offline_state", OfflineState.FRESH.value),
            "role": role,
            "result": result,
            "reason_code": reason_code,
            "metadata_versions": dict(versions),
        }
        if candidate_bundle_id:
            distribution["candidate_bundle_id"] = candidate_bundle_id
        if active_bundle_id:
            distribution["active_bundle_id"] = active_bundle_id
        successful = result in {"activated", "root_rotated", "state_changed"}
        self.audit(
            {
                "event": {
                    "kind": "event" if successful else "alert",
                    "category": ["configuration"],
                    "type": ["change" if successful else "denied"],
                    "action": f"distribution.{result}",
                    "outcome": "success" if successful else "failure",
                },
                "watchmyai": {
                    "agent": {"id": self.endpoint_id, "type": "system"},
                    "attribution": {"level": "confirmed"},
                    "session": {"id": f"distribution:{self.endpoint_id}"},
                    "distribution": distribution,
                },
            }
        )

    def _verify_role(self, raw: bytes, role: str, now: datetime) -> VerifiedMetadata:
        versions = self.state.setdefault("highest_versions", {})
        digests = self.state.setdefault("accepted_digests", {})
        return self.verifier.verify(
            raw,
            role,
            now=now,
            highest_version=int(versions.get(role, 0)),
            accepted_digest=digests.get(role),
        )

    def _validate_descriptor(self, descriptor: dict[str, Any], now: datetime) -> None:
        required = {
            "organization_id",
            "policy_bundle_id",
            "policy_sequence",
            "policy_bundle_version",
            "schema_version",
            "length",
            "hashes",
            "issued_at",
            "expires_at",
            "minimum_agent_version",
            "required_capabilities",
        }
        missing = sorted(required - set(descriptor))
        if missing:
            raise MetadataError("INVALID_DESCRIPTOR", f"missing fields: {', '.join(missing)}")
        if "bundle_id" in descriptor or "policy_version" in descriptor:
            raise MetadataError("NON_CANONICAL_FIELD", "use policy_bundle_id and policy_bundle_version")
        if descriptor["organization_id"] != self.verifier.organization_id:
            raise MetadataError("ORGANIZATION_MISMATCH", "target organization mismatch")
        if not isinstance(descriptor["policy_sequence"], int) or descriptor["policy_sequence"] < 1:
            raise MetadataError("INVALID_DESCRIPTOR", "policy_sequence must be positive")
        if now >= parse_time(descriptor["expires_at"]):
            raise MetadataError("TARGET_EXPIRED", "target authorization expired")
        if parse_time(descriptor["issued_at"]) > now + timedelta(minutes=5):
            raise MetadataError("FUTURE_RELEASE", "target issued_at is in the future")
        if _version_tuple(self.agent_version) < _version_tuple(str(descriptor["minimum_agent_version"])):
            raise MetadataError("AGENT_INCOMPATIBLE", "agent version is below minimum_agent_version")
        if descriptor["schema_version"] != "1.2":
            raise MetadataError("SCHEMA_INCOMPATIBLE", "unsupported target policy schema")
        if not isinstance(descriptor["required_capabilities"], list):
            raise MetadataError("INVALID_DESCRIPTOR", "required_capabilities must be an array")

    def _bind_policy(self, descriptor: dict[str, Any], bundle: PolicyBundle) -> None:
        comparisons = {
            "policy_bundle_id": bundle.policy_bundle_id,
            "policy_bundle_version": bundle.policy_bundle_version,
            "policy_sequence": bundle.policy_sequence,
            "schema_version": bundle.schema_version,
            "organization_id": bundle.organization_id,
        }
        for field, actual in comparisons.items():
            if descriptor[field] != actual:
                raise MetadataError("POLICY_BINDING_MISMATCH", f"descriptor {field} does not match bundle")
        descriptor_capabilities = set(descriptor.get("required_capabilities", []))
        missing = sorted(set(bundle.required_capabilities) - descriptor_capabilities)
        if missing:
            raise MetadataError(
                "POLICY_BINDING_MISMATCH",
                f"bundle capabilities absent from signed descriptor: {', '.join(missing)}",
            )

    def _validate_rollback(self, descriptor: dict[str, Any], now: datetime, approval_count: int) -> None:
        authorization = descriptor.get("rollback_authorization")
        if not isinstance(authorization, dict):
            raise MetadataError("POLICY_ROLLBACK", "lower policy_sequence has no rollback authorization")
        required = {
            "rollback_id",
            "from_policy_sequence",
            "to_policy_sequence",
            "target_bundle_id",
            "reason",
            "issued_at",
            "expires_at",
            "minimum_approvals",
        }
        if required - set(authorization):
            raise MetadataError("ROLLBACK_AUTHORIZATION", "rollback authorization is incomplete")
        if authorization["from_policy_sequence"] != self.state.get("active_policy_sequence"):
            raise MetadataError("ROLLBACK_AUTHORIZATION", "rollback from_policy_sequence mismatch")
        if authorization["to_policy_sequence"] != descriptor["policy_sequence"]:
            raise MetadataError("ROLLBACK_AUTHORIZATION", "rollback to_policy_sequence mismatch")
        if authorization["target_bundle_id"] != descriptor["policy_bundle_id"]:
            raise MetadataError("ROLLBACK_AUTHORIZATION", "rollback target_bundle_id mismatch")
        if not (parse_time(authorization["issued_at"]) <= now < parse_time(authorization["expires_at"])):
            raise MetadataError("ROLLBACK_AUTHORIZATION", "rollback authorization is not current")
        if approval_count < int(authorization["minimum_approvals"]):
            raise MetadataError("ROLLBACK_APPROVALS", "minimum rollback approvals not met")
        verified = self.state.get("verified_targets", {})
        key = f"{descriptor['policy_bundle_id']}:{descriptor['policy_sequence']}"
        if key not in verified:
            # The exact bytes are still re-verified by current Targets below; this records first-time
            # recovery of a previously unavailable target rather than trusting local history alone.
            return

    def _commit_state(
        self,
        timestamp: VerifiedMetadata,
        snapshot: VerifiedMetadata,
        targets: VerifiedMetadata,
        descriptor: dict[str, Any],
        bundle: PolicyBundle,
        now: datetime,
        rollback: bool,
    ) -> None:
        versions = self.state.setdefault("highest_versions", {})
        digests = self.state.setdefault("accepted_digests", {})
        for item in (timestamp, snapshot, targets):
            versions[item.role] = max(int(versions.get(item.role, 0)), item.metadata_version)
            digests[item.role] = item.digest
        self.state["highest_seen_policy_sequence"] = max(
            int(self.state.get("highest_seen_policy_sequence", 0)), bundle.policy_sequence
        )
        self.state["active_policy_sequence"] = bundle.policy_sequence
        self.state["active_policy_bundle_id"] = bundle.policy_bundle_id
        self.state["active_policy_bundle_version"] = bundle.policy_bundle_version
        self.state["timestamp_expires_at"] = timestamp.signed["expires_at"]
        self.state["target_expires_at"] = descriptor["expires_at"]
        self.state["last_trusted_time"] = _time_string(now)
        self.state["offline_state"] = OfflineState.FRESH.value
        self.state["last_activation_was_rollback"] = rollback
        key = f"{bundle.policy_bundle_id}:{bundle.policy_sequence}"
        self.state.setdefault("verified_targets", {})[key] = descriptor["hashes"]["sha256"]
        self._save_state()

    def offline_state(self, now: datetime) -> OfflineState:
        try:
            self._check_clock(now, persist=False)
        except MetadataError:
            result = OfflineState.CLOCK_UNTRUSTED
            self._record_offline_state(result)
            return result
        timestamp_value = self.state.get("timestamp_expires_at")
        target_value = self.state.get("target_expires_at")
        if not timestamp_value or not target_value:
            result = OfflineState.STALE_BLOCKED
            self._record_offline_state(result)
            return result
        timestamp_expiry = parse_time(timestamp_value)
        target_expiry = parse_time(target_value)
        if now < timestamp_expiry and now < target_expiry:
            result = OfflineState.FRESH
            self._record_offline_state(result)
            return result
        grace_end = min(timestamp_expiry + self.grace_period, target_expiry)
        if now < grace_end:
            result = OfflineState.STALE_GRACE
            self._record_offline_state(result)
            return result
        result = OfflineState.STALE_BLOCKED
        self._record_offline_state(result)
        return result

    def _record_offline_state(self, state: OfflineState) -> None:
        previous = self.state.get("offline_state")
        if previous == state.value:
            return
        self.state["offline_state"] = state.value
        self._save_state()
        self._audit("state_changed", state.value, role="timestamp")

    def _check_clock(self, now: datetime, *, persist: bool = True) -> None:
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        previous = self.state.get("last_trusted_time")
        if previous and now < parse_time(previous) - self.clock_rollback_tolerance:
            self.state["offline_state"] = OfflineState.CLOCK_UNTRUSTED.value
            if persist:
                self._save_state()
            raise MetadataError("CLOCK_UNTRUSTED", "system time moved backwards beyond tolerance")


def _version_tuple(value: str) -> tuple[int, ...]:
    pieces = value.split("-", 1)[0].split(".")
    try:
        return tuple(int(piece) for piece in pieces)
    except ValueError as exc:
        raise MetadataError("INVALID_VERSION", f"invalid semantic version {value!r}") from exc


def _time_string(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
