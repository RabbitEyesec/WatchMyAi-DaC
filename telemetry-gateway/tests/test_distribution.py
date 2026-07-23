from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from watchmyai.distribution.canonical import CanonicalJSONError, canonicalize, load_strict_json
from watchmyai.distribution.client import DistributionClient, OfflineState
from watchmyai.distribution.metadata import MetadataError, RoleVerifier, public_key_id, sign_signed_object
from watchmyai.distribution.store import TwoSlotStore

NOW = datetime(2030, 1, 1, tzinfo=UTC)


def timestamp(days: int) -> str:
    return (NOW + timedelta(days=days)).isoformat(timespec="seconds").replace("+00:00", "Z")


def key_object(private: Ed25519PrivateKey) -> tuple[str, dict]:
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    obj = {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": {"public": base64.urlsafe_b64encode(raw).decode().rstrip("=")},
    }
    return public_key_id(obj), obj


def envelope(signed: dict, signers: list[tuple[str, Ed25519PrivateKey]]) -> bytes:
    value = {
        "signed": signed,
        "signatures": [sign_signed_object(signed, key, keyid) for keyid, key in signers],
    }
    return canonicalize(value)


class Repository:
    def __init__(self):
        self.private = {
            role: Ed25519PrivateKey.generate()
            for role in ("root-a", "root-b", "targets", "snapshot", "timestamp")
        }
        pairs = {name: key_object(key) for name, key in self.private.items()}
        self.keyids = {name: pair[0] for name, pair in pairs.items()}
        self.keys = {pair[0]: pair[1] for pair in pairs.values()}
        self.root_signed = {
            "_type": "root",
            "organization_id": "org-test",
            "root_version": 1,
            "expires_at": timestamp(3650),
            "algorithms": ["ed25519"],
            "keys": self.keys,
            "roles": {
                "root": {"keyids": [self.keyids["root-a"], self.keyids["root-b"]], "threshold": 2},
                "targets": {"keyids": [self.keyids["targets"]], "threshold": 1},
                "snapshot": {"keyids": [self.keyids["snapshot"]], "threshold": 1},
                "timestamp": {"keyids": [self.keyids["timestamp"]], "threshold": 1},
            },
        }
        self.root_bytes = envelope(
            self.root_signed,
            [
                (self.keyids["root-a"], self.private["root-a"]),
                (self.keyids["root-b"], self.private["root-b"]),
            ],
        )

    def bundle(self, sequence: int) -> bytes:
        value = {
            "schema_version": "1.2",
            "policy_bundle_id": f"bundle-{sequence}",
            "policy_bundle_version": f"{sequence}.0.0",
            "policy_sequence": sequence,
            "organization_id": "org-test",
            "mode": "strict",
            "default_effect": "DENY",
            "required_capabilities": [],
            "metadata": {},
            "policies": [
                {
                    "policy_id": "allow-local",
                    "policy_version": "1",
                    "priority": 1,
                    "effect": "ALLOW",
                    "match": {"tool_class": "local_function"},
                    "obligations": ["AUDIT_METADATA_ONLY"],
                }
            ],
        }
        return canonicalize(value)

    def release(self, sequence: int, version: int, *, rollback=None, required_capabilities=None):
        policy = self.bundle(sequence)
        descriptor = {
            "organization_id": "org-test",
            "policy_bundle_id": f"bundle-{sequence}",
            "policy_sequence": sequence,
            "policy_bundle_version": f"{sequence}.0.0",
            "schema_version": "1.2",
            "length": len(policy),
            "hashes": {"sha256": hashlib.sha256(policy).hexdigest()},
            "issued_at": timestamp(-1),
            "expires_at": timestamp(30),
            "minimum_agent_version": "1.0.0",
            "required_capabilities": required_capabilities or [],
        }
        if rollback:
            descriptor["rollback_authorization"] = rollback
        targets_signed = {
            "_type": "targets",
            "organization_id": "org-test",
            "targets_version": version,
            "expires_at": timestamp(30),
            "targets": {"policy.json": descriptor},
        }
        targets = envelope(targets_signed, [(self.keyids["targets"], self.private["targets"])])
        snapshot_signed = {
            "_type": "snapshot",
            "organization_id": "org-test",
            "snapshot_version": version,
            "expires_at": timestamp(7),
            "targets": {
                "metadata_version": version,
                "length": len(targets),
                "hashes": {"sha256": hashlib.sha256(targets).hexdigest()},
            },
        }
        snapshot = envelope(snapshot_signed, [(self.keyids["snapshot"], self.private["snapshot"])])
        timestamp_signed = {
            "_type": "timestamp",
            "organization_id": "org-test",
            "timestamp_version": version,
            "expires_at": timestamp(1),
            "snapshot": {
                "metadata_version": version,
                "length": len(snapshot),
                "hashes": {"sha256": hashlib.sha256(snapshot).hexdigest()},
            },
        }
        timestamp_bytes = envelope(timestamp_signed, [(self.keyids["timestamp"], self.private["timestamp"])])
        return {
            "timestamp_bytes": timestamp_bytes,
            "snapshot_bytes": snapshot,
            "targets_bytes": targets,
            "target_name": "policy.json",
            "target_bytes": policy,
            "now": NOW,
        }


@pytest.fixture
def repository():
    return Repository()


@pytest.fixture
def client(tmp_path, repository):
    verifier = RoleVerifier.enroll(repository.root_bytes, "org-test")
    return DistributionClient(tmp_path / "dist", verifier, endpoint_id="endpoint", agent_version="1.0.0")


def allow_capabilities(*_):
    return True, []


def activate(client, release, **kwargs):
    return client.verify_and_activate(**release, capability_validator=allow_capabilities, **kwargs)


def test_dist_001_canonical_whitespace_and_order():
    # DIST-CONF-001 / DIST-TEST-001
    a = load_strict_json('{"b":2, "a":1}')
    b = load_strict_json('{\n  "a": 1,\n  "b": 2\n}')
    assert canonicalize(a) == canonicalize(b) == b'{"a":1,"b":2}'


def test_dist_002_duplicate_json_key_rejected():
    # DIST-CONF-001 / DIST-TEST-002
    with pytest.raises(CanonicalJSONError, match="duplicate"):
        load_strict_json('{"a":1,"a":2}')


def test_dist_003_threshold_distinct_keys(repository):
    # DIST-CONF-002 / DIST-TEST-003
    one_signature = envelope(
        repository.root_signed, [(repository.keyids["root-a"], repository.private["root-a"])]
    )
    with pytest.raises(MetadataError, match="THRESHOLD_NOT_MET"):
        RoleVerifier.enroll(one_signature, "org-test")


def test_dist_004_old_timestamp_replay_rejected(client, repository):
    # DIST-CONF-004, DIST-VERIFY-003 / DIST-TEST-004
    activate(client, repository.release(1, 2))
    with pytest.raises(MetadataError, match="VERSION_ROLLBACK"):
        activate(client, repository.release(2, 1))


def test_dist_005_altered_snapshot_rejected(client, repository):
    # DIST-CONF-005, DIST-VERIFY-004 / DIST-TEST-005
    release = repository.release(1, 1)
    release["snapshot_bytes"] += b" "
    with pytest.raises(MetadataError, match="LENGTH_MISMATCH"):
        activate(client, release)


def test_dist_006_old_valid_bundle_without_rollback_rejected(client, repository):
    # DIST-CONF-006, DIST-VERIFY-007 / DIST-TEST-006
    activate(client, repository.release(2, 1))
    with pytest.raises(MetadataError, match="POLICY_ROLLBACK"):
        activate(client, repository.release(1, 2))


def test_dist_007_authorized_rollback_preserves_highest(client, repository):
    # DIST-CONF-007 / DIST-TEST-007
    activate(client, repository.release(2, 1))
    authorization = {
        "rollback_id": "rb-1",
        "from_policy_sequence": 2,
        "to_policy_sequence": 1,
        "target_bundle_id": "bundle-1",
        "reason": "known regression",
        "issued_at": timestamp(-1),
        "expires_at": timestamp(1),
        "minimum_approvals": 2,
    }
    result = activate(client, repository.release(1, 2, rollback=authorization), rollback_approval_count=2)
    assert result.rollback
    assert client.state["active_policy_sequence"] == 1
    assert client.state["highest_seen_policy_sequence"] == 2


def test_dist_008_root_rotation_requires_old_and_new_thresholds(repository):
    # DIST-CONF-003, DIST-ROOT-001, DIST-ROOT-002 / DIST-TEST-008
    verifier = RoleVerifier.enroll(repository.root_bytes, "org-test")
    new_a, new_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    new_a_id, new_a_obj = key_object(new_a)
    new_b_id, new_b_obj = key_object(new_b)
    candidate = {
        **repository.root_signed,
        "root_version": 2,
        "keys": {**repository.keys, new_a_id: new_a_obj, new_b_id: new_b_obj},
    }
    candidate["roles"] = {
        **repository.root_signed["roles"],
        "root": {"keyids": [new_a_id, new_b_id], "threshold": 2},
    }
    old_only = envelope(
        candidate,
        [
            (repository.keyids["root-a"], repository.private["root-a"]),
            (repository.keyids["root-b"], repository.private["root-b"]),
        ],
    )
    with pytest.raises(MetadataError, match="THRESHOLD_NOT_MET"):
        verifier.rotate_root(old_only, now=NOW)
    dual = envelope(
        candidate,
        [
            (repository.keyids["root-a"], repository.private["root-a"]),
            (repository.keyids["root-b"], repository.private["root-b"]),
            (new_a_id, new_a),
            (new_b_id, new_b),
        ],
    )
    assert verifier.rotate_root(dual, now=NOW)["root_version"] == 2


def test_dist_009_revoked_timestamp_key_rejected(repository):
    # DIST-KEY-002, DIST-VERIFY-003 / DIST-TEST-009
    verifier = RoleVerifier.enroll(repository.root_bytes, "org-test")
    replacement = Ed25519PrivateKey.generate()
    replacement_id, replacement_obj = key_object(replacement)
    candidate = {
        **repository.root_signed,
        "root_version": 2,
        "keys": {**repository.keys, replacement_id: replacement_obj},
    }
    candidate["roles"] = {
        **repository.root_signed["roles"],
        "timestamp": {"keyids": [replacement_id], "threshold": 1},
    }
    rotated = envelope(
        candidate,
        [
            (repository.keyids["root-a"], repository.private["root-a"]),
            (repository.keyids["root-b"], repository.private["root-b"]),
        ],
    )
    # Root role did not change, so the same old/new root threshold satisfies both checks.
    verifier.rotate_root(rotated, now=NOW)
    release = repository.release(1, 1)
    with pytest.raises(MetadataError, match="THRESHOLD_NOT_MET"):
        verifier.verify(release["timestamp_bytes"], "timestamp", now=NOW)


def test_dist_010_crash_before_pointer_switch_preserves_active(tmp_path):
    # DIST-CONF-008 / DIST-TEST-010
    store = TwoSlotStore(tmp_path / "slots")
    first = store.stage({"policy.json": b"one"}, {"sequence": 1})
    store.activate(first, lambda _: True)
    store.stage({"policy.json": b"two"}, {"sequence": 2})
    assert store.read_pointer("ACTIVE") == first


def test_dist_011_failed_health_check_restores_lkg(tmp_path):
    # DIST-CONF-008 / DIST-TEST-011
    store = TwoSlotStore(tmp_path / "slots")
    first = store.stage({"policy.json": b"one"}, {"sequence": 1})
    store.activate(first, lambda _: True)
    second = store.stage({"policy.json": b"two"}, {"sequence": 2})
    with pytest.raises(RuntimeError, match="LAST_KNOWN_GOOD"):
        store.activate(second, lambda _: False)
    assert store.read_pointer("ACTIVE") == first


def test_dist_012_offline_beyond_grace_is_blocked(client, repository):
    # DIST-CONF-009 / DIST-TEST-012
    activate(client, repository.release(1, 1))
    assert client.offline_state(NOW + timedelta(days=5)) == OfflineState.STALE_BLOCKED


def test_dist_013_unsupported_obligation_refuses_activation(client, repository):
    # DIST-VERIFY-009 / DIST-TEST-013
    release = repository.release(1, 1, required_capabilities=["supports_session_termination"])
    with pytest.raises(MetadataError, match="CAPABILITY_MISMATCH"):
        client.verify_and_activate(
            **release,
            capability_validator=lambda _bundle, required: (False, list(required)),
        )


def test_distribution_audits_activation_and_rejection(tmp_path, repository):
    events = []
    activated = []
    client = DistributionClient(
        tmp_path / "dist",
        RoleVerifier.enroll(repository.root_bytes, "org-test"),
        endpoint_id="endpoint",
        agent_version="1.0.0",
        audit=events.append,
        on_activation=lambda bundle, _rollback: activated.append(bundle.policy_bundle_id),
    )
    activate(client, repository.release(1, 1))
    assert events[-1]["event"]["action"] == "distribution.activated"
    assert activated == ["bundle-1"]
    tampered = repository.release(2, 2)
    tampered["snapshot_bytes"] += b" "
    with pytest.raises(MetadataError):
        activate(client, tampered)
    assert events[-1]["event"]["action"] == "distribution.rejected"
    assert events[-1]["watchmyai"]["distribution"]["reason_code"] == "LENGTH_MISMATCH"
