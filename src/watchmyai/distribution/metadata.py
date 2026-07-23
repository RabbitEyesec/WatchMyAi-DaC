"""Ed25519 role metadata and threshold verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from watchmyai.distribution.canonical import canonicalize, load_strict_json


class MetadataError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class VerifiedMetadata:
    role: str
    signed: dict[str, Any]
    metadata_version: int
    digest: str
    valid_keyids: tuple[str, ...]


def _decode_fixed(value: str, length: int, label: str) -> bytes:
    try:
        if len(value) == length * 2:
            decoded = bytes.fromhex(value)
        else:
            padded = value + ("=" * (-len(value) % 4))
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
        raise MetadataError("UNSUPPORTED_KEY", f"invalid {label} encoding") from exc
    if len(decoded) != length:
        raise MetadataError("UNSUPPORTED_KEY", f"{label} must be {length} bytes")
    return decoded


def public_key_id(key_object: dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize(key_object)).hexdigest()


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise MetadataError("INVALID_TIME", "timestamps must be RFC 3339 UTC with trailing Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise MetadataError("INVALID_TIME", f"invalid timestamp {value!r}") from exc
    return parsed.astimezone(UTC)


def exact_bytes(expected: dict[str, Any], raw: bytes, label: str) -> None:
    length = expected.get("length")
    digest = (expected.get("hashes") or {}).get("sha256")
    if not isinstance(length, int) or length < 0 or not isinstance(digest, str):
        raise MetadataError("INVALID_DESCRIPTOR", f"{label} descriptor lacks length/sha256")
    if len(raw) != length:
        raise MetadataError("LENGTH_MISMATCH", f"{label} length mismatch")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != digest.lower():
        raise MetadataError("HASH_MISMATCH", f"{label} SHA-256 mismatch")


class RoleVerifier:
    def __init__(self, trusted_root: dict[str, Any], organization_id: str):
        self.trusted_root = trusted_root
        self.organization_id = organization_id

    @classmethod
    def enroll(cls, raw_root: bytes, organization_id: str) -> RoleVerifier:
        envelope = _envelope(raw_root)
        root = envelope["signed"]
        if root.get("organization_id") != organization_id:
            raise MetadataError("ORGANIZATION_MISMATCH", "root organization scope mismatch")
        _validate_root(root)
        verifier = cls(root, organization_id)
        verifier._verify_signatures(envelope, "root", root)
        _check_expiry(root, datetime.now(UTC))
        return verifier

    def verify(
        self,
        raw: bytes,
        role: str,
        *,
        now: datetime,
        highest_version: int = 0,
        accepted_digest: str | None = None,
    ) -> VerifiedMetadata:
        envelope = _envelope(raw)
        signed = envelope["signed"]
        if signed.get("_type") != role:
            raise MetadataError("ROLE_MISMATCH", f"expected {role!r}")
        if signed.get("organization_id") != self.organization_id:
            raise MetadataError("ORGANIZATION_MISMATCH", f"{role} organization scope mismatch")
        self._verify_signatures(envelope, role, self.trusted_root)
        _check_expiry(signed, now)
        version = _metadata_version(signed, role)
        digest = hashlib.sha256(canonicalize(signed)).hexdigest()
        if version < highest_version:
            raise MetadataError("VERSION_ROLLBACK", f"{role} version {version} < {highest_version}")
        if version == highest_version and accepted_digest and digest != accepted_digest:
            raise MetadataError("VERSION_REUSE", f"{role} version reused with different bytes")
        return VerifiedMetadata(
            role, signed, version, digest, tuple(self._valid_keyids(envelope, role, self.trusted_root))
        )

    def rotate_root(self, raw: bytes, *, now: datetime) -> dict[str, Any]:
        envelope = _envelope(raw)
        candidate = envelope["signed"]
        _validate_root(candidate)
        old_version = int(self.trusted_root["root_version"])
        new_version = int(candidate["root_version"])
        if new_version != old_version + 1:
            raise MetadataError("ROOT_VERSION_GAP", "root updates must be sequential")
        if candidate.get("organization_id") != self.organization_id:
            raise MetadataError("ORGANIZATION_MISMATCH", "new root organization scope mismatch")
        _check_expiry(candidate, now)
        self._verify_signatures(envelope, "root", self.trusted_root)
        self._verify_signatures(envelope, "root", candidate)
        self.trusted_root = candidate
        return candidate

    def _valid_keyids(self, envelope: dict[str, Any], role: str, root: dict[str, Any]) -> list[str]:
        role_spec = (root.get("roles") or {}).get(role)
        if not isinstance(role_spec, dict):
            raise MetadataError("UNKNOWN_ROLE", f"root has no role {role!r}")
        authorized = set(role_spec.get("keyids", []))
        keys = root.get("keys") or {}
        message = canonicalize(envelope["signed"])
        valid: list[str] = []
        seen: set[str] = set()
        for signature in envelope["signatures"]:
            if not isinstance(signature, dict):
                continue
            keyid = signature.get("keyid")
            if not isinstance(keyid, str) or keyid in seen or keyid not in authorized:
                continue
            seen.add(keyid)
            key_object = keys.get(keyid)
            if not isinstance(key_object, dict) or public_key_id(key_object) != keyid:
                continue
            if key_object.get("keytype") != "ed25519" or key_object.get("scheme") != "ed25519":
                continue
            public = (key_object.get("keyval") or {}).get("public")
            encoded_signature = signature.get("signature")
            if not isinstance(public, str) or not isinstance(encoded_signature, str):
                continue
            try:
                Ed25519PublicKey.from_public_bytes(_decode_fixed(public, 32, "public key")).verify(
                    _decode_fixed(encoded_signature, 64, "signature"), message
                )
            except (InvalidSignature, MetadataError, ValueError):
                continue
            valid.append(keyid)
        return valid

    def _verify_signatures(self, envelope: dict[str, Any], role: str, root: dict[str, Any]) -> None:
        role_spec = (root.get("roles") or {}).get(role)
        if not isinstance(role_spec, dict):
            raise MetadataError("UNKNOWN_ROLE", f"root has no role {role!r}")
        threshold = role_spec.get("threshold")
        if not isinstance(threshold, int) or threshold < 1:
            raise MetadataError("INVALID_THRESHOLD", f"invalid {role} threshold")
        valid = self._valid_keyids(envelope, role, root)
        if len(valid) < threshold:
            raise MetadataError(
                "THRESHOLD_NOT_MET", f"{role}: {len(valid)} valid distinct signatures, need {threshold}"
            )


def _envelope(raw: bytes) -> dict[str, Any]:
    value = load_strict_json(raw)
    if not isinstance(value, dict) or set(value) != {"signed", "signatures"}:
        raise MetadataError("INVALID_ENVELOPE", "metadata envelope must contain only signed and signatures")
    if not isinstance(value["signed"], dict) or not isinstance(value["signatures"], list):
        raise MetadataError("INVALID_ENVELOPE", "signed must be object and signatures must be array")
    return value


def _validate_root(root: dict[str, Any]) -> None:
    if root.get("_type") != "root":
        raise MetadataError("ROLE_MISMATCH", "root metadata must have _type=root")
    version = root.get("root_version")
    if not isinstance(version, int) or version < 1:
        raise MetadataError("INVALID_VERSION", "root_version must be a positive integer")
    if root.get("algorithms") != ["ed25519"]:
        raise MetadataError("UNSUPPORTED_ALGORITHM", "root algorithms must be exactly [ed25519]")
    keys = root.get("keys")
    roles = root.get("roles")
    if not isinstance(keys, dict) or not isinstance(roles, dict):
        raise MetadataError("INVALID_ROOT", "root keys and roles must be objects")
    for keyid, key_object in keys.items():
        if not isinstance(key_object, dict) or public_key_id(key_object) != keyid:
            raise MetadataError("KEYID_MISMATCH", f"key {keyid!r} does not match its canonical object")
    root_keys = set((roles.get("root") or {}).get("keyids", []))
    timestamp_keys = set((roles.get("timestamp") or {}).get("keyids", []))
    if root_keys.intersection(timestamp_keys):
        raise MetadataError("ROLE_SEPARATION", "one key cannot serve both root and timestamp")


def _metadata_version(signed: dict[str, Any], role: str) -> int:
    field = "root_version" if role == "root" else f"{role}_version"
    version = signed.get(field, signed.get("metadata_version"))
    if not isinstance(version, int) or version < 1:
        raise MetadataError("INVALID_VERSION", f"{role} metadata version must be positive")
    return version


def _check_expiry(signed: dict[str, Any], now: datetime) -> None:
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    if now.astimezone(UTC) >= parse_time(signed.get("expires_at")):
        raise MetadataError("EXPIRED", f"{signed.get('_type', 'metadata')} metadata expired")


def sign_signed_object(signed: dict[str, Any], private_key: Ed25519PrivateKey, keyid: str) -> dict[str, str]:
    """Release/test helper. Endpoint distribution clients never hold private keys."""
    signature = private_key.sign(canonicalize(signed))
    return {"keyid": keyid, "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")}
