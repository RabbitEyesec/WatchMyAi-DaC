"""Atomic, one-time, strongly bound approval service.

The bearer approval identifier is persisted because separate hook processes
must present it, but it is never emitted. Telemetry contains only a SHA-256
reference. Every persistent mutation holds an inter-process lock, reloads the
latest state, validates, writes a temporary file, fsyncs it, and atomically
replaces the store.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from watchmyai.schema.event import canonical_hash, to_iso

DEFAULT_TTL_SECONDS = 300
EmitFn = Callable[[dict[str, Any]], Any]


@dataclass
class Approval:
    approval_id: str = field(repr=False)
    approval_ref: str
    session_id: str
    task_id: str
    agent_id: str
    tool_name: str
    payload_hash: str
    target_hash: str | None
    requires_justification: bool
    issued_at: float
    expires_at: float
    action_id: str = ""
    request_id: str = ""
    decision_id: str = ""
    policy_bundle_id: str = ""
    policy_sequence: int = 0
    idempotency_key_hash: str | None = None
    justification_hash: str | None = None
    status: str = "pending"
    use_count: int = 0
    max_uses: int = 1
    attempt_count: int = 0
    consumed_at: float | None = None

    @property
    def used(self) -> bool:
        return self.use_count >= self.max_uses

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Approval:
        return cls(**raw)


@dataclass(frozen=True)
class ConsumeResult:
    allowed: bool
    reason: str
    event_action: str
    approval: Approval | None = None


class _FileLock:
    def __init__(self, path: Path):
        self.path = path
        self.handle: Any = None

    def __enter__(self) -> _FileLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+b")
        if os.name == "nt":
            import msvcrt

            self.handle.seek(0)
            if self.handle.tell() == 0:
                self.handle.write(b"0")
                self.handle.flush()
            self.handle.seek(0)
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
        else:
            import fcntl

            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *_: object) -> None:
        if self.handle is None:
            return
        if os.name == "nt":
            import msvcrt

            self.handle.seek(0)
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
        else:
            import fcntl

            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        self.handle.close()


@dataclass
class ApprovalService:
    store_path: Path | None = None
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    clock: Callable[[], float] = time.time
    emit: EmitFn | None = None
    _approvals: dict[str, Approval] = field(default_factory=dict)
    _thread_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        if self.ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        if self.store_path is not None:
            self.store_path = Path(self.store_path)
            with self._transaction(write=False):
                pass

    @contextmanager
    def _transaction(self, *, write: bool = True) -> Iterator[None]:
        with self._thread_lock:
            if self.store_path is None:
                yield
                return
            lock_path = self.store_path.with_suffix(self.store_path.suffix + ".lock")
            with _FileLock(lock_path):
                self._load_unlocked()
                yield
                if write:
                    self._save_unlocked()

    def request(
        self,
        session_id: str,
        task_id: str,
        agent_id: str,
        tool_name: str,
        payload: Any,
        target: str | None = None,
        *,
        action_id: str = "",
        request_id: str = "",
        decision_id: str = "",
        policy_bundle_id: str = "",
        policy_sequence: int = 0,
        idempotency_key: str | None = None,
        requires_justification: bool = False,
    ) -> Approval:
        now = self.clock()
        key_hash = canonical_hash(idempotency_key) if idempotency_key else None
        event: tuple[str, Approval, str | None] | None = None
        with self._transaction():
            if key_hash:
                existing = next(
                    (item for item in self._approvals.values() if item.idempotency_key_hash == key_hash),
                    None,
                )
                if existing is not None:
                    expected = (
                        session_id,
                        task_id,
                        agent_id,
                        tool_name,
                        canonical_hash(payload),
                        canonical_hash(target) if target is not None else None,
                        action_id,
                        request_id,
                        decision_id,
                        policy_bundle_id,
                        policy_sequence,
                        requires_justification,
                    )
                    actual = (
                        existing.session_id,
                        existing.task_id,
                        existing.agent_id,
                        existing.tool_name,
                        existing.payload_hash,
                        existing.target_hash,
                        existing.action_id,
                        existing.request_id,
                        existing.decision_id,
                        existing.policy_bundle_id,
                        existing.policy_sequence,
                        existing.requires_justification,
                    )
                    if expected != actual:
                        raise ValueError("idempotency key reused with different approval binding")
                    return existing
            token = "apr-" + secrets.token_urlsafe(32)
            approval = Approval(
                approval_id=token,
                approval_ref=canonical_hash(token),
                session_id=session_id,
                task_id=task_id,
                agent_id=agent_id,
                tool_name=tool_name,
                action_id=action_id,
                request_id=request_id,
                decision_id=decision_id,
                policy_bundle_id=policy_bundle_id,
                policy_sequence=policy_sequence,
                payload_hash=canonical_hash(payload),
                target_hash=canonical_hash(target) if target is not None else None,
                requires_justification=requires_justification,
                issued_at=now,
                expires_at=now + self.ttl_seconds,
                idempotency_key_hash=key_hash,
            )
            self._approvals[token] = approval
            event = ("approval.requested", approval, None)
        if event:
            self._emit_event(*event)
        return approval

    def grant(self, approval_id: str, *, justification: str | None = None) -> Approval | None:
        event: tuple[str, Approval, str | None] | None = None
        with self._transaction():
            approval = self._approvals.get(approval_id)
            if approval is None or approval.status != "pending":
                return None
            if approval.requires_justification and not justification:
                event = ("approval.failed", approval, "justification_required")
            elif self.clock() >= approval.expires_at:
                approval.status = "expired"
                event = ("approval.failed", approval, "expired")
            else:
                approval.status = "approved"
                approval.justification_hash = canonical_hash(justification) if justification else None
                event = ("approval.granted", approval, None)
        if event:
            self._emit_event(*event)
        return approval if event and event[0] == "approval.granted" else None

    def reject(self, approval_id: str, *, justification: str | None = None) -> Approval | None:
        with self._transaction():
            approval = self._approvals.get(approval_id)
            if approval is None or approval.status not in ("pending", "approved"):
                return None
            approval.status = "rejected"
            approval.justification_hash = canonical_hash(justification) if justification else None
        self._emit_event("approval.rejected", approval)
        return approval

    def consume(
        self,
        approval_id: str,
        session_id: str,
        task_id: str,
        agent_id: str,
        tool_name: str,
        payload: Any,
        target: str | None = None,
        *,
        action_id: str = "",
        request_id: str = "",
        decision_id: str = "",
        policy_bundle_id: str = "",
        policy_sequence: int = 0,
    ) -> ConsumeResult:
        approval: Approval | None
        reason = "ok"
        with self._transaction():
            approval = self._approvals.get(approval_id)
            if approval is None:
                reason = "unknown_approval"
            else:
                approval.attempt_count += 1
                now = self.clock()
                bindings = {
                    "session_id": session_id,
                    "task_id": task_id,
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                }
                expected = {
                    "session_id": approval.session_id,
                    "task_id": approval.task_id,
                    "agent_id": approval.agent_id,
                    "tool_name": approval.tool_name,
                }
                optional_bindings = {
                    "action_id": (action_id, approval.action_id),
                    "request_id": (request_id, approval.request_id),
                    "decision_id": (decision_id, approval.decision_id),
                    "policy_bundle_id": (policy_bundle_id, approval.policy_bundle_id),
                }
                if approval.use_count >= approval.max_uses or approval.status == "consumed":
                    reason = "approval_replay"
                elif now >= approval.expires_at or approval.status == "expired":
                    approval.status = "expired"
                    reason = "expired"
                elif approval.status == "rejected":
                    reason = "rejected"
                elif approval.status != "approved":
                    reason = "not_approved"
                elif canonical_hash(payload) != approval.payload_hash:
                    reason = "payload_mismatch"
                elif approval.target_hash is not None and canonical_hash(target) != approval.target_hash:
                    reason = "resolved_path_mismatch"
                elif bindings != expected:
                    reason = "binding_mismatch"
                elif any(stored and supplied != stored for supplied, stored in optional_bindings.values()):
                    reason = "binding_mismatch"
                elif approval.policy_sequence and policy_sequence != approval.policy_sequence:
                    reason = "policy_mismatch"
                else:
                    approval.use_count += 1
                    approval.status = "consumed"
                    approval.consumed_at = now
        if approval is None:
            self._emit_unknown_failure(reason)
            return ConsumeResult(False, reason, "approval.failed", None)
        if reason != "ok":
            self._emit_event("approval.failed", approval, reason)
            return ConsumeResult(False, reason, "approval.failed", approval)
        self._emit_event("approval.consumed", approval)
        return ConsumeResult(True, "ok", "approval.consumed", approval)

    def get(self, approval_id: str) -> Approval | None:
        with self._transaction(write=False):
            return self._approvals.get(approval_id)

    def get_by_ref(self, approval_ref: str) -> Approval | None:
        """Resolve an exact hash or unique prefix without exposing the bearer value."""
        with self._transaction(write=False):
            matches = [
                item for item in self._approvals.values() if item.approval_ref.startswith(approval_ref)
            ]
            if len(matches) > 1:
                raise ValueError("approval reference prefix is ambiguous")
            return matches[0] if matches else None

    def list_live(self) -> list[dict[str, Any]]:
        """Return operator-safe approval summaries without bearer identifiers."""
        with self._transaction(write=False):
            items = [
                {
                    "approval_ref": item.approval_ref,
                    "status": item.status,
                    "session_id": item.session_id,
                    "task_id": item.task_id,
                    "agent_id": item.agent_id,
                    "tool_name": item.tool_name,
                    "action_id": item.action_id,
                    "decision_id": item.decision_id,
                    "expires_at": item.expires_at,
                }
                for item in self._approvals.values()
                if item.status in {"pending", "approved"}
                and item.use_count < item.max_uses
                and self.clock() < item.expires_at
            ]
        return sorted(items, key=lambda item: (item["expires_at"], item["approval_ref"]))

    def find_approved(
        self,
        *,
        session_id: str,
        task_id: str,
        agent_id: str,
        tool_name: str,
        payload: Any,
        target: str | None,
    ) -> Approval | None:
        payload_hash = canonical_hash(payload)
        target_hash = canonical_hash(target) if target is not None else None
        with self._transaction(write=False):
            matches = [
                item
                for item in self._approvals.values()
                if item.status == "approved"
                and item.use_count < item.max_uses
                and self.clock() < item.expires_at
                and item.session_id == session_id
                and item.task_id == task_id
                and item.agent_id == agent_id
                and item.tool_name == tool_name
                and item.payload_hash == payload_hash
                and item.target_hash == target_hash
            ]
            if len(matches) > 1:
                raise ValueError("multiple live approvals match one action")
            return matches[0] if matches else None

    def grant_ref(self, approval_ref: str, *, justification: str | None = None) -> Approval | None:
        approval = self.get_by_ref(approval_ref)
        return self.grant(approval.approval_id, justification=justification) if approval else None

    def reject_ref(self, approval_ref: str, *, justification: str | None = None) -> Approval | None:
        approval = self.get_by_ref(approval_ref)
        return self.reject(approval.approval_id, justification=justification) if approval else None

    def sweep_expired(self) -> list[Approval]:
        expired: list[Approval] = []
        with self._transaction():
            now = self.clock()
            for approval in self._approvals.values():
                if approval.status in ("pending", "approved") and now >= approval.expires_at:
                    approval.status = "expired"
                    expired.append(approval)
        for approval in expired:
            self._emit_event("approval.failed", approval, "expired")
        return expired

    def _emit_unknown_failure(self, reason: str) -> None:
        if self.emit is None:
            return
        self.emit(
            {
                "event": {
                    "kind": "alert",
                    "category": ["iam"],
                    "type": ["denied"],
                    "action": "approval.failed",
                    "outcome": "failure",
                },
                "watchmyai": {
                    "attribution": {"level": "confirmed"},
                    "approval": {"status": "failed", "failure": {"reason": reason}},
                },
            }
        )

    def _emit_event(self, action: str, approval: Approval, reason: str | None = None) -> None:
        if self.emit is None:
            return
        failed = action == "approval.failed"
        payload: dict[str, Any] = {
            "event": {
                "kind": "alert" if failed else "event",
                "category": ["iam"],
                "type": ["denied"] if failed else ["info"],
                "action": action,
                "outcome": "failure" if failed else "success",
            },
            "watchmyai": {
                "agent": {"id": approval.agent_id, "type": "known_ai_agent"},
                "attribution": {"level": "confirmed"},
                "session": {"id": approval.session_id},
                "task": {"id": approval.task_id},
                "action": {"id": approval.action_id},
                "request": {"id": approval.request_id, "payload_hash": approval.payload_hash},
                "decision": {"id": approval.decision_id},
                "tool": {"name": approval.tool_name},
                "policy": {
                    "policy_bundle_id": approval.policy_bundle_id,
                    "policy_sequence": approval.policy_sequence,
                },
                "approval": {
                    "id_hash": approval.approval_ref,
                    "status": approval.status,
                    "required": True,
                    "requires_justification": approval.requires_justification,
                    "use_count": approval.use_count,
                    "max_uses": approval.max_uses,
                    "attempt_count": approval.attempt_count,
                    "expires_at": to_iso(approval.expires_at),
                    "payload_hash": approval.payload_hash,
                    **({"target_hash": approval.target_hash} if approval.target_hash else {}),
                    **({"consumed_at": to_iso(approval.consumed_at)} if approval.consumed_at else {}),
                    **({"failure": {"reason": reason}} if reason else {}),
                },
            },
        }
        self.emit(payload)

    def _load_unlocked(self) -> None:
        if self.store_path is None or not self.store_path.exists():
            self._approvals = {}
            return
        raw = json.loads(self.store_path.read_text("utf-8"))
        if raw.get("format_version") != 3:
            raise ValueError("unsupported approval store format; migrate explicitly to format 3")
        self._approvals = {item["approval_id"]: Approval.from_dict(item) for item in raw.get("approvals", [])}

    def _save_unlocked(self) -> None:
        assert self.store_path is not None
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "format_version": 3,
            "approvals": [
                item.to_dict() for item in sorted(self._approvals.values(), key=lambda x: x.approval_ref)
            ],
        }
        temporary = self.store_path.with_suffix(self.store_path.suffix + f".{os.getpid()}.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(self.store_path)
        if os.name != "nt":
            directory_fd = os.open(self.store_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
