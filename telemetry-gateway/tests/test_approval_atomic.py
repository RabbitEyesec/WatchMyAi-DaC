from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from watchmyai.approval.service import ApprovalService


def test_atomic_one_time_consumption_and_secret_safe_telemetry(tmp_path):
    events = []
    store = tmp_path / "approvals.json"
    service = ApprovalService(store_path=store, emit=events.append)
    approval = service.request(
        "session",
        "task",
        "agent",
        "shell",
        "payload-hash",
        "target-hash",
        action_id="action",
        request_id="request",
        decision_id="decision",
        policy_bundle_id="bundle",
        policy_sequence=9,
    )
    service.grant_ref(approval.approval_ref, justification="approved change ticket")
    listed = service.list_live()
    assert listed[0]["approval_ref"] == approval.approval_ref
    assert approval.approval_id not in str(listed)

    def consume():
        instance = ApprovalService(store_path=store, emit=events.append)
        return instance.consume(
            approval.approval_id,
            "session",
            "task",
            "agent",
            "shell",
            "payload-hash",
            "target-hash",
            action_id="action",
            request_id="request",
            decision_id="decision",
            policy_bundle_id="bundle",
            policy_sequence=9,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: consume(), range(2)))
    assert sum(result.allowed for result in results) == 1
    assert {result.reason for result in results} == {"ok", "approval_replay"}
    assert approval.approval_id not in str(events)
    assert approval.approval_ref in str(events)


def test_payload_path_expiry_and_binding_fail_closed(tmp_path):
    now = [100.0]
    service = ApprovalService(store_path=tmp_path / "a.json", clock=lambda: now[0], ttl_seconds=10)
    approval = service.request("s", "t", "a", "tool", {"x": 1}, "/safe")
    service.grant(approval.approval_id)
    assert (
        service.consume(approval.approval_id, "s", "t", "a", "tool", {"x": 2}, "/safe").reason
        == "payload_mismatch"
    )
    assert (
        service.consume(approval.approval_id, "s", "t", "a", "tool", {"x": 1}, "/other").reason
        == "resolved_path_mismatch"
    )
    assert (
        service.consume(approval.approval_id, "other", "t", "a", "tool", {"x": 1}, "/safe").reason
        == "binding_mismatch"
    )
    now[0] = 111.0
    assert service.consume(approval.approval_id, "s", "t", "a", "tool", {"x": 1}, "/safe").reason == "expired"


def test_required_justification_cannot_be_bypassed_through_service_api():
    events = []
    service = ApprovalService(emit=events.append)
    approval = service.request(
        "s",
        "t",
        "a",
        "tool",
        {"x": 1},
        requires_justification=True,
    )
    assert service.grant(approval.approval_id) is None
    assert service.get(approval.approval_id).status == "pending"
    assert events[-1]["watchmyai"]["approval"]["failure"]["reason"] == "justification_required"
    assert service.grant(approval.approval_id, justification="TICKET-123") is not None
