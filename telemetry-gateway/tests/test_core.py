from __future__ import annotations

from pathlib import Path

import pytest
from watchmyai.capability.service import CapabilityRegistry
from watchmyai.classifiers.command import classify_command
from watchmyai.classifiers.path import classify_paths, resolve_paths
from watchmyai.classifiers.resource import repository_approved
from watchmyai.core.models import AdapterCapability, DecisionEffect, ToolRequest
from watchmyai.policy.evaluator import PolicyDecisionPoint
from watchmyai.policy.model import PolicyBundle


def capability(adapter_id: str = "test") -> AdapterCapability:
    return AdapterCapability(
        adapter_id=adapter_id,
        adapter_version="1",
        supports_pre_execution=True,
        supports_post_execution=True,
        supports_blocking=True,
        supports_approval=True,
        supports_argument_redaction=True,
        supports_result_redaction=True,
        mediated_tool_classes=frozenset({"*"}),
    )


def request(tmp_path: Path, **overrides) -> ToolRequest:
    values = {
        "adapter_id": "test",
        "agent_id": "agent",
        "session_id": "session",
        "task_id": "task",
        "tool_name": "read",
        "tool_class": "file_read",
        "operation": "read",
        "arguments": {},
        "cwd": str(tmp_path),
        "requested_paths": ["ok.txt"],
        "resolved_paths": [str(tmp_path / "ok.txt")],
        "attributes": {"path_outside_approved_workspace": False, "path_restricted": False},
    }
    values.update(overrides)
    return ToolRequest(**values)


def test_deny_first_conflict_resolution(bundle_dict, tmp_path):
    bundle_dict["policies"].append(
        {
            "policy_id": "allow-restricted",
            "policy_version": "1",
            "priority": 9999,
            "effect": "ALLOW",
            "match": {"path_restricted": True},
        }
    )
    registry = CapabilityRegistry()
    registry.register(capability())
    req = request(tmp_path, attributes={"path_restricted": True, "path_outside_approved_workspace": False})
    result = PolicyDecisionPoint(PolicyBundle.from_dict(bundle_dict), registry).evaluate(req)
    assert result.effect == DecisionEffect.DENY
    assert result.evidence.winning_policy_id == "deny-restricted"
    assert {item["policy_id"] for item in result.evidence.match_evidence} >= {
        "deny-restricted",
        "allow-restricted",
    }


def test_strict_unmatched_is_default_deny(bundle_dict, tmp_path):
    registry = CapabilityRegistry()
    registry.register(capability())
    result = PolicyDecisionPoint(PolicyBundle.from_dict(bundle_dict), registry).evaluate(
        request(tmp_path, tool_class="unknown")
    )
    assert result.effect == DecisionEffect.DENY
    assert "STRICT_DEFAULT_DENY" in result.evidence.reason_codes


def test_unknown_obligation_and_non_deny_strict_default_rejected(bundle_dict):
    bundle_dict["policies"][0]["obligations"] = ["MADE_UP"]
    with pytest.raises(ValueError, match="unknown obligations"):
        PolicyBundle.from_dict(bundle_dict)
    bundle_dict["policies"][0]["obligations"] = []
    bundle_dict["default_effect"] = "ALLOW"
    with pytest.raises(ValueError, match="default-deny"):
        PolicyBundle.from_dict(bundle_dict)


def test_missing_mandatory_capability_refuses(bundle_dict, tmp_path):
    registry = CapabilityRegistry()
    registry.register(
        AdapterCapability(
            adapter_id="test",
            adapter_version="1",
            supports_pre_execution=True,
            supports_blocking=True,
            mediated_tool_classes=frozenset({"*"}),
        )
    )
    result = PolicyDecisionPoint(PolicyBundle.from_dict(bundle_dict), registry).evaluate(request(tmp_path))
    assert result.effect == DecisionEffect.DENY
    assert "OBLIGATION_UNAVAILABLE" in result.evidence.reason_codes


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("sudo id", "privilege_escalation"),
        ("doas id", "privilege_escalation"),
        ("pkexec id", "privilege_escalation"),
        ("rm -rf ./build", "recursive_delete"),
        ("find . -delete", "recursive_delete"),
        ("pwsh -c 'Remove-Item x -Recurse'", "recursive_delete"),
        ("ssh user@example", "ssh_session"),
        ("printenv", "environment_harvest"),
        ("aws configure", "cloud_credential"),
        ("docker run alpine", "container"),
        ("kubectl delete pod x", "kubernetes"),
        ("echo ok; sudo id", "privilege_escalation"),
        ("runas /user:Administrator cmd.exe", "privilege_escalation"),
        ('powershell -Command "Start-Process cmd -Verb RunAs"', "privilege_escalation"),
        ('bash -c "rm -rf ./build"', "recursive_delete"),
        ("/usr/bin/ssh host.example", "ssh_session"),
        ("command git push origin main", "git"),
        ('pwsh -Command "Get-ChildItem Env:"', "environment_harvest"),
        ("/usr/local/bin/aws configure", "cloud_credential"),
        ("docker compose up", "container"),
        ("/opt/bin/kubectl get pods", "kubernetes"),
    ],
)
def test_command_classifier_variants(command, expected):
    assert classify_command(command).command_class == expected


def test_path_resolution_is_segment_aware(tmp_path):
    approved = tmp_path / "work"
    sibling = tmp_path / "workspace-escape"
    resolved = resolve_paths([str(approved / "a"), str(sibling / "b")], str(tmp_path))
    classes = classify_paths(["a", "b"], resolved, [str(approved)], [])
    assert classes[0].approved_workspace
    assert not classes[1].approved_workspace


@pytest.mark.parametrize("name", ["authorized_keys", "shadow", "sudoers", "SUDOERS"])
def test_restricted_resource_token_matching(tmp_path, name):
    resolved = resolve_paths([name], str(tmp_path))
    classified = classify_paths([name], resolved, [str(tmp_path)], [])
    assert classified[0].restricted


def test_repository_identity_normalizes_ssh_https_and_dot_git():
    allowed = ["github.com/example/*"]
    assert repository_approved("git@github.com:example/project.git", allowed)
    assert repository_approved("https://github.com/example/project.git", allowed)
    assert not repository_approved("https://github.com/other/project.git", allowed)
