from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def bundle_dict(tmp_path: Path) -> dict[str, Any]:
    return {
        "schema_version": "1.2",
        "policy_bundle_id": "polb-test",
        "policy_bundle_version": "1.0.0",
        "policy_sequence": 1,
        "organization_id": "org-test",
        "mode": "strict",
        "default_effect": "DENY",
        "required_capabilities": [],
        "metadata": {
            "approved_workspace_roots": [str(tmp_path)],
            "restricted_paths": [str(tmp_path / "restricted")],
            "allowed_destinations": ["example.com"],
            "allowed_repositories": ["repo-approved"],
            "allowed_mcp_servers": ["mcp-approved"],
        },
        "policies": [
            {
                "policy_id": "deny-restricted",
                "policy_version": "1",
                "priority": 100,
                "effect": "DENY",
                "match": {"path_restricted": True},
                "reason_code": "RESTRICTED_PATH",
                "obligations": ["AUDIT_METADATA_ONLY", "CAPTURE_ARGUMENT_HASH"],
            },
            {
                "policy_id": "deny-recursive-delete",
                "policy_version": "1",
                "priority": 100,
                "effect": "DENY",
                "match": {"command_class": "recursive_delete"},
                "reason_code": "RECURSIVE_DELETE",
                "obligations": ["AUDIT_METADATA_ONLY", "CAPTURE_ARGUMENT_HASH"],
            },
            {
                "policy_id": "shell-approval",
                "policy_version": "1",
                "priority": 50,
                "effect": "REQUIRE_APPROVAL",
                "match": {"tool_class": "shell"},
                "reason_code": "SHELL_APPROVAL",
                "obligations": ["AUDIT_METADATA_ONLY", "REQUIRE_APPROVAL_RECEIPT"],
            },
            {
                "policy_id": "allow-files",
                "policy_version": "1",
                "priority": 10,
                "effect": "ALLOW",
                "match": {
                    "tool_class": ["file_read", "file_write"],
                    "path_outside_approved_workspace": False,
                },
                "reason_code": "FILE_ALLOWED",
                "obligations": ["AUDIT_METADATA_ONLY", "CAPTURE_ARGUMENT_HASH", "REQUIRE_EXECUTION_RECEIPT"],
            },
            {
                "policy_id": "allow-local",
                "policy_version": "1",
                "priority": 1,
                "effect": "ALLOW",
                "match": {"tool_class": "local_function"},
                "reason_code": "LOCAL_ALLOWED",
                "obligations": ["AUDIT_METADATA_ONLY"],
            },
        ],
    }


@pytest.fixture
def policy_file(tmp_path: Path, bundle_dict: dict[str, Any]) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(bundle_dict), "utf-8")
    return path
