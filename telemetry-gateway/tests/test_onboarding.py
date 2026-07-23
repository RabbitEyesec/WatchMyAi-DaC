from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

import pytest
import yaml
from watchmyai import onboarding
from watchmyai.cli.main import main
from watchmyai.gateway import Gateway, GatewayConfig
from watchmyai.onboarding import FleetClient, OnboardingError, _emit_verification_event


def _write_repository_markers(root: Path) -> None:
    (root / "scripts").mkdir(parents=True)
    (root / "deployment").mkdir()
    (root / ".env.example").touch()
    (root / "scripts/preflight.py").touch()
    (root / "deployment/rules_schema_1.1.0.ndjson").touch()


def test_repository_root_discovers_current_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "WatchMyAI"
    _write_repository_markers(root)
    monkeypatch.delenv("WATCHMYAI_REPOSITORY", raising=False)
    monkeypatch.setattr(onboarding, "__file__", str(tmp_path / "site-packages/watchmyai/onboarding.py"))
    monkeypatch.chdir(root)

    assert onboarding.repository_root() == root.resolve()


def test_repository_root_honors_explicit_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configured = tmp_path / "configured-repository"
    current = tmp_path / "current-repository"
    _write_repository_markers(configured)
    _write_repository_markers(current)
    monkeypatch.setenv("WATCHMYAI_REPOSITORY", str(configured))
    monkeypatch.setattr(onboarding, "__file__", str(tmp_path / "site-packages/watchmyai/onboarding.py"))
    monkeypatch.chdir(current)

    assert onboarding.repository_root() == configured.resolve()


def test_repository_root_outside_repository_fails_safely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.delenv("WATCHMYAI_REPOSITORY", raising=False)
    monkeypatch.setattr(onboarding, "__file__", str(tmp_path / "site-packages/watchmyai/onboarding.py"))
    monkeypatch.chdir(outside)

    with pytest.raises(OnboardingError, match="release repository not found"):
        onboarding.repository_root()


def test_repository_only_public_setup_initializes_generated_development_policy(
    tmp_path: Path,
) -> None:
    home = tmp_path / "runtime-home"

    assert (
        main(
            [
                "--home",
                str(home),
                "setup",
                "--repository-only",
                "--non-interactive",
            ]
        )
        == 0
    )

    config = GatewayConfig.load(home)
    assert config.output_mode == "jsonl"
    assert config.allow_unsigned_policy is True
    assert config.unsigned_policy_bundle.is_file()
    assert main(["--home", str(home), "self-check"]) == 0
    assert main(["--home", str(home), "uninstall", "--yes"]) == 0
    assert home.is_dir()


def test_gateway_reads_direct_export_settings_from_owner_only_file(tmp_path: Path) -> None:
    home = tmp_path / "home"
    config = GatewayConfig(home=home)
    config.save_default()
    environment_file = home / "gateway.env"
    environment_file.write_text(
        "ELASTICSEARCH_URL=https://elastic.example.invalid:9200\n"
        "ELASTIC_AUTH_METHOD=api_key\n"
        "ELASTIC_API_KEY=synthetic-test-key\n",
        "utf-8",
    )
    environment_file.chmod(0o600)
    raw = yaml.safe_load(config.config_path.read_text("utf-8"))
    raw["output"]["mode"] = "elastic"
    raw["output"]["elastic"] = {"environment_file": str(environment_file)}
    config.config_path.write_text(yaml.safe_dump(raw, sort_keys=False), "utf-8")

    gateway = Gateway(GatewayConfig.load(home))

    assert gateway.config.output_mode == "elastic"
    assert gateway.pipeline.sink.headers["Authorization"] == "ApiKey synthetic-test-key"


def test_verification_event_uses_gateway_and_matches_wmai_001(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    home = tmp_path / "verification-home"
    assert (
        main(
            [
                "--home",
                str(home),
                "setup",
                "--repository-only",
                "--non-interactive",
            ]
        )
        == 0
    )

    session_id, started_at = _emit_verification_event(root, home)
    event = yaml.safe_load(GatewayConfig.load(home).jsonl_path.read_text("utf-8"))

    assert event["event"]["action"] == "policy_violation"
    assert event["watchmyai"]["policy"]["violation"]["type"] == ("ai_access_outside_approved_workspace")
    assert event["watchmyai"]["session"]["id"] == session_id
    assert event["watchmyai"]["context"]["rule_id"] == "WMAI-001"
    assert event["@timestamp"].startswith(started_at[:19])


class FakeFleet(FleetClient):
    def __init__(self, responses: dict[tuple[str, str], dict[str, Any]]):
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def request(
        self, path: str, *, method: str = "GET", body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        self.calls.append((method, path, body))
        return self.responses[(method, path)]


def test_fleet_rejects_external_insecure_transport() -> None:
    with pytest.raises(OnboardingError, match="TLS_VERIFY=false"):
        FleetClient(
            {
                "KIBANA_URL": "https://kibana.example.invalid",
                "ELASTIC_AUTH_METHOD": "api_key",
                "ELASTIC_API_KEY": "synthetic-test-key",
                "TLS_VERIFY": "false",
            }
        )


def test_fleet_policy_autodetection_and_safe_endpoint_creation() -> None:
    hostname = socket.gethostname()
    responses = {
        ("GET", "/api/fleet/agent_policies?perPage=100"): {
            "items": [{"id": "policy-1", "name": "Ubuntu endpoints"}]
        },
        ("GET", "/api/fleet/agents?perPage=100&showInactive=false"): {
            "items": [
                {
                    "status": "online",
                    "policy_id": "policy-1",
                    "local_metadata": {"host": {"hostname": hostname}},
                }
            ]
        },
        ("GET", "/api/fleet/package_policies?perPage=100&format=legacy"): {"items": []},
        ("GET", "/api/fleet/epm/packages/endpoint"): {"item": {"version": "9.4.3"}},
        ("POST", "/api/fleet/package_policies"): {"item": {"id": "endpoint-policy-1"}},
    }
    fleet = FakeFleet(responses)

    assert fleet.select_policy("", interactive=False) == "policy-1"
    assert fleet.ensure_endpoint("policy-1") == ("endpoint-policy-1", True)
    create = next(call for call in fleet.calls if call[:2] == ("POST", "/api/fleet/package_policies"))
    assert create[2] is not None
    assert create[2]["policy_ids"] == ["policy-1"]
    endpoint_config = create[2]["inputs"][0]["config"]["_config"]["value"]["endpointConfig"]
    assert endpoint_config == {"preset": "DataCollection"}


def test_fleet_verification_requires_online_agent_and_endpoint() -> None:
    package_path = "/api/fleet/package_policies?perPage=100&format=legacy"
    fleet = FakeFleet(
        {
            ("GET", package_path): {
                "items": [
                    {
                        "policy_ids": ["policy-1"],
                        "package": {"name": "endpoint"},
                    }
                ]
            },
            ("GET", "/api/fleet/agent_policies?perPage=100"): {"items": [{"id": "policy-1", "revision": 3}]},
            ("GET", "/api/fleet/agents?perPage=100&showInactive=false"): {
                "items": [
                    {
                        "status": "online",
                        "policy_id": "policy-1",
                        "policy_revision": 3,
                    }
                ]
            },
        }
    )

    assert "1 online agent" in fleet.verify_policy("policy-1", wait_seconds=0)
