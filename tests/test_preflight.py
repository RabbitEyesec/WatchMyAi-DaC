import importlib.util
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "watchmyai_repository_preflight", ROOT / "scripts" / "preflight.py"
)
assert SPEC is not None and SPEC.loader is not None
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)
CI_HOME = Path("/home") / "runner"


def _scan_single_file(tmp_path: Path, content: str, *, home: Path = CI_HOME) -> str:
    tracked = tmp_path / "README.md"
    tracked.write_text(content, encoding="utf-8")
    with (
        patch.object(preflight, "ROOT", tmp_path),
        patch.object(preflight, "_tracked_files", return_value=[tracked]),
        patch.object(preflight.Path, "home", return_value=home),
    ):
        return preflight.check_machine_specific_and_secrets()


def test_machine_hygiene_allows_generic_runner_word(tmp_path: Path) -> None:
    result = _scan_single_file(tmp_path, "The runner supports isolated lab jobs.")

    assert result.startswith("1 release paths contain no recognized credentials")


def test_machine_hygiene_rejects_full_home_path(tmp_path: Path) -> None:
    expected = re.escape(f"local machine value {str(CI_HOME)!r}")
    with pytest.raises(RuntimeError, match=expected):
        _scan_single_file(tmp_path, f"Captured from {CI_HOME}/private/session.jsonl")


def test_machine_hygiene_is_segment_aware_for_root_home(tmp_path: Path) -> None:
    result = _scan_single_file(
        tmp_path,
        "Fixtures live under /workspace/repository/root/cases and /rooted/names.",
        home=Path("/root"),
    )

    assert result.startswith("1 release paths contain no recognized credentials")


def test_machine_hygiene_rejects_actual_root_home_path(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="local machine value '/root'"):
        _scan_single_file(
            tmp_path,
            "Captured from /root/private/session.jsonl",
            home=Path("/root"),
        )


def test_remote_asset_comparison_allows_only_server_metadata() -> None:
    expected = {"template": {"settings": {"index.default_pipeline": "watchmyai-events"}}}
    actual = {
        "template": {"settings": {"index.default_pipeline": "watchmyai-events"}},
        "version": 3,
    }
    preflight._assert_contains(actual, expected, "index template")
    actual["template"]["settings"]["index.default_pipeline"] = "stale-pipeline"
    with pytest.raises(RuntimeError, match="reviewed repository definition"):
        preflight._assert_contains(actual, expected, "index template")


def test_supported_elastic_version_is_exact() -> None:
    assert preflight._service_version({"version": {"number": "9.4.3"}}, "Elasticsearch") == "9.4.3"
    with pytest.raises(RuntimeError, match="unsupported"):
        preflight._service_version({"version": "9.4.2"}, "Fleet Server")


def test_fleet_agent_version_comes_from_reported_local_metadata() -> None:
    agent = {
        "id": "agent-1",
        "local_metadata": {"elastic": {"agent": {"version": "9.4.3"}}},
    }
    assert preflight._agent_reported_version(agent) == "9.4.3"
    with pytest.raises(RuntimeError, match="did not report"):
        preflight._agent_reported_version({"id": "agent-2"})


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"state": 2}, True),
        ({"state": 3}, False),
        ({"status": "HEALTHY"}, True),
        ({"status": "offline"}, False),
    ],
)
def test_elastic_agent_health_accepts_documented_json_state(
    payload: dict[str, object], expected: bool
) -> None:
    assert preflight._elastic_agent_is_healthy(payload) is expected
