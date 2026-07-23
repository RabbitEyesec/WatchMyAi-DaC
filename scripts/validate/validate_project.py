#!/usr/bin/env python3
"""Validate WatchMyAI's repository-wide identity and configuration contract."""

from __future__ import annotations

import json
import re
import sys
import tomllib
import urllib.parse
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from utilities.build_source_archive import release_files  # noqa: E402

SEMVER_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
COMPONENT_CONFIGURATION = (
    "detection-rules/pyproject.toml",
    "telemetry-gateway/pyproject.toml",
    "detection-rules/VERSION",
    "telemetry-gateway/VERSION",
    "detection-rules/LICENSE",
    "telemetry-gateway/LICENSE",
    "pytest.ini",
)
DEPLOYMENT_DOCUMENTATION = (
    "deployment/README.md",
    "detection-rules/deployment/README.md",
    "telemetry-gateway/deployment/elastic/README.md",
)


def _require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def _validate_links(errors: list[str]) -> None:
    for document in release_files(ROOT):
        if document.suffix.casefold() != ".md":
            continue
        relative = document.relative_to(ROOT)
        text = document.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"(?<!!)\[[^\]]*\]\(([^)]+)\)", text):
            destination = match.group(1).strip().split()[0].strip("<>")
            if not destination or destination.startswith(("#", "http://", "https://", "mailto:")):
                continue
            target = urllib.parse.unquote(destination.split("#", 1)[0])
            line = text.count("\n", 0, match.start()) + 1
            _require(
                errors,
                (document.parent / target).resolve().exists(),
                f"broken documentation link {relative}:{line}: {destination}",
            )


def _active_identity_files() -> list[Path]:
    excluded_files = {
        "CHANGELOG.md",
        "detection-rules/CHANGELOG.md",
        "scripts/validate/validate_project.py",
        "telemetry-gateway/CHANGELOG.md",
    }
    excluded_parts = {
        ".git",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "production docs",
        "research",
        "runtime",
    }
    suffixes = {".json", ".md", ".ps1", ".py", ".sh", ".toml", ".yaml", ".yml"}
    return [
        path
        for path in release_files(ROOT)
        if path.relative_to(ROOT).as_posix() not in excluded_files
        and not set(path.relative_to(ROOT).parts) & excluded_parts
        and (path.suffix.casefold() in suffixes or path.name == "LICENSE")
    ]


def validate() -> list[str]:
    errors: list[str] = []
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    _require(errors, bool(SEMVER_RE.fullmatch(version)), f"VERSION is not SemVer: {version!r}")

    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = config.get("project", {})
    _require(errors, project.get("name") == "WatchMyAI", "project name must be WatchMyAI")
    _require(
        errors,
        project.get("requires-python") == ">=3.11,<3.13",
        "Python range must be >=3.11,<3.13",
    )
    _require(errors, project.get("license") == "Apache-2.0", "licence must be Apache-2.0")
    _require(
        errors,
        project.get("authors") == [{"name": "RabbitEyeSec"}],
        "project author organisation must be RabbitEyeSec",
    )
    _require(
        errors,
        project.get("maintainers") == [{"name": "WatchMyAI contributors"}],
        "project maintainer identity must be WatchMyAI contributors",
    )
    _require(errors, project.get("dynamic") == ["version"], "project version must be dynamic")
    dynamic_version = config.get("tool", {}).get("setuptools", {}).get("dynamic", {}).get("version")
    _require(
        errors,
        dynamic_version == {"attr": "watchmyai.__version__"},
        "package version must resolve through watchmyai.__version__",
    )

    tools = config.get("tool", {})
    ruff = tools.get("ruff", {})
    _require(errors, ruff.get("line-length") == 110, "Ruff line length must be 110")
    _require(errors, ruff.get("target-version") == "py311", "Ruff target must be py311")
    _require(
        errors,
        set(ruff.get("lint", {}).get("select", [])) == {"E", "F", "W", "I", "B", "UP"},
        "Ruff lint selection drifted",
    )
    _require(
        errors,
        tools.get("mypy", {}).get("python_version") == "3.11",
        "mypy Python version must be 3.11",
    )
    _require(
        errors,
        tools.get("pytest", {}).get("ini_options", {}).get("testpaths")
        == ["tests", "telemetry-gateway/tests", "detection-rules/tests"],
        "pytest must cover both components and repository tests",
    )

    for relative in COMPONENT_CONFIGURATION:
        _require(errors, not (ROOT / relative).exists(), f"competing configuration exists: {relative}")

    manifest = yaml.safe_load((ROOT / "detection-rules/detections/manifest.yml").read_text(encoding="utf-8"))
    _require(errors, manifest.get("pack_version") == version, "rule manifest version drifted")
    _require(
        errors,
        manifest.get("validation_scope") == f"production-validated-v{version}",
        "rule manifest validation scope drifted",
    )
    scenarios = json.loads((ROOT / "scenarios/definitions/supported-rules.json").read_text(encoding="utf-8"))
    _require(errors, scenarios.get("version") == version, "scenario version drifted")

    version_surfaces = {
        ".env.example": f"WatchMyAI v{version}",
        "README.md": f"Release v{version}",
        "detection-rules/README.md": f"WatchMyAI detection rules {version}",
        "docs/ARCHITECTURE.md": f"Runtime and package: {version}",
        "docs/INSTALLATION.md": f"v{version} live onboarding contract",
        "requirements-release.lock": f"WatchMyAI v{version}",
        "telemetry-gateway/src/watchmyai/schema/watchmyai_event.schema.json": (
            f"WatchMyAI {version} Elastic laboratory deployment"
        ),
    }
    for relative, marker in version_surfaces.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        _require(errors, marker in text, f"documented version drifted in {relative}")

    for relative in ("release/excluded-rules.json", "release/technical-readiness.json"):
        payload = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        _require(errors, payload.get("release") == f"v{version}", f"release version drifted in {relative}")

    for path in _active_identity_files():
        relative = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8", errors="replace")
        for invalid in ("RabbitEyesec", "RabbitEyeSEC", "WatchMyAI Contributors"):
            _require(errors, invalid not in text, f"inconsistent identity {invalid!r} in {relative}")

    _require(
        errors,
        "Copyright 2026 Abhinav Kadam (RabbitEyeSec)" in (ROOT / "LICENSE").read_text("utf-8"),
        "root licence ownership notice drifted",
    )
    for relative in ("detection-rules/README.md", "telemetry-gateway/README.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        _require(errors, "../QUICKSTART.md" in text, f"{relative} must link to QUICKSTART.md")

    for relative in DEPLOYMENT_DOCUMENTATION:
        path = ROOT / relative
        _require(errors, path.is_file(), f"missing deployment documentation: {relative}")
        if path.is_file():
            text = path.read_text(encoding="utf-8").casefold()
            for term in ("owns", "workflow", "generated", "manually"):
                _require(errors, term in text, f"{relative} does not explain {term!r} responsibility")

    workflow_dir = ROOT / ".github/workflows"
    _require(
        errors,
        (workflow_dir / "watchmyai-ci.yml").is_file(),
        "the unified WatchMyAI CI workflow is missing",
    )
    for obsolete in ("detection-rules-ci.yml", "telemetry-gateway-ci.yml", "release-candidate-ci.yml"):
        _require(errors, not (workflow_dir / obsolete).exists(), f"obsolete component CI remains: {obsolete}")
    active_automation = [
        *(workflow_dir.glob("*.yml")),
        ROOT / "scripts/install/install.sh",
        ROOT / "scripts/install/install.ps1",
        ROOT / "scripts/preflight.py",
        ROOT / "detection-rules/scripts/package_rules.py",
    ]
    for path in active_automation:
        text = path.read_text(encoding="utf-8")
        for obsolete in ("detection-rules/pyproject.toml", "telemetry-gateway/pyproject.toml"):
            _require(errors, obsolete not in text, f"obsolete configuration reference in {path}: {obsolete}")

    sys.path.insert(0, str(ROOT / "telemetry-gateway/src"))
    from watchmyai import __version__

    _require(errors, __version__ == version, "runtime package version differs from VERSION")
    _validate_links(errors)
    return errors


def main() -> int:
    errors = validate()
    if errors:
        print(f"FAIL: {len(errors)} project consistency error(s)")
        for error in errors:
            print(f"- {error}")
        return 1
    print("PASS: one WatchMyAI identity, version, configuration, workflow, and documentation contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
