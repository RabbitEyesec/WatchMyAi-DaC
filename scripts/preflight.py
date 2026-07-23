#!/usr/bin/env python3
"""Fail-closed WatchMyAI repository and isolated-lab readiness preflight."""

from __future__ import annotations

import argparse
import base64
import email.utils
import hashlib
import importlib
import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

import yaml
from packaging.markers import Marker

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "telemetry-gateway"
RULES = ROOT / "detection-rules"
sys.path.insert(0, str(ROOT / "scripts"))
from utilities.release_contract import (  # noqa: E402
    DEFERRED_IDS,
    NATIVE_FILE_INDEX_PATTERNS,
    PROJECT_VERSION,
    SUPPORTED_COUNT,
    SUPPORTED_ELASTIC_VERSION,
    SUPPORTED_IDS,
    load_dotenv,
    parse_bool,
    resolve_repository_path,
    sanitize_target,
    validate_technical_readiness,
    validate_url,
)

SELECTED_IDS = set(SUPPORTED_IDS)
DEFERRED_IDS_SET = set(DEFERRED_IDS)
TEXT_SUFFIXES = {
    ".cfg",
    ".ini",
    ".json",
    ".jsonl",
    ".lock",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "OpenAI-style key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "credentialed URL": re.compile(r"https?://[^\s/@:]+:[^\s/@]+@"),
}


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    detail: str
    duration_ms: int


class Preflight:
    def __init__(self) -> None:
        self.results: list[CheckResult] = []

    def run(self, name: str, check: Callable[[], str]) -> None:
        started = time.monotonic()
        try:
            detail = check()
            status = "PASS"
        except Exception as exc:  # every failed readiness assertion is reported, never hidden
            detail = str(exc)
            status = "FAIL"
        elapsed = round((time.monotonic() - started) * 1000)
        self.results.append(CheckResult(name, status, detail, elapsed))

    def skip(self, name: str, detail: str) -> None:
        self.results.append(CheckResult(name, "SKIP", detail, 0))

    def warn(self, name: str, detail: str) -> None:
        self.results.append(CheckResult(name, "WARN", detail, 0))

    def fix(self, name: str, detail: str) -> None:
        self.results.append(CheckResult(name, "FIX", detail, 0))

    @property
    def failed(self) -> bool:
        return any(result.status == "FAIL" for result in self.results)


def _run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    timeout: int = 180,
    env: dict[str, str] | None = None,
) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        output = (completed.stdout + completed.stderr).strip()
        raise RuntimeError(f"{' '.join(command)} exited {completed.returncode}: {output[-2000:]}")
    return completed.stdout.strip()


def _tracked_files() -> list[Path]:
    from utilities.build_source_archive import release_files

    return release_files(ROOT)


def check_runtime() -> str:
    if not ((3, 11) <= sys.version_info[:2] < (3, 13)):
        raise RuntimeError(f"Python 3.11 or 3.12 required; found {sys.version.split()[0]}")
    if shutil.which("git") is None:
        raise RuntimeError("git is not installed")
    return f"Python {sys.version.split()[0]}; {_run(['git', '--version'])}"


def check_host_capacity() -> str:
    import psutil

    system = platform.system().lower()
    if system not in {"linux", "windows", "darwin"}:
        raise RuntimeError(f"unsupported operating system: {platform.system()}")
    architecture = platform.machine().lower()
    if architecture not in {"x86_64", "amd64", "arm64", "aarch64"}:
        raise RuntimeError(f"unsupported architecture: {platform.machine()}")
    free_gib = shutil.disk_usage(ROOT).free / (1024**3)
    memory_gib = psutil.virtual_memory().total / (1024**3)
    if free_gib < 2:
        raise RuntimeError(f"insufficient free disk: {free_gib:.1f} GiB; require at least 2 GiB")
    if memory_gib < 2:
        raise RuntimeError(f"insufficient memory: {memory_gib:.1f} GiB; require at least 2 GiB")
    return (
        f"{platform.system()} {platform.machine()}; {free_gib:.1f} GiB free disk; {memory_gib:.1f} GiB memory"
    )


def check_dependencies() -> str:
    modules = (
        "yaml",
        "jsonschema",
        "cryptography",
        "psutil",
        "pytest",
        "setuptools",
        "wheel",
    )
    missing = []
    for module in modules:
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)
    if missing:
        raise RuntimeError(f"missing declared validation dependencies: {', '.join(missing)}")
    lock = ROOT / "requirements-release.lock"
    pinned: dict[str, str] = {}
    for raw in lock.read_text("utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^ ;\\]+)(?:\s*;\s*(.*?))?\s*\\?$", raw)
        if not match:
            continue
        name, expected, marker = match.groups()
        if marker and not Marker(marker).evaluate():
            continue
        pinned[name] = expected
    mismatches: list[str] = []
    for name, expected in pinned.items():
        try:
            actual = metadata.version(name)
        except metadata.PackageNotFoundError:
            mismatches.append(f"{name} is missing")
            continue
        if actual != expected:
            mismatches.append(f"{name} expected {expected}, found {actual}")
    if mismatches:
        raise RuntimeError("release lock mismatch: " + "; ".join(mismatches))
    return (
        f"{len(modules)} required modules import; {len(pinned)} distributions match requirements-release.lock"
    )


def check_project_contract() -> str:
    return _run([sys.executable, "scripts/validate/validate_project.py"])


def check_repository_clean() -> str:
    if not (ROOT / ".git").exists():
        return "source export has no Git metadata; generated/cache paths are excluded from inventory"
    status = _run(["git", "status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        raise RuntimeError("repository has tracked/untracked changes:\n" + status[:2000])
    return "Git worktree is clean"


def check_machine_specific_and_secrets() -> str:
    findings: list[str] = []
    local_values = {str(ROOT), str(Path.home())}
    local_values.discard("")
    for path in _tracked_files():
        if (
            path.suffix.lower() not in TEXT_SUFFIXES and not path.name.startswith(".env")
        ) or not path.is_file():
            continue
        text = path.read_text("utf-8", errors="replace")
        relative = path.relative_to(ROOT)
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{relative}: possible {label}")
        for value in local_values:
            # Match an exact absolute path prefix at token boundaries. A plain
            # substring check made root's /root home collide with fixture and
            # repository names containing that segment.
            normalized_value = value.rstrip("/\\")
            boundary_pattern = re.compile(
                rf"(?<![A-Za-z0-9_.-]){re.escape(normalized_value)}"
                rf"(?=$|[/\\\s\"'`),;:\]}}])"
            )
            if boundary_pattern.search(text):
                findings.append(f"{relative}: local machine value {value!r}")
    if findings:
        raise RuntimeError("; ".join(findings[:20]))
    return f"{len(_tracked_files())} release paths contain no recognized credentials or local checkout values"


def check_runtime_assets() -> str:
    assets = {
        "component template": GATEWAY / "deployment/elastic/component_template.json",
        "index template": GATEWAY / "deployment/elastic/index_template.json",
        "ingest pipeline": GATEWAY / "deployment/elastic/ingest_pipeline.json",
        "ILM policy": GATEWAY / "deployment/elastic/ilm_policy.json",
    }
    for label, path in assets.items():
        try:
            json.loads(path.read_text("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"invalid {label} {path.relative_to(ROOT)}: {exc}") from exc
    index = json.loads(assets["index template"].read_text("utf-8"))
    settings = index.get("template", {}).get("settings", {})
    if settings.get("index.default_pipeline") != "watchmyai-events":
        raise RuntimeError("index template does not bind the watchmyai-events ingest pipeline")
    if index.get("composed_of") != ["watchmyai-events-mappings"]:
        raise RuntimeError("index template does not bind the strict WatchMyAI component mapping")
    saved_objects = GATEWAY / "deployment/elastic/kibana.ndjson"
    saved_object_types: set[str] = set()
    for line in saved_objects.read_text("utf-8").splitlines():
        if line.strip():
            item = json.loads(line)
            saved_object_types.add(str(item.get("type", "")))
    if "dashboard" in saved_object_types:
        raise RuntimeError("the mandatory Kibana bundle must not contain a dashboard")
    if not saved_object_types <= {"index-pattern", "search"}:
        raise RuntimeError("the optional Kibana bundle contains an unsupported saved-object type")
    return (
        "component/index templates, ingest pipeline, ILM, and optional Kibana searches "
        "parse and cross-link for direct gateway export; no dashboard is required"
    )


def check_rule_pack() -> str:
    manifest = yaml.safe_load((RULES / "detections/manifest.yml").read_text("utf-8"))
    if (
        set(manifest.get("selected_rule_ids", [])) != SELECTED_IDS
        or manifest.get("rule_count") != SUPPORTED_COUNT
    ):
        raise RuntimeError(f"manifest is not the exact supported {SUPPORTED_COUNT}-rule set")
    metadata_paths = sorted((RULES / "detections/metadata").glob("WMAI-*.yml"))
    elastic_paths = sorted((RULES / "detections/elastic").glob("WMAI-*.json"))
    if {path.stem for path in metadata_paths} != SELECTED_IDS:
        raise RuntimeError("production metadata IDs differ from the approved set")
    if {path.stem for path in elastic_paths} != SELECTED_IDS:
        raise RuntimeError("Elastic rule IDs differ from the approved set")
    enabled = [path.stem for path in elastic_paths if json.loads(path.read_text("utf-8")).get("enabled")]
    if enabled:
        raise RuntimeError(f"production rules are enabled: {', '.join(enabled)}")
    source = ROOT / "deployment/rules_schema_1.1.0.ndjson"
    authoritative = [json.loads(line) for line in source.read_text("utf-8").splitlines()]
    if [item.get("rule_id") for item in authoritative] != list(SUPPORTED_IDS):
        raise RuntimeError("authoritative schema 1.1.0 NDJSON has the wrong rule set")
    for item in authoritative:
        generated = json.loads((RULES / "detections/elastic" / f"{item['rule_id']}.json").read_text("utf-8"))
        if generated != item:
            raise RuntimeError(f"{item['rule_id']} differs from authoritative schema 1.1.0 NDJSON")
    for group in ("metadata", "elastic", "fixtures/benign", "fixtures/malicious"):
        paths = (RULES / "research/deferred-catalog" / group).glob("WMAI-*.*")
        if {path.stem for path in paths} != DEFERRED_IDS_SET:
            raise RuntimeError(f"deferred catalog {group} does not contain the exact 45-rule set")
    return f"{SUPPORTED_COUNT} authoritative disabled rules; excluded IDs absent; research catalog isolated"


def check_fixture_safety() -> str:
    atomics = sorted((RULES / "tests/corpus/atomic").glob("WMAI-*.json"))
    if {path.stem for path in atomics} != SELECTED_IDS:
        raise RuntimeError("atomic corpus is not the exact approved rule set")
    for path in atomics:
        atomic = json.loads(path.read_text("utf-8"))
        safety = str(atomic.get("safety", "")).lower()
        if atomic.get("execution") != "real_adapter_required" or "isolated_lab_only" not in safety:
            raise RuntimeError(f"{path.stem} lacks real-adapter/isolation safety guards")
    return f"{SUPPORTED_COUNT} atomics require the real adapter path and isolated disposable resources"


def check_signed_test_policy(release_dir: Path) -> str:
    required = {
        "root.json",
        "timestamp.json",
        "snapshot.json",
        "targets.json",
        "policy.json",
    }
    missing = sorted(name for name in required if not (release_dir / name).is_file())
    if missing:
        raise RuntimeError(f"signed test release is incomplete: {', '.join(missing)}")
    source_path = str(ROOT / "src")
    if source_path not in sys.path:
        sys.path.insert(0, source_path)
    from watchmyai.distribution.client import DistributionClient
    from watchmyai.distribution.metadata import RoleVerifier

    root = (release_dir / "root.json").read_bytes()
    organization = json.loads(root).get("signed", {}).get("organization_id")
    if not organization:
        raise RuntimeError("signed test root lacks organization_id")
    verifier = RoleVerifier.enroll(root, organization)
    with tempfile.TemporaryDirectory(prefix="watchmyai-preflight-policy-") as temporary:
        client = DistributionClient(
            Path(temporary), verifier, endpoint_id="preflight", agent_version=PROJECT_VERSION
        )
        result = client.verify_and_activate(
            timestamp_bytes=(release_dir / "timestamp.json").read_bytes(),
            snapshot_bytes=(release_dir / "snapshot.json").read_bytes(),
            targets_bytes=(release_dir / "targets.json").read_bytes(),
            target_name="policy.json",
            target_bytes=(release_dir / "policy.json").read_bytes(),
            now=datetime.now(UTC),
            capability_validator=lambda _bundle, _required: (True, []),
        )
    return f"verified signed synthetic policy {result.policy_bundle_id}@{result.policy_bundle_version}"


def check_evidence_directory(path: Path) -> str:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=".preflight-", dir=path) as probe:
        probe.write(b"watchmyai")
        probe.flush()
        os.fsync(probe.fileno())
    return f"writable evidence directory {path}"


def check_package_buildability() -> str:
    with tempfile.TemporaryDirectory(prefix="watchmyai-preflight-build-") as temporary:
        output = Path(temporary)
        source = output / "source"
        repository_source = source / "repository"
        for source_path in _tracked_files():
            destination = repository_source / source_path.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)
        build_environment = dict(os.environ)
        source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
        if not source_date_epoch and (ROOT / ".git").exists():
            commit_time = subprocess.run(
                ["git", "log", "-1", "--format=%ct"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            if commit_time.returncode == 0:
                source_date_epoch = commit_time.stdout.strip()
        build_environment["SOURCE_DATE_EPOCH"] = source_date_epoch or "946684800"
        for label in ("first", "second"):
            _run(
                [
                    sys.executable,
                    "scripts/utilities/build_release.py",
                    "--output-dir",
                    str(output / label),
                ],
                cwd=repository_source,
                env=build_environment,
            )
        first = output / "first"
        second = output / "second"
        first_artifacts = {
            path.relative_to(first): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in first.rglob("*")
            if path.is_file()
        }
        second_artifacts = {
            path.relative_to(second): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in second.rglob("*")
            if path.is_file()
        }
        if first_artifacts != second_artifacts:
            drift = sorted(
                str(path)
                for path in set(first_artifacts) | set(second_artifacts)
                if first_artifacts.get(path) != second_artifacts.get(path)
            )
            raise RuntimeError(f"release artifact hashes are not reproducible: {', '.join(drift)}")
        wheel = next(first.glob("*.whl"), None)
        source_archive = next(first.glob("WatchMyAI-v*-source.zip"), None)
        if wheel is None or source_archive is None:
            raise RuntimeError("WatchMyAI wheel or deterministic source archive was not produced")
        smoke_site = output / "wheel-site"
        _run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--target",
                str(smoke_site),
                str(wheel),
            ],
            cwd=output,
        )
        smoke_home = output / "wheel-home"
        environment = dict(os.environ)
        environment["WATCHMYAI_ALLOW_UNSIGNED_POLICY"] = "1"
        environment["PYTHONPATH"] = str(smoke_site)
        location = subprocess.run(
            [sys.executable, "-c", "import watchmyai; print(watchmyai.__file__)"],
            cwd=output,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if location.returncode or not Path(location.stdout.strip()).is_relative_to(smoke_site):
            raise RuntimeError("wheel smoke test imported WatchMyAI from outside the wheel target")
        for action in ("init", "self-check"):
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "watchmyai.cli.main",
                    "--home",
                    str(smoke_home),
                    action,
                ],
                cwd=output,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if completed.returncode:
                raise RuntimeError(
                    f"installed wheel {action} failed: {(completed.stdout + completed.stderr)[-2000:]}"
                )
    return (
        f"wheel, sdist, source archive, and {SUPPORTED_COUNT}-rule artifacts are byte-reproducible; "
        "installed gateway wheel initializes and validates without the source tree"
    )


def check_runtime_self_validation() -> str:
    with tempfile.TemporaryDirectory(prefix="watchmyai-preflight-runtime-") as temporary:
        home = Path(temporary) / "home"
        command = [sys.executable, "-m", "watchmyai.cli.main", "--home", str(home)]
        environment = dict(os.environ)
        environment["WATCHMYAI_ALLOW_UNSIGNED_POLICY"] = "1"
        source_path = str(ROOT / "src")
        environment["PYTHONPATH"] = source_path + os.pathsep + environment.get("PYTHONPATH", "")
        for action in ("init", "self-check"):
            completed = subprocess.run(
                [*command, action],
                cwd=GATEWAY,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if completed.returncode:
                raise RuntimeError(
                    f"runtime {action} failed: {(completed.stdout + completed.stderr)[-2000:]}"
                )
    return "fresh runtime home initializes and self-validates from packaged resources"


def check_technical_readiness_state(*, repository_checks_failed: bool) -> str:
    path = ROOT / "release/technical-readiness.json"
    try:
        payload = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid technical readiness declaration: {exc}") from exc
    errors = validate_technical_readiness(payload, repository_preflight_failed=repository_checks_failed)
    if errors:
        raise RuntimeError("; ".join(errors))
    blockers = payload["repository_controlled_blockers"]
    return f"technical readiness declaration is consistent; {len(blockers)} repository-controlled blocker(s)"


def check_central_configuration(path: Path, *, template: bool) -> str:
    command = [
        sys.executable,
        str(ROOT / "scripts/validate/validate_config.py"),
        "--config",
        str(path),
    ]
    if template:
        command.append("--template")
    return _run(command)


def _auth_headers(*, kibana: bool = False) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    method = os.environ.get("ELASTIC_AUTH_METHOD", "api_key")
    if method == "api_key":
        api_key = os.environ.get("ELASTIC_API_KEY", "")
        key_file = os.environ.get("ELASTIC_API_KEY_FILE", "")
        if not api_key and key_file:
            api_key = resolve_repository_path(key_file).read_text("utf-8").strip()
        if not api_key:
            raise RuntimeError("ELASTIC_API_KEY or ELASTIC_API_KEY_FILE is required")
        headers["Authorization"] = f"ApiKey {api_key}"
    elif method == "basic":
        username = os.environ.get("ELASTIC_USERNAME", "")
        password = os.environ.get("ELASTIC_PASSWORD", "")
        if not username or not password:
            raise RuntimeError("ELASTIC_USERNAME and ELASTIC_PASSWORD are required")
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    else:
        raise RuntimeError(f"unsupported ELASTIC_AUTH_METHOD {method!r}")
    if kibana:
        headers["kbn-xsrf"] = "preflight"
    return headers


def _json_request(
    url: str,
    *,
    kibana: bool = False,
    method: str = "GET",
    body: Any | None = None,
    ca_environment: str = "ELASTIC_CA_CERT",
) -> tuple[dict[str, Any], Any]:
    parsed = urllib.parse.urlparse(url)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.scheme not in ({"http", "https"} if loopback else {"https"})
    ):
        raise RuntimeError("service target must be credential-free HTTPS (HTTP is allowed only on loopback)")
    headers = _auth_headers(kibana=kibana)
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    verify = parse_bool(os.environ.get("TLS_VERIFY", "true"), name="TLS_VERIFY")
    if not verify and not loopback:
        raise RuntimeError("TLS_VERIFY=false is allowed only for loopback services")
    ca_file = os.environ.get(ca_environment, "")
    context = (
        ssl.create_default_context(cafile=str(resolve_repository_path(ca_file)))
        if verify and ca_file
        else ssl.create_default_context()
        if verify
        # Insecure contexts are reachable only for explicitly selected loopback URLs.
        else ssl._create_unverified_context()  # nosec B323
    )
    request = urllib.request.Request(url, headers=headers, data=data, method=method)
    try:
        # The target scheme, credentials, and host were constrained above.
        with urllib.request.urlopen(  # nosec B310
            request, timeout=20, context=context
        ) as response:
            return json.loads(response.read()), response.headers
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(
            f"service request to {sanitize_target(url)} returned HTTP {exc.code}: "
            f"{detail}; verify with: curl -I {sanitize_target(url)}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(
            f"service request to {sanitize_target(url)} failed: {exc}; likely cause: "
            f"DNS, TLS trust, firewall, or service readiness; verify with: curl -I "
            f"{sanitize_target(url)}"
        ) from exc


def _service_version(payload: dict[str, Any], service: str) -> str:
    version = payload.get("version")
    if isinstance(version, dict):
        version = version.get("number") or version.get("version")
    if not isinstance(version, str) or not version:
        raise RuntimeError(f"{service} did not report its version")
    normalized = version.split("+", 1)[0]
    if normalized != SUPPORTED_ELASTIC_VERSION:
        raise RuntimeError(f"{service} version {version} is unsupported; require {SUPPORTED_ELASTIC_VERSION}")
    return normalized


def _agent_reported_version(agent: dict[str, Any]) -> str:
    candidates: tuple[Any, ...] = (
        agent.get("local_metadata", {}).get("elastic", {}).get("agent", {}).get("version"),
        agent.get("agent", {}).get("version"),
        agent.get("version"),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate:
            return candidate
    raise RuntimeError(f"Fleet agent {agent.get('id', '<unknown>')} did not report its version")


def _elastic_agent_is_healthy(payload: dict[str, Any]) -> bool:
    state = payload.get("state", payload.get("status", ""))
    if isinstance(state, int):
        return state == 2
    return str(state).lower() in {"healthy", "online"}


def _assert_contains(actual: Any, expected: Any, label: str) -> None:
    """Require an API response to contain the exact reviewed asset definition."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            raise RuntimeError(f"{label} has the wrong response type")
        for key, value in expected.items():
            if key not in actual:
                raise RuntimeError(f"{label} is missing reviewed field {key}")
            _assert_contains(actual[key], value, f"{label}.{key}")
        return
    if actual != expected:
        raise RuntimeError(f"{label} differs from the reviewed repository definition")


def check_external_configuration() -> str:
    role = os.environ.get("WATCHMYAI_MACHINE_ROLE", "")
    if role not in {"ubuntu-server", "windows-endpoint"}:
        raise RuntimeError(
            "WATCHMYAI_MACHINE_ROLE must select ubuntu-server or windows-endpoint for live preflight"
        )
    for name in (
        "ELASTICSEARCH_URL",
        "KIBANA_URL",
        "FLEET_SERVER_URL",
    ):
        validate_url(name, os.environ.get(name, ""))
    if os.environ.get("WATCHMYAI_DATASET") != "watchmyai.events":
        raise RuntimeError("WATCHMYAI_DATASET must equal watchmyai.events")
    return f"live configuration is complete for role={role}"


def check_remote_lab() -> str:
    elastic_url = os.environ["ELASTICSEARCH_URL"].rstrip("/")
    kibana_url = os.environ["KIBANA_URL"].rstrip("/")
    elastic_info, headers = _json_request(elastic_url)
    elastic_version = _service_version(elastic_info, "Elasticsearch")
    date_header = headers.get("Date")
    if date_header:
        remote = email.utils.parsedate_to_datetime(date_header).timestamp()
        tolerance = int(os.environ.get("WATCHMYAI_CLOCK_MAX_SKEW_SECONDS", "120"))
        if abs(time.time() - remote) > tolerance:
            raise RuntimeError(f"clock skew exceeds {tolerance} seconds")
    asset_specs = (
        (
            "ILM policy",
            "/_ilm/policy/watchmyai-events",
            GATEWAY / "deployment/elastic/ilm_policy.json",
            lambda payload: payload["watchmyai-events"],
        ),
        (
            "component template",
            "/_component_template/watchmyai-events-mappings",
            GATEWAY / "deployment/elastic/component_template.json",
            lambda payload: payload["component_templates"][0]["component_template"],
        ),
        (
            "ingest pipeline",
            "/_ingest/pipeline/watchmyai-events",
            GATEWAY / "deployment/elastic/ingest_pipeline.json",
            lambda payload: payload["watchmyai-events"],
        ),
        (
            "index template",
            "/_index_template/logs-watchmyai.events",
            GATEWAY / "deployment/elastic/index_template.json",
            lambda payload: payload["index_templates"][0]["index_template"],
        ),
    )
    for label, endpoint, path, select in asset_specs:
        payload, _ = _json_request(elastic_url + endpoint)
        try:
            actual = select(payload)
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"{label} response has an unexpected shape") from exc
        expected = json.loads(path.read_text("utf-8"))
        _assert_contains(actual, expected, label)
    data_stream, _ = _json_request(elastic_url + "/_data_stream/logs-watchmyai.events-default")
    if not any(
        stream.get("name") == "logs-watchmyai.events-default"
        for stream in data_stream.get("data_streams", [])
    ):
        raise RuntimeError("required data stream logs-watchmyai.events-default is missing")
    health, _ = _json_request(elastic_url + "/_cluster/health")
    if health.get("status") == "red":
        raise RuntimeError("Elasticsearch cluster health is red")
    source_pattern = os.environ.get("SOURCE_DATA_STREAM", "logs-watchmyai.events-*")
    encoded_source = urllib.parse.quote(source_pattern, safe="*,-._")
    telemetry_filters: list[dict[str, Any]] = [
        {"term": {"event.dataset": "watchmyai.events"}},
        {"term": {"watchmyai.schema.version": "1.1.0"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}},
    ]
    verification_session = os.environ.get("WATCHMYAI_VERIFY_SESSION_ID", "")
    if verification_session:
        telemetry_filters.append({"term": {"watchmyai.session.id": verification_session}})
    telemetry: dict[str, Any] = {}
    for attempt in range(6):
        telemetry, _ = _json_request(
            elastic_url + f"/{encoded_source}/_search",
            method="POST",
            body={
                "size": 1,
                "sort": [{"@timestamp": "desc"}],
                "query": {"bool": {"filter": telemetry_filters}},
            },
        )
        if telemetry.get("hits", {}).get("total", {}).get("value", 0) >= 1:
            break
        if attempt < 5:
            time.sleep(2)
    if telemetry.get("hits", {}).get("total", {}).get("value", 0) < 1:
        raise RuntimeError(
            "telemetry data stream has no matching recent schema 1.1.0 watchmyai.events record; "
            "verify gateway export credentials and ingest pipeline failures"
        )
    alert_pattern = os.environ.get("ALERT_INDEX_PATTERN", ".alerts-security.alerts-*")
    encoded_alerts = urllib.parse.quote(alert_pattern, safe="*,-._")
    _json_request(elastic_url + f"/_resolve/index/{encoded_alerts}")
    native_pattern = ",".join(NATIVE_FILE_INDEX_PATTERNS)
    encoded_native = urllib.parse.quote(native_pattern, safe="*,-._")
    native_indices, _ = _json_request(elastic_url + f"/_resolve/index/{encoded_native}")
    if not native_indices.get("indices"):
        raise RuntimeError("no native file-event indices resolve for WMAI-023/WMAI-024 validation")
    _json_request(
        elastic_url + f"/{encoded_native}/_search",
        method="POST",
        body={"size": 0, "query": {"match_none": {}}},
    )
    space = os.environ.get("KIBANA_SPACE", "default")
    prefix = "" if space == "default" else f"/s/{urllib.parse.quote(space, safe='')}"
    kibana_status, _ = _json_request(kibana_url + prefix + "/api/status", kibana=True)
    kibana_version = _service_version(kibana_status, "Kibana")
    payload, _ = _json_request(
        kibana_url + prefix + "/api/detection_engine/rules/_find?per_page=100",
        kibana=True,
    )
    rules = {
        item.get("rule_id"): item for item in payload.get("data", []) if item.get("rule_id") in SELECTED_IDS
    }
    if set(rules) != SELECTED_IDS:
        raise RuntimeError(f"Kibana contains {len(rules)}/{SUPPORTED_COUNT} supported WatchMyAI rules")
    for rule_id in SUPPORTED_IDS:
        expected = json.loads((RULES / "detections/elastic" / f"{rule_id}.json").read_text("utf-8"))
        expected.pop("enabled", None)
        _assert_contains(rules[rule_id], expected, f"detection rule {rule_id}")
    should_enable = parse_bool(os.environ.get("ENABLE_RULES", "false"), name="ENABLE_RULES")
    enabled_ids = sorted(rule_id for rule_id, item in rules.items() if item.get("enabled") is True)
    if should_enable and len(enabled_ids) != SUPPORTED_COUNT:
        missing = sorted(SELECTED_IDS - set(enabled_ids))
        raise RuntimeError("ENABLE_RULES=true but Kibana has disabled supported rules: " + ", ".join(missing))
    if not should_enable and enabled_ids:
        raise RuntimeError(
            "ENABLE_RULES=false but Kibana has enabled supported rules: " + ", ".join(enabled_ids)
        )
    state = "enabled by explicit opt-in" if should_enable else "disabled by default"
    return (
        f"Elasticsearch/Kibana {elastic_version}/{kibana_version}; exact remote "
        "assets, data stream, native file indices, and "
        f"{SUPPORTED_COUNT} Kibana rules verified {state}"
    )


def check_fleet_and_gateway() -> str:
    fleet = os.environ["FLEET_SERVER_URL"].rstrip("/") + "/api/status"
    fleet_status, _ = _json_request(fleet, ca_environment="FLEET_CA_CERT")
    state = str(fleet_status.get("status", fleet_status.get("state", ""))).lower()
    if state and state not in {"healthy", "ready", "ok", "green"}:
        raise RuntimeError(f"Fleet Server is reachable but unhealthy: {state}")
    kibana_url = os.environ["KIBANA_URL"].rstrip("/")
    space = os.environ.get("KIBANA_SPACE", "default")
    prefix = "" if space == "default" else f"/s/{urllib.parse.quote(space, safe='')}"
    package_policies, _ = _json_request(
        kibana_url + prefix + "/api/fleet/package_policies?perPage=100&format=legacy",
        kibana=True,
    )
    fleet_policy_ids = {
        str(policy_id)
        for item in package_policies.get("items", [])
        if item.get("package", {}).get("name") == "fleet_server"
        for policy_id in (item.get("policy_ids") or [item.get("policy_id")])
        if policy_id
    }
    agents, _ = _json_request(
        kibana_url + prefix + "/api/fleet/agents?perPage=100&showInactive=false",
        kibana=True,
    )
    fleet_agents = [
        item
        for item in agents.get("items", [])
        if str(item.get("policy_id")) in fleet_policy_ids
        and str(item.get("status", "")).lower() in {"online", "healthy"}
    ]
    if not fleet_agents:
        raise RuntimeError("Kibana reports no online Fleet Server agent on a Fleet Server policy")
    fleet_versions = {
        _service_version({"version": _agent_reported_version(item)}, "Fleet Server agent")
        for item in fleet_agents
    }
    home = Path(os.environ["WATCHMYAI_HOME"])
    environment = dict(os.environ)
    development = os.environ.get("WATCHMYAI_POLICY_MODE") == "development"
    environment["WATCHMYAI_ALLOW_UNSIGNED_POLICY"] = "1" if development else "0"
    source = str(ROOT / "src")
    environment["PYTHONPATH"] = source + os.pathsep + environment.get("PYTHONPATH", "")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "watchmyai.cli.main",
            "--home",
            str(home),
            "self-check",
        ],
        cwd=GATEWAY,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            "local gateway validation failed: " + (completed.stdout + completed.stderr)[-1000:]
        )
    policy = "generated development policy" if development else "valid signed ACTIVE policy"
    return (
        f"Fleet Server is reachable; {len(fleet_agents)} online Fleet Server agent(s) "
        f"report {', '.join(sorted(fleet_versions))}; the local gateway has a {policy}"
    )


def check_local_elastic_agent() -> str:
    configured = os.environ.get("ELASTIC_AGENT_PATH", "").strip()
    executable = (
        resolve_repository_path(configured) if configured else Path(shutil.which("elastic-agent") or "")
    )
    if not executable.is_file():
        raise RuntimeError("Elastic Agent is not installed; configure ELASTIC_AGENT_PATH after installation")
    version_result = subprocess.run(
        [str(executable), "version"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if version_result.returncode:
        detail = (version_result.stdout + version_result.stderr)[-1000:]
        raise RuntimeError(f"Elastic Agent version check failed: {detail}")
    version_match = re.search(
        r"(?<!\d)(\d+\.\d+\.\d+(?:\+build\d+)?)(?!\d)",
        version_result.stdout + version_result.stderr,
    )
    if version_match is None:
        raise RuntimeError("Elastic Agent version output did not contain a semantic version")
    agent_version = _service_version({"version": version_match.group(1)}, "Elastic Agent")
    completed = subprocess.run(
        [str(executable), "status", "--output", "json"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode:
        detail = (completed.stdout + completed.stderr)[-1000:]
        raise RuntimeError(
            f"Elastic Agent is installed but stopped, unenrolled, or unhealthy: {detail}; "
            f"verify with: {executable} status"
        )
    try:
        status = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Elastic Agent returned invalid status JSON: {exc}") from exc
    if not _elastic_agent_is_healthy(status):
        state = status.get("state", status.get("status", "unknown"))
        raise RuntimeError(
            f"Elastic Agent is enrolled but unhealthy ({state}); "
            f"verify policy assignment with: {executable} status"
        )
    return f"Elastic Agent {agent_version} is installed, running, enrolled, and healthy"


def check_claude_endpoint() -> str:
    if shutil.which("claude") is None:
        raise RuntimeError("Claude Code is not installed or not available on PATH")
    from watchmyai.adapters.claude_code import installer
    from watchmyai.adapters.claude_code.adapter import HOOK_EVENTS

    report = installer.status()
    if report.get("error"):
        raise RuntimeError(f"Claude settings JSON is invalid: {report['error']}")
    duplicates = report.get("duplicate_events", [])
    if duplicates:
        raise RuntimeError(f"duplicate WatchMyAI Claude hooks: {', '.join(duplicates)}")
    installed = set(report.get("installed_events", []))
    if installed != set(HOOK_EVENTS):
        missing = sorted(set(HOOK_EVENTS) - installed)
        raise RuntimeError(
            "Claude hooks are incomplete; missing: " + ", ".join(missing) + "; run watchmyai install claude"
        )
    installer.verify_controlled_hook_event()
    return "Claude Code hooks are valid, unique, and preserve controlled telemetry session IDs"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-only",
        action="store_true",
        help="validate the release candidate without requiring the external isolated lab",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(os.environ.get("WATCHMYAI_CONFIG", ROOT / ".env")),
    )
    parser.add_argument(
        "--signed-test-release",
        type=Path,
        default=Path(
            os.environ.get(
                "WATCHMYAI_SIGNED_TEST_RELEASE",
                GATEWAY / "fixtures" / "distribution" / "signed-test-release",
            )
        ),
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="skip only the Git cleanliness assertion while changes are under test",
    )
    args = parser.parse_args()

    config_path = ROOT / ".env.example" if args.repository_only else args.config
    if not args.repository_only and args.config.is_file():
        configuration = load_dotenv(args.config)
        for key, value in configuration.items():
            os.environ.setdefault(key, value)
        if os.environ.get("ELASTICSEARCH_URL"):
            os.environ.setdefault("ELASTIC_URL", os.environ["ELASTICSEARCH_URL"])

    preflight = Preflight()
    checks: list[tuple[str, Callable[[], str]]] = [
        ("runtime versions", check_runtime),
        ("operating system and capacity", check_host_capacity),
        ("declared dependencies", check_dependencies),
        ("unified project configuration", check_project_contract),
        (
            "central configuration",
            lambda: check_central_configuration(
                config_path,
                template=args.repository_only,
            ),
        ),
        ("secret and machine-path hygiene", check_machine_specific_and_secrets),
        ("Elastic asset definitions", check_runtime_assets),
        ("exact disabled detection pack", check_rule_pack),
        ("atomic fixture safety", check_fixture_safety),
        (
            "signed synthetic test policy",
            lambda: check_signed_test_policy(args.signed_test_release),
        ),
        ("package buildability", check_package_buildability),
        ("runtime self-validation", check_runtime_self_validation),
    ]
    if args.allow_dirty:
        preflight.warn(
            "repository cleanliness",
            "explicitly skipped with --allow-dirty; clean-clone verification remains required",
        )
    else:
        checks.insert(2, ("repository cleanliness", check_repository_clean))
    for name, check in checks:
        preflight.run(name, check)
    repository_checks_failed = preflight.failed
    preflight.run(
        "technical readiness declaration",
        lambda: check_technical_readiness_state(repository_checks_failed=repository_checks_failed),
    )
    if args.repository_only:
        preflight.skip("external lab configuration", "repository-only mode")
        preflight.skip("Elastic/Kibana connectivity and clock", "repository-only mode")
        preflight.skip("Fleet Server and telemetry gateway", "repository-only mode")
        preflight.skip("local Elastic Agent", "repository-only mode")
        preflight.skip("Claude Code hook path", "repository-only mode")
    else:
        preflight.run("external lab configuration", check_external_configuration)
        if preflight.results[-1].status == "PASS":
            preflight.run("Elastic/Kibana connectivity and clock", check_remote_lab)
            preflight.run("Fleet Server and telemetry gateway", check_fleet_and_gateway)
            role = os.environ.get("WATCHMYAI_MACHINE_ROLE")
            platform_matches = (role == "windows-endpoint" and sys.platform.startswith("win")) or (
                role == "ubuntu-server" and sys.platform.startswith("linux")
            )
            if platform_matches:
                preflight.run("local Elastic Agent", check_local_elastic_agent)
            else:
                preflight.skip(
                    "local Elastic Agent",
                    f"selected role {role} is unavailable on platform {sys.platform}",
                )
            if role == "windows-endpoint" and sys.platform.startswith("win"):
                preflight.run("Claude Code hook path", check_claude_endpoint)
            else:
                preflight.skip(
                    "Claude Code hook path",
                    "requires the Windows endpoint role on Windows",
                )
        else:
            preflight.skip("Elastic/Kibana connectivity and clock", "configuration failed")
            preflight.skip("Fleet Server and telemetry gateway", "configuration failed")
            preflight.skip("local Elastic Agent", "configuration failed")
            preflight.skip("Claude Code hook path", "configuration failed")

    summary = {
        "status": "NOT READY" if preflight.failed else "READY",
        "mode": "repository-only" if args.repository_only else "isolated-lab",
        "checks": [asdict(result) for result in preflight.results],
    }
    if args.json_output:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        for result in preflight.results:
            print(f"[{result.status}] {result.name}: {result.detail} ({result.duration_ms} ms)")
        passed = sum(result.status == "PASS" for result in preflight.results)
        skipped = sum(result.status == "SKIP" for result in preflight.results)
        print(
            f"\n{summary['status']}: {passed} passed, {skipped} skipped, "
            f"{len(preflight.results) - passed - skipped} other"
        )
    return 1 if preflight.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
