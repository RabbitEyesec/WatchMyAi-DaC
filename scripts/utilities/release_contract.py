"""Authoritative WatchMyAI release contract and safe helpers."""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlparse

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROJECT_VERSION = (REPOSITORY_ROOT / "VERSION").read_text(encoding="utf-8").strip()
CANONICAL_DATASET = "watchmyai.events"
SUPPORTED_ELASTIC_VERSION = "9.4.3"
NATIVE_FILE_INDEX_PATTERNS = (
    "logs-endpoint.events.file-*",
    "logs-windows.sysmon_operational-*",
)
SUPPORTED_RULES = {
    "WMAI-001": "AI Access Outside Approved Workspace",
    "WMAI-002": "AI File Modification Outside Approved Workspace",
    "WMAI-007": "Privilege Escalation Attempt",
    "WMAI-009": "Command Executed Without Approval",
    "WMAI-022": "Sensitive File Read",
    "WMAI-023": "Bulk File Modification",
    "WMAI-024": "Bulk File Deletion",
    "WMAI-025": "Executable Written to Disk",
    "WMAI-030": "Unexpected Outbound Network Connection",
    "WMAI-048": "Repeated Policy Violations",
    "WMAI-051": "Unauthorized Shell Execution",
    "WMAI-053": "SSH Session Initiation",
    "WMAI-054": "Access to SSH Private Keys",
    "WMAI-055": "Unexpected Git Clone/Push",
    "WMAI-057": "Access to .env Files",
    "WMAI-058": "Environment Variable Harvesting",
    "WMAI-059": "Cloud CLI Credential Usage",
    "WMAI-060": "Unexpected Docker Operations",
    "WMAI-061": "Unexpected Kubernetes Commands",
    "WMAI-063": "Recursive Delete Attempt",
}
EXCLUDED_RULES = {
    "WMAI-003": "Access to Unapproved Repository",
    "WMAI-006": "Access to Restricted Directories",
    "WMAI-010": "Approval Replay",
    "WMAI-011": "Approval Used for Different Payload",
    "WMAI-012": "Resolved Path Mismatch",
    "WMAI-013": "Rejected Action Executed",
    "WMAI-014": "Expired Approval Used",
    "WMAI-034": "Security Control Tampering",
    "WMAI-067": "Unauthorized MCP Server Connection",
    "WMAI-070": "Policy Bypass Attempt",
}
DEFERRED_IDS = (
    "WMAI-004",
    "WMAI-005",
    "WMAI-008",
    "WMAI-015",
    "WMAI-016",
    "WMAI-017",
    "WMAI-018",
    "WMAI-019",
    "WMAI-020",
    "WMAI-021",
    "WMAI-026",
    "WMAI-027",
    "WMAI-028",
    "WMAI-029",
    "WMAI-031",
    "WMAI-032",
    "WMAI-033",
    "WMAI-035",
    "WMAI-036",
    "WMAI-037",
    "WMAI-038",
    "WMAI-039",
    "WMAI-040",
    "WMAI-041",
    "WMAI-042",
    "WMAI-043",
    "WMAI-044",
    "WMAI-045",
    "WMAI-046",
    "WMAI-047",
    "WMAI-049",
    "WMAI-050",
    "WMAI-052",
    "WMAI-056",
    "WMAI-062",
    "WMAI-064",
    "WMAI-065",
    "WMAI-066",
    "WMAI-068",
    "WMAI-069",
    "WMAI-071",
    "WMAI-072",
    "WMAI-073",
    "WMAI-074",
    "WMAI-075",
)
SUPPORTED_IDS = tuple(SUPPORTED_RULES)
EXCLUDED_IDS = tuple(EXCLUDED_RULES)
SUPPORTED_COUNT = len(SUPPORTED_IDS)
EXCLUDED_COUNT = len(EXCLUDED_IDS)
DEFERRED_COUNT = len(DEFERRED_IDS)

_catalog_sets = (set(SUPPORTED_IDS), set(EXCLUDED_IDS), set(DEFERRED_IDS))
if any(left & right for index, left in enumerate(_catalog_sets) for right in _catalog_sets[index + 1 :]):
    raise RuntimeError("active, excluded, and deferred WatchMyAI rule sets overlap")
if set.union(*_catalog_sets) != {f"WMAI-{number:03d}" for number in range(1, 76)}:
    raise RuntimeError("WatchMyAI historical rule catalog must contain exactly WMAI-001 through WMAI-075")

EXIT_GENERAL = 1
EXIT_MISSING_PREREQUISITE = 2
EXIT_INVALID_CONFIGURATION = 3
EXIT_CONNECTIVITY = 4
EXIT_RULE_IMPORT = 5
EXIT_VALIDATION = 6
EXIT_SAFETY = 7

PLACEHOLDER_RE = re.compile(r"(__SET_ME__|<[^>]+>|\$\{[^}]+\}|CHANGE_ME)", re.IGNORECASE)
# Only values known to identify the original author workstation are prohibited.
# Generic deployment classes such as /home/<user>, C:\Users\<user>, and RFC1918
# addresses are legitimate configuration and must not be rejected wholesale.
_ORIGINAL_AUTHOR = "abhinav" + "mac"
ORIGINAL_PATH_RE = re.compile(
    rf"(?:/Users/{re.escape(_ORIGINAL_AUTHOR)}(?:/|$)|"
    rf"/home/{re.escape(_ORIGINAL_AUTHOR)}(?:/|$)|"
    rf"C:\\Users\\{re.escape(_ORIGINAL_AUTHOR)}(?:\\|$))",
    re.IGNORECASE,
)

STALE_SCOPE_SUFFIXES = {".json", ".md", ".ps1", ".py", ".sh", ".toml", ".yaml", ".yml"}
STALE_SCOPE_RE = re.compile(
    r"(?:\b(?:22|30)\s*/\s*(?:22|30)\b|\b0\s*/\s*(?:22|30)\b|"
    r"\b(?:22|30)[- ]rules?\b|\b(?:selected|supported|exactly)\s+(?:22|30)\b|"
    r"\b(?:rule_count|supported_rule_count|deployable_rule_count)\b"
    r".{0,12}[:=]\s*(?:22|30)\b)",
    re.IGNORECASE,
)
HISTORICAL_SCOPE_RE = re.compile(
    r"\b(?:historical(?:ly)?|superseded|former|prior release|previous release)\b",
    re.IGNORECASE,
)


def parse_bool(value: str, *, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise ValueError(f"{name} must be true or false; found {value!r}")


def stale_active_scope_lines(path: Path) -> list[int]:
    """Return stale active-release scope claims, excluding explicit history."""
    if path.suffix.lower() not in STALE_SCOPE_SUFFIXES:
        return []
    findings: list[int] = []
    for line_number, line in enumerate(path.read_text("utf-8", errors="replace").splitlines(), 1):
        if STALE_SCOPE_RE.search(line) and not HISTORICAL_SCOPE_RE.search(line):
            findings.append(line_number)
    return findings


def validate_technical_readiness(
    payload: object, *, repository_preflight_failed: bool | None = None
) -> list[str]:
    """Validate the release readiness declaration against the v1 contract."""
    if not isinstance(payload, dict):
        return ["technical readiness root must be an object"]
    errors: list[str] = []
    if payload.get("supported_rule_count") != SUPPORTED_COUNT:
        errors.append(f"supported_rule_count must equal {SUPPORTED_COUNT}")
    if payload.get("supported_rules") != list(SUPPORTED_IDS):
        errors.append("supported_rules differ from the authoritative ordered set")
    if payload.get("excluded_rules") != list(EXCLUDED_IDS):
        errors.append("excluded_rules differ from the authoritative ordered set")
    if payload.get("deferred_rule_count") != DEFERRED_COUNT:
        errors.append(f"deferred_rule_count must equal {DEFERRED_COUNT}")
    if payload.get("deferred_rules") != list(DEFERRED_IDS):
        errors.append("deferred_rules differ from the authoritative ordered set")
    allowed_statuses = {
        "repository_static_checks": {"PASS", "FAIL"},
        "configuration_validation": {"PASS", "FAIL"},
        "schema_validation": {"PASS", "FAIL"},
        "ndjson_validation": {"PASS", "FAIL"},
        "preflight": {"PASS", "PARTIAL", "FAIL"},
        "clean_source_test": {"PASS", "PARTIAL", "FAIL"},
        "clean_clone_test": {"PASS", "PARTIAL", "FAIL"},
        "rule_import": {"PASS", "DRY_RUN_PASS", "SKIPPED", "FAIL"},
        "fixture_validation": {"PASS", "SKIPPED", "FAIL"},
        "live_end_to_end_validation": {"PASS", "SKIPPED", "FAIL"},
    }
    for field, allowed in allowed_statuses.items():
        if payload.get(field) not in allowed:
            errors.append(f"{field} must be one of: {', '.join(sorted(allowed))}")
    prerequisites = payload.get("external_prerequisites")
    if (
        not isinstance(prerequisites, list)
        or len(prerequisites) < 5
        or not all(isinstance(item, str) and item.strip() for item in prerequisites)
    ):
        errors.append("external_prerequisites must list the connected services, credentials, Agent, and host")
    blockers = payload.get("repository_controlled_blockers")
    if not isinstance(blockers, list) or not all(isinstance(item, str) and item.strip() for item in blockers):
        errors.append("repository_controlled_blockers must be a list of non-empty strings")
        blockers = []
    commands = payload.get("commands")
    required_commands = {
        "install_linux",
        "install_windows",
        "validate_config",
        "preflight_linux",
        "preflight_windows",
        "import_rules",
        "validate_supported_rules",
    }
    if (
        not isinstance(commands, dict)
        or set(commands) != required_commands
        or not all(isinstance(value, str) and value.strip() for value in commands.values())
    ):
        errors.append("commands must contain every non-empty supported release entry point")
    required_pass_fields = (
        "repository_static_checks",
        "configuration_validation",
        "schema_validation",
        "ndjson_validation",
        "preflight",
        "clean_source_test",
        "clean_clone_test",
        "fixture_validation",
    )
    if not blockers:
        incomplete = [name for name in required_pass_fields if payload.get(name) != "PASS"]
        if incomplete:
            errors.append("zero repository blockers requires PASS for: " + ", ".join(incomplete))
        if payload.get("rule_import") not in {"PASS", "DRY_RUN_PASS"}:
            errors.append("zero repository blockers requires a successful rule import dry-run or import")
    if payload.get("retained_live_evidence") != "HISTORICAL_EXTERNAL_ONLY":
        errors.append("retained_live_evidence must be HISTORICAL_EXTERNAL_ONLY")
    if payload.get("connected_infrastructure_validation") != "REQUIRED_BEFORE_DEPLOYMENT":
        errors.append("connected_infrastructure_validation must be REQUIRED_BEFORE_DEPLOYMENT")
    if repository_preflight_failed is True and not blockers:
        errors.append("repository preflight failed but repository_controlled_blockers is empty")
    if repository_preflight_failed is False:
        if blockers:
            errors.append("repository preflight passed but repository-controlled blockers remain")
        if payload.get("preflight") != "PASS":
            errors.append("repository preflight passed but readiness preflight is not PASS")
        if payload.get("clean_clone_test") != "PASS":
            errors.append("repository preflight passed but clean_clone_test is not PASS")
    return errors


def validate_url(name: str, value: str, *, allow_loopback_http: bool = True) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{name} must be an absolute http(s) URL; found {value!r}")
    if parsed.username or parsed.password:
        raise ValueError(f"{name} must not contain credentials")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{name} has an invalid port: {exc}") from exc
    if parsed.scheme == "http" and not (
        allow_loopback_http and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    ):
        raise ValueError(f"{name} must use HTTPS outside loopback")
    return value.rstrip("/")


def resolve_repository_path(value: str) -> Path:
    path = Path(os.path.expandvars(value)).expanduser()
    return path if path.is_absolute() else (REPOSITORY_ROOT / path).resolve()


def require_safe_workspace(path: Path) -> None:
    resolved = path.resolve()
    forbidden = {Path("/"), Path.home().resolve(), REPOSITORY_ROOT.resolve()}
    if resolved in forbidden:
        raise ValueError(f"unsafe test workspace {resolved}: use a dedicated disposable child path")
    if len(resolved.parts) < 3:
        raise ValueError(f"unsafe test workspace {resolved}: path is too broad")
    temp_root = Path(tempfile.gettempdir()).resolve()
    if (
        resolved.is_relative_to(Path.home().resolve())
        and not resolved.is_relative_to(REPOSITORY_ROOT.resolve())
        and not resolved.is_relative_to(temp_root)
    ):
        raise ValueError(f"unsafe test workspace {resolved}: real user-home targets are forbidden")


def sanitize_target(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.hostname:
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{parsed.hostname}{port}"
    return value


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text("utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path}:{line_number}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"{path}:{line_number}: invalid configuration key {key!r}")
        if key in values:
            raise ValueError(f"{path}:{line_number}: duplicate configuration key {key}")
        values[key] = value.strip().strip('"').strip("'")
    return values


def merged_config(path: Path, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    values = load_dotenv(path)
    environment = environ if environ is not None else os.environ
    return {key: environment.get(key, value) for key, value in values.items()}
