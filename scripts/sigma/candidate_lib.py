"""Deterministic Sigma -> Elastic candidate conversion with fail-closed contract checks.

Candidates are staged for human review. This module never writes into
``detection-rules/detections/`` and never talks to Elastic, Kibana, or the network.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from eql_eval import UnsupportedQueryError, compile_query  # noqa: E402

POLICY_PATH = ROOT / "detection-rules" / "config" / "sigma-conversion-policy.yml"
SCHEMA_VERSION = 1

# Error codes are part of the tool contract; tests and fixtures reference them.
E_PARSE = "SIGMA_PARSE_ERROR"
E_CORRELATION = "UNSUPPORTED_CORRELATION"
E_MULTI = "UNSUPPORTED_MULTI_DOCUMENT"
E_NO_ID = "MISSING_OR_INVALID_ID"
E_NO_RULE_ID = "MISSING_WATCHMYAI_RULE_ID"
E_PRODUCTION_ID = "PRODUCTION_RULE_ID_FORBIDDEN"
E_STATUS = "UNSUPPORTED_STATUS"
E_LOGSOURCE = "UNSUPPORTED_LOGSOURCE"
E_MODIFIER = "UNSUPPORTED_MODIFIER"
E_CONDITION = "UNSUPPORTED_CONDITION"
E_UNMAPPED = "UNMAPPED_FIELD"
E_CONVERT = "CONVERSION_FAILED"
E_QUERY = "UNSUPPORTED_GENERATED_QUERY"
E_DUPLICATE = "DUPLICATE_ID"
E_POLICY = "POLICY_INVALID"


class CandidateError(Exception):
    """A rule violated the conversion contract; no candidate is produced."""

    def __init__(self, code: str, message: str, source: str = "") -> None:
        super().__init__(f"{code}: {message}" + (f" [{source}]" if source else ""))
        self.code = code
        self.message = message
        self.source = source


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    policy = yaml.safe_load(path.read_text("utf-8"))
    required = {
        "pipeline",
        "output_format",
        "query_language",
        "sources",
        "supported_modifiers",
        "allowed_target_fields",
        "logsources",
        "allowed_statuses",
        "promotion",
        "attribution",
    }
    if not isinstance(policy, dict) or required - set(policy):
        raise CandidateError(E_POLICY, f"policy missing keys {sorted(required - set(policy or {}))}")
    if policy["output_format"] != "eql" or policy["query_language"] != "eql":
        raise CandidateError(
            E_POLICY, "only the eql output format is reviewed; lucene must never be labelled kql"
        )
    return policy


def forbidden_rule_ids() -> set[str]:
    """Production and excluded IDs that Sigma conversion must never produce."""
    from scripts.utilities.release_contract import EXCLUDED_RULES, SUPPORTED_RULES

    return set(SUPPORTED_RULES) | set(EXCLUDED_RULES)


def _import_sigma() -> Any:
    # Imported lazily so that importing this module never requires the build extra.
    import sigma.backends.elasticsearch as backend_module  # noqa: PLC0415
    import sigma.collection as collection_module  # noqa: PLC0415
    import sigma.modifiers as modifiers_module  # noqa: PLC0415
    import sigma.processing.pipeline as pipeline_module  # noqa: PLC0415
    import sigma.rule as rule_module  # noqa: PLC0415

    return backend_module, collection_module, modifiers_module, pipeline_module, rule_module


def toolchain_versions() -> dict[str, str]:
    versions = {}
    for dist in ("pySigma", "pySigma-backend-elasticsearch"):
        try:
            versions[dist] = importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            raise CandidateError(
                E_POLICY, f"{dist} is not installed; install the build extra: pip install '.[sigma]'"
            ) from None
    return versions


def _modifier_names(modifier_mapping: dict[str, type]) -> dict[type, str]:
    return {cls: name for name, cls in modifier_mapping.items()}


def _walk_items(detection: Any) -> Any:
    for item in detection.detection_items:
        if hasattr(item, "detection_items"):
            yield from _walk_items(item)
        else:
            yield item


def parse_rule(path: Path, source: str) -> Any:
    backend_module, collection_module, _, _, rule_module = _import_sigma()
    from sigma.exceptions import SigmaError

    try:
        collection = collection_module.SigmaCollection.from_yaml(path.read_text("utf-8"))
    except (SigmaError, yaml.YAMLError) as exc:
        code = E_CORRELATION if "correlation" in str(exc).lower() else E_PARSE
        raise CandidateError(code, str(exc), source) from exc
    if len(collection.rules) != 1:
        raise CandidateError(E_MULTI, f"expected exactly one rule, found {len(collection.rules)}", source)
    rule = collection.rules[0]
    if not isinstance(rule, rule_module.SigmaRule):
        raise CandidateError(E_CORRELATION, "correlation rules are not supported", source)
    if rule.errors:
        raise CandidateError(E_PARSE, "; ".join(str(e) for e in rule.errors), source)
    return rule


def check_rule_contract(rule: Any, raw: dict[str, Any], policy: dict[str, Any], source: str) -> str:
    """Validate everything knowable before conversion. Returns the WatchMyAI rule ID."""
    _, _, modifiers_module, _, _ = _import_sigma()
    try:
        uuid.UUID(str(rule.id))
    except (ValueError, TypeError):
        raise CandidateError(E_NO_ID, "id must be a UUID", source) from None
    rule_id = str(raw.get("x_watchmyai_rule_id") or "")
    if not re.fullmatch(r"WMAI-\d{3}", rule_id):
        raise CandidateError(E_NO_RULE_ID, "x_watchmyai_rule_id must look like WMAI-NNN", source)
    if rule_id in forbidden_rule_ids():
        raise CandidateError(E_PRODUCTION_ID, f"{rule_id} belongs to the production or excluded set", source)
    status = str(rule.status.name.lower()) if rule.status else ""
    if status not in policy["allowed_statuses"]:
        raise CandidateError(E_STATUS, f"status {status or 'missing'} is not convertible", source)
    category = rule.logsource.category
    if category not in policy["logsources"] or rule.logsource.product or rule.logsource.service:
        raise CandidateError(
            E_LOGSOURCE,
            f"logsource {rule.logsource.category}/{rule.logsource.product}/{rule.logsource.service} "
            "is not in the reviewed allowlist",
            source,
        )
    names = _modifier_names(modifiers_module.modifier_mapping)
    allowed = set(policy["supported_modifiers"])
    for detection in rule.detection.detections.values():
        for item in _walk_items(detection):
            for modifier in item.modifiers:
                name = names.get(modifier, modifier.__name__)
                if name not in allowed:
                    raise CandidateError(E_MODIFIER, f"modifier |{name} is not supported", source)
    conditions = [str(c) for c in rule.detection.condition]
    if any(re.search(r"\||\bcount\b|\bnear\b|\bby\b", c) for c in conditions):
        raise CandidateError(E_CONDITION, "aggregation/temporal conditions are not supported", source)
    return rule_id


def _build_pipeline(policy: dict[str, Any]) -> Any:
    _, _, _, pipeline_module, _ = _import_sigma()
    path = ROOT / policy["pipeline"]
    return pipeline_module.ProcessingPipeline.from_dict(yaml.safe_load(path.read_text("utf-8")))


def convert_rule(path: Path, policy: dict[str, Any], versions: dict[str, str]) -> dict[str, Any]:
    """Convert one Sigma file into a candidate record, or raise ``CandidateError``."""
    source = rel(path)
    raw_bytes = path.read_bytes()
    try:
        raw = yaml.safe_load(raw_bytes)
    except yaml.YAMLError as exc:
        raise CandidateError(E_PARSE, str(exc), source) from exc
    if not isinstance(raw, dict):
        raise CandidateError(E_PARSE, "Sigma document is not a mapping", source)
    rule = parse_rule(path, source)
    rule_id = check_rule_contract(rule, raw, policy, source)

    backend_module, *_ = _import_sigma()
    backend = backend_module.EqlBackend(processing_pipeline=_build_pipeline(policy))
    try:
        queries = backend.convert_rule(rule, "default")
    except Exception as exc:  # backend raises many SigmaError subclasses
        raise CandidateError(E_CONVERT, f"{type(exc).__name__}: {exc}", source) from exc
    if len(queries) != 1 or not isinstance(queries[0], str):
        raise CandidateError(E_CONVERT, "backend did not return exactly one query string", source)
    query = queries[0]
    try:
        compiled = compile_query(query)
    except UnsupportedQueryError as exc:
        raise CandidateError(E_QUERY, str(exc), source) from exc
    stray = sorted(compiled.fields - set(policy["allowed_target_fields"]))
    if stray:
        raise CandidateError(
            E_UNMAPPED, f"fields {stray} are not mapped to the allowed ECS field set", source
        )

    category = rule.logsource.category
    pipeline_path = ROOT / policy["pipeline"]
    fixture_root = policy["fixtures_dir"]
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": f"wmai-sigma-candidate-{rule_id}",
        "watchmyai_rule_id": rule_id,
        "status": "requires_review",
        "promotion": policy["promotion"],
        "attribution": policy["attribution"],
        "source": {
            "path": source,
            "sha256": sha256_bytes(raw_bytes),
            "sigma_id": str(rule.id),
            "title": rule.title,
            "author": rule.author,
            "sigma_status": rule.status.name.lower(),
            "license": raw.get("license"),
            "logsource": {"category": category},
            "tags": sorted(str(t) for t in rule.tags),
        },
        "conversion": {
            "pipeline": policy["pipeline_name"],
            "pipeline_path": rel(pipeline_path),
            "pipeline_sha256": sha256_file(pipeline_path),
            "policy_sha256": sha256_file(POLICY_PATH),
            "converter": versions,
            "output_format": policy["output_format"],
            "field_mapping_status": policy["field_mapping_status"],
            "target_stack": "elastic-9.4.3",
        },
        "query_language": policy["query_language"],
        "rule_type": policy["rule_type"],
        "index_patterns": list(policy["logsources"][category]["index_patterns"]),
        "query": query,
        "query_fields": sorted(compiled.fields),
        "elastic_rule_draft": {
            "rule_id": f"wmai-sigma-candidate-{rule_id}",
            "name": rule.title,
            "description": rule.description or "",
            "type": policy["rule_type"],
            "language": policy["query_language"],
            "query": query,
            "index": list(policy["logsources"][category]["index_patterns"]),
            "enabled": False,
            "severity": _severity(rule),
            "tags": ["WatchMyAI", "Sigma candidate", "Requires review", "Endpoint-only"],
        },
        "semantic_tests": {
            "positive_fixture": f"{fixture_root}/positive/{rule_id}.json",
            "negative_fixture": f"{fixture_root}/negative/{rule_id}.json",
        },
        "review": {"decision": "pending", "reviewed_by": None, "reviewed_at": None},
    }


def _severity(rule: Any) -> str:
    level = rule.level.name.lower() if rule.level else "medium"
    return level if level in {"low", "medium", "high"} else ("high" if level == "critical" else "low")


def source_files(policy: dict[str, Any]) -> list[Path]:
    files: list[Path] = []
    for directory in policy["sources"]:
        files.extend(sorted((ROOT / directory).glob("*.yml")))
    return files


def convert_all(policy: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Convert every configured source. Returns (candidates, rejections)."""
    versions = toolchain_versions()
    candidates: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    seen_ids: dict[str, str] = {}
    for path in source_files(policy):
        try:
            candidate = convert_rule(path, policy, versions)
        except CandidateError as exc:
            rejected.append({"source": rel(path), "code": exc.code, "message": exc.message})
            continue
        sigma_id = candidate["source"]["sigma_id"]
        previous = seen_ids.get(sigma_id) or seen_ids.get(candidate["watchmyai_rule_id"])
        if previous:
            rejected.append({"source": rel(path), "code": E_DUPLICATE, "message": f"duplicates {previous}"})
            continue
        seen_ids[sigma_id] = seen_ids[candidate["watchmyai_rule_id"]] = rel(path)
        candidates.append(candidate)
    candidates.sort(key=lambda c: c["watchmyai_rule_id"])
    rejected.sort(key=lambda r: r["source"])
    return candidates, rejected


def dumps(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build_manifest(candidates: list[dict[str, Any]], rejected: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_count": len(candidates),
        "rejected_count": len(rejected),
        "converter": toolchain_versions(),
        "candidates": [
            {
                "candidate_id": c["candidate_id"],
                "file": f"{c['watchmyai_rule_id']}.candidate.json",
                "sha256": sha256_bytes(dumps(c).encode()),
                "source_sha256": c["source"]["sha256"],
                "status": c["status"],
            }
            for c in candidates
        ],
        "rejected": rejected,
        "production_mutation": False,
    }
