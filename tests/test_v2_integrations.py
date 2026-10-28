"""Automated checks for the Version 2 Sigma, Sysmon, D3FEND and correlation tooling."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "detection-rules" / "tests"


def load(name: str, relative: str):
    path = ROOT / relative
    sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        sys.modules[name] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module
    finally:
        sys.path.remove(str(path.parent))


eql = load("wmai_eql_eval", "scripts/sigma/eql_eval.py")
sysmon = load("wmai_verify_sysmon", "scripts/validate/verify_sysmon_ingest.py")
d3fend = load("wmai_d3fend", "scripts/validate/validate_d3fend_mappings.py")
correlation = load("wmai_correlate", "scripts/validate/correlate_agent_endpoint.py")


# --- EQL evaluator -----------------------------------------------------------------------


def test_eql_colon_is_case_insensitive_with_wildcards() -> None:
    query = eql.compile_query('any where process.executable:"*\\\\schtasks.exe"')
    assert query.matches({"process": {"executable": "C:\\Windows\\SYSTEM32\\SCHTASKS.EXE"}})
    assert not query.matches({"process": {"executable": "C:\\Windows\\notepad.exe"}})
    assert not query.matches({})


def test_eql_like_is_case_sensitive_and_in_tilde_is_not() -> None:
    assert not eql.compile_query('any where a like ("ab*")').matches({"a": "ABC"})
    assert eql.compile_query('any where a like~ ("ab*")').matches({"a": "ABC"})


def test_eql_boolean_logic_and_arrays() -> None:
    query = eql.compile_query(
        'any where event.category:"file" and not (file.path:"*.tmp" or file.path:"*.log")'
    )
    assert query.matches({"event": {"category": ["file"]}, "file": {"path": "a.txt"}})
    assert not query.matches({"event": {"category": ["file"]}, "file": {"path": "a.tmp"}})


@pytest.mark.parametrize(
    "text",
    ['process where a:"x"', 'any where a regex~ "x"', 'any where a:"x" | head 1', 'any where a:"\\q"'],
)
def test_eql_rejects_unsupported_syntax(text: str) -> None:
    with pytest.raises(eql.UnsupportedQueryError):
        eql.compile_query(text)


# --- Sigma conversion --------------------------------------------------------------------

sigma_available = importlib.util.find_spec("sigma") is not None
needs_sigma = pytest.mark.skipif(
    not sigma_available, reason="install the Version 2 tools: pip install '.[sigma]'"
)


@pytest.fixture(scope="module")
def lib():
    if not sigma_available:
        pytest.skip("pySigma not installed")
    return load("wmai_candidate_lib", "scripts/sigma/candidate_lib.py")


@needs_sigma
def test_all_catalog_sources_convert_deterministically(lib) -> None:
    policy = lib.load_policy()
    first, rejected = lib.convert_all(policy)
    second, _ = lib.convert_all(policy)
    assert not rejected
    assert len(first) == 7
    assert lib.dumps(first) == lib.dumps(second)


@needs_sigma
def test_candidates_are_disabled_staged_and_never_production(lib) -> None:
    candidates, _ = lib.convert_all(lib.load_policy())
    production = lib.forbidden_rule_ids()
    for candidate in candidates:
        assert candidate["elastic_rule_draft"]["enabled"] is False
        assert candidate["watchmyai_rule_id"] not in production
        assert candidate["query_language"] == "eql"
        assert candidate["attribution"] == "endpoint-only"
        assert candidate["status"] == "requires_review"


@needs_sigma
def test_unsupported_inputs_are_rejected_with_expected_codes(lib) -> None:
    directory = FIXTURES / "sigma" / "fixtures" / "unsupported"
    expectations = yaml.safe_load((directory / "expectations.yml").read_text("utf-8"))
    policy, versions = lib.load_policy(), lib.toolchain_versions()
    for name, code in expectations.items():
        with pytest.raises(lib.CandidateError) as info:
            lib.convert_rule(directory / name, policy, versions)
        assert info.value.code == code, name


@needs_sigma
def test_fixtures_agree_with_every_candidate_query(lib) -> None:
    compare = load("wmai_compare", "scripts/sigma/compare_semantics.py")
    candidates, _ = lib.convert_all(lib.load_policy())
    for candidate in candidates:
        assert compare.compare(candidate) == [], candidate["watchmyai_rule_id"]


@needs_sigma
def test_candidate_validator_flags_enabled_drafts(lib, tmp_path) -> None:
    validator = load("wmai_validate_candidates", "scripts/sigma/validate_candidates.py")
    policy = lib.load_policy()
    candidate = lib.convert_all(policy)[0][0]
    candidate["elastic_rule_draft"]["enabled"] = True
    path = tmp_path / "WMAI-026.candidate.json"
    path.write_text(lib.dumps(candidate), encoding="utf-8")
    errors = validator.validate_candidate(path, policy, lib.forbidden_rule_ids())
    assert any("disabled" in error for error in errors)


# --- Sysmon ------------------------------------------------------------------------------


def docs(name: str) -> list[dict]:
    return json.loads((FIXTURES / "sysmon" / "fixtures" / name).read_text("utf-8"))


@pytest.mark.parametrize("name", ["event11_create.json", "event23_delete.json", "event26_delete.json"])
def test_valid_sysmon_documents_satisfy_the_field_contract(name: str) -> None:
    for doc in docs(name):
        assert sysmon.check_document(doc) == []


def test_missing_process_entity_is_rejected() -> None:
    problems = sysmon.check_document(docs("missing_process_guid.json")[0])
    assert any("process.entity_id" in problem for problem in problems)


def test_duplicate_records_are_counted_once() -> None:
    result = sysmon.count_run(docs("duplicate_record.json"), "wmai-demo")
    assert result["WMAI-023"]["max_events_by_one_process_entity"] == 1


def test_thresholds_respect_process_entities() -> None:
    base = docs("event11_create.json")[0]
    events = []
    for index in range(60):
        event = json.loads(json.dumps(base))
        event["event"]["id"] = f"r{index}"
        event["process"]["entity_id"] = "{A}" if index < 30 else "{B}"
        events.append(event)
    result = sysmon.count_run(events, "wmai-demo")["WMAI-023"]
    assert result["max_events_by_one_process_entity"] == 30
    assert result["threshold_met"] is False
    assert result["distinct_process_entities"] == 2


# --- D3FEND ------------------------------------------------------------------------------


def test_shipped_sidecar_is_valid_and_covers_all_production_rules() -> None:
    errors, counts = d3fend.validate()
    assert errors == []
    assert sum(counts.values()) == 20


def make_sidecar(tmp_path: Path, **changes) -> Path:
    data = yaml.safe_load(d3fend.SIDECAR.read_text("utf-8"))
    data["items"][0].update(changes)
    path = tmp_path / "d3fend.yml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_approved_mapping_is_rejected_without_a_pinned_snapshot(tmp_path) -> None:
    sidecar = make_sidecar(
        tmp_path,
        mapping_status="approved",
        defensive_techniques=["D3-PSA"],
        rationale="Process spawn analysis fits this behaviour.",
        reviewed_by="reviewer",
        reviewed_at="2026-10-28",
    )
    errors, _ = d3fend.validate(sidecar)
    assert any("no verified ontology snapshot" in error for error in errors)


def test_approved_mapping_validates_against_a_pinned_snapshot(tmp_path) -> None:
    import hashlib

    snapshot = tmp_path / "d3fend.json"
    snapshot.write_text(
        json.dumps(
            {
                "@graph": [
                    {"d3f:d3fend-id": "D3-PSA", "rdfs:label": "Process Spawn Analysis"},
                    {"d3f:d3fend-id": "D3-OLD", "owl:deprecated": True},
                ]
            }
        ),
        encoding="utf-8",
    )
    lock = json.loads(d3fend.LOCK.read_text("utf-8"))
    lock.update(
        snapshot_status="PINNED",
        snapshot_path=str(snapshot),
        sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),
    )
    lock_path = tmp_path / "lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    common = {
        "mapping_status": "approved",
        "rationale": "Process spawn analysis fits this behaviour.",
        "reviewed_by": "reviewer",
        "reviewed_at": "2026-10-28",
    }
    ok = make_sidecar(tmp_path, defensive_techniques=["D3-PSA"], **common)
    errors, counts = d3fend.validate(ok, lock_path)
    assert errors == [] and counts["approved"] == 1
    for technique, fragment in (("D3-NOPE", "does not exist"), ("D3-OLD", "deprecated")):
        bad = make_sidecar(tmp_path, defensive_techniques=[technique], **common)
        assert any(fragment in error for error in d3fend.validate(bad, lock_path)[0])


def test_pending_item_with_content_is_rejected(tmp_path) -> None:
    sidecar = make_sidecar(tmp_path, defensive_techniques=["D3-PSA"])
    errors, _ = d3fend.validate(sidecar)
    assert any("empty placeholder" in error for error in errors)


# --- Agent-to-endpoint correlation ---------------------------------------------------------


def test_correlation_levels_and_endpoint_only_labelling() -> None:
    base = FIXTURES / "integration" / "fixtures"
    agents = json.loads((base / "agent_events.json").read_text("utf-8"))
    endpoints = json.loads((base / "endpoint_events.json").read_text("utf-8"))
    report = correlation.correlate(agents, endpoints)
    levels = {row["endpoint_event_id"]: row["attribution"] for row in report["results"]}
    assert levels == {"e1": "confirmed", "e2": "probable", "e3": "endpoint-only", "e4": "endpoint-only"}
    other_host = next(row for row in report["results"] if row["endpoint_event_id"] == "e3")
    assert other_host["agent_action_id"] is None and other_host["missing_links"]


def test_correlation_never_attributes_outside_the_window() -> None:
    base = FIXTURES / "integration" / "fixtures"
    agents = json.loads((base / "agent_events.json").read_text("utf-8"))
    endpoints = json.loads((base / "endpoint_events.json").read_text("utf-8"))
    late = correlation.correlate(agents, endpoints, window_seconds=1)
    assert late["counts"]["confirmed"] == 0
