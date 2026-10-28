# Changelog

## WatchMyAI Version 2: detection integrations

- Added the Sigma + pySigma toolchain: `scripts/sigma/convert_candidates.py`, `validate_candidates.py`, `compare_semantics.py`, an EQL fixture evaluator, the `sigma-ecs-windows` pipeline, the conversion policy and per-rule positive/negative/unsupported fixtures. Output is staged under `dist/sigma-candidates` as disabled candidates.
- Added Windows Sysmon integration: minimum-necessary Sysmon configuration, signature-checked `install-sysmon.ps1`, `generate-sysmon-load.ps1`, and `verify_sysmon_ingest.py` for ECS field and `WMAI-023`/`WMAI-024` threshold checks.
- Added MITRE D3FEND mapping: completed mappings for all 20 production rules, ontology lock file, `update_d3fend_snapshot.py` and `validate_d3fend_mappings.py`.
- Added agent-to-endpoint correlation (`correlate_agent_endpoint.py`) with confirmed / strong / probable / endpoint-only levels, Sysmon and correlation sample fixtures, and `tests/test_v2_integrations.py` (24 checks).
- Added `scripts/run_v2_integrations.py` and wired it into the CI repository gate; added the `sigma` optional dependency and regenerated `requirements-dev.lock`.
- Added `docs/V2_INTEGRATIONS.md`. The gateway, signed policy handling, schema 1.1.0 and the 20-rule pack are unchanged.

## v1.0.0 release reconciliation - 2026-07-22

- Reconciled the repository with the validated schema 1.1.0 Elastic implementation and its 20 production rules.
- Added the authoritative NDJSON, deterministic reconciliation tool, synchronized metadata, schema-compatible fixtures, remediation matrix, and sanitized 779-alert evidence summary.
- Aligned the gateway event actions, redacted argument fields, Elastic mappings, ingest pipeline, import paths, scenarios, manifests, tests, and documentation.
- Historical: removed ten non-production IDs and superseded the earlier 22/30-rule scope claims.
- Added reproducible installation, configuration, verification, uninstall, security, and clean-clone guidance.
- Bound WMAI-023/WMAI-024 live validation to run-ID file paths, matching native source-event process entities, and threshold-alert group terms so unrelated endpoint activity cannot pass.
- Removed the unused vulnerable Sigma toolchain, upgraded pytest to its fixed release line, and regenerated the 33-distribution lock with zero known vulnerabilities.
- Detection component: regenerated every active Elastic rule and metadata record from the authoritative
  NDJSON, restored WMAI-057 through WMAI-063, and replaced timestamp-only native threshold validation
  with run-path, source-event entity, and alert-term correlation.
- Telemetry component: aligned emitted events, mappings, pipeline, and redaction with schema 1.1.0 while
  retaining owner-only runtime state, verified TLS defaults, and strict secret-field prohibitions.
- Consolidated component changelogs and ignore rules into these root project files; the two component
  directories remain internal implementation boundaries and do not carry independent release metadata.
- Rebuilt the public documentation around one quick start, one operator setup path, an authoritative
  configuration reference, a generated 20-rule catalog, symptom-based troubleshooting, and an
  audience-oriented documentation index.
- Moved completed baseline, implementation, and migration records out of the operator path and added
  deterministic Markdown link and documentation-asset validation.
