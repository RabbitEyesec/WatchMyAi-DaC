# WatchMyAI detection rules 1.0.0

This internal component validates, tests, documents, and packages WatchMyAI's 20 production rules
for Elastic 9.4.3. It is not a separately published product. Use the root
[`QUICKSTART.md`](../QUICKSTART.md) for installation, setup, verification, and live validation.

The sole rule source of truth is
[`../deployment/rules_schema_1.1.0.ndjson`](../deployment/rules_schema_1.1.0.ndjson). The files in
`detections/elastic/`, the packaged NDJSON, and release manifests are generated artefacts; do not
edit them manually. Metadata, fixtures, corpora, scenarios, and playbooks are synchronized support
assets managed by the reconciliation workflow, with editorial fields retained where documented.

Eighteen rules query WatchMyAI schema 1.1.0 telemetry. `WMAI-023` and `WMAI-024` are threshold rules over ECS endpoint file events. Ten retired or unvalidated IDs are listed in [`../release/excluded-rules.json`](../release/excluded-rules.json) and are absent from every active rule, fixture, corpus, scenario, and playbook directory. The separate research catalog remains source-only in the complete archive and is never included in the deployable rule set or imported.

The root [detection-rule catalog](../docs/DETECTION_RULES.md) is the public reference for titles,
purpose, severity, risk, sources, behavior, metadata, and playbooks.

The top-level `version` in metadata mirrors the Elastic rule revision. It is independent of the telemetry schema version, which is fixed at 1.1.0 for this release.

## Layout

- `detections/elastic/`: 20 generated import objects, disabled by default.
- `detections/metadata/`: synchronized rule support metadata and traceability.
- `tests/fixtures/`: deterministic positive and negative events for all 20 rules.
- `tests/corpus/`: safety, evasion, and producer-conformance contracts.
- `playbooks/`: investigation and response guidance.
- `deployment/`: an internal maintainer-only rule export utility; root commands own imports.

## Reconcile, validate, and package

From the repository root:

```bash
.venv/bin/python scripts/rules/reconcile_rules.py --check
(cd detection-rules && ../.venv/bin/python scripts/validate.py)
(cd detection-rules && ../.venv/bin/python -m pytest -q tests)
(cd detection-rules && ../.venv/bin/python scripts/package_rules.py)
```

After an approved change to the authoritative NDJSON, regenerate derived content with:

```bash
.venv/bin/python scripts/rules/reconcile_rules.py --sync
```

Packaging rejects an enabled, duplicate, excluded, missing, non-authoritative, or incomplete release.
Generated artifacts are written to the ignored root `dist/` directory. The rule package consists of
`watchmyai-rules.ndjson`, `watchmyai-package-manifest.json`, and checksums. The complete project
source archive is built separately as `WatchMyAI-v1.0.0-source.zip` by the root archive builder.

## Import

```bash
.venv/bin/watchmyai setup --development
```

Setup calls the internal importer, which updates by stable `rule_id`, rejects duplicates and partial
API success, and verifies the post-import set. Rules stay disabled in signed setup unless explicit
enablement is requested; development setup enables them for the documented current-alert scenario.

## Validation meaning

Fixture validation proves that checked-in events satisfy the checked-in query logic. Historical
laboratory output is retained outside the source repository as private evidence and is not treated
as a current release run. Neither claim establishes a false-positive rate or universal efficacy
outside the validated environment.
