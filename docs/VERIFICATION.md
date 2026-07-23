# Verification and evidence

WatchMyAI separates repository evidence from connected deployment evidence. A successful earlier
tier must not be described as proof of a later tier.

## Validation tiers

| Tier | What it proves | What it does not prove |
| --- | --- | --- |
| Syntax validation | Supported JSON, YAML, Python, shell, and project files parse as checked | Schema meaning, connected services, or alerts |
| Schema validation | Telemetry, configuration, rules, and fixtures satisfy current contracts | That deployed producers emit those documents |
| Deterministic fixture validation | Checked-in positive, negative, conformance, atomic, and evasion cases agree with checked-in rule logic | Current Elastic scheduling, alert creation, recall, or false-positive rate |
| Importer dry run | The authoritative pack is exact, disabled, ordered, and import-safe without a network mutation | That Kibana accepted or scheduled any rule |
| Repository-only preflight | Static release, package, rule, archive, and configuration gates pass | Connected Elasticsearch, Kibana, Fleet, Agent, telemetry, or alerts |
| Connected deployment verification | Configured services, Agent/Fleet state, Elastic assets, gateway, hooks, rule state, one new event, and one current alert are healthy | All 20 rule scenarios or future availability |
| Current live alert validation | All 20 controlled current-run scenarios correlate to current alerts | Universal efficacy or organization-specific production acceptance |
| Retained historical evidence | A prior controlled environment produced retained results | That the present checkout or deployment was rerun now |

## Result states

| State | Meaning |
| --- | --- |
| `PASS` | The check ran and met every required condition in its stated scope. |
| `FAIL` | The check ran and a required condition was not met. |
| `SKIPPED` | The check did not run, usually because its tier was not requested or prerequisites were absent. It is not a pass. |
| `ERROR` | The check could not complete because of an unexpected or invalid execution condition. It is not a pass. |

Static validation does not prove current live alerts. A dry-run import does not modify Kibana.
Imported does not mean enabled. Enabled does not prove that scheduling completed successfully.

## Repository-only validation

Use these non-connected commands from the repository root:

```bash
.venv/bin/python scripts/validate/validate_project.py
.venv/bin/python scripts/rules/reconcile_rules.py --check
.venv/bin/python scripts/import/import_rules.py --dry-run
.venv/bin/python scripts/preflight.py --repository-only --allow-dirty
.venv/bin/watchmyai validate --static-only
```

The static validate result records live validation as `SKIPPED`. Do not convert that field to
`PASS` in a report.

## Connected deployment verification

```bash
.venv/bin/watchmyai verify
```

The command checks:

- generated configuration, safe paths, owner-only files, TLS, credentials, and supported versions;
- Elasticsearch, Kibana, and Fleet Server connectivity and clock tolerance;
- the enrolled local Elastic Agent and selected Fleet policy acknowledgement;
- Elastic Defend data collection for native file-event scenarios;
- the WatchMyAI ILM policy, component template, ingest pipeline, index template, and data stream;
- gateway schema, redaction, policy mode, exporter settings, and local evidence paths;
- exact 20-rule stable-ID parity and expected enabled state;
- a newly generated schema 1.1.0 `WMAI-001` event and its correlated current alert.

The telemetry query uses a unique verification session and current start time. A historical event
or alert cannot satisfy it. Verification waits for normal rule scheduling and fails when a required
connected stage is missing, skipped, or unverifiable.

Setup treats a requested hook installer failure as an error, but the v1.0.0 Ubuntu connected
verification path does not assert current Claude Code or Codex CLI hook-file presence. Use
`.venv/bin/watchmyai doctor` for current hook status and treat this as a separate integration check.

## All-rule current validation

```bash
.venv/bin/watchmyai validate
```

The command first runs its static gates, then generates a unique validation run. The 18
WatchMyAI-telemetry rules receive schema-valid correlated events carrying current run, scenario,
session, action, and rule identifiers.

`WMAI-023` and `WMAI-024` perform native disposable file activity. Validation finds the run-marked
source events, requires the threshold from one `process.entity_id`, and accepts only a newer alert
whose threshold terms contain that entity. This prevents unrelated endpoint activity from passing
the scenario.

Every accepted alert must match its stable rule ID and current scenario time boundary. Where the
source supports them, validation also requires run ID, session ID, and entity correlation. Final
output is `PASS` only for 20/20 current alerts. The default JSON result is stored under ignored
`runtime/` state.

## Reading an honest release claim

The machine-readable [technical readiness record](../release/technical-readiness.json) reports
repository checks as passed, rule import as `DRY_RUN_PASS`, live end-to-end validation as
`SKIPPED`, retained live evidence as historical and external only, and connected infrastructure
validation as required before deployment. Those states must remain distinct.
