# Verification and evidence

WatchMyAI verifies a deployment in tiers, from repository checks to current live alerts. Each tier
has its own command and reports its own result.

## Validation tiers

| Tier | What it confirms | Confirmed by a later tier |
| --- | --- | --- |
| Syntax validation | Supported JSON, YAML, Python, shell, and project files parse as checked | Schema meaning, connected services, and alerts |
| Schema validation | Telemetry, configuration, rules, and fixtures satisfy current contracts | Deployed producers emitting those documents |
| Deterministic fixture validation | Checked-in positive, negative, conformance, atomic, and evasion cases agree with checked-in rule logic | Elastic scheduling and alert creation |
| Importer dry run | The authoritative pack is exact, disabled, ordered, and import-safe without a network mutation | Kibana import and scheduling |
| Repository-only preflight | Static release, package, rule, archive, and configuration gates pass | Connected Elasticsearch, Kibana, Fleet, Agent, telemetry, and alerts |
| Connected deployment verification | Configured services, Agent/Fleet state, Elastic assets, gateway, hooks, rule state, one new event, and one current alert are healthy | All 20 rule scenarios |
| Current live alert validation | All 20 controlled current-run scenarios correlate to current alerts | Organization-specific production acceptance |

## Result states

| State | Meaning |
| --- | --- |
| `PASS` | The check ran and met every required condition in its stated scope. |
| `FAIL` | The check ran and a required condition was not met. |
| `SKIPPED` | The check did not run because its tier was not requested or a prerequisite was absent. Run that tier to get a result. |
| `ERROR` | The check could not complete because of an unexpected or invalid execution condition. Fix the condition and re-run. |

A dry-run import makes no Kibana changes. Importing, enabling, and scheduling are separate rule
states; `watchmyai verify` checks each of them.

## Repository-only validation

Use these non-connected commands from the repository root:

```bash
.venv/bin/python scripts/validate/validate_project.py
.venv/bin/python scripts/rules/reconcile_rules.py --check
.venv/bin/python scripts/import/import_rules.py --dry-run
.venv/bin/python scripts/preflight.py --repository-only --allow-dirty
.venv/bin/watchmyai validate --static-only
```

The static validate result reports live validation as `SKIPPED`; `watchmyai validate` against a
connected deployment produces the live result.

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

The telemetry query uses a unique verification session and current start time, so only events and
alerts from that run count. Verification waits for normal rule scheduling and fails when a required
connected stage is missing or skipped.

Setup treats a requested hook installer failure as an error. Claude Code and Codex CLI hook status is
reported by `.venv/bin/watchmyai doctor`.

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

## Release readiness record

The machine-readable [technical readiness record](../release/technical-readiness.json) reports each
tier separately: repository checks, rule import (`DRY_RUN_PASS`), and the connected and live
end-to-end tiers, which are completed by `watchmyai verify` and `watchmyai validate` in the target
environment.
