# Product deployment sources

This directory owns product-level deployment inputs for the complete WatchMyAI release.
`rules_schema_1.1.0.ndjson` is the sole authoritative, import-safe source for the 20 production
detection rules validated in the July 2026 Elastic laboratory. It is a reviewed source asset, not a
generated output. Source rules are deliberately disabled; `watchmyai setup` enables them only for
explicit development validation or when signed setup receives `--enable-rules`.

After an approved manual change to the authoritative NDJSON, run the reconciliation workflow:

```bash
.venv/bin/python scripts/rules/reconcile_rules.py --sync
.venv/bin/python scripts/rules/reconcile_rules.py --check
```

The workflow regenerates the per-rule JSON and managed supporting artefacts, then checks for stale
or non-production copies. Do not manually edit generated rule copies. The recovery-only option
accepts a laboratory alert export and selects the latest embedded parameters for each production
rule; raw Elastic exports are evidence inputs and must never be committed.

`remediation-matrix.csv` is retained validation evidence recording the schema 1.1.0 event/field
basis and observed alert count. The complete release workflow consumes this directory through
`detection-rules/scripts/package_rules.py`; installation and service entry points remain under
`scripts/` and the telemetry gateway CLI.

See the public [detection-rule catalog](../docs/DETECTION_RULES.md) for the exact supported rules and
links to their generated objects, metadata, and playbooks.
