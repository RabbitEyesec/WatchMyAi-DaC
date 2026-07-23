# Detection-rule deployment assets

This directory owns the maintainer-only rule export utility. The root setup workflow and
`.github/workflows/detection-rules-deploy.yml` use the single importer at
`../../scripts/import/import_rules.py` when deploying WatchMyAI.

- `export_rules.sh` is an internal maintainer utility that generates its request from the root
  release contract. It is not a second supported import or onboarding workflow.
- Import, validation, and setup remain owned by the root public commands and generated release
  artifacts; no generated ID inventory is stored here or edited manually.

This directory does not own detection logic. The authoritative rules remain
[`../../deployment/rules_schema_1.1.0.ndjson`](../../deployment/rules_schema_1.1.0.ndjson).
The [public catalog](../../docs/DETECTION_RULES.md) documents only the reconciled active set.
