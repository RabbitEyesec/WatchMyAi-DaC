# Contributing to WatchMyAI

WatchMyAI is one project with two internal components. `telemetry-gateway/` contains the packaged
runtime and CLI; `detection-rules/` contains the active rule representations, fixtures, playbooks,
and research catalog. Root metadata, installers, validation, and release tooling govern both.

## Contributor environment

Use Python 3.11 or 3.12. From the repository root:

```bash
./scripts/install/install.sh --dev
```

On Windows, use `& .\scripts\install\install.ps1 -Dev`. The runtime and repository-validation
environment is locked in `requirements-release.lock`; formatting, typing, and security tools are
isolated in `requirements-dev.lock`. Do not update either lock as an incidental documentation or
rule change.

## Change boundaries

Keep pull requests focused and explain the affected contract, test evidence, and external
validation requirements. Do not mix generated rule drift, runtime behavior, and unrelated
documentation cleanup in one change.

The following files are derived from the authoritative
[`deployment/rules_schema_1.1.0.ndjson`](deployment/rules_schema_1.1.0.ndjson) or from its release
contract and must not be edited as a shortcut:

- `detection-rules/detections/elastic/WMAI-*.json`;
- packaged rule NDJSON and release manifests under ignored `dist/`; and
- synchronized rule support assets managed by reconciliation.

Do not add or remove a production rule ID without an approved release-contract change covering the
authoritative NDJSON, technical readiness record, exclusion/deferred partition, scenarios, tests,
documentation, and release count.

## Tests and static validation

Run the applicable checks from the repository root:

```bash
.venv/bin/python scripts/validate/validate_project.py
.venv/bin/python scripts/rules/reconcile_rules.py --check
.venv/bin/python scripts/import/import_rules.py --dry-run
.venv/bin/python scripts/preflight.py --repository-only --allow-dirty
.venv/bin/python scripts/validate/validate_docs.py
.venv/bin/python -m pytest
.venv/bin/ruff format --check telemetry-gateway/src telemetry-gateway/tests \
  detection-rules/scripts detection-rules/tests scripts scenarios tests
.venv/bin/ruff check telemetry-gateway/src telemetry-gateway/tests \
  detection-rules/scripts detection-rules/tests scripts scenarios tests
.venv/bin/mypy
```

The complete detection component checks are:

```bash
(cd detection-rules && ../.venv/bin/python scripts/validate.py)
(cd detection-rules && ../.venv/bin/python -m pytest -q tests)
(cd detection-rules && ../.venv/bin/python scripts/package_rules.py)
```

After an approved authoritative rule change, run
`.venv/bin/python scripts/rules/reconcile_rules.py --sync`, review every generated diff, then run the
full checks. Do not rewrite a test merely to make unsupported rule content pass.

## Documentation and screenshots

Use one H1, hierarchical headings, descriptive relative links, fenced code languages, and commands
verified against the current CLI. Update [the documentation index](docs/README.md) when adding a
primary guide. Run the documentation validator before requesting review.

Only authentic, current, sanitized screenshots may be tracked. Store selected images under
`docs/assets/screenshots/`, use descriptive lowercase names, reference every tracked asset, and
remove duplicates. Never include credentials, private infrastructure, personal data, synthetic
terminal output, generated product mockups, or a dashboard presented as required.

## Secrets, generated output, and release artifacts

Never commit generated `.env` files, `.venv`, `runtime/`, `dist/`, caches, local evidence, raw
Elastic exports, signing keys, or credentials. Release artifacts are built with:

```bash
.venv/bin/python scripts/utilities/build_release.py
```

Inspect `git diff --check`, `git status`, generated-rule parity, and documentation links before a
pull request. A connected Elastic validation must remain clearly separate from repository-only
results.
