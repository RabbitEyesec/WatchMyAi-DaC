# Pull request

## Summary

Explain the problem, the chosen change, and the affected contract.

## Validation

- [ ] `python scripts/validate/validate_project.py`
- [ ] `python scripts/validate/validate_docs.py`
- [ ] `python scripts/rules/reconcile_rules.py --check`
- [ ] `pytest`
- [ ] `ruff format --check src telemetry-gateway/tests detection-rules/scripts detection-rules/tests scripts scenarios tests`
- [ ] `ruff check src telemetry-gateway/tests detection-rules/scripts detection-rules/tests scripts scenarios tests`
- [ ] `mypy`
- [ ] Relevant connected validation was run, or its absence is explained below.

## Release and security review

- [ ] No secrets, private infrastructure, raw telemetry, generated output, or local paths are included.
- [ ] Public APIs, schemas, rules, generated files, and version surfaces are unchanged or explicitly justified.
- [ ] Documentation and compatibility implications are covered.

## Connected validation notes

State what was run, what was not run, and why.
