# Troubleshooting

Start with the command that failed. WatchMyAI reports the stage and a secret-safe reason. Correct
the input or external prerequisite, rerun the same supported setup mode, then run `verify` again.
Do not repair generated JSON, gateway YAML, hooks, rules, or installed Elastic assets by hand.

## Installation and command problems

| Symptom | Likely causes | Diagnostic command | Corrective action | Do not |
| --- | --- | --- | --- | --- |
| Unsupported Python version | Only Python 3.13 or an older interpreter is selected; an existing `.venv` was created with it | `python3.12 --version` or `python3.11 --version`; then `.venv/bin/python --version` when the environment exists | Install Python 3.11 or 3.12. Recreate only the repository `.venv` through the installer when its interpreter is unsupported. | Change `requires-python`, bypass the installer check, or claim Python 3.13 support. |
| Virtual environment creation fails | `python3-venv` is absent, the checkout is not writable, or the selected interpreter is incomplete | `python3.12 -m venv --help` | On Ubuntu install `python3-venv`, restore checkout ownership, and rerun `./scripts/install/install.sh`. | Run the installer as root or create runtime state in a system directory. |
| Locked dependency installation fails | Package index or proxy unavailable, TLS trust failure, wrong platform wheel, or a modified lock | `.venv/bin/python -m pip install --dry-run --require-hashes -r requirements-release.lock` | Restore network/proxy trust, use a supported Python/platform, and retry the unchanged reviewed lock. | Remove hashes, use an unlocked install, or edit version pins as a quick fix. |
| `watchmyai` command not found | Installer did not finish, wrong working directory, or hooks point to a removed environment | `test -x .venv/bin/watchmyai` followed by `.venv/bin/python -m pip check` | Run the root installer and use `.venv/bin/watchmyai` from the checkout. Rerun setup to refresh managed hook commands. | Add an arbitrary global wrapper or edit hook JSON manually. |

## Configuration and TLS problems

| Symptom | Likely causes | Diagnostic command | Corrective action | Do not |
| --- | --- | --- | --- | --- |
| Placeholder rejection | `.env.example` was copied without setup, or a generated file still contains reserved values | `.venv/bin/python scripts/validate/validate_config.py --config .env` | Export real deployment inputs and rerun the selected `watchmyai setup` mode. | Replace only the reported string while leaving other generated state stale. |
| Invalid URL or embedded credentials | URL is relative, remote HTTP, lacks a host, or includes `user:password@` | `.venv/bin/python scripts/validate/validate_config.py --config .env` | Supply a credential-free absolute HTTPS URL. Keep authentication in the supported key file or owner-only basic-auth settings. | Put credentials in a URL, command argument, issue, or screenshot. |
| TLS certificate validation fails | Missing issuing CA, wrong CA file, expired certificate, hostname mismatch, or interception proxy | `curl --cacert "$ELASTIC_CA_CERT" --head "$ELASTICSEARCH_URL"` | Install the correct CA in system trust or provide the correct absolute `ELASTIC_CA_CERT` and `FLEET_CA_CERT`, then rerun setup. | Set `TLS_VERIFY=false` for a remote service. |
| Development workspace safety rejection | Workspace resolves to the repository, home, a broad ancestor, or another unsafe path | `.venv/bin/python scripts/validate/validate_config.py --config .env` | Let setup regenerate the private workspace below `WATCHMYAI_HOME`, which must remain outside the checkout. | Point validation at a real repository, home directory, root, or production data. |

## Elastic, Kibana, Fleet, and Agent problems

| Symptom | Likely causes | Diagnostic command | Corrective action | Do not |
| --- | --- | --- | --- | --- |
| Elasticsearch unreachable | DNS, routing, port, proxy, service state, or TLS trust | `curl --cacert "$ELASTIC_CA_CERT" --head "$ELASTICSEARCH_URL"` | Restore the intended endpoint and trust chain, then rerun setup or `verify`. An authentication response still proves network reachability. | Disable TLS or substitute an unreviewed cluster. |
| Kibana unreachable | Wrong URL/space, service state, proxy, or TLS trust | `curl --cacert "$ELASTIC_CA_CERT" --head "$KIBANA_URL"` | Correct the credential-free URL, space, route, or trust chain and rerun. | Import rules or saved objects manually to hide the failed stage. |
| Fleet Server unreachable | Wrong Fleet URL, service state, route, or Fleet CA | `curl --cacert "$FLEET_CA_CERT" --head "$FLEET_SERVER_URL"` | Restore Fleet reachability and CA trust, then rerun setup. | Treat Kibana reachability as proof that Fleet is healthy. |
| Elastic Agent not found | `ELASTIC_AGENT_PATH` missing, nonstandard installation, or Agent absent | `test -x "$ELASTIC_AGENT_PATH"` | Install and enroll Agent 9.4.3, or export its exact executable path before rerunning setup. | Create a dummy executable or bypass the path check. |
| Agent stopped or unhealthy | Agent service stopped, unenrolled, policy failure, or Fleet connectivity loss | `sudo "$ELASTIC_AGENT_PATH" status` | Repair Agent enrollment/service health and wait for policy acknowledgement before `verify`. | Accept rules WMAI-023 or WMAI-024 as validated without healthy native telemetry. |
| Fleet policy selection ambiguous | Multiple local or online policies are plausible | `.venv/bin/watchmyai setup --development --non-interactive` | Review the IDs reported by setup, export the exact intended `FLEET_AGENT_POLICY_ID`, and rerun the same mode. | Guess an ID or choose a production policy for a disposable lab. |
| API key authentication fails | Revoked, malformed, wrong cluster, or key file unreadable | `.venv/bin/watchmyai verify` | Issue a scoped replacement, read it into `ELASTIC_API_KEY` or write an owner-only key file, rerun setup, then revoke the old key. | Print the key with shell diagnostics or paste it into an issue. |
| Insufficient Elastic privileges | Authentication succeeds but a named asset, Fleet, rule, validation write, or alert read is denied | `.venv/bin/watchmyai verify` | Grant only the missing operation described by the failed stage and rerun. | Replace the key with an unrestricted administrator credential as a permanent fix. |

## Rules, telemetry, and current alerts

| Symptom | Likely causes | Diagnostic command | Corrective action | Do not |
| --- | --- | --- | --- | --- |
| Rule import count mismatch | Stale or partial Kibana state, generated-rule drift, excluded ID present, or wrong NDJSON | `.venv/bin/python scripts/rules/reconcile_rules.py --check` and `.venv/bin/python scripts/import/import_rules.py --dry-run` | Restore authoritative parity, then rerun setup so the importer updates by stable `rule_id` and verifies all 20. | Delete or edit rules directly in Kibana to force the count. |
| Rules imported but disabled | Source default is working, or signed setup did not request enablement | `.venv/bin/watchmyai verify` | For a controlled validation, rerun development setup or signed setup with explicit `--enable-rules`. | Change `enabled` in generated JSON or claim an imported rule is active. |
| Telemetry missing | Gateway export failure, invalid key, wrong output state, hook absent, or event rejected to dead letter | `.venv/bin/watchmyai status` followed by `.venv/bin/watchmyai verify` | Correct the reported exporter, policy, hook, or schema issue and rerun setup/verify. Inspect owner-only dead-letter state under the runtime home without publishing it. | Insert documents directly into an alert index or fabricate source telemetry. |
| Wrong `event.dataset` | Producer or hand-built event did not use schema 1.1.0, or fixed setup values were changed | `rg -n '^WATCHMYAI_DATASET=' .env` | Rerun setup and emit through the telemetry gateway. The only accepted dataset is `watchmyai.events`. | Rename the rule query or data stream to match an invalid producer. |
| Current telemetry exists but no alert | Rule disabled, scheduling not complete, query fields missing, time drift, or insufficient alert-index read privilege | `.venv/bin/watchmyai verify` | Confirm enabled state, source schema, clock, rule health, and credentials. Wait within the configured timeout after fixing the cause. | Treat the source event as proof that an alert exists. |
| Historical alerts appear relevant | A manual search ignores run/session/time boundaries | `.venv/bin/watchmyai validate --output runtime/validation-results.json` | Use the generated current-run result and correlation fields. Retain old alerts only as historical evidence. | Reuse an older alert ID or timestamp as current validation proof. |
| WMAI-023 or WMAI-024 times out | Elastic Defend file data absent, Agent policy not acknowledged, threshold interval incomplete, run path absent, or process entity mismatch | `VALIDATION_TIMEOUT_SECONDS=600 .venv/bin/watchmyai validate` | First restore Agent and source-event health. Then allow enough time for the five-minute threshold schedule and require matching run path and entity. | Lower the rule threshold, generate activity outside the disposable workspace, or accept unrelated endpoint events. |

## Hooks, policy, and uninstall

| Symptom | Likely causes | Diagnostic command | Corrective action | Do not |
| --- | --- | --- | --- | --- |
| Claude Code hook missing | Claude was not detected, a custom settings path was omitted, or settings changed after setup | `.venv/bin/watchmyai doctor` | Export the correct `CLAUDE_SETTINGS_PATH` when needed and rerun setup with `--hooks claude`. | Paste command groups into settings by hand. |
| Codex CLI hook missing | Codex home was not detected, hooks file moved, or settings changed after setup | `.venv/bin/watchmyai doctor` | Set the correct environment for the installed CLI and rerun setup with `--hooks codex`. | Reuse an older single notification setting as the enforcement boundary. |
| Duplicate hook entry | A manual entry or old installer path coexists with the managed group | `.venv/bin/watchmyai doctor` | Back up the user settings, remove only the confirmed obsolete duplicate through its owning installer, then rerun setup. Current setup itself is idempotent. | Delete unrelated hook groups or replace the whole settings file. |
| Policy verification fails | Missing signed input, bad signature, wrong organization, expired metadata, rollback/reuse, integrity mismatch, or unavailable ACTIVE policy | `.venv/bin/watchmyai verify` | Publish or supply a valid organization-signed forward release and rerun signed setup. Use development mode only in an explicit isolated lab. | Edit signed metadata, reset highest-seen state, ignore expiry, or silently switch production to unsigned mode. |
| Uninstall does not remove expected state | `--yes` omitted, rule disablement failed, hook state not recorded, or preserved evidence mistaken for a failure | `.venv/bin/watchmyai uninstall --help` | Run the documented command, resolve any reported disablement/hook error, and use `--purge-runtime` only after retention approval. | Delete the runtime home or Elastic assets before preserving required evidence. |

## Exit codes

| Code | Meaning | Response |
| --- | --- | --- |
| `0` | Requested checks passed in their stated scope | Record the exact scope; do not extend a static pass into a live claim. |
| `1` | General command or package-tool failure | Read the immediate command output and correct that local failure. |
| `2` | Missing prerequisite, invalid invocation, or required confirmation absent | Install the prerequisite or rerun with the documented option. |
| `3` | Invalid, missing, or unsafe configuration | Run the configuration validator, correct inputs, and rerun setup. |
| `4` | Connectivity, TLS, authentication, or external service failure | Restore the named endpoint, trust, or credential. |
| `5` | Rule import or post-import parity failure | Run reconciliation and dry-run import, then rerun setup. |
| `6` | Repository, gateway, Fleet, telemetry, policy, alert, or uninstall validation failure | Correct the failed validation stage; a skipped live requirement is not a pass. |
| `7` | Reserved release-contract code for a safety refusal | Stop and review the target or requested action. Current public v1.0.0 workflows generally report implemented safety/configuration refusals as code 3 or 6; do not reinterpret another code as success. |

If a failure remains unclear, retain only sanitized command output, the checkout commit, and the
named failed stage. Do not include `.env`, owner-only runtime files, credentials, or raw live
telemetry in a public report.
