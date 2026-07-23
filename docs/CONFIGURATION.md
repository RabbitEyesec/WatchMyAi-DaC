# Configuration reference

`watchmyai setup` generates and validates the setup file. `.env.example` defines its complete key
set, but its reserved example values are not deployable configuration. Re-run setup with changed
inputs instead of editing generated files or gateway YAML.

## Input precedence

Setup resolves each value from `.env.example`, an existing setup file, the non-empty process
environment, and command options, in that order. Later sources take precedence. The default setup
file is `.env`; `--config` selects another path.

Changed setup files are replaced atomically after a timestamped `.wmai-backup-*` copy. Unchanged
reruns do not write or create backups. POSIX setup and credential files use owner-only permissions.

## Variable reference

Examples below are neutral. Values marked **generated** are controlled by setup for the selected
workflow.

| Variable | Requirement and default | Accepted format and validation | Mode and security notes |
| --- | --- | --- | --- |
| `WATCHMYAI_MACHINE_ROLE` | Generated; `ubuntu-server` for connected setup | `repository-only`, `ubuntu-server`, or `windows-endpoint` | The public connected path generates `ubuntu-server`; other roles do not extend live platform validation. |
| `WATCHMYAI_POLICY_MODE` | Generated; `development` or `signed` | Exact enum | Development is explicit. Signed mode never falls back to unsigned policy. |
| `WATCHMYAI_HOME` | Optional; setup defaults to `~/.local/state/watchmyai` | Absolute path outside the repository | Contains sensitive policy, approval, evidence, and exporter state. Use owner-only access. Global `--home` overrides it. |
| `ELASTICSEARCH_URL` | Required | Credential-free absolute HTTPS URL, for example `https://elastic.example:9200`; loopback HTTP only when TLS verification is disabled | All connected modes. Never embed a username or password. |
| `KIBANA_URL` | Required | Credential-free absolute HTTPS URL, for example `https://kibana.example:5601`; same loopback rule | Used for Fleet and Detection Engine APIs. |
| `KIBANA_SPACE` | Optional; `default` | Kibana space identifier | Applied to Kibana API paths; grant the credential access to the selected space. |
| `FLEET_SERVER_URL` | Required | Credential-free absolute HTTPS URL, for example `https://fleet.example:8220`; same loopback rule | Used for reachability and readiness checks. |
| `FLEET_AGENT_POLICY_ID` | Conditional; no deployable default | Existing Fleet policy ID | Setup selects it only when one local or online policy is unambiguous. Otherwise supply the listed ID. |
| `ELASTIC_AUTH_METHOD` | Optional; `api_key` | `api_key` or `basic` | API key is the documented path. Both modes require least privilege. |
| `ELASTIC_API_KEY` | Conditional direct setup input | Non-empty key; obvious example credentials are rejected | Read it without shell history. Setup moves it to the runtime key file and clears it from generated `.env`. |
| `ELASTIC_API_KEY_FILE` | Conditional alternative to direct key | Absolute existing file; mode `0600` on POSIX | Preferred for automation. The gateway references this file without copying its value into YAML. |
| `ELASTIC_USERNAME` | Required only for basic auth | Non-empty text | Stored in owner-only generated setup state when basic auth is selected. |
| `ELASTIC_PASSWORD` | Required only for basic auth | Non-empty text; obvious example values are rejected | Basic auth keeps this value in the owner-only generated setup file. Never commit it. |
| `TLS_VERIFY` | Optional; `true` | Boolean `true` or `false` | `false` is accepted only when all configured service hosts are loopback. Keep `true` for connected deployments. |
| `ELASTIC_CA_CERT` | Conditional; empty when system trust is sufficient | Absolute path to an existing PEM CA file | Used for Elasticsearch and Kibana TLS. Do not commit private trust material. |
| `FLEET_CA_CERT` | Conditional; empty when system trust is sufficient | Absolute path to an existing PEM CA file | Used for Fleet Server TLS. |
| `CLAUDE_SETTINGS_PATH` | Optional; empty uses the adapter default | Filesystem path to Claude Code settings | Setup input for detection and installation. The installer preserves unrelated entries and creates a backup on change. |
| `ELASTIC_AGENT_PATH` | Required for connected Ubuntu/Windows roles; setup probes standard Ubuntu paths | Existing executable path, for example `/opt/Elastic/Agent/elastic-agent` | The enrolled local Agent must be healthy and attached to the selected policy. |
| `WATCHMYAI_DATASET` | Generated; `watchmyai.events` | Must equal the canonical dataset | Fixed for v1.0.0. Do not rename it to repair missing telemetry. |
| `SOURCE_DATA_STREAM` | Generated; `logs-watchmyai.events-*` | Must retain the active source pattern | Covers the 18 WatchMyAI telemetry rules. |
| `ALERT_INDEX_PATTERN` | Generated; `.alerts-security.alerts-*` | Elastic Security alert index pattern | Used for read-only current-alert correlation. Do not insert alerts directly. |
| `VALIDATION_TIMEOUT_SECONDS` | Optional; `300` | Integer 10 through 3600 | Maximum wait for current alerts. Increase only after checking rule scheduling and source telemetry. |
| `POLL_INTERVAL_SECONDS` | Optional; `5` | Integer 1 through 300 | Poll interval for live correlation. Avoid aggressive polling against shared services. |
| `WATCHMYAI_TEST_WORKSPACE` | Generated below runtime home | Safe path accepted by workspace validation | Development scenarios are constrained to this disposable path. It must not be a broad or sensitive directory. |
| `WATCHMYAI_LAB_MODE` | Generated; `true` only for development setup | Boolean | Records explicit lab intent. It does not weaken path-safety validation. |
| `ENABLE_RULES` | Generated; `true` for development setup, otherwise `false` unless explicitly enabled | Boolean | Source rules remain disabled. Signed setup requires `--enable-rules` for its mandatory current-alert verification. |

For API-key mode, set either `ELASTIC_API_KEY` or `ELASTIC_API_KEY_FILE`, not a credential in a
URL. For basic mode, set all of `ELASTIC_AUTH_METHOD=basic`, `ELASTIC_USERNAME`, and
`ELASTIC_PASSWORD`.

## Setup option equivalents

| Option | Configuration value |
| --- | --- |
| Global `--home PATH` | `WATCHMYAI_HOME` |
| `--config PATH` | Generated setup-file location |
| `--elastic-url URL` | `ELASTICSEARCH_URL` |
| `--kibana-url URL` | `KIBANA_URL` |
| `--fleet-url URL` | `FLEET_SERVER_URL` |
| `--api-key-file PATH` | `ELASTIC_API_KEY_FILE` |
| `--elastic-agent-path PATH` | `ELASTIC_AGENT_PATH` |
| `--fleet-policy-id ID` | `FLEET_AGENT_POLICY_ID` |
| `--enable-rules` or `--no-enable-rules` | `ENABLE_RULES` |

`--development`, signed-policy options, and `--hooks` select workflow behavior rather than
operator-editable `.env.example` defaults.

## Generated runtime configuration

Setup creates `$WATCHMYAI_HOME/config.yml` with the selected policy and exporter modes. For direct
Elastic export, it references `$WATCHMYAI_HOME/gateway.env`. The environment file references the
owner-only API-key file. Gateway YAML does not contain a bearer credential.

Generated configuration validation rejects:

- unresolved placeholders and known original-machine paths;
- missing required values or unsupported enum and boolean values;
- embedded URL credentials or insecure remote HTTP;
- missing CA, key, or Elastic Agent files;
- non-owner-only API-key files on POSIX;
- runtime state inside the repository;
- unsafe validation workspace targets; and
- timeout or polling values outside their bounds.

Run the validator without printing secret values:

```bash
.venv/bin/python scripts/validate/validate_config.py --config .env
```

Related documents: [Setup and configuration](SETUP_AND_CONFIGURATION.md),
[Security policy](../SECURITY.md), and [Troubleshooting](TROUBLESHOOTING.md).
