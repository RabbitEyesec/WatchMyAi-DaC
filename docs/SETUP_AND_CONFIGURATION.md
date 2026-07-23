# Setup and configuration

This is the complete operator workflow after package installation. Run commands from the repository
root. The validated connected deployment uses Ubuntu 24.04, Python 3.11 or 3.12, and Elastic 9.4.3.

For the shortest path, use the [quick start](../QUICKSTART.md). For every supported variable and
validation rule, use the [configuration reference](CONFIGURATION.md).

## 1. Confirm operator prerequisites

Before setup, confirm that:

- Elasticsearch, Kibana, and Fleet Server 9.4.3 are reachable over HTTPS;
- Elastic Agent 9.4.3 is installed, enrolled, and healthy on this host;
- service CAs are available when they are not in the operating-system trust store;
- a scoped API key or basic-auth credential covers the documented setup operations; and
- the organization has selected either isolated development validation or signed production mode.

WatchMyAI does not provision those services or enroll Elastic Agent.

## 2. Install the command

```bash
./scripts/install/install.sh
```

The installer creates `.venv`, applies the reviewed lock, installs the root project, and runs smoke
checks. It does not contact external services or create runtime configuration.

## 3. Provide deployment inputs

Environment variables are the recommended input for deployment-specific values. Read the key
without adding it to shell history:

```bash
export ELASTICSEARCH_URL=https://elastic.example:9200
export KIBANA_URL=https://kibana.example:5601
export FLEET_SERVER_URL=https://fleet.example:8220
export ELASTIC_AGENT_PATH=/opt/Elastic/Agent/elastic-agent
read -rsp "Elastic API key: " ELASTIC_API_KEY && export ELASTIC_API_KEY && printf '\n'
```

Set absolute CA paths only when system trust is insufficient:

```bash
export ELASTIC_CA_CERT=/etc/watchmyai/elastic-ca.pem
export FLEET_CA_CERT=/etc/watchmyai/fleet-ca.pem
```

Setup resolves values in this order, with later sources winning:

1. `.env.example` defaults;
2. an existing setup file, `.env` unless `--config` changes it;
3. non-empty process environment variables; and
4. setup command options.

The command equivalents are `--elastic-url`, `--kibana-url`, `--fleet-url`, `--api-key-file`,
`--elastic-agent-path`, and `--fleet-policy-id`. `--home` is a global option and must precede the
subcommand:

```bash
.venv/bin/watchmyai --home /var/lib/watchmyai setup --development
```

Use `--non-interactive` for automation. Missing input or ambiguous Fleet policy selection then
fails instead of prompting.

## 4. Choose a policy mode

### Development or isolated lab

```bash
.venv/bin/watchmyai setup --development
unset ELASTIC_API_KEY
```

Development setup generates a private unsigned policy restricted to
`WATCHMYAI_TEST_WORKSPACE`. It explicitly enables unsigned loading and the 20 imported rules for
the requested validation. It is not an automatic or production fallback.

### Organization-signed production

```bash
.venv/bin/watchmyai setup \
  --signed-root /etc/watchmyai/root.json \
  --signed-policy-release /etc/watchmyai/releases/1.0.0 \
  --organization-id example-organization \
  --enable-rules
```

All three policy inputs are required. Setup enrolls the root when no trust anchor exists, verifies
and activates the signed release, and fails closed on any rejection. It never creates production
signing keys or downgrades to an unsigned policy. In v1.0.0 signed setup also requires
`--enable-rules` because final setup verification must prove a new alert.

## 5. Understand setup actions

Setup owns this sequence:

1. collect inputs and create the disposable validation workspace;
2. select the local Agent's Fleet policy, refusing ambiguous selection;
3. write and validate the owner-only setup configuration;
4. run repository-only preflight and generated-rule parity checks;
5. initialize the runtime and selected policy mode;
6. install the ILM policy, component template, ingest pipeline, index template, and data stream;
7. attempt optional Kibana data-view and investigation-search import;
8. attach Elastic Defend Data Collection to the selected Fleet policy and wait for Agent
   acknowledgement;
9. import exactly 20 rules and verify their enabled state;
10. install requested hooks without replacing unrelated settings; and
11. emit controlled telemetry and run final verification.

No dashboard is installed or required.

Hook selection defaults to `--hooks auto`, which installs only detected Claude Code or Codex CLI
integrations. Use `--hooks all`, `claude`, `codex`, or `none` to make the choice explicit. Setup
merges WatchMyAI entries idempotently and preserves unrelated hook groups.

## 6. Generated files and permissions

| Location | Contents and ownership |
| --- | --- |
| `.env` or `--config` path | Validated deployment values and credential-file references; mode `0600` on POSIX. Basic-auth deployments retain their credential here. |
| `$WATCHMYAI_HOME/secrets/elastic-api-key` | API key supplied directly to setup; owner-only on POSIX. |
| `$WATCHMYAI_HOME/gateway.env` | Gateway Elastic settings and API-key file reference; owner-only. |
| `$WATCHMYAI_HOME/config.yml` | Generated gateway paths, exporter mode, and policy mode; no bearer credential. |
| `$WATCHMYAI_HOME/setup-state.json` | Managed Fleet policy, hook list, configuration path, and policy mode. |
| `$WATCHMYAI_HOME/validation-workspace` | Private disposable workspace for controlled scenarios. |
| Agent hook configuration | Merged WatchMyAI command groups plus timestamped backup when changed. |

`WATCHMYAI_HOME` defaults to `~/.local/state/watchmyai` during setup and must be an absolute path
outside the checkout. Setup fixes the dataset to `watchmyai.events`, its source pattern to
`logs-watchmyai.events-*`, and the alert pattern to `.alerts-security.alerts-*`.

Before replacing a generated setup or hook file, setup creates a timestamped
`.wmai-backup-*` copy. An unchanged rerun writes nothing and creates no backup.

## 7. Idempotent reruns and reconfiguration

Export only changed inputs and rerun the same policy mode. Do not hand-edit generated gateway YAML,
hook JSON, installed rules, or Elastic assets.

For example, after resolving an ambiguous Fleet selection:

```bash
export FLEET_AGENT_POLICY_ID=policy-id-from-fleet
.venv/bin/watchmyai setup --development
.venv/bin/watchmyai verify
```

To rotate an API key, read the new value into `ELASTIC_API_KEY`, rerun setup, unset it, and revoke
the old key through the organization's credential process. Do not print it or store it in source
control, shell history, gateway YAML, or screenshots.

## 8. Verify and validate

```bash
.venv/bin/watchmyai verify
.venv/bin/watchmyai validate
```

With a non-default setup file:

```bash
.venv/bin/watchmyai verify --config /etc/watchmyai/watchmyai.env
.venv/bin/watchmyai validate --config /etc/watchmyai/watchmyai.env
```

`verify` checks the connected deployment and one current `WMAI-001` telemetry-to-alert path.
`validate` runs all 20 controlled scenarios and requires 20 correlated current alerts. See
[Verification](VERIFICATION.md) for result semantics and [Troubleshooting](TROUBLESHOOTING.md) for
failed stages.
