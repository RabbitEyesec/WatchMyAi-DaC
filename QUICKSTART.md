# WatchMyAI quick start

This is the shortest supported path from a fresh checkout to current WatchMyAI alerts. Live
deployment is validated on Ubuntu 24.04 with Python 3.11 or 3.12 and Elastic 9.4.3.

Elasticsearch, Kibana, Fleet Server, and an enrolled Elastic Agent are external prerequisites.
WatchMyAI does not create or enroll them.

## 1. Prepare the host

Install Git, Python, virtual-environment support, curl, and CA certificates:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv curl ca-certificates
```

In GitHub, open the repository's **Code** menu and copy its clone command. Enter the resulting
checkout, then confirm the required external services are reachable over HTTPS and Elastic Agent
9.4.3 is enrolled on this host.

## 2. Install WatchMyAI

```bash
cd watchmyai
./scripts/install/install.sh
```

The installer creates `.venv`, installs the reviewed runtime and validation lock, installs the root
package without dependency re-resolution, and runs package smoke checks. It does not contact
Elastic or create runtime configuration.

Windows users can bootstrap the command with:

```powershell
& .\scripts\install\install.ps1
```

The Windows installer is supported, but v1.0.0 live Elastic deployment is validated only on
Ubuntu.

## 3. Supply deployment values

Use credential-free HTTPS URLs. Read the API key without placing it in shell history:

```bash
export ELASTICSEARCH_URL=https://elastic.example:9200
export KIBANA_URL=https://kibana.example:5601
export FLEET_SERVER_URL=https://fleet.example:8220
export ELASTIC_AGENT_PATH=/opt/Elastic/Agent/elastic-agent
read -rsp "Elastic API key: " ELASTIC_API_KEY && export ELASTIC_API_KEY && printf '\n'
```

If the service certificates are not trusted by the operating system, also set absolute CA paths:

```bash
export ELASTIC_CA_CERT=/etc/watchmyai/elastic-ca.pem
export FLEET_CA_CERT=/etc/watchmyai/fleet-ca.pem
```

The scoped key must cover the WatchMyAI Elastic assets, Detection Engine rules, Fleet reads and
Elastic Defend package-policy setup, controlled validation writes, and the source and alert reads
described in [Installation](docs/INSTALLATION.md). Do not use a credential embedded in a URL.

## 4. Run development setup

```bash
.venv/bin/watchmyai setup --development
unset ELASTIC_API_KEY
```

Development mode is explicit. It generates an unsigned policy restricted to the private validation
workspace, configures direct Elastic export, installs WatchMyAI Elastic assets, selects the enrolled
Agent's Fleet policy, adds Elastic Defend data collection, imports exactly 20 rules, enables them for
the requested validation, installs detected hooks, and runs final verification.

If setup reports more than one plausible Fleet policy, set the exact ID it lists and rerun:

```bash
export FLEET_AGENT_POLICY_ID=policy-id-from-fleet
.venv/bin/watchmyai setup --development
```

Kibana data views and investigation searches are optional. No dashboard is required.

## 5. Verify and validate

```bash
.venv/bin/watchmyai verify
.venv/bin/watchmyai validate
```

`verify` checks the configured services, Fleet and Agent state, Elastic Defend, Elastic assets,
gateway policy, the exact rule set, a newly emitted schema 1.1.0 event, and a correlated
current-run `WMAI-001` alert.

Hook installation is performed during setup. Use `.venv/bin/watchmyai doctor` to inspect current
Claude Code and Codex CLI hook status; v1.0.0 connected verification does not gate Ubuntu readiness
on those hook files.

`validate` runs the static gates, generates one current scenario for every supported rule, and
accepts only correlated alerts inside the current run boundaries. Eighteen scenarios use
`watchmyai.events`; `WMAI-023` and `WMAI-024` use disposable native file activity and matching
Elastic Defend process entities. Success is `20/20` current alerts and a final `PASS`.

Default results are written to ignored `runtime/validation-results.json`. Historical alerts cannot
satisfy the current run.

## Signed production mode

Do not use development mode as a production fallback. Signed setup requires all three
organization-controlled inputs and explicit rule enablement:

```bash
.venv/bin/watchmyai setup \
  --signed-root /etc/watchmyai/root.json \
  --signed-policy-release /etc/watchmyai/releases/1.0.0 \
  --organization-id example-organization \
  --enable-rules
```

Setup verifies enrollment and activation. It does not generate signing keys or silently downgrade
to an unsigned policy.

## If a command fails

Do not edit generated rule JSON, gateway YAML, hook JSON, or installed Elastic assets as a repair.
Use the reported exit code and [Troubleshooting](docs/TROUBLESHOOTING.md), correct the input or
external service, rerun the same setup mode, and then run `verify` again.

For configuration details, upgrades, and safe removal, see:

- [Setup and configuration](docs/SETUP_AND_CONFIGURATION.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Installation and upgrades](docs/INSTALLATION.md)
- [Uninstall](docs/UNINSTALL.md)
