# Detection-rule catalog

WatchMyAI v1.0.0 packages exactly 20 production rules for Elastic 9.4.3. This catalog is derived
from the active Elastic rule objects and synchronized metadata under `detection-rules/`, reconciled
against [`deployment/rules_schema_1.1.0.ndjson`](../deployment/rules_schema_1.1.0.ndjson).

Every source rule is disabled by default. `watchmyai setup --development` enables the imported
rules for explicit validation. Organization-signed setup enables them only with the required
`--enable-rules` confirmation.

## Active v1.0.0 catalog

| Rule and support files | Purpose | Severity / risk | Source and principal telemetry | Behavior / source default |
| --- | --- | --- | --- | --- |
| **WMAI-001**<br>AI Access Outside Approved Workspace<br>[rule](../detection-rules/detections/elastic/WMAI-001.json) · [metadata](../detection-rules/detections/metadata/WMAI-001.yml) · [playbook](../detection-rules/playbooks/WMAI-001.md) | Detect policy evidence for AI access outside an approved workspace. | High / 73 | `logs-watchmyai.events-*`<br>`event.action: policy_violation`; violation type `ai_access_outside_approved_workspace` | Query; disabled |
| **WMAI-002**<br>AI File Modification Outside Approved Workspace<br>[rule](../detection-rules/detections/elastic/WMAI-002.json) · [metadata](../detection-rules/detections/metadata/WMAI-002.yml) · [playbook](../detection-rules/playbooks/WMAI-002.md) | Detect file-category policy violations for execution or path scope outside an approved workspace. | Critical / 91 | `logs-watchmyai.events-*`<br>`policy_violation`; file tool; execution/path-scope violation | Query; disabled |
| **WMAI-007**<br>Privilege Escalation Attempt<br>[rule](../detection-rules/detections/elastic/WMAI-007.json) · [metadata](../detection-rules/detections/metadata/WMAI-007.yml) · [playbook](../detection-rules/playbooks/WMAI-007.md) | Detect tool requests containing supported privilege-escalation command indicators. | Critical / 91 | `logs-watchmyai.events-*`<br>`tool_request`; redacted command or ECS command-line indicator | Query; disabled |
| **WMAI-009**<br>Command Executed Without Approval<br>[rule](../detection-rules/detections/elastic/WMAI-009.json) · [metadata](../detection-rules/detections/metadata/WMAI-009.yml) · [playbook](../detection-rules/playbooks/WMAI-009.md) | Detect command-execution policy violations caused by missing approval. | Critical / 91 | `logs-watchmyai.events-*`<br>`policy_violation`; missing-approval violation | Query; disabled |
| **WMAI-022**<br>Sensitive File Read<br>[rule](../detection-rules/detections/elastic/WMAI-022.json) · [metadata](../detection-rules/detections/metadata/WMAI-022.yml) · [playbook](../detection-rules/playbooks/WMAI-022.md) | Detect tool requests that reference supported sensitive-key, credential, or environment-file patterns. | High / 73 | `logs-watchmyai.events-*`<br>`tool_request`; redacted command, file path, or ECS command line | Query; disabled |
| **WMAI-023**<br>Bulk File Modification<br>[rule](../detection-rules/detections/elastic/WMAI-023.json) · [metadata](../detection-rules/detections/metadata/WMAI-023.yml) · [playbook](../detection-rules/playbooks/WMAI-023.md) | Detect bulk native file changes or creations by one process entity. | Medium / 47 | `logs-endpoint.events.file-*`, `logs-windows.sysmon_operational-*`<br>ECS file change/creation and `process.entity_id` | Threshold: at least 50 by process entity; disabled |
| **WMAI-024**<br>Bulk File Deletion<br>[rule](../detection-rules/detections/elastic/WMAI-024.json) · [metadata](../detection-rules/detections/metadata/WMAI-024.yml) · [playbook](../detection-rules/playbooks/WMAI-024.md) | Detect bulk native file deletions by one process entity. | Medium / 47 | `logs-endpoint.events.file-*`, `logs-windows.sysmon_operational-*`<br>ECS file deletion and `process.entity_id` | Threshold: at least 20 by process entity; disabled |
| **WMAI-025**<br>Executable Written to Disk<br>[rule](../detection-rules/detections/elastic/WMAI-025.json) · [metadata](../detection-rules/detections/metadata/WMAI-025.yml) · [playbook](../detection-rules/playbooks/WMAI-025.md) | Detect tool requests writing supported executable or script file types. | High / 73 | `logs-watchmyai.events-*`<br>`tool_request`; file path and write/edit tool name | Query; disabled |
| **WMAI-030**<br>Unexpected Outbound Network Connection<br>[rule](../detection-rules/detections/elastic/WMAI-030.json) · [metadata](../detection-rules/detections/metadata/WMAI-030.yml) · [playbook](../detection-rules/playbooks/WMAI-030.md) | Detect tool requests containing supported download or outbound network command indicators. | High / 73 | `logs-watchmyai.events-*`<br>`tool_request`; redacted command or ECS command line | Query; disabled |
| **WMAI-048**<br>Repeated Policy Violations<br>[rule](../detection-rules/detections/elastic/WMAI-048.json) · [metadata](../detection-rules/detections/metadata/WMAI-048.yml) · [playbook](../detection-rules/playbooks/WMAI-048.md) | Detect repeated policy violations in one WatchMyAI session. | High / 73 | `logs-watchmyai.events-*`<br>`policy_violation`; `watchmyai.session.id` | Threshold: at least 5 by session; disabled |
| **WMAI-051**<br>Unauthorized Shell Execution<br>[rule](../detection-rules/detections/elastic/WMAI-051.json) · [metadata](../detection-rules/detections/metadata/WMAI-051.yml) · [playbook](../detection-rules/playbooks/WMAI-051.md) | Detect unauthorized shell or script execution policy violations. | Critical / 91 | `logs-watchmyai.events-*`<br>`policy_violation`; unauthorized shell/script violation | Query; disabled |
| **WMAI-053**<br>SSH Session Initiation<br>[rule](../detection-rules/detections/elastic/WMAI-053.json) · [metadata](../detection-rules/detections/metadata/WMAI-053.yml) · [playbook](../detection-rules/playbooks/WMAI-053.md) | Detect tool requests containing supported SSH, SCP, or SFTP command indicators. | High / 73 | `logs-watchmyai.events-*`<br>`tool_request`; redacted command or ECS command line | Query; disabled |
| **WMAI-054**<br>Access to SSH Private Keys<br>[rule](../detection-rules/detections/elastic/WMAI-054.json) · [metadata](../detection-rules/detections/metadata/WMAI-054.yml) · [playbook](../detection-rules/playbooks/WMAI-054.md) | Detect tool requests referencing supported SSH private-key or SSH configuration patterns. | Critical / 91 | `logs-watchmyai.events-*`<br>`tool_request`; redacted command, file path, or ECS command line | Query; disabled |
| **WMAI-055**<br>Unexpected Git Clone/Push<br>[rule](../detection-rules/detections/elastic/WMAI-055.json) · [metadata](../detection-rules/detections/metadata/WMAI-055.yml) · [playbook](../detection-rules/playbooks/WMAI-055.md) | Detect Git clone or push tool requests. | High / 73 | `logs-watchmyai.events-*`<br>`tool_request`; redacted Git command | Query; disabled |
| **WMAI-057**<br>Access to .env Files<br>[rule](../detection-rules/detections/elastic/WMAI-057.json) · [metadata](../detection-rules/detections/metadata/WMAI-057.yml) · [playbook](../detection-rules/playbooks/WMAI-057.md) | Detect tool requests referencing environment files or dotenv commands. | High / 73 | `logs-watchmyai.events-*`<br>`tool_request`; redacted command, file path, or ECS command line | Query; disabled |
| **WMAI-058**<br>Environment Variable Harvesting<br>[rule](../detection-rules/detections/elastic/WMAI-058.json) · [metadata](../detection-rules/detections/metadata/WMAI-058.yml) · [playbook](../detection-rules/playbooks/WMAI-058.md) | Detect tool requests containing supported environment-variable enumeration indicators. | High / 73 | `logs-watchmyai.events-*`<br>`tool_request`; redacted command or ECS command line | Query; disabled |
| **WMAI-059**<br>Cloud CLI Credential Usage<br>[rule](../detection-rules/detections/elastic/WMAI-059.json) · [metadata](../detection-rules/detections/metadata/WMAI-059.yml) · [playbook](../detection-rules/playbooks/WMAI-059.md) | Detect tool requests using supported cloud CLI command indicators. | Critical / 91 | `logs-watchmyai.events-*`<br>`tool_request`; redacted command or ECS command line | Query; disabled |
| **WMAI-060**<br>Unexpected Docker Operations<br>[rule](../detection-rules/detections/elastic/WMAI-060.json) · [metadata](../detection-rules/detections/metadata/WMAI-060.yml) · [playbook](../detection-rules/playbooks/WMAI-060.md) | Detect tool requests containing Docker command indicators. | High / 73 | `logs-watchmyai.events-*`<br>`tool_request`; redacted command or ECS command line | Query; disabled |
| **WMAI-061**<br>Unexpected Kubernetes Commands<br>[rule](../detection-rules/detections/elastic/WMAI-061.json) · [metadata](../detection-rules/detections/metadata/WMAI-061.yml) · [playbook](../detection-rules/playbooks/WMAI-061.md) | Detect tool requests containing kubectl, Helm, or k9s indicators. | High / 73 | `logs-watchmyai.events-*`<br>`tool_request`; redacted command or ECS command line | Query; disabled |
| **WMAI-063**<br>Recursive Delete Attempt<br>[rule](../detection-rules/detections/elastic/WMAI-063.json) · [metadata](../detection-rules/detections/metadata/WMAI-063.yml) · [playbook](../detection-rules/playbooks/WMAI-063.md) | Detect tool requests containing supported recursive-delete indicators. | Critical / 91 | `logs-watchmyai.events-*`<br>`tool_request`; redacted command or ECS command line | Query; disabled |

## Native threshold rules

`WMAI-023` and `WMAI-024` do not consume WatchMyAI schema 1.1.0 documents. They query native ECS
file telemetry from Elastic Defend or compatible Sysmon indices. Setup adds the Elastic Defend Data
Collection preset to the selected enrolled Agent policy when absent.

During current validation, a run ID is carried in the disposable file path. Validation confirms
that the threshold source events belong to one process entity and requires that same entity in the
resulting alert terms. Threshold scheduling can take longer than a one-minute query rule.

## Reconciliation and release partition

The root reconciliation tool checks the authoritative NDJSON against the 20 active JSON objects,
metadata, fixtures, corpora, scenarios, playbooks, manifests, and release contract:

```bash
.venv/bin/python scripts/rules/reconcile_rules.py --check
```

After an approved change to the authoritative source, maintainers use `--sync` and review every
generated difference. Do not manually edit an active JSON rule as a repair.

Ten rule IDs are explicitly excluded from v1.0.0 in
[`release/excluded-rules.json`](../release/excluded-rules.json). Another 45 definitions remain under
the deferred research catalog. Neither set is packaged, imported, enabled, or documented as
supported deployment content.

Fixture matches prove checked-in query and schema agreement only. They do not prove current Elastic
alerts, recall, false-positive rate, or efficacy outside the validated environment. See
[Verification](VERIFICATION.md).
