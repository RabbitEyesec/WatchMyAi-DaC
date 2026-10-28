# WatchMyAI Version 2: detection integrations

Version 2 adds three integrations around the existing gateway and the 20 packaged Elastic Security
rules. The gateway, the policy engine, schema 1.1.0 telemetry, signed policy handling and the
authoritative rule pack are unchanged.

| Integration | What it adds | Entry points |
|---|---|---|
| Sigma + pySigma | Converts the Sigma research catalog into reviewable, disabled Elastic EQL candidates | `scripts/sigma/` |
| Windows Sysmon | Sysmon configuration, installer, load generator and an ECS field verifier for Elastic | `deployment/windows/sysmon/`, `scripts/install/install-sysmon.ps1`, `scripts/validate/` |
| MITRE D3FEND | Version-pinned defensive-technique mapping sidecar and validator | `detection-rules/detections/mappings/`, `scripts/validate/validate_d3fend_mappings.py` |

## Install

One command creates `.venv`, installs hash-pinned dependencies, and runs the whole toolchain:

```bash
./scripts/install/install-v2.sh                       # Linux / macOS
```

```powershell
.\scripts\install\install-v2.ps1                     # Windows; add -InstallSysmon on a lab host
```

Run every tool again at any time from the repository root:

```bash
.venv/bin/python scripts/run_v2_integrations.py
```

Manual installs can use `pip install -e ".[sigma]"` or the hashed `requirements-dev.lock`.

## Sigma + pySigma

Sigma YAML stays the authored source. The converter produces candidate records; Elastic keeps
running the 20 production rules.

```bash
.venv/bin/python scripts/sigma/convert_candidates.py --check                 # determinism check, writes nothing
.venv/bin/python scripts/sigma/convert_candidates.py --output dist/sigma-candidates
.venv/bin/python scripts/sigma/validate_candidates.py --strict               # provenance, allowlists, drafts disabled
.venv/bin/python scripts/sigma/compare_semantics.py                          # positive/negative fixtures vs each query
```

How it works:

- `detection-rules/config/sigma-ecs-windows.yml` is the pySigma processing pipeline. It maps
  `Image`, `CommandLine`, `ParentImage`, `TargetFilename` and `TargetObject` to
  `process.executable`, `process.command_line`, `process.parent.executable`, `file.path` and
  `registry.path`, and adds the `event.category` / `event.type` scope for each Sigma logsource
  category.
- `detection-rules/config/sigma-conversion-policy.yml` holds the supported modifiers
  (`contains`, `startswith`, `endswith`, `all`), the allowed ECS fields, the allowed data streams
  per logsource category, and the output format (`eql`).
- EQL is the output format because its `:` and `like~` operators are case-insensitive, matching
  Sigma string semantics. The backend's `siem_rule` format is not used because it fetches MITRE
  ATT&CK data over the network; conversion here never touches the network.
- A rule is rejected with a stable error code instead of being approximated when it uses an
  unsupported modifier (`UNSUPPORTED_MODIFIER`), an aggregation or temporal condition
  (`UNSUPPORTED_CONDITION`), an unreviewed logsource (`UNSUPPORTED_LOGSOURCE`), a field the
  pipeline does not map (`UNMAPPED_FIELD`), a correlation rule, a malformed or duplicate ID, or a
  production/excluded `WMAI-` ID (`PRODUCTION_RULE_ID_FORBIDDEN`).
- Each candidate (`dist/sigma-candidates/WMAI-NNN.candidate.json`) records the source path and
  SHA-256, Sigma ID, pipeline and policy hashes, pySigma and backend versions, query, index
  patterns, an Elastic rule draft with `enabled: false`, fixture references, and a pending review
  decision. `manifest.json` lists every candidate hash and every rejection.
- `scripts/sigma/eql_eval.py` evaluates the EQL subset the backend emits and raises on anything
  outside it, so fixtures and queries are compared without an Elastic cluster.
- Fixtures live in `detection-rules/tests/sigma/fixtures/` (`positive/`, `negative/` per rule, and
  `unsupported/` inputs with their expected rejection codes).

Candidates are written to `dist/` (ignored by git). The converter refuses to write into
`detection-rules/detections/`. Promoting a candidate to a deployable rule is a separate release
change.

## Windows Sysmon

Sysmon events reach Elastic through the Elastic Agent Windows integration
(`sysmon_operational` data stream, `logs-windows.sysmon_operational-*`), which the native file
rules `WMAI-023` and `WMAI-024` and the Sigma candidates already query.

1. On the Windows host (elevated PowerShell), install Sysmon with the WatchMyAI configuration:

   ```powershell
   .\scripts\install\install-sysmon.ps1 -DryRun   # preview
   .\scripts\install\install-sysmon.ps1           # downloads Sysmon, checks the Microsoft signature, installs
   ```

   `deployment/windows/sysmon/watchmyai-sysmon.xml` enables process creation (1), file creation
   (11), file delete detected (26) and Run/RunOnce registry values (13). Event 23 is left off
   because it archives deleted file contents.
2. Enrol the host's Elastic Agent in a dedicated Fleet policy and add the Windows integration with
   the Sysmon Operational data stream enabled.
3. Generate benign file activity from one process. The defaults exceed the `WMAI-023` threshold
   (50 creations) and the `WMAI-024` threshold (20 deletions); use `-Creates 10 -Deletes 5` for a
   below-threshold run:

   ```powershell
   .\scripts\validate\generate-sysmon-load.ps1
   ```

4. Check the documents and thresholds from any machine that can reach Elasticsearch, using the
   same `ELASTICSEARCH_URL` / `ELASTIC_API_KEY` / `ELASTIC_CA_CERT` variables as the rest of
   WatchMyAI:

   ```bash
   .venv/bin/python scripts/validate/verify_sysmon_ingest.py --run-id <run id printed by step 3>
   .venv/bin/python scripts/validate/verify_sysmon_ingest.py --fixture sysmon-sample.json   # saved documents, no network
   ```

   The verifier checks `@timestamp`, `event.dataset`, `event.category`/`event.type`,
   `winlog.event_id`, host identity, `process.entity_id`, `file.path` and record provenance for
   duplicate suppression; counts creations and deletions per `process.entity_id` for the run; and
   reports matching alerts from `.alerts-security.alerts-*`. Results are endpoint-only; they do not
   attribute activity to an AI agent without separate session evidence. Exit code 2 means no
   Elastic connection was configured.

## MITRE D3FEND

`detection-rules/detections/mappings/d3fend.yml` has one item per production rule, with a mapping
status (`pending_review`, `approved`, `unmapped`), defensive techniques, related ATT&CK
techniques, rationale, evidence source and reviewer. The ontology is pinned by
`d3fend-ontology.lock.json`.

```bash
.venv/bin/python scripts/utilities/update_d3fend_snapshot.py --version 1.6.0                     # maintainer: pin the ontology
.venv/bin/python scripts/utilities/update_d3fend_snapshot.py --version 1.6.0 --from-file d3fend.json
.venv/bin/python scripts/validate/validate_d3fend_mappings.py --offline
.venv/bin/python scripts/validate/validate_d3fend_mappings.py --offline --require-complete       # release gate
```

Approving a mapping means adding resolvable technique IDs from the pinned snapshot, a rationale
(20+ characters), `reviewed_by`/`reviewed_at`, and `mapping_status: approved`. The validator
rejects unknown or deprecated IDs, approved items without a pinned snapshot, duplicate items, and
sidecars that do not cover exactly the 20 production rules. The mapping is documentation metadata;
it never changes rules or policy enforcement.

## CI

`scripts/run_v2_integrations.py` runs in the `repository_gate` job of `.github/workflows/watchmyai-ci.yml`
alongside the existing validation, using the pinned `requirements-dev.lock`.
