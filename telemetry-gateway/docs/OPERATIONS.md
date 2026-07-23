# Operations runbook

## Daily checks

- `watchmyai status`, `watchmyai policy status`, and `watchmyai doctor`.
- Hook installation/adapter health and capability fingerprints.
- ACTIVE bundle ID/version/sequence, freshness, and clock state.
- Dead-letter volume, evidence-chain verification, exporter lag, and Elastic ingest failures.
- Approval backlog/expiry and distribution rejection alerts.

## Safe changes

Policy changes are new signed immutable releases. Never edit ACTIVE state, a staged policy, approval JSON, or evidence rows in place. Test candidate policy against adapter capabilities and the real integration environment, activate, confirm health, and retain the release manifest.

Rule changes preserve stable rule IDs, remain disabled, run deterministic validation/package checks, and import into staging with `ENABLE_RULES=false`. Optional controlled live validation requires explicit `ENABLE_RULES=true`, ingests fixture events, and correlates current-run alerts. It is not measured efficacy or complete adapter-to-alert validation; production acceptance remains organization-controlled.

## Backup and recovery

Back up trusted root, distribution state/states, evidence SQLite database (using SQLite backup or quiesced filesystem snapshot), and configuration. Approval state requires special handling: restore only as part of an incident procedure and invalidate/reject live approvals when consistency is uncertain.

LAST_KNOWN_GOOD is automatic only for activation health failure. Other rollback is an explicit signed release; it is never a direct pointer edit.

## Decommission

Remove hooks with `watchmyai uninstall claude|codex`, remove MCP routes, revoke exporter credentials, preserve evidence under retention policy, revoke endpoint trust/targets authorization, and document final chain/export state.
