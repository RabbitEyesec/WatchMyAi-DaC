# WatchMyAI telemetry schema 1.1.0

The JSON Schema at `src/watchmyai/schema/watchmyai_event.schema.json` and the Elastic component
template at `telemetry-gateway/deployment/elastic/component_template.json` define the release
contract. The ingest pipeline rejects any WatchMyAI event whose `watchmyai.schema.version` is not
`1.1.0`.

Every WatchMyAI event contains `@timestamp`, ECS `event.*`, host identity, `watchmyai.schema.version`, agent identity, and attribution. Events use `event.dataset: watchmyai.events` and are routed to `logs-watchmyai.events-*`.

The production detection fields are:

- `event.action: tool_request` with `watchmyai.tool.name`, `watchmyai.tool.category`, `watchmyai.tool.arguments.command`, or `watchmyai.tool.arguments.file_path`;
- `event.action: policy_violation` with `watchmyai.policy.violation.type`;
- `watchmyai.session.id` for repeated-violation thresholds;
- optional ECS `process.command_line` as the validated compatibility fallback.

Tool arguments and command lines are redacted before evidence hashing or export. Values that match credential, token, password, authorization-header, cookie, environment-secret, or private-key patterns are replaced. Approval bearer IDs, prompt text, and raw secret values remain prohibited. Operators may add redaction patterns but should not disable the defaults in production.

The evidence fields are `chain_id`, monotonic per-session `sequence`, `previous_hash`, `event_hash`, and `hash_algorithm: sha256`. The chain and exporter receive the same normalized, redacted event.

`WMAI-023` and `WMAI-024` do not consume this schema. They use ECS `event.category`, `event.type`, and `process.entity_id` from Elastic Defend or Sysmon file events.
Their live scenarios carry the validation run ID in `file.path`; validation confirms the run-marked
source-event threshold and requires the same `process.entity_id` in the threshold alert terms.
