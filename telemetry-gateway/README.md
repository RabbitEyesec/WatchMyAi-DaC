# WatchMyAI telemetry gateway

This internal WatchMyAI component is the runtime for pre-execution policy decisions,
approval holds, evidence integrity, signed policy activation, and secret-safe telemetry from AI
coding agents. It is built and released through the root project configuration, not as a separate
product.

## What is implemented

- Canonical `ToolRequest`, `PolicyDecision`, `DecisionEvidence`, adapter capability, and obligation contracts.
- Deterministic deny-first PDP with strict default deny and explicit `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, and `MONITOR` effects.
- PEP enforcement for Claude Code and Codex lifecycle `PreToolUse` hooks and the WatchMyAI MCP stdio gateway.
- Cross-process locked approval storage with atomic replacement, hashed public references, strong binding, expiry, replay protection, and one-time consumption.
- Command/path/resource classifiers and secret-safe request hashes.
- SQLite WAL per-session SHA-256 chains over the final normalized/redacted event.
- Ed25519 threshold signed policy distribution with pinned roots, monotonic metadata, expiry/clock controls, immutable two-slot activation, root rotation, and explicit rollback.
- JSONL, HTTP, and Elasticsearch exporters; validated schema 1.1.0 mappings, pipeline, data stream,
  ILM, and optional Kibana investigation searches. No dashboard is required by v1.0.0.

## Onboarding boundary

Use the root [quick start](../docs/QUICKSTART.md) for the authoritative installation, setup,
verification, validation, and uninstall workflow. Gateway documentation covers component-specific
runtime and administration details only. The root setup workflow owns runtime initialization,
generated configuration, policy mode, gateway export, hooks, Fleet, Elastic assets, and detection
rules.

The wheel contains the default signature catalogue, redaction configuration, schema, and synthetic
development-policy template. Runtime homes and generated configuration are private and outside the
repository. Do not put Elastic API keys, approval bearer identifiers, raw user input, or unredacted tool
arguments in YAML.

A signed release directory contains `timestamp.json`, `snapshot.json`, `targets.json`, and
`policy.json`. Use `watchmyai policy rotate-root root-v2.json [root-v3.json ...]` for sequential
dual-threshold rotation. Authorized emergency rollback uses the activation command documented in
the quick start plus `--rollback-approval-count N`; unsigned or unlisted rollback is rejected.
Development setup generates the safe private policy and explicitly enables it in gateway config.
Unsigned loading remains off in signed mode.

## Agent integration

Setup detects and installs Claude/Codex lifecycle hooks with an absolute executable and runtime home.
Installers merge only WatchMyAI hook groups and retain backups. Pre-tool hook errors fail closed.
Secondary session/post-tool events are evidence-only. The lower-level integration commands remain
available for targeted administration after onboarding.

## Approvals

When a policy returns `REQUIRE_APPROVAL`, the first request is held and telemetry exposes only a `sha256:` approval reference.

```bash
watchmyai approval list
watchmyai approval grant sha256:abc123 --justification TICKET-1234
# Retry the identical native request; the runtime finds and atomically consumes the binding.
```

Changing the payload, resolved target, session, task, agent, tool, action, decision, policy bundle, or sequence fails closed. Reuse produces `approval_replay`.

## Elastic

Setup configures direct HTTPS export to `logs-watchmyai.events-default`, loads the reviewed assets,
and adds Elastic Defend data collection to the selected enrolled Fleet policy. Credentials live in
owner-only files generated from the setup environment. No Kibana/Fleet editing or manual asset API
calls are part of the supported path.

## Component verification

Maintainers use `watchmyai self-check` for the packaged-resource check. Product deployment and
current-alert verification remain the root quick-start workflow.

See the project [architecture](../docs/ARCHITECTURE.md) for deployment and trust boundaries. Runtime
details are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
[`docs/POLICY_MODEL.md`](docs/POLICY_MODEL.md),
[`docs/SIGNED_POLICY_DISTRIBUTION.md`](docs/SIGNED_POLICY_DISTRIBUTION.md), and
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).
