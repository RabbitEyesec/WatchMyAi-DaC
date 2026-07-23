# Runtime architecture

`WatchMyAIRuntime.process` is the single enforcement orchestration path:

1. Record the secret-safe `tool.requested` event.
2. Classify command, paths, repository, destination, and MCP identity.
3. Resolve the registered adapter capability and requested obligations.
4. Evaluate the active policy bundle in the PDP.
5. Record `decision.created` with every matching rule and the winning evidence.
6. If required, create/find and atomically consume a strongly bound approval.
7. Let the PEP release, block, hold, or fail closed.
8. Record execution evidence only when the mediated operation is actually released/observed.

The gateway normalizes and redacts before chaining. The chain database stores the canonical final event, its per-session sequence, previous hash, and event hash in a SQLite WAL transaction. Exporters receive that same chained object.

The PDP cache key includes the canonical payload hash, bundle version, and adapter capability fingerprint. Capability generation or policy activation invalidates the cache. Explicit signed rollback may activate a lower sequence, but the distribution client's highest-seen security state never decreases.

Long-running services should construct a distribution client with an activation callback that invokes `pdp.activate(bundle, verified_rollback=rollback)`; short-lived hooks load ACTIVE for each invocation.

Failure rule: a pre-tool request is never released on an exception, missing ACTIVE policy, uncovered adapter/tool pair, unavailable required obligation, invalid approval, or unusable evidence path.
