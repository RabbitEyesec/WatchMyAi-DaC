# Security boundaries

- WatchMyAI is not a kernel sandbox. A process that bypasses configured hooks/gateways can perform effects outside the PEP.
- Claude/Codex enforcement is only as complete as the local lifecycle-hook coverage reported by that installed version. Hosted tools and specialized paths can be outside coverage.
- The MCP gateway provides deterministic pre-execution control for its stdio route. Direct, SSE, and Streamable HTTP connections are not mediated by the stdio gateway.
- Generic wrapping/discovery supplies metadata and probable/strong process attribution, not confirmed per-action causation or blocking.
- A `DENY` stops the mediated request at that boundary; requests sent through other routes are outside it.
- Ed25519 signatures establish provenance/integrity, not policy correctness. Compromise of a signing threshold, local administrator, kernel, or trusted root is outside the design boundary.
- Offline grace trades availability for freshness. After grace the client blocks; it does not silently extend trust.
- SQLite chaining detects modification/reordering when verified, but a local administrator can delete the entire database. Export/backup controls must protect availability.
- Raw prompts, arguments, results, command lines, and bearer approval IDs are intentionally absent. Investigations use hashes and classifications unless a separate approved evidence system exists.
- The 20 production detection rules have deterministic query, schema, and corpus coverage and isolated-lab alert evidence. Recall, false-positive rate, and latency depend on the environment; tune thresholds per deployment.
- Elastic 9.4.3 is the supported compatibility baseline. For other Elastic versions, run `watchmyai verify` and `watchmyai validate` before rollout.

A deployment that cannot satisfy a required capability or obligation stays in monitor/observe mode or fails closed.
