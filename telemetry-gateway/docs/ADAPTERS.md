# Adapter contracts

## Claude Code

The installer merges WatchMyAI command-hook groups into Claude settings and covers `PreToolUse`, permission, post-tool, session, subagent, compaction, cwd, file, and configuration lifecycle events. `PreToolUse` is the enforcement boundary: the adapter validates the payload, creates a `ToolRequest`, invokes the runtime, and returns the native allow/deny envelope. Raw arguments and results are hashed/redacted before telemetry. The registered capability covers all current Claude tool classes exposed through the hook.

## Codex CLI

The installer adds WatchMyAI groups to `~/.codex/hooks.json`; it does not use or replace the older single `notify` setting. `PreToolUse` is the blocking boundary for Bash, `apply_patch`, MCP, and covered local function tools. Permission and post-tool lifecycle records add approval/execution evidence. Rollout JSONL is an optional secondary forensic source, never the policy enforcement contract.

Some hosted tools and specialized execution paths may not invoke local lifecycle hooks. Such paths are outside the declared capability and need endpoint or service-side controls.

## MCP

`watchmyai mcp-gateway` is a protocol-aware stdio JSON-RPC proxy. It fingerprints the server command, evaluates connection and `tools/call` requests before forwarding, preserves request IDs, and returns a JSON-RPC error for blocked calls. Server responses add execution evidence without logging tool arguments/results.

This release does not claim deterministic mediation for direct, SSE, or Streamable HTTP MCP routes. Clients must be configured so the stdio gateway is the sole route; otherwise `gateway_bypassed` is a correlated observation/capability gap.

## Generic sources

`watchmyai run` and process discovery report session/process metadata and hashes only. They do not capture command-line arguments, do not create policy decisions for child processes, and do not claim prevention. Attribution is capped below confirmed unless a structured native adapter supplies the request.
