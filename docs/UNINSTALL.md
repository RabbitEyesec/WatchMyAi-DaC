# Uninstall

Review the retention boundary, then run the supported project command:

```bash
.venv/bin/watchmyai uninstall --yes
```

The command:

1. reimports the authoritative pack with rule enablement disabled and verifies all 20 stable IDs
   are disabled;
2. removes only WatchMyAI-owned Claude Code and Codex CLI hook entries recorded by setup;
3. preserves unrelated hook settings and the timestamped backups created during installation;
4. preserves local policy, approvals, evidence chain, dead letters, and setup state; and
5. leaves Elastic templates, pipeline, data stream, historical data, optional investigation
   objects, Fleet integrations, and credentials under external operator control.

Without `--yes`, the command exits without changing setup state. A failed rule-disablement or hook
removal produces `FAIL` and retains the information needed for diagnosis.

## Purge retained local state

Only after the evidence owner approves disposal:

```bash
.venv/bin/watchmyai uninstall --yes --purge-runtime
```

The command resolves the configured runtime home and refuses `/`, the user home, the repository,
its parent, or a path inside the repository. Deletion is not recoverable. Confirm the path in
`$WATCHMYAI_HOME/setup-state.json` and preserve required evidence before purging.

## External cleanup

WatchMyAI does not delete indexed telemetry, alerts, data streams, Fleet package policies, or
external credentials. Remove or retain them through the organization's change, evidence, and
credential processes. Revoke a no-longer-needed API key even when local runtime evidence is kept.

For reinstall behavior, see [Installation](INSTALLATION.md). For failures, see
[Troubleshooting](TROUBLESHOOTING.md).
