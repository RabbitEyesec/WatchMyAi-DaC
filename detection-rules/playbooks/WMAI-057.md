# WMAI-057: Access to .env Files

## Detection basis

Source: WatchMyAI schema 1.1.0 telemetry.

```text
event.dataset:"watchmyai.events" and event.action:"tool_request" and (watchmyai.tool.arguments.command:(*.env or *.env.* or *dotenv*) or watchmyai.tool.arguments.file_path:(*.env or *.env.*) or process.command_line:*.env)
```

## Triage

1. Confirm the alert's stable rule ID is `WMAI-057` and record its source event time.
2. Inspect the fields below and preserve the original source events:

- `event.action`
- `event.dataset`
- `process.command_line`
- `watchmyai.tool.arguments.command`
- `watchmyai.tool.arguments.file_path`

3. Correlate the session and action IDs with adjacent WatchMyAI records.
4. Determine whether the activity was approved, expected, and confined to its intended scope.

## Containment

If the activity is unauthorized, stop the affected session or process, isolate exposed credentials or resources, and preserve the alert and source telemetry. Do not disable the rule globally to resolve a single expected workflow.

## False-positive handling

- An outdated allowlist, workspace root, adapter capability declaration, or operator-approved administrative workflow can resemble the condition.

Use a narrowly scoped exception with an owner and expiry only after the activity is verified.

## Validation

Follow the [public verification guide](../../docs/VERIFICATION.md) for `SCN-WMAI-057`. A passing validation requires a current alert from `WMAI-057`; historical or uncorrelated alerts do not count.
