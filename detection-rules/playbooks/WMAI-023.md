# WMAI-023: Bulk File Modification

## Detection basis

Source: ECS endpoint file telemetry.

```text
event.category:file and event.type:(change or creation)
```

Threshold: 50 events grouped by `process.entity_id`.

## Triage

1. Confirm the alert's stable rule ID is `WMAI-023` and record its source event time.
2. Inspect the fields below and preserve the original source events:

- `event.category`
- `event.type`
- `process.entity_id`

3. Trace the run-ID file path to one `process.entity_id`, then match that entity in `kibana.alert.threshold_result.terms`.
4. Determine whether the activity was approved, expected, and confined to its intended scope.

## Containment

If the activity is unauthorized, stop the affected session or process, isolate exposed credentials or resources, and preserve the alert and source telemetry. Do not disable the rule globally to resolve a single expected workflow.

## False-positive handling

- Approved maintenance or controlled laboratory activity can resemble bulk file modification.

Use a narrowly scoped exception with an owner and expiry only after the activity is verified.

## Validation

Follow the [public verification guide](../../docs/VERIFICATION.md) for `SCN-WMAI-023`. A passing validation requires a current alert from `WMAI-023`; historical or uncorrelated alerts do not count.
