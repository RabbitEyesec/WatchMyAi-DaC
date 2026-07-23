# Signed policy distribution runbook

## Enrollment

Transfer the initial root over an authenticated out-of-band channel. Verify organization ID and expected root key fingerprints with two operators, then run `watchmyai policy enroll-root`. Enrollment refuses an existing trust anchor; replacement requires the incident re-enrollment procedure.

## Release metadata

A release has canonical JSON envelopes for Timestamp, Snapshot, and Targets plus exact policy target bytes. Root assigns distinct Ed25519 keys/thresholds. Targets binds organization, bundle ID/version/sequence, schema, issue/expiry, minimum agent version, required capabilities, length, and SHA-256. Timestamp and Snapshot bind exact subordinate metadata.

Activation order is Timestamp → Snapshot → Targets → policy target. The client rejects duplicate keys, floats/non-finite numbers, unknown algorithms, bad/duplicate threshold signatures, organization mismatch, version rollback/reuse, expiry, future issue time, length/hash mismatch, schema/agent/capability mismatch, or failed health checks.

Expected verification rejection is reported as one sanitized operator error with a stable reason code and exit status `6` (validation failure). The CLI does not print a traceback or metadata contents, and verification remains fail closed: no candidate becomes ACTIVE after rejection.

## Rotation

Create root N+1 with `root_version == N+1`. Its envelope must satisfy the old root threshold and the new root threshold. Apply every intermediate envelope in order:

```bash
watchmyai policy rotate-root root-v2.json root-v3.json
```

Timestamp/Snapshot online keys should be rotated frequently. Targets keys should be offline or protected by a strongly authenticated release service. Root keys should be offline, separated, and threshold controlled.

## Rollback

Rollback is a new currently signed Targets authorization with rollback ID, exact from/to sequence, target bundle, reason, issue/expiry, and minimum approvals. Run normal activation with the externally verified approval count. ACTIVE may move lower, but highest-seen versions and policy sequence never decrease.

## Offline states

- `FRESH`: Timestamp and target authorizations current.
- `STALE_GRACE`: Timestamp expired but bounded grace remains and target authorization is current.
- `STALE_BLOCKED`: no trusted current/grace state; new enforcement startup must block.
- `CLOCK_UNTRUSTED`: wall clock moved backward beyond tolerance.

Every enrollment, root rotation, activation, rejection, and offline-state transition is exported as distribution evidence.
