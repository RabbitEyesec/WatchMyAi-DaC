# Policy model 1.2

Bundles use only `policy_bundle_id`, `policy_bundle_version`, and monotonic integer `policy_sequence`. `bundle_id` and a bundle-level `policy_version` are rejected.

Decisions are exactly `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, and `MONITOR`. Modes are separate: `observe`, `monitor`, `restrict`, and `strict`. Strict mode must use `default_effect: DENY`.

Every rule has a stable ID/version, integer priority, effect, non-empty match, reason code, and zero or more canonical obligations. All matching rules are retained as evidence. Ordering is deterministic:

1. `DENY` before `REQUIRE_APPROVAL` before `MONITOR` before `ALLOW`.
2. Higher priority first.
3. Lexical policy ID and version as stable tie breakers.

The supported obligations are:

- `AUDIT_FULL`
- `AUDIT_METADATA_ONLY`
- `REDACT_ARGUMENTS`
- `REDACT_RESULT`
- `CAPTURE_ARGUMENT_HASH`
- `REQUIRE_EXECUTION_RECEIPT`
- `REQUIRE_APPROVAL_RECEIPT`
- `REQUIRE_JUSTIFICATION`
- `TERMINATE_SESSION_ON_FAILURE`
- `EMIT_HIGH_SEVERITY_ALERT`
- `NOTIFY_SECURITY`

Unknown obligations fail bundle loading. An obligation whose adapter capability is absent causes a documented optional fallback only for argument hashing; otherwise evaluation denies. A `REQUIRE_APPROVAL` effect also requires native approval capability.

Production policy is loaded only from signed ACTIVE state. The YAML file in `examples/policies` is a development example and needs the explicit unsigned opt-in.
