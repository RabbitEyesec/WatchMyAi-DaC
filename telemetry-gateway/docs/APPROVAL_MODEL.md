# Approval security model

An approval is a one-time authorization for one already-decided action, not a general permission. It binds:

- session, task, agent, tool, action, request, and decision IDs;
- policy bundle ID and sequence;
- canonical payload hash and resolved target hash;
- issue/expiry time, maximum use count, and optional idempotency key;
- a hash of the operator justification.

The random bearer identifier is stored because a later hook process must consume it. It is never printed, listed, logged, or exported. Operators see only its SHA-256 reference and may use an exact hash or unique prefix.

Every persistent mutation takes an in-process lock and OS file lock, reloads current state, validates it, writes a private temporary file, fsyncs, atomically replaces the store, and fsyncs the directory. Concurrent consumers therefore produce exactly one success; later attempts produce `approval_replay`.

Statuses are pending, approved, rejected, expired, or consumed. Payload, target, identity, action, decision, or policy mismatch does not alter the binding and never releases execution. Approval requests, grants, rejections, failures, and consumption are evidence events.
