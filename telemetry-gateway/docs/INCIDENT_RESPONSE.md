# Incident response

1. Stop or isolate the affected mediated session when execution followed DENY, approval integrity failed, the evidence chain broke, or a gateway was bypassed.
2. Preserve the evidence database, JSONL/dead-letter output, ACTIVE/LAST_KNOWN_GOOD manifests, signed metadata, adapter versions, and relevant Elastic event/alert IDs. Do not collect raw secrets into WatchMyAI telemetry.
3. Verify the per-session evidence chain and correlate request/action/decision/approval/execution IDs.
4. Confirm the root/Targets key status, bundle sequence, timestamp/target expiry, capability fingerprint, and hook/gateway route.
5. Revoke affected approval, exporter, agent, repository, cloud, or MCP credentials through their owning systems.
6. If policy is faulty, publish a new signed forward release. Use explicit rollback only when its authorization and approvals are current.
7. If a signing role key is compromised, rotate/revoke it through root metadata. A compromised root threshold requires authenticated out-of-band re-enrollment.
8. Record scope, timeline, chain verification, containment, recovery release, and follow-up classifier/rule changes. Re-run affected atomics, benign cases, and evasions before closure.
