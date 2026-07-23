# Security policy

## Supported version

Security fixes target the current v1.0.x release line. Historical engineering records and deferred
research rules are not deployable releases.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, private telemetry, or customer
data. After publication, contact the repository owner through the private security channel they
identify for the GitHub repository. No verified reporting address or GitHub private-vulnerability
configuration is recorded in this checkout, so this document does not invent one.

Include the affected version, impact, affected boundary, minimal reproduction steps, and any known
mitigation. Replace live secrets and customer data with neutral values. Coordinate public
disclosure only after the owner has had an opportunity to assess and fix the issue.

## Secrets and sensitive telemetry

- Never commit `.env`, API keys, passwords, enrollment tokens, private keys, runtime databases,
  approval bearer identifiers, raw Elastic exports, or agent logs.
- Use credential-free HTTPS URLs and verified TLS. Scope credentials to the operations required by
  setup, export, verification, and validation.
- API keys supplied to setup are moved into an owner-only runtime file. Basic-auth credentials, when
  selected, remain in the generated owner-only configuration and need equivalent protection.
- Keep `WATCHMYAI_HOME`, dead-letter output, approval state, policy state, and evidence databases
  outside the repository with owner-only permissions.
- Schema 1.1.0 retains redacted command and path values required by the active rules. Treat live
  telemetry and alerts as sensitive operational evidence.
- Sanitize screenshots by removing credentials, personal data, private hosts, private IP addresses,
  unrelated tabs, and user-specific paths. Do not alter results or rule IDs.

## Policy and validation boundaries

Production policy trust begins with an organization-controlled signed root. WatchMyAI verifies
signed policy releases and fails closed; it does not create production signing authority. Protect
the root, role keys, release process, and rollback approvals outside this repository.

Run live validation only in the generated disposable workspace with fake test credentials and
controlled destinations. WatchMyAI does not provision or secure Elasticsearch, Kibana, Fleet
Server, Elastic Agent, host access, backups, or credential lifecycle; those remain the operator's
responsibility.

If a secret is committed, revoke it first. Then remove it from current files and coordinate any
history remediation through the repository owner's incident process.
