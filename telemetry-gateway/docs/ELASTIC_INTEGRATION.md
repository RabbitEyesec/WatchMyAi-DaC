# Elastic integration

`watchmyai setup` is the supported loader. It configures direct HTTPS gateway export to
`logs-watchmyai.events-default`, installs the `watchmyai-events` ILM policy, strict component
template, ingest pipeline, composable data-stream template, and data stream,
then imports the exact 20-rule pack.

The loader also attempts to import an optional data view and investigation searches. Their failure
does not block telemetry or rule installation, and v1.0.0 has no required dashboard.

The generated gateway YAML references an owner-only environment file, which in turn references the
owner-only API-key file. Credentials are not stored in gateway YAML or passed as command options.
TLS verification is enabled by default.

Setup also identifies the enrolled local Elastic Agent's Fleet policy and adds Elastic Defend using
the non-preventing Data Collection preset. This supplies native endpoint file telemetry required by
`WMAI-023` and `WMAI-024`; no manual Fleet or Kibana policy construction is required.

The lower-level `deployment/elastic/load-assets.sh` remains an internal, tested setup component. It
is not a separately supported onboarding command.
