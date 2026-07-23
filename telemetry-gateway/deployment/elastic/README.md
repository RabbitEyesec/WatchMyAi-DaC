# Telemetry Elastic deployment assets

This directory owns the reviewed Elastic assets for WatchMyAI telemetry: the component template,
index template, ingest pipeline, ILM policy, and optional Kibana data view/searches. The root setup
workflow consumes these assets to configure the validated Elastic deployment.

The JSON, NDJSON, and `load-assets.sh` loader are source assets; this directory contains no
generated release outputs. The loader name describes its executable purpose and is intentionally
separate from this README. Installed cluster objects and packaged copies are derived artefacts.
Edit source assets manually only through a reviewed telemetry-schema or deployment change, then run
the repository schema, package, and preflight validation. The optional saved-object import is not
a readiness gate and contains no dashboard. Do not edit installed cluster copies as a substitute
for changing the source.
