#!/usr/bin/env python3
"""Read-only staging smoke test for imported WatchMyAI Elastic rules."""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

from rulelib import ROOT, load_json, load_metadata

sys.path.insert(0, str(ROOT.parent / "scripts"))

from utilities.release_contract import (  # noqa: E402
    parse_bool,
    resolve_repository_path,
    validate_url,
)


def main() -> int:
    kibana_url = os.environ.get("KIBANA_URL", "").rstrip("/")
    api_key = os.environ.get("ELASTIC_API_KEY", "")
    api_key_file = os.environ.get("ELASTIC_API_KEY_FILE", "")
    space = os.environ.get("KIBANA_SPACE") or "default"
    if not api_key and api_key_file:
        api_key = resolve_repository_path(api_key_file).read_text("utf-8").strip()
    if not kibana_url or not api_key:
        print(
            "KIBANA_URL and ELASTIC_API_KEY or ELASTIC_API_KEY_FILE are required",
            file=sys.stderr,
        )
        return 2
    try:
        kibana_url = validate_url("KIBANA_URL", kibana_url)
        verify = parse_bool(os.environ.get("TLS_VERIFY", "true"), name="TLS_VERIFY")
    except ValueError as exc:
        print(f"Invalid staging configuration: {exc}", file=sys.stderr)
        return 2
    hostname = urllib.parse.urlparse(kibana_url).hostname
    if not verify and hostname not in {"127.0.0.1", "::1", "localhost"}:
        print("TLS_VERIFY=false is allowed only for loopback Kibana", file=sys.stderr)
        return 2
    ca_file = os.environ.get("ELASTIC_CA_CERT", "")
    context = (
        ssl.create_default_context(cafile=str(resolve_repository_path(ca_file)))
        if verify and ca_file
        else ssl.create_default_context()
        if verify
        # Insecure contexts are reachable only for explicitly selected loopback URLs.
        else ssl._create_unverified_context()  # nosec B323
    )
    prefix = "" if space == "default" else f"/s/{urllib.parse.quote(space, safe='')}"
    deployable_ids = {rule["rule_id"] for rule in load_metadata() if rule["deployment"]["packageable"]}
    expected = {
        rule_id: load_json(ROOT / "detections" / "elastic" / f"{rule_id}.json")
        for rule_id in sorted(deployable_ids)
    }
    failures: list[str] = []
    for rule_id, packaged in expected.items():
        query = urllib.parse.urlencode({"rule_id": rule_id})
        request = urllib.request.Request(
            f"{kibana_url}{prefix}/api/detection_engine/rules?{query}",
            headers={"Authorization": f"ApiKey {api_key}", "kbn-xsrf": "true"},
        )
        try:
            # validate_url constrains the base to HTTP(S), with HTTP limited to loopback.
            with urllib.request.urlopen(  # nosec B310
                request, timeout=30, context=context
            ) as response:
                deployed = json.load(response)
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            failures.append(f"{rule_id}: {exc}")
            continue
        if deployed.get("rule_id") != rule_id:
            failures.append(f"{rule_id}: stable rule_id mismatch")
        if deployed.get("enabled") is not False:
            failures.append(f"{rule_id}: imported rule is unexpectedly enabled")
        if deployed.get("query") != packaged.get("query"):
            failures.append(f"{rule_id}: deployed query differs from package")
        if deployed.get("type") != packaged.get("type"):
            failures.append(f"{rule_id}: deployed rule type differs from package")
        if deployed.get("threshold") != packaged.get("threshold"):
            failures.append(f"{rule_id}: deployed threshold differs from package")
    if failures:
        print("Elastic smoke test failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"PASS: {len(expected)} imported rules exist, are disabled and match packaged queries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
