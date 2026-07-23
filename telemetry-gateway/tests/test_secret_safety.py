from __future__ import annotations

import json
import os

import pytest

from watchmyai.adapters.claude_code.adapter import parse_hook_payload
from watchmyai.exporters.elastic.exporter import ElasticSink, elastic_settings_from_env
from watchmyai.exporters.http.exporter import HttpSink
from watchmyai.normalization.normalizer import Normalizer


def test_prompt_lifecycle_emits_only_hash():
    # Assemble the token so repository scanners never mistake this synthetic value for a credential.
    secret = "sk-" + "proj-" + "this-must-never-appear-in-telemetry"
    partial = parse_hook_payload(
        {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "session-1",
            "prompt": f"use {secret} to deploy",
        }
    )[0]
    event = Normalizer().normalize(partial)
    rendered = json.dumps(event)
    assert secret not in rendered
    assert event["watchmyai"]["task"]["hash"].startswith("sha256:")


def test_remote_exporters_require_https_by_default():
    with pytest.raises(ValueError, match="HTTPS"):
        HttpSink("http://collector.example/events")
    with pytest.raises(ValueError, match="HTTPS"):
        ElasticSink("http://elastic.example:9200")
    with pytest.raises(ValueError, match="TLS verification"):
        ElasticSink("https://elastic.example:9200", verify_tls=False)
    assert HttpSink("http://127.0.0.1:8080/events")
    assert ElasticSink("http://localhost:9200")


def test_elastic_environment_supports_owner_only_key_file_and_tls_switch(tmp_path):
    key_file = tmp_path / "elastic-api-key"
    key_file.write_text("synthetic-redaction-test-value\n", "utf-8")
    key_file.chmod(0o600)
    settings = elastic_settings_from_env(
        {
            "ELASTICSEARCH_URL": "https://elastic.example.invalid:9200",
            "ELASTIC_AUTH_METHOD": "api_key",
            "ELASTIC_API_KEY_FILE": str(key_file),
            "TLS_VERIFY": "false",
        }
    )
    assert settings["api_key"] == "synthetic-redaction-test-value"
    assert settings["verify_tls"] is False


def test_elastic_environment_rejects_permissive_key_file(tmp_path):
    if os.name == "nt":
        pytest.skip("owner-only key file enforcement is a POSIX-only permission check")
    key_file = tmp_path / "elastic-api-key"
    key_file.write_text("synthetic-redaction-test-value\n", "utf-8")
    key_file.chmod(0o644)

    with pytest.raises(ValueError, match="owner-only"):
        elastic_settings_from_env(
            {
                "ELASTICSEARCH_URL": "https://elastic.example.invalid:9200",
                "ELASTIC_AUTH_METHOD": "api_key",
                "ELASTIC_API_KEY_FILE": str(key_file),
            }
        )
