"""Elasticsearch bulk-API sink.

Credentials are read from the environment (ELASTICSEARCH_URL plus ELASTIC_API_KEY
or ELASTIC_USERNAME/ELASTIC_PASSWORD) — never from code or config files.
Partial bulk failures are surfaced as retryable errors with the per-item
reasons so nothing is silently dropped.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from watchmyai.exporters.base import ExportError, validate_export_batch

DEFAULT_DATA_STREAM = "logs-watchmyai.events-default"

_RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


def elastic_settings_from_env(env: dict[str, str] | None = None) -> dict[str, Any]:
    """Read Elastic connection settings from the environment.

    Returns {} when ELASTICSEARCH_URL/ELASTIC_URL is unset (not configured).
    """
    env = env if env is not None else dict(os.environ)
    url = env.get("ELASTICSEARCH_URL", env.get("ELASTIC_URL", "")).strip()
    if not url:
        return {}
    settings: dict[str, Any] = {"url": url.rstrip("/")}
    method = env.get("ELASTIC_AUTH_METHOD", "api_key").strip().lower()
    if method == "api_key":
        api_key = env.get("ELASTIC_API_KEY", "").strip()
        api_key_file = env.get("ELASTIC_API_KEY_FILE", "").strip()
        if not api_key and api_key_file:
            key_path = Path(api_key_file).expanduser()
            if os.name != "nt" and key_path.stat().st_mode & 0o077:
                raise ValueError(f"ELASTIC_API_KEY_FILE must be owner-only (mode 0600): {key_path}")
            api_key = key_path.read_text("utf-8").strip()
        if api_key:
            settings["api_key"] = api_key
    elif method == "basic" and env.get("ELASTIC_USERNAME") and env.get("ELASTIC_PASSWORD"):
        settings["username"] = env["ELASTIC_USERNAME"]
        settings["password"] = env["ELASTIC_PASSWORD"]
    elif method not in {"api_key", "basic"}:
        raise ValueError("ELASTIC_AUTH_METHOD must be api_key or basic")
    tls_verify = env.get("TLS_VERIFY", "true").strip().lower()
    if tls_verify not in {"true", "false"}:
        raise ValueError("TLS_VERIFY must be true or false")
    settings["verify_tls"] = tls_verify == "true"
    if env.get("ELASTIC_CA_CERT"):
        settings["ca_file"] = str(Path(env["ELASTIC_CA_CERT"]).expanduser())
    settings["index"] = env.get("ELASTIC_INDEX", DEFAULT_DATA_STREAM)
    return settings


class ElasticSink:
    def __init__(
        self,
        url: str,
        index: str = DEFAULT_DATA_STREAM,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 15.0,
        opener: Any = None,  # injectable for tests
        allow_insecure: bool = False,
        verify_tls: bool = True,
        ca_file: str | None = None,
    ):
        parsed = urlparse(url)
        loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        if parsed.scheme != "https" and not loopback and not allow_insecure:
            raise ValueError("ElasticSink requires HTTPS outside loopback")
        if not verify_tls and not loopback and not allow_insecure:
            raise ValueError("ElasticSink requires TLS verification outside loopback")
        self.url = url.rstrip("/")
        self.index = index
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen
        self._context = (
            ssl.create_default_context(cafile=ca_file) if verify_tls else ssl._create_unverified_context()  # nosec B323
        )
        self.headers = {"Content-Type": "application/x-ndjson"}
        if api_key:
            self.headers["Authorization"] = f"ApiKey {api_key}"
        elif username and password:
            token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
            self.headers["Authorization"] = f"Basic {token}"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None, **kwargs: Any) -> ElasticSink:
        settings = elastic_settings_from_env(env)
        if not settings:
            raise ExportError(
                "ELASTICSEARCH_URL is not set; Elastic export is not configured",
                retryable=False,
            )
        return cls(
            url=settings["url"],
            index=settings.get("index", DEFAULT_DATA_STREAM),
            api_key=settings.get("api_key"),
            username=settings.get("username"),
            password=settings.get("password"),
            verify_tls=settings.get("verify_tls", True),
            ca_file=settings.get("ca_file"),
            **kwargs,
        )

    # ------------------------------------------------------------------
    def format_bulk(self, batch: list[dict[str, Any]]) -> bytes:
        """NDJSON bulk body: a create action line before each document."""
        lines: list[str] = []
        for event in batch:
            lines.append(json.dumps({"create": {"_index": self.index}}, separators=(",", ":")))
            lines.append(
                json.dumps(
                    event,
                    separators=(",", ":"),
                    default=str,
                    ensure_ascii=False,
                )
            )
        return ("\n".join(lines) + "\n").encode("utf-8")

    def send(self, batch: list[dict[str, Any]]) -> None:
        validate_export_batch(batch)
        body = self.format_bulk(batch)
        request = urllib.request.Request(f"{self.url}/_bulk", data=body, headers=self.headers, method="POST")
        try:
            with self._opener(
                request,
                timeout=self.timeout,
                context=self._context,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ExportError(
                f"bulk HTTP {exc.code}: {exc.reason}", retryable=exc.code in _RETRYABLE_STATUS
            ) from exc
        except urllib.error.URLError as exc:
            raise ExportError(f"connection failed: {exc.reason}") from exc
        except (TimeoutError, json.JSONDecodeError) as exc:
            raise ExportError(f"bulk response error: {exc}") from exc
        if payload.get("errors"):
            reasons = []
            for item in payload.get("items", []):
                info = item.get("create") or item.get("index") or {}
                if info.get("error"):
                    reasons.append(str(info["error"].get("reason", "unknown")))
            raise ExportError(f"bulk partial failure: {reasons[:3]}")

    def test_connection(self) -> dict[str, Any]:
        """GET / to verify reachability and auth. Raises ExportError on failure."""
        request = urllib.request.Request(self.url + "/", headers=self.headers, method="GET")
        try:
            with self._opener(
                request,
                timeout=self.timeout,
                context=self._context,
            ) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ExportError(
                f"connection test failed: HTTP {exc.code} {exc.reason}", retryable=False
            ) from exc
        except urllib.error.URLError as exc:
            raise ExportError(f"connection test failed: {exc.reason}", retryable=False) from exc
