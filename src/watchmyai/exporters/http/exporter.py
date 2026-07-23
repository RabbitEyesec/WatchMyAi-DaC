"""Generic HTTP sink: POSTs NDJSON batches to a collector endpoint.

Uses only the standard library so the gateway has no HTTP-client
dependency. Credentials come from headers supplied by the caller (which
reads them from the environment) — never hardcoded.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from watchmyai.exporters.base import ExportError, validate_export_batch

_RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


class HttpSink:
    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        opener: Any = None,  # injectable for tests
        allow_insecure: bool = False,
        verify_tls: bool = True,
        ca_file: str | None = None,
    ):
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError(f"HttpSink requires an http(s) URL, got {url!r}")
        parsed = urlparse(url)
        if (
            parsed.scheme != "https"
            and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
            and not allow_insecure
        ):
            raise ValueError("HttpSink requires HTTPS outside loopback")
        self.url = url
        self.headers = {"Content-Type": "application/x-ndjson", **(headers or {})}
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen
        self._context = (
            ssl.create_default_context(cafile=ca_file) if verify_tls else ssl._create_unverified_context()  # nosec B323
        )

    @staticmethod
    def encode(batch: list[dict[str, Any]]) -> bytes:
        lines = [json.dumps(event, separators=(",", ":"), default=str, ensure_ascii=False) for event in batch]
        return ("\n".join(lines) + "\n").encode("utf-8")

    def send(self, batch: list[dict[str, Any]]) -> None:
        validate_export_batch(batch)
        body = self.encode(batch)
        request = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
        try:
            with self._opener(
                request,
                timeout=self.timeout,
                context=self._context,
            ) as response:
                status = getattr(response, "status", 200)
                if status >= 400:
                    raise ExportError(f"HTTP {status}", retryable=status in _RETRYABLE_STATUS)
        except urllib.error.HTTPError as exc:
            raise ExportError(
                f"HTTP {exc.code}: {exc.reason}", retryable=exc.code in _RETRYABLE_STATUS
            ) from exc
        except urllib.error.URLError as exc:
            raise ExportError(f"connection failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise ExportError("request timed out") from exc
