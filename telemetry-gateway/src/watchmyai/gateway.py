"""Production gateway configuration, evidence recording, and export pipeline."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from watchmyai.approval.service import ApprovalService
from watchmyai.capability.service import CapabilityRegistry
from watchmyai.evidence.chain import EvidenceChain
from watchmyai.exporters.base import ExportPipeline
from watchmyai.exporters.elastic.exporter import ElasticSink
from watchmyai.exporters.http.exporter import HttpSink
from watchmyai.exporters.jsonl.writer import JsonlSink
from watchmyai.normalization.normalizer import InvalidEventError, Normalizer
from watchmyai.policy.model import PolicyBundle
from watchmyai.privacy.redaction import Redactor
from watchmyai.runtime import WatchMyAIRuntime
from watchmyai.schema.event import validate_event

DEFAULT_HOME = Path.home() / ".watchmyai"


@dataclass
class GatewayConfig:
    home: Path = DEFAULT_HOME
    output_mode: str = "jsonl"
    jsonl_path: Path = None  # type: ignore[assignment]
    jsonl_max_bytes: int = 50 * 1024 * 1024
    jsonl_backups: int = 5
    http_url: str = ""
    http_headers_env: dict[str, str] = field(default_factory=dict)
    elastic_environment_file: Path | None = None
    dead_letter_path: Path = None  # type: ignore[assignment]
    approvals_store: Path = None  # type: ignore[assignment]
    evidence_database: Path = None  # type: ignore[assignment]
    distribution_root: Path = None  # type: ignore[assignment]
    unsigned_policy_bundle: Path = None  # type: ignore[assignment]
    allow_unsigned_policy: bool = False
    redaction_config: Path | None = None
    signatures_path: Path | None = None

    def __post_init__(self) -> None:
        self.home = Path(self.home)
        self.jsonl_path = Path(self.jsonl_path or self.home / "events" / "events.jsonl")
        self.dead_letter_path = Path(self.dead_letter_path or self.home / "dead-letter" / "events.jsonl")
        self.approvals_store = Path(self.approvals_store or self.home / "state" / "approvals.json")
        self.evidence_database = Path(self.evidence_database or self.home / "state" / "evidence.sqlite3")
        self.distribution_root = Path(self.distribution_root or self.home / "distribution")
        self.unsigned_policy_bundle = Path(self.unsigned_policy_bundle or self.home / "policy-bundle.yml")

    @property
    def config_path(self) -> Path:
        return self.home / "config.yml"

    @classmethod
    def load(cls, home: str | Path | None = None) -> GatewayConfig:
        home_path = Path(home or os.environ.get("WATCHMYAI_HOME") or DEFAULT_HOME)
        path = home_path / "config.yml"
        raw = yaml.safe_load(path.read_text("utf-8")) if path.exists() else {}
        raw = raw or {}
        output = raw.get("output", {}) or {}
        jsonl = output.get("jsonl", {}) or {}
        http = output.get("http", {}) or {}
        elastic = output.get("elastic", {}) or {}
        enforcement = raw.get("enforcement", {}) or {}

        def resolved(value: Any) -> Path | None:
            return Path(str(value)).expanduser() if value else None

        env_override = os.environ.get("WATCHMYAI_ALLOW_UNSIGNED_POLICY") == "1"
        return cls(
            home=home_path,
            output_mode=str(output.get("mode", "jsonl")),
            jsonl_path=resolved(jsonl.get("path")) or home_path / "events" / "events.jsonl",
            jsonl_max_bytes=int(jsonl.get("max_bytes", 50 * 1024 * 1024)),
            jsonl_backups=int(jsonl.get("backups", 5)),
            http_url=str(http.get("url", "")),
            http_headers_env=dict(http.get("headers_env", {}) or {}),
            elastic_environment_file=resolved(elastic.get("environment_file")),
            dead_letter_path=resolved(raw.get("dead_letter")) or home_path / "dead-letter" / "events.jsonl",
            approvals_store=resolved(raw.get("approvals_store")) or home_path / "state" / "approvals.json",
            evidence_database=resolved(raw.get("evidence_database"))
            or home_path / "state" / "evidence.sqlite3",
            distribution_root=resolved(raw.get("distribution_root")) or home_path / "distribution",
            unsigned_policy_bundle=resolved(enforcement.get("unsigned_policy_bundle"))
            or home_path / "policy-bundle.yml",
            allow_unsigned_policy=bool(enforcement.get("allow_unsigned_policy", False) or env_override),
            redaction_config=resolved(raw.get("redaction_config")) or home_path / "redaction.yml",
            signatures_path=resolved(raw.get("signatures")),
        )

    def save_default(self) -> None:
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        content = {
            "output": {
                "mode": self.output_mode,
                "jsonl": {
                    "path": str(self.jsonl_path),
                    "max_bytes": self.jsonl_max_bytes,
                    "backups": self.jsonl_backups,
                },
                "http": {"url": self.http_url, "headers_env": self.http_headers_env},
                "elastic": {
                    "environment_file": (
                        str(self.elastic_environment_file) if self.elastic_environment_file else ""
                    )
                },
            },
            "dead_letter": str(self.dead_letter_path),
            "approvals_store": str(self.approvals_store),
            "evidence_database": str(self.evidence_database),
            "distribution_root": str(self.distribution_root),
            "redaction_config": str(self.redaction_config or self.home / "redaction.yml"),
            "signatures": str(self.signatures_path or self.home / "agent_signatures.yml"),
            "enforcement": {
                "allow_unsigned_policy": False,
                "unsigned_policy_bundle": str(self.unsigned_policy_bundle),
            },
        }
        header = (
            "# WatchMyAI production gateway. Signed ACTIVE policy is required by default.\n"
            "# Credentials are read only from environment variables.\n"
        )
        self.config_path.write_text(header + yaml.safe_dump(content, sort_keys=False), "utf-8")
        self.config_path.chmod(0o600)


class Gateway:
    def __init__(self, config: GatewayConfig | None = None, normalizer: Normalizer | None = None):
        self.config = config or GatewayConfig.load()
        redactor = Redactor.from_config(self.config.redaction_config)
        self.normalizer = normalizer or Normalizer(redactor=redactor)
        self.evidence = EvidenceChain(self.config.evidence_database)
        self.pipeline = ExportPipeline(self._build_sink(), self.config.dead_letter_path)
        self.approvals = ApprovalService(store_path=self.config.approvals_store, emit=self.emit)
        self.capabilities = CapabilityRegistry()
        self._register_builtin_capabilities()

    def _register_builtin_capabilities(self) -> None:
        from watchmyai.adapters.claude_code.adapter import CAPABILITY as CLAUDE
        from watchmyai.adapters.codex_cli.adapter import CAPABILITY as CODEX
        from watchmyai.adapters.generic_mcp.gateway import CAPABILITY as MCP

        self.capabilities.register(CLAUDE)
        self.capabilities.register(CODEX)
        self.capabilities.register(MCP)

    def _build_sink(self) -> Any:
        if self.config.output_mode == "elastic":
            return ElasticSink.from_env(self.elastic_environment())
        if self.config.output_mode == "http":
            headers = {
                name: os.environ[environment]
                for name, environment in self.config.http_headers_env.items()
                if environment in os.environ
            }
            return HttpSink(self.config.http_url, headers=headers)
        return JsonlSink(
            self.config.jsonl_path, max_bytes=self.config.jsonl_max_bytes, backups=self.config.jsonl_backups
        )

    def elastic_environment(self) -> dict[str, str]:
        """Return explicit Elastic settings without persisting bearer values in YAML."""
        environment = dict(os.environ)
        path = self.config.elastic_environment_file
        if path is None:
            return environment
        if not path.is_file():
            raise RuntimeError(f"Elastic environment file does not exist: {path}")
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise RuntimeError(f"Elastic environment file must be owner-only (mode 0600): {path}")
        for number, raw in enumerate(path.read_text("utf-8").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise RuntimeError(f"invalid Elastic environment entry at {path}:{number}")
            key, value = line.split("=", 1)
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
                raise RuntimeError(f"invalid Elastic environment key at {path}:{number}")
            environment.setdefault(key, value)
        return environment

    def load_active_bundle(self) -> PolicyBundle:
        from watchmyai.distribution.store import TwoSlotStore

        store = TwoSlotStore(self.config.distribution_root / "policy-store")
        active = store.read_pointer("ACTIVE")
        if active is not None:
            return PolicyBundle.from_dict(json.loads((active / "policy.json").read_text("utf-8")))
        if self.config.allow_unsigned_policy and self.config.unsigned_policy_bundle.exists():
            return PolicyBundle.load(self.config.unsigned_policy_bundle)
        raise RuntimeError(
            "no signed ACTIVE policy; enroll and activate a signed bundle. "
            "Unsigned policy requires the explicit development-only allow_unsigned_policy setting."
        )

    def build_runtime(self) -> WatchMyAIRuntime:
        return WatchMyAIRuntime(
            self.load_active_bundle(),
            self.capabilities,
            self.approvals,
            self.evidence,
            recorder=self.record,
        )

    def record(self, partial: dict[str, Any], session_id: str) -> dict[str, Any]:
        """Normalize/redact first, then chain and export the exact master event."""
        try:
            normalized = self.normalizer.normalize(partial)
            chained = self.evidence.append(normalized, session_id)
            errors = validate_event(chained)
            if errors:
                raise InvalidEventError(errors, chained)
        except InvalidEventError as exc:
            self.pipeline._dead_letter(exc.doc, f"schema_invalid: {exc.errors[:3]}")
            raise
        self.pipeline.enqueue(chained)
        return chained

    def emit(self, partial: dict[str, Any]) -> dict[str, Any] | None:
        session_id = partial.get("watchmyai", {}).get("session", {}).get("id")
        try:
            if isinstance(session_id, str) and session_id:
                return self.record(partial, session_id)
            normalized = self.normalizer.normalize(partial)
            self.pipeline.enqueue(normalized)
            return normalized
        except InvalidEventError as exc:
            self.pipeline._dead_letter(exc.doc, f"schema_invalid: {exc.errors[:3]}")
            return None

    def emit_and_flush(self, partial: dict[str, Any]) -> dict[str, Any] | None:
        event = self.emit(partial)
        self.pipeline.flush()
        return event

    def flush(self) -> int:
        return self.pipeline.flush()

    def status(self) -> dict[str, Any]:
        active_error = None
        try:
            active = self.load_active_bundle()
            bundle = {
                "policy_bundle_id": active.policy_bundle_id,
                "policy_bundle_version": active.policy_bundle_version,
                "policy_sequence": active.policy_sequence,
            }
        except (OSError, ValueError, RuntimeError) as exc:
            bundle = None
            active_error = str(exc)
        return {
            "home": str(self.config.home),
            "output_mode": self.config.output_mode,
            "active_policy": bundle,
            "active_policy_error": active_error,
            "capabilities": sorted(self.capabilities._capabilities),
            "pipeline": self.pipeline.health(),
        }


def read_json_stdin(stream: Any) -> dict[str, Any] | None:
    try:
        value = json.loads(stream.read())
        return value if isinstance(value, dict) else None
    except (json.JSONDecodeError, TypeError):
        return None
