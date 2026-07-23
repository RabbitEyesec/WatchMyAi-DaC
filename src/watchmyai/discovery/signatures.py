"""Signature catalogue loader. Signatures live in YAML, never in code."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Signature:
    agent_id: str
    vendor: str
    product: str
    executable_names: list[str] = field(default_factory=list)
    process_patterns: list[str] = field(default_factory=list)
    install_paths: list[str] = field(default_factory=list)
    config_paths: list[str] = field(default_factory=list)
    parent_process_patterns: list[str] = field(default_factory=list)
    env_markers: list[str] = field(default_factory=list)
    adapter: str = "generic_cli"
    confidence: float = 0.5

    _process_res: list[re.Pattern[str]] = field(default_factory=list, repr=False)
    _parent_res: list[re.Pattern[str]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._process_res = [re.compile(p, re.IGNORECASE) for p in self.process_patterns]
        self._parent_res = [re.compile(p, re.IGNORECASE) for p in self.parent_process_patterns]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Signature:
        return cls(
            agent_id=raw["agent_id"],
            vendor=raw.get("vendor", "unknown"),
            product=raw.get("product", raw["agent_id"]),
            executable_names=[n.lower() for n in raw.get("executable_names", [])],
            process_patterns=raw.get("process_patterns", []),
            install_paths=raw.get("install_paths", []),
            config_paths=raw.get("config_paths", []),
            parent_process_patterns=raw.get("parent_process_patterns", []),
            env_markers=raw.get("env_markers", []),
            adapter=raw.get("adapter", "generic_cli"),
            confidence=float(raw.get("confidence", 0.5)),
        )


@dataclass
class UnknownHeuristics:
    cmdline_patterns: list[str] = field(default_factory=list)
    env_markers: list[str] = field(default_factory=list)
    _res: list[re.Pattern[str]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._res = [re.compile(p, re.IGNORECASE) for p in self.cmdline_patterns]


@dataclass
class SignatureCatalog:
    signatures: list[Signature]
    unknown: UnknownHeuristics
    schema_version: int = 1

    @classmethod
    def load(cls, path: str | Path) -> SignatureCatalog:
        raw = yaml.safe_load(Path(path).read_text("utf-8")) or {}
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SignatureCatalog:
        signatures = [Signature.from_dict(s) for s in raw.get("signatures", [])]
        heur = raw.get("unknown_agent_heuristics", {}) or {}
        unknown = UnknownHeuristics(
            cmdline_patterns=heur.get("cmdline_patterns", []),
            env_markers=heur.get("env_markers", []),
        )
        return cls(signatures=signatures, unknown=unknown, schema_version=int(raw.get("schema_version", 1)))

    @classmethod
    def load_default(cls) -> SignatureCatalog:
        """Load the operator copy, falling back to the wheel resource."""
        user_copy = Path.home() / ".watchmyai" / "agent_signatures.yml"
        if user_copy.exists():
            return cls.load(user_copy)
        text = (
            resources.files("watchmyai.resources")
            .joinpath("agent_signatures.yml")
            .read_text(encoding="utf-8")
        )
        return cls.from_dict(yaml.safe_load(text) or {})
