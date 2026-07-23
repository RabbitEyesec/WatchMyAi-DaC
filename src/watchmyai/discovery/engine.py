"""Discovery engine: classify processes as known agents, unknown AI agents,
or non-agents, with confidence-scored attribution.

Attribution rules (see docs/AGENT_DISCOVERY.md):
- signature matches can reach at most "strong" — process-level evidence alone
  never proves AI causation, so "confirmed" is reserved for deep adapters
  that receive structured telemetry from the agent itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from watchmyai.capture.process import ProcessRecord
from watchmyai.discovery.signatures import Signature, SignatureCatalog

# Relative weight of each match method. Combined with the signature's base
# confidence via noisy-OR so multiple weak signals add up but saturate < 1.
METHOD_WEIGHTS = {
    "executable_name": 1.0,
    "process_pattern": 0.9,
    "env_marker": 0.45,
    "parent_process": 0.2,
    "install_path": 0.3,
    "config_path": 0.3,
}


def attribution_for_score(score: float) -> str:
    """Map a signature confidence score to an attribution level.

    Capped at "strong": confirmed attribution requires deep telemetry.
    """
    if score >= 0.75:
        return "strong"
    if score >= 0.5:
        return "probable"
    if score >= 0.2:
        return "weak"
    return "unknown"


@dataclass
class AgentMatch:
    agent_id: str
    vendor: str
    product: str
    adapter: str
    agent_type: str  # known_ai_agent | unknown_ai_agent
    confidence: float
    methods: list[str] = field(default_factory=list)
    process: ProcessRecord | None = None

    @property
    def attribution_level(self) -> str:
        return attribution_for_score(self.confidence)

    @property
    def discovery_method(self) -> str:
        return ",".join(self.methods) if self.methods else "none"


class DiscoveryEngine:
    def __init__(self, catalog: SignatureCatalog):
        self.catalog = catalog

    @classmethod
    def from_config(cls, path: str | Path | None = None) -> DiscoveryEngine:
        return cls(SignatureCatalog.load(path) if path else SignatureCatalog.load_default())

    # ------------------------------------------------------------------
    def match_process(self, proc: ProcessRecord) -> AgentMatch | None:
        """Best signature match for a process, then unknown-agent fallback."""
        best: AgentMatch | None = None
        for sig in self.catalog.signatures:
            match = self._match_signature(sig, proc)
            if match and (best is None or match.confidence > best.confidence):
                best = match
        if best is not None:
            return best
        return self._match_unknown(proc)

    def _match_signature(self, sig: Signature, proc: ProcessRecord) -> AgentMatch | None:
        methods: list[str] = []
        name = (proc.name or Path(proc.executable).name).lower()
        if name and name in sig.executable_names:
            methods.append("executable_name")
        haystack = f"{proc.executable} {proc.command_line}"
        if any(r.search(haystack) for r in sig._process_res):
            methods.append("process_pattern")
        if proc.environ and any(marker in proc.environ for marker in sig.env_markers):
            methods.append("env_marker")
        # Parent match is corroborating only — it never matches on its own.
        primary = {"executable_name", "process_pattern", "env_marker"}
        if not (primary & set(methods)):
            return None
        if proc.parent_name and any(r.search(proc.parent_name) for r in sig._parent_res):
            methods.append("parent_process")
        confidence = self._combine(sig.confidence, methods)
        return AgentMatch(
            agent_id=sig.agent_id,
            vendor=sig.vendor,
            product=sig.product,
            adapter=sig.adapter,
            agent_type="known_ai_agent",
            confidence=confidence,
            methods=methods,
            process=proc,
        )

    def _match_unknown(self, proc: ProcessRecord) -> AgentMatch | None:
        heur = self.catalog.unknown
        methods: list[str] = []
        haystack = f"{proc.executable} {proc.command_line}"
        if any(r.search(haystack) for r in heur._res):
            methods.append("process_pattern")
        if proc.environ and any(m in proc.environ for m in heur.env_markers):
            methods.append("env_marker")
        if "process_pattern" not in methods:
            # Env markers alone (e.g. an API key in the environment) are too
            # weak to classify a process as an AI agent.
            return None
        return AgentMatch(
            agent_id="unknown",
            vendor="unknown",
            product="unknown",
            adapter="generic_desktop",
            agent_type="unknown_ai_agent",
            confidence=0.3,
            methods=methods,
            process=proc,
        )

    @staticmethod
    def _combine(base: float, methods: list[str]) -> float:
        """Noisy-OR combination of per-method evidence."""
        miss = 1.0
        for method in methods:
            weight = METHOD_WEIGHTS.get(method, 0.1)
            miss *= 1.0 - min(base * weight, 0.95)
        return round(1.0 - miss, 4)

    # ------------------------------------------------------------------
    def scan(self, processes: list[ProcessRecord]) -> list[AgentMatch]:
        """Classify a process snapshot; non-agent processes are dropped."""
        matches = []
        for proc in processes:
            match = self.match_process(proc)
            if match is not None:
                matches.append(match)
        return matches

    def scan_installed(self, home: Path | None = None) -> list[AgentMatch]:
        """Detect installed-but-not-running agents from install/config paths."""
        home = home or Path.home()
        found: list[AgentMatch] = []
        for sig in self.catalog.signatures:
            methods = []
            for raw in sig.install_paths:
                if _expand(raw, home).exists():
                    methods.append("install_path")
                    break
            for raw in sig.config_paths:
                if _expand(raw, home).exists():
                    methods.append("config_path")
                    break
            if methods:
                found.append(
                    AgentMatch(
                        agent_id=sig.agent_id,
                        vendor=sig.vendor,
                        product=sig.product,
                        adapter=sig.adapter,
                        agent_type="known_ai_agent",
                        confidence=self._combine(sig.confidence, methods),
                        methods=methods,
                    )
                )
        return found


def _expand(raw: str, home: Path) -> Path:
    if raw.startswith("~"):
        return home / raw[2:] if raw.startswith("~/") else Path(raw).expanduser()
    return Path(raw)
