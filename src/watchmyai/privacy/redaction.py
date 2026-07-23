"""Configurable secret redaction applied to every event before export.

Defaults redact API keys, passwords, bearer tokens, cookies, SSH private
keys, environment secrets, and authorization headers. Operators can extend
or narrow the rule set via their generated redaction.yml; disabling redaction
entirely requires an explicit opt-out in that file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class RedactionRule:
    name: str
    pattern: str
    replacement: str = ""
    _re: re.Pattern[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self._re = re.compile(self.pattern, re.IGNORECASE)
        if not self.replacement:
            self.replacement = f"[REDACTED:{self.name}]"


DEFAULT_RULES: list[RedactionRule] = [
    RedactionRule(
        "ssh_private_key",
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    ),
    RedactionRule("anthropic_api_key", r"sk-ant-[A-Za-z0-9_\-]{16,}"),
    RedactionRule("openai_api_key", r"sk-(proj-)?[A-Za-z0-9_\-]{20,}"),
    RedactionRule("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
    RedactionRule("github_token", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    RedactionRule("slack_token", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    RedactionRule("bearer_token", r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/=]{8,}"),
    RedactionRule(
        "authorization_header",
        r"(?im)^(authorization|proxy-authorization)\s*:\s*.+$",
        "[REDACTED:authorization_header]",
    ),
    RedactionRule("cookie_header", r"(?im)^(cookie|set-cookie)\s*:\s*.+$", "[REDACTED:cookie_header]"),
    RedactionRule(
        "keyvalue_secret",
        r"(?i)\b(api[_-]?key|apikey|secret|password|passwd|pwd|token|access[_-]?key)\b(\s*[=:]\s*)(\"[^\"]+\"|'[^']+'|\S+)",
        r"\1\2[REDACTED:keyvalue_secret]",
    ),
]

# Environment variable names whose values are always redacted.
DEFAULT_ENV_KEY_PATTERNS = [
    r".*_API_KEY$",
    r".*_SECRET.*",
    r".*_TOKEN$",
    r".*PASSWORD.*",
    r"^AWS_(SECRET_ACCESS_KEY|SESSION_TOKEN)$",
]


class Redactor:
    def __init__(
        self,
        rules: list[RedactionRule] | None = None,
        env_key_patterns: list[str] | None = None,
        enabled: bool = True,
    ):
        self.rules = rules if rules is not None else list(DEFAULT_RULES)
        patterns = env_key_patterns or DEFAULT_ENV_KEY_PATTERNS
        self.env_key_res = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.enabled = enabled

    @classmethod
    def from_config(cls, path: str | Path | None = None) -> Redactor:
        """Build from an operator redaction file; fall back to safe defaults."""
        if path is None or not Path(path).exists():
            return cls()
        raw = yaml.safe_load(Path(path).read_text("utf-8")) or {}
        rules = list(DEFAULT_RULES) if raw.get("include_defaults", True) else []
        for extra in raw.get("rules", []) or []:
            rules.append(RedactionRule(extra["name"], extra["pattern"], extra.get("replacement", "")))
        disabled = set(raw.get("disable_rules", []) or [])
        rules = [r for r in rules if r.name not in disabled]
        env_patterns = raw.get("env_key_patterns") or DEFAULT_ENV_KEY_PATTERNS
        return cls(rules=rules, env_key_patterns=env_patterns, enabled=bool(raw.get("enabled", True)))

    # ------------------------------------------------------------------
    def redact_text(self, text: str) -> tuple[str, list[str]]:
        if not self.enabled or not text:
            return text, []
        applied: list[str] = []
        for rule in self.rules:
            new_text, count = rule._re.subn(rule.replacement, text)
            if count:
                applied.append(rule.name)
                text = new_text
        return text, applied

    def redact_env(self, environ: dict[str, str]) -> tuple[dict[str, str], list[str]]:
        if not self.enabled:
            return environ, []
        out: dict[str, str] = {}
        applied: list[str] = []
        for key, value in environ.items():
            if any(r.match(key) for r in self.env_key_res):
                out[key] = "[REDACTED:env_secret]"
                if "env_secret" not in applied:
                    applied.append("env_secret")
            else:
                redacted, names = self.redact_text(value)
                out[key] = redacted
                applied.extend(n for n in names if n not in applied)
        return out, applied

    def redact_value(self, value: Any) -> tuple[Any, list[str]]:
        """Recursively redact strings inside dicts/lists."""
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            applied: list[str] = []
            out: dict[str, Any] = {}
            for key, item in value.items():
                red, names = self.redact_value(item)
                out[key] = red
                applied.extend(n for n in names if n not in applied)
            return out, applied
        if isinstance(value, list):
            applied = []
            items = []
            for item in value:
                red, names = self.redact_value(item)
                items.append(red)
                applied.extend(n for n in names if n not in applied)
            return items, applied
        return value, []

    def redact_event(self, doc: dict[str, Any]) -> dict[str, Any]:
        """Redact a full event and stamp watchmyai.redaction metadata."""
        redacted, applied = self.redact_value(doc)
        meta = redacted.setdefault("watchmyai", {}).setdefault("redaction", {})
        meta["applied"] = bool(applied)
        if applied:
            meta["rule_names"] = sorted(applied)
        return redacted
