"""Path resolution and segment-aware policy classification."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_RESTRICTED_RESOURCE_NAMES = {"authorized_keys", "shadow", "sudoers"}


@dataclass(frozen=True)
class PathClassification:
    requested: str
    resolved: str
    approved_workspace: bool
    restricted: bool
    sensitivity_class: str


def resolve_paths(paths: list[str], cwd: str | None) -> list[str]:
    base = Path(cwd or os.getcwd())
    return [
        str(
            (base / path).resolve(strict=False)
            if not Path(path).is_absolute()
            else Path(path).resolve(strict=False)
        )
        for path in paths
    ]


def _inside(path: str, root: str) -> bool:
    try:
        Path(path).resolve(strict=False).relative_to(Path(root).resolve(strict=False))
        return True
    except ValueError:
        return False


def _sensitivity(path: str) -> str:
    p = path.replace("\\", "/").lower()
    name = p.rsplit("/", 1)[-1]
    if name in {".env.example", ".env.sample", ".env.template"}:
        return "safe_template"
    if name == ".env" or name.startswith(".env."):
        return "env_secret"
    if (
        "/.ssh/" in f"/{p.strip('/')}/"
        and (name.startswith("id_") or name.endswith((".pem", ".key", ".ppk")))
        and not name.endswith(".pub")
    ):
        return "ssh_private_key"
    if any(part in p for part in ("/.aws/credentials", "/.config/gcloud/", "/.azure/")):
        return "cloud_credential"
    return "ordinary"


def classify_paths(
    requested: list[str],
    resolved: list[str],
    approved_roots: list[str],
    restricted_roots: list[str],
) -> list[PathClassification]:
    result = []
    for index, path in enumerate(resolved):
        raw = requested[index] if index < len(requested) else path
        normalized_name = Path(path.replace("\\", "/")).name.casefold()
        result.append(
            PathClassification(
                requested=raw,
                resolved=path,
                approved_workspace=any(_inside(path, root) for root in approved_roots),
                restricted=(
                    normalized_name in _RESTRICTED_RESOURCE_NAMES
                    or any(_inside(path, root) for root in restricted_roots)
                ),
                sensitivity_class=_sensitivity(path),
            )
        )
    return result
