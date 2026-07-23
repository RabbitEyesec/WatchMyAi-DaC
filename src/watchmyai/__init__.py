"""WatchMyAI telemetry gateway runtime."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _project_version() -> str:
    """Read the repository version in source trees and package metadata when installed."""
    source_version = Path(__file__).resolve().parents[2] / "VERSION"
    if source_version.is_file():
        return source_version.read_text(encoding="utf-8").strip()
    try:
        return version("WatchMyAI")
    except PackageNotFoundError:
        return "0+unknown"


__version__ = _project_version()
