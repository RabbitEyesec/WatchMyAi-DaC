#!/usr/bin/env python3
"""Build and verify the deterministic complete WatchMyAI source archive."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_SOURCE_ARCHIVE_BYTES = 10 * 1024 * 1024
FORBIDDEN_PARTS = {
    ".cache",
    ".claude",
    ".codex",
    ".continue",
    ".cursor",
    ".direnv",
    ".git",
    ".idea",
    ".local-evidence",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".vscode",
    "__MACOSX",
    "__pycache__",
    "build",
    "credentials",
    "dist",
    "htmlcov",
    "local-reports",
    "logs",
    "node_modules",
    "queue",
    "runtime",
    "secrets",
    "tmp-screenshots",
    "venv",
}
FORBIDDEN_NAMES = {
    ".DS_Store",
    ".env",
    ".envrc",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "Thumbs.db",
    "desktop.ini",
    "id_ed25519",
    "id_rsa",
}
FORBIDDEN_SUFFIXES = {
    ".bak",
    ".db",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
    ".tmp",
    ".zip",
}
REQUIRED_FILES = {
    ".env.example",
    "LICENSE",
    "QUICKSTART.md",
    "README.md",
    "VERSION",
    "deployment/rules_schema_1.1.0.ndjson",
    "detection-rules/detections/manifest.yml",
    "detection-rules/tests/fixtures/manifest.json",
    "docs/DETECTION_RULES.md",
    "docs/assets/screenshots/elastic-watchmyai-alerts.png",
    "docs/assets/screenshots/elastic-watchmyai-events.png",
    "pyproject.toml",
    "scripts/install/install.ps1",
    "scripts/install/install.sh",
    "telemetry-gateway/deployment/elastic/load-assets.sh",
    "telemetry-gateway/src/watchmyai/__init__.py",
}


def _has_git_head(root: Path) -> bool:
    if not (root / ".git").is_dir():
        return False
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode == 0


def _is_forbidden(relative: Path) -> bool:
    parts = set(relative.parts)
    if parts & FORBIDDEN_PARTS:
        return True
    if relative.parts and relative.parts[0] == "screenshots":
        return True
    if any(
        part.startswith(".venv") or part.startswith(".wheel-smoke") or part.endswith(".egg-info")
        for part in parts
    ):
        return True
    name = relative.name
    lower_name = name.casefold()
    if name in FORBIDDEN_NAMES or lower_name.startswith("~$"):
        return True
    if name != ".env.example" and (name.startswith(".env.") or name.startswith(".secrets")):
        return True
    if name != ".env.example" and (name.endswith(".env") or name.startswith(".env")):
        return True
    if Path(name).suffix.casefold() in FORBIDDEN_SUFFIXES:
        return True
    if "alert-export" in lower_name or "validation-report" in lower_name or "validation report" in lower_name:
        return True
    if lower_name.startswith("screenshot"):
        return True
    return False


def release_files(root: Path = ROOT) -> list[Path]:
    root = root.resolve()
    if _has_git_head(root):
        raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
        candidates = [root / item.decode("utf-8") for item in raw.split(b"\0") if item]
    else:
        candidates = list(root.rglob("*"))
    selected: dict[str, Path] = {}
    for path in candidates:
        relative = path.relative_to(root)
        if _is_forbidden(relative):
            continue
        if path.is_symlink():
            raise RuntimeError(f"source archive refuses symbolic link: {relative}")
        if not path.is_file():
            continue
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError(f"unsafe source path: {relative}")
        name = relative.as_posix()
        if name in selected:
            raise RuntimeError(f"duplicate source archive path: {name}")
        selected[name] = path
    return [selected[name] for name in sorted(selected)]


def build(output: Path, *, root: Path = ROOT) -> tuple[int, int, str]:
    root = root.resolve()
    output = output.resolve()
    files = release_files(root)
    names = {path.relative_to(root).as_posix() for path in files}
    missing = sorted(REQUIRED_FILES - names)
    if missing:
        raise RuntimeError("source archive is missing required files: " + ", ".join(missing))
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for path in files:
                relative = path.relative_to(root).as_posix()
                info = zipfile.ZipInfo(relative, date_time=FIXED_ZIP_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                executable = bool(path.stat().st_mode & stat.S_IXUSR)
                mode = 0o100755 if executable else 0o100644
                info.external_attr = (mode & 0xFFFF) << 16
                archive.writestr(info, path.read_bytes(), compresslevel=9)
        size = temporary.stat().st_size
        if size > MAX_SOURCE_ARCHIVE_BYTES:
            raise RuntimeError(
                f"source archive is {size} bytes; v1.0.0 sanity limit is {MAX_SOURCE_ARCHIVE_BYTES} bytes"
            )
        temporary.replace(output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    verify(output)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return len(files), output.stat().st_size, digest


def verify(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if names != sorted(names):
            raise RuntimeError("source archive entries are not deterministically ordered")
        if len(names) != len(set(names)):
            raise RuntimeError("source archive contains duplicate entries")
        unsafe = []
        for name in names:
            archive_path = Path(name)
            if archive_path.is_absolute() or ".." in archive_path.parts or _is_forbidden(archive_path):
                unsafe.append(name)
        if unsafe:
            raise RuntimeError("source archive contains unsafe entries: " + ", ".join(unsafe[:10]))
        bad = archive.testzip()
        if bad:
            raise RuntimeError(f"source archive CRC check failed: {bad}")


def main() -> int:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / f"WatchMyAI-v{version}-source.zip",
    )
    args = parser.parse_args()
    count, size, digest = build(args.output)
    print(f"PASS: deterministic source archive contains {count} files ({size} bytes): {args.output}")
    print(f"SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
