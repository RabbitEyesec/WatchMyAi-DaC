#!/usr/bin/env python3
"""Build the complete deterministic WatchMyAI v1.0.0 release artifact set."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

try:
    from .build_source_archive import build as build_source_archive
    from .build_source_archive import release_files
except ImportError:  # direct script execution
    from build_source_archive import build as build_source_archive
    from build_source_archive import release_files

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
DEFAULT_OUTPUT = ROOT / "dist"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(content)
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
) -> None:
    completed = subprocess.run(command, cwd=cwd, env=env, check=False)
    if completed.returncode:
        raise RuntimeError(f"release command failed ({completed.returncode}): {' '.join(command)}")


def _normalize_sdist(path: Path, *, epoch: int) -> None:
    """Remove backend/host timestamps and ownership from the generated sdist."""
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as source:
        for member in source.getmembers():
            archive_path = Path(member.name)
            if archive_path.is_absolute() or ".." in archive_path.parts:
                raise RuntimeError(f"unsafe sdist member: {member.name}")
            extracted = source.extractfile(member) if member.isfile() else None
            members.append((member, extracted.read() if extracted is not None else None))

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as normalized:
        for member, content in members:
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.pax_headers = {}
            member.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
            normalized.addfile(member, io.BytesIO(content) if content is not None else None)

    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as destination:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=destination,
                compresslevel=9,
                mtime=epoch,
            ) as compressed:
                compressed.write(tar_buffer.getvalue())
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def build(output: Path) -> list[Path]:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for pattern in (
        "WatchMyAI-v*-source.zip",
        "watchmyai-*.tar.gz",
        "watchmyai-*.whl",
        "watchmyai-package-manifest.json",
        "watchmyai-rules.ndjson",
        "SHA256SUMS.txt",
    ):
        for stale in output.glob(pattern):
            stale.unlink()

    environment = dict(os.environ)
    if not environment.get("SOURCE_DATE_EPOCH"):
        completed = subprocess.run(
            ["git", "log", "-1", "--format=%ct"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        environment["SOURCE_DATE_EPOCH"] = (
            completed.stdout.strip() if completed.returncode == 0 else "946684800"
        )
    with tempfile.TemporaryDirectory(prefix="watchmyai-release-source-") as temporary:
        source_root = Path(temporary) / "repository"
        for source in release_files(ROOT):
            relative = source.relative_to(ROOT)
            destination = source_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        _run(
            [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output)],
            cwd=source_root,
            env=environment,
        )
    _run(
        [
            sys.executable,
            "detection-rules/scripts/package_rules.py",
            "--skip-validation",
            "--output-dir",
            str(output),
        ],
        env=environment,
    )
    source_archive = output / f"WatchMyAI-v{VERSION}-source.zip"
    build_source_archive(source_archive)

    wheels = sorted(output.glob("watchmyai-*.whl"))
    sdists = sorted(output.glob("watchmyai-*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise RuntimeError("release build must produce exactly one wheel and one source distribution")
    _normalize_sdist(sdists[0], epoch=int(environment["SOURCE_DATE_EPOCH"]))
    artifacts = [
        source_archive,
        output / "watchmyai-rules.ndjson",
        wheels[0],
        sdists[0],
    ]
    manifest_path = output / "watchmyai-package-manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["release_artifacts"] = {
        path.name: {"sha256": _sha256(path), "size": path.stat().st_size}
        for path in sorted(artifacts, key=lambda item: item.name)
    }
    manifest_content = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(manifest_path, manifest_content)
    artifacts.append(manifest_path)
    checksum_path = output / "SHA256SUMS.txt"
    checksum_content = "".join(
        f"{_sha256(path)}  {path.name}\n" for path in sorted(artifacts, key=lambda item: item.name)
    ).encode("ascii")
    _atomic_write(checksum_path, checksum_content)
    return [*sorted(artifacts, key=lambda item: item.name), checksum_path]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        artifacts = build(args.output_dir)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL: release build: {exc}", file=sys.stderr)
        return 1
    for path in artifacts:
        print(f"{_sha256(path)}  {path.name}  {path.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
