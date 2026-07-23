"""Immutable candidate staging with ACTIVE and LAST_KNOWN_GOOD pointers."""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Callable
from pathlib import Path


class TwoSlotStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.states = self.root / "states"
        self.states.mkdir(parents=True, exist_ok=True)

    def _pointer(self, name: str) -> Path:
        return self.root / name

    def read_pointer(self, name: str) -> Path | None:
        path = self._pointer(name)
        if not path.exists():
            return None
        target = path.read_text("utf-8").strip()
        if not target or "/" in target or "\\" in target:
            raise ValueError(f"invalid {name} pointer")
        state = self.states / target
        return state if state.is_dir() else None

    def stage(self, files: dict[str, bytes], manifest: dict[str, object]) -> Path:
        state_name = "state-" + secrets.token_hex(16)
        candidate = self.states / state_name
        candidate.mkdir(mode=0o700)
        try:
            for name, content in sorted(files.items()):
                if not name or Path(name).name != name:
                    raise ValueError(f"unsafe staged filename {name!r}")
                self._write_synced(candidate / name, content)
            self._write_synced(
                candidate / "manifest.json",
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            )
            self._fsync_directory(candidate)
            self._fsync_directory(self.states)
            return candidate
        except Exception:
            # Candidate is not active. Leave it quarantined for safe operator cleanup.
            raise

    def activate(self, candidate: Path, health_check: Callable[[Path], bool]) -> Path:
        candidate = candidate.resolve(strict=True)
        if candidate.parent != self.states.resolve(strict=True):
            raise ValueError("candidate is not an immutable staged state")
        previous = self.read_pointer("ACTIVE")
        if previous:
            self._switch_pointer("LAST_KNOWN_GOOD", previous.name)
        self._switch_pointer("ACTIVE", candidate.name)
        try:
            healthy = health_check(candidate)
        except Exception:
            healthy = False
        if not healthy:
            if previous:
                self._switch_pointer("ACTIVE", previous.name)
            else:
                self._pointer("ACTIVE").unlink(missing_ok=True)
                self._fsync_directory(self.root)
            raise RuntimeError("candidate activation health check failed; LAST_KNOWN_GOOD restored")
        return candidate

    def _switch_pointer(self, name: str, state_name: str) -> None:
        temporary = self.root / f".{name}.{os.getpid()}.tmp"
        self._write_synced(temporary, (state_name + "\n").encode("utf-8"))
        temporary.replace(self._pointer(name))
        self._fsync_directory(self.root)

    @staticmethod
    def _write_synced(path: Path, content: bytes) -> None:
        with path.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
