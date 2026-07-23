"""JSON Lines sink with size-based rotation.

This is the recommended default output: Elastic Agent's custom-logs
integration tails the file, so the gateway needs no Elastic credentials at
all on the monitored host.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from watchmyai.exporters.base import ExportError, validate_export_batch


class JsonlSink:
    def __init__(self, path: str | Path, max_bytes: int = 50 * 1024 * 1024, backups: int = 5):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups

    def send(self, batch: list[dict[str, Any]]) -> None:
        validate_export_batch(batch)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate_if_needed()
            with self.path.open("a", encoding="utf-8") as fh:
                for event in batch:
                    fh.write(
                        json.dumps(
                            event,
                            separators=(",", ":"),
                            default=str,
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
        except OSError as exc:
            raise ExportError(f"jsonl write failed: {exc}") from exc

    def _rotate_if_needed(self) -> None:
        if not self.path.exists() or self.path.stat().st_size < self.max_bytes:
            return
        # events.jsonl.(backups-1) is discarded; everything else shifts up.
        for idx in range(self.backups - 1, 0, -1):
            src = self.path.with_name(f"{self.path.name}.{idx}")
            dst = self.path.with_name(f"{self.path.name}.{idx + 1}")
            if src.exists():
                src.replace(dst)
        self.path.replace(self.path.with_name(f"{self.path.name}.1"))
