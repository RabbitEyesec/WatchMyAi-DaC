"""Export pipeline: bounded local queue, retry with backoff, dead-letter file,
and health metrics.

Behaviour:
- events are validated by the normalizer before they reach the pipeline;
  anything that still fails to serialize goes straight to the dead-letter.
- ``flush()`` sends the queue in batches through the configured sink with
  bounded retries; events that exhaust retries are dead-lettered, never
  silently dropped.
- backpressure: when the queue is full the oldest events are dead-lettered
  with reason "queue_overflow" so memory stays bounded.
- ``sleep`` is injectable so retry tests run instantly and deterministically.
"""

from __future__ import annotations

import json
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from watchmyai.schema.event import validate_event


class ExportError(Exception):
    """Raised by sinks on delivery failure. retryable=False skips retries."""

    def __init__(self, message: str, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


class Sink(Protocol):
    def send(self, batch: list[dict[str, Any]]) -> None: ...


def validate_export_batch(batch: list[dict[str, Any]]) -> None:
    """Fail before I/O when a producer bypasses the normalizer."""
    for index, event in enumerate(batch):
        errors = validate_event(event)
        if errors:
            raise ExportError(
                f"event {index} violates telemetry schema: {'; '.join(errors)}",
                retryable=False,
            )


class ExportPipeline:
    def __init__(
        self,
        sink: Sink,
        dead_letter_path: str | Path,
        max_queue: int = 10_000,
        batch_size: int = 100,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.sink = sink
        self.dead_letter_path = Path(dead_letter_path)
        self.max_queue = max_queue
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.sleep = sleep
        self.queue: deque[dict[str, Any]] = deque()
        self.metrics: dict[str, int] = {
            "enqueued": 0,
            "exported": 0,
            "retries": 0,
            "dead_lettered": 0,
            "overflow_dropped": 0,
        }

    # ------------------------------------------------------------------
    def enqueue(self, event: dict[str, Any]) -> None:
        try:
            json.dumps(event, default=str)
        except Exception as exc:  # noqa: BLE001 - any serialization failure means DLQ, not crash
            self._dead_letter({"repr": repr(event)}, f"unserializable_event: {exc}")
            return
        if len(self.queue) >= self.max_queue:
            oldest = self.queue.popleft()
            self.metrics["overflow_dropped"] += 1
            self._dead_letter(oldest, "queue_overflow")
        self.queue.append(event)
        self.metrics["enqueued"] += 1

    def flush(self) -> int:
        """Drain the queue through the sink. Returns events exported."""
        exported = 0
        while self.queue:
            take = min(self.batch_size, len(self.queue))
            batch = [self.queue.popleft() for _ in range(take)]
            if self._send_with_retry(batch):
                exported += len(batch)
                self.metrics["exported"] += len(batch)
            else:
                for event in batch:
                    self._dead_letter(event, "delivery_failed_after_retries")
        return exported

    def _send_with_retry(self, batch: list[dict[str, Any]]) -> bool:
        attempt = 0
        while True:
            try:
                self.sink.send(batch)
                return True
            except ExportError as exc:
                if not exc.retryable or attempt >= self.max_retries:
                    return False
                self.metrics["retries"] += 1
                self.sleep(self.backoff_base * (2**attempt))
                attempt += 1

    # ------------------------------------------------------------------
    def _dead_letter(self, event: dict[str, Any], reason: str) -> None:
        self.metrics["dead_lettered"] += 1
        self.dead_letter_path.parent.mkdir(parents=True, exist_ok=True)
        record = {"reason": reason, "event": event}
        with self.dead_letter_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

    def health(self) -> dict[str, Any]:
        return {
            "queue_depth": len(self.queue),
            "queue_capacity": self.max_queue,
            **self.metrics,
        }
