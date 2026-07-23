"""Durable per-session SHA-256 evidence chains backed by SQLite transactions."""

from __future__ import annotations

import copy
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from watchmyai.schema.event import canonical_hash

GENESIS_HASH = "sha256:" + ("0" * 64)


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    session_id: str
    entries: int
    first_invalid_sequence: int | None = None
    reason: str | None = None


class EvidenceChain:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence (
                    session_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    canonical_event TEXT NOT NULL,
                    PRIMARY KEY (session_id, sequence),
                    UNIQUE (session_id, event_hash)
                )
                """
            )

    def append(self, event: dict[str, Any], session_id: str) -> dict[str, Any]:
        if not session_id:
            raise ValueError("session_id is required for tamper-evident evidence")
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT sequence, event_hash FROM evidence "
                    "WHERE session_id=? ORDER BY sequence DESC LIMIT 1",
                    (session_id,),
                ).fetchone()
                sequence = int(row[0]) + 1 if row else 1
                previous_hash = str(row[1]) if row else GENESIS_HASH
                chained = copy.deepcopy(event)
                evidence = chained.setdefault("watchmyai", {}).setdefault("evidence", {})
                evidence.update(
                    {
                        "chain_id": canonical_hash({"session_id": session_id}),
                        "sequence": sequence,
                        "previous_hash": previous_hash,
                        "hash_algorithm": "sha256",
                    }
                )
                event_hash = canonical_hash(chained)
                evidence["event_hash"] = event_hash
                serialized = json.dumps(chained, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                connection.execute(
                    "INSERT INTO evidence(session_id, sequence, previous_hash, event_hash, "
                    "canonical_event) VALUES(?,?,?,?,?)",
                    (session_id, sequence, previous_hash, event_hash, serialized),
                )
                connection.commit()
                return chained
            except Exception:
                connection.rollback()
                raise

    def entries(self, session_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT canonical_event FROM evidence WHERE session_id=? ORDER BY sequence",
                (session_id,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def verify(self, session_id: str) -> VerificationResult:
        rows = self.entries(session_id)
        previous = GENESIS_HASH
        for expected_sequence, event in enumerate(rows, start=1):
            evidence = event.get("watchmyai", {}).get("evidence", {})
            if evidence.get("sequence") != expected_sequence:
                return VerificationResult(False, session_id, len(rows), expected_sequence, "sequence_gap")
            if evidence.get("previous_hash") != previous:
                return VerificationResult(
                    False, session_id, len(rows), expected_sequence, "previous_hash_mismatch"
                )
            stored_hash = evidence.pop("event_hash", None)
            calculated = canonical_hash(event)
            evidence["event_hash"] = stored_hash
            if stored_hash != calculated:
                return VerificationResult(
                    False, session_id, len(rows), expected_sequence, "event_hash_mismatch"
                )
            previous = str(stored_hash)
        return VerificationResult(True, session_id, len(rows))
