"""Generic CLI wrapper: ``watchmyai run [--agent ID] -- <agent command>``.

Wraps any CLI AI agent to provide MODE 1 (generic) visibility:
- WatchMyAI session ID assignment
- operator identity, working directory, start/end time, exit code
- process tree sampling (spawned children) via psutil when available
- stdout/stderr *metadata* (byte/line counts) — content is not stored
- normalized session_start / child_process / session_end events

Attribution: "strong". The wrapper knows exactly which process is the agent
(it launched it), but without deep telemetry it cannot confirm that any
individual downstream effect was AI-initiated, so it never claims
"confirmed".

Note: stdout/stderr are relayed through pipes to count bytes. Full-screen
TUI agents that require a TTY should use ``--passthrough``, which inherits
stdio and skips output metadata.
"""

from __future__ import annotations

import getpass
import hashlib
import os
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, BinaryIO

try:  # pragma: no cover
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

EmitFn = Callable[[dict[str, Any]], Any]


@dataclass
class WrapResult:
    session_id: str
    exit_code: int
    duration_seconds: float
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    children_seen: list[dict[str, Any]] = field(default_factory=list)


def _new_session_id() -> str:
    return "sess-" + secrets.token_urlsafe(12)


def _agent_fields(agent_id: str | None, command: list[str]) -> dict[str, Any]:
    if agent_id:
        return {
            "id": agent_id,
            "type": "known_ai_agent",
            "discovery_method": "wrapper",
            "discovery_confidence": 0.9,
        }
    return {
        "id": "unknown",
        "name": os.path.basename(command[0]) if command else "unknown",
        "type": "unknown_ai_agent",
        "discovery_method": "wrapper",
        "discovery_confidence": 0.5,
    }


def _relay(src: BinaryIO, dst: BinaryIO, counter: dict[str, int], key: str) -> None:
    while True:
        chunk = src.read(4096)
        if not chunk:
            break
        counter[key] += len(chunk)
        try:
            dst.write(chunk)
            dst.flush()
        except (BrokenPipeError, ValueError):
            pass


def _sample_children(root_pid: int, seen: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    """Return newly observed child processes of the wrapped agent."""
    if psutil is None:
        return []
    new: list[dict[str, Any]] = []
    try:
        root = psutil.Process(root_pid)
        for child in root.children(recursive=True):
            if child.pid in seen:
                continue
            try:
                info = {
                    "pid": child.pid,
                    "name": child.name(),
                    "executable": child.exe(),
                    "ppid": child.ppid(),
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            seen[child.pid] = info
            new.append(info)
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
        pass
    return new


def run_wrapped(
    command: list[str],
    emit: EmitFn,
    agent_id: str | None = None,
    passthrough: bool = False,
    sample_interval: float = 1.0,
    session_id: str | None = None,
    clock: Callable[[], float] = time.time,
) -> WrapResult:
    if not command:
        raise ValueError("no agent command given")
    session_id = session_id or _new_session_id()
    try:
        operator = getpass.getuser()
    except (KeyError, OSError):
        operator = "unknown"
    cwd = os.getcwd()
    agent = _agent_fields(agent_id, command)
    base_wm: dict[str, Any] = {
        "agent": agent,
        "attribution": {"level": "strong"},
        "visibility": {"mode": "generic"},
        "session": {"id": session_id},
    }
    started = clock()

    emit(
        {
            "event": {
                "kind": "event",
                "category": ["session"],
                "type": ["start"],
                "action": "session.started",
            },
            "user": {"name": operator},
            "process": {"working_directory": cwd, "executable": command[0]},
            "watchmyai": {
                **base_wm,
                "request": {
                    "payload_hash": "sha256:" + hashlib.sha256("\0".join(command).encode()).hexdigest()
                },
            },
        }
    )

    counters = {"stdout": 0, "stderr": 0}
    seen_children: dict[int, dict[str, Any]] = {}
    if passthrough:
        proc = subprocess.Popen(command)
        relays: list[threading.Thread] = []
    else:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        relays = [
            threading.Thread(
                target=_relay, args=(proc.stdout, sys.stdout.buffer, counters, "stdout"), daemon=True
            ),
            threading.Thread(
                target=_relay, args=(proc.stderr, sys.stderr.buffer, counters, "stderr"), daemon=True
            ),
        ]
        for t in relays:
            t.start()

    children_events: list[dict[str, Any]] = []
    while proc.poll() is None:
        for child in _sample_children(proc.pid, seen_children):
            children_events.append(child)
            emit(
                {
                    "event": {
                        "kind": "event",
                        "category": ["process"],
                        "type": ["start"],
                        "action": "process.child_observed",
                    },
                    "process": {
                        "pid": child["pid"],
                        "name": child["name"],
                        "executable": child["executable"],
                    },
                    "watchmyai": base_wm,
                }
            )
        time.sleep(min(sample_interval, 0.25))
    for t in relays:
        t.join(timeout=5)
    exit_code = proc.returncode or 0
    duration = clock() - started

    emit(
        {
            "event": {
                "kind": "event",
                "category": ["session"],
                "type": ["end"],
                "action": "session.ended",
                "outcome": "success" if exit_code == 0 else "failure",
            },
            "user": {"name": operator},
            "process": {
                "pid": proc.pid,
                "working_directory": cwd,
                "exit_code": exit_code,
            },
            "watchmyai": {
                **base_wm,
                "execution": {
                    "result": (
                        f"exit_code={exit_code} duration_s={duration:.2f} "
                        f"stdout_bytes={counters['stdout']} stderr_bytes={counters['stderr']} "
                        f"children={len(seen_children)}"
                    )
                },
            },
        }
    )
    return WrapResult(
        session_id=session_id,
        exit_code=exit_code,
        duration_seconds=duration,
        stdout_bytes=counters["stdout"],
        stderr_bytes=counters["stderr"],
        children_seen=children_events,
    )
