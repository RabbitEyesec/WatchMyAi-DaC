"""Process records used by discovery and generic capture.

``ProcessRecord`` is a plain data structure so that discovery and tests are
deterministic: records can come from a live ``psutil`` snapshot or from JSON
fixtures with identical behaviour. ``psutil`` is an optional dependency — the
package imports without it, and live capture degrades gracefully.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

try:  # pragma: no cover - exercised only when psutil is installed
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]


@dataclass
class ProcessRecord:
    pid: int
    name: str = ""
    executable: str = ""
    command_line: str = ""
    ppid: int | None = None
    parent_name: str = ""
    username: str = ""
    working_directory: str = ""
    environ: dict[str, str] = field(default_factory=dict)
    create_time: float | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ProcessRecord:
        return cls(
            pid=int(raw["pid"]),
            name=raw.get("name", ""),
            executable=raw.get("executable", ""),
            command_line=raw.get("command_line", ""),
            ppid=raw.get("ppid"),
            parent_name=raw.get("parent_name", ""),
            username=raw.get("username", ""),
            working_directory=raw.get("working_directory", ""),
            environ=dict(raw.get("environ", {})),
            create_time=raw.get("create_time"),
        )

    def to_ecs(self) -> dict[str, Any]:
        """Render as an ECS ``process`` object."""
        out: dict[str, Any] = {"pid": self.pid}
        if self.name:
            out["name"] = self.name
        if self.executable:
            out["executable"] = self.executable
        # Command-line arguments remain in-memory for discovery only. They are
        # never copied to telemetry because arguments can contain credentials.
        if self.working_directory:
            out["working_directory"] = self.working_directory
        parent: dict[str, Any] = {}
        if self.ppid is not None:
            parent["pid"] = self.ppid
        if self.parent_name:
            parent["name"] = self.parent_name
        if parent:
            out["parent"] = parent
        return out


def capture_available() -> bool:
    return psutil is not None


def snapshot_processes() -> list[ProcessRecord]:
    """Snapshot live processes via psutil. Returns [] when psutil is absent.

    Fields that require elevated privileges (environ, cwd) are captured
    best-effort; access errors never abort the snapshot.
    """
    if psutil is None:
        return []
    records: list[ProcessRecord] = []
    attrs = ["pid", "name", "exe", "cmdline", "ppid", "username", "create_time"]
    for proc in psutil.process_iter(attrs=attrs):
        info = proc.info
        try:
            cwd = proc.cwd()
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            cwd = ""
        try:
            environ = dict(proc.environ())
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            environ = {}
        try:
            parent = proc.parent()
            parent_name = parent.name() if parent else ""
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            parent_name = ""
        records.append(
            ProcessRecord(
                pid=info.get("pid", 0),
                name=info.get("name") or "",
                executable=info.get("exe") or "",
                command_line=" ".join(info.get("cmdline") or []),
                ppid=info.get("ppid"),
                parent_name=parent_name,
                username=info.get("username") or "",
                working_directory=cwd,
                environ=environ,
                create_time=info.get("create_time"),
            )
        )
    return records


def ancestry_chain(records: list[ProcessRecord], pid: int, max_depth: int = 16) -> list[dict[str, Any]]:
    """Walk the parent chain within a snapshot: [{pid, name}, ...] root-last."""
    by_pid = {r.pid: r for r in records}
    chain: list[dict[str, Any]] = []
    current = by_pid.get(pid)
    seen: set[int] = set()
    while current is not None and current.ppid is not None and len(chain) < max_depth:
        if current.ppid in seen or current.ppid == current.pid:
            break
        seen.add(current.pid)
        parent = by_pid.get(current.ppid)
        if parent is None:
            chain.append({"pid": current.ppid, "name": current.parent_name or "unknown"})
            break
        chain.append({"pid": parent.pid, "name": parent.name})
        current = parent
    return chain


def child_processes(records: list[ProcessRecord], pid: int) -> list[ProcessRecord]:
    """Direct and transitive children of ``pid`` within a snapshot."""
    children: list[ProcessRecord] = []
    frontier = {pid}
    remaining = list(records)
    while frontier:
        next_frontier: set[int] = set()
        rest: list[ProcessRecord] = []
        for rec in remaining:
            if rec.ppid in frontier:
                children.append(rec)
                next_frontier.add(rec.pid)
            else:
                rest.append(rec)
        remaining = rest
        frontier = next_frontier
    return children
