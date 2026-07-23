"""Generic runtime capture: process snapshots and endpoint activity records."""

from watchmyai.capture.process import ProcessRecord, ancestry_chain, snapshot_processes

__all__ = ["ProcessRecord", "ancestry_chain", "snapshot_processes"]
