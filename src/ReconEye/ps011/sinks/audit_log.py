"""Audit log sink for writing JSONL audit entries."""

import json
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager


class AuditLogSink:
    """Async sink for writing audit log entries to a JSONL file."""

    def __init__(self, log_path: str = "ps011/data/audit.jsonl") -> None:
        """Initialize AuditLogSink with path to JSONL log file.

        Args:
            log_path: Path to the audit log file.
        """
        self.log_path = Path(log_path)
        self._file = None

    def _ensure_dir(self) -> None:
        """Ensure the log directory exists."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    @asynccontextmanager
    async def open(self):
        """Async context manager to open the audit log file."""
        self._ensure_dir()
        self._file = self.log_path.open("a", encoding="utf-8")
        try:
            yield self
        finally:
            if self._file:
                self._file.close()
                self._file = None

    async def write(self, entry: dict) -> None:
        """Write a single audit log entry as a JSON line.

        Args:
            entry: Dictionary containing audit log fields:
                ts (str): ISO8601 timestamp
                target (str): Target hostname/IP
                port (int): Target port
                check_id (str, optional): Check identifier
                decision (str): "allow" or "deny"
                reason (str): Reason for decision
                scope_hash (str): SHA-256 hash of scope config
        """
        self._ensure_dir()
        line = json.dumps(entry, separators=(",", ":"))
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    async def write_many(self, entries: list[dict]) -> None:
        """Write multiple audit log entries.

        Args:
            entries: List of audit log entry dictionaries.
        """
        self._ensure_dir()
        lines = [json.dumps(e, separators=(",", ":")) + "\n" for e in entries]
        with self.log_path.open("a", encoding="utf-8") as f:
            f.writelines(lines)

    def read_all(self) -> list[dict]:
        """Read all audit log entries from the file.

        Returns:
            List of parsed JSON objects.
        """
        if not self.log_path.exists():
            return []

        entries = []
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries

    def clear(self) -> None:
        """Clear the audit log file."""
        if self.log_path.exists():
            self.log_path.unlink()


__all__ = ["AuditLogSink"]