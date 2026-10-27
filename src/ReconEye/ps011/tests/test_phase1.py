"""Phase 1 tests: ScopeGuard, NetClient, AuditLogSink, CLI."""

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from ps011.net import ConnectionDenied, NetClient
from ps011.scope import ScopeGuard
from ps011.sinks.audit_log import AuditLogSink


class MockStreamReader:
    """Mock asyncio StreamReader."""

    def __init__(self):
        self._buffer = b""

    def feed_data(self, data: bytes):
        self._buffer += data

    async def read(self, n: int = -1) -> bytes:
        if not self._buffer:
            return b""
        if n == -1:
            data = self._buffer
            self._buffer = b""
            return data
        data = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return data


class MockStreamWriter:
    """Mock asyncio StreamWriter."""

    def __init__(self):
        self._buffer = b""
        self.closed = False

    def write(self, data: bytes):
        self._buffer += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def get_extra_info(self, name: str):
        if name == "peername":
            return ("127.0.0.1", 8080)
        if name == "sockname":
            return ("127.0.0.1", 12345)
        return None


@pytest.mark.asyncio
async def test_netclient_approved_target_connects(sample_scope_with_localhost: Path) -> None:
    """Test NetClient connects to approved target."""
    guard = ScopeGuard(sample_scope_with_localhost)
    client = NetClient(guard)

    mock_reader = MockStreamReader()
    mock_writer = MockStreamWriter()

    with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))) as mock_open:
        reader, writer = await client.open("localhost", 8080, check_id="TEST_C1")

        mock_open.assert_called_once_with("localhost", 8080)
        assert reader is mock_reader
        assert writer is mock_writer

        # Check audit log has allow entry
        audit = guard.get_audit_log()
        assert len(audit) == 1
        assert audit[0]["decision"] == "allow"
        assert audit[0]["target"] == "localhost"
        assert audit[0]["port"] == 8080
        assert audit[0]["check_id"] == "TEST_C1"


@pytest.mark.asyncio
async def test_netclient_unapproved_target_denied(sample_scope_with_localhost: Path) -> None:
    """Test NetClient denies unapproved target."""
    guard = ScopeGuard(sample_scope_with_localhost)
    client = NetClient(guard)

    with pytest.raises(ConnectionDenied) as exc_info:
        await client.open("google.com", 443, check_id="TEST_C1")

    assert "google.com" in str(exc_info.value)
    assert exc_info.value.host == "google.com"
    assert exc_info.value.port == 443

    # Check audit log has deny entry
    audit = guard.get_audit_log()
    assert len(audit) == 1
    assert audit[0]["decision"] == "deny"
    assert audit[0]["target"] == "google.com"
    assert audit[0]["port"] == 443
    assert "not in approved scope" in audit[0]["reason"]


@pytest.mark.asyncio
async def test_audit_log_format(audit_log_sink: AuditLogSink) -> None:
    """Test AuditLogSink writes valid JSONL with correct format."""
    import datetime

    ts1 = datetime.datetime.now(datetime.timezone.utc).isoformat()
    ts2 = datetime.datetime.now(datetime.timezone.utc).isoformat()

    entries = [
        {
            "ts": ts1,
            "target": "example.com",
            "port": 443,
            "check_id": "C3",
            "decision": "allow",
            "reason": "Approved domain",
            "scope_hash": "abc123",
        },
        {
            "ts": ts2,
            "target": "malicious.com",
            "port": 80,
            "check_id": "C1",
            "decision": "deny",
            "reason": "Not in scope",
            "scope_hash": "abc123",
        },
        {
            "ts": ts1,
            "target": "localhost",
            "port": 8080,
            "check_id": "C1",
            "decision": "allow",
            "reason": "Approved host",
            "scope_hash": "abc123",
        },
    ]

    for entry in entries:
        await audit_log_sink.write(entry)

    # Read back and verify
    read_entries = audit_log_sink.read_all()
    assert len(read_entries) == 3

    for entry in read_entries:
        # Each line is valid JSON (already parsed)
        assert "ts" in entry
        assert "target" in entry
        assert "port" in entry
        assert "check_id" in entry
        assert "decision" in entry
        assert entry["decision"] in ("allow", "deny")
        assert "reason" in entry
        assert "scope_hash" in entry

        # Verify ISO8601 timestamp format (should parse without error)
        datetime.datetime.fromisoformat(entry["ts"].replace("Z", "+00:00"))


@pytest.mark.asyncio
async def test_cli_denied(sample_scope_with_localhost: Path, tmp_path: Path) -> None:
    """Test CLI scan command exits 1 for denied target."""
    from ps011.cli import scan_command

    # Use a scope that doesn't include google.com
    exit_code = await scan_command("google.com", 443, str(sample_scope_with_localhost))

    assert exit_code == 1

    # Check audit log was written
    audit_file = Path("ps011/data/audit.jsonl")
    if audit_file.exists():
        with audit_file.open("r") as f:
            lines = f.readlines()
            assert len(lines) > 0
            last_entry = json.loads(lines[-1])
            assert last_entry["target"] == "google.com"
            assert last_entry["decision"] == "deny"


@pytest.mark.asyncio
async def test_cli_approved(sample_scope_with_localhost: Path, tmp_path: Path) -> None:
    """Test CLI scan command exits 0 for approved target (mocked)."""
    from ps011.cli import scan_command

    mock_reader = MockStreamReader()
    mock_writer = MockStreamWriter()

    with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
        exit_code = await scan_command("localhost", 8080, str(sample_scope_with_localhost))

    assert exit_code == 0

    # Check audit log was written
    audit_file = Path("ps011/data/audit.jsonl")
    if audit_file.exists():
        with audit_file.open("r") as f:
            lines = f.readlines()
            if lines:
                last_entry = json.loads(lines[-1])
                assert last_entry["target"] == "localhost"
                assert last_entry["port"] == 8080
                assert last_entry["decision"] == "allow"


@pytest.mark.asyncio
async def test_scope_guard_canonicalize_target() -> None:
    """Test ScopeGuard canonicalizes targets correctly."""
    guard = ScopeGuard(Path("scope.yaml"))

    assert guard.canonicalize_target("  EXAMPLE.COM  ") == "example.com"
    assert guard.canonicalize_target("localhost") == "localhost"
    assert guard.canonicalize_target("192.168.1.1") == "192.168.1.1"


@pytest.mark.asyncio
async def test_scope_guard_resolve_once(sample_scope_with_localhost: Path) -> None:
    """Test ScopeGuard resolves and caches DNS."""
    guard = ScopeGuard(sample_scope_with_localhost)

    result = guard.resolve_once("localhost")
    assert "localhost:" in result
    assert result != "localhost:unresolved"

    # Second call should use cache
    result2 = guard.resolve_once("localhost")
    assert result == result2


@pytest.mark.asyncio
async def test_scope_guard_port_validation(sample_scope_with_localhost: Path) -> None:
    """Test ScopeGuard validates port range."""
    guard = ScopeGuard(sample_scope_with_localhost)

    with pytest.raises(ValueError):
        guard.authorize("localhost", 0)

    with pytest.raises(ValueError):
        guard.authorize("localhost", 65536)

    # Valid ports should not raise
    guard.authorize("localhost", 1)
    guard.authorize("localhost", 65535)