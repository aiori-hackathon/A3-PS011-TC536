"""Unit tests for ScopeGuard and scope authorization."""

from pathlib import Path
import pytest
from ps011.net import ConnectionDenied, NetClient
from ps011.scope import ScopeGuard


def test_approved_domain_and_port_authorized(sample_scope_file: Path) -> None:
    """Test 1: approved (domain, port) is authorized."""
    guard = ScopeGuard(sample_scope_file)
    assert guard.authorize("lab.internal", 443) is True
    assert guard.authorize("example.com", 80) is True


def test_unapproved_domain_denied(sample_scope_file: Path) -> None:
    """Test 2: unapproved domain is DENIED."""
    guard = ScopeGuard(sample_scope_file)
    assert guard.authorize("unapproved-target.com", 80) is False
    assert guard.authorize("google.com", 443) is False

    # Check audit log contains denial
    assert len(guard.audit_log) >= 2
    last_entry = guard.audit_log[-1]
    assert last_entry["target"] == "google.com"
    assert last_entry["decision"] == "deny"


def test_unapproved_port_on_approved_domain_denied(sample_scope_file: Path) -> None:
    """Test 3: unapproved port on approved host/domain is DENIED."""
    guard = ScopeGuard(sample_scope_file)
    # www.lab.internal only allows ports 80, 443
    assert guard.authorize("www.lab.internal", 22) is False
    # lab.internal (domain) only allows 80, 443, 53
    assert guard.authorize("lab.internal", 22) is False


def test_scope_hash_is_deterministic(sample_scope_file: Path) -> None:
    """Test 4: scope hash is deterministic."""
    guard1 = ScopeGuard(sample_scope_file)
    guard2 = ScopeGuard(sample_scope_file)

    hash1 = guard1.get_hash()
    hash2 = guard2.get_hash()

    assert hash1 == hash2
    assert len(hash1) == 64  # SHA-256 hex digest length


@pytest.mark.asyncio
async def test_net_client_denies_unapproved(sample_scope_file: Path) -> None:
    """Test NetClient raises ConnectionDenied when ScopeGuard denies."""
    guard = ScopeGuard(sample_scope_file)
    client = NetClient(guard)

    with pytest.raises(ConnectionDenied) as exc_info:
        await client.open("unapproved.org", 80)

    assert "unapproved.org" in str(exc_info.value)
