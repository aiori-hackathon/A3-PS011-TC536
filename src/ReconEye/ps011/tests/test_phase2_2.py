"""Phase 2.2 integration tests: TLS, Port, HTTP collectors, Orchestrator."""

import pytest
import asyncio
import time
import json
from ps011.collectors.tls import TLSCollector
from ps011.collectors.port import PortCollector
from ps011.collectors.orchestrator import TokenBucket, Orchestrator
from ps011.normalizers.tls import normalize_tls_observation
from ps011.normalizers.port import normalize_port_observation
from ps011.models.observation import Observation
from ps011.scope import ScopeGuard
from ps011.net import NetClient
from ps011.config import load_scope
from ps011.models.db import get_db


@pytest.mark.asyncio
async def test_tls_collector_on_localhost(db_setup):
    """TLS collector on localhost:443 (may fail but should handle gracefully)."""
    tls_col = TLSCollector(timeout_s=1)
    obs_list = await tls_col.collect("localhost", 443)
    assert len(obs_list) == 1
    obs = obs_list[0]
    assert obs.check_id == "C3"
    # Should have either cert data or error_class
    attrs = json.loads(obs.attrs_json)
    assert "error" in attrs or "subject" in attrs


@pytest.mark.asyncio
async def test_port_collector_c1_c2(db_setup):
    """Port collector C1 (connect) and C2 (banner) on localhost:22 (likely SSH)."""
    port_col = PortCollector(timeout_s=2)
    obs_list = await port_col.collect_c1_c2("localhost", 22)
    assert len(obs_list) == 2
    assert obs_list[0].check_id == "C1"
    assert obs_list[1].check_id == "C2"
    
    # Check C1 attributes
    c1_attrs = json.loads(obs_list[0].attrs_json)
    assert "status" in c1_attrs
    
    # Check C2 attributes - banner might timeout, that's OK
    c2_attrs = json.loads(obs_list[1].attrs_json)
    assert "banner" in c2_attrs or "error" in c2_attrs


@pytest.mark.asyncio
async def test_port_collector_c4_http(db_setup):
    """Port collector C4 (HTTP HEAD) on localhost:80."""
    port_col = PortCollector(timeout_s=2)
    obs_list = await port_col.collect_c4("localhost", 80)
    assert len(obs_list) == 1
    assert obs_list[0].check_id == "C4"
    
    attrs = json.loads(obs_list[0].attrs_json)
    # Either has headers/status_code or error
    assert "status_code" in attrs or "error" in attrs


@pytest.mark.asyncio
async def test_rate_limiter_enforces_max_rps(db_setup):
    """Token bucket rate limiter respects max_rps."""
    limiter = TokenBucket(max_rps=10)
    
    start = time.time()
    for _ in range(11):
        await limiter.acquire()
    elapsed = time.time() - start
    
    # 11 tokens at 10 rps should take ~1.1 seconds (starts with 0 tokens)
    # Allow some timing variance - at least 0.5s
    assert elapsed >= 0.5


@pytest.mark.asyncio
async def test_orchestrator_one_cycle_stores_snapshot(db_setup, sample_scope_with_localhost):
    """Orchestrator runs one full cycle, stores snapshot + observations."""
    db = get_db()
    db.init_db()
    
    scope_cfg = load_scope(sample_scope_with_localhost)
    scope_guard = ScopeGuard(sample_scope_with_localhost)
    net_client = NetClient(scope_guard)
    
    orchestrator = Orchestrator(scope_guard, net_client, db, scope_cfg)
    snap = await orchestrator.run_cycle()
    
    assert snap.status == "success"
    
    # Verify observations stored
    with db.session() as sess:
        from ps011.models.schema import Observation
        obs_count = sess.query(Observation).filter_by(snapshot_id=snap.id).count()
        assert obs_count > 0


@pytest.mark.asyncio
async def test_normalize_tls_observation(db_setup):
    """TLS normalizer produces canonical form: sorted SANs."""
    obs = Observation(
        check_id="C3",
        attrs_json='{"subject": {"cn": "example.com"}, "san": ["b.com", "a.com"], "serial": "0x123", "not_after": "2025-01-01"}',
        error_class=None
    )
    normalized = normalize_tls_observation(obs)
    assert normalized["san"] == ["a.com", "b.com"]  # sorted


@pytest.mark.asyncio
async def test_normalize_port_observation_c1(db_setup):
    """Port normalizer C1: canonical status."""
    obs = Observation(
        check_id="C1",
        attrs_json='{"status": "open"}',
        error_class=None
    )
    normalized = normalize_port_observation(obs)
    assert normalized["status"] == "open"


@pytest.mark.asyncio
async def test_normalize_port_observation_c2(db_setup):
    """Port normalizer C2: canonical banner."""
    obs = Observation(
        check_id="C2",
        attrs_json='{"banner": "  SSH-2.0-OpenSSH_8.9  \\n"}',
        error_class=None
    )
    normalized = normalize_port_observation(obs)
    assert normalized["banner"] == "SSH-2.0-OpenSSH_8.9"


@pytest.mark.asyncio
async def test_normalize_port_observation_c4(db_setup):
    """Port normalizer C4: sorted headers."""
    obs = Observation(
        check_id="C4",
        attrs_json='{"status_code": "200", "headers": {"b-header": "val2", "a-header": "val1"}}',
        error_class=None
    )
    normalized = normalize_port_observation(obs)
    assert normalized["status_code"] == "200"
    assert list(normalized["headers"].keys()) == ["a-header", "b-header"]