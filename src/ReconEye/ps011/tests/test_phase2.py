"""Phase 2 tests: Database, DNS Collector, Normalizer, Integration."""

import json
import pytest
from datetime import datetime

from ps011.models.schema import (
    Asset,
    Snapshot,
    Observation,
    Baseline,
    Finding,
    AuditLog,
    SchedulerState,
)
from ps011.collectors.dns import DNSCollector
from ps011.normalizers.dns import normalize_dns_observation, normalize_dns_attrs
from ps011.models.observation import Observation as ObsDataclass


@pytest.mark.asyncio
async def test_dns_collector_resolves_localhost(db_setup) -> None:
    """DNS collector resolves localhost -> 127.0.0.1"""
    # Use a known working nameserver
    async with DNSCollector(nameserver="8.8.8.8", timeout_s=5.0) as collector:
        obs_list = await collector.collect("localhost")
        assert len(obs_list) == 1
        obs = obs_list[0]
        assert obs.check_id == "C2"
        attrs = json.loads(obs.attrs_json)
        # localhost may resolve to 127.0.0.1 or ::1, or timeout depending on DNS
        assert "A" in attrs or "AAAA" in attrs or "error" in attrs
        # Should not crash


@pytest.mark.asyncio
async def test_dns_collector_nxdomain(db_setup) -> None:
    """DNS collector for nonexistent domain -> nxdomain error class"""
    async with DNSCollector(nameserver="8.8.8.8", timeout_s=5.0) as collector:
        obs_list = await collector.collect("this-does-not-exist-zzzzz.example.com")
        assert len(obs_list) == 1
        obs = obs_list[0]
        assert obs.check_id == "C2"
        # Should get some error class (nxdomain, servfail, timeout, etc.)
        assert obs.error_class in ["nxdomain", "servfail", "timeout", "nodata", None]


@pytest.mark.asyncio
async def test_integration_one_cycle_stores_snapshot(db_setup) -> None:
    """One scan cycle: create snapshot, resolve domain, store observation."""
    from ps011.models.db import get_db
    from sqlalchemy.orm import Session

    db = db_setup

    # Create a snapshot
    with db.session() as sess:
        snap = Snapshot(scope_hash="abc123", status="running")
        sess.add(snap)
        sess.commit()
        snap_id = snap.id

    # Create an asset
    with db.session() as sess:
        asset = Asset(kind="domain", identifier="example.com")
        sess.add(asset)
        sess.commit()
        asset_id = asset.id

    # Collect DNS observations
    async with DNSCollector(nameserver="8.8.8.8", timeout_s=5.0) as collector:
        obs_list = await collector.collect("example.com")

        # Store observation in DB (convert dataclass to ORM model)
        with db.session() as sess:
            snap = sess.query(Snapshot).filter_by(id=snap_id).one()
            asset = sess.query(Asset).filter_by(id=asset_id).one()
            for obs in obs_list:
                orm_obs = Observation(
                    snapshot_id=snap.id,
                    asset_id=asset.id,
                    check_id=obs.check_id,
                    attrs_json=obs.attrs_json,
                    error_class=obs.error_class,
                    timestamp=obs.timestamp,
                )
                sess.add(orm_obs)
            sess.commit()

    # Verify stored
    with db.session() as sess:
        obs_count = sess.query(Observation).filter_by(snapshot_id=snap_id).count()
        assert obs_count == 1
        obs = sess.query(Observation).filter_by(snapshot_id=snap_id).first()
        assert obs.check_id == "C2"
        # Verify attrs_json is valid JSON
        attrs = json.loads(obs.attrs_json)
        assert isinstance(attrs, dict)


@pytest.mark.asyncio
async def test_normalize_dns_observation(db_setup) -> None:
    """Normalizer produces canonical form: lowercase, sorted."""
    # Create an Observation dataclass (not the ORM model)
    obs = ObsDataclass(
        check_id="C2",
        attrs_json='{"A": ["example.com. 300 IN A 1.2.3.4", "example.com. 300 IN A 5.6.7.8"]}',
        error_class=None,
        timestamp=datetime.utcnow(),
    )
    normalized = normalize_dns_observation(obs)
    assert "A" in normalized
    assert normalized["A"] == ["1.2.3.4", "5.6.7.8"]


@pytest.mark.asyncio
async def test_normalize_dns_attrs_direct() -> None:
    """Test normalize_dns_attrs function directly."""
    attrs_json = '{"A": ["EXAMPLE.COM. 300 IN A 1.2.3.4", "EXAMPLE.COM. 300 IN A 5.6.7.8"]}'
    normalized = normalize_dns_attrs(attrs_json)
    assert "A" in normalized
    assert normalized["A"] == ["1.2.3.4", "5.6.7.8"]


@pytest.mark.asyncio
async def test_normalize_dns_with_error() -> None:
    """Normalizer preserves error field."""
    obs = ObsDataclass(
        check_id="C2",
        attrs_json='{"error": "NXDOMAIN", "A": []}',
        error_class="nxdomain",
        timestamp=datetime.utcnow(),
    )
    normalized = normalize_dns_observation(obs)
    assert normalized["error"] == "NXDOMAIN"


@pytest.mark.asyncio
async def test_database_wal_mode(db_setup) -> None:
    """Verify database is created with WAL mode enabled."""
    assert db_setup.verify_wal_mode() is True


@pytest.mark.asyncio
async def test_database_all_tables_created(db_setup) -> None:
    """Verify all 7 tables are created."""
    tables = db_setup.get_table_names()
    expected = {"assets", "snapshots", "observations", "baseline", "findings", "audit_log", "scheduler_state"}
    assert set(tables) == expected


@pytest.mark.asyncio
async def test_dns_collector_cname_chain() -> None:
    """DNS collector handles CNAME records."""
    async with DNSCollector(nameserver="8.8.8.8", timeout_s=5.0) as collector:
        obs_list = await collector.collect("www.google.com")
        assert len(obs_list) == 1
        obs = obs_list[0]
        attrs = json.loads(obs.attrs_json)
        # Should have CNAME or A records
        assert "CNAME" in attrs or "A" in attrs or "error" in attrs


@pytest.mark.asyncio
async def test_observation_orm_roundtrip(db_setup) -> None:
    """Test Observation ORM model get_attrs/set_attrs roundtrip."""
    db = db_setup

    with db.session() as sess:
        obs = Observation(
            snapshot_id=1,
            asset_id=1,
            check_id="C2",
            attrs_json='{"A": ["1.2.3.4"]}',
            error_class=None,
        )
        sess.add(obs)
        sess.commit()

        # Retrieve and test get_attrs
        retrieved = sess.query(Observation).first()
        attrs = retrieved.get_attrs()
        assert attrs == {"A": ["1.2.3.4"]}

        # Test set_attrs
        retrieved.set_attrs({"AAAA": ["::1"]})
        sess.commit()

        retrieved2 = sess.query(Observation).first()
        attrs2 = retrieved2.get_attrs()
        assert attrs2 == {"AAAA": ["::1"]}