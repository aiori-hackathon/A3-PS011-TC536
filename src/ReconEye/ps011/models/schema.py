"""SQLAlchemy ORM models for PS-011."""

import json
from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Float,
    ForeignKey,
    Text,
    create_engine,
    text,
)
from sqlalchemy.orm import relationship, declarative_base, Session
from sqlalchemy.dialects.sqlite import JSON

Base = declarative_base()


class Asset(Base):
    """Asset being monitored: domain, host, or service."""

    __tablename__ = "assets"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    kind: str = Column(String(20), nullable=False)  # domain, host, service
    identifier: str = Column(String(255), nullable=False, unique=True, index=True)
    first_seen: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)

    observations = relationship("Observation", back_populates="asset", lazy="dynamic")
    findings = relationship("Finding", back_populates="asset", lazy="dynamic")


class Snapshot(Base):
    """A single scan cycle snapshot."""

    __tablename__ = "snapshots"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    started_at: datetime = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    finished_at: Optional[datetime] = Column(DateTime, nullable=True)
    scope_hash: str = Column(String(64), nullable=False)
    status: str = Column(String(20), default="running", nullable=False)

    observations = relationship("Observation", back_populates="snapshot", lazy="dynamic")
    baselines = relationship("Baseline", back_populates="snapshot", lazy="dynamic")


class Observation(Base):
    """Raw observation from a collector check."""

    __tablename__ = "observations"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: int = Column(Integer, ForeignKey("snapshots.id"), nullable=False, index=True)
    asset_id: int = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    check_id: str = Column(String(20), nullable=False)
    attrs_json: str = Column(Text, nullable=False)  # JSON blob
    error_class: Optional[str] = Column(String(255), nullable=True)
    timestamp: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)

    snapshot = relationship("Snapshot", back_populates="observations")
    asset = relationship("Asset", back_populates="observations")

    def get_attrs(self) -> dict:
        """Parse and return attrs_json as dict."""
        return json.loads(self.attrs_json) if self.attrs_json else {}

    def set_attrs(self, attrs: dict) -> None:
        """Set attrs_json from dict."""
        self.attrs_json = json.dumps(attrs, separators=(",", ":"))


class Baseline(Base):
    """Approved baseline snapshot for drift detection."""

    __tablename__ = "baseline"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: int = Column(Integer, ForeignKey("snapshots.id"), unique=True, nullable=False)
    approved_by: Optional[str] = Column(String(255), nullable=True)
    approved_at: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)

    snapshot = relationship("Snapshot", back_populates="baselines")


class Finding(Base):
    """Security or operational finding."""

    __tablename__ = "findings"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint: str = Column(String(255), nullable=False, unique=True, index=True)
    asset_id: int = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    rule_id: str = Column(String(50), nullable=False)
    severity: str = Column(String(20), nullable=False, default="medium")
    confidence: float = Column(Float, nullable=False, default=1.0)
    evidence_json: str = Column(Text, nullable=False)
    state: str = Column(String(20), default="new", nullable=False)
    first_seen: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)

    asset = relationship("Asset", back_populates="findings")

    def get_evidence(self) -> dict:
        """Parse and return evidence_json as dict."""
        return json.loads(self.evidence_json) if self.evidence_json else {}

    def set_evidence(self, evidence: dict) -> None:
        """Set evidence_json from dict."""
        self.evidence_json = json.dumps(evidence, separators=(",", ":"))


class AuditLog(Base):
    """Audit log for scope authorization decisions."""

    __tablename__ = "audit_log"
    __table_args__ = ()

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    ts: datetime = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    target: str = Column(String(255), nullable=False, index=True)
    port: int = Column(Integer, nullable=False)
    check_id: Optional[str] = Column(String(20), nullable=True)
    decision: str = Column(String(10), nullable=False)  # allow, deny
    reason: str = Column(String(255), nullable=False)
    scope_hash: str = Column(String(64), nullable=False)


class SchedulerState(Base):
    """Persistent scheduler state for APScheduler."""

    __tablename__ = "scheduler_state"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    last_run: Optional[datetime] = Column(DateTime, nullable=True)
    next_run: Optional[datetime] = Column(DateTime, nullable=True)