"""Dataclasses for raw observations and findings."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class Observation:
    """Raw observation result collected during a check."""

    id: Optional[int] = None
    snapshot_id: Optional[int] = None
    asset_id: Optional[str] = None
    check_id: str = ""
    attrs_json: dict[str, Any] = field(default_factory=dict)
    error_class: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Finding:
    """Security or operational finding derived from observation rules."""

    id: Optional[int] = None
    fingerprint: str = ""
    asset_id: str = ""
    rule_id: str = ""
    severity: str = "medium"
    confidence: str = "high"
    evidence_json: dict[str, Any] = field(default_factory=dict)
    state: str = "new"
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
