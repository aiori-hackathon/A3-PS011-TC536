"""Configuration loader and Pydantic schemas for scope.yaml."""

from pathlib import Path
from typing import Any, Union
from pydantic import BaseModel, Field
import yaml


class HostScope(BaseModel):
    """Configuration for a specific host target and approved ports."""

    hostname: str
    ports: list[int] = Field(default_factory=list)


class ScopeDetails(BaseModel):
    """Scope target lists including domains and hosts."""

    domains: list[str] = Field(default_factory=list)
    hosts: list[HostScope] = Field(default_factory=list)


class DiscoveryConfig(BaseModel):
    """Configuration options for discovery."""

    allowed_labels: list[str] = Field(default_factory=list)
    max_candidates: int = 50


class LimitsConfig(BaseModel):
    """Rate limiting and timeout configurations."""

    max_rps: int = 20
    per_host_concurrency: int = 2
    timeout_s: int = 5


class ScopeConfig(BaseModel):
    """Root configuration model for scope.yaml."""

    scope: ScopeDetails
    checks: list[Union[dict[str, str], Any]] = Field(default_factory=list)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)


def load_scope(path: Union[str, Path]) -> ScopeConfig:
    """Load and parse scope configuration from a YAML file.

    Args:
        path: Path to the scope YAML file.

    Returns:
        ScopeConfig instance containing parsed configuration.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Scope file not found at: {file_path}")

    with file_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return ScopeConfig.model_validate(data)
