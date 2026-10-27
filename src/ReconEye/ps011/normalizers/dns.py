"""DNS observation normalizer: canonical form (lowercase, sorted RRsets, no TTL)."""

import json
import logging
from typing import Any, Dict
from ps011.models.observation import Observation

logger = logging.getLogger(__name__)


def normalize_dns_observation(obs: Observation) -> Dict[str, Any]:
    """Canonical form for DNS observations: lowercase, sorted RRsets, no TTL.

    Args:
        obs: Observation with attrs_json containing A/AAAA/CNAME records.

    Returns:
        Dict with normalized attrs: {A: [...], AAAA: [...], CNAME: [...], error: ...}
    """
    try:
        attrs = json.loads(obs.attrs_json) if obs.attrs_json else {}
    except json.JSONDecodeError:
        return {"error": "Invalid JSON in attrs_json"}

    normalized = {}

    for key in ["A", "AAAA", "CNAME"]:
        if key in attrs and attrs[key]:
            records = []
            for record_str in attrs[key]:
                # record_str format: "example.com. 300 IN A 1.2.3.4"
                # or just "1.2.3.4" for simple cases
                parts = record_str.split()
                if len(parts) >= 5 and parts[3] in ("A", "AAAA", "CNAME"):
                    # Standard DNS record format
                    addr = parts[4]
                elif len(parts) >= 1:
                    # Fallback: last part might be the address
                    addr = parts[-1]
                else:
                    addr = record_str
                records.append(addr.lower())
            normalized[key] = sorted(records)

    if "error" in attrs:
        normalized["error"] = attrs["error"]

    return normalized


def normalize_dns_attrs(attrs_json: str) -> Dict[str, Any]:
    """Normalize DNS attributes from JSON string directly.

    Args:
        attrs_json: JSON string of DNS attributes.

    Returns:
        Normalized attributes dict.
    """
    try:
        attrs = json.loads(attrs_json) if attrs_json else {}
    except json.JSONDecodeError:
        return {"error": "Invalid JSON"}

    normalized = {}

    for key in ["A", "AAAA", "CNAME"]:
        if key in attrs and attrs[key]:
            records = []
            for record_str in attrs[key]:
                parts = record_str.split()
                if len(parts) >= 5 and parts[3] in ("A", "AAAA", "CNAME"):
                    addr = parts[4]
                elif len(parts) >= 1:
                    addr = parts[-1]
                else:
                    addr = record_str
                records.append(addr.lower())
            normalized[key] = sorted(records)

    if "error" in attrs:
        normalized["error"] = attrs["error"]

    return normalized