"""Port observation normalizer: canonical form for port/banner/HTTP data."""

import json
from typing import Dict, Any
from ps011.models.observation import Observation


def normalize_port_observation(obs: Observation) -> Dict[str, Any]:
    """Canonical form for port observations: status, headers (sorted)."""
    attrs = json.loads(obs.attrs_json)
    normalized = {}

    if obs.check_id == "C1":
        normalized["status"] = attrs.get("status", "unknown")

    if obs.check_id == "C2":
        normalized["banner"] = attrs.get("banner", "").strip()

    if obs.check_id == "C4":
        normalized["status_code"] = attrs.get("status_code")
        headers = attrs.get("headers", {})
        # Sort headers for determinism
        normalized["headers"] = {k: headers[k] for k in sorted(headers.keys())}

    if "error" in attrs:
        normalized["error"] = attrs["error"]

    return normalized