"""TLS observation normalizer: canonical form for certificate data."""

import json
from typing import Dict, Any
from ps011.models.observation import Observation


def normalize_tls_observation(obs: Observation) -> Dict[str, Any]:
    """Canonical form for TLS certs: subject/SAN/serial/not_after.
    
    Ignore: signature algorithm, cert chain order, minor formatting.
    Output: normalized dict suitable for diffing.
    """
    attrs = json.loads(obs.attrs_json)
    normalized = {}

    if "subject" in attrs:
        normalized["subject"] = attrs["subject"]
    if "san" in attrs:
        normalized["san"] = sorted(attrs["san"])  # Sort SANs
    if "serial" in attrs:
        normalized["serial"] = attrs["serial"]
    if "not_before" in attrs:
        normalized["not_before"] = attrs["not_before"]
    if "not_after" in attrs:
        normalized["not_after"] = attrs["not_after"]
    if "is_self_signed" in attrs:
        normalized["is_self_signed"] = attrs["is_self_signed"]
    if "days_to_expiry" in attrs:
        normalized["days_to_expiry"] = attrs["days_to_expiry"]

    if "error" in attrs:
        normalized["error"] = attrs["error"]

    return normalized