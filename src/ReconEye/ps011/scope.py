"""ScopeGuard implementation for scope authorization and audit logging."""

import hashlib
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union
from ps011.config import ScopeConfig, load_scope


class ScopeLoadError(Exception):
    """Raised when scope file cannot be loaded or is malformed."""

    pass


class ScopeGuard:
    """Enforces scope checks and keeps audit logs for outbound calls."""

    def __init__(self, scope_yaml_path: Union[str, Path]) -> None:
        """Initialize ScopeGuard with a path to scope.yaml.

        Args:
            scope_yaml_path: Path to the scope YAML configuration file.

        Raises:
            ScopeLoadError: If the scope file cannot be loaded or is malformed.
        """
        self.scope_path = Path(scope_yaml_path)
        if not self.scope_path.exists():
            raise ScopeLoadError(f"Scope file not found: {self.scope_path}")

        try:
            self.config: ScopeConfig = load_scope(self.scope_path)
        except Exception as e:
            raise ScopeLoadError(f"Failed to parse scope YAML: {e}") from e

        self.hash: str = self._compute_hash()
        # Audit log entry format: list of dicts
        self.audit_log: list[dict] = []
        # DNS resolution cache for this session
        self._dns_cache: dict[str, str] = {}

    def _compute_hash(self) -> str:
        """Compute SHA-256 hash of the scope configuration file content.

        Returns:
            Hex string of the SHA-256 hash.
        """
        content = self.scope_path.read_bytes()
        return hashlib.sha256(content).hexdigest()

    def get_hash(self) -> str:
        """Get the SHA-256 hash of the scope configuration.

        Returns:
            Hex string of SHA-256 hash.
        """
        return self.hash

    def canonicalize_target(self, target: str) -> str:
        """Canonicalize target to lowercase and strip whitespace.

        Args:
            target: Target hostname or IP address.

        Returns:
            Canonicalized target string.
        """
        return target.strip().lower()

    def resolve_once(self, target: str) -> str:
        """Resolve target via DNS once and cache the IP for this session.

        Args:
            target: Target hostname.

        Returns:
            Canonical form "target:ip" if resolution succeeds, otherwise "target:unresolved".
        """
        target = self.canonicalize_target(target)

        if target in self._dns_cache:
            return f"{target}:{self._dns_cache[target]}"

        try:
            ip = socket.gethostbyname(target)
            self._dns_cache[target] = ip
            return f"{target}:{ip}"
        except (socket.gaierror, OSError):
            self._dns_cache[target] = "unresolved"
            return f"{target}:unresolved"

    def _is_port_allowed_for_domain(self, domain: str, port: int) -> bool:
        """Check if port is allowed for a domain target.

        Args:
            domain: Domain name.
            port: Port number.

        Returns:
            True if port is allowed for domain.
        """
        # Standard ports for domain-level checks (DNS, HTTP, HTTPS)
        standard_ports = {53, 80, 443}
        return port in standard_ports

    def _is_port_allowed_for_host(self, host_entry, port: int) -> bool:
        """Check if port is allowed for a host entry.

        Args:
            host_entry: HostScope object from config.
            port: Port number.

        Returns:
            True if port is in host's allowed ports.
        """
        return port in host_entry.ports

    def authorize(self, target: str, port: int, check_id: Optional[str] = None) -> bool:
        """Authorize if a given target and port combination is within approved scope.

        Args:
            target: Target domain name or IP address / hostname.
            port: Target TCP port.
            check_id: Optional check identifier for audit logging.

        Returns:
            True if authorized, False otherwise.

        Raises:
            ValueError: If port is out of valid range (1-65535).
        """
        if not (1 <= port <= 65535):
            raise ValueError(f"Port out of range: {port}")

        ts = datetime.now(timezone.utc).isoformat()
        target_clean = self.canonicalize_target(target)

        # Check host scope FIRST (explicit host and port matching)
        for host in self.config.scope.hosts:
            if host.hostname.lower() == target_clean:
                if self._is_port_allowed_for_host(host, port):
                    entry = {
                        "ts": ts,
                        "target": target_clean,
                        "port": port,
                        "check_id": check_id,
                        "decision": "allow",
                        "reason": "Approved host and port",
                        "scope_hash": self.hash,
                    }
                    self.audit_log.append(entry)
                    return True
                else:
                    reason = f"Port {port} not in approved host ports {host.ports}"
                    entry = {
                        "ts": ts,
                        "target": target_clean,
                        "port": port,
                        "check_id": check_id,
                        "decision": "deny",
                        "reason": reason,
                        "scope_hash": self.hash,
                    }
                    self.audit_log.append(entry)
                    return False

        # Check domain scope (default allowed ports for domain-only checks e.g., 80, 443, 53)
        if target_clean in [d.lower() for d in self.config.scope.domains]:
            if self._is_port_allowed_for_domain(target_clean, port):
                entry = {
                    "ts": ts,
                    "target": target_clean,
                    "port": port,
                    "check_id": check_id,
                    "decision": "allow",
                    "reason": "Approved domain and standard port",
                    "scope_hash": self.hash,
                }
                self.audit_log.append(entry)
                return True
            else:
                reason = f"Port {port} not allowed for domain target '{target_clean}'"
                entry = {
                    "ts": ts,
                    "target": target_clean,
                    "port": port,
                    "check_id": check_id,
                    "decision": "deny",
                    "reason": reason,
                    "scope_hash": self.hash,
                }
                self.audit_log.append(entry)
                return False

        # Not in scope
        reason = f"Target '{target_clean}' not in approved scope"
        entry = {
            "ts": ts,
            "target": target_clean,
            "port": port,
            "check_id": check_id,
            "decision": "deny",
            "reason": reason,
            "scope_hash": self.hash,
        }
        self.audit_log.append(entry)
        return False

    def get_audit_log(self) -> list[dict]:
        """Get the audit log entries.

        Returns:
            List of audit log entry dictionaries.
        """
        return self.audit_log.copy()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        path = sys.argv[1]
        guard = ScopeGuard(path)
        print(guard.get_hash())
    else:
        print("Usage: python -m ps011.scope <path_to_scope.yaml>")