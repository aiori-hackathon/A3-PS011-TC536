"""NetClient wrapper choke-point for outbound calls."""

import asyncio
from typing import Any, Optional, Tuple
from ps011.scope import ScopeGuard


class ConnectionDenied(Exception):
    """Exception raised when an outbound connection attempt is denied by ScopeGuard."""

    def __init__(self, host: str, port: int, reason: str = "") -> None:
        self.host = host
        self.port = port
        self.reason = reason
        super().__init__(f"Connection to {host}:{port} DENIED. {reason}".strip())


class NetClient:
    """Wrapper class providing a single choke-point for outbound connections."""

    def __init__(self, scope_guard: ScopeGuard, timeout: float = 5.0) -> None:
        """Initialize NetClient with an active ScopeGuard.

        Args:
            scope_guard: ScopeGuard instance for authorizing connections.
            timeout: Connection timeout in seconds.
        """
        self.scope_guard = scope_guard
        self.timeout = timeout

    async def open(
        self, host: str, port: int, check_id: Optional[str] = None, **kwargs: Any
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open a TCP connection to host:port if authorized by ScopeGuard.

        Args:
            host: Target host or IP address.
            port: Target port.
            check_id: Optional check identifier for audit logging.
            **kwargs: Additional arguments to pass to asyncio.open_connection.

        Returns:
            Tuple of (StreamReader, StreamWriter).

        Raises:
            ConnectionDenied: If connection target:port is not in scope.
            asyncio.TimeoutError: If connection times out.
        """
        if not self.scope_guard.authorize(host, port, check_id=check_id):
            # Fetch last audit log reason if available
            reason = ""
            if self.scope_guard.audit_log:
                reason = self.scope_guard.audit_log[-1].get("reason", "")
            raise ConnectionDenied(host, port, reason)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, **kwargs),
                timeout=self.timeout,
            )
            return reader, writer
        except asyncio.TimeoutError as e:
            raise asyncio.TimeoutError(f"Connection to {host}:{port} timed out after {self.timeout}s") from e