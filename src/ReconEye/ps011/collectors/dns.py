"""DNS collector for C2 check: resolve domain, distinguish error types."""

import asyncio
import json
import logging
from datetime import datetime
from typing import List, Optional
from dns.asyncresolver import Resolver
from dns import resolver as dns_resolver
from dns import exception as dns_exception

from ps011.collectors.base import Collector
from ps011.models.observation import Observation

logger = logging.getLogger(__name__)


class DNSCollector(Collector):
    """C2 DNS check: resolve domain, distinguish error types.

    Supports A, AAAA, CNAME record types.
    Error classes: nxdomain, nodata, servfail, timeout, other
    """

    def __init__(
        self,
        nameserver: str = "8.8.8.8",
        timeout_s: float = 5.0,
        record_types: Optional[List[str]] = None,
    ) -> None:
        """Initialize DNS collector.

        Args:
            nameserver: DNS server to query.
            timeout_s: Query timeout in seconds.
            record_types: List of record types to query (default: A, AAAA, CNAME).
        """
        self.nameserver = nameserver
        self.timeout_s = timeout_s
        self.record_types = record_types or ["A", "AAAA", "CNAME"]
        self._resolver: Optional[Resolver] = None

    async def __aenter__(self) -> "DNSCollector":
        """Async context manager entry: initialize resolver."""
        self._resolver = Resolver()
        self._resolver.nameservers = [self.nameserver]
        self._resolver.lifetime = self.timeout_s
        self._resolver.timeout = self.timeout_s
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit: cleanup."""
        self._resolver = None

    async def collect(self, target: str) -> List[Observation]:
        """Resolve target and return list of Observation objects.

        Args:
            target: FQDN to resolve.

        Returns:
            List of Observation with attrs_json containing records and error if any.
        """
        if not self._resolver:
            raise RuntimeError("DNSCollector not initialized; use 'async with'")

        observations = []
        attrs = {}
        error_class: Optional[str] = None

        # Track if we got NXDOMAIN (terminal error)
        got_nxdomain = False

        for record_type in self.record_types:
            if got_nxdomain:
                break

            try:
                answer = await self._resolver.resolve(
                    target, record_type, raise_on_no_answer=False
                )
                if answer.rrset:
                    attrs[record_type] = [str(rr) for rr in answer.rrset]
                else:
                    attrs[record_type] = []
            except dns_resolver.NXDOMAIN:
                error_class = "nxdomain"
                attrs["error"] = "NXDOMAIN"
                got_nxdomain = True
            except dns_resolver.NoAnswer:
                if error_class is None:
                    error_class = "nodata"
                    attrs["error"] = "NODATA"
                attrs[record_type] = []
            except dns_resolver.Timeout:
                if error_class is None:
                    error_class = "timeout"
                    attrs["error"] = "Timeout"
                attrs[record_type] = []
            except dns_exception.DNSException as e:
                if error_class is None:
                    error_class = "servfail"
                    attrs["error"] = str(e)
                attrs[record_type] = []
            except asyncio.TimeoutError:
                if error_class is None:
                    error_class = "timeout"
                    attrs["error"] = "Timeout"
                attrs[record_type] = []

        # If no records and no error, mark as nodata
        if not attrs.get("A") and not attrs.get("AAAA") and not attrs.get("CNAME"):
            if error_class is None:
                error_class = "nodata"
                attrs["error"] = "NODATA"

        obs = Observation(
            check_id="C2",
            attrs_json=json.dumps(attrs, separators=(",", ":")),
            error_class=error_class,
            timestamp=datetime.utcnow(),
        )
        observations.append(obs)
        return observations


async def collect_dns(target: str, nameserver: str = "8.8.8.8", timeout_s: float = 5.0) -> List[Observation]:
    """Convenience function to collect DNS records for a target.

    Args:
        target: FQDN to resolve.
        nameserver: DNS server to query.
        timeout_s: Query timeout.

    Returns:
        List of Observation objects.
    """
    async with DNSCollector(nameserver=nameserver, timeout_s=timeout_s) as collector:
        return await collector.collect(target)