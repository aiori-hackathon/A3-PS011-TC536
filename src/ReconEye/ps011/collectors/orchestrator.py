"""Orchestrator for coordinating collectors with rate limiting and concurrency control."""

import asyncio
from datetime import datetime
from typing import Dict, List

from ps011.models.schema import Snapshot, Asset, Observation as ObservationModel
from ps011.scope import ScopeGuard
from ps011.net import NetClient
from ps011.models.db import Database
from ps011.config import ScopeConfig


class TokenBucket:
    """Rate limiter: max_rps tokens per second."""

    def __init__(self, max_rps: int = 20) -> None:
        """Initialize token bucket rate limiter.
        
        Args:
            max_rps: Maximum requests per second.
        """
        self.max_rps = max_rps
        self.tokens = 0.0  # Start with 0 tokens to enforce rate from start
        self.last_update = asyncio.get_event_loop().time()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until one token is available, then consume it."""
        async with self.lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self.last_update
            self.tokens = min(self.max_rps, self.tokens + elapsed * self.max_rps)
            self.last_update = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.max_rps
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class Orchestrator:
    """Coordinate collectors: rate limit, per-host concurrency, one snapshot per cycle."""

    def __init__(
        self,
        scope_guard: ScopeGuard,
        net_client: NetClient,
        db: Database,
        scope_config: ScopeConfig
    ) -> None:
        """Initialize orchestrator.
        
        Args:
            scope_guard: ScopeGuard for authorization checks
            net_client: NetClient for connection management
            db: Database instance
            scope_config: Loaded scope configuration
        """
        self.scope_guard = scope_guard
        self.net_client = net_client
        self.db = db
        self.scope_config = scope_config
        self.rate_limiter = TokenBucket(max_rps=scope_config.limits.max_rps)
        self.per_host_semaphores: Dict[str, asyncio.Semaphore] = {}

    def _get_host_semaphore(self, target: str) -> asyncio.Semaphore:
        """Lazy-init semaphore per host.
        
        Args:
            target: Hostname or IP address
        
        Returns:
            Semaphore for per-host concurrency control
        """
        if target not in self.per_host_semaphores:
            concurrency = self.scope_config.limits.per_host_concurrency
            self.per_host_semaphores[target] = asyncio.Semaphore(concurrency)
        return self.per_host_semaphores[target]

    async def run_cycle(self) -> Snapshot:
        """One complete scan cycle: collect all checks for all targets, store in one transaction.
        
        Returns:
            Snapshot object with status "success" or "error".
        """
        # Import collectors here to avoid circular imports
        from ps011.collectors.dns import DNSCollector
        from ps011.collectors.tls import TLSCollector
        from ps011.collectors.port import PortCollector

        # Create snapshot
        with self.db.session() as sess:
            snap = Snapshot(
                scope_hash=self.scope_guard.get_hash(),
                status="running"
            )
            sess.add(snap)
            sess.flush()
            snap_id = snap.id

        all_observations = []

        try:
            # Iterate over all domains for DNS checks
            for domain in self.scope_config.scope.domains:
                await self.rate_limiter.acquire()

                # DNS collect
                async with DNSCollector() as dns_col:
                    dns_obs = await dns_col.collect(domain)
                    all_observations.append((domain, None, dns_obs))

            # Iterate over all hosts for port/TLS/HTTP checks
            for host_cfg in self.scope_config.scope.hosts:
                hostname = host_cfg.hostname
                for port in host_cfg.ports:
                    await self.rate_limiter.acquire()

                    # Check if authorized (via ScopeGuard)
                    if not self.scope_guard.authorize(hostname, port):
                        continue

                    host_sem = self._get_host_semaphore(hostname)
                    async with host_sem:
                        # Port checks C1/C2
                        port_col = PortCollector(timeout_s=self.scope_config.limits.timeout_s)
                        c1c2_obs = await port_col.collect_c1_c2(hostname, port)
                        all_observations.append((hostname, port, c1c2_obs))

                        # TLS check C3 (if HTTPS port)
                        if port in [443, 8443]:
                            tls_col = TLSCollector(timeout_s=self.scope_config.limits.timeout_s)
                            c3_obs = await tls_col.collect(hostname, port)
                            all_observations.append((hostname, port, c3_obs))

                        # HTTP HEAD C4 (if HTTP port)
                        if port in [80, 8080]:
                            c4_obs = await port_col.collect_c4(hostname, port)
                            all_observations.append((hostname, port, c4_obs))

            # Store all observations in one transaction
            with self.db.session() as sess:
                snap = sess.query(Snapshot).filter_by(id=snap_id).one()

                for target, port, obs_list in all_observations:
                    # Get or create asset
                    identifier = f"{target}:{port}" if port else target
                    asset = sess.query(Asset).filter_by(identifier=identifier).first()
                    if not asset:
                        asset = Asset(kind="domain" if not port else "service", identifier=identifier)
                        sess.add(asset)
                        sess.flush()

                    # Add observations - convert dataclass to SQLAlchemy model
                    for obs in obs_list:
                        model_obs = ObservationModel(
                            snapshot_id=snap.id,
                            asset_id=asset.id,
                            check_id=obs.check_id,
                            attrs_json=obs.attrs_json,
                            error_class=obs.error_class,
                            timestamp=obs.timestamp
                        )
                        sess.add(model_obs)

                snap.status = "success"
                snap.finished_at = datetime.utcnow()
                sess.commit()

        except Exception as e:
            with self.db.session() as sess:
                snap = sess.query(Snapshot).filter_by(id=snap_id).one()
                snap.status = "error"
                snap.finished_at = datetime.utcnow()
                sess.commit()
            raise

        return snap