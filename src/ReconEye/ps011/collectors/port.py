"""Port collectors for C1 (TCP connect), C2 (banner grab), and C4 (HTTP HEAD)."""

import asyncio
import json
from datetime import datetime
from typing import List, Optional

from ps011.collectors.base import Collector
from ps011.models.observation import Observation


class PortCollector(Collector):
    """C1 TCP connect + C2 banner grab + C4 HTTP HEAD."""

    def __init__(self, timeout_s: float = 5.0) -> None:
        """Initialize port collector.
        
        Args:
            timeout_s: Connection and operation timeout in seconds.
        """
        self.timeout_s = timeout_s

    async def collect(self, target: str) -> List[Observation]:
        """Abstract method implementation - delegates to collect_c1_c2 with default port 80.
        
        This is a fallback implementation. Use collect_c1_c2, collect_c4 directly for specific checks.
        
        Args:
            target: hostname or IP (format: "host:port" or just "host" for port 80)
        
        Returns:
            List of observations for C1/C2 on the target.
        """
        # Parse target:port
        if ':' in target:
            host, port_str = target.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 80
        else:
            host = target
            port = 80
        
        return await self.collect_c1_c2(host, port)

    async def collect_c1_c2(self, target: str, port: int) -> List[Observation]:
        """C1: TCP connect. C2: grab banner (first 1KB).
        
        Args:
            target: hostname or IP
            port: target port
        
        Returns:
            Two Observation objects: one for C1, one for C2.
        """
        obs = []
        c1_attrs = {}
        c2_attrs = {}
        c1_error = None
        c2_error = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout_s
            )
            c1_attrs["status"] = "open"

            # Try to read banner (some services send unsolicited)
            try:
                banner_data = await asyncio.wait_for(
                    reader.readexactly(1024),
                    timeout=0.5  # Quick timeout for banner read
                )
                c2_attrs["banner"] = banner_data.decode('utf-8', errors='ignore')
            except asyncio.IncompleteReadError as e:
                # Partial banner
                c2_attrs["banner"] = e.partial.decode('utf-8', errors='ignore')
            except asyncio.TimeoutError:
                c2_attrs["banner"] = ""
            except Exception as e:
                c2_error = "banner_read_error"
                c2_attrs["error"] = str(e)

            writer.close()
            await writer.wait_closed()

        except asyncio.TimeoutError:
            c1_error = "timeout"
            c1_attrs["status"] = "timeout"
            c2_error = "timeout"
            c2_attrs["error"] = "Timeout before banner"

        except ConnectionRefusedError:
            c1_error = "connection_refused"
            c1_attrs["status"] = "closed"

        except OSError as e:
            c1_error = "connection_error"
            c1_attrs["status"] = "error"
            c1_attrs["error"] = str(e)

        obs.append(Observation(
            check_id="C1",
            attrs_json=json.dumps(c1_attrs),
            error_class=c1_error,
            timestamp=datetime.utcnow()
        ))
        obs.append(Observation(
            check_id="C2",
            attrs_json=json.dumps(c2_attrs),
            error_class=c2_error,
            timestamp=datetime.utcnow()
        ))

        return obs

    async def collect_c4(self, target: str, port: int = 80) -> List[Observation]:
        """C4: HTTP HEAD request, parse headers.
        
        Args:
            target: hostname or IP
            port: target port (default 80)
        
        Returns:
            Single Observation with response status and headers.
        """
        obs = []
        attrs = {}
        error_class = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout_s
            )

            # Send HEAD / HTTP/1.1
            request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            # Read response
            response = await asyncio.wait_for(
                reader.readuntil(b'\r\n\r\n'),
                timeout=self.timeout_s
            )

            response_str = response.decode('utf-8', errors='ignore')
            lines = response_str.split('\r\n')

            # Status line
            if lines:
                status_line = lines[0]
                attrs["status_line"] = status_line
                parts = status_line.split()
                if len(parts) >= 2:
                    attrs["status_code"] = parts[1]

            # Headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, val = line.split(':', 1)
                    headers[key.strip()] = val.strip()
            attrs["headers"] = headers

            writer.close()
            await writer.wait_closed()

        except asyncio.TimeoutError:
            error_class = "timeout"
            attrs["error"] = "HTTP request timeout"

        except ConnectionRefusedError:
            error_class = "connection_refused"
            attrs["error"] = "Connection refused"

        except Exception as e:
            error_class = "http_error"
            attrs["error"] = str(e)

        obs_obj = Observation(
            check_id="C4",
            attrs_json=json.dumps(attrs, default=str),
            error_class=error_class,
            timestamp=datetime.utcnow()
        )
        obs.append(obs_obj)
        return obs