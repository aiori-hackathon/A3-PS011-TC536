"""TLS collector for C3 check: TLS handshake + certificate inspection."""

import asyncio
import ssl
import json
import base64
from datetime import datetime
from typing import List, Optional

from ps011.collectors.base import Collector
from ps011.models.observation import Observation


class TLSCollector(Collector):
    """C3 TLS handshake + certificate inspection.
    
    Dual-view approach:
    1. Peer cert chain: what the server presented
    2. DER parse: full X.509 parsing via cryptography
    """

    def __init__(self, timeout_s: float = 5.0) -> None:
        """Initialize TLS collector.
        
        Args:
            timeout_s: Connection and handshake timeout in seconds.
        """
        self.timeout_s = timeout_s

    async def collect(self, target: str, port: int = 443) -> List[Observation]:
        """Attempt TLS handshake on target:port.
        
        Args:
            target: hostname or IP
            port: TLS port (default 443)
        
        Returns:
            Single Observation with attrs_json containing:
                {
                    "cert_chain": [...],  # PEM-encoded certs
                    "subject": {...},     # X.509 subject DN
                    "san": [...],         # Subject Alt Names
                    "issuer": {...},      # Issuer DN
                    "not_before": ISO8601,
                    "not_after": ISO8601,
                    "serial": "0x...",
                    "signature_alg": "...",
                    "is_self_signed": bool,
                    "days_to_expiry": int
                }
            Or error_class in [ssl_error, timeout, connection_refused, bad_cert, connection_error]
        """
        obs = []
        attrs = {}
        error_class = None

        try:
            # Open raw socket
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout_s
            )

            # Wrap with SSL
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE  # Accept any cert (we'll parse it)

            # Perform TLS handshake
            try:
                transport = writer.get_extra_info('socket')
                wrapped = ssl_context.wrap_socket(
                    transport,
                    server_hostname=target,
                    do_handshake_on_connect=True
                )
                # Get peer certificate (DER format)
                der_cert = transport.getpeercert(binary_form=True)

                if der_cert is None:
                    error_class = "bad_cert"
                    attrs["error"] = "No peer certificate"
                else:
                    # Parse with cryptography
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend

                    cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    # Extract fields
                    attrs["subject"] = self._dn_to_dict(cert.subject)
                    attrs["issuer"] = self._dn_to_dict(cert.issuer)
                    attrs["not_before"] = cert.not_valid_before.isoformat()
                    attrs["not_after"] = cert.not_valid_after.isoformat()
                    attrs["serial"] = hex(cert.serial_number)
                    attrs["signature_alg"] = cert.signature_algorithm_oid._name

                    # SAN
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                        )
                        attrs["san"] = [name.value for name in san_ext.value]
                    except x509.ExtensionNotFound:
                        attrs["san"] = []

                    # Self-signed check
                    attrs["is_self_signed"] = cert.issuer == cert.subject

                    # Days to expiry
                    now = datetime.utcnow()
                    delta = cert.not_valid_after - now
                    attrs["days_to_expiry"] = max(0, delta.days)

                    # Cert chain (simplified; just the peer cert for now)
                    attrs["cert_chain"] = [self._cert_to_pem(der_cert)]

            except ssl.SSLError as e:
                error_class = "ssl_error"
                attrs["error"] = str(e)

            finally:
                writer.close()
                await writer.wait_closed()

        except asyncio.TimeoutError:
            error_class = "timeout"
            attrs["error"] = "TLS handshake timeout"

        except ConnectionRefusedError:
            error_class = "connection_refused"
            attrs["error"] = "Connection refused"

        except OSError as e:
            error_class = "connection_error"
            attrs["error"] = str(e)

        obs_obj = Observation(
            check_id="C3",
            attrs_json=json.dumps(attrs, default=str),
            error_class=error_class,
            timestamp=datetime.utcnow()
        )
        obs.append(obs_obj)
        return obs

    def _dn_to_dict(self, dn) -> dict:
        """Convert X.509 DN to dict {attr: value}."""
        result = {}
        for attr in dn:
            result[attr.oid._name] = attr.value
        return result

    def _cert_to_pem(self, der: bytes) -> str:
        """Convert DER to PEM."""
        b64 = base64.b64encode(der).decode('ascii')
        lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
        return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"