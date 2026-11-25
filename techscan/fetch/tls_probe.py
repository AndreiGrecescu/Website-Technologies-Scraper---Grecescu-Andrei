"""TLS certificate issuer (Let's Encrypt, Cloudflare, Sectigo, Amazon...).

Works even when the HTTP layer is behind a bot wall, because the handshake happens first.
"""
from __future__ import annotations

import asyncio
import socket
import ssl


def _issuer_sync(host: str, timeout: float = 6.0) -> tuple[str, bool]:
    """Returns (issuer organization, cert_valid)."""
    for verify in (True, False):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    if verify:
                        cert = ss.getpeercert() or {}
                        issuer = dict(x[0] for x in cert.get("issuer", ()))
                        return issuer.get("organizationName") or issuer.get("commonName", ""), True
                    der = ss.getpeercert(binary_form=True)
                    return _issuer_from_der(der), False
        except ssl.SSLCertVerificationError:
            continue
        except Exception:
            return "", False
    return "", False


def _issuer_from_der(der: bytes | None) -> str:
    """Cheap issuer extraction without a full X.509 parser (unverified certs only)."""
    if not der:
        return ""
    try:
        from cryptography import x509  # optional dependency

        cert = x509.load_der_x509_certificate(der)
        for attr in cert.issuer:
            if attr.oid.dotted_string == "2.5.4.10":
                return str(attr.value)
    except Exception:
        pass
    return ""


async def issuer(host: str) -> tuple[str, bool]:
    return await asyncio.to_thread(_issuer_sync, host)
