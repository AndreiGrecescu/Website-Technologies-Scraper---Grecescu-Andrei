"""DNS records: cheap, never bot-blocked, and surprisingly rich.

MX -> email provider (Google Workspace, Microsoft 365, Zoho...)
TXT -> SPF includes (Mailchimp, SendGrid, Klaviyo, HubSpot...), site verifications
       (google-site-verification, facebook-domain-verification, shopify...)
NS / SOA -> DNS provider / CDN (Cloudflare, Route 53, Shopify's own DNS)
CNAME (www) -> hosting (shops.myshopify.com, *.wixdns.net, ext-sq.squarespace.com, ...)
A -> known platform IP ranges (Shopify 23.227.38.0/24)

It also tells us early that a domain is dead (NXDOMAIN) so we don't waste a browser on it.
"""
from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver

_RESOLVER = dns.asyncresolver.Resolver(configure=False)
_RESOLVER.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
_RESOLVER.timeout = 4.0
_RESOLVER.lifetime = 8.0

# Platform IP ranges that the public DB does not cover (A-record evidence)
KNOWN_RANGES = {
    "Shopify": ["23.227.38.0/24"],
    "Squarespace": ["198.185.159.0/24", "198.49.23.0/24"],
    "Wix": ["185.230.63.0/24", "185.230.60.0/24"],
    "Webflow": ["75.2.70.75/32", "99.83.190.102/32"],
    "Netlify": ["75.2.60.5/32"],
    "GitHub Pages": ["185.199.108.0/22"],
    "Weebly": ["199.34.228.0/22"],
}


@dataclass
class DnsResult:
    records: dict[str, list[str]] = field(default_factory=dict)
    nxdomain: bool = False
    error: str = ""
    ip_hints: list[tuple[str, str]] = field(default_factory=list)  # (tech, "A 23.227.38.65 in 23.227.38.0/24")


async def _q(name: str, rtype: str) -> list[str]:
    try:
        ans = await _RESOLVER.resolve(name, rtype)
        return [r.to_text().strip('"') for r in ans]
    except dns.resolver.NXDOMAIN:
        raise
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.name.EmptyLabel):
        return []
    except Exception:
        return []


async def probe(domain: str) -> DnsResult:
    out = DnsResult()
    try:
        a = await _q(domain, "A")
    except dns.resolver.NXDOMAIN:
        out.nxdomain = True
        return out
    jobs = {
        "MX": _q(domain, "MX"),
        "TXT": _q(domain, "TXT"),
        "NS": _q(domain, "NS"),
        "SOA": _q(domain, "SOA"),
        "CNAME": _q(f"www.{domain}", "CNAME"),
        "AAAA": _q(domain, "AAAA"),
    }
    results = await asyncio.gather(*jobs.values(), return_exceptions=True)
    out.records["A"] = a
    for k, v in zip(jobs.keys(), results):
        out.records[k] = v if isinstance(v, list) else []
    # also the apex CNAME for subdomain inputs (e.g. shop.brand.com -> shops.myshopify.com)
    try:
        apex_cname = await _q(domain, "CNAME")
        out.records["CNAME"] = list(dict.fromkeys(out.records["CNAME"] + apex_cname))
    except Exception:
        pass
    for ip in a:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for tech, nets in KNOWN_RANGES.items():
            for n in nets:
                if addr in ipaddress.ip_network(n):
                    out.ip_hints.append((tech, f"A record {ip} is inside {tech} range {n}"))
    return out
