"""Tier 1: plain HTTP fetch (cheap: ~100-300 ms and a few KB of CPU per domain).

Lessons encoded here:
- Default library User-Agents (python-httpx/...) get 403'd by many WAFs outright.
  A real browser header set (UA + Accept + sec-ch-ua + sec-fetch-*) avoids most of that.
- Try several URL candidates: https://domain, https://www.domain, http://domain.
  Plenty of small sites only answer on one of them, or have broken TLS on the apex.
- Keep the whole redirect chain: headers/cookies set on intermediate hops are evidence too.
- 429 / 503 are retried with exponential backoff + jitter (rate limits are often per-IP
  and short-lived); 403 is not retried on the same tier - it escalates to the browser.
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field

import httpx

from .blockdetect import PageVerdict, classify

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
BROWSER_HEADERS = {
    "User-Agent": CHROME_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}
NAIVE_HEADERS = {"User-Agent": f"python-httpx/{httpx.__version__}"}

MAX_BODY = 3_000_000


@dataclass
class Attempt:
    url: str
    status: int | None = None
    error: str | None = None
    elapsed_ms: int = 0
    verdict: str = ""
    vendor: str = ""


@dataclass
class HttpResult:
    final_url: str = ""
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    html: str = ""
    redirects: list[str] = field(default_factory=list)
    verdict: PageVerdict = field(default_factory=lambda: PageVerdict("error", reason="not fetched"))
    attempts: list[Attempt] = field(default_factory=list)


def make_client(ua_profile: str = "chrome", proxy: str | None = None, timeout: float = 15.0,
                http2: bool | None = None) -> httpx.AsyncClient:
    headers = BROWSER_HEADERS if ua_profile == "chrome" else NAIVE_HEADERS
    return httpx.AsyncClient(
        headers=headers,
        http2=(ua_profile == "chrome") if http2 is None else http2,
        follow_redirects=True,
        max_redirects=8,
        timeout=httpx.Timeout(timeout, connect=8.0),
        verify=False,  # broken certs are common on small sites; cert validity is reported separately by the TLS probe
        proxy=proxy,
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
    )


def url_candidates(domain: str, has_subdomain: bool) -> list[str]:
    c = [f"https://{domain}/"]
    if not has_subdomain:
        c.append(f"https://www.{domain}/")
    c.append(f"http://{domain}/")
    return c


async def fetch(client: httpx.AsyncClient, domain: str, has_subdomain: bool, retries: int = 2,
                h1_client: httpx.AsyncClient | None = None) -> HttpResult:
    best: HttpResult | None = None
    attempts: list[Attempt] = []
    for url in url_candidates(domain, has_subdomain):
        for attempt_no in range(retries + 1):
            res = await _get(client, url)
            if res.verdict.state == "error" and "RemoteProtocolError" in res.verdict.reason and h1_client is not None:
                # some servers / middleboxes break on HTTP/2 framing: retry over HTTP/1.1
                res2 = await _get(h1_client, url)
                res.attempts[0].error = (res.attempts[0].error or "") + " -> retried over HTTP/1.1"
                res2.attempts = res.attempts + res2.attempts
                res = res2
            attempts.extend(res.attempts)
            if res.verdict.usable:
                res.attempts = attempts
                return res
            # remember the most informative failure (a blocked page beats a DNS error,
            # an HTTP 404 page with HTML beats a connection error)
            if best is None or _rank(res) > _rank(best):
                best = res
            best.attempts = attempts
            if res.status in (429, 503) and attempt_no < retries:
                await asyncio.sleep((2 ** attempt_no) * 1.5 + random.uniform(0, 1.0))
                continue
            break
        if best.verdict.state in ("challenge", "blocked", "parked"):
            break  # another URL variant will hit the same WAF / parking page
    return best


def _rank(r: HttpResult) -> int:
    base = {"ok": 50, "parked": 40, "challenge": 30, "blocked": 30, "empty": 20, "error": 10}.get(r.verdict.state, 0)
    return base + (5 if r.status else 0)


async def _get(client: httpx.AsyncClient, url: str) -> HttpResult:
    t0 = time.perf_counter()
    out = HttpResult()
    att = Attempt(url=url)
    try:
        async with client.stream("GET", url) as r:
            body = b""
            async for chunk in r.aiter_bytes():
                body += chunk
                if len(body) > MAX_BODY:
                    break
            out.status = r.status_code
            out.final_url = str(r.url)
            out.redirects = [str(h.url) for h in r.history]
            out.headers = _merge_headers(r)
            for hop in list(r.history) + [r]:
                for k, v in hop.cookies.items():
                    out.cookies[k] = v
            enc = r.encoding or "utf-8"
            try:
                out.html = body.decode(enc, errors="replace")
            except LookupError:
                out.html = body.decode("utf-8", errors="replace")
        out.verdict = classify(out.status, out.headers, out.html)
    except httpx.TooManyRedirects:
        out.verdict = classify(None, {}, "", error="too many redirects")
    except (httpx.ConnectError, httpx.ConnectTimeout) as e:
        out.verdict = classify(None, {}, "", error=f"connect: {_short(e)}")
    except httpx.TimeoutException:
        out.verdict = classify(None, {}, "", error="timeout")
    except Exception as e:  # ssl, protocol, decoding ...
        out.verdict = classify(None, {}, "", error=f"{type(e).__name__}: {_short(e)}")
    att.status, att.elapsed_ms = out.status, int((time.perf_counter() - t0) * 1000)
    att.verdict, att.vendor = out.verdict.state, out.verdict.vendor
    att.error = out.verdict.reason if out.verdict.state == "error" else None
    out.attempts = [att]
    return out


def _merge_headers(r: httpx.Response) -> dict[str, str]:
    h: dict[str, str] = {}
    for k, v in r.headers.multi_items():
        k = k.lower()
        h[k] = f"{h[k]}, {v}" if k in h else v
    return h


def _short(e: Exception) -> str:
    s = str(e) or type(e).__name__
    return s[:160]


async def fetch_text(client: httpx.AsyncClient, url: str, max_bytes: int = 200_000) -> tuple[int | None, str]:
    try:
        r = await client.get(url)
        return r.status_code, r.text[:max_bytes]
    except Exception:
        return None, ""
