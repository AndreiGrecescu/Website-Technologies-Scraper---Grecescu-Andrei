"""Store name (from an App Store review) -> verified Shopify domain.

The App Store shows only a display name ("NomaDesk", "Pixie Wing"), never the URL. Candidates,
cheapest and most reliable first:

  1. the name itself, if it already looks like a domain ("brand.com")
  2. https://<slug>.myshopify.com - a store's permanent Shopify address; it redirects to the
     store's primary domain. Strongest evidence when the store kept its original handle.
  3. <slug>.<tld> for .com, the country's ccTLD, .co, .shop, .store (DNS-checked first)

A candidate is accepted only if the site is Shopify (headers / cdn.shopify.com / Shopify.shop)
AND the site's name (title, og:site_name, myshopify handle) matches the review's store name.
Anything else stays unresolved - a wrong domain is worse than no domain for a sales team.

While the page is open we also keep its Web Pixels manifest (apiClientIds) for learn.py.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
import unicodedata
from difflib import SequenceMatcher
from typing import Callable
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.resolver
from bs4 import BeautifulSoup

from ..fetch import http
from ..shopify import extract_app_extensions, extract_manifest
from . import STORES_FILE, ensure_dir

COUNTRY_TLDS = {
    "United States": [".com", ".us"], "United Kingdom": [".co.uk", ".uk"], "Canada": [".ca"],
    "Australia": [".com.au"], "New Zealand": [".co.nz"], "Germany": [".de"], "Austria": [".at"],
    "Switzerland": [".ch"], "France": [".fr"], "Netherlands": [".nl"], "Belgium": [".be"],
    "Spain": [".es"], "Italy": [".it"], "Portugal": [".pt"], "Ireland": [".ie"], "Sweden": [".se"],
    "Norway": [".no"], "Denmark": [".dk"], "Finland": [".fi"], "Poland": [".pl"], "Czechia": [".cz"],
    "Romania": [".ro"], "Hungary": [".hu"], "Greece": [".gr"], "Lithuania": [".lt"], "Latvia": [".lv"],
    "Estonia": [".ee"], "Israel": [".co.il"], "India": [".in"], "Singapore": [".sg"],
    "Hong Kong SAR": [".hk"], "Japan": [".jp"], "South Africa": [".co.za"], "Brazil": [".com.br"],
    "Mexico": [".mx"], "United Arab Emirates": [".ae"], "Turkey": [".com.tr"],
}
GENERIC_TLDS = [".com", ".co", ".shop", ".store"]
STOP = {"the", "store", "shop", "official", "inc", "llc", "ltd", "gmbh", "limited", "company", "co", "online", "eu", "us", "uk"}

_RES = dns.asyncresolver.Resolver(configure=False)
_RES.nameservers = ["1.1.1.1", "8.8.8.8"]
_RES.timeout, _RES.lifetime = 3.0, 5.0

_SHOP_HANDLE = re.compile(r"""Shopify\.shop\s*=\s*["']([a-z0-9-]+)\.myshopify\.com""", re.I)


def store_key(name: str, country: str = "") -> str:
    return f"{_ascii(name)}|{country}".lower()


def _ascii(s: str) -> str:
    return unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode().strip()


def slugs(name: str) -> list[str]:
    n = _ascii(name).lower().replace("&", " and ").replace("+", " and ")
    words = re.findall(r"[a-z0-9]+", n)
    core = [w for w in words if w not in STOP] or words
    out = []
    for v in ("".join(words), "".join(core), "-".join(words), "-".join(core)):
        if v and v not in out and len(v) >= 3:
            out.append(v)
    return out


def candidates(name: str, country: str) -> list[tuple[str, str]]:
    """[(method, url)] in priority order."""
    c: list[tuple[str, str]] = []
    low = name.strip().lower()
    if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", low):
        c.append(("name is a domain", f"https://{low}/"))
    sl = slugs(name)
    for s in sl:
        c.append(("myshopify handle", f"https://{s}.myshopify.com/"))
    tlds = list(dict.fromkeys(GENERIC_TLDS[:1] + COUNTRY_TLDS.get(country, []) + GENERIC_TLDS[1:]))
    for s in sl[:2]:
        if "-" in s:
            continue
        for t in tlds:
            c.append(("domain guess", f"https://{s}{t}/"))
    seen, uniq = set(), []
    for m, u in c:
        if u not in seen:
            seen.add(u)
            uniq.append((m, u))
    return uniq


def name_score(name: str, title: str, site_name: str) -> float:
    """How well the site's own name matches the review's store name (0-1).

    The myshopify handle is deliberately NOT used: we built it from the name, so it would
    always match. Only what the site says about itself counts."""
    a = re.sub(r"[^a-z0-9]", "", _ascii(name).lower())
    best = 0.0
    for b_raw in (site_name, title):
        b = re.sub(r"[^a-z0-9]", "", _ascii(b_raw or "").lower())
        if not a or not b:
            continue
        if a == b:
            best = max(best, 1.0)
        elif len(a) >= 4 and (b.startswith(a) or a in b[: len(a) + 15]):
            best = max(best, 0.85)
        best = max(best, SequenceMatcher(None, a, b[: max(len(a) + 6, 12)]).ratio())
    return round(best, 2)


SHOPIFY_NETS = ("23.227.38.",)  # Shopify storefront edge


async def _dns_shopify(host: str) -> tuple[bool, bool]:
    """(exists, points_to_shopify) - DNS is free and never rate-limited, so it filters
    domain guesses before we spend a (rate-limited) HTTP request on them."""
    try:
        a = [r.to_text() for r in await _RES.resolve(host, "A")]
    except Exception:
        return False, False
    if any(ip.startswith(SHOPIFY_NETS) for ip in a):
        return True, True
    try:
        cn = [r.to_text().lower() for r in await _RES.resolve(host, "CNAME")]
    except Exception:
        cn = []
    if not cn and not host.startswith("www."):
        try:
            cn = [r.to_text().lower() for r in await _RES.resolve("www." + host, "CNAME")]
        except Exception:
            cn = []
    return True, any("myshopify.com" in c for c in cn)


class ShopifyThrottle:
    """All Shopify stores sit behind the same edge, which rate-limits per client IP.
    First run without this: 12 parallel workers -> HTTP 429 'Verifying your connection...'
    on 95% of stores. Global pacing + a shared cool-down on 429 fixes it."""

    def __init__(self, min_interval: float = 1.0, cooldown: float = 90.0):
        self.min_interval, self.cooldown = min_interval, cooldown
        self._lock = asyncio.Lock()
        self._next = 0.0
        self.hits_429 = 0

    async def wait(self):
        async with self._lock:
            now = time.monotonic()
            if now < self._next:
                await asyncio.sleep(self._next - now)
            self._next = time.monotonic() + self.min_interval

    async def rate_limited(self):
        self.hits_429 += 1
        async with self._lock:
            self._next = max(self._next, time.monotonic() + self.cooldown)


def _is_rate_limited(status, html: str) -> bool:
    return status == 429 or (status in (403, 503) and "Verifying your connection" in (html or "")[:5000])


def _inspect(html: str, headers: dict) -> dict:
    soup = BeautifulSoup(html[:800_000], "lxml")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    og = soup.find("meta", attrs={"property": "og:site_name"})
    site_name = og.get("content", "") if og else ""
    m = _SHOP_HANDLE.search(html)
    is_shopify = bool(
        "x-shopid" in headers or "x-shopify-stage" in headers
        or "cdn.shopify.com" in html or m or "shopify" in headers.get("powered-by", "").lower()
    )
    inline = [s.string for s in soup.find_all("script") if s.string]
    pixels = [
        {"apiClientId": p.get("apiClientId"), "type": p.get("type"),
         "config": str(p.get("configuration") or "")[:300]}
        for p in extract_manifest(inline)
    ]
    return {"title": title[:150], "site_name": site_name[:100], "myshopify": m.group(1) if m else "",
            "is_shopify": is_shopify, "pixels": pixels, "extensions": extract_app_extensions(html)}


def _ordered(cands: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Domain guesses (pre-filtered by DNS) before myshopify handles: a guess that DNS already
    shows on Shopify costs one request; myshopify handles always cost a request."""
    pri = {"name is a domain": 0, "domain guess": 1, "myshopify handle": 2}
    return sorted(cands, key=lambda c: pri.get(c[0], 3))


async def resolve_store(client, name: str, country: str, throttle: "ShopifyThrottle | None" = None) -> dict:
    rec = {"store": name, "country": country, "status": "not_found", "domain": "", "method": "",
           "score": 0.0, "evidence": "", "myshopify": "", "pixels": [], "tried": 0,
           "checked_at": time.strftime("%Y-%m-%d")}
    best_partial = None
    limited = False
    for method, url in _ordered(candidates(name, country)):
        host = urlsplit(url).netloc
        if method in ("domain guess", "name is a domain"):
            exists, on_shopify = await _dns_shopify(host)
            if not exists or (method == "domain guess" and not on_shopify):
                continue
        rec["tried"] += 1
        status, final_url, headers, html = None, url, {}, ""
        for attempt in range(3):
            if throttle:
                await throttle.wait()
            status, final_url, headers, html = await _fetch(client, url)
            if not _is_rate_limited(status, html):
                break
            if throttle:
                await throttle.rate_limited()
        if _is_rate_limited(status, html):
            limited = True
            continue
        if not html or status is None or status >= 400:
            continue
        final_host = urlsplit(final_url).netloc.lower()
        info = _inspect(html, headers)
        if not info["is_shopify"]:
            continue
        if method == "myshopify handle" and final_host.endswith(".myshopify.com"):
            if "/password" in final_url:
                # often an old/dev store of the same brand - keep looking (e.g. allbirds.myshopify.com
                # is password-protected while the real store is allbirds.com)
                if best_partial is None:
                    best_partial = {"domain": final_host, "score": 0.0, "method": method,
                                    "evidence": "myshopify store exists but is password-protected", "_closed": True}
                continue
            # store exists but serves on myshopify (no custom domain) - still a valid store
        score = name_score(name, info["title"], info["site_name"])
        threshold = 0.75
        domain = re.sub(r"^www\.", "", final_host)
        if score >= threshold:
            rec.update(status="verified", domain=domain, method=method, score=score,
                       myshopify=info["myshopify"], pixels=info["pixels"], extensions=info["extensions"],
                       evidence=f"{url} -> {final_url} | Shopify | title '{info['title'][:60]}' "
                                f"| og:site_name '{info['site_name'][:40]}' | name match {score}")
            return rec
        if best_partial is None or score > best_partial["score"] or best_partial.get("_closed"):
            best_partial = {"domain": domain, "score": score, "method": method,
                            "evidence": f"Shopify site but name match only {score}: '{info['title'][:60]}'"}
    if best_partial:
        closed = best_partial.pop("_closed", False)
        rec.update(status="closed" if closed else "weak_match", **best_partial)
    elif limited:
        rec.update(status="rate_limited", evidence="Shopify returned 429 / 'Verifying your connection' - retry later")
    return rec


async def _fetch(client, url: str):
    try:
        r = await client.get(url)
        h = {k.lower(): v for k, v in r.headers.items()}
        return r.status_code, str(r.url), h, r.text[:1_500_000]
    except Exception:
        return None, url, {}, ""


def load_stores() -> dict:
    if STORES_FILE.exists():
        return json.loads(STORES_FILE.read_text("utf-8"))
    return {}


def save_stores(stores: dict) -> None:
    ensure_dir()
    STORES_FILE.write_text(json.dumps(stores, indent=1, ensure_ascii=False), "utf-8")


RETRY_STATUSES = {"rate_limited", "error"}


async def enrich_verified(min_interval: float = 1.0, on_progress: Callable | None = None) -> int:
    """Re-read verified stores that predate a signal (e.g. theme app extensions), paced."""
    stores = load_stores()
    todo = [k for k, s in stores.items() if s.get("status") == "verified" and "extensions" not in s]
    throttle = ShopifyThrottle(min_interval=min_interval)
    async with http.make_client("chrome", timeout=12.0) as client:
        for n, k in enumerate(todo, 1):
            s = stores[k]
            for _ in range(3):
                await throttle.wait()
                status, final_url, headers, html = await _fetch(client, f"https://{s['domain']}/")
                if not _is_rate_limited(status, html):
                    break
                await throttle.rate_limited()
            if html and status and status < 400 and not _is_rate_limited(status, html):
                info = _inspect(html, headers)
                s["pixels"] = info["pixels"] or s.get("pixels", [])
                s["extensions"] = info["extensions"]
            if on_progress:
                on_progress(n, len(todo), s)
            if n % 25 == 0:
                save_stores(stores)
    save_stores(stores)
    return len(todo)


async def resolve_all(reviews: list[dict], concurrency: int = 6, refresh: bool = False,
                      on_progress: Callable | None = None, min_interval: float = 1.0) -> dict:
    stores = load_stores()
    todo = {}
    for rv in reviews:
        if not rv.get("store"):
            continue
        k = store_key(rv["store"], rv.get("country", ""))
        if refresh or k not in stores or stores[k].get("status") in RETRY_STATUSES:
            todo[k] = (rv["store"], rv.get("country", ""))
    sem = asyncio.Semaphore(concurrency)  # DNS work runs in parallel; HTTP to Shopify is paced by the throttle
    throttle = ShopifyThrottle(min_interval=min_interval)
    done = 0
    async with http.make_client("chrome", timeout=12.0) as client:
        async def one(k, name, country):
            nonlocal done
            async with sem:
                try:
                    stores[k] = await resolve_store(client, name, country, throttle)
                except Exception as e:
                    stores[k] = {"store": name, "country": country, "status": "error", "evidence": str(e)[:120]}
                done += 1
                if on_progress:
                    on_progress(done, len(todo), stores[k])
                if done % 25 == 0:
                    save_stores(stores)
        await asyncio.gather(*(one(k, n, c) for k, (n, c) in todo.items()))
    save_stores(stores)
    from collections import Counter
    return {"resolved_now": len(todo), "shopify_429s": throttle.hits_429,
            "status": dict(Counter(s.get("status") for s in stores.values()))}
