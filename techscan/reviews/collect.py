"""Collect Shopify App Store reviews for competitor apps, 1 star first.

URL pattern: https://apps.shopify.com/<handle>/reviews?ratings[]=<1..5>&sort_by=newest&page=<n>
Each review block exposes: rating (aria-label), date, text, store name, country,
"N months using the app", and a stable review id (data-review-content-id).

Politeness: one request at a time, 1-2 s between requests, backoff on 429/5xx.
Results are merged into data/reviews/reviews.json by review id, so re-runs only add new reviews.
"""
from __future__ import annotations

import asyncio
import json
import random
import re
import time
from datetime import datetime
from typing import Callable

import httpx
from bs4 import BeautifulSoup

from ..competitors import CompetitorMap
from ..fetch.http import BROWSER_HEADERS
from . import REVIEWS_FILE, ensure_dir

BASE = "https://apps.shopify.com"
_STARS = re.compile(r"(\d)\s+out of\s+5", re.I)


def parse_reviews(html: str, tool: str, handle: str) -> list[dict]:
    soup = BeautifulSoup(html, "lxml")
    out = []
    for b in soup.select("[data-merchant-review]"):
        rid = b.get("data-review-content-id")
        star_el = b.select_one('[aria-label*="out of 5"]')
        m = _STARS.search(star_el.get("aria-label", "")) if star_el else None
        rating = int(m.group(1)) if m else None
        date_el = b.select_one(".tw-text-body-xs.tw-text-fg-tertiary")
        date_txt = date_el.get_text(strip=True) if date_el else ""
        text_el = b.select_one("[data-truncate-content-copy]")
        text = text_el.get_text(" ", strip=True) if text_el else ""
        name_el = b.select_one("span[title]")
        store = (name_el.get("title") or name_el.get_text(strip=True)).strip() if name_el else ""
        meta_box = name_el.find_parent("div").find_parent("div") if name_el else None
        country, usage = "", ""
        if meta_box:
            for d in meta_box.find_all("div", recursive=False)[1:]:
                t = d.get_text(" ", strip=True)
                if "using the app" in t:
                    usage = t
                elif t and not country:
                    country = t
        reply = b.select_one("[data-merchant-review-reply]")
        out.append({
            "id": rid,
            "tool": tool,
            "app_handle": handle,
            "rating": rating,
            "date": _iso(date_txt),
            "store": store,
            "country": country,
            "usage": usage,
            "usage_months": _months(usage),
            "text": text,
            "developer_replied": bool(reply and reply.get_text(strip=True)),
            "url": f"{BASE}/{handle}/reviews/{rid}" if rid else f"{BASE}/{handle}/reviews",
        })
    return out


def _iso(s: str) -> str:
    s = re.sub(r"^Edited\s+", "", s.strip())
    for fmt in ("%B %d, %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            pass
    return s


def _months(usage: str) -> int | None:
    if not usage:
        return None
    m = re.search(r"(\d+)\s+(day|month|year)", usage)
    if not m:
        return 0 if "day" in usage or "less than" in usage.lower() else None
    n, unit = int(m.group(1)), m.group(2)
    return n * 12 if unit == "year" else (n if unit == "month" else 0)


def load() -> list[dict]:
    if REVIEWS_FILE.exists():
        return json.loads(REVIEWS_FILE.read_text("utf-8"))
    return []


def save(reviews: list[dict]) -> None:
    ensure_dir()
    REVIEWS_FILE.write_text(json.dumps(reviews, indent=1, ensure_ascii=False), "utf-8")


async def _get(client: httpx.AsyncClient, url: str, params: dict) -> str | None:
    for attempt in range(4):
        try:
            r = await client.get(url, params=params)
        except httpx.HTTPError:
            await asyncio.sleep(3 * (attempt + 1))
            continue
        if r.status_code == 200:
            return r.text
        if r.status_code == 404:
            return None
        await asyncio.sleep((2 ** attempt) * 3 + random.uniform(0, 2))  # 429 / 5xx
    return None


async def collect(tools: list[str] | None = None, ratings=(1, 2, 3, 4, 5), max_pages: int = 5,
                  delay: float = 1.2, on_progress: Callable | None = None) -> dict:
    """Collect reviews, star by star from 1 to 5. Returns stats; merges into reviews.json."""
    handles = CompetitorMap().app_store_handles
    tools = tools or list(handles)
    existing = {r["id"]: r for r in load() if r.get("id")}
    stats = {"requests": 0, "new": 0, "seen": 0, "by_tool": {}}
    now = time.strftime("%Y-%m-%d")
    async with httpx.AsyncClient(headers=BROWSER_HEADERS, follow_redirects=True, timeout=25, http2=True) as client:
        for tool in tools:
            handle = handles.get(tool)
            if not handle:
                continue
            tstats = stats["by_tool"].setdefault(tool, {str(r): 0 for r in ratings})
            for star in ratings:
                for page in range(1, max_pages + 1):
                    html = await _get(client, f"{BASE}/{handle}/reviews",
                                      {"ratings[]": star, "sort_by": "newest", "page": page})
                    stats["requests"] += 1
                    batch = parse_reviews(html, tool, handle) if html else []
                    for rv in batch:
                        rv["collected_at"] = existing.get(rv["id"], {}).get("collected_at", now)
                        if rv["id"] not in existing:
                            stats["new"] += 1
                        else:
                            stats["seen"] += 1
                            # keep resolution fields from earlier runs
                        existing[rv["id"]] = {**existing.get(rv["id"], {}), **rv}
                    tstats[str(star)] += len(batch)
                    if on_progress:
                        on_progress({"tool": tool, "star": star, "page": page, "found": len(batch),
                                     "total": len(existing)})
                    await asyncio.sleep(delay + random.uniform(0, 0.8))
                    if len(batch) < 10:  # last page for this star rating
                        break
            save(list(existing.values()))
    stats["total"] = len(existing)
    return stats
