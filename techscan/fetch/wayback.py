"""Last-resort fallback: the most recent Internet Archive snapshot of the homepage.

When a site is behind a bot wall we can't pass (DataDome, aggressive Cloudflare), the
Wayback Machine has often already crawled it. `id_` mode returns the original bytes
without the archive toolbar. Detections from here are marked with the snapshot date and a
lower confidence: the stack may have changed since. Only HTML-derived signals are used
(headers/cookies would be the archive's, not the site's).
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx


async def latest_snapshot(client: httpx.AsyncClient, domain: str, max_age_days: int = 730) -> tuple[str, str] | None:
    """Returns (timestamp, html) or None.

    Uses the CDX API (latest 200 capture). The simpler /wayback/available endpoint was
    tried first and returned empty results even for example.com during our runs.
    """
    try:
        r = await client.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": domain, "output": "json", "limit": "-1", "filter": "statuscode:200",
                    "fl": "timestamp,original"},
            timeout=25,
        )
        rows = r.json() if r.status_code == 200 and r.text.strip() else []
    except Exception:
        return None
    if len(rows) < 2:
        return None
    ts, original = rows[-1][0], rows[-1][1]
    snap = {"url": original}
    try:
        age = (datetime.now(timezone.utc) - datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)).days
    except ValueError:
        return None
    if age > max_age_days:
        return None
    raw_url = f"https://web.archive.org/web/{ts}id_/{snap['url']}"
    try:
        r = await client.get(raw_url, timeout=30)
        if r.status_code != 200 or len(r.text) < 500:
            return None
        return ts, r.text[:3_000_000]
    except Exception:
        return None
