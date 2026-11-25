"""Search-depth presets with time estimates.

Every number here was measured on the 200-domain test list from one home connection
(see runs/history.csv). Time model per preset:

    estimate = max(floor_s, base_s + n_domains * per_domain_s)

- per_domain_s : wall-clock seconds per domain at the preset's default concurrency
- base_s       : fixed cost (load 7.7k fingerprints, launch Chromium)
- floor_s      : even 3 domains take this long - the slowest site (timeouts, Cloudflare
                 challenge wait) dominates small batches

Estimates assume default concurrency and a single IP; they scale ~linearly with list size.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Preset:
    key: str
    name: str
    description: str
    tiers: tuple[str, ...]
    browser_mode: str
    per_domain_s: float
    base_s: float
    floor_s: float
    measured_run: str          # label of the run the numbers come from
    measured_live_rate: float  # share of domains whose live content was analyzed
    measured_unique_techs: int # on the 200-domain list

    def estimate_s(self, n: int) -> float:
        if n <= 0:
            return 0.0
        return max(self.floor_s, self.base_s + n * self.per_domain_s)

    def estimate_text(self, n: int) -> str:
        s = self.estimate_s(n)
        lo, hi = s * 0.7, s * 1.4
        return f"~{_fmt(s)} ({_fmt(lo)}-{_fmt(hi)})"


PRESETS: dict[str, Preset] = {
    "light": Preset(
        key="light",
        name="Light",
        description="HTTP + DNS + TLS + robots.txt. No browser. Fast triage: platform, CDN, "
                    "server, email provider, tags hard-coded in HTML. Misses tools injected by JS/GTM.",
        tiers=("http", "dns", "tls", "robots"),
        browser_mode="off",
        per_domain_s=0.6, base_s=10, floor_s=30,
        measured_run="v3", measured_live_rate=0.755, measured_unique_techs=333,
    ),
    "medium": Preset(
        key="medium",
        name="Medium",
        description="Light + headless browser only where HTTP fails (bot walls, JS-only sites) "
                    "+ Wayback fallback. Best cost/coverage ratio for large lists.",
        tiers=("http", "browser", "dns", "tls", "robots", "wayback"),
        browser_mode="smart",
        per_domain_s=1.1, base_s=15, floor_s=60,
        measured_run="v4", measured_live_rate=0.83, measured_unique_techs=387,
    ),
    "advanced": Preset(
        key="advanced",
        name="Advanced",
        description="Headless browser on every live site: JS globals, every network request, "
                    "Shopify Web Pixels, GTM-injected analytics, live-DOM checks. Max coverage, "
                    "what competitor detection needs.",
        tiers=("http", "browser", "dns", "tls", "robots", "wayback"),
        browser_mode="all",
        per_domain_s=2.4, base_s=15, floor_s=90,
        measured_run="v7", measured_live_rate=0.83, measured_unique_techs=504,
    ),
}


def get(key: str) -> Preset:
    try:
        return PRESETS[key.lower()]
    except KeyError:
        raise ValueError(f"Unknown preset {key!r}. Choose from {list(PRESETS)}")


def estimates(n: int) -> list[dict]:
    return [{
        "key": p.key, "name": p.name, "description": p.description,
        "estimate_s": round(p.estimate_s(n)), "estimate_text": p.estimate_text(n),
        "measured_live_rate": p.measured_live_rate, "measured_unique_techs": p.measured_unique_techs,
        "measured_run": p.measured_run,
    } for p in PRESETS.values()]


def _fmt(s: float) -> str:
    s = int(round(s))
    if s < 90:
        return f"{s}s"
    if s < 3600:
        return f"{round(s / 60)} min"
    h, m = divmod(round(s / 60), 60)
    return f"{h}h {m:02d}m"
