"""Per-domain orchestration: cheap tiers first, escalate only when they fail or say little.

    DNS + TLS  ──┐  (always, parallel, never bot-blocked)
    HTTP fetch ──┤──> classify page: ok | challenge | blocked | parked | empty | error
                 │
    Browser    ──┤  browser_mode="all":   every reachable domain (max coverage, ~10x cost)
                 │  browser_mode="smart": only when HTTP was blocked/empty/JS-shell
    robots.txt ──┤  (cheap, sometimes says "Shopify")
    Wayback    ──┘  only if no live HTML could be obtained at all

Each tier yields a Signals object -> Engine.analyze -> evidence tagged with that tier.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable

from .competitors import CompetitorMap
from .engine import Detection, Engine, Evidence
from .fetch import dns_probe, http, tls_probe, wayback
from .fetch.blockdetect import needs_js_render
from .fetch.browser import BrowserPool
from .fingerprints import FingerprintDB
from .inputs import has_subdomain
from .shopify import (detections_from_extensions, detections_from_manifest, extract_app_extensions,
                      extract_manifest, summarize)
from .signals import Signals

ALL_TIERS = ("http", "browser", "dns", "tls", "robots", "wayback")
CMS_CATS = {1, 6, 51, 11}  # CMS, Ecommerce, Page builders, Blogs


@dataclass
class ScanConfig:
    tiers: tuple[str, ...] = ALL_TIERS
    ua: str = "chrome"              # chrome | naive
    browser_mode: str = "all"       # all | smart | off
    concurrency: int = 24
    browser_concurrency: int = 4
    http_retries: int = 2
    proxy: str | None = None
    wayback_max_age_days: int = 730
    label: str = ""
    preset: str = ""

    @classmethod
    def from_preset(cls, key: str, **overrides) -> "ScanConfig":
        from .presets import get
        p = get(key)
        return cls(tiers=p.tiers, browser_mode=p.browser_mode, preset=p.key, **overrides)

    def uses(self, tier: str) -> bool:
        if tier == "browser" and self.browser_mode == "off":
            return False
        return tier in self.tiers


@dataclass
class Context:
    cfg: ScanConfig
    engine: Engine
    db: FingerprintDB
    comp: CompetitorMap
    client: object
    browser: BrowserPool | None
    on_progress: Callable | None = None
    h1_client: object = None
    done: int = 0
    total: int = 0
    stats: dict = field(default_factory=dict)


async def scan_domain(domain: str, ctx: Context) -> dict:
    cfg, engine = ctx.cfg, ctx.engine
    t0 = time.perf_counter()
    rec: dict = {"domain": domain, "status": "", "status_detail": "", "final_url": "", "analysis_sources": [],
                 "fetch": {}, "technologies": [], "competitive": {}, "shopify_pixels": []}
    found: dict[str, Detection] = {}
    sub = has_subdomain(domain)

    dns_task = asyncio.create_task(dns_probe.probe(domain)) if cfg.uses("dns") else None
    tls_task = asyncio.create_task(tls_probe.issuer(domain if sub else domain)) if cfg.uses("tls") else None

    # ---- tier 1: HTTP
    hres = await http.fetch(ctx.client, domain, sub, retries=cfg.http_retries, h1_client=ctx.h1_client) if cfg.uses("http") else None
    if hres:
        rec["fetch"]["http"] = {
            "final_url": hres.final_url, "status": hres.status, "verdict": hres.verdict.state,
            "vendor": hres.verdict.vendor, "reason": hres.verdict.reason,
            "redirects": hres.redirects[:6],
            "attempts": [a.__dict__ for a in hres.attempts],
        }

    dres = await dns_task if dns_task else None
    if dres:
        rec["fetch"]["dns"] = {"nxdomain": dres.nxdomain, "records": {k: v[:8] for k, v in dres.records.items()}}
        if dres.records:
            engine.analyze(Signals(source="dns", dns=dres.records), found)
            for tech, why in dres.ip_hints:
                if tech in ctx.db.techs:
                    found.setdefault(tech, Detection(tech)).add(Evidence("dns", "A-record range", "A", why, "", 75), f"iprange|{tech}", None)
    tls_issuer, tls_valid = (await tls_task) if tls_task else ("", False)
    if tls_task:
        rec["fetch"]["tls"] = {"issuer": tls_issuer, "valid": tls_valid}
        if tls_issuer:
            engine.analyze(Signals(source="tls", cert_issuer=tls_issuer), found)

    live_html_sigs: list[Signals] = []
    if hres and (hres.verdict.state != "error" or hres.html):  # even a 404/500 page reveals server, CDN, builder
        s = Signals(source="http", url=hres.final_url, headers=hres.headers, cookies=hres.cookies, html=hres.html).parse_html()
        engine.analyze(s, found)
        if hres.verdict.usable:
            live_html_sigs.append(s)
        rec["final_url"] = hres.final_url

    dead = bool(dres and dres.nxdomain)

    # ---- tier 2: headless browser
    want_browser = False
    if ctx.browser and cfg.uses("browser") and not dead:
        if cfg.browser_mode == "all":
            want_browser = True
        else:  # smart escalation
            want_browser = (hres is None or not hres.verdict.usable or needs_js_render(hres.html))
        if hres and hres.verdict.state == "parked":
            want_browser = False
    bres = None
    if want_browser:
        target = (hres.final_url if hres and hres.final_url else f"https://{domain}/")
        bres = await _render_bounded(ctx.browser, target, engine)
        if not bres.verdict.usable and bres.verdict.state == "error" and target.startswith("https://"):
            alt = f"http://{domain}/" if sub else f"https://www.{domain}/"
            bres2 = await _render_bounded(ctx.browser, alt, engine)
            if bres2.verdict.usable or bres2.verdict.state != "error":
                bres = bres2
        rec["fetch"]["browser"] = {
            "final_url": bres.final_url, "status": bres.status, "verdict": bres.verdict.state,
            "vendor": bres.verdict.vendor, "reason": bres.verdict.reason, "elapsed_ms": bres.elapsed_ms,
            "challenge_waited": bres.challenge_waited, "network_requests": len(bres.network),
            "js_globals_found": len(bres.js_values), "engine": ctx.browser.engine,
        }
        if bres.verdict.state != "error" or bres.html:
            s = Signals(source="browser", url=bres.final_url, headers=bres.headers, cookies=bres.cookies,
                        html=bres.html, network=bres.network, js_values=bres.js_values).parse_html()
            engine.analyze(s, found)
            if bres.verdict.usable:
                live_html_sigs.insert(0, s)  # rendered DOM is the richest source
                rec["final_url"] = bres.final_url or rec["final_url"]

    # ---- robots.txt
    if cfg.uses("robots") and live_html_sigs:
        origin = _origin(rec["final_url"]) or f"https://{domain}"
        code, txt = await http.fetch_text(ctx.client, f"{origin}/robots.txt", 100_000)
        if code == 200 and txt and "<html" not in txt[:500].lower():
            engine.analyze(Signals(source="robots", robots=txt), found)

    # ---- Shopify Web Pixels manifest
    for s in live_html_sigs:
        manifest = extract_manifest(s.inline_scripts)
        if manifest:
            rec["shopify_pixels"] = summarize(manifest)
            for name, det in detections_from_manifest(manifest, s.source, set(ctx.db.techs)).items():
                tgt = found.setdefault(name, Detection(name))
                for ev in det.evidence:
                    tgt.add(ev, f"wpm|{ev.key}|{name}", None)
            break

    # ---- Shopify theme app extensions (apps without a pixel still load their theme blocks)
    ext_handles: set[str] = set()
    for s in live_html_sigs:
        ext_handles.update(extract_app_extensions(s.html, [u for u, _ in s.network]))
    if ext_handles:
        rec["shopify_app_extensions"] = sorted(ext_handles)
        src = live_html_sigs[0].source
        for name, det in detections_from_extensions(sorted(ext_handles), src, set(ctx.db.techs)).items():
            tgt = found.setdefault(name, Detection(name))
            for ev in det.evidence:
                tgt.add(ev, f"ext|{ev.key}|{name}", None)

    # ---- last resort: Wayback snapshot
    stale_names: set[str] = set()
    if not live_html_sigs and cfg.uses("wayback") and not dead:
        snap = await wayback.latest_snapshot(ctx.client, domain, cfg.wayback_max_age_days)
        if snap:
            ts, html_ = snap
            wfound = engine.analyze(Signals(source=f"wayback:{ts[:8]}", html=html_).parse_html(), {})
            for name, det in wfound.items():
                if name not in found:
                    det.confidence = max(1, int(det.confidence * 0.6))
                    found[name] = det
                    stale_names.add(name)
            rec["fetch"]["wayback"] = {"snapshot": ts, "techs_added": len(stale_names)}

    found = engine.finalize(found)

    # ---- status
    states = [x.verdict.state for x in (hres, bres) if x is not None]
    vendors = [x.verdict.vendor for x in (hres, bres) if x is not None and x.verdict.vendor]
    if live_html_sigs:
        rec["status"] = "ok"
        rec["status_detail"] = "browser" if bres and bres.verdict.usable else "http"
    elif dead:
        rec["status"], rec["status_detail"] = "dead", "NXDOMAIN"
    elif "parked" in states:
        rec["status"], rec["status_detail"] = "parked", "domain parking page"
    elif "challenge" in states or "blocked" in states:
        rec["status"] = "blocked"
        rec["status_detail"] = (vendors[0] if vendors else "unknown WAF") + (" (wayback fallback)" if stale_names else "")
    elif "empty" in states:
        rec["status"], rec["status_detail"] = "empty", "no content"
    else:
        reasons = [x.verdict.reason for x in (hres, bres) if x is not None]
        rec["status"], rec["status_detail"] = "unreachable", (reasons[0] if reasons else "")
    rec["analysis_sources"] = sorted({e.source.split(":")[0] for d in found.values() for e in d.evidence})

    # ---- serialize
    techs = {}
    for name, det in sorted(found.items(), key=lambda kv: (-kv[1].confidence, kv[0])):
        t = ctx.db.techs.get(name)
        techs[name] = {
            "name": name,
            "categories": ctx.db.category_names(t.cats) if t else [],
            "confidence": det.confidence,
            "version": det.version or None,
            "evidence": [e.as_dict() for e in det.evidence],
            "implied_by": det.implied_by or None,
            "stale_from_archive": name in stale_names or None,
            "rule_source": t.source if t else "custom",
            "website": t.website if t else "",
        }
        techs[name] = {k: v for k, v in techs[name].items() if v is not None}
    rec["technologies"] = list(techs.values())
    cms = [n for n in techs if ctx.db.techs.get(n) and set(ctx.db.techs[n].cats) & CMS_CATS]
    rec["competitive"] = ctx.comp.evaluate(techs, cms).__dict__
    rec["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
    return rec


async def _render_bounded(browser: BrowserPool, url: str, engine: Engine, timeout_s: float = 75):
    """A hung page must not cost us the DNS/TLS/HTTP evidence already collected for the
    domain (an early run lost a whole domain to the global per-domain timeout)."""
    from .fetch.blockdetect import classify as _classify
    from .fetch.browser import BrowserResult
    try:
        async with browser.sem:  # queue time for a browser slot must not count against the page
            return await asyncio.wait_for(browser._render(url, engine.js_paths, engine.dom_props), timeout=timeout_s)
    except asyncio.TimeoutError:
        r = BrowserResult()
        r.verdict = _classify(None, {}, "", error=f"browser: render exceeded {timeout_s:.0f}s")
        return r


def _origin(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        u = urlsplit(url)
        return f"{u.scheme}://{u.netloc}" if u.scheme and u.netloc else ""
    except Exception:
        return ""


async def run_scan(domains: list[str], cfg: ScanConfig, on_progress: Callable | None = None) -> tuple[list[dict], dict]:
    db = FingerprintDB.load()
    engine = Engine(db)
    comp = CompetitorMap()
    started = time.time()
    results: list[dict | None] = [None] * len(domains)
    sem = asyncio.Semaphore(cfg.concurrency)

    async with http.make_client(cfg.ua, cfg.proxy) as client, http.make_client(cfg.ua, cfg.proxy, http2=False) as h1:
        browser_cm = BrowserPool(cfg.browser_concurrency, cfg.proxy) if cfg.uses("browser") else None
        browser = await browser_cm.__aenter__() if browser_cm else None
        ctx = Context(cfg, engine, db, comp, client, browser, on_progress, h1_client=h1, total=len(domains))
        try:
            async def one(i: int, d: str):
                async with sem:
                    try:
                        rec = await asyncio.wait_for(scan_domain(d, ctx), timeout=300)
                    except Exception as e:  # never lose a domain from the output
                        rec = {"domain": d, "status": "error", "status_detail": f"{type(e).__name__}: {str(e)[:150]}",
                               "technologies": [], "competitive": comp.evaluate({}, []).__dict__, "fetch": {}}
                    results[i] = rec
                    ctx.done += 1
                    if on_progress:
                        on_progress(ctx.done, ctx.total, rec)

            await asyncio.gather(*(one(i, d) for i, d in enumerate(domains)))
        finally:
            if browser_cm:
                await browser_cm.__aexit__(None, None, None)

    meta = {
        "label": cfg.label,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)),
        "duration_s": round(time.time() - started, 1),
        "config": {k: (list(v) if isinstance(v, tuple) else v) for k, v in cfg.__dict__.items() if k != "proxy"},
        "proxy_used": bool(cfg.proxy),
        "fingerprints": db.stats,
        "browser_engine": browser.engine if browser else None,
    }
    return [r for r in results if r is not None], meta
