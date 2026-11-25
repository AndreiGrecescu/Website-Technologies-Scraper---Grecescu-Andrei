"""Shopify-specific signal: the Web Pixels manifest.

Since 2023 Shopify apps track customers through "Web Pixels" that run in sandboxed iframes,
so classic detection (a <script src> in the theme) misses them. But every storefront page
ships an inline config, `webPixelsConfigList`, that lists *every* installed app pixel with
its `apiClientId` (the app's id) and its `configuration` (often containing account ids and
the vendor's own endpoints/keys). That is a near-complete inventory of the store's
tracking/analytics apps - exactly what a Shopify analytics vendor's sales team wants.

We parse it, keep the raw inventory in the output (pixel count, app ids), and turn vendor
keywords found inside each pixel's configuration into detections with evidence.
"""
from __future__ import annotations

import json
import re

from .engine import Detection, Evidence

# keyword (searched inside one pixel's configuration/JSON) -> technology name
PIXEL_KEYWORDS = {
    r"triple[\s_-]?whale|triplewhale|triple_pixel": "Triple Whale",
    r"polaranalytics|polar[\s_-]?pixel": "Polar Analytics",
    r"northbeam": "Northbeam",
    r"lifetimely": "Lifetimely",
    r"peelinsights|peel[\s_-]?insights": "Peel Insights",
    r"beprofit": "BeProfit",
    r"trueprofit": "TrueProfit",
    r"elevar": "Elevar",
    r"littledata": "Littledata",
    r"wickedreports": "Wicked Reports",
    r"hyros": "Hyros",
    r"rockerbox": "Rockerbox",
    r"lebesgue": "Lebesgue",
    r"admetrics": "Admetrics",
    r"getklar": "Klar",
    r"segmentstream": "SegmentStream",
    r"analyzify": "Analyzify",
    r"hotjar": "Hotjar",
    r"clarity\.ms|\"clarity": "Microsoft Clarity",
    r"luckyorange": "Lucky Orange",
    r"mixpanel": "Mixpanel",
    r"amplitude": "Amplitude",
    r"heapanalytics|heap[\s_-]?app": "Heap",
    r"klaviyo": "Klaviyo",
    r"\bG-[A-Z0-9]{6,}\b": "Google Analytics",
    r"\bAW-\d{6,}\b": "Google Ads Conversion Tracking",
    r"\"pixel_?id\"\s*:\s*\\?\"\d{10,}": "Facebook Pixel",
    r"tiktok": "TikTok Pixel",
    r"pinterest": "Pinterest Conversion Tag",
    r"snapchat|sc-static": "Snap Pixel",
}
_KW = [(re.compile(k, re.I), v) for k, v in PIXEL_KEYWORDS.items()]


def extract_manifest(inline_scripts: list[str]) -> list[dict]:
    for body in inline_scripts:
        i = body.find("webPixelsConfigList")
        if i < 0:
            continue
        start = body.find("[", i)
        if start < 0:
            continue
        end = _match_bracket(body, start)
        if end < 0:
            continue
        chunk = body[start:end + 1]
        try:
            items = json.loads(chunk)
            if isinstance(items, list):
                return [x for x in items if isinstance(x, dict)]
        except Exception:
            pass
        # fallback: not strict JSON - split on top-level objects
        return [{"raw": m.group(0)} for m in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", chunk)]
    return []


def _match_bracket(s: str, start: int) -> int:
    depth, in_str, esc = 0, False, False
    for j in range(start, min(len(s), start + 400_000)):
        ch = s[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return j
    return -1


def summarize(manifest: list[dict]) -> list[dict]:
    out = []
    for p in manifest:
        cfg = p.get("configuration") or p.get("raw") or ""
        out.append({
            "id": p.get("id"),
            "type": p.get("type"),
            "apiClientId": p.get("apiClientId"),
            "configuration_excerpt": (cfg if isinstance(cfg, str) else json.dumps(cfg))[:160],
        })
    return out


_EXT = re.compile(r"cdn\.shopify\.com/extensions/[^/\"'\s]+/([a-z0-9][a-z0-9-]*?)-(\d+)/", re.I)
_PROXY = re.compile(r"""["'(]/apps/([a-z0-9][a-z0-9_-]{2,40})""", re.I)


def extract_app_extensions(html: str, urls: list[str] | None = None) -> list[str]:
    """Theme app extensions: apps that add blocks/embeds to the theme load them from
    cdn.shopify.com/extensions/<uuid>/<app-handle>-<version>/ - the app's handle is in the URL.
    App proxies (/apps/<name>) are a weaker hint of the same kind. Works for apps with no pixel."""
    blob = (html or "") + "\n" + "\n".join(urls or [])
    out = []
    for m in _EXT.finditer(blob):
        h = m.group(1).lower()
        if re.fullmatch(r"[0-9a-f]{6,}(-[0-9a-f]+)*", h):  # anonymous uuid-style handle
            continue
        out.append(h)
    for m in _PROXY.finditer(html or ""):
        out.append("proxy:" + m.group(1).lower())
    return sorted(set(out))


def detections_from_extensions(handles: list[str], source: str, known_techs: set[str]) -> dict[str, Detection]:
    found: dict[str, Detection] = {}
    learned = _app_ids()
    for h in handles:
        app = learned.get(f"ext:{h}")
        hits = [(app["tool"], f"learned: {app['evidence']}")] if app else []
        for rx, tech in _KW:
            if rx.search(h):
                hits.append((tech, "app handle names the vendor"))
        for tech, why in hits:
            if tech not in known_techs:
                continue
            ev = Evidence(source=source, field="shopify theme app extension", key=h,
                          match=f"cdn.shopify.com/extensions/.../{h}-<version>/ ({why})"[:260], confidence=85)
            found.setdefault(tech, Detection(tech)).add(ev, f"ext|{h}|{tech}", None)
    return found


_APP_IDS: dict | None = None


def _app_ids() -> dict:
    """apiClientId -> {tool, method, evidence}, learned by techscan.reviews.learn."""
    global _APP_IDS
    if _APP_IDS is None:
        from .reviews.learn import load_ids
        try:
            _APP_IDS = load_ids()
        except Exception:
            _APP_IDS = {}
    return _APP_IDS


def detections_from_manifest(manifest: list[dict], source: str, known_techs: set[str]) -> dict[str, Detection]:
    found: dict[str, Detection] = {}
    learned = _app_ids()
    for p in manifest:
        app = learned.get(str(p.get("apiClientId")))
        if app and app["tool"] in known_techs:
            ev = Evidence(
                source=source,
                field="shopify app id",
                key=f"apiClientId={p.get('apiClientId')}",
                match=f"{app['tool']} pixel id ({app['method']}: {app['evidence']})"[:260],
                confidence=85,
            )
            found.setdefault(app["tool"], Detection(app["tool"])).add(ev, f"appid|{p.get('apiClientId')}", None)
        blob = json.dumps(p, ensure_ascii=False)
        for rx, tech in _KW:
            if tech not in known_techs:
                continue
            m = rx.search(blob)
            if not m:
                continue
            a, b = max(0, m.start() - 50), min(len(blob), m.end() + 50)
            ev = Evidence(
                source=source,
                field="shopify web pixel",
                key=f"apiClientId={p.get('apiClientId')} type={p.get('type')}",
                match=blob[a:b],
                pattern=rx.pattern,
                confidence=90,
            )
            found.setdefault(tech, Detection(tech)).add(ev, f"wpm|{p.get('id')}|{tech}", None)
    return found
