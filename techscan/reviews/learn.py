"""Learn which Shopify `apiClientId` belongs to which competitor app.

Reviewer stores are a labelled dataset: we *know* a store used BeProfit because it wrote a
BeProfit review. For each app, compare how often every apiClientId appears in its reviewers'
Web Pixels manifests (p_in) versus in all other Shopify stores we have seen (p_out):

    candidate if  c_in >= MIN_STORES  and  p_in >= MIN_SHARE  and  p_in >= LIFT * p_out + 0.05

Two caveats are built in:
- Reviewers may have uninstalled the app since (1-2 star reviewers especially), so the signal
  is computed on 3-5 star reviewers first, and on everyone as a fallback.
- An app with no storefront pixel produces no candidate. That is a result too: it proves the
  app is backend-only, and App Store reviews are the only way to find its users.

A second, independent method: an app pixel whose configuration names the vendor (e.g. a
config_url on getelevar.com) maps its apiClientId directly. Both methods are recorded with
their evidence in config/shopify_app_ids.json, which shopify.py uses for detection.
"""
from __future__ import annotations

import glob
import json
import re
import time
from collections import Counter, defaultdict

from .. import RUNS_DIR
from ..shopify import PIXEL_KEYWORDS
from . import APP_IDS_FILE
from .collect import load as load_reviews
from .resolve import load_stores, store_key

MIN_STORES = 3
MIN_SHARE = 0.25
LIFT = 4.0


def _background_pixels() -> dict[str, set[str]]:
    """domain -> set(apiClientId) from every scan run (other Shopify stores = the 'out' group)."""
    out: dict[str, set[str]] = {}
    for f in sorted(glob.glob(str(RUNS_DIR / "*" / "results.json"))):
        try:
            data = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        for r in data.get("results", []):
            ids = {str(p.get("apiClientId")) for p in r.get("shopify_pixels", []) if p.get("type") == "APP" and p.get("apiClientId")}
            ids |= {f"ext:{h}" for h in r.get("shopify_app_extensions", [])}
            if ids:
                out[r["domain"]] = ids
    return out


def learn() -> dict:
    reviews = load_reviews()
    stores = load_stores()
    # domain -> pixel ids, for verified reviewer stores that expose a manifest
    store_ids: dict[str, set[str]] = {}
    store_cfg: dict[str, list[dict]] = {}
    tool_domains: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"all": set(), "positive": set()})
    for rv in reviews:
        st = stores.get(store_key(rv.get("store", ""), rv.get("country", "")))
        if not st or st.get("status") != "verified" or not (st.get("pixels") or st.get("extensions")):
            continue
        d = st["domain"]
        # two kinds of app signal share one namespace: pixel apiClientIds and "ext:<theme-extension-handle>"
        store_ids[d] = {str(p["apiClientId"]) for p in st.get("pixels") or [] if p.get("type") == "APP" and p.get("apiClientId")}
        store_ids[d] |= {f"ext:{h}" for h in st.get("extensions") or []}
        store_cfg[d] = st["pixels"]
        tool_domains[rv["tool"]]["all"].add(d)
        if (rv.get("rating") or 0) >= 3:
            tool_domains[rv["tool"]]["positive"].add(d)

    universe = dict(_background_pixels())
    universe.update(store_ids)

    per_tool, ids = {}, {}
    for tool, groups in sorted(tool_domains.items()):
        result = {"reviewer_stores_with_pixels": len(groups["all"]), "positive_reviewer_stores": len(groups["positive"])}
        chosen = None
        for label in ("positive", "all"):
            members = groups[label]
            if len(members) < MIN_STORES:
                continue
            others = [d for d in universe if d not in members]
            c_in = Counter(i for d in members for i in universe.get(d, ()))
            c_out = Counter(i for d in others for i in universe.get(d, ()))
            cands = []
            for i, n in c_in.items():
                p_in, p_out = n / len(members), c_out[i] / max(1, len(others))
                if n >= MIN_STORES and p_in >= MIN_SHARE and p_in >= LIFT * p_out + 0.05:
                    cands.append({"apiClientId": i, "stores": n, "of": len(members), "p_in": round(p_in, 2),
                                  "p_out": round(p_out, 3), "group": label,
                                  "example_stores": sorted(d for d in members if i in universe.get(d, ()))[:5]})
            cands.sort(key=lambda c: (c["p_in"] - c["p_out"], c["stores"]), reverse=True)
            result[f"top_candidates_{label}"] = cands[:3]
            if cands and not chosen:
                chosen = cands[0]
        if chosen:
            result["status"] = "learned"
            result["apiClientId"] = chosen["apiClientId"]
            ids.setdefault(chosen["apiClientId"], {
                "tool": tool,
                "kind": "theme app extension" if chosen["apiClientId"].startswith("ext:") else "web pixel apiClientId",
                "method": "co-occurrence in App Store reviewer stores",
                "evidence": f"{chosen['stores']}/{chosen['of']} {tool} reviewer stores carry it vs "
                            f"{chosen['p_out']:.1%} of other Shopify stores",
                "example_stores": chosen["example_stores"],
            })
        elif len(groups["all"]) < MIN_STORES:
            result["status"] = "too_few_stores"
        else:
            result["status"] = "no_pixel_signal"
            result["note"] = ("Neither a pixel nor a theme extension is shared by this app's reviewers: "
                              "likely backend-only (Admin API) - App Store reviews are the way to find its users.")
        per_tool[tool] = result

    # method 2: vendor named inside a pixel's configuration
    kw = [(re.compile(k, re.I), t) for k, t in PIXEL_KEYWORDS.items() if t in tool_domains or t in {"Elevar", "Triple Whale", "Polar Analytics", "Littledata"}]
    seen_cfg: dict[tuple[str, str], set[str]] = defaultdict(set)
    all_pixels = dict(store_cfg)
    for f in sorted(glob.glob(str(RUNS_DIR / "*" / "results.json"))):
        try:
            for r in json.load(open(f, encoding="utf-8")).get("results", []):
                if r.get("shopify_pixels"):
                    all_pixels[r["domain"]] = [{"apiClientId": p.get("apiClientId"), "type": p.get("type"),
                                                "config": p.get("configuration_excerpt", "")} for p in r["shopify_pixels"]]
        except Exception:
            continue
    for d, pixels in all_pixels.items():
        for p in pixels:
            if p.get("type") != "APP" or not p.get("apiClientId"):
                continue
            for rx, tool in kw:
                if rx.search(p.get("config") or ""):
                    seen_cfg[(str(p["apiClientId"]), tool)].add(d)
    for (i, tool), domains in seen_cfg.items():
        if len(domains) >= 2 and i not in ids:
            ids[i] = {"tool": tool, "method": "vendor named in pixel configuration",
                      "evidence": f"configuration references {tool} on {len(domains)} stores",
                      "example_stores": sorted(domains)[:5]}
            per_tool.setdefault(tool, {})
            per_tool[tool].setdefault("status", "learned")
            per_tool[tool].setdefault("apiClientId", i)

    out = {"learned_at": time.strftime("%Y-%m-%d %H:%M"), "universe_shopify_stores": len(universe),
           "ids": ids, "per_tool": per_tool}
    APP_IDS_FILE.write_text(json.dumps(out, indent=1, ensure_ascii=False), "utf-8")
    return out


async def quick_learn(per_tool: int = 5, max_attempts: int = 30, on_progress=None) -> dict:
    """Sample-based variant: per tool, resolve reviewers (4-5★ newest first: most likely still
    installed) only until `per_tool` stores are verified, then look for the signal they share.

    A signal shared by >= 4 of 5 stores of one tool and by few stores of the other tools is
    taken as that tool's id. Comparing against the other tools' samples filters out ids that
    almost every store has (Google & YouTube, Facebook & Instagram, Klaviyo...).
    """
    from ..fetch import http as _http
    from .resolve import (ShopifyThrottle, _fetch, _inspect, _is_rate_limited, resolve_store,
                          save_stores)

    reviews = load_reviews()
    stores = load_stores()
    throttle = ShopifyThrottle(min_interval=1.0)
    sample: dict[str, list[str]] = {}
    async with _http.make_client("chrome", timeout=12.0) as client:
        by_tool: dict[str, list[dict]] = defaultdict(list)
        for rv in reviews:
            by_tool[rv["tool"]].append(rv)
        for tool, rvs in sorted(by_tool.items()):
            rvs.sort(key=lambda r: (r.get("rating") or 0, r.get("date") or ""), reverse=True)
            picked, attempts = [], 0
            for rv in rvs:
                if len(picked) >= per_tool or attempts >= max_attempts:
                    break
                k = store_key(rv["store"], rv.get("country", ""))
                st = stores.get(k)
                if not st or st.get("status") in ("rate_limited", "error"):
                    attempts += 1
                    st = await resolve_store(client, rv["store"], rv.get("country", ""), throttle)
                    stores[k] = st
                if st.get("status") != "verified":
                    continue
                if "extensions" not in st:  # older record: re-read homepage for theme extensions
                    for _ in range(3):
                        await throttle.wait()
                        status, _u, headers, html = await _fetch(client, f"https://{st['domain']}/")
                        if not _is_rate_limited(status, html):
                            break
                        await throttle.rate_limited()
                    if html and status and status < 400:
                        info = _inspect(html, headers)
                        st["pixels"] = info["pixels"] or st.get("pixels", [])
                        st["extensions"] = info["extensions"]
                if st["domain"] not in picked:
                    picked.append(st["domain"])
                    if on_progress:
                        on_progress(tool, len(picked), st)
            sample[tool] = picked
            save_stores(stores)

    signals = {}
    for st in stores.values():
        if st.get("status") == "verified":
            s = {str(p["apiClientId"]) for p in st.get("pixels") or [] if p.get("type") == "APP" and p.get("apiClientId")}
            s |= {f"ext:{h}" for h in st.get("extensions") or []}
            signals[st["domain"]] = s

    result, ids = {}, {}
    for tool, doms in sample.items():
        others = [d for t, ds in sample.items() if t != tool for d in ds if d not in doms]
        c_in = Counter(i for d in doms for i in signals.get(d, ()))
        c_out = Counter(i for d in others for i in signals.get(d, ()))
        need = max(2, round(0.8 * len(doms)))
        shared = [
            {"id": i, "in": n, "of": len(doms), "other_tools_stores": c_out[i], "of_other": len(others)}
            for i, n in c_in.most_common() if n >= need
        ]
        specific = [s for s in shared if s["other_tools_stores"] <= max(1, 0.15 * len(others))]
        r = {"sample": doms, "shared_by_most": shared[:8], "status": "", "id": None}
        if len(doms) < 3:
            r["status"] = "too_few_stores"
        elif specific:
            best = specific[0]
            r.update(status="learned", id=best["id"])
            ids[best["id"]] = {
                "tool": tool,
                "kind": "theme app extension" if best["id"].startswith("ext:") else "web pixel apiClientId",
                "method": f"shared by {best['in']}/{best['of']} sampled {tool} reviewer stores",
                "evidence": f"{best['in']}/{best['of']} {tool} reviewer stores vs {best['other_tools_stores']}/"
                            f"{best['of_other']} stores of other tools",
                "example_stores": [d for d in doms if best["id"] in signals.get(d, ())][:5],
            }
        else:
            r["status"] = "no_pixel_signal"
            r["note"] = ("No pixel or theme extension shared by this tool's sampled stores that other tools' "
                         "stores lack: likely backend-only (Admin API).")
        result[tool] = r

    # keep ids learned earlier from pixel configurations (e.g. Elevar's config_url) if not contradicted
    prev = json.loads(APP_IDS_FILE.read_text("utf-8")) if APP_IDS_FILE.exists() else {}
    for i, v in (prev.get("ids") or {}).items():
        ids.setdefault(i, v)
    out = {"learned_at": time.strftime("%Y-%m-%d %H:%M"), "method": f"sample of {per_tool} verified stores per tool",
           "ids": ids, "per_tool": {t: {"status": r["status"], "apiClientId": r["id"], "sample": r["sample"],
                                        "shared_by_most": r["shared_by_most"], "note": r.get("note", ""),
                                        "reviewer_stores_with_pixels": len(r["sample"])}
                                    for t, r in result.items()}}
    APP_IDS_FILE.write_text(json.dumps(out, indent=1, ensure_ascii=False), "utf-8")
    return out


def load_ids() -> dict:
    if APP_IDS_FILE.exists():
        return json.loads(APP_IDS_FILE.read_text("utf-8")).get("ids", {})
    return {}
