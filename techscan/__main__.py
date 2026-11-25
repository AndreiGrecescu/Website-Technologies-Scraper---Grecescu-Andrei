"""CLI.

  python -m techscan scan data/domains.parquet --label "full run"
  python -m techscan scan data/domains.parquet --ua naive --browser off --tiers http   # the naive baseline
  python -m techscan scan list.txt --browser smart --limit 50
  python -m techscan history
  python -m techscan serve            # upload UI on http://127.0.0.1:8000
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time

from .inputs import load_domains
from .pipeline import ALL_TIERS, ScanConfig, run_scan
from .presets import PRESETS, estimates
from .presets import get as get_preset
from .report import history_markdown, write_run


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):  # store names in any script; Windows consoles default to cp1252
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(prog="techscan")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a list of domains")
    s.add_argument("input", help=".parquet / .csv / .txt / .json / .xlsx with domains")
    s.add_argument("--label", default="")
    s.add_argument("--preset", choices=list(PRESETS), default=None,
                   help="light | medium | advanced (sets --tiers and --browser; see `techscan estimate`)")
    s.add_argument("--tiers", default=None, help=f"comma list from {ALL_TIERS} (expert mode)")
    s.add_argument("--ua", choices=["chrome", "naive"], default="chrome")
    s.add_argument("--browser", dest="browser_mode", choices=["all", "smart", "off"], default=None)
    s.add_argument("--concurrency", type=int, default=24)
    s.add_argument("--browser-concurrency", type=int, default=4)
    s.add_argument("--retries", type=int, default=2)
    s.add_argument("--proxy", default=None, help="http://user:pass@host:port (optional)")
    s.add_argument("--limit", type=int, default=0)
    s.add_argument("--only", default="", help="comma list of domains to (re)scan from the input")
    s.add_argument("--out", default=None, help="output dir (default runs/<timestamp>)")

    e = sub.add_parser("estimate", help="show Light / Medium / Advanced time estimates for a list")
    e.add_argument("input")

    rv = sub.add_parser("reviews", help="competitor customers from Shopify App Store reviews")
    rv.add_argument("step", choices=["collect", "resolve", "learn", "quick", "all", "stats"],
                    help="quick = resolve only 5 verified stores per tool and learn ids from that sample")
    rv.add_argument("--per-tool", type=int, default=5)
    rv.add_argument("--tools", default="", help="comma list (default: every app in config/competitors.json)")
    rv.add_argument("--max-pages", type=int, default=5, help="pages (10 reviews) per star rating per app")
    rv.add_argument("--refresh", action="store_true", help="re-resolve stores already resolved")

    sub.add_parser("history", help="print the run log as a markdown table")
    sv = sub.add_parser("serve", help="start the upload web UI")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)

    a = ap.parse_args(argv)
    if a.cmd == "history":
        print(history_markdown())
        return 0
    if a.cmd == "reviews":
        return _reviews_cmd(a)
    if a.cmd == "estimate":
        n = len(load_domains(a.input))
        print(f"{n} domains\n")
        for est in estimates(n):
            print(f"  {est['name']:<9} {est['estimate_text']:<22} live coverage ~{est['measured_live_rate']:.0%}, "
                  f"{est['measured_unique_techs']} unique techs on the 200-domain benchmark")
            print(f"            {est['description']}\n")
        return 0
    if a.cmd == "serve":
        import uvicorn
        uvicorn.run("techscan.web:app", host=a.host, port=a.port)
        return 0

    domains = load_domains(a.input)
    if a.only:
        keep = {d.strip() for d in a.only.split(",")}
        domains = [d for d in domains if d in keep]
    if a.limit:
        domains = domains[: a.limit]
    common = dict(ua=a.ua, concurrency=a.concurrency, browser_concurrency=a.browser_concurrency,
                  http_retries=a.retries, proxy=a.proxy, label=a.label)
    if a.preset and not (a.tiers or a.browser_mode):
        cfg = ScanConfig.from_preset(a.preset, **common)
    else:  # expert mode (used for the v1-v7 ablation runs); defaults = advanced
        cfg = ScanConfig(tiers=tuple(t.strip() for t in (a.tiers or ",".join(ALL_TIERS)).split(",") if t.strip()),
                         browser_mode=a.browser_mode or "all", **common)
    eta = ""
    if cfg.preset:
        eta = f" | preset={cfg.preset}, estimated {get_preset(cfg.preset).estimate_text(len(domains))}"
    print(f"Scanning {len(domains)} domains | tiers={cfg.tiers} ua={cfg.ua} browser={cfg.browser_mode}{eta}", flush=True)
    t0 = time.time()

    def progress(done, total, rec):
        n = len(rec.get("technologies", []))
        seg = rec.get("competitive", {}).get("segment", "")
        print(f"[{done:>4}/{total}] {rec['domain'][:42]:<42} {rec['status']:<11} {rec.get('status_detail','')[:28]:<28} techs={n:<3} seg={seg}", flush=True)

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    results, meta = asyncio.run(run_scan(domains, cfg, progress))
    from pathlib import Path
    out = write_run(results, meta, Path(a.out) if a.out else None)
    from .report import summarize
    s = summarize(results, meta)
    print(f"\nDone in {time.time()-t0:.0f}s -> {out}")
    print(f"status: {s['status']}  success_rate={s['success_rate']}")
    print(f"unique technologies: {s['unique_techs']}   total detections: {s['total_detections']}   shopify stores: {s['shopify_stores']}")
    print(f"lead segments: {s['segments']}")
    return 0


def _reviews_cmd(a) -> int:
    import json
    from collections import Counter

    from .reviews import collect as rc
    from .reviews import learn as rl
    from .reviews import resolve as rr

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    tools = [t.strip() for t in a.tools.split(",") if t.strip()] or None
    if a.step in ("collect", "all"):
        def p(e):
            print(f"{e['tool']:<16} {e['star']}* page {e['page']}: {e['found']} reviews (total {e['total']})", flush=True)
        print(json.dumps(asyncio.run(rc.collect(tools, max_pages=a.max_pages, on_progress=p))))
    if a.step in ("resolve", "all"):
        reviews = [r for r in rc.load() if not tools or r["tool"] in tools]

        def p2(done, total, s):
            print(f"[{done}/{total}] {s.get('store','')[:30]:<30} {s.get('status',''):<10} {s.get('domain','')}", flush=True)
        print(json.dumps(asyncio.run(rr.resolve_all(reviews, refresh=a.refresh, on_progress=p2))))
    if a.step in ("learn", "all"):
        n = asyncio.run(rr.enrich_verified(on_progress=lambda d, t, s: print(
            f"[enrich {d}/{t}] {s.get('domain','')}: {len(s.get('extensions') or [])} extensions", flush=True)))
        if n:
            print(f"enriched {n} verified stores with theme app extensions")
        out = rl.learn()
        for tool, r in sorted(out["per_tool"].items()):
            print(f"{tool:<18} {r.get('status',''):<16} id={r.get('apiClientId','-'):<14} "
                  f"stores_with_pixels={r.get('reviewer_stores_with_pixels','-')}")
    if a.step == "quick":
        out = asyncio.run(rl.quick_learn(a.per_tool, on_progress=lambda t, n, s: print(
            f"{t:<16} {n}/{a.per_tool} {s['domain']:<32} pixels={len(s.get('pixels') or [])} "
            f"extensions={len(s.get('extensions') or [])}", flush=True)))
        print()
        for tool, r in sorted(out["per_tool"].items()):
            print(f"{tool:<16} {r['status']:<16} id={r['apiClientId'] or '-':<26} sample={len(r['sample'])}")
            for s in r["shared_by_most"][:4]:
                print(f"{'':<18}shared {s['id']:<30} {s['in']}/{s['of']} of this tool · {s['other_tools_stores']}/{s['of_other']} of other tools")
    if a.step == "stats":
        reviews, stores = rc.load(), rr.load_stores()
        print("reviews by tool:", dict(Counter(r["tool"] for r in reviews)))
        print("reviews by rating:", dict(sorted(Counter(r["rating"] for r in reviews).items())))
        print("stores:", dict(Counter(s.get("status") for s in stores.values())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
