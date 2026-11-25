"""Write run outputs + append one row to runs/history.csv (the experiment log)."""
from __future__ import annotations

import csv
import json
import re
import time
from collections import Counter
from pathlib import Path

from . import RUNS_DIR

HISTORY = RUNS_DIR / "history.csv"
HISTORY_FIELDS = [
    "run_id", "label", "started_at", "duration_s", "domains", "ok", "ok_via_browser", "blocked", "parked",
    "dead", "unreachable", "empty", "error", "success_rate", "unique_techs", "total_detections",
    "avg_techs_per_ok", "shopify_stores", "seg_A", "seg_B", "seg_C", "seg_D", "seg_E",
    "ua", "browser_mode", "tiers", "concurrency", "browser_concurrency", "proxy",
]


def summarize(results: list[dict], meta: dict) -> dict:
    status = Counter(r["status"] for r in results)
    ok = [r for r in results if r["status"] == "ok"]
    techs = Counter(t["name"] for r in results for t in r.get("technologies", []))
    seg = Counter(r.get("competitive", {}).get("segment", "F") for r in results)
    blocked_by = Counter(r.get("status_detail", "").split(" ")[0] for r in results if r["status"] == "blocked")
    unreachable = Counter(_bucket(r.get("status_detail", "")) for r in results if r["status"] == "unreachable")
    competitor_usage = Counter(
        tool for r in results for tier, tools in r.get("competitive", {}).get("competitors", {}).items() for tool in tools
    )
    source_counts = Counter(e["source"].split(":")[0] for r in results for t in r.get("technologies", []) for e in t.get("evidence", []))
    only_browser = sum(
        1 for r in results for t in r.get("technologies", [])
        if t.get("evidence") and all(e["source"] == "browser" for e in t["evidence"])
    )
    return {
        "domains": len(results),
        "status": dict(status),
        "success_rate": round(len(ok) / max(1, len(results)), 3),
        "ok_via_browser": sum(1 for r in ok if r.get("status_detail") == "browser"),
        "blocked_by": dict(blocked_by),
        "unreachable_reasons": dict(unreachable),
        "unique_techs": len(techs),
        "total_detections": sum(techs.values()),
        "avg_techs_per_ok": round(sum(len(r["technologies"]) for r in ok) / max(1, len(ok)), 1),
        "top_techs": techs.most_common(40),
        "shopify_stores": sum(1 for r in results if r.get("competitive", {}).get("is_shopify")),
        "segments": dict(seg),
        "competitor_usage": competitor_usage.most_common(),
        "evidence_by_source": dict(source_counts),
        "detections_only_visible_in_browser": only_browser,
        "meta": meta,
    }


def _bucket(reason: str) -> str:
    r = reason.lower()
    for k in ("timeout", "connect", "ssl", "redirect", "http 4", "http 5", "browser"):
        if k in r:
            return k
    return re.sub(r"[:(].*", "", r)[:30] or "other"


def write_run(results: list[dict], meta: dict, out_dir: Path | None = None, run_id: str | None = None) -> Path:
    run_id = run_id or time.strftime("%Y%m%d-%H%M%S")
    out = out_dir or RUNS_DIR / run_id
    out.mkdir(parents=True, exist_ok=True)
    summary = summarize(results, meta)

    (out / "results.json").write_text(json.dumps({"meta": meta, "results": results}, indent=1, ensure_ascii=False), "utf-8")
    (out / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False), "utf-8")

    with open(out / "technologies.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "technology", "categories", "confidence", "version", "evidence_sources", "proof", "implied_by", "stale_from_archive"])
        for r in results:
            for t in r.get("technologies", []):
                ev = t.get("evidence", [])
                proof = " | ".join(
                    f"[{e['source']}] {e['field']}{(' ' + e['key']) if e.get('key') else ''}: {e.get('match', '')}"[:180] for e in ev[:3]
                )
                w.writerow([r["domain"], t["name"], "; ".join(t.get("categories", [])), t["confidence"], t.get("version", ""),
                            "; ".join(sorted({e["source"] for e in ev})), proof, "; ".join(t.get("implied_by", []) or []),
                            t.get("stale_from_archive", "")])

    with open(out / "leads.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "status", "platform", "segment", "segment_label", "lead_score",
                    "shopify_analytics_competitors", "behavior_analytics", "product_analytics", "web_analytics",
                    "shopify_app_pixels", "pitch", "proof"])
        rows = sorted(results, key=lambda r: (r.get("competitive", {}).get("segment", "F"), -r.get("competitive", {}).get("lead_score", 0)))
        for r in rows:
            c = r.get("competitive", {})
            comp = c.get("competitors", {})
            w.writerow([r["domain"], r["status"], c.get("platform", ""), c.get("segment", ""), c.get("segment_label", ""),
                        c.get("lead_score", 0), "; ".join(comp.get("shopify_analytics", [])),
                        "; ".join(comp.get("behavior_analytics", [])), "; ".join(comp.get("product_analytics", [])),
                        "; ".join(comp.get("web_analytics", [])), len(r.get("shopify_pixels", [])),
                        c.get("pitch", ""), " || ".join(c.get("proof", []))])

    with open(out / "domains.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "status", "status_detail", "final_url", "techs_found", "http_verdict", "http_status",
                    "browser_verdict", "browser_status", "challenge_waited", "tls_issuer", "elapsed_ms"])
        for r in results:
            fh, fb = r.get("fetch", {}).get("http", {}), r.get("fetch", {}).get("browser", {})
            w.writerow([r["domain"], r["status"], r.get("status_detail", ""), r.get("final_url", ""), len(r.get("technologies", [])),
                        fh.get("verdict", ""), fh.get("status", ""), fb.get("verdict", ""), fb.get("status", ""),
                        fb.get("challenge_waited", ""), r.get("fetch", {}).get("tls", {}).get("issuer", ""), r.get("elapsed_ms", "")])

    _append_history(run_id, summary, meta)
    return out


def _append_history(run_id: str, s: dict, meta: dict) -> None:
    RUNS_DIR.mkdir(exist_ok=True)
    new = not HISTORY.exists()
    st, seg, cfg = s["status"], s["segments"], meta.get("config", {})
    row = {
        "run_id": run_id, "label": meta.get("label", ""), "started_at": meta.get("started_at"),
        "duration_s": meta.get("duration_s"), "domains": s["domains"], "ok": st.get("ok", 0),
        "ok_via_browser": s["ok_via_browser"], "blocked": st.get("blocked", 0), "parked": st.get("parked", 0),
        "dead": st.get("dead", 0), "unreachable": st.get("unreachable", 0), "empty": st.get("empty", 0),
        "error": st.get("error", 0), "success_rate": s["success_rate"], "unique_techs": s["unique_techs"],
        "total_detections": s["total_detections"], "avg_techs_per_ok": s["avg_techs_per_ok"],
        "shopify_stores": s["shopify_stores"], **{f"seg_{k}": seg.get(k, 0) for k in "ABCDE"},
        "ua": cfg.get("ua"), "browser_mode": cfg.get("browser_mode"), "tiers": "+".join(cfg.get("tiers", [])),
        "concurrency": cfg.get("concurrency"), "browser_concurrency": cfg.get("browser_concurrency"),
        "proxy": meta.get("proxy_used"),
    }
    with open(HISTORY, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=HISTORY_FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)


def history_markdown() -> str:
    if not HISTORY.exists():
        return "(no runs yet)"
    rows = list(csv.DictReader(open(HISTORY, encoding="utf-8")))
    cols = ["run_id", "label", "ok", "blocked", "parked", "dead", "unreachable", "success_rate", "unique_techs",
            "total_detections", "shopify_stores", "seg_A", "duration_s"]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        lines.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
    return "\n".join(lines)
