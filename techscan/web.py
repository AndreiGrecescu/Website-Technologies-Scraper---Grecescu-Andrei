"""Upload UI: drop a parquet/csv/txt/json/xlsx with domains, watch it scan, filter the leads.

    python -m techscan serve   ->  http://127.0.0.1:8000

Jobs run in a worker thread with their own event loop (Playwright needs the Proactor loop
on Windows, which uvicorn's loop may not be). Every job is a normal run: same outputs in
runs/<id>/ and a row in runs/history.csv, so CLI and UI runs are directly comparable.
"""
from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from . import ROOT, RUNS_DIR
from .inputs import load_domains
from .pipeline import ScanConfig, run_scan
from .presets import PRESETS
from .presets import estimates as preset_estimates
from .report import summarize, write_run

UPLOADS = ROOT / "uploads"
STATIC = Path(__file__).parent / "static"
ALLOWED = {".parquet", ".pq", ".csv", ".tsv", ".txt", ".json", ".xlsx", ".xls"}
DOWNLOADABLE = {"results.json", "technologies.csv", "leads.csv", "domains.csv", "summary.json"}

app = FastAPI(title="techscan")
JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text("utf-8")


UPLOADED: dict[str, dict] = {}


@app.post("/api/uploads")
async def upload(file: UploadFile = File(...)):
    """Step 1: store + parse the list, return domain count and per-preset time estimates."""
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED:
        raise HTTPException(400, f"Unsupported file type {ext}. Use one of {sorted(ALLOWED)}")
    UPLOADS.mkdir(exist_ok=True)
    upload_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    path = UPLOADS / f"{upload_id}{ext}"
    path.write_bytes(await file.read())
    try:
        domains = load_domains(path)
    except Exception as e:
        raise HTTPException(400, f"Could not read domains: {e}")
    if not domains:
        raise HTTPException(400, "No valid domains found in the file")
    UPLOADED[upload_id] = {"file": file.filename, "domains": domains}
    return {"upload_id": upload_id, "file": file.filename, "domains": len(domains),
            "sample": domains[:5], "estimates": preset_estimates(len(domains))}


@app.get("/api/estimate")
def estimate(n: int):
    return {"estimates": preset_estimates(max(0, n))}


@app.post("/api/jobs")
async def create_job(
    upload_id: str = Form(...),
    preset: str = Form("medium"),
    limit: int = Form(0),
    label: str = Form(""),
):
    up = UPLOADED.get(upload_id)
    if not up:
        raise HTTPException(404, "Upload expired - please upload the file again")
    if preset not in PRESETS:
        raise HTTPException(400, f"preset must be one of {list(PRESETS)}")
    domains = up["domains"][:limit] if limit and limit > 0 else up["domains"]
    job_id = upload_id if upload_id not in JOBS else f"{upload_id}-{uuid.uuid4().hex[:3]}"
    p = PRESETS[preset]
    cfg = ScanConfig.from_preset(preset, label=label or f"{p.name}: {up['file']}")
    job = {"id": job_id, "file": up["file"], "label": cfg.label, "state": "running", "done": 0,
           "total": len(domains), "log": [], "started": time.time(), "error": None, "preset": preset,
           "estimate_s": round(p.estimate_s(len(domains)))}
    with _LOCK:
        JOBS[job_id] = job
    threading.Thread(target=_run_job, args=(job_id, domains, cfg), daemon=True).start()
    return {"id": job_id, "total": len(domains)}


def _run_job(job_id: str, domains: list[str], cfg: ScanConfig) -> None:
    job = JOBS[job_id]

    def progress(done, total, rec):
        job["done"] = done
        job["log"].append({
            "domain": rec["domain"], "status": rec["status"], "detail": rec.get("status_detail", ""),
            "techs": len(rec.get("technologies", [])), "segment": rec.get("competitive", {}).get("segment", ""),
        })
        job["log"] = job["log"][-400:]

    loop = asyncio.ProactorEventLoop() if sys.platform == "win32" else asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        results, meta = loop.run_until_complete(run_scan(domains, cfg, progress))
        write_run(results, meta, RUNS_DIR / job_id, run_id=job_id)
        job["state"] = "done"
    except Exception as e:
        job["state"], job["error"] = "failed", f"{type(e).__name__}: {e}"
    finally:
        loop.close()


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str):
    job = JOBS.get(job_id)
    if job:
        out = {k: v for k, v in job.items()}
        elapsed = time.time() - job["started"]
        out["elapsed_s"] = round(elapsed)
        if job["state"] == "running":
            # blend the preset estimate with the observed pace once some domains are done
            if job["done"] >= 5:
                pace = elapsed / job["done"]
                out["remaining_s"] = round(max(0, pace * (job["total"] - job["done"])))
            else:
                out["remaining_s"] = round(max(0, job["estimate_s"] - elapsed))
        return out
    if (RUNS_DIR / job_id / "results.json").exists():
        return {"id": job_id, "state": "done"}
    raise HTTPException(404, "unknown job")


@app.get("/api/runs")
def list_runs():
    runs = []
    if RUNS_DIR.exists():
        for d in sorted(RUNS_DIR.iterdir(), reverse=True):
            sfile = d / "summary.json"
            if d.is_dir() and sfile.exists():
                s = json.loads(sfile.read_text("utf-8"))
                runs.append({
                    "id": d.name, "label": s.get("meta", {}).get("label", ""), "domains": s["domains"],
                    "success_rate": s["success_rate"], "unique_techs": s["unique_techs"],
                    "shopify_stores": s["shopify_stores"], "segments": s["segments"],
                    "started_at": s.get("meta", {}).get("started_at", ""),
                })
    running = [{"id": j["id"], "label": j["label"], "state": j["state"], "done": j["done"], "total": j["total"]}
               for j in JOBS.values() if j["state"] == "running"]
    return {"runs": runs, "running": running}


@app.get("/api/runs/{run_id}")
def run_data(run_id: str):
    d = _run_dir(run_id)
    data = json.loads((d / "results.json").read_text("utf-8"))
    summary = json.loads((d / "summary.json").read_text("utf-8")) if (d / "summary.json").exists() else summarize(data["results"], data["meta"])
    rows = []
    for r in data["results"]:
        rows.append({
            "domain": r["domain"], "status": r["status"], "detail": r.get("status_detail", ""),
            "final_url": r.get("final_url", ""), "competitive": r.get("competitive", {}),
            "pixels": len(r.get("shopify_pixels", [])),
            "technologies": [
                {"name": t["name"], "categories": t.get("categories", []), "confidence": t["confidence"],
                 "version": t.get("version"), "implied_by": t.get("implied_by"), "stale": t.get("stale_from_archive"),
                 "evidence": t.get("evidence", [])[:4]}
                for t in r.get("technologies", [])
            ],
        })
    return JSONResponse({"summary": summary, "rows": rows})


@app.get("/api/runs/{run_id}/download/{name}")
def download(run_id: str, name: str):
    if name not in DOWNLOADABLE:
        raise HTTPException(404)
    f = _run_dir(run_id) / name
    if not f.exists():
        raise HTTPException(404)
    return FileResponse(f, filename=f"{run_id}-{name}")


# ----------------------------------------------------------------- Leads (App Store reviews)
LEADS_JOB: dict = {"state": "idle", "log": [], "step": "", "started": None, "error": None}


@app.get("/api/leads")
def leads():
    from .reviews import APP_IDS_FILE
    from .reviews.collect import load as load_reviews
    from .reviews.resolve import load_stores, store_key

    stores = load_stores()
    rows = []
    for rv in load_reviews():
        st = stores.get(store_key(rv.get("store", ""), rv.get("country", ""))) or {}
        rows.append({
            "id": rv.get("id"), "tool": rv["tool"], "rating": rv.get("rating"), "date": rv.get("date"),
            "store": rv.get("store"), "country": rv.get("country"), "usage": rv.get("usage"),
            "usage_months": rv.get("usage_months"), "text": rv.get("text"), "url": rv.get("url"),
            "developer_replied": rv.get("developer_replied"),
            "domain": st.get("domain", ""), "domain_status": st.get("status", "unresolved"),
            "domain_evidence": st.get("evidence", ""), "domain_method": st.get("method", ""),
            "pixels": len(st.get("pixels") or []),
        })
    app_ids = json.loads(APP_IDS_FILE.read_text("utf-8")) if APP_IDS_FILE.exists() else {}
    return JSONResponse({"rows": rows, "app_ids": app_ids, "job": {k: LEADS_JOB[k] for k in ("state", "step")}})


@app.post("/api/leads/refresh")
def leads_refresh(step: str = Form("all"), max_pages: int = Form(5)):
    if LEADS_JOB["state"] == "running":
        raise HTTPException(409, "A leads job is already running")
    if step not in ("all", "collect", "resolve", "learn"):
        raise HTTPException(400, "step must be all|collect|resolve|learn")
    LEADS_JOB.update(state="running", log=[], step=step, started=time.time(), error=None)
    threading.Thread(target=_leads_job, args=(step, max(1, min(max_pages, 30))), daemon=True).start()
    return {"ok": True}


@app.get("/api/leads/job")
def leads_job():
    out = dict(LEADS_JOB)
    out["log"] = out["log"][-80:]
    out["elapsed_s"] = round(time.time() - out["started"]) if out["started"] else 0
    return out


def _leads_job(step: str, max_pages: int) -> None:
    from .reviews import collect as rc
    from .reviews import learn as rl
    from .reviews import resolve as rr

    def log(msg):
        LEADS_JOB["log"].append(msg)
        LEADS_JOB["log"] = LEADS_JOB["log"][-500:]

    loop = asyncio.ProactorEventLoop() if sys.platform == "win32" else asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        if step in ("collect", "all"):
            LEADS_JOB["step"] = "collecting reviews (1★ → 5★)"
            loop.run_until_complete(rc.collect(max_pages=max_pages, on_progress=lambda e: log(
                f"{e['tool']} {e['star']}★ page {e['page']}: {e['found']} reviews (total {e['total']})")))
        if step in ("resolve", "all"):
            LEADS_JOB["step"] = "finding store domains"
            loop.run_until_complete(rr.resolve_all(rc.load(), on_progress=lambda d, t, s: log(
                f"[{d}/{t}] {s.get('store', '')} → {s.get('status', '')} {s.get('domain', '')}")))
        if step in ("learn", "all"):
            LEADS_JOB["step"] = "reading theme app extensions of verified stores"
            loop.run_until_complete(rr.enrich_verified(on_progress=lambda d, t, s: log(
                f"[{d}/{t}] {s.get('domain', '')}: {len(s.get('extensions') or [])} extensions")))
            LEADS_JOB["step"] = "learning app ids (pixels + theme extensions)"
            out = rl.learn()
            for tool, r in sorted(out["per_tool"].items()):
                log(f"{tool}: {r.get('status')} {r.get('apiClientId', '')}")
            global_reset()
        LEADS_JOB["state"], LEADS_JOB["step"] = "done", "done"
    except Exception as e:
        LEADS_JOB["state"], LEADS_JOB["error"] = "failed", f"{type(e).__name__}: {e}"
    finally:
        loop.close()


def global_reset() -> None:
    """Make freshly learned app ids active for the next scans in this process."""
    from . import shopify
    shopify._APP_IDS = None


def _run_dir(run_id: str) -> Path:
    d = (RUNS_DIR / run_id).resolve()
    if RUNS_DIR.resolve() not in d.parents or not (d / "results.json").exists():
        raise HTTPException(404, "unknown run")
    return d
