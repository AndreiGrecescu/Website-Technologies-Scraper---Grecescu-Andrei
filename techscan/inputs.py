"""Read domain lists from parquet / csv / txt / json / xlsx and normalize them."""
from __future__ import annotations

import json
import re
from pathlib import Path

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # offline, bundled PSL
_PREFERRED_COLS = ("root_domain", "domain", "domains", "website", "url", "host", "hostname", "site")


def load_domains(path: str | Path) -> list[str]:
    path = Path(path)
    ext = path.suffix.lower()
    values: list[str]
    if ext in (".parquet", ".pq"):
        import pandas as pd
        values = _from_frame(pd.read_parquet(path))
    elif ext in (".csv", ".tsv"):
        import pandas as pd
        df = pd.read_csv(path, sep=_sniff_sep(path), dtype=str)
        # headerless single-column csv: the "header" is itself a domain
        if len(df.columns) == 1 and "." in str(df.columns[0]):
            values = [str(df.columns[0])] + df.iloc[:, 0].dropna().tolist()
        else:
            values = _from_frame(df)
    elif ext in (".xlsx", ".xls"):
        import pandas as pd
        values = _from_frame(pd.read_excel(path, dtype=str))
    elif ext == ".json":
        data = json.loads(path.read_text("utf-8"))
        if isinstance(data, dict):
            data = next((v for v in data.values() if isinstance(v, list)), [])
        values = [d if isinstance(d, str) else (d.get("domain") or d.get("url") or "") for d in data]
    else:  # .txt or anything else: one per line / whitespace / comma separated
        lines = [ln for ln in path.read_text("utf-8", errors="replace").splitlines() if not ln.lstrip().startswith("#")]
        values = re.split(r"[\s,;]+", "\n".join(lines))
    return normalize(values)


def _sniff_sep(path: Path) -> str:
    """Pick the delimiter among real CSV separators only.

    pandas' own sniffing (sep=None) may pick any character: on a one-column file such as
    "Domain\\nhttps://www.freshful.ro" it chose "o" and cut the domain to "freshful.r".
    """
    import csv
    sample = path.read_text("utf-8-sig", errors="replace")[:65536]
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:  # single column: no delimiter at all
        return "\t" if path.suffix.lower() == ".tsv" else ","


def _from_frame(df) -> list[str]:
    cols = {c.lower(): c for c in df.columns}
    col = next((cols[c] for c in _PREFERRED_COLS if c in cols), None)
    if col is None:  # first column that looks like domains
        for c in df.columns:
            sample = df[c].dropna().astype(str).head(20)
            if len(sample) and (sample.str.contains(r"\.", regex=True).mean() > 0.8):
                col = c
                break
    if col is None:
        raise ValueError(f"No domain-like column found. Columns: {list(df.columns)}")
    return df[col].dropna().astype(str).tolist()


def normalize(values) -> list[str]:
    out, seen = [], set()
    for v in values:
        d = clean(v)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def clean(v: str) -> str:
    v = (v or "").strip().lower()
    if not v or v.startswith("#"):
        return ""
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
    v = v.split("/")[0].split("?")[0].split("#")[0].split("@")[-1].split(":")[0].strip(".")
    if v.startswith("www."):
        v = v[4:]
    try:
        v = v.encode("idna").decode("ascii")  # unicode domains -> punycode
    except Exception:
        pass
    return v if "." in v and re.fullmatch(r"[a-z0-9.-]+", v) else ""


def has_subdomain(domain: str) -> bool:
    return bool(_EXTRACT(domain).subdomain)
