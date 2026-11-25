"""Detection engine: Signals + FingerprintDB -> technologies, each with evidence.

Own implementation of the Wappalyzer rule semantics (pattern/confidence/version syntax,
implies / requires / requiresCategory / excludes), plus two extensions:
  - scriptSrc rules are also tested against *network* script requests, so tags injected
    at runtime (GTM, Shopify Web Pixels) are found, not just <script src> in the HTML.
  - DNS A-record range hints and the Shopify Web Pixels manifest (see shopify.py).

Every detection carries a list of Evidence: where it was seen (http/browser/dns/...), which
rule field matched, the key (header/cookie/js variable name) and the matched text.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from .fingerprints import FingerprintDB, Pattern, Tech
from .signals import Signals

MAX_EVIDENCE_PER_TECH = 6
SNIPPET = 140

# Sites embed browser API keys in their HTML (e.g. Google Maps `key=AIza...`). They are public,
# but they belong to the scanned site, so evidence keeps the proof and drops the key value.
_SECRET_RES = [re.compile(r"AIza[0-9A-Za-z_\-]{35}")]


def redact(text: str) -> str:
    for rx in _SECRET_RES:
        text = rx.sub(lambda m: m.group(0)[:4] + "...REDACTED", text)
    return text


@dataclass
class Evidence:
    source: str
    field: str
    key: str = ""
    match: str = ""
    pattern: str = ""
    confidence: int = 100

    def __post_init__(self) -> None:
        self.key = redact(self.key)
        self.match = redact(self.match)

    def as_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in ("", None)}

    def short(self) -> str:
        k = f"{self.key}=" if self.key else ""
        return f"[{self.source}] {self.field}: {k}{self.match}"[:220]


@dataclass
class Detection:
    name: str
    confidence: int = 0
    version: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    implied_by: list[str] = field(default_factory=list)
    _seen_patterns: set = field(default_factory=set)

    def add(self, ev: Evidence, pattern_id: str, version: str | None) -> None:
        if pattern_id not in self._seen_patterns:
            self._seen_patterns.add(pattern_id)
            self.confidence = min(100, self.confidence + ev.confidence)
        if version and len(version) > len(self.version):
            self.version = version[:40]
        if len(self.evidence) < MAX_EVIDENCE_PER_TECH and not any(
            e.field == ev.field and e.key == ev.key and e.source == ev.source for e in self.evidence
        ):
            self.evidence.append(ev)


class Engine:
    def __init__(self, db: FingerprintDB):
        self.db = db
        self.techs = list(db.techs.values())
        # all JS global paths, sent to the browser in one evaluate() call
        self.js_paths = sorted({p for t in self.techs for p in t.js})
        # DOM "properties" rules (e.g. React: `body > div` has `_reactRootContainer`) can only be
        # checked on a live DOM; the browser evaluates them and reports under DOM_PROP_KEY keys.
        self.dom_props = sorted({(r.selector, r.name) for t in self.techs for r in t.dom if r.kind == "property"})

    # ------------------------------------------------------------------ public
    def analyze(self, sig: Signals, found: dict[str, Detection] | None = None) -> dict[str, Detection]:
        """Accumulates into `found`: the same rule matched via two sources (http + browser)
        adds evidence but is only counted once towards confidence."""
        found = {} if found is None else found
        html_low = sig.html.lower() if sig.html else ""
        net_scripts = [u for u, rt in sig.network if rt == "script"]
        net_hosts_paths = [_host_path(u) for u, _ in sig.network]
        cookie_names = list(sig.cookies)
        select_cache: dict[str, list] = {}

        for t in self.techs:
            hits: list[tuple[Evidence, str, str | None]] = []
            src = sig.source

            if sig.url:
                for p in t.url:
                    self._test(p, sig.url, src, "url", "", hits)
            if sig.headers:
                for name, pats in t.headers.items():
                    if name in sig.headers:
                        for p in pats:
                            self._test(p, sig.headers[name], src, "header", name, hits)
            if sig.cookies:
                for name, pats in t.cookies.items():
                    matched = [c for c in cookie_names if fnmatch.fnmatch(c.lower(), name)] if "*" in name else (
                        [name] if name in sig.cookies else [c for c in cookie_names if c.lower() == name]
                    )
                    for c in matched[:1]:
                        for p in pats:
                            self._test(p, sig.cookies[c], src, "cookie", c, hits, show_value=False)
            if sig.meta:
                for name, pats in t.meta.items():
                    for content in sig.meta.get(name, [])[:3]:
                        for p in pats:
                            self._test(p, content, src, "meta", name, hits)
            if t.script_src:
                for s in sig.script_srcs:
                    for p in t.script_src:
                        self._test(p, s, src, "script src", "", hits)
                for s in net_scripts:
                    for p in t.script_src:
                        self._test(p, s, src, "network script", "", hits)
            if t.scripts and sig.inline_scripts:
                for p in t.scripts:
                    for body in sig.inline_scripts:
                        if self._test(p, body, src, "inline script", "", hits):
                            break
            if t.html and sig.html:
                for p in t.html:
                    self._test(p, sig.html, src, "html", "", hits)
            if t.text and sig.text:
                for p in t.text:
                    self._test(p, sig.text, src, "text", "", hits)
            if t.css and sig.css:
                for p in t.css:
                    self._test(p, sig.css, src, "css", "", hits)
            if t.xhr and net_hosts_paths:
                for p in t.xhr:
                    for hp in net_hosts_paths:
                        if self._test(p, hp, src, "network request", "", hits):
                            break
            if t.js and sig.js_values:
                for path, pats in t.js.items():
                    if path in sig.js_values:
                        for p in pats:
                            self._test(p, sig.js_values[path], src, "js global", path, hits)
            if t.dns and sig.dns:
                for rtype, pats in t.dns.items():
                    for rec in sig.dns.get(rtype.upper(), []):
                        for p in pats:
                            self._test(p, rec, src, "dns", rtype.upper(), hits)
            if t.cert_issuer and sig.cert_issuer:
                for p in t.cert_issuer:
                    self._test(p, sig.cert_issuer, src, "tls issuer", "", hits)
            if t.robots and sig.robots:
                for p in t.robots:
                    self._test(p, sig.robots, src, "robots.txt", "", hits)
            if t.dom and html_low:
                self._dom(t, sig, html_low, select_cache, hits)

            if hits:
                det = found.setdefault(t.name, Detection(t.name))
                for ev, pid, ver in hits:
                    det.add(ev, pid, ver)
        return found

    def finalize(self, found: dict[str, Detection]) -> dict[str, Detection]:
        """implies -> requires/requiresCategory -> excludes (Wappalyzer order)."""
        db = self.db
        changed = True
        while changed:
            changed = False
            for name in list(found):
                t = db.techs.get(name)
                if not t:
                    continue
                for imp, conf in t.implies:
                    if imp not in db.techs:
                        continue
                    parent_conf = found[name].confidence
                    if imp not in found:
                        found[imp] = Detection(imp, confidence=min(conf, parent_conf), implied_by=[name])
                        changed = True
                    elif name not in found[imp].implied_by and not found[imp].evidence:
                        found[imp].implied_by.append(name)

        present_cats = {c for n in found for c in db.techs[n].cats if n in db.techs}
        for name in list(found):
            t = db.techs.get(name)
            if not t:
                continue
            if t.requires and not any(r in found for r in t.requires):
                del found[name]
            elif t.requires_cats and not any(c in present_cats for c in t.requires_cats):
                del found[name]
        for name in list(found):
            t = db.techs.get(name)
            if t:
                for ex in t.excludes:
                    found.pop(ex, None)
        return found

    # --------------------------------------------------------------- matching
    @staticmethod
    def _test(p: Pattern, value: str, source: str, fld: str, key: str, hits: list, show_value: bool = True) -> bool:
        if value is None:
            return False
        if p.regex is None:
            m = None
            shown = value[:SNIPPET] if show_value and value else "(present)"
        else:
            m = p.regex.search(value)
            if not m:
                return False
            if fld in ("html", "inline script", "text", "css", "robots.txt"):
                a, b = max(0, m.start() - 40), min(len(value), m.end() + 60)
                shown = value[a:b].replace("\n", " ").strip()
            else:
                shown = value[:SNIPPET] if show_value else "(present)"
        ver = _resolve_version(p.version, m) if p.version else None
        pid = f"{fld}|{key}|{p.raw}"
        hits.append((Evidence(source, fld, key, shown[:SNIPPET * 2], p.raw[:120], p.confidence), pid, ver))
        return True

    def _dom(self, t: Tech, sig: Signals, html_low: str, cache: dict, hits: list) -> None:
        soup = sig.soup
        if soup is None:
            return
        for rule in t.dom:
            if rule.hints and not any(all(tok in html_low for tok in alt) for alt in rule.hints):
                continue
            if rule.selector not in cache:
                try:
                    cache[rule.selector] = soup.select(rule.selector, limit=5)
                except Exception:
                    cache[rule.selector] = []
            els = cache[rule.selector]
            if not els:
                continue
            el = els[0]
            if rule.kind == "exists":
                hits.append((Evidence(sig.source, "dom", rule.selector[:80], str(el)[:SNIPPET], "", rule.pattern.confidence),
                             f"dom|{rule.selector}|exists", None))
            elif rule.kind == "property":
                # Only trust the live-DOM check done in the browser. An earlier version treated
                # "element exists" as a match and flagged React/Preact on ~95% of sites
                # (`body > div` exists everywhere) - see README, run v6 audit.
                key = dom_prop_key(rule.selector, rule.name)
                if key in sig.js_values:
                    self._test(rule.pattern, sig.js_values[key], sig.source, "dom property", f"{rule.selector[:60]}.{rule.name}", hits)
            elif rule.kind == "attribute":
                for e in els:
                    val = e.get(rule.name)
                    if isinstance(val, list):
                        val = " ".join(val)
                    if val is not None and self._test(rule.pattern, val, sig.source, "dom attribute", f"{rule.selector[:60]}@{rule.name}", hits):
                        break
            elif rule.kind == "text":
                for e in els:
                    if self._test(rule.pattern, e.get_text(" ", strip=True)[:2000], sig.source, "dom text", rule.selector[:60], hits):
                        break


def dom_prop_key(selector: str, prop: str) -> str:
    return f"dom::{selector}::{prop}"


def _host_path(url: str) -> str:
    try:
        u = urlsplit(url)
        return f"{u.netloc}{u.path}"
    except Exception:
        return url


_TERNARY = re.compile(r"\\(\d+)\?([^:]*):(.*)")


def _resolve_version(tpl: str, m: re.Match | None) -> str | None:
    if not tpl:
        return None

    def grp(i: int) -> str:
        if m is None:
            return ""
        try:
            return m.group(i) or ""
        except (IndexError, re.error):
            return ""

    t = _TERNARY.fullmatch(tpl)
    if t:
        return (t.group(2) if grp(int(t.group(1))) else t.group(3)) or None
    out = re.sub(r"\\(\d+)", lambda x: grp(int(x.group(1))), tpl).strip()
    return out if out and re.search(r"[\w]", out) else None
