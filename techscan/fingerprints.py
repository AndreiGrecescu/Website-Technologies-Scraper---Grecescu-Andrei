"""Load and compile the fingerprint database.

Sources, merged in this order (later wins on name collision):
  1. webappanalyzer (open-source continuation of the Wappalyzer rule set, GPL-3.0),
     fetched by scripts/update_fingerprints.py into vendor/ - not committed.
  2. config/custom_fingerprints.json - our own rules (Shopify analytics competitors etc).

Rule pattern syntax (Wappalyzer-compatible):
  "regex\\;confidence:50\\;version:\\1"
JS-flavoured regexes are translated to Python `re` where needed; the ones that still fail
to compile are counted and reported (never silently dropped).
"""
from __future__ import annotations

import glob
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import CONFIG_DIR, VENDOR_DIR

_NAMED_GROUP = re.compile(r"\(\?<(?=[A-Za-z_])")  # JS (?<name> -> Python (?P<name>


@dataclass
class Pattern:
    raw: str
    regex: re.Pattern | None  # None => "presence is enough"
    confidence: int = 100
    version: str | None = None


@dataclass
class DomRule:
    selector: str
    kind: str  # exists | attribute | property | text
    name: str | None
    pattern: Pattern
    hints: list[list[str]] = field(default_factory=list)  # literal tokens for cheap prefilter


@dataclass
class Tech:
    name: str
    cats: list[int]
    website: str = ""
    description: str = ""
    saas: bool | None = None
    source: str = "webappanalyzer"
    url: list[Pattern] = field(default_factory=list)
    html: list[Pattern] = field(default_factory=list)
    text: list[Pattern] = field(default_factory=list)
    css: list[Pattern] = field(default_factory=list)
    robots: list[Pattern] = field(default_factory=list)
    script_src: list[Pattern] = field(default_factory=list)
    scripts: list[Pattern] = field(default_factory=list)
    xhr: list[Pattern] = field(default_factory=list)
    cert_issuer: list[Pattern] = field(default_factory=list)
    headers: dict[str, list[Pattern]] = field(default_factory=dict)
    cookies: dict[str, list[Pattern]] = field(default_factory=dict)
    meta: dict[str, list[Pattern]] = field(default_factory=dict)
    js: dict[str, list[Pattern]] = field(default_factory=dict)
    dns: dict[str, list[Pattern]] = field(default_factory=dict)
    dom: list[DomRule] = field(default_factory=list)
    implies: list[tuple[str, int]] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    requires_cats: list[int] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)


class FingerprintDB:
    def __init__(self) -> None:
        self.techs: dict[str, Tech] = {}
        self.categories: dict[int, str] = {}
        self.compile_errors: list[tuple[str, str]] = []
        self.stats: dict[str, int] = {}

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, vendor_dir: Path = VENDOR_DIR, custom_file: Path | None = None) -> "FingerprintDB":
        db = cls()
        custom_file = custom_file or CONFIG_DIR / "custom_fingerprints.json"
        cats_file = vendor_dir / "categories.json"
        if not cats_file.exists():
            raise FileNotFoundError(
                f"Fingerprint DB not found in {vendor_dir}. Run: python scripts/update_fingerprints.py"
            )
        db.categories = {int(k): v["name"] for k, v in json.loads(cats_file.read_text("utf-8")).items()}

        raw: dict[str, tuple[dict, str]] = {}
        for f in sorted(glob.glob(str(vendor_dir / "technologies" / "*.json"))):
            for name, spec in json.loads(Path(f).read_text("utf-8")).items():
                raw[name] = (spec, "webappanalyzer")
        n_public = len(raw)
        n_custom = 0
        if custom_file.exists():
            for name, spec in json.loads(custom_file.read_text("utf-8")).items():
                if name.startswith("_"):
                    continue
                raw[name] = (spec, "custom")
                n_custom += 1

        for name, (spec, source) in raw.items():
            db.techs[name] = db._compile_tech(name, spec, source)
        db.stats = {"public_rules": n_public, "custom_rules": n_custom, "total": len(db.techs),
                    "regex_compile_errors": len(db.compile_errors)}
        return db

    def category_names(self, cats: list[int]) -> list[str]:
        return [self.categories.get(c, str(c)) for c in cats]

    # ---------------------------------------------------------------- compiling
    def _pattern(self, tech: str, s) -> Pattern | None:
        if not isinstance(s, str):
            s = "" if s is None else str(s)
        parts = s.split("\\;")
        rx_src, conf, ver = parts[0], 100, None
        for p in parts[1:]:
            if p.startswith("confidence:"):
                try:
                    conf = int(p[len("confidence:"):])
                except ValueError:
                    pass
            elif p.startswith("version:"):
                ver = p[len("version:"):]
        if not rx_src:
            return Pattern(raw=s, regex=None, confidence=conf, version=ver)
        py_src = _NAMED_GROUP.sub("(?P<", rx_src).replace("[^]", "[\\s\\S]")
        try:
            rx = re.compile(py_src, re.I)
        except re.error as e:
            self.compile_errors.append((tech, f"{rx_src!r}: {e}"))
            return None
        return Pattern(raw=s, regex=rx, confidence=conf, version=ver)

    def _plist(self, tech: str, v) -> list[Pattern]:
        if v is None:
            return []
        vals = v if isinstance(v, list) else [v]
        return [p for p in (self._pattern(tech, x) for x in vals) if p is not None]

    def _pdict(self, tech: str, v, lower_keys: bool = True) -> dict[str, list[Pattern]]:
        if not isinstance(v, dict):
            return {}
        out = {}
        for k, pats in v.items():
            key = k.lower() if lower_keys else k
            out[key] = self._plist(tech, pats)
        return out

    def _compile_tech(self, name: str, spec: dict, source: str) -> Tech:
        t = Tech(
            name=name,
            cats=[int(c) for c in spec.get("cats", [])],
            website=spec.get("website", ""),
            description=spec.get("description", ""),
            saas=spec.get("saas"),
            source=source,
        )
        t.url = self._plist(name, spec.get("url"))
        t.html = self._plist(name, spec.get("html"))
        t.text = self._plist(name, spec.get("text"))
        t.css = self._plist(name, spec.get("css"))
        t.robots = self._plist(name, spec.get("robots"))
        t.script_src = self._plist(name, spec.get("scriptSrc"))
        t.scripts = self._plist(name, spec.get("scripts"))
        t.xhr = self._plist(name, spec.get("xhr"))
        t.cert_issuer = self._plist(name, spec.get("certIssuer"))
        t.headers = self._pdict(name, spec.get("headers"))
        t.cookies = self._pdict(name, spec.get("cookies"))
        t.meta = self._pdict(name, spec.get("meta"))
        t.js = self._pdict(name, spec.get("js"), lower_keys=False)
        t.dns = self._pdict(name, spec.get("dns"), lower_keys=False)
        t.dom = self._compile_dom(name, spec.get("dom"))
        for imp in _as_list(spec.get("implies")):
            p = imp.split("\\;")
            conf = 100
            for x in p[1:]:
                if x.startswith("confidence:"):
                    try:
                        conf = int(x[11:])
                    except ValueError:
                        pass
            t.implies.append((p[0], conf))
        t.requires = [r.split("\\;")[0] for r in _as_list(spec.get("requires"))]
        t.requires_cats = [int(c) for c in _as_list(spec.get("requiresCategory"))]
        t.excludes = [e.split("\\;")[0] for e in _as_list(spec.get("excludes"))]
        return t

    def _compile_dom(self, name: str, dom) -> list[DomRule]:
        rules: list[DomRule] = []
        if dom is None:
            return rules
        presence = Pattern(raw="", regex=None)
        if isinstance(dom, (str, list)):
            for sel in _as_list(dom):
                rules.append(DomRule(sel, "exists", None, presence, _selector_hints(sel)))
            return rules
        for sel, spec in dom.items():
            hints = _selector_hints(sel)
            if not isinstance(spec, dict):
                rules.append(DomRule(sel, "exists", None, presence, hints))
                continue
            if "exists" in spec:
                rules.append(DomRule(sel, "exists", None, presence, hints))
            for attr, pat in (spec.get("attributes") or {}).items():
                for p in self._plist(name, pat):
                    rules.append(DomRule(sel, "attribute", attr, p, hints))
            for prop, pat in (spec.get("properties") or {}).items():
                for p in self._plist(name, pat):
                    rules.append(DomRule(sel, "property", prop, p, hints))
            if "text" in spec:
                for p in self._plist(name, spec["text"]):
                    rules.append(DomRule(sel, "text", None, p, hints))
        return rules


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


_QUOTED = re.compile(r"""['"]([^'"]{3,})['"]""")
_IDCLASS = re.compile(r"[#.]([A-Za-z_][\w-]{2,})")


def _selector_hints(selector: str) -> list[list[str]]:
    """Literal tokens that MUST appear in raw HTML for the selector to possibly match.

    Returns a list of alternatives (one per comma-separated sub-selector); each alternative
    is a list of tokens that must all be present. Running ~3000 CSS selectors per page with
    BeautifulSoup is slow; this prefilter skips >95% of them with a substring check.
    """
    alts = []
    for part in selector.split(","):
        toks = [t.lower() for t in _QUOTED.findall(part)] + [t.lower() for t in _IDCLASS.findall(part)]
        alts.append(toks)
    return alts
