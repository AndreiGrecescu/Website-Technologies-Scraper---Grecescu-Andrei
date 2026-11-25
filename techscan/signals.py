"""A normalized bag of observations about one website, from one collection method.

Every collector (plain HTTP, headless browser, DNS, TLS, Wayback snapshot) produces a
Signals object tagged with its `source`. The detection engine runs on each one separately,
so every piece of evidence keeps track of *how* it was observed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

MAX_HTML = 1_500_000
MAX_SCRIPT = 200_000


@dataclass
class Signals:
    source: str                                   # http | browser | dns | tls | robots | wayback:<ts>
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)      # lower-case name -> value
    cookies: dict[str, str] = field(default_factory=dict)
    html: str = ""
    script_srcs: list[str] = field(default_factory=list)       # <script src> in the document
    inline_scripts: list[str] = field(default_factory=list)
    meta: dict[str, list[str]] = field(default_factory=dict)   # lower-case name/property -> contents
    text: str = ""
    css: str = ""
    network: list[tuple[str, str]] = field(default_factory=list)  # (url, resource_type) - browser only
    js_values: dict[str, str] = field(default_factory=dict)       # global JS path -> value - browser only
    dns: dict[str, list[str]] = field(default_factory=dict)
    cert_issuer: str = ""
    robots: str = ""
    _soup: BeautifulSoup | None = None

    @property
    def soup(self) -> BeautifulSoup | None:
        if self._soup is None and self.html:
            try:
                self._soup = BeautifulSoup(self.html, "lxml")
            except Exception:
                self._soup = None
        return self._soup

    def parse_html(self) -> "Signals":
        """Extract scripts / meta / text / css from self.html."""
        if not self.html:
            return self
        self.html = self.html[:MAX_HTML]
        soup = self.soup
        if soup is None:
            return self
        srcs, inline, css_parts = [], [], []
        for s in soup.find_all("script"):
            src = s.get("src") or s.get("data-src")
            if src:
                srcs.append(src.strip())
            elif s.string:
                inline.append(s.string[:MAX_SCRIPT])
        for m in soup.find_all("meta"):
            key = (m.get("name") or m.get("property") or m.get("http-equiv") or "").strip().lower()
            content = m.get("content")
            if key and content is not None:
                self.meta.setdefault(key, []).append(content)
        for st in soup.find_all("style"):
            if st.string:
                css_parts.append(st.string[:MAX_SCRIPT])
        self.script_srcs = list(dict.fromkeys(self.script_srcs + srcs))
        self.inline_scripts = inline
        self.css = "\n".join(css_parts)
        body = soup.body
        self.text = re.sub(r"\s+", " ", body.get_text(" ", strip=True))[:100_000] if body else ""
        return self
