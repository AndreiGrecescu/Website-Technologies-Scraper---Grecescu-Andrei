"""Classify a fetched page: real content, a bot wall, a parked domain, or an error.

Why this exists: "HTTP 200" is not "success". Bot walls (Cloudflare "Just a moment...",
DataDome / PerimeterX captchas) and domain-parking pages often answer 200, yet contain
zero real technologies - only the WAF. Counting them as successes inflates the success
rate and hides the real problem, so every response is classified before it is trusted.
Signatures are kept as data so new ones found in fetch logs are one line each.

Even a blocked page is useful: the block itself is proof of a technology (the WAF/CDN),
and the response headers often still reveal the server / CDN.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class PageVerdict:
    state: str          # ok | challenge | blocked | parked | empty | error
    vendor: str = ""    # cloudflare | akamai | datadome | ...
    reason: str = ""

    @property
    def usable(self) -> bool:
        return self.state == "ok"


# (vendor, where, regex) - where: header-name, "html", "title", "status:<code>"
_CHALLENGE_SIGS = [
    ("cloudflare", "header:cf-mitigated", r"challenge"),
    ("cloudflare", "title", r"^\s*(just a moment|attention required|un instant|einen moment|un momento)"),
    ("cloudflare", "html", r"/cdn-cgi/challenge-platform/|cf-browser-verification|cf_chl_opt|challenges\.cloudflare\.com/turnstile"),
    ("datadome", "header:x-datadome", r""),
    ("datadome", "html", r"captcha-delivery\.com|geo\.captcha-delivery"),
    ("perimeterx", "html", r"px-captcha|_pxCaptcha|perimeterx\.net|human-challenge"),
    ("imperva", "html", r"_Incapsula_Resource|Incapsula incident ID|/_Incapsula_"),
    ("akamai", "html", r"Reference&#32;&#35;[\d.]+|Access Denied.{0,300}Reference #|_abck|akam/\d+/"),
    ("sucuri", "header:x-sucuri-block", r""),
    ("sucuri", "html", r"Sucuri WebSite Firewall - Access Denied|sucuri\.net/privacy-policy"),
    ("aws-waf", "html", r"awswaf|aws-waf-token|challenge\.js.{0,80}token"),
    ("kasada", "html", r"ips\.js\?|KPSDK"),
    ("ddos-guard", "html", r"ddos-guard\.net|DDoS-GUARD"),
    ("vercel", "html", r"Vercel Security Checkpoint"),
    ("generic-captcha", "html", r"g-recaptcha.{0,200}(verify|robot)|hcaptcha\.com/1/api\.js.{0,400}(verify|human)|are you a robot|verify you are (a )?human"),
]

_PARKED = re.compile(
    r"(this domain (name )?(is|may be) for sale|buy this domain|domain is parked|parkingcrew|sedoparking|"
    r"bodis\.com|dan\.com/|afternic|hugedomains|godaddy\.com/domainsearch|domain has expired|"
    r"window\.park\s*=|parking-lander|/lander\b|domainmarket\.com|this web page is parked)",
    re.I,
)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def classify(status: int | None, headers: dict[str, str], html: str, error: str | None = None) -> PageVerdict:
    if error:
        return PageVerdict("error", reason=error)
    html = html or ""
    head = html[:60_000]
    m = _TITLE.search(head)
    title = (m.group(1).strip() if m else "")[:200]

    for vendor, where, rx in _CHALLENGE_SIGS:
        if where.startswith("header:"):
            name = where.split(":", 1)[1]
            if name in headers and (not rx or re.search(rx, headers[name], re.I)):
                return PageVerdict("challenge", vendor, f"header {name}")
        elif where == "title":
            if title and re.search(rx, title, re.I):
                return PageVerdict("challenge", vendor, f"title '{title[:60]}'")
        elif where == "html":
            # only trust body signatures on small pages or error statuses: big real pages
            # legitimately embed recaptcha / cloudflare scripts
            if (len(html) < 40_000 or (status or 0) >= 400) and re.search(rx, head, re.I | re.S):
                return PageVerdict("challenge", vendor, f"body matches /{rx[:40]}/")

    if status and status in (401, 403, 406, 429, 451, 503):
        vendor = _vendor_from_headers(headers)
        return PageVerdict("blocked", vendor, f"HTTP {status}")
    if status and status >= 400:
        return PageVerdict("error", reason=f"HTTP {status}")

    if _PARKED.search(head) and len(html) < 80_000:
        return PageVerdict("parked", reason="parking page signature")

    visible = re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>", " ", head, flags=re.S | re.I)
    if len(html) < 600 or len(visible.split()) < 5 and "<script" not in head.lower():
        return PageVerdict("empty", reason=f"{len(html)} bytes, no content")
    return PageVerdict("ok")


def needs_js_render(html: str) -> bool:
    """Heuristic: a JS app shell (React/Vue SPA, Wix, etc.) where raw HTML says little."""
    low = (html or "")[:200_000].lower()
    visible = re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>", " ", low, flags=re.S)
    return len(visible.split()) < 60 and low.count("<script") >= 2


def _vendor_from_headers(h: dict[str, str]) -> str:
    server = h.get("server", "").lower()
    if "cf-ray" in h or "cloudflare" in server:
        return "cloudflare"
    if "akamai" in server or "x-akamai-transformed" in h:
        return "akamai"
    if "x-datadome" in h:
        return "datadome"
    if "x-sucuri-id" in h:
        return "sucuri"
    if "x-iinfo" in h or "incap" in h.get("set-cookie", "").lower():
        return "imperva"
    if "x-amz-cf-id" in h:
        return "cloudfront"
    return ""
