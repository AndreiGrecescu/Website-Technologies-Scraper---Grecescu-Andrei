"""Tier 2: headless Chromium via Playwright (~5-15 s and ~150 MB RAM per page).

What it sees that plain HTTP cannot:
- Global JS variables (window.Shopify, window.TriplePixel, jQuery.fn.jquery -> versions)
- Every network request, including tags injected later by Google Tag Manager or by
  Shopify's sandboxed Web Pixels iframes - this is where most analytics tools show up.
- Cookies set from JavaScript (_ga, _hjSessionUser, _clck ...)
- The DOM after client-side rendering (SPAs, Wix, Squarespace)

Anti-bot measures (kept deliberately modest - no CAPTCHA solving, no fingerprint spoofing
services): real Chrome channel when installed, consistent UA/locale/viewport, the
`navigator.webdriver` flag hidden, waiting out non-interactive JS challenges (Cloudflare's
"Just a moment..." often clears by itself in a few seconds for a real browser engine),
a small scroll to trigger lazy-loaded tags.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from playwright.async_api import Browser, Playwright, async_playwright

from .blockdetect import PageVerdict, classify

STEALTH_INIT = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = window.chrome || {runtime: {}};
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
"""

JS_PROBE = """
(paths) => {
  const out = {};
  for (const p of paths) {
    try {
      let v = window;
      for (const k of p.split('.')) {
        if (v === undefined || v === null) { v = undefined; break; }
        v = v[k];
      }
      if (v === undefined) continue;
      const t = typeof v;
      out[p] = (t === 'string' || t === 'number' || t === 'boolean') ? String(v).slice(0, 200) : '';
    } catch (e) {}
  }
  return out;
}
"""

DOM_PROBE = """
(pairs) => {
  const out = {};
  for (const [sel, prop] of pairs) {
    try {
      const els = document.querySelectorAll(sel);
      const n = Math.min(els.length, 25);
      for (let i = 0; i < n; i++) {
        const v = els[i][prop];
        if (v !== undefined && v !== null) {
          const t = typeof v;
          out['dom::' + sel + '::' + prop] = (t === 'string' || t === 'number' || t === 'boolean') ? String(v).slice(0, 200) : '';
          break;
        }
      }
    } catch (e) {}
  }
  return out;
}
"""

CHALLENGE_TITLES = ("just a moment", "attention required", "please wait", "checking your browser", "un instant")


@dataclass
class BrowserResult:
    final_url: str = ""
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    html: str = ""
    network: list[tuple[str, str]] = field(default_factory=list)
    js_values: dict[str, str] = field(default_factory=dict)
    verdict: PageVerdict = field(default_factory=lambda: PageVerdict("error", reason="not rendered"))
    elapsed_ms: int = 0
    challenge_waited: bool = False


class BrowserPool:
    def __init__(self, concurrency: int = 4, proxy: str | None = None, nav_timeout_ms: int = 30_000):
        self.sem = asyncio.Semaphore(concurrency)
        self.proxy = proxy
        self.nav_timeout_ms = nav_timeout_ms
        self._pw: Playwright | None = None
        self._browser: Browser | None = None
        self.engine = ""
        self.user_agent = ""

    async def __aenter__(self):
        self._pw = await async_playwright().start()
        args = ["--disable-blink-features=AutomationControlled", "--no-first-run", "--mute-audio"]
        launch_kw = {"headless": True, "args": args}
        if self.proxy:
            launch_kw["proxy"] = {"server": self.proxy}
        # Real Google Chrome (new headless mode) is much harder to fingerprint than the
        # bundled headless shell; fall back to bundled Chromium when Chrome isn't installed.
        for channel in ("chrome", "chromium", None):
            try:
                kw = dict(launch_kw)
                if channel:
                    kw["channel"] = channel
                self._browser = await self._pw.chromium.launch(**kw)
                self.engine = f"{channel or 'bundled'} {self._browser.version}"
                break
            except Exception:
                continue
        if not self._browser:
            raise RuntimeError("Could not launch Chromium. Run: python -m playwright install chromium")
        major = self._browser.version.split(".")[0]
        self.user_agent = (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        )
        return self

    async def __aexit__(self, *exc):
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()

    async def render(self, url: str, js_paths: list[str], dom_props=()) -> BrowserResult:
        async with self.sem:
            return await self._render(url, js_paths, dom_props)

    async def _render(self, url: str, js_paths: list[str], dom_props=()) -> BrowserResult:
        t0 = time.perf_counter()
        out = BrowserResult()
        ctx = await self._browser.new_context(
            user_agent=self.user_agent,
            locale="en-US",
            timezone_id="Europe/Bucharest",
            viewport={"width": 1366, "height": 860},
            ignore_https_errors=True,
            java_script_enabled=True,
        )
        await ctx.add_init_script(STEALTH_INIT)
        # skip heavy media; keep scripts/xhr/documents (they are the evidence)
        await ctx.route("**/*", _route_filter)
        network: list[tuple[str, str]] = []
        ctx.on("request", lambda req: network.append((req.url, req.resource_type)))
        main_responses = []
        page = await ctx.new_page()
        page.on("response", lambda r: main_responses.append(r) if r.request.is_navigation_request() and r.frame == page.main_frame else None)
        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=self.nav_timeout_ms)
            await _settle(page)
            title = (await _safe_title(page)).lower()
            if any(t in title for t in CHALLENGE_TITLES):
                out.challenge_waited = True
                for _ in range(8):  # up to ~16 s for a JS challenge to clear itself
                    await asyncio.sleep(2)
                    title = (await _safe_title(page)).lower()
                    if not any(t in title for t in CHALLENGE_TITLES):
                        await _settle(page)
                        break
            try:
                await page.mouse.wheel(0, 1600)
                await asyncio.sleep(1.2)
            except Exception:
                pass
            last = main_responses[-1] if main_responses else resp
            if last is not None:
                out.status = last.status
                try:
                    out.headers = {k.lower(): v for k, v in (await last.all_headers()).items()}
                except Exception:
                    out.headers = {}
            out.final_url = page.url
            out.html = await page.content()
            for c in await ctx.cookies():
                out.cookies[c["name"]] = c.get("value", "")
            try:
                out.js_values = await page.evaluate(JS_PROBE, js_paths)
            except Exception:
                out.js_values = {}
            if dom_props:
                try:
                    out.js_values.update(await page.evaluate(DOM_PROBE, [list(p) for p in dom_props]))
                except Exception:
                    pass
            out.network = network[:3000]
            out.verdict = classify(out.status, out.headers, out.html)
        except Exception as e:
            msg = str(e).split("\n")[0][:160]
            out.network = network[:3000]
            out.verdict = classify(None, {}, "", error=f"browser: {msg}")
        finally:
            out.elapsed_ms = int((time.perf_counter() - t0) * 1000)
            try:
                await ctx.close()
            except Exception:
                pass
        return out


async def _settle(page) -> None:
    try:
        await page.wait_for_load_state("networkidle", timeout=8_000)
    except Exception:
        pass


async def _safe_title(page) -> str:
    try:
        return await page.title()
    except Exception:
        return ""


_BLOCK_TYPES = {"image", "media", "font"}


async def _route_filter(route):
    # Requests are still *recorded* by ctx.on("request") before being aborted, so
    # image pixels (e.g. facebook.com/tr) still count as evidence.
    if route.request.resource_type in _BLOCK_TYPES:
        await route.abort()
    else:
        await route.continue_()
