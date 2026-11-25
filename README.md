# techscan: website technology detection, built for a sales team

> **Task:** given 200 domains, identify the technologies each site is built with, with proof.
> **Context:** the client sells an **analytics plugin for Shopify**. Its salespeople want sites that
> use **competing products**, so they can pitch a migration.

## Results at a glance

| | Benchmark (provided) | **techscan (final run, v7)** |
|---|---|---|
| Unique technologies found on the 200 domains | 477 | **504** (502 with confidence ≥ 50%) |
| Total detections (domain × technology) | n/a | **3,345**, every one with evidence |
| Domains whose live content was analyzed | n/a | **166 / 200 (83%)** |
| Remaining 34 domains | n/a | 8 dead (NXDOMAIN), 14 gone (HTTP 404/5xx), 10 behind a bot wall, 1 parked, 1 empty |

Even the 34 "failed" domains get technologies: DNS, TLS, the WAF's own response, and Internet
Archive snapshots (12 blocked or dead sites recovered 126 detections, flagged as stale).

**Deliverables**

| What | Where |
|---|---|
| Output: one row per domain × technology, with proof | [`output/technologies.csv`](output/technologies.csv) |
| Output: full structured result (evidence, fetch diagnostics, Shopify pixels) | [`output/results.json`](output/results.json) |
| Sales view: lead list, segmented and scored | [`output/leads.csv`](output/leads.csv) |
| Per-domain fetch diagnostics (what was blocked, by whom, why) | [`output/domains.csv`](output/domains.csv) |
| Competitor layer demo on 20 Shopify brands | [`output/demo_shopify/leads.csv`](output/demo_shopify/leads.csv) |
| Every experiment, reproducible | [`runs/history.csv`](runs/history.csv) + `runs/<run_id>/` |
| Debate topics | [§5 below](#5-debate-topics), infrastructure appendix in [`docs/SCALING.md`](docs/SCALING.md) |

---

## 1. How I read the task

"Identify technologies" is the mechanism. The goal is a **list of companies a salesperson can
call, with a reason to call them**. That changed several decisions:

1. **Proof is part of the product, not a debugging aid.** A salesperson who says "you use Triple
   Whale" must be right. Each detection carries *where* it was seen (HTTP, rendered browser, DNS,
   TLS, archive), *which rule* matched, and the *exact text*. For example:
   ```json
   {"name": "Elevar", "confidence": 100, "evidence": [{
     "source": "browser", "field": "shopify web pixel", "key": "apiClientId=2509311 type=APP",
     "match": "\"config_url\": \"https://shopify-gtm-suite.getelevar.com/configs/...\""}]}
   ```
2. **Raw tech lists aren't enough, so there is a business layer on top** ([`config/competitors.json`](config/competitors.json)):
   - *Tier 1:* Shopify analytics / attribution / profit apps, the direct competitors (Triple Whale,
     Polar, Northbeam, Elevar, Littledata, Lifetimely, BeProfit, ...).
   - *Tier 2:* behavior and product analytics (Hotjar, Clarity, Lucky Orange, Heap, Mixpanel, ...).
   - *Tier 3:* generic web analytics (GA4, Matomo, Plausible, ...).
   - Each domain gets a **segment** and a **lead score**:

   | Segment | Meaning | Sales motion |
   |---|---|---|
   | **A** | Shopify + a direct competitor | switch campaign (primary target) |
   | **B** | Shopify + only generic analytics | upgrade campaign |
   | **C** | Shopify, no 3rd-party analytics found | greenfield |
   | D | Other ecommerce platform + analytics | secondary: future migration |
   | E | Other CMS / site + analytics | secondary, low priority |
   | F | No relevant signal / unreachable | - |

3. **Shopify deserves a dedicated detector.** Since 2023, Shopify apps track through sandboxed
   *Web Pixels*, so classic "find the `<script src>`" detection misses them. But every storefront
   embeds an inline `webPixelsConfigList`, which is the store's own inventory of installed app
   pixels, each with an `apiClientId` and a configuration. [`techscan/shopify.py`](techscan/shopify.py)
   parses it. On the smoke test this found **Elevar on allbirds.com**, which no script tag reveals.

---

## 2. How it works

```
domain ──► DNS (A/MX/TXT/NS/SOA/CNAME)  ┐   never bot-blocked; detects dead domains early;
       ──► TLS certificate issuer       ┤   email provider, DNS/CDN, Shopify IP range, SPF tools
       ──► HTTP fetch (real browser headers, https / www / http variants,
       │    retries with backoff, HTTP/2 → HTTP/1.1 fallback)
       │      └─► classify response: ok | challenge | blocked | parked | empty | error
       ──► Headless Chrome (Playwright)  ── JS globals, every network request (incl. GTM-
       │    injected and Shopify sandboxed pixels), JS-set cookies, live DOM, rendered HTML
       ──► robots.txt
       ──► Internet Archive snapshot  ── only if no live HTML could be obtained
                 │
     each source → Signals → Engine (7.7k rules) → detections + evidence
                 │
     implies / requires / excludes → competitor layer → segment, score, pitch, proof
```

| Module | Role |
|---|---|
| [`techscan/fingerprints.py`](techscan/fingerprints.py) | Loads 7,715 public rules ([webappanalyzer](https://github.com/enthec/webappanalyzer), the open continuation of Wappalyzer's rule set) + 17 own rules; translates JS regex syntax to Python (0 compile errors) |
| [`techscan/engine.py`](techscan/engine.py) | **Own matching engine**: headers, cookies (wildcards), meta, script src, inline scripts, HTML, CSS, DOM selectors/attributes/text, live-DOM properties, JS globals, network requests, DNS, TLS, robots; confidence + version extraction; implies/requires/excludes |
| [`techscan/fetch/blockdetect.py`](techscan/fetch/blockdetect.py) | Bot-wall / parking classifier: Cloudflare, Akamai, DataDome, PerimeterX, Imperva, Sucuri, AWS WAF, Kasada, DDoS-Guard, Vercel, generic captchas |
| [`techscan/fetch/browser.py`](techscan/fetch/browser.py) | Playwright pool: real Chrome channel when installed, consistent UA/locale, `webdriver` flag hidden, waits out non-interactive JS challenges, blocks media but still records pixels |
| [`techscan/shopify.py`](techscan/shopify.py) | Shopify Web Pixels manifest parser |
| [`techscan/competitors.py`](techscan/competitors.py) | Segment, lead score, pitch line, proof lines |
| [`techscan/presets.py`](techscan/presets.py) | Light / Medium / Advanced presets with measured time estimates |
| [`techscan/web.py`](techscan/web.py) | Upload UI |

**Why not just call the Wappalyzer library?** It would answer "which technologies" and nothing
else. I reused the *rule data* (thousands of community-maintained fingerprints, no point in
rewriting them) but wrote the engine. That made it possible to add: network-level matching
for runtime-injected tags, DNS/TLS/IP-range evidence, live-DOM property checks, the Shopify pixel
manifest, archive fallback, per-source evidence, and the competitor layer.

**What I deliberately did not do:** CAPTCHA solving, paid anti-detect browsers, or rotating
residential proxies. On 200 domains the remaining bot walls are 5%. At scale, proxies become
an engineering decision (see [docs/SCALING.md](docs/SCALING.md)).

---

## 3. The path: 7 runs on the same 200 domains

Every run is logged automatically ([`runs/history.csv`](runs/history.csv), artifacts in `runs/<id>/`,
console logs in `logs/`), so each change can be measured, not assumed. The commands are in
[`scripts/run_series.sh`](scripts/run_series.sh). v1-v5 used the code as it was at the time;
re-running them today uses the improved engine, so the numbers would shift slightly.

| Run | Change | Live analyzed | Blocked | Unique techs | Detections | Time |
|---|---|---|---|---|---|---|
| v1 | Naive: python-httpx UA, HTTP only, no retries | 141 (70.5%) | 31 | 266 | 2,105 | 105 s |
| v2 | Real browser header set, https/www/http variants, retries | 151 (75.5%) | 21 | 280 | 2,252 | 122 s |
| v3 | + DNS, TLS issuer, robots.txt | 151 | 21 | 333 | 2,593 | 128 s |
| v4 | + Headless browser, only when HTTP fails ("smart") | 166 (83%) | 10 | 387 | 2,877 | 228 s |
| v5 | Headless browser on **every** live site + Wayback fallback | 166 | 10 | 493 | 3,536 | 466 s |
| v6 | Fixes found in v5 logs (below) | 166 | 10 | 504 | 3,694 | 477 s |
| v7 | Fix a systematic false positive found by auditing v6 | 166 | 10 | **504** | **3,345** | 493 s |

What each step taught:

- **v1 → v2: a library User-Agent is a bot signature.** 31 domains (15%) were blocked outright.
  Real Chrome headers alone cleared a third of them.
- **"200 OK" is not success.** Several sites answered 200 with a Cloudflare "Just a moment…" or an
  Akamai "Access Denied / Reference #" page. Counting those as successes would have inflated the
  numbers while yielding only the WAF, so every response is classified before it's trusted.
- **v3: DNS is the cheapest evidence there is.** +53 unique technologies at near-zero cost (email
  providers from MX, SaaS tools from SPF/TXT verifications, DNS/CDN providers). It also flags dead
  domains early (8 NXDOMAIN), so no browser time is wasted on them.
- **v4: the browser beats most bot walls.** Blocked domains dropped 21 → 10 by escalating only the
  failures to a real Chrome engine.
- **v5: the browser on every site is where analytics lives.** +106 unique technologies. **928
  detections are only visible in the rendered page** (JS globals, GTM-injected tags, JS-set
  cookies, sandboxed Shopify pixels). For a company hunting *analytics* competitors this tier is
  not optional.
- **v6: fixes from the logs.**
  - Some servers reset HTTP/2 streams (`RemoteProtocolError`); they now retry over HTTP/1.1.
  - One slow site hit the global per-domain timeout and **lost its DNS/TLS evidence too**; the
    browser now has its own bounded time budget, so partial results survive.
  - The Internet Archive's `/wayback/available` endpoint returned nothing, even for example.com;
    switched to the CDX API. The fallback now recovers 126 detections on 12 blocked or dead sites.
- **v7: auditing my own output.** React was "detected" on 175 domains and Preact on 191, more
  than the 166 live sites. Root cause: some rules check a **JavaScript property on a DOM element**
  (e.g. `body > div` has `_reactRootContainer`), and my engine treated "element exists" as a match.
  `body > div` exists everywhere. These rules are now evaluated **inside the live page**: React
  went 175 → 25 (each now backed by `React.version` or real markup), Preact 191 → 3.
  **349 false detections removed**, unique count unchanged.

Other things observed in the data:

- *Snowplow on 6 sites looks wrong but is real:* Weebly/Square injects its own Snowplow tracker
  (`GlobalSnowplowNamespace`). Useful nuance for sales: **platform-injected analytics ≠ analytics
  the owner chose**.
- The 200-domain list is a random mix (local services, WordPress, Weebly, a Disney store). It
  contains **only 2 Shopify stores**, so segment A is empty on it. Hence the demo below.

### Competitor layer on a Shopify-heavy list (demo)

[`data/demo_shopify_stores.txt`](data/demo_shopify_stores.txt): 20 well-known DTC brands
(`python -m techscan scan data/demo_shopify_stores.txt --preset advanced`):

Run `20261125-153651`: 20/20 live, **19 confirmed Shopify**, 260 unique technologies, 230 s.
**8 stores land in segment A** (running a direct competitor), 8 in B, 3 in C:

| Store | Seg | Direct competitors (Tier 1) | Other analytics | Proof (first line) |
|---|---|---|---|---|
| brooklinen.com | A | Elevar, Northbeam | Contentsquare, Snowplow | `js global elevar_gtm_errors` |
| ridge.com | A | Elevar, Northbeam | - | Shopify web pixel `apiClientId=2509311` → `shopify-gtm-suite.getelevar.com/configs/…` |
| rothys.com | A | Littledata | Amplitude, Segment, Snowplow | `js global LittledataLayer` |
| allbirds.com | A | Elevar | Microsoft Clarity | Shopify web pixel → `getelevar.com/configs/…` |
| mvmt.com | A | Elevar | - | Shopify web pixel → `getelevar.com/configs/…` |
| skims.com | A | Elevar | - | `js global elevar_gtm_errors` |
| jonesroadbeauty.com | A | Northbeam | Snowplow | script src `//j.northbeam.io/vendor/nb-sp.min.js` |
| cutsclothing.com | A | Northbeam | Snowplow | script src `//j.northbeam.io/vendor/nb-sp.min.js` |
| ruggable.com | B | - | Amplitude, Snowplow | network request `sr-client-cfg.amplitude.com/…` |
| gymshark.com | B | - | Mixpanel | DNS TXT `mixpanel-domain-verify=…` |

Points worth noticing:
- The same competitor is proven by **different mechanisms** on different stores: the Shopify pixel
  manifest, a JS global, a script URL. Any single-technique detector would miss some of them.
- `apiClientId=2509311` appears on several stores with Elevar configs. That is **Elevar's
  Shopify app id**, learned from the data, and it can now identify Elevar from the manifest alone
  (see "discovering new technologies").
- bombas.com and fashionnova.com land in C ("no analytics found"). Large stores almost certainly
  run analytics, so this is the consent-gating / homepage-only limitation in action. These are
  the cases a multi-page, consent-aware crawl would fix.

### Finding competitors that leave no trace: App Store reviews → learned app IDs

Some competitors (Peel, BeProfit, Lifetimely...) connect only through the Shopify Admin API and
are invisible to any crawler. Two things solve this ([`techscan/reviews/`](techscan/reviews/)):

1. **Reviews are a customer list.** Every Shopify App Store review names the store that wrote it,
   plus its country, how long it has used the app, and its rating. I collected **714 reviews from
   12 competitor apps**, star by star from 1★ to 5★ (89 are 1★: the warmest leads). Triple Whale,
   OrderMetrics and Admetrics are now "no longer available" on the App Store.
2. **Reviewer stores are labelled data.** Store names are matched to **verified** Shopify domains:
   - try `<name>.myshopify.com` (it redirects to the real domain);
   - try domain guesses that are first filtered by DNS, keeping only those pointing at
     Shopify's IP range;
   - accept a match only if the site is Shopify **and** its own title / og:site_name matches.

   Then, for each tool, take **5 verified stores** (4-5★ first: most likely still installed) and
   look for an app signal they share that the other tools' stores don't have. The signal is
   either a Web Pixel `apiClientId` or a theme-extension handle
   (`cdn.shopify.com/extensions/<id>/<app>-<version>/`).

| Tool | Learned signal | In its 5 sampled stores | In the 55 stores of other tools | Validation |
|---|---|---|---|---|
| Elevar | pixel `2509311` | 4/5 | 0/55 | all 13 stores carrying it have an Elevar `config_url` (100% precision); same id found independently earlier |
| Polar Analytics | pixel `4294333` | 5/5 | 0/55 | holdout: 11/33 other Polar reviewers vs 0/105 stores of other tools |
| Littledata | pixel `1464241` + extension `littledata` | 5/5 | 1/55 | - |
| TrueProfit | pixel `2553263` | 4/5 | 0/55 | - |
| Trackify X | pixel `838114` + extension `trackify-x` | 4/5 | 0/55 | - |
| Analyzify | extension `analyzify-ga4-ads-tracking` | 5/5 | 0/55 | - |
| BeProfit, Lifetimely, Peel, Lebesgue, Daasity, Sirge | none shared | - | - | **backend-only**: the App Store reviews are the way to find their users |

Learned IDs live in [`config/shopify_app_ids.json`](config/shopify_app_ids.json) and are used by every
scan automatically. On the demo list, a plain **Light** scan (no browser) now finds Polar
Analytics on drinkolipop.com. The earlier Advanced run had classified that store as "generic
analytics only".

**Lesson learned on the way:** the first resolution pass marked 95% of stores "not found". In
reality Shopify's edge was rate-limiting the IP (`429 Verifying your connection…`): every store
sits behind the same edge, so 12 parallel workers across different domains still looked like
one bot. Fixes:
- a global Shopify throttle (~1 req/s, shared cool-down on 429);
- DNS pre-filtering (free, never rate-limited);
- recording 429 as `rate_limited` (retried later) instead of "not found".

After the fixes, ~70% of stores resolved. Sampling 5 stores per tool instead of resolving all
~700 reviewers reached the same answer in minutes. That is the same per-CDN rate-limit
argument made in [docs/SCALING.md](docs/SCALING.md).

The upload UI has a **Leads** tab with all reviews: filter by competitor tool and by star rating,
sorted 1★ first, verified domains linked, CSV export, a "Collect & update" button, and the
learned-IDs table.

```bash
python -m techscan reviews collect          # App Store reviews, 1★ → 5★, per competitor app
python -m techscan reviews quick            # 5 verified stores per tool → learn shared app ids
python -m techscan reviews resolve          # (optional) resolve every reviewer store, throttled
```

---

## 4. Running it

```bash
python -m venv .venv && .venv/Scripts/activate      # Windows; source .venv/bin/activate elsewhere
pip install -r requirements.txt
python -m playwright install chromium
python scripts/update_fingerprints.py                # fetches the public rule set into vendor/

python -m techscan estimate data/domains.parquet     # time estimate per preset
python -m techscan scan data/domains.parquet --preset advanced
python -m techscan history                           # run log as a table
python -m techscan serve                             # upload UI → http://127.0.0.1:8000
```

Inputs: `.parquet`, `.csv`, `.txt`, `.json`, `.xlsx`. The domain column is auto-detected,
URLs are normalized, unicode domains are converted to punycode, duplicates are removed.

### Search depth presets (with measured time estimates)

| Preset | What runs | 200 domains | Benchmark coverage |
|---|---|---|---|
| **Light** | HTTP + DNS + TLS + robots. No browser | ~2 min | 76% live · 333 techs |
| **Medium** | Light + browser only where HTTP fails + Wayback | ~4 min | 83% live · 387 techs |
| **Advanced** | Browser on every live site (JS, network, pixels, live DOM) | ~8 min | 83% live · 504 techs |

Estimates come from the measured runs (`max(floor, base + n × seconds_per_domain)`, shown with a
-30%/+40% range). The UI shows them for the uploaded file's real domain count, then switches
to a live ETA based on the observed pace once scanning starts. Use **Light** for triage of big
lists, **Advanced** when you need the analytics stack (i.e. for competitor hunting).

### Upload UI

`python -m techscan serve`. Drop a file, see the domain count and the three presets with time
estimates, start, then watch live progress. Results are a filterable lead table (segment chips,
"Shopify only", search by domain or technology). Competitors are color-coded by tier, and clicking a
row shows the pitch, the proof lines and every technology with its evidence. CSV/JSON downloads
are one click away. UI runs are normal runs (same outputs, same history log).

---

## 5. Debate topics

Every number below was measured in this project (runs v1-v7, the Shopify demo, and the App Store
review pipeline). The infrastructure detail (queues, architecture) is in
[docs/SCALING.md](docs/SCALING.md).

### 5.1 What were the main issues with the current implementation, and how would I tackle them?

I group them by *why* a competitor gets missed or mis-reported. For a sales team, a wrong "you
use X" costs more than a missing one.

#### A. Tools that leave no visible trace on the website (the most important one)

Competitors fall into three visibility classes. Each class needs a different technique:

| Class | What the storefront shows | Examples (measured) | How it's handled |
|---|---|---|---|
| **1. Visible** | A script URL, a JS global, a cookie, a network call to the vendor's domain | Northbeam (`j.northbeam.io`), Hotjar, Clarity, GA4 | Fingerprint rules (7.7k public + own), headless browser for runtime-injected tags |
| **2. Sandboxed / anonymous** | Only a **numeric id** in Shopify's Web Pixels manifest (`apiClientId`), or a theme-extension handle. No vendor name, no vendor script in the page. | Polar `4294333`, Elevar `2509311`, TrueProfit `2553263`, Littledata `1464241`, Trackify X `838114`, Analyzify (extension) | **Learned** from App Store reviewer stores: 5 verified stores per tool, find the signal they share that other tools' stores lack. Elevar: 13/13 stores carrying the id have an Elevar config (100% precision). Polar holdout: 11/33 own reviewers, 0/105 others. |
| **3. Backend-only** | **Nothing.** The app reads orders/ads data through the Shopify Admin API and never touches the storefront. | BeProfit, Lifetimely, Peel, Lebesgue, Daasity, Sirge (no shared signal in their samples) | Not crawlable, by definition. **The customer list has to come from outside the website:** App Store reviews (implemented: 714 reviews, store names resolved to verified domains for 70%), then vendor case studies / logo walls, job posts ("experience with Peel"), agency partner pages, G2/Capterra. |

Two more reasons a *visible* tool can still be missed:
- **Conditional loading.** Pixels that fire only on product/cart/checkout pages, only after
  cookie consent (EU), or only for some geos. Two large stores in the demo (bombas.com,
  fashionnova.com) came out as "no analytics", which is almost certainly this.
  - Tackle: crawl 3-5 typed pages per store (home, a product from `/products.json`, a
    collection, `/cart`).
  - Run an optional consent-accepting lane for known CMPs (a legal decision, so off by default).
  - Use EU and US egress.
- **Rules = coverage.** A tool with no rule is invisible. Tackle: the discovery loop in 5.3.

#### B. Sites that can't be reached, or answer with something that isn't the site

| Problem (as it showed up) | Impact | What I did / would do |
|---|---|---|
| **"200 OK" that is a bot wall** (Cloudflare "Just a moment…", Akamai "Access Denied", DataDome) | Counted as success → zero real techs | Response classifier for 11 WAF / captcha vendors before trusting any page |
| **Bot walls** | 31/200 blocked with a library UA → 21 with real browser headers → **10** with headless Chrome | Remaining fix is IP reputation: clean egress pool, per-CDN pacing, residential proxies only for the blocked tail and only for the ~100 KB HTTP fetch. No CAPTCHA solving. |
| **Platform-wide rate limits.** All Shopify stores sit behind one edge. | Resolving reviewer stores at 12 parallel workers → `429 Verifying your connection` → **95% false "not found"** | Global throttle per edge (~1 req/s), shared cool-down on 429, DNS pre-filtering (free, never limited), `rate_limited` status retried instead of "not found" → **70% resolved** |
| **Dead and gone domains** | 8 NXDOMAIN, 14 HTTP 404/5xx (deleted Weebly/booked.net pages, GoDaddy 409s), 1 parked | Detected early via DNS so no browser time is wasted; status kept in the output; **Wayback fallback** recovered 126 detections on 12 blocked/dead sites (flagged `stale_from_archive`) |
| **Protocol / tooling quirks** | HTTP/2 stream resets; one hung page lost its DNS/TLS evidence to a global timeout; the Wayback `available` API returned nothing even for example.com | HTTP/1.1 fallback, bounded browser time per page, switched to the CDX API |

#### C. Things detected wrongly

- **Rule false positives.**
  - React was "detected" on 175 domains and Preact on 191, more than the 166 live sites.
    Cause: rules that check a JS property on a DOM node had been treated as "the node exists".
  - Fixed by evaluating them in the live page (→ 25 and 3), which removed 349 false detections.
  - Process fix: audit any technology whose frequency is implausible, and keep a regression set
    of known sites per technology.
- **Platform-injected vs owner-chosen.** Snowplow on Weebly sites is Weebly's tracker, not the
  owner's choice, so these should be labelled differently for sales.
- **Name → domain mistakes on leads.** A wrong domain sends an email to the wrong company.
  - The resolver accepts a match only when the site is Shopify **and** its own title /
    og:site_name matches the review's store name.
  - Partial matches are kept as `weak_match` and never used.

#### D. Engineering limits of the prototype

- It runs on one machine and one IP, keeps state in memory, and has no resume. Regex has no
  timeout (mitigated with size caps).
- Review collection is fine at hundreds of pages; at scale, App Store terms and rate limits make
  it a business decision.

---

### 5.2 How would I scale this to millions of domains in 1-2 months?

#### The numbers

- 10M domains in 60 days ≈ **2 domains/second**. CPU is not the problem. Measured throughput:
  - HTTP tier: ~0.6 s/domain wall-clock at modest concurrency.
  - Browser tier: ~9 slot-seconds/domain.
  - So even "browser on everything" is ~130 node-days, i.e. **3-5 spot nodes for 45 days**.
- **The real bottleneck is per-edge rate limiting**, as the Shopify 429 episode showed: millions
  of Shopify stores are one target from Shopify's point of view. The scheduler must therefore
  budget requests **per edge/CDN per egress IP** (Shopify, Cloudflare, Akamai...), interleave
  work across edges, and scale out with more egress IPs rather than more threads.

#### The key insight for *this* client: Shopify app detection needs no browser

The Web Pixels manifest and theme-extension URLs are in the **raw HTML**. With a map from
`apiClientId` / extension handle to app, detecting pixel-based Shopify apps is **one HTTP GET per
store**. The Light preset (no browser) already found Elevar, Littledata and Polar on the demo
stores this way. That turns the expensive part of the problem into a cheap one:

```
1. Find Shopify stores   DNS pass on all candidate domains: A 23.227.38.0/24 or CNAME *.myshopify.com
                         (free, never rate-limited; domain sources: Common Crawl, zone files)
2. One HTTP GET each     parse webPixelsConfigList + cdn.shopify.com/extensions/* + script URLs
                         → lookup in the app-id registry → competitor list per store
3. Browser only for      bot-walled stores, JS-only shells, and a rotating sample for QA
4. Store raw signals     (manifest, extension handles, script hosts, headers) in Parquet/S3,
                         so a newly learned id re-scores every store without re-crawling
```

The quality of step 2 depends entirely on the **app-id registry**: which id/handle belongs to
which app. That's where the own-store idea comes in.

#### Analysis: should we run our own Shopify store with the competitor apps installed?

**Yes, as a fingerprinting lab. It finds more than the reviewer-store sampling can, but it cannot
make a purely backend app visible. Where the line is matters.**

How it works:
1. Install app X on a clean development store with **every feature switched on**.
2. Browse, add to cart and place a **test order** (Shopify's test gateway).
3. Record everything (storefront HTML, pixel manifest, theme extensions, network calls,
   cookies, globals, app-proxy routes) and diff it against a baseline store without the app.

What it discovers beyond what we have today:
- **Exact identifiers instead of inferred ones.** The `apiClientId`, extension handles, ScriptTag
  URLs, cookies and globals, read directly. Today they are learned statistically from 5 reviewer
  stores; the lab also works for apps with few or no reviews.
- **Signals behind optional features.** Several "profit" apps (BeProfit, Lifetimely) sell
  attribution as an add-on. Its pixel only exists on stores that enabled it, which is likely why
  5 random reviewer stores shared nothing. Turned on in the lab, the add-on's pixel id becomes
  known, and every customer who uses it becomes detectable.
- **App-proxy routes, i.e. an active probe.** Some apps register a public route on the store
  (`/apps/<name>/...`) even when nothing in the page links to it. Once the lab reveals the route,
  a single request per store answers "installed or not": the route responds when the app is
  installed and 404s when it isn't. This is the one way to detect some apps that look
  backend-only from the HTML.
- **What happens at purchase.** On the test order we see:
  - which checkout / thank-you extensions the app adds (post-purchase surveys, upsells);
  - which events its sandboxed pixel subscribes to (`checkout_completed`, `product_viewed`);
  - which vendor endpoint receives the data.

  This maps each competitor's data flow. It is directly usable at scale only when the same app
  also leaves a pre-purchase trace, because we won't place orders on other people's stores.
- **Change detection.** Re-capture each lab store weekly and diff. Vendors change endpoints,
  re-register pixels and rename extensions; the lab catches it the day it happens instead of
  recall silently dropping.
- **A definitive "backend-only" verdict** when, with all features on and an order placed, nothing
  changes.

What it can't do, and why the data layer doesn't help there:
- A purely backend app (reads orders through the Admin API / webhooks) **never touches the
  storefront or the data layer**. The purchase event is emitted by Shopify, not by the app, and
  the app picks the order up server-side afterwards. There is nothing to observe on the
  website, so these apps' users still come from reviews and the other off-site sources.
- Some apps refuse dev stores, need approval, or only activate after real data (orders,
  connected ad accounts). A few need a real paid plan on a real store.
- Setup is manual (~15-30 minutes per app through the admin, including onboarding so the
  pixels actually turn on). Capture and diffing are automated after that.

**How it scales:**
- **Lab:** one app per dev store against one baseline store, so every diff is clean.
- **Validation:** reviewer stores (already implemented) become the *validation set*. The lab says
  "Polar = `4294333`"; the reviewer stores measure how often it is found in the wild
  (recall/precision per app per month).
- **Crawl:** the registry feeds step 2 above, so millions of stores are scored by an id lookup
  in a single GET each, plus one extra request per known app-proxy route where an app has one.

#### Improvements on the leads side

- **Automatic domains for review leads.** This is implemented: myshopify-handle redirect, DNS
  pre-filtered domain guesses, then Shopify + name verification. That gives 143 verified domains
  of 205 attempted (70%), 110 of them from DNS-filtered guesses. To get closer to 100%:
  1. **Join against the crawl itself.** Once millions of Shopify stores are crawled with their
     title / og:site_name / myshopify handle, matching a reviewer name becomes an offline fuzzy
     join, with no extra requests.
  2. A search API (Brave/Bing/SerpAPI) for the rest: `"<store name>" <country> shop`, then the
     same verification.
- **Contact enrichment.** Push verified domains to **Apollo** (or Skrapp / Hunter / Snov) through
  their APIs to get decision makers: founder, head of e-commerce, growth or marketing lead, with
  verified emails. Then create CRM records (HubSpot/Pipedrive) carrying:
  - the competitor tool, review rating, review text and months of use;
  - the proof line from our crawl.

  The salesperson opens a lead and already has the angle: *"You gave BeProfit one star in
  October because of pricing…"*.
- **Lead scoring.** Rating (1-2★ = churn risk = hottest), review recency, months of use (lock-in),
  store size proxies (number of installed app pixels, Shopify Plus signals, traffic rank), and
  country/language fit.
- **Speed matters for unhappy reviews.** Collect new reviews **daily**, not monthly, and send a
  Slack alert when a new 1-2★ review lands on a competitor. The best time to call is the week
  someone is publicly unhappy.
- **Compliance.** B2B outreach in the EU runs on legitimate interest: use business contacts only,
  honour opt-outs, and state the source. Reviews are public, but how they're used in outreach
  should be tactful.

---

### 5.3 How would I discover new technologies in the future?

#### Continuous, cheap (built on what exists)

1. **Monthly crawl of the Shopify App Store** categories that matter (Analytics, Reports,
   Attribution, Profit tracking). Track:
   - **New apps** → added to `competitors.json`, with reviews collected and ids learned.
   - **Delisted apps.** This run found Triple Whale, OrderMetrics and Admetrics "no longer
     available".
   - **Review velocity.** A fast-growing app is a rising competitor.
2. **Mine the crawl for unknown signals.** Rank `apiClientId`s, extension handles, third-party
   script hosts, JS globals and cookie names that **no rule explains**, by frequency × share on
   Shopify stores. Extension handles usually name the app (`analyzify-ga4-ads-tracking`), and
   pixel configs often contain the vendor's URL (`getelevar.com`). An LLM drafts the rule and
   category; a human approves it.
3. **Back-test before shipping.** New rules run against the stored raw signals (precision check
   on labelled stores) and against a per-technology regression set.
4. **Upstream feeds.** The public fingerprint DB (`scripts/update_fingerprints.py`), Shopify's
   changelog (new pixel/extension APIs change what is detectable), and vendors' install docs
   (they literally publish their script URLs).

#### Long term: the maximum-accuracy setup for competitor identification

The goal is to know **each competitor's identification system** (every id, script, endpoint and
extension it uses, and when it changes) and to know our own precision and recall per competitor:

| Component | What it does |
|---|---|
| **Competitor lab** | One dev store per competitor app (paid plan where needed), all features on, fully onboarded, with test orders through checkout. Automated weekly capture + diff of storefront, PDP, cart, checkout, thank-you pages and app-proxy routes. |
| **Identifier registry** | App → all known identifiers (pixel ids, extension handles, app-proxy routes, script hosts, globals, cookies), with version history, provenance (lab / reviews / config) and confidence. Single source of truth for the crawler. |
| **In-the-wild validation** | Labelled sets per app: reviewer stores, vendor case-study logos, known customers. Monthly precision/recall per app on a dashboard; alert when recall drops (fingerprint changed). |
| **Off-site coverage for backend-only apps** | Daily App Store reviews; vendor logo walls and case studies; job posts; agency partner pages; G2/Capterra. Optionally a commercial dataset (Store Leads / BuiltWith API) as an extra vote. |
| **Lookalike model** | Trained on confirmed customers of each competitor (stack, size, vertical, country, apps installed) → probability that an unlabelled store uses competitor X. Reported as "likely", never as fact. |
| **Lead delivery** | Apollo/Skrapp enrichment + CRM sync + daily 1-2★ review alerts. |
| **People** | 1 engineer (crawler + registry) and a part-time analyst who approves new rules weekly and runs app onboarding in the lab. |

The result for sales: three confidence levels per lead.
- **Confirmed**: lab-verified identifier seen on the store, or the store wrote a review.
- **Likely**: lookalike model.
- **Unknown**.

Each comes with its proof. Nobody gets an email that claims something we can't show.

---

## 6. Caveats, stated plainly

- The benchmark's "477" was produced by an unknown tool at an unknown date. Sites change, rule sets
  differ, and "different technologies" may be counted differently. 504 vs 477 shows comparable
  coverage, not a precise head-to-head.
- 232 detections are *implied* (e.g. WordPress ⇒ PHP + MySQL). They are marked `implied_by`
  rather than presented as directly observed.
- Archive-derived detections are flagged `stale_from_archive` and down-weighted.
- The public rule set is GPL-3.0. It is fetched by a script into `vendor/` and not redistributed
  here. Own rules are in [`config/custom_fingerprints.json`](config/custom_fingerprints.json).
