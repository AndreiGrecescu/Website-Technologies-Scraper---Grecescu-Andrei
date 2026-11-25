# From 200 domains on a laptop to millions in 2-3 months

Infrastructure appendix to the debate topics. The main answers (invisible tools, the competitor
lab, leads enrichment, discovery) are in [README §5](../README.md#5-debate-topics). This file holds
the supporting detail: the limits table and the queue architecture.

---

## 1. Limits of the current ("cheap") version

| Limit | Why it happens | Impact on this run | What fixes it |
|---|---|---|---|
| **One residential IP** | Everything leaves from one home connection. WAFs (Cloudflare, Akamai, DataDome) score IP reputation and request rate *across all the sites they protect*, so 200 different domains still look like one client hammering Cloudflare. | ~5% of domains stay behind a bot wall even with a real browser | IP pool across clouds/regions, per-ASN/CDN rate limits, residential/ISP proxies only for the blocked tail |
| **Homepage only** | One URL per domain. | Pixels that only fire on product / cart / checkout pages are missed (Shopify apps often load on PDP and cart) | Crawl 3-5 typed pages per store: home, a product (`/products.json` -> first handle), `/cart`, a collection |
| **No consent given** | EU sites hold analytics until the cookie banner is accepted (GDPR). We never click it. | Under-detects GA4/Hotjar/Clarity on EU sites | Optional "consent mode" that accepts known CMPs (OneTrust, Cookiebot, Complianz) - must be a legal/ethics decision, so it's off by design |
| **Backend-only apps are invisible** | BeProfit, Lifetimely, Peel, Lebesgue, Daasity, Sirge share no storefront signal in our samples (Admin API only). | Direct competitors are under-counted by crawling alone | Implemented: App Store reviews as a customer list + app IDs learned from reviewer stores (README §3). Further: case studies, job posts, partner data |
| **Fingerprint coverage** | Detection = rules. A tool with no rule is invisible. | Long tail of local/niche tools missed | Rule discovery pipeline (section 3) |
| **Single-process, in-memory** | asyncio on one machine, results written at the end. | A crash loses the run; no resume | Queue + per-domain persisted results (section 2) |
| **Regex engine** | Python `re` has no timeout; a pathological pattern on a huge page could stall a worker. | Not observed, mitigated by size caps | `regex` module with timeouts, or run matching in a process pool with a watchdog |
| **DOM "properties" rules** | Evaluated as "element exists" (needs live DOM). | Slight over-confidence on ~1% of rules | Evaluate in-page with `querySelector` during the browser pass |
| **Wayback fallback is stale** | Snapshots can be months old. | Marked `stale_from_archive`, confidence x0.6 | Use only when nothing live is available (already the case) |

---

## 2. Scaling to millions of domains in 1-2 (or 2-3) months

### Back-of-the-envelope (10M domains in 60 days)

* 10M / 60 days ≈ **170k domains/day ≈ 2 domains/second** on average. That is *not* a lot of
  throughput; the hard parts are **IP reputation, the browser tier's load, and data handling**,
  not raw speed.
* Measured on this project: plain HTTP ≈ 0.1-0.5 s/domain and async-cheap; headless browser
  ≈ 9 slot-seconds/domain (466 s × 4 slots / 200 domains in run v5).
* Browser on **everything**: 10M × 9 s ≈ 90M slot-seconds. At ~8 browser slots per 8 vCPU/16 GB
  node that's ≈ 130 node-days → **~3-5 spot nodes for 45 days**. Compute is not the constraint.
* Browser **only where needed** (smart mode + every Shopify store): in run v4 smart escalation
  sent only the failing / JS-shell domains to the browser. With a DNS pre-pass to find Shopify
  stores (CNAME `shops.myshopify.com`, A `23.227.38.0/24`), the browser tier shrinks to
  "Shopify stores + blocked + SPA shells", probably 20-30% of the input.

### Architecture

```
                    ┌──────────────────────────┐
 domain lists ─────▶│ Frontier DB (Postgres)   │  domain, priority, last_seen, status, attempts
 (CSV/parquet,      │  + scheduler             │  re-crawl policy: Shopify stores weekly, rest quarterly
  Common Crawl,     └────────────┬─────────────┘
  zone files)                    │ enqueue by tier
          ┌──────────────────────┼──────────────────────┬────────────────────┐
          ▼                      ▼                      ▼                    ▼
   q.dns (Kafka/SQS)      q.http                  q.browser            q.fallback
   massive async DNS      async httpx workers     Playwright pods      Wayback / Common Crawl
   (own Unbound cluster)  (k8s, autoscale)        (k8s, spot, KEDA     readers
                                                   autoscale on lag)
          │                      │                      │                    │
          └──────────┬───────────┴──────────┬───────────┴────────────────────┘
                     ▼                      ▼
          raw signals → S3 (Parquet / WARC)   per-tier metrics → Prometheus/Grafana
          headers, cookies, script URLs,      (success rate, block rate per WAF vendor,
          network log, js globals, DNS,        p95 latency, domains per hour)  
          html (gz, optional)
                     │
                     ▼
          Detection = batch job (Spark / DuckDB / Ray) over raw signals
          → technologies + evidence table (Iceberg/Delta)  → leads API / CRM export
```

Key design decisions:

1. **Separate collection from detection.** Store the raw signals, not just the verdict. When a
   new fingerprint is added (e.g. a new Shopify analytics app), re-run detection over the
   stored signals in minutes instead of re-crawling millions of sites. This one decision is
   what makes "discover new technologies" (section 3) cheap.
2. **Tiered escalation with per-tier queues.** DNS for everyone (minutes for millions, never
   blocked, already tells us *Shopify yes/no*); HTTP for everyone; browser only when needed;
   archive fallback for the rest. Each tier scales independently on its own queue lag.
3. **Prioritize by business value.** The client sells to Shopify stores, so a DNS pre-pass
   finds Shopify stores first and gives them the expensive treatment (browser, multi-page,
   weekly re-crawl). Non-Shopify sites get the cheap pass.
4. **Egress / politeness layer.** A pool of egress IPs across several clouds and regions,
   with rate limits **per target CDN/WAF and per ASN**, not just per domain (Cloudflare sees
   all our requests together). Residential/ISP proxies are billed by traffic, so they are used
   *only* for the blocked tail and preferably for the HTTP fetch (~100 KB) rather than a full
   browser page (~3 MB): ~30x less traffic per domain.
5. **Idempotent, resumable work.** Every task keyed by (domain, tier, crawl_epoch); results
   written per domain; retries with backoff and a dead-letter queue for permanent failures.
6. **Don't crawl what's already crawled.** Common Crawl publishes a monthly crawl of ~billions
   of pages, including WAT files (headers + every link/script URL) - running detection over
   that first covers a large share of domains for the price of S3 reads. HTTP Archive runs
   Wappalyzer over ~16M sites monthly in BigQuery - useful as a validation set.
7. **Be a good citizen.** Honor robots.txt and opt-out requests, cap per-site concurrency at 1,
   use an identifiable UA with a contact page for the "polite" lane. This is also a business
   protection: the client's brand is attached to the crawler.

---

## 3. Discovering new technologies

Detection is only as good as the rule set, so discovery has to be a continuous process:

1. **Mine the network logs we already store.** Every browser visit records every third-party
   host. Aggregate by registrable domain across all crawled sites: frequent hosts that match
   **no existing rule** are candidate technologies. Rank by frequency × "share on Shopify
   stores" so the client's market comes first.
2. **Same for JS globals, cookie names and response headers.** Diff `window` against a blank
   page baseline; unknown globals/cookies seen on many sites = candidate fingerprints.
3. **Shopify Web Pixels as a labelled stream.** Every store publishes its installed app pixels
   with an `apiClientId` (see `techscan/shopify.py`). New `apiClientId`s appearing across many
   stores = a new app gaining traction - exactly the competitive early-warning signal an
   analytics vendor wants. Map ids to app names once (co-occurrence with known vendor hosts,
   or the App Store), then it's free detection forever.
4. **Auto-draft, human-approve.** For each candidate, generate a draft rule (`xhr` / `scriptSrc`
   on its domain, or the global/cookie name), fetch the vendor's homepage, and let an LLM
   propose name + category + description. A human approves it; the rule is back-tested on the
   stored signals (precision check on a labelled set) before it ships.
5. **External watch-lists.** New apps in the Shopify App Store "Analytics" category, the
   upstream open-source fingerprint repo (pulled by `scripts/update_fingerprints.py`),
   competitor docs ("install our pixel: `<script src=...>`") as rule sources.
6. **Regression set.** Keep a list of known sites per technology; every rule change is
   re-validated against it so precision doesn't silently drift.
